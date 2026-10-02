
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "crypto_memory.h"
#include "dma_isr_handler.h"
#include "FreeRTOS.h"
#include "task.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define DMA_CHUNK_ELEMENTS 128U
#define DMA_CHUNK_BYTES (DMA_CHUNK_ELEMENTS * sizeof(int16_t))

/* Active ping/pong buffer indices */
static volatile uint8_t g_dma_rx_active = 0U;
static volatile uint8_t g_dma_tx_active = 0U;

/* Network coordinator task notified by DMA interrupts */
static TaskHandle_t g_network_task_handle = NULL;

/* Switch active RX buffer */
static inline void dma_rx_buffer_switch(void)
{
    g_dma_rx_active ^= 1U;
}

/* Switch active TX buffer */
static inline void dma_tx_buffer_switch(void)
{
    g_dma_tx_active ^= 1U;
}

/* Return the currently active RX buffer */
uint8_t *dma_get_rx_buffer(void)
{
    dma_double_buffer_t *dma_rx = scratch_get_dma_rx();

    if (dma_rx == NULL) {
        return NULL;
    }

    return (g_dma_rx_active != 0U) ? dma_rx->pong : dma_rx->ping;
}

/* Return the currently active TX buffer */
uint8_t *dma_get_tx_buffer(void)
{
    dma_double_buffer_t *dma_tx = scratch_get_dma_tx();

    if (dma_tx == NULL) {
        return NULL;
    }

    return (g_dma_tx_active != 0U) ? dma_tx->pong : dma_tx->ping;
}

/*
 * RX completion handler.
 * Must only be called from the target DMA ISR.
 */
void dma_isr_rx_complete(void)
{
    BaseType_t higher_priority_task_woken = pdFALSE;

    dma_rx_buffer_switch();

    if (g_network_task_handle != NULL) {
        xTaskNotifyFromISR(
            g_network_task_handle,
            0x01U,
            eSetBits,
            &higher_priority_task_woken
        );
    }

    portYIELD_FROM_ISR(higher_priority_task_woken);
}

/*
 * TX completion handler.
 * Must only be called from the target DMA ISR.
 */
void dma_isr_tx_complete(void)
{
    BaseType_t higher_priority_task_woken = pdFALSE;

    dma_tx_buffer_switch();

    if (g_network_task_handle != NULL) {
        xTaskNotifyFromISR(
            g_network_task_handle,
            0x02U,
            eSetBits,
            &higher_priority_task_woken
        );
    }

    portYIELD_FROM_ISR(higher_priority_task_woken);
}

/*
 * DMA error handler.
 * Must only be called from the target DMA ISR.
 */
void dma_isr_error(void)
{
    BaseType_t higher_priority_task_woken = pdFALSE;

    if (g_network_task_handle != NULL) {
        xTaskNotifyFromISR(
            g_network_task_handle,
            0x80U,
            eSetBits,
            &higher_priority_task_woken
        );
    }

    portYIELD_FROM_ISR(higher_priority_task_woken);
}

/* Register the network coordinator task */
void dma_isr_set_network_task(TaskHandle_t handle)
{
    taskENTER_CRITICAL();
    g_network_task_handle = handle;
    taskEXIT_CRITICAL();
}

/*
 * Initialize DMA state and clear buffers.
 *
 * Call during startup before registering the network task.
 * This function deliberately preserves the registered task handle
 * if called later, avoiding accidental loss of notifications.
 */
void dma_isr_init(void)
{
    g_dma_rx_active = 0U;
    g_dma_tx_active = 0U;

    dma_double_buffer_t *dma_rx = scratch_get_dma_rx();
    dma_double_buffer_t *dma_tx = scratch_get_dma_tx();

    if (dma_rx != NULL) {
        if (dma_rx->ping != NULL) {
            crypto_zeroize(dma_rx->ping, DMA_BUFFER_BYTES);
        }

        if (dma_rx->pong != NULL) {
            crypto_zeroize(dma_rx->pong, DMA_BUFFER_BYTES);
        }
    }

    if (dma_tx != NULL) {
        if (dma_tx->ping != NULL) {
            crypto_zeroize(dma_tx->ping, DMA_BUFFER_BYTES);
        }

        if (dma_tx->pong != NULL) {
            crypto_zeroize(dma_tx->pong, DMA_BUFFER_BYTES);
        }
    }
}

/* Prepare RX operation */
pqc_status_t dma_isr_start_rx(void)
{
    uint8_t *buf = dma_get_rx_buffer();

    if (buf == NULL) {
        return ERR_INVALID_STATE;
    }

    /*
     * Hardware DMA start is target-specific and is not implemented
     * in this generic ISR handler.
     *
     * The target driver must configure and start DMA, then invoke
     * dma_isr_rx_complete() from its actual completion ISR.
     */
    (void)buf;

    return PQC_SUCCESS;
}

/* Prepare TX operation */
pqc_status_t dma_isr_start_tx(const uint8_t *data, uint16_t len)
{
    if (data == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    if ((size_t)len > (size_t)DMA_BUFFER_BYTES) {
        return ERR_CHUNK_TOO_LARGE;
    }

    uint8_t *buf = dma_get_tx_buffer();

    if (buf == NULL) {
        return ERR_INVALID_STATE;
    }

    if (len > 0U) {
        memcpy(buf, data, (size_t)len);
    }

    /*
     * Hardware DMA start is target-specific and is not implemented
     * in this generic ISR handler.
     *
     * The target driver must configure and start DMA, then invoke
     * dma_isr_tx_complete() from its actual completion ISR.
     */
    return PQC_SUCCESS;
}

/* Return active RX buffer index */
uint8_t dma_isr_get_rx_active(void)
{
    return g_dma_rx_active;
}

/* Return active TX buffer index */
uint8_t dma_isr_get_tx_active(void)
{
    return g_dma_tx_active;
}