#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "dma_stream_bridge.h"
#include "stream_aggregator.h"

#ifdef TEST_BUILD
#include "freertos_mock.h"
#else
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#endif

#include <stdint.h>
#include <string.h>

/*
 * DMA ping-pong buffer state.
 *
 * 0 = ping
 * 1 = pong
 */
static volatile uint8_t g_dma_rx_active = 0u;
static volatile uint8_t g_dma_tx_active = 0u;

/*
 * Stream task notified by DMA ISR events.
 *
 * This symbol is intentionally non-static because the DMA stream bridge
 * uses it to notify the stream aggregation task from ISR context.
 */
TaskHandle_t g_stream_task_handle = NULL;


/*
 * Switch the active DMA RX buffer.
 */
static inline void dma_rx_buffer_switch(void)
{
    g_dma_rx_active ^= 1u;
}


/*
 * Switch the active DMA TX buffer.
 */
static inline void dma_tx_buffer_switch(void)
{
    g_dma_tx_active ^= 1u;
}


/*
 * Get the currently active RX buffer.
 */
static inline uint8_t* dma_get_rx_buffer(void)
{
    dma_double_buffer_t* dma_rx = scratch_get_dma_rx();

    return g_dma_rx_active
        ? dma_rx->pong
        : dma_rx->ping;
}


/*
 * Get the currently active TX buffer.
 */
static inline uint8_t* dma_get_tx_buffer(void)
{
    dma_double_buffer_t* dma_tx = scratch_get_dma_tx();

    return g_dma_tx_active
        ? dma_tx->pong
        : dma_tx->ping;
}


/*
 * DMA RX completion ISR.
 *
 * The DMA bridge owns the RX buffer state transition and is responsible
 * for notifying the stream task.
 */
void dma_isr_rx_complete(void)
{
    dma_stream_bridge_t* bridge =
        stream_aggregator_get_dma_bridge();

    if (bridge == NULL) {
        return;
    }

    /*
     * The current transport path uses DMA_CHUNK_BYTES as the
     * completed transfer size.
     */
    (void)dma_stream_bridge_rx_complete_isr(
        bridge,
        DMA_CHUNK_BYTES
    );
}


/*
 * DMA TX completion ISR.
 *
 * TX completion is a notification event for the stream task.
 */
void dma_isr_tx_complete(void)
{
    BaseType_t higher_priority_task_woken = pdFALSE;

    dma_tx_buffer_switch();

    if (g_stream_task_handle != NULL) {
        xTaskNotifyFromISR(
            g_stream_task_handle,
            0x02u,
            eSetBits,
            &higher_priority_task_woken
        );

        portYIELD_FROM_ISR(higher_priority_task_woken);
    }
}


/*
 * DMA error ISR.
 *
 * Route the error through the stream bridge so that the affected
 * buffer transitions into the ERROR state before the stream task
 * is notified.
 */
void dma_isr_error(void)
{
    dma_stream_bridge_t* bridge =
        stream_aggregator_get_dma_bridge();

    if (bridge == NULL) {
        return;
    }

    (void)dma_stream_bridge_error_isr(bridge);
}


/*
 * Set the stream task that should receive DMA notifications.
 */
void dma_isr_set_stream_task(TaskHandle_t handle)
{
    g_stream_task_handle = handle;
}


/*
 * Initialize/reset DMA ISR software state.
 *
 * This function resets the software ping-pong state and clears all
 * DMA buffers.
 */
void dma_isr_init(void)
{
    g_dma_rx_active = 0u;
    g_dma_tx_active = 0u;
    g_stream_task_handle = NULL;

    dma_double_buffer_t* dma_rx = scratch_get_dma_rx();
    dma_double_buffer_t* dma_tx = scratch_get_dma_tx();

    crypto_zeroize(
        dma_rx->ping,
        DMA_BUFFER_BYTES
    );

    crypto_zeroize(
        dma_rx->pong,
        DMA_BUFFER_BYTES
    );

    crypto_zeroize(
        dma_tx->ping,
        DMA_BUFFER_BYTES
    );

    crypto_zeroize(
        dma_tx->pong,
        DMA_BUFFER_BYTES
    );
}


/*
 * Prepare/start an RX transfer.
 *
 * Actual hardware DMA programming is target-specific and is handled
 * by the platform transport layer. This function validates that the
 * current RX buffer exists.
 */
pqc_status_t dma_isr_start_rx(void)
{
    uint8_t* buffer = dma_get_rx_buffer();

    if (buffer == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    return PQC_SUCCESS;
}


/*
 * Prepare a TX transfer.
 */
pqc_status_t dma_isr_start_tx(
    const uint8_t* data,
    uint16_t len)
{
    if (data == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    if (len == 0u) {
        return ERR_INVALID_ARGUMENT;
    }

    if (len > DMA_BUFFER_BYTES) {
        return ERR_CHUNK_TOO_LARGE;
    }

    uint8_t* buffer = dma_get_tx_buffer();

    if (buffer == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    memcpy(buffer, data, len);

    return PQC_SUCCESS;
}


/*
 * Return the currently active RX buffer index.
 */
uint8_t dma_isr_get_rx_active(void)
{
    return g_dma_rx_active;
}


/*
 * Return the currently active TX buffer index.
 */
uint8_t dma_isr_get_tx_active(void)
{
    return g_dma_tx_active;
}