
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include <stdint.h>

#define DMA_CHUNK_ELEMENTS 128
#define DMA_CHUNK_BYTES (DMA_CHUNK_ELEMENTS * sizeof(int16_t))

static volatile uint8_t g_dma_rx_active = 0;
static volatile uint8_t g_dma_tx_active = 0;
static TaskHandle_t g_stream_task_handle = NULL;

static inline void dma_rx_buffer_switch(void) {
    g_dma_rx_active ^= 1u;
}

static inline void dma_tx_buffer_switch(void) {
    g_dma_tx_active ^= 1u;
}

static inline uint8_t* dma_get_rx_buffer(void) {
    dma_double_buffer_t* dma_rx = scratch_get_dma_rx();
    return g_dma_rx_active ? dma_rx->pong : dma_rx->ping;
}

static inline uint8_t* dma_get_tx_buffer(void) {
    dma_double_buffer_t* dma_tx = scratch_get_dma_tx();
    return g_dma_tx_active ? dma_tx->pong : dma_tx->ping;
}

void dma_isr_rx_complete(void) {
    BaseType_t higher_priority_task_woken = pdFALSE;
    dma_rx_buffer_switch();
    if (g_stream_task_handle != NULL) {
        xTaskNotifyFromISR(g_stream_task_handle, 0x01, eSetBits, &higher_priority_task_woken);
    }
    portYIELD_FROM_ISR(higher_priority_task_woken);
}

void dma_isr_tx_complete(void) {
    BaseType_t higher_priority_task_woken = pdFALSE;
    dma_tx_buffer_switch();
    if (g_stream_task_handle != NULL) {
        xTaskNotifyFromISR(g_stream_task_handle, 0x02, eSetBits, &higher_priority_task_woken);
    }
    portYIELD_FROM_ISR(higher_priority_task_woken);
}

void dma_isr_error(void) {
    BaseType_t higher_priority_task_woken = pdFALSE;
    if (g_stream_task_handle != NULL) {
        xTaskNotifyFromISR(g_stream_task_handle, 0x80, eSetBits, &higher_priority_task_woken);
    }
    portYIELD_FROM_ISR(higher_priority_task_woken);
}

void dma_isr_set_stream_task(TaskHandle_t handle) {
    g_stream_task_handle = handle;
}

void dma_isr_init(void) {
    g_dma_rx_active = 0;
    g_dma_tx_active = 0;
    g_stream_task_handle = NULL;
    dma_double_buffer_t* dma_rx = scratch_get_dma_rx();
    dma_double_buffer_t* dma_tx = scratch_get_dma_tx();
    crypto_zeroize(dma_rx->ping, DMA_BUFFER_BYTES);
    crypto_zeroize(dma_rx->pong, DMA_BUFFER_BYTES);
    crypto_zeroize(dma_tx->ping, DMA_BUFFER_BYTES);
    crypto_zeroize(dma_tx->pong, DMA_BUFFER_BYTES);
}

pqc_status_t dma_isr_start_rx(void) {
    uint8_t* buf = dma_get_rx_buffer();
    return PQC_SUCCESS;
}

pqc_status_t dma_isr_start_tx(const uint8_t* data, uint16_t len) {
    if (len > DMA_BUFFER_BYTES) return ERR_CHUNK_TOO_LARGE;
    uint8_t* buf = dma_get_tx_buffer();
    memcpy(buf, data, len);
    return PQC_SUCCESS;
}

uint8_t dma_isr_get_rx_active(void) {
    return g_dma_rx_active;
}

uint8_t dma_isr_get_tx_active(void) {
    return g_dma_tx_active;
}
