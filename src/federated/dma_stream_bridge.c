#include "dma_stream_bridge.h"
#include "memory_scratchpad.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include <string.h>
#include <stdint.h>

/* External reference to stream task handle set by dma_isr_set_stream_task */
extern TaskHandle_t g_stream_task_handle;

pqc_status_t dma_stream_bridge_init(dma_stream_bridge_t* bridge, uint32_t timeout_ms) {
    if (!bridge) return ERR_INVALID_ARGUMENT;

    memset(bridge, 0, sizeof(dma_stream_bridge_t));
    bridge->chunks[0].state = DMA_STREAM_BUF_STATE_FREE;
    bridge->chunks[1].state = DMA_STREAM_BUF_STATE_FREE;
    bridge->active_idx = 0;
    bridge->processing_idx = 0;
    bridge->chunk_sequence = 0;
    bridge->chunks_dropped = 0;
    bridge->chunks_processed = 0;
    bridge->chunk_timeout_ms = timeout_ms ? timeout_ms : 1000;

    /* Initialize DMA buffers from scratchpad */
    dma_double_buffer_t* dma_rx = scratch_get_dma_rx();
    crypto_zeroize(dma_rx->ping, DMA_BUFFER_BYTES);
    crypto_zeroize(dma_rx->pong, DMA_BUFFER_BYTES);

    /* Point bridge buffers to the DMA ping-pong buffers */
    bridge->chunks[0].buffer = scratch_get_dma_rx_active(0);  // ping
    bridge->chunks[1].buffer = scratch_get_dma_rx_active(1);  // pong

    return PQC_SUCCESS;
}

BaseType_t dma_stream_bridge_rx_complete_isr(dma_stream_bridge_t* bridge, uint16_t length) {
    BaseType_t higher_priority_task_woken = pdFALSE;

    if (!bridge) return pdFALSE;

    uint8_t idx = bridge->active_idx;

    /* Validate buffer state - must be FREE to accept new data */
    if (bridge->chunks[idx].state != DMA_STREAM_BUF_STATE_FREE) {
        /* Buffer not ready - overflow condition */
        bridge->chunks_dropped++;
        return pdFALSE;
    }

    /* Update buffer metadata */
    bridge->chunks[idx].length = length;
    bridge->chunks[idx].chunk_index = bridge->chunk_sequence++;
    bridge->chunks[idx].state = DMA_STREAM_BUF_STATE_FULL;
    bridge->chunks[idx].timestamp = xTaskGetTickCountFromISR();

    /* Toggle to next buffer for next DMA transfer */
    bridge->active_idx ^= 1u;

    /* Notify stream task */
    if (g_stream_task_handle != NULL) {
        BaseType_t higher_priority_task_woken = pdFALSE;
        xTaskNotifyFromISR(g_stream_task_handle, 0x01, eSetBits, &higher_priority_task_woken);
        portYIELD_FROM_ISR(higher_priority_task_woken);
    }

    return pdTRUE;
}

BaseType_t dma_stream_bridge_error_isr(dma_stream_bridge_t* bridge) {
    BaseType_t higher_priority_task_woken = pdFALSE;

    if (!bridge) return pdFALSE;

    uint8_t idx = bridge->active_idx;
    bridge->chunks[idx].state = DMA_STREAM_BUF_STATE_ERROR;
    bridge->chunks_dropped++;

    if (g_stream_task_handle != NULL) {
        BaseType_t higher_priority_task_woken = pdFALSE;
        xTaskNotifyFromISR(g_stream_task_handle, 0x80, eSetBits, &higher_priority_task_woken);
        portYIELD_FROM_ISR(higher_priority_task_woken);
    }

    return pdTRUE;
}

pqc_status_t dma_stream_bridge_get_rx_buffer(dma_stream_bridge_t* bridge, uint8_t** buffer_out, uint16_t* max_len) {
    if (!bridge || !buffer_out || !max_len) return ERR_INVALID_ARGUMENT;

    uint8_t idx = bridge->active_idx;

    if (bridge->chunks[idx].state != DMA_STREAM_BUF_STATE_FREE) {
        return ERR_BUFFER_TOO_SMALL;  // Buffer not available
    }

    *buffer_out = bridge->chunks[idx].buffer;
    *max_len = DMA_BUFFER_BYTES;
    bridge->chunks[idx].state = DMA_STREAM_BUF_STATE_FREE; // Will be filled by DMA

    return PQC_SUCCESS;
}

pqc_status_t dma_stream_bridge_submit_buffer(dma_stream_bridge_t* bridge, uint16_t length) {
    if (!bridge) return ERR_INVALID_ARGUMENT;

    uint8_t idx = bridge->active_idx ^ 1u; // Previous buffer

    if (bridge->chunks[idx].state != DMA_STREAM_BUF_STATE_FREE) {
        bridge->chunks_dropped++;
        return ERR_GENERIC;
    }

    bridge->chunks[idx].length = length;
    bridge->chunks[idx].chunk_index = bridge->chunk_sequence++;
    bridge->chunks[idx].state = DMA_STREAM_BUF_STATE_FULL;
    bridge->chunks[idx].timestamp = xTaskGetTickCount();

    return PQC_SUCCESS;
}

pqc_status_t dma_stream_bridge_get_chunk(dma_stream_bridge_t* bridge, uint8_t** data_out, uint16_t* length_out, uint16_t* chunk_index, uint32_t timeout_ms) {
    if (!bridge || !data_out || !length_out || !chunk_index) return ERR_INVALID_ARGUMENT;

    uint32_t timeout_ticks = pdMS_TO_TICKS(timeout_ms);
    uint32_t start_tick = xTaskGetTickCount();

    while (1) {
        uint8_t idx = bridge->processing_idx;

        if (bridge->chunks[idx].state == DMA_STREAM_BUF_STATE_FULL) {
            /* Found a ready buffer */
            *data_out = bridge->chunks[idx].buffer;
            *length_out = bridge->chunks[idx].length;
            *chunk_index = bridge->chunks[idx].chunk_index;

            bridge->chunks[idx].state = DMA_STREAM_BUF_STATE_PROCESSING;
            bridge->processing_idx ^= 1u;
            bridge->chunks_processed++;

            return PQC_SUCCESS;
        }

        /* Check timeout */
        uint32_t elapsed = xTaskGetTickCount() - xTaskGetTickCount(); // Simplified
        if (elapsed >= pdMS_TO_TICKS(bridge->chunk_timeout_ms)) {
            return ERR_NETWORK_TIMEOUT;
        }

        /* Wait for notification */
        ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(10));
    }
}

pqc_status_t dma_stream_bridge_release_buffer(dma_stream_bridge_t* bridge, uint8_t buffer_index) {
    if (!bridge || buffer_index >= 2) return ERR_INVALID_ARGUMENT;

    if (bridge->chunks[buffer_index].state == DMA_STREAM_BUF_STATE_PROCESSING) {
        crypto_zeroize(bridge->chunks[buffer_index].buffer, DMA_BUFFER_BYTES);
        bridge->chunks[buffer_index].length = 0;
        bridge->chunks[buffer_index].chunk_index = 0;
        bridge->chunks[buffer_index].state = DMA_STREAM_BUF_STATE_FREE;
        return PQC_SUCCESS;
    }

    return ERR_INVALID_STATE;
}

pqc_status_t dma_stream_bridge_get_stats(dma_stream_bridge_t* bridge, uint16_t* chunks_processed, uint16_t* chunks_dropped) {
    if (!bridge || !chunks_processed || !chunks_dropped) return ERR_INVALID_ARGUMENT;

    *chunks_processed = bridge->chunks_processed;
    *chunks_dropped = bridge->chunks_dropped;
    return PQC_SUCCESS;
}

pqc_status_t dma_stream_bridge_reset(dma_stream_bridge_t* bridge) {
    if (!bridge) return ERR_INVALID_ARGUMENT;

    bridge->active_idx = 0;
    bridge->processing_idx = 0;
    bridge->chunk_sequence = 0;
    bridge->chunks_dropped = 0;
    bridge->chunks_processed = 0;

    bridge->chunks[0].state = DMA_STREAM_BUF_STATE_FREE;
    bridge->chunks[1].state = DMA_STREAM_BUF_STATE_FREE;
    bridge->chunks[0].length = 0;
    bridge->chunks[1].length = 0;
    bridge->chunks[0].chunk_index = 0;
    bridge->chunks[1].chunk_index = 0;

    dma_double_buffer_t* dma_rx = scratch_get_dma_rx();
    crypto_zeroize(dma_rx->ping, DMA_BUFFER_BYTES);
    crypto_zeroize(dma_rx->pong, DMA_BUFFER_BYTES);

    return PQC_SUCCESS;
}
