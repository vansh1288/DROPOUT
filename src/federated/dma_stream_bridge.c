#include "dma_stream_bridge.h"
#include "memory_scratchpad.h"

#ifdef TEST_BUILD
#include "freertos_mock.h"
#else
#include "FreeRTOS.h"
#include "task.h"
#endif

#include <stdint.h>
#include <string.h>

/* Set by dma_isr_set_stream_task(). */
extern TaskHandle_t g_stream_task_handle;

static void clear_chunk_metadata(dma_stream_chunk_t *chunk)
{
    if (chunk == NULL) {
        return;
    }

    chunk->length = 0u;
    chunk->chunk_index = 0u;
    chunk->timestamp = 0u;
}

pqc_status_t dma_stream_bridge_init(
    dma_stream_bridge_t *bridge,
    uint32_t timeout_ms)
{
    dma_double_buffer_t *dma_rx;

    if (bridge == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    memset(bridge, 0, sizeof(*bridge));

    dma_rx = scratch_get_dma_rx();
    if (dma_rx == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    bridge->chunks[0].buffer = scratch_get_dma_rx_active(0u);
    bridge->chunks[1].buffer = scratch_get_dma_rx_active(1u);
    if (bridge->chunks[0].buffer == NULL ||
        bridge->chunks[1].buffer == NULL) {
        memset(bridge, 0, sizeof(*bridge));
        return ERR_INVALID_ARGUMENT;
    }

    crypto_zeroize(dma_rx->ping, DMA_BUFFER_BYTES);
    crypto_zeroize(dma_rx->pong, DMA_BUFFER_BYTES);

    bridge->chunks[0].state = DMA_STREAM_BUF_STATE_FREE;
    bridge->chunks[1].state = DMA_STREAM_BUF_STATE_FREE;
    bridge->active_idx = 0u;
    bridge->processing_idx = 0u;
    bridge->chunk_sequence = 0u;
    bridge->chunks_dropped = 0u;
    bridge->chunks_processed = 0u;
    bridge->chunk_timeout_ms = (timeout_ms != 0u) ? timeout_ms : 1000u;

    return PQC_SUCCESS;
}

BaseType_t dma_stream_bridge_rx_complete_isr(
    dma_stream_bridge_t *bridge,
    uint16_t length)
{
    BaseType_t higher_priority_task_woken = pdFALSE;
    uint8_t idx;

    if (bridge == NULL) {
        return pdFALSE;
    }

    if (length == 0u || length > DMA_BUFFER_BYTES) {
        bridge->chunks_dropped++;
        return pdFALSE;
    }

    idx = bridge->active_idx;
    if (idx >= 2u || bridge->chunks[idx].state != DMA_STREAM_BUF_STATE_FREE) {
        bridge->chunks_dropped++;
        return pdFALSE;
    }

    /* Publish metadata before changing state to FULL. */
    bridge->chunks[idx].length = length;
    bridge->chunks[idx].chunk_index = bridge->chunk_sequence++;
    bridge->chunks[idx].timestamp = (uint32_t)xTaskGetTickCountFromISR();
    bridge->chunks[idx].state = DMA_STREAM_BUF_STATE_FULL;
    bridge->active_idx = (uint8_t)(idx ^ 1u);

    if (g_stream_task_handle != NULL) {
        xTaskNotifyFromISR(
            g_stream_task_handle,
            0x01u,
            eSetBits,
            &higher_priority_task_woken);
        portYIELD_FROM_ISR(higher_priority_task_woken);
    }

    return higher_priority_task_woken;
}

BaseType_t dma_stream_bridge_error_isr(dma_stream_bridge_t *bridge)
{
    BaseType_t higher_priority_task_woken = pdFALSE;
    uint8_t idx;

    if (bridge == NULL) {
        return pdFALSE;
    }

    idx = bridge->active_idx;
    if (idx < 2u) {
        /* Keep the errored buffer unavailable until get_rx_buffer() clears it. */
        bridge->chunks[idx].state = DMA_STREAM_BUF_STATE_ERROR;
        bridge->chunks_dropped++;
    }

    if (g_stream_task_handle != NULL) {
        xTaskNotifyFromISR(
            g_stream_task_handle,
            0x80u,
            eSetBits,
            &higher_priority_task_woken);
        portYIELD_FROM_ISR(higher_priority_task_woken);
    }

    return higher_priority_task_woken;
}

pqc_status_t dma_stream_bridge_get_rx_buffer(
    dma_stream_bridge_t *bridge,
    uint8_t **buffer_out,
    uint16_t *max_len)
{
    uint8_t idx;

    if (bridge == NULL || buffer_out == NULL || max_len == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    idx = bridge->active_idx;
    if (idx >= 2u || bridge->chunks[idx].buffer == NULL) {
        return ERR_INVALID_STATE;
    }

    if (bridge->chunks[idx].state == DMA_STREAM_BUF_STATE_ERROR) {
        crypto_zeroize(bridge->chunks[idx].buffer, DMA_BUFFER_BYTES);
        clear_chunk_metadata(&bridge->chunks[idx]);
        bridge->chunks[idx].state = DMA_STREAM_BUF_STATE_FREE;
    }

    if (bridge->chunks[idx].state != DMA_STREAM_BUF_STATE_FREE) {
        return ERR_DMA_BUSY;
    }

    *buffer_out = bridge->chunks[idx].buffer;
    *max_len = DMA_BUFFER_BYTES;
    return PQC_SUCCESS;
}

pqc_status_t dma_stream_bridge_submit_buffer(
    dma_stream_bridge_t *bridge,
    uint16_t length)
{
    uint8_t idx;

    if (bridge == NULL) {
        return ERR_INVALID_ARGUMENT;
    }
    if (length == 0u) {
        return ERR_CHUNK_TOO_SMALL;
    }
    if (length > DMA_BUFFER_BYTES) {
        return ERR_CHUNK_TOO_LARGE;
    }

    idx = bridge->active_idx;
    if (idx >= 2u || bridge->chunks[idx].state != DMA_STREAM_BUF_STATE_FREE) {
        bridge->chunks_dropped++;
        return ERR_DMA_BUSY;
    }

    bridge->chunks[idx].length = length;
    bridge->chunks[idx].chunk_index = bridge->chunk_sequence++;
    bridge->chunks[idx].timestamp = (uint32_t)xTaskGetTickCount();
    bridge->chunks[idx].state = DMA_STREAM_BUF_STATE_FULL;
    bridge->active_idx = (uint8_t)(idx ^ 1u);
    return PQC_SUCCESS;
}

pqc_status_t dma_stream_bridge_get_chunk(
    dma_stream_bridge_t *bridge,
    uint8_t **data_out,
    uint16_t *length_out,
    uint16_t *chunk_index_out,
    uint8_t *buffer_index_out,
    uint32_t timeout_ms)
{
    TickType_t timeout_ticks;
    TickType_t start_tick;

    if (bridge == NULL || data_out == NULL || length_out == NULL ||
        chunk_index_out == NULL || buffer_index_out == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    *data_out = NULL;
    *length_out = 0u;
    *chunk_index_out = 0u;
    *buffer_index_out = 0u;

    if (timeout_ms == 0u) {
        timeout_ms = bridge->chunk_timeout_ms;
    }
    timeout_ticks = pdMS_TO_TICKS(timeout_ms);
    if (timeout_ticks == 0u && timeout_ms != 0u) {
        timeout_ticks = 1u;
    }
    start_tick = xTaskGetTickCount();

    for (;;) {
        uint8_t idx = bridge->processing_idx;

        if (idx >= 2u || bridge->chunks[idx].state != DMA_STREAM_BUF_STATE_FULL) {
            idx = (uint8_t)(idx ^ 1u);
        }

        if (idx < 2u && bridge->chunks[idx].state == DMA_STREAM_BUF_STATE_FULL) {
            if (bridge->chunks[idx].buffer == NULL ||
                bridge->chunks[idx].length == 0u ||
                bridge->chunks[idx].length > DMA_BUFFER_BYTES) {
                bridge->chunks[idx].state = DMA_STREAM_BUF_STATE_ERROR;
                bridge->chunks_dropped++;
                return ERR_INVALID_STATE;
            }

            *data_out = bridge->chunks[idx].buffer;
            *length_out = bridge->chunks[idx].length;
            *chunk_index_out = bridge->chunks[idx].chunk_index;
            *buffer_index_out = idx;
            bridge->chunks[idx].state = DMA_STREAM_BUF_STATE_PROCESSING;
            bridge->processing_idx = (uint8_t)(idx ^ 1u);
            bridge->chunks_processed++;
            return PQC_SUCCESS;
        }

        {
            TickType_t elapsed = (TickType_t)(xTaskGetTickCount() - start_tick);
            TickType_t remaining;
            TickType_t wait_ticks;

            if (elapsed >= timeout_ticks) {
                return ERR_NETWORK_TIMEOUT;
            }

            remaining = (TickType_t)(timeout_ticks - elapsed);
            wait_ticks = pdMS_TO_TICKS(10u);
            if (wait_ticks == 0u) {
                wait_ticks = 1u;
            }
            if (wait_ticks > remaining) {
                wait_ticks = remaining;
            }
            if (wait_ticks == 0u) {
                return ERR_NETWORK_TIMEOUT;
            }

            (void)ulTaskNotifyTake(pdTRUE, wait_ticks);
        }
    }
}

pqc_status_t dma_stream_bridge_release_buffer(
    dma_stream_bridge_t *bridge,
    uint8_t buffer_index)
{
    dma_stream_chunk_t *chunk;

    if (bridge == NULL || buffer_index >= 2u) {
        return ERR_INVALID_ARGUMENT;
    }

    chunk = &bridge->chunks[buffer_index];
    if (chunk->state != DMA_STREAM_BUF_STATE_PROCESSING) {
        return ERR_INVALID_STATE;
    }
    if (chunk->buffer == NULL) {
        return ERR_INVALID_STATE;
    }

    crypto_zeroize(chunk->buffer, DMA_BUFFER_BYTES);
    clear_chunk_metadata(chunk);
    chunk->state = DMA_STREAM_BUF_STATE_FREE;
    return PQC_SUCCESS;
}

pqc_status_t dma_stream_bridge_get_stats(
    dma_stream_bridge_t *bridge,
    uint16_t *chunks_processed,
    uint16_t *chunks_dropped)
{
    if (bridge == NULL || chunks_processed == NULL || chunks_dropped == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    *chunks_processed = bridge->chunks_processed;
    *chunks_dropped = bridge->chunks_dropped;
    return PQC_SUCCESS;
}

pqc_status_t dma_stream_bridge_reset(dma_stream_bridge_t *bridge)
{
    dma_double_buffer_t *dma_rx;
    uint32_t timeout_ms;
    uint8_t *buffer0;
    uint8_t *buffer1;

    if (bridge == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    /* Preserve the buffer addresses and configured timeout across reset. */
    buffer0 = bridge->chunks[0].buffer;
    buffer1 = bridge->chunks[1].buffer;
    timeout_ms = bridge->chunk_timeout_ms;

    if (buffer0 == NULL || buffer1 == NULL) {
        return ERR_INVALID_STATE;
    }

    crypto_zeroize(buffer0, DMA_BUFFER_BYTES);
    crypto_zeroize(buffer1, DMA_BUFFER_BYTES);

    bridge->active_idx = 0u;
    bridge->processing_idx = 0u;
    bridge->chunk_sequence = 0u;
    bridge->chunks_dropped = 0u;
    bridge->chunks_processed = 0u;
    bridge->chunk_timeout_ms = (timeout_ms != 0u) ? timeout_ms : 1000u;

    clear_chunk_metadata(&bridge->chunks[0]);
    clear_chunk_metadata(&bridge->chunks[1]);
    bridge->chunks[0].buffer = buffer0;
    bridge->chunks[1].buffer = buffer1;
    bridge->chunks[0].state = DMA_STREAM_BUF_STATE_FREE;
    bridge->chunks[1].state = DMA_STREAM_BUF_STATE_FREE;

    dma_rx = scratch_get_dma_rx();
    if (dma_rx == NULL) {
        return ERR_INVALID_STATE;
    }
    crypto_zeroize(dma_rx->ping, DMA_BUFFER_BYTES);
    crypto_zeroize(dma_rx->pong, DMA_BUFFER_BYTES);

    return PQC_SUCCESS;
}
