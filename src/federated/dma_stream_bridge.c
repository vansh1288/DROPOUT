#include "dma_stream_bridge.h"
#include "memory_scratchpad.h"

#ifdef TEST_BUILD
#include "freertos_mock.h"
#else
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#endif

#include <string.h>
#include <stdint.h>

/*
 * External reference to the stream task handle configured by
 * dma_isr_set_stream_task().
 */
extern TaskHandle_t g_stream_task_handle;


/*
 * Initialize the DMA stream bridge.
 */
pqc_status_t dma_stream_bridge_init(
    dma_stream_bridge_t* bridge,
    uint32_t timeout_ms)
{
    if (bridge == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    memset(bridge, 0, sizeof(*bridge));

    bridge->chunks[0].state = DMA_STREAM_BUF_STATE_FREE;
    bridge->chunks[1].state = DMA_STREAM_BUF_STATE_FREE;

    bridge->active_idx = 0u;
    bridge->processing_idx = 0u;
    bridge->chunk_sequence = 0u;
    bridge->chunks_dropped = 0u;
    bridge->chunks_processed = 0u;

    bridge->chunk_timeout_ms =
        (timeout_ms != 0u) ? timeout_ms : 1000u;

    /*
     * Initialize the DMA RX ping-pong buffers.
     */
    dma_double_buffer_t* dma_rx = scratch_get_dma_rx();

    crypto_zeroize(dma_rx->ping, DMA_BUFFER_BYTES);
    crypto_zeroize(dma_rx->pong, DMA_BUFFER_BYTES);

    /*
     * Bridge buffers point directly into the scratchpad DMA buffers.
     */
    bridge->chunks[0].buffer =
        scratch_get_dma_rx_active(0);

    bridge->chunks[1].buffer =
        scratch_get_dma_rx_active(1);

    if (bridge->chunks[0].buffer == NULL ||
        bridge->chunks[1].buffer == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    return PQC_SUCCESS;
}


/*
 * DMA RX completion ISR callback.
 */
BaseType_t dma_stream_bridge_rx_complete_isr(
    dma_stream_bridge_t* bridge,
    uint16_t length)
{
    BaseType_t higher_priority_task_woken = pdFALSE;

    if (bridge == NULL) {
        return pdFALSE;
    }

    /*
     * DMA_BUFFER_BYTES is the hard upper bound for one DMA buffer.
     */
    if (length == 0u || length > DMA_BUFFER_BYTES) {
        bridge->chunks_dropped++;
        return pdFALSE;
    }

    const uint8_t idx = bridge->active_idx;

    /*
     * The active buffer must be free when DMA completes.
     * Otherwise the consumer has not returned the buffer quickly enough.
     */
    if (bridge->chunks[idx].state != DMA_STREAM_BUF_STATE_FREE) {
        bridge->chunks_dropped++;
        return pdFALSE;
    }

    /*
     * Publish the received buffer.
     *
     * Metadata is written before the state changes to FULL so the
     * consumer never observes a FULL buffer with incomplete metadata.
     */
    bridge->chunks[idx].length = length;
    bridge->chunks[idx].chunk_index = bridge->chunk_sequence++;
    bridge->chunks[idx].timestamp = xTaskGetTickCountFromISR();
    bridge->chunks[idx].state = DMA_STREAM_BUF_STATE_FULL;

    /*
     * Switch to the other ping-pong buffer for the next DMA transfer.
     */
    bridge->active_idx ^= 1u;

    /*
     * Wake the stream task.
     */
    if (g_stream_task_handle != NULL) {
        xTaskNotifyFromISR(
            g_stream_task_handle,
            0x01u,
            eSetBits,
            &higher_priority_task_woken
        );

        portYIELD_FROM_ISR(higher_priority_task_woken);
    }

    return higher_priority_task_woken;
}


/*
 * DMA error ISR callback.
 */
BaseType_t dma_stream_bridge_error_isr(
    dma_stream_bridge_t* bridge)
{
    BaseType_t higher_priority_task_woken = pdFALSE;

    if (bridge == NULL) {
        return pdFALSE;
    }

    const uint8_t idx = bridge->active_idx;

    bridge->chunks[idx].state = DMA_STREAM_BUF_STATE_ERROR;
    bridge->chunks_dropped++;

    if (g_stream_task_handle != NULL) {
        xTaskNotifyFromISR(
            g_stream_task_handle,
            0x80u,
            eSetBits,
            &higher_priority_task_woken
        );

        portYIELD_FROM_ISR(higher_priority_task_woken);
    }

    return higher_priority_task_woken;
}


/*
 * Get the currently active DMA RX buffer.
 *
 * This is used when software explicitly prepares a DMA transfer.
 */
pqc_status_t dma_stream_bridge_get_rx_buffer(
    dma_stream_bridge_t* bridge,
    uint8_t** buffer_out,
    uint16_t* max_len)
{
    if (bridge == NULL ||
        buffer_out == NULL ||
        max_len == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    const uint8_t idx = bridge->active_idx;

    if (bridge->chunks[idx].state != DMA_STREAM_BUF_STATE_FREE) {
        return ERR_DMA_BUSY;
    }

    *buffer_out = bridge->chunks[idx].buffer;
    *max_len = DMA_BUFFER_BYTES;

    /*
     * The buffer remains logically owned by DMA until completion.
     * The DMA completion ISR transitions it to FULL.
     */
    return PQC_SUCCESS;
}


/*
 * Submit a completed DMA buffer from software.
 *
 * Kept for transports that complete DMA through task context rather
 * than the hardware ISR path.
 */
pqc_status_t dma_stream_bridge_submit_buffer(
    dma_stream_bridge_t* bridge,
    uint16_t length)
{
    if (bridge == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    if (length == 0u || length > DMA_BUFFER_BYTES) {
        return ERR_CHUNK_TOO_LARGE;
    }

    const uint8_t idx = bridge->active_idx;

    if (bridge->chunks[idx].state != DMA_STREAM_BUF_STATE_FREE) {
        bridge->chunks_dropped++;
        return ERR_DMA_BUSY;
    }

    bridge->chunks[idx].length = length;
    bridge->chunks[idx].chunk_index = bridge->chunk_sequence++;
    bridge->chunks[idx].timestamp = xTaskGetTickCount();
    bridge->chunks[idx].state = DMA_STREAM_BUF_STATE_FULL;

    bridge->active_idx ^= 1u;

    return PQC_SUCCESS;
}


/*
 * Get the next completed DMA buffer.
 *
 * This function is called from the stream task.
 */
pqc_status_t dma_stream_bridge_get_chunk(
    dma_stream_bridge_t* bridge,
    uint8_t** data_out,
    uint16_t* length_out,
    uint16_t* chunk_index,
    uint32_t timeout_ms)
{
    if (bridge == NULL ||
        data_out == NULL ||
        length_out == NULL ||
        chunk_index == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    /*
     * A zero timeout means "use the bridge's configured timeout".
     */
    const uint32_t effective_timeout_ms =
        (timeout_ms != 0u)
            ? timeout_ms
            : bridge->chunk_timeout_ms;

    const TickType_t timeout_ticks =
        pdMS_TO_TICKS(effective_timeout_ms);

    const TickType_t start_tick =
        xTaskGetTickCount();

    for (;;) {

        /*
         * Prefer the current processing index, then inspect the
         * other ping-pong buffer. This prevents a FULL buffer from
         * being missed simply because the other buffer was processed
         * previously.
         */
        uint8_t idx = bridge->processing_idx;

        if (bridge->chunks[idx].state != DMA_STREAM_BUF_STATE_FULL) {
            idx ^= 1u;
        }

        if (bridge->chunks[idx].state == DMA_STREAM_BUF_STATE_FULL) {

            *data_out = bridge->chunks[idx].buffer;
            *length_out = bridge->chunks[idx].length;
            *chunk_index = bridge->chunks[idx].chunk_index;

            /*
             * Transfer ownership from the DMA/producer side to the
             * stream-processing side.
             */
            bridge->chunks[idx].state =
                DMA_STREAM_BUF_STATE_PROCESSING;

            /*
             * Next lookup starts with the other ping-pong buffer.
             */
            bridge->processing_idx = idx ^ 1u;

            bridge->chunks_processed++;

            return PQC_SUCCESS;
        }

        /*
         * Correct timeout calculation:
         *
         * elapsed = current_tick - start_tick
         *
         * The previous implementation subtracted the current tick
         * from itself, which always produced zero.
         */
        const TickType_t current_tick =
            xTaskGetTickCount();

        const TickType_t elapsed =
            current_tick - start_tick;

        if (elapsed >= timeout_ticks) {
            return ERR_NETWORK_TIMEOUT;
        }

        /*
         * Do not sleep longer than the remaining timeout.
         */
        TickType_t wait_ticks =
            pdMS_TO_TICKS(10u);

        const TickType_t remaining =
            timeout_ticks - elapsed;

        if (wait_ticks > remaining) {
            wait_ticks = remaining;
        }

        /*
         * A zero-tick wait would otherwise create a busy loop.
         */
        if (wait_ticks == 0u) {
            return ERR_NETWORK_TIMEOUT;
        }

        (void)ulTaskNotifyTake(
            pdTRUE,
            wait_ticks
        );
    }
}


/*
 * Release a buffer after stream processing.
 */
pqc_status_t dma_stream_bridge_release_buffer(
    dma_stream_bridge_t* bridge,
    uint8_t buffer_index)
{
    if (bridge == NULL || buffer_index >= 2u) {
        return ERR_INVALID_ARGUMENT;
    }

    uint8_t idx = buffer_index;

    /*
     * The current stream task calls this API with buffer index 0.
     * If that is not the buffer actually being processed, locate the
     * processing buffer safely rather than freeing the wrong buffer.
     */
    if (bridge->chunks[idx].state != DMA_STREAM_BUF_STATE_PROCESSING) {
        const uint8_t other_idx = idx ^ 1u;

        if (bridge->chunks[other_idx].state ==
            DMA_STREAM_BUF_STATE_PROCESSING) {
            idx = other_idx;
        } else {
            return ERR_INVALID_STATE;
        }
    }

    /*
     * Sensitive model data must not remain in a released DMA buffer.
     */
    crypto_zeroize(
        bridge->chunks[idx].buffer,
        DMA_BUFFER_BYTES
    );

    bridge->chunks[idx].length = 0u;
    bridge->chunks[idx].chunk_index = 0u;
    bridge->chunks[idx].timestamp = 0u;
    bridge->chunks[idx].state = DMA_STREAM_BUF_STATE_FREE;

    return PQC_SUCCESS;
}


/*
 * Get bridge statistics.
 */
pqc_status_t dma_stream_bridge_get_stats(
    dma_stream_bridge_t* bridge,
    uint16_t* chunks_processed,
    uint16_t* chunks_dropped)
{
    if (bridge == NULL ||
        chunks_processed == NULL ||
        chunks_dropped == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    *chunks_processed = bridge->chunks_processed;
    *chunks_dropped = bridge->chunks_dropped;

    return PQC_SUCCESS;
}


/*
 * Reset the bridge to its initial state.
 */
pqc_status_t dma_stream_bridge_reset(
    dma_stream_bridge_t* bridge)
{
    if (bridge == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    bridge->active_idx = 0u;
    bridge->processing_idx = 0u;
    bridge->chunk_sequence = 0u;
    bridge->chunks_dropped = 0u;
    bridge->chunks_processed = 0u;

    for (uint8_t i = 0u; i < 2u; i++) {
        bridge->chunks[i].length = 0u;
        bridge->chunks[i].chunk_index = 0u;
        bridge->chunks[i].timestamp = 0u;
        bridge->chunks[i].state = DMA_STREAM_BUF_STATE_FREE;
    }

    /*
     * Clear both DMA RX buffers so no previous model data survives
     * a bridge reset.
     */
    dma_double_buffer_t* dma_rx = scratch_get_dma_rx();

    crypto_zeroize(
        dma_rx->ping,
        DMA_BUFFER_BYTES
    );

    crypto_zeroize(
        dma_rx->pong,
        DMA_BUFFER_BYTES
    );

    return PQC_SUCCESS;
}