
#ifndef DMA_STREAM_BRIDGE_H
#define DMA_STREAM_BRIDGE_H

#ifdef TEST_BUILD
typedef long BaseType_t;
#define pdFALSE ((BaseType_t)0)
#define pdTRUE  ((BaseType_t)1)
#else
#include "FreeRTOS.h"
#include "task.h"
extern "C" {
#endif

/*
 * DMA Stream Bridge
 *
 * Bridges DMA RX completion events to the stream aggregator task.
 * Tracks ping-pong buffer ownership and prevents a buffer from being
 * reused while the consumer is processing it.
 */

#define DMA_STREAM_MAX_CHUNKS_PER_BUFFER (DMA_BUFFER_BYTES / 2u)

typedef enum {
    DMA_STREAM_BUF_STATE_FREE       = 0,
    DMA_STREAM_BUF_STATE_FULL       = 1,
    DMA_STREAM_BUF_STATE_PROCESSING  = 2,
    DMA_STREAM_BUF_STATE_ERROR      = 3
} dma_stream_buf_state_t;

typedef struct {
    uint8_t* buffer;
    uint16_t length;
    uint16_t chunk_index;
    dma_stream_buf_state_t state;
    uint32_t timestamp;
} dma_stream_chunk_t;

typedef struct {
    dma_stream_chunk_t chunks[2];

    volatile uint8_t active_idx;
    volatile uint8_t processing_idx;
    volatile uint16_t chunk_sequence;
    volatile uint16_t chunks_dropped;
    volatile uint16_t chunks_processed;

    uint32_t chunk_timeout_ms;
} dma_stream_bridge_t;

/*
 * Initialize the DMA stream bridge.
 */
pqc_status_t dma_stream_bridge_init(
    dma_stream_bridge_t* bridge,
    uint32_t timeout_ms
);

/*
 * Notify the bridge that DMA RX completed.
 *
 * ISR context only.
 *
 * Returns pdTRUE if a task was woken, otherwise pdFALSE.
 */
BaseType_t dma_stream_bridge_rx_complete_isr(
    dma_stream_bridge_t* bridge,
    uint16_t length
);

/*
 * Notify the bridge of a DMA error.
 *
 * ISR context only.
 */
BaseType_t dma_stream_bridge_error_isr(
    dma_stream_bridge_t* bridge
);

/*
 * Get the currently active buffer available for DMA RX.
 *
 * The returned buffer remains owned by the producer/DMA until
 * completion is reported.
 */
pqc_status_t dma_stream_bridge_get_rx_buffer(
    dma_stream_bridge_t* bridge,
    uint8_t** buffer_out,
    uint16_t* max_len
);

/*
 * Submit a completed buffer through the software submission path.
 */
pqc_status_t dma_stream_bridge_submit_buffer(
    dma_stream_bridge_t* bridge,
    uint16_t length
);

/*
 * Get the next completed DMA buffer for processing.
 *
 * data_out:
 *     Receives the pointer to the completed buffer.
 *
 * length_out:
 *     Receives the valid payload length in bytes.
 *
 * chunk_index_out:
 *     Receives the chunk's sequence number.
 *
 * buffer_index_out:
 *     Receives the physical ping-pong buffer index: 0 or 1.
 *     This value must be passed to dma_stream_bridge_release_buffer().
 *
 * timeout_ms:
 *     Maximum wait time in milliseconds. Zero uses the configured
 *     bridge timeout.
 *
 * Task context only.
 */
pqc_status_t dma_stream_bridge_get_chunk(
    dma_stream_bridge_t* bridge,
    uint8_t** data_out,
    uint16_t* length_out,
    uint16_t* chunk_index_out,
    uint8_t* buffer_index_out,
    uint32_t timeout_ms
);

/*
 * Release the exact ping-pong buffer returned by get_chunk().
 *
 * The buffer is zeroized before being returned to the free pool.
 */
pqc_status_t dma_stream_bridge_release_buffer(
    dma_stream_bridge_t* bridge,
    uint8_t buffer_index
);

/*
 * Retrieve bridge statistics.
 */
pqc_status_t dma_stream_bridge_get_stats(
    dma_stream_bridge_t* bridge,
    uint16_t* chunks_processed,
    uint16_t* chunks_dropped
);

/*
 * Reset bridge state and clear DMA buffers.
 */
pqc_status_t dma_stream_bridge_reset(
    dma_stream_bridge_t* bridge
);

#ifdef __cplusplus
