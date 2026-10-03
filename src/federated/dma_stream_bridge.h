#ifndef DMA_STREAM_BRIDGE_H
#define DMA_STREAM_BRIDGE_H

#include "protocol_types.h"
#include <stdint.h>
#include <stddef.h>

#ifdef TEST_BUILD
typedef long BaseType_t;
#define pdFALSE ((BaseType_t)0)
#define pdTRUE ((BaseType_t)1)
#else
#include "FreeRTOS.h"
#include "task.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * DMA Stream Bridge - bridges DMA RX ISR to stream aggregator task
 *
 * Provides a thread-safe bridge between DMA RX ISR and the stream aggregator task.
 * Implements ping-pong buffer ownership tracking and proper synchronization.
 */

#define DMA_STREAM_MAX_CHUNKS_PER_BUFFER (DMA_BUFFER_BYTES / 2)  // 768 int16_t elements

typedef enum {
    DMA_STREAM_BUF_STATE_FREE     = 0,  // Buffer available for DMA RX
    DMA_STREAM_BUF_STATE_FULL     = 1,  // Buffer filled by DMA, ready for processing
    DMA_STREAM_BUF_STATE_PROCESSING = 2, // Being processed by stream task
    DMA_STREAM_BUF_STATE_ERROR    = 3   // Error state
} dma_stream_buf_state_t;

typedef struct {
    uint8_t* buffer;                    // Pointer to buffer data
    uint16_t length;                    // Valid data length in bytes
    uint16_t chunk_index;               // Chunk sequence number
    dma_stream_buf_state_t state;       // Buffer state
    uint32_t timestamp;                 // Timestamp when filled (tick count)
} dma_stream_chunk_t;

typedef struct {
    dma_stream_chunk_t chunks[2];       // Ping-pong buffers
    volatile uint8_t active_idx;        // Index of buffer currently being filled by DMA (0 or 1)
    volatile uint8_t processing_idx;    // Index of buffer being processed
    volatile uint16_t chunk_sequence;   // Monotonically increasing chunk sequence number
    volatile uint16_t chunks_dropped;   // Count of dropped chunks
    volatile uint16_t chunks_processed; // Count of successfully processed chunks
    uint32_t chunk_timeout_ms;          // Timeout for chunk processing (ms)
} dma_stream_bridge_t;

/**
 * Initialize the DMA stream bridge
 * @param bridge Pointer to bridge structure to initialize
 * @param timeout_ms Timeout for chunk processing in milliseconds
 * @return PQC_SUCCESS on success, error code on failure
 */
pqc_status_t dma_stream_bridge_init(dma_stream_bridge_t* bridge, uint32_t timeout_ms);

/**
 * Called from DMA RX complete ISR when a buffer is filled
 * @param bridge Pointer to bridge structure
 * @param length Actual bytes received
 * @return pdTRUE if a task was woken, pdFALSE otherwise
 * @note Must be called from ISR context only
 */
BaseType_t dma_stream_bridge_rx_complete_isr(dma_stream_bridge_t* bridge, uint16_t length);

/**
 * Called from DMA error ISR
 * @param bridge Pointer to bridge structure
 * @return pdTRUE if a task was woken, pdFALSE otherwise
 * @note Must be called from ISR context only
 */
BaseType_t dma_stream_bridge_error_isr(dma_stream_bridge_t* bridge);

/**
 * Get the next available buffer for DMA RX
 * @param bridge Pointer to bridge structure
 * @param buffer_out Output pointer to buffer address
 * @param max_len Maximum length that can be received
 * @return PQC_SUCCESS on success, error code otherwise
 * @note Must be called from task context
 */
pqc_status_t dma_stream_bridge_get_rx_buffer(dma_stream_bridge_t* bridge, uint8_t** buffer_out, uint16_t* max_len);

/**
 * Mark a buffer as filled and ready for processing
 * @param bridge Pointer to bridge structure
 * @param length Actual data length received
 * @return PQC_SUCCESS on success, error code otherwise
 * @note Called from ISR context after DMA transfer completes
 */
pqc_status_t dma_stream_bridge_submit_buffer(dma_stream_bridge_t* bridge, uint16_t length);

/**
 * Get the next filled buffer for processing
 * @param bridge Pointer to bridge structure
 * @param chunk_out Output chunk structure
 * @param timeout_ms Timeout in milliseconds
 * @return PQC_SUCCESS on success, ERR_NETWORK_TIMEOUT on timeout
 * @note Called from stream task context
 */
pqc_status_t dma_stream_bridge_get_chunk(dma_stream_bridge_t* bridge, uint8_t** data_out, uint16_t* length_out, uint16_t* chunk_index, uint32_t timeout_ms);

/**
 * Release a buffer back to the free pool after processing
 * @param bridge Pointer to bridge structure
 * @param buffer_index Index of buffer to release (0 or 1)
 * @return PQC_SUCCESS on success, error code otherwise
 * @note Called from stream task context after processing
 */
pqc_status_t dma_stream_bridge_release_buffer(dma_stream_bridge_t* bridge, uint8_t buffer_index);

/**
 * Get bridge statistics
 * @param bridge Pointer to bridge structure
 * @param chunks_processed Output: number of chunks processed
 * @param chunks_dropped Output: number of chunks dropped
 * @return PQC_SUCCESS
 */
pqc_status_t dma_stream_bridge_get_stats(dma_stream_bridge_t* bridge, uint16_t* chunks_processed, uint16_t* chunks_dropped);

/**
 * Reset the bridge to initial state
 * @param bridge Pointer to bridge structure
 * @return PQC_SUCCESS
 */
pqc_status_t dma_stream_bridge_reset(dma_stream_bridge_t* bridge);

#ifdef __cplusplus
}
#endif

#endif // DMA_STREAM_BRIDGE_H