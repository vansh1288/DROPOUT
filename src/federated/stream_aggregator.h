#ifndef STREAM_AGGREGATOR_H
#define STREAM_AGGREGATOR_H

#include "protocol_types.h"
#include "memory_scratchpad.h"
#include "dma_stream_bridge.h"

#include <stdint.h>
#include <stddef.h>

#ifdef TEST_BUILD
#include "freertos_mock.h"
#else
#include "FreeRTOS.h"
#include "task.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/* Stream work operations */
#define STREAM_OP_PROCESS 1u
#define STREAM_OP_UNMASK  2u

/* Valid chunk sizes in bytes */
#define STREAM_CHUNK_SIZE_MIN       64u
#define STREAM_CHUNK_SIZE_MAX       1024u
#define STREAM_CHUNK_SIZE_DEFAULT   256u

#define STREAM_CHUNK_SIZE_64        64u
#define STREAM_CHUNK_SIZE_128       128u
#define STREAM_CHUNK_SIZE_256       256u
#define STREAM_CHUNK_SIZE_512       512u
#define STREAM_CHUNK_SIZE_1024      1024u

/*
 * Maximum number of chunks for a 1 MiB model
 * when using the minimum 64-byte chunk size.
 */
#define STREAM_MAX_CHUNKS \
    (1024u * 1024u / STREAM_CHUNK_SIZE_MIN)

/* Stream aggregator state */
typedef enum {
    STREAM_STATE_IDLE        = 0,
    STREAM_STATE_RECEIVING   = 1,
    STREAM_STATE_AGGREGATING = 2,
    STREAM_STATE_COMPLETE    = 3,
    STREAM_STATE_ERROR       = 0xFF
} stream_state_t;

/* Chunk validation result */
typedef enum {
    CHUNK_VALID          = 0,
    CHUNK_DUPLICATE      = 1,
    CHUNK_OUT_OF_ORDER   = 2,
    CHUNK_INVALID_SIZE   = 3,
    CHUNK_INVALID_ROUND  = 4,
    CHUNK_INVALID_CLIENT = 5
} chunk_validation_t;

/*
 * Work item submitted to the stream aggregator task.
 *
 * NOTE:
 * shared_secret remains a pointer for API compatibility.
 * Its lifetime must cover queue processing.
 */
typedef struct {
    uint8_t op;
    uint8_t client_id;
    uint32_t round_id;
    uint16_t chunk_index;
    uint16_t chunk_size;
    const uint8_t* shared_secret;
} stream_work_item_t;

/* Chunk metadata for tracking */
typedef struct {
    uint16_t chunk_index;
    uint16_t chunk_size;
    uint32_t round_id;
    uint8_t client_id;
    uint32_t received_tick;
    uint8_t is_final;
} chunk_metadata_t;

/*
 * Aggregation context.
 *
 * The implementation uses a bounded scratch accumulator rather than
 * allocating a full model-sized receive buffer.
 */
typedef struct {
    /* Optional externally managed accumulator metadata */
    int16_t* accumulator;
    size_t accumulator_size;
    size_t element_count;

    /* Chunk tracking */
    chunk_metadata_t* chunks_received;
    uint16_t chunks_received_count;
    uint16_t expected_chunks;
    uint16_t expected_chunk_size;

    /* Round/session context */
    uint32_t current_round_id;
    uint8_t current_client_id;
    uint16_t total_chunks_expected;
    uint16_t chunk_size;

    /* State */
    stream_state_t state;
    chunk_validation_t last_validation;
    uint32_t last_activity_tick;

    /*
     * Bounded-memory accumulator scratch.
     *
     * Maximum supported chunk size is 1024 bytes, so this provides
     * 512 int16_t elements.
     */
    int16_t chunk_accumulator[CHUNK_BUFFER_BYTES / sizeof(int16_t)];

    /*
     * Duplicate-detection bitmap.
     *
     * STREAM_MAX_CHUNKS = 16384, therefore this is 2048 bytes.
     */
    uint8_t chunk_bitmap[(STREAM_MAX_CHUNKS + 7u) / 8u];

} stream_aggregator_ctx_t;

/* Queue configuration */
#define STREAM_QUEUE_LENGTH    8u
#define STREAM_QUEUE_ITEM_SIZE sizeof(stream_work_item_t)

/* Task and queue management */
void stream_aggregator_init(void);
TaskHandle_t stream_aggregator_get_task_handle(void);
BaseType_t stream_aggregator_submit(
    const stream_work_item_t* item,
    TickType_t timeout
);

/* Processing APIs */
pqc_status_t stream_aggregator_process_chunk(
    uint8_t client_id,
    uint32_t round_id,
    uint16_t chunk_index,
    uint16_t chunk_size,
    const uint8_t* shared_secret
);

pqc_status_t stream_aggregator_unmask_chunk(
    uint8_t client_id,
    uint32_t round_id,
    uint16_t chunk_index,
    uint16_t chunk_size,
    const uint8_t* shared_secret
);

pqc_status_t stream_aggregator_process_dma_data(
    uint8_t client_id,
    uint32_t round_id,
    uint16_t chunk_index,
    uint16_t chunk_size,
    const uint8_t* shared_secret
);

/* DMA bridge access */
dma_stream_bridge_t* stream_aggregator_get_dma_bridge(void);

/* Bounded-memory streaming aggregation */
pqc_status_t stream_aggregator_start_session(
    uint32_t round_id,
    uint8_t client_id,
    uint16_t chunk_size,
    uint16_t total_chunks
);

pqc_status_t stream_aggregator_receive_chunk(
    uint16_t chunk_index,
    const uint8_t* masked_chunk,
    uint16_t chunk_size,
    uint32_t round_id,
    uint8_t client_id,
    const uint8_t* shared_secret
);

pqc_status_t stream_aggregator_finalize_session(
    int16_t* output_accumulator,
    size_t* output_size
);

pqc_status_t stream_aggregator_reset(void);

/* Validation */
chunk_validation_t stream_aggregator_validate_chunk(
    uint16_t chunk_index,
    uint16_t chunk_size,
    uint32_t round_id,
    uint8_t client_id
);

pqc_status_t stream_aggregator_check_duplicate(
    uint16_t chunk_index
);

pqc_status_t stream_aggregator_validate_chunk_size(
    uint16_t chunk_size
);

/* Statistics and utilities */
void stream_aggregator_get_stats(
    uint8_t* chunks_received,
    uint8_t* total_expected,
    stream_state_t* state
);

void stream_aggregator_zeroize_accumulator(void);

#ifdef __cplusplus
}
#endif

#endif /* STREAM_AGGREGATOR_H */