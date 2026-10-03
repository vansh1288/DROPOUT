#ifndef STREAM_AGGREGATOR_H
#define STREAM_AGGREGATOR_H

#include "protocol_types.h"
#include "FreeRTOS.h"
#include <stdint.h>
#include <stddef.h>

#define STREAM_OP_PROCESS 1
#define STREAM_OP_UNMASK 2

/* Valid chunk sizes (bytes) */
#define STREAM_CHUNK_SIZE_MIN       64u
#define STREAM_CHUNK_SIZE_MAX       1024u
#define STREAM_CHUNK_SIZE_DEFAULT   256u

/* Valid chunk sizes: 64, 128, 256, 512, 1024 bytes */
#define STREAM_CHUNK_SIZE_64        64u
#define STREAM_CHUNK_SIZE_128       128u
#define STREAM_CHUNK_SIZE_256       256u
#define STREAM_CHUNK_SIZE_512       512u
#define STREAM_CHUNK_SIZE_1024      1024u

/* Maximum number of chunks per model (assuming max 1MB model with 64-byte chunks) */
#define STREAM_MAX_CHUNKS           (1024 * 1024 / STREAM_CHUNK_SIZE_MIN)

/* Stream aggregator state */
typedef enum {
    STREAM_STATE_IDLE       = 0,
    STREAM_STATE_RECEIVING  = 1,
    STREAM_STATE_AGGREGATING = 2,
    STREAM_STATE_COMPLETE   = 3,
    STREAM_STATE_ERROR      = 0xFF
} stream_state_t;

/* Chunk validation result */
typedef enum {
    CHUNK_VALID       = 0,
    CHUNK_DUPLICATE   = 1,
    CHUNK_OUT_OF_ORDER = 2,
    CHUNK_INVALID_SIZE = 3,
    CHUNK_INVALID_ROUND = 4,
    CHUNK_INVALID_CLIENT = 5
} chunk_validation_t;

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

/* Aggregation context - bounded memory, no full-model buffer */
typedef struct {
    /* Accumulator - pre-allocated, size = max model size / chunk_size * chunk_size */
    int16_t* accumulator;
    size_t accumulator_size;        /* Total size in int16_t elements */
    size_t element_count;           /* Number of elements per chunk */
    
    /* Chunk tracking */
    chunk_metadata_t* chunks_received;
    uint8_t chunks_received_count;
    uint8_t expected_chunks;
    uint16_t expected_chunk_size;
    
    /* Round/session context */
    uint32_t current_round_id;
    uint8_t current_client_id;
    uint16_t expected_chunk_size;
    uint8_t total_chunks_expected;
    uint8_t chunk_size;
    
    /* State */
    stream_state_t state;
    chunk_validation_t last_validation;
    uint32_t last_activity_tick;
    
    /* Accumulator scratch (reused for each chunk) */
    int16_t chunk_accumulator[CHUNK_BUFFER_BYTES / 2];
    
    /* Duplicate detection bitmap (up to 256 chunks) */
    uint8_t chunk_bitmap[STREAM_MAX_CHUNKS / 8];
} stream_aggregator_ctx_t;

/* Stream work item for queue */
#define STREAM_OP_PROCESS 1
#define STREAM_OP_UNMASK 2

typedef struct {
    uint8_t op;
    uint8_t client_id;
    uint32_t round_id;
    uint16_t chunk_index;
    uint16_t chunk_size;
    const uint8_t* shared_secret;
} stream_work_item_t;

/* External queue for submitting work to stream aggregator task */
#define STREAM_QUEUE_LENGTH 8
#define STREAM_QUEUE_ITEM_SIZE sizeof(stream_work_item_t)

void stream_aggregator_init(void);
TaskHandle_t stream_aggregator_get_task_handle(void);
BaseType_t stream_aggregator_submit(const stream_work_item_t* item, TickType_t timeout);
pqc_status_t stream_aggregator_process_chunk(uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size, const uint8_t* shared_secret);
pqc_status_t stream_aggregator_unmask_chunk(uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size, const uint8_t* shared_secret);
pqc_status_t stream_aggregator_process_dma_data(uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size, const uint8_t* shared_secret);
dma_stream_bridge_t* stream_aggregator_get_dma_bridge(void);

/* New public API for bounded-memory streaming aggregation */
pqc_status_t stream_aggregator_start_session(uint32_t round_id, uint8_t client_id, uint16_t chunk_size, uint16_t total_chunks);
pqc_status_t stream_aggregator_receive_chunk(uint16_t chunk_index, const uint8_t* masked_chunk, uint16_t chunk_size, uint32_t round_id, uint8_t client_id, const uint8_t* shared_secret);
pqc_status_t stream_aggregator_finalize_session(int16_t* output_accumulator, size_t* output_size);
pqc_status_t stream_aggregator_reset(void);

/* Validation functions */
chunk_validation_t stream_aggregator_validate_chunk(uint16_t chunk_index, uint16_t chunk_size, uint32_t round_id, uint8_t client_id);
pqc_status_t stream_aggregator_check_duplicate(uint16_t chunk_index);

/* Utility functions */
void stream_aggregator_get_stats(uint8_t* chunks_received, uint8_t* total_expected, stream_state_t* state);
pqc_status_t stream_aggregator_validate_chunk_size(uint16_t chunk_size);
void stream_aggregator_zeroize_accumulator(void);

#endif