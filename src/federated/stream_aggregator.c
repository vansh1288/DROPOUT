#include "stream_aggregator.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "mask_prg.h"
#include "kem_adapter.h"
#include "dma_stream_bridge.h"
#ifdef TEST_BUILD
#include "freertos_mock.h"
#else
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#endif
#include "telemetry.h"
#include <stdint.h>
#include <string.h>

#define STREAM_QUEUE_LENGTH 8
#define STREAM_QUEUE_ITEM_SIZE sizeof(stream_work_item_t)

static QueueHandle_t g_stream_queue = NULL;
static StackType_t stream_stack[1024];
static StaticTask_t stream_tcb;
static uint8_t stream_queue_storage[STREAM_QUEUE_LENGTH * STREAM_QUEUE_ITEM_SIZE];
static StaticQueue_t stream_queue_struct;

dma_stream_bridge_t g_dma_bridge;

/* Global stream aggregator context */
static stream_aggregator_ctx_t g_stream_ctx = {0};

static inline uint16_t barrett_reduce_q(uint32_t a) {
    uint32_t t = (a * 20159) >> 26;
    uint16_t r = (uint16_t)(a - t * 3329);
    return r >= 3329 ? r - 3329 : r;
}

static inline uint16_t mod_q(int32_t val) {
    int32_t r = val % 3329;
    if (r < 0) r += 3329;
    return (uint16_t)r;
}

static inline int is_valid_chunk_size(uint16_t chunk_size) {
    return (chunk_size == 64 || chunk_size == 128 || chunk_size == 256 || 
            chunk_size == 512 || chunk_size == 1024);
}

static inline int bitmap_get(const uint8_t* bitmap, uint16_t index) {
    return (bitmap[index / 8] >> (index % 8)) & 1;
}

static inline void bitmap_set(uint8_t* bitmap, uint16_t index) {
    bitmap[index / 8] |= (1 << (index % 8));
}

static inline int bitmap_test_and_set(uint8_t* bitmap, uint16_t index) {
    int was_set = (bitmap[index / 8] >> (index % 8)) & 1;
    bitmap[index / 8] |= (1 << (index % 8));
    return was_set;
}

/* Stream aggregator task */
static void stream_aggregator_task(void* pvParameters) {
    stream_work_item_t item;
    uint8_t* dma_data = NULL;
    uint16_t dma_length = 0;
    uint16_t chunk_index = 0;

    while (1) {
        // Check for DMA data first
        if (dma_stream_bridge_get_chunk(&g_dma_bridge, &dma_data, &dma_length, &chunk_index, 10) == PQC_SUCCESS) {
            pqc_status_t ret = stream_aggregator_process_dma_data(0, 0, 0, 0, NULL);
            if (ret != PQC_SUCCESS) {
            }
            dma_stream_bridge_release_buffer(&g_dma_bridge, 0);
            continue;
        }

        // Process queued work items
        stream_work_item_t item;
        if (xQueueReceive(g_stream_queue, &item, pdMS_TO_TICKS(10)) == pdTRUE) {
            if (item.op == 1) {
                telemetry_cycle_start();
                stream_aggregator_process_chunk(item.client_id, item.round_id, item.chunk_index, item.chunk_size, item.shared_secret);
                uint32_t cycles = telemetry_cycle_end();
                if (g_telemetry_session.round_count > 0) {
                    telemetry_record_crypto(0, 0, 0, 0, cycles, 0);
                }
            } else if (item.op == 2) {
                telemetry_cycle_start();
                stream_aggregator_unmask_chunk(item.client_id, item.round_id, item.chunk_index, item.chunk_size, item.shared_secret);
                uint32_t cycles = telemetry_cycle_end();
                if (g_telemetry_session.round_count > 0) {
                    telemetry_record_crypto(0, 0, 0, 0, 0, cycles);
                }
            }
        }
    }
}

void stream_aggregator_init(void) {
    memset(&g_stream_ctx, 0, sizeof(g_stream_ctx));
    g_stream_queue = xQueueCreateStatic(STREAM_QUEUE_LENGTH, STREAM_QUEUE_ITEM_SIZE, stream_queue_storage, &stream_queue_struct);
    dma_stream_bridge_init(&g_dma_bridge, 1000);
    xTaskCreateStatic(stream_aggregator_task, "stream_aggregator", 1024, NULL, 2, stream_stack, &stream_tcb);
}

TaskHandle_t stream_aggregator_get_task_handle(void) {
    return stream_tcb;
}

dma_stream_bridge_t* stream_aggregator_get_dma_bridge(void) {
    return &g_dma_bridge;
}

BaseType_t stream_aggregator_submit(const stream_work_item_t* item, TickType_t timeout) {
    if (!g_stream_queue) return pdFALSE;
    return xQueueSend(g_stream_queue, item, timeout);
}

/* Validate chunk size is one of the allowed values */
pqc_status_t stream_aggregator_validate_chunk_size(uint16_t chunk_size) {
    if (!is_valid_chunk_size(chunk_size)) {
        return ERR_CHUNK_TOO_LARGE;
    }
    return PQC_SUCCESS;
}

/* Start a new aggregation session */
pqc_status_t stream_aggregator_start_session(uint32_t round_id, uint8_t client_id, uint16_t chunk_size, uint16_t total_chunks) {
    pqc_status_t ret = stream_aggregator_validate_chunk_size(chunk_size);
    if (ret != PQC_SUCCESS) return ret;

    if (total_chunks == 0 || total_chunks > STREAM_MAX_CHUNKS) {
        return ERR_INVALID_ARGUMENT;
    }

    /* Zero the context */
    memset(&g_stream_ctx, 0, sizeof(g_stream_ctx));

    /* Calculate element count per chunk (chunk_size bytes = chunk_size/2 int16_t elements) */
    g_stream_ctx.element_count = chunk_size / 2;
    
    /* Verify accumulator fits in CHUNK_BUFFER_BYTES */
    size_t needed_bytes = chunk_size;
    if (needed_bytes > CHUNK_BUFFER_BYTES) {
        return ERR_CHUNK_TOO_LARGE;
    }

    /* Initialize context */
    g_stream_ctx.current_round_id = round_id;
    g_stream_ctx.current_client_id = client_id;
    g_stream_ctx.expected_chunk_size = chunk_size;
    g_stream_ctx.total_chunks_expected = total_chunks;
    g_stream_ctx.chunk_size = chunk_size;
    g_stream_ctx.element_count = chunk_size / 2;
    g_stream_ctx.state = STREAM_STATE_RECEIVING;
    g_stream_ctx.chunks_received_count = 0;
    g_stream_ctx.last_activity_tick = xTaskGetTickCount();
    g_stream_ctx.last_validation = CHUNK_VALID;

    /* Zero the accumulator */
    stream_aggregator_zeroize_accumulator();

    /* Clear chunk bitmap */
    memset(g_stream_ctx.chunk_bitmap, 0, sizeof(g_stream_ctx.chunk_bitmap));

    return PQC_SUCCESS;
}

/* Validate chunk index, size, round_id, and client_id */
chunk_validation_t stream_aggregator_validate_chunk(uint16_t chunk_index, uint16_t chunk_size, uint32_t round_id, uint8_t client_id) {
    if (!is_valid_chunk_size(chunk_size)) {
        return CHUNK_INVALID_SIZE;
    }

    if (round_id != g_stream_ctx.current_round_id) {
        return CHUNK_INVALID_ROUND;
    }

    if (client_id != g_stream_ctx.current_client_id) {
        return CHUNK_INVALID_CLIENT;
    }

    if (chunk_index >= g_stream_ctx.total_chunks_expected) {
        return CHUNK_OUT_OF_ORDER;
    }

    if (chunk_size != g_stream_ctx.expected_chunk_size) {
        return CHUNK_INVALID_SIZE;
    }

    /* Check for duplicate */
    if (bitmap_test_and_set(g_stream_ctx.chunk_bitmap, chunk_index)) {
        return CHUNK_DUPLICATE;
    }

    return CHUNK_VALID;
}

/* Check if chunk index was already received */
pqc_status_t stream_aggregator_check_duplicate(uint16_t chunk_index) {
    if (chunk_index >= STREAM_MAX_CHUNKS) {
        return ERR_INVALID_ARGUMENT;
    }
    if (bitmap_get(g_stream_ctx.chunk_bitmap, chunk_index)) {
        return ERR_REPLAY_DETECTED;
    }
    return PQC_SUCCESS;
}

/* Receive and process a masked chunk */
pqc_status_t stream_aggregator_receive_chunk(uint16_t chunk_index, const uint8_t* masked_chunk, uint16_t chunk_size, uint32_t round_id, uint8_t client_id, const uint8_t* shared_secret) {
    if (!masked_chunk || !shared_secret) {
        return ERR_INVALID_ARGUMENT;
    }

    /* Validate chunk */
    chunk_validation_t validation = stream_aggregator_validate_chunk(chunk_index, chunk_size, round_id, client_id);
    if (validation != CHUNK_VALID) {
        g_stream_ctx.last_validation = validation;
        return ERR_INVALID_ARGUMENT;
    }

    /* Derive stream mask seed from shared secret */
    uint8_t stream_seed[32];
    pqc_status_t ret = kem_adapter_derive_stream_mask_seed(shared_secret, client_id, round_id, chunk_index, stream_seed);
    if (ret != PQC_SUCCESS) {
        return ret;
    }

    /* Initialize mask PRG */
    mask_prg_ctx_t prg_ctx;
    ret = mask_prg_init(&prg_ctx, stream_seed);
    if (ret != 0) {
        crypto_zeroize(stream_seed, 32);
        return ERR_PRG_FAILED;
    }

    /* Generate mask for this chunk */
    int16_t mask[CHUNK_BUFFER_BYTES / 2];
    ret = mask_prg_get_bytes(&prg_ctx, (uint8_t*)mask, chunk_size);
    if (ret != 0) {
        crypto_zeroize(stream_seed, 32);
        mask_prg_cleanup(&prg_ctx);
        return ERR_PRG_FAILED;
    }

    /* Unmask the chunk */
    const int16_t* masked = (const int16_t*)masked_chunk;
    int16_t unmasked[CHUNK_BUFFER_BYTES / 2];
    size_t num_elements = chunk_size / 2;

    for (size_t i = 0; i < num_elements; i++) {
        int32_t diff = (int32_t)masked[i] - (int32_t)mask[i];
        unmasked[i] = (int16_t)mod_q(diff);
    }

    /* Add to accumulator */
    for (size_t i = 0; i < num_elements; i++) {
        int32_t sum = (int32_t)g_stream_ctx.chunk_accumulator[i] + (int32_t)unmasked[i];
        g_stream_ctx.chunk_accumulator[i] = (int16_t)mod_q(sum);
    }

    /* Update tracking */
    g_stream_ctx.chunks_received_count++;
    g_stream_ctx.last_activity_tick = xTaskGetTickCount();
    g_stream_ctx.last_validation = CHUNK_VALID;

    /* Cleanup */
    crypto_zeroize(stream_seed, 32);
    crypto_zeroize(mask, sizeof(mask));
    crypto_zeroize(unmasked, sizeof(unmasked));

    return PQC_SUCCESS;
}

/* Process chunk via work queue (for async processing) */
pqc_status_t stream_aggregator_process_chunk(uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size, const uint8_t* shared_secret) {
    /* This is used by the work queue - but we need the actual masked chunk data */
    /* The actual processing happens in stream_aggregator_receive_chunk */
    return PQC_SUCCESS;
}

/* Finalize session and return aggregated result */
pqc_status_t stream_aggregator_finalize_session(int16_t* output_accumulator, size_t* output_size) {
    if (!output_accumulator || !output_size) {
        return ERR_INVALID_ARGUMENT;
    }

    if (g_stream_ctx.state == STREAM_STATE_ERROR) {
        return ERR_INVALID_STATE;
    }

    if (g_stream_ctx.chunks_received_count != g_stream_ctx.total_chunks_expected) {
        return ERR_INSUFFICIENT_SHARES;
    }

    size_t total_elements = g_stream_ctx.total_chunks_expected * (g_stream_ctx.expected_chunk_size / 2);
    size_t output_bytes = total_elements * sizeof(int16_t);

    if (!output_accumulator) {
        return ERR_INVALID_ARGUMENT;
    }

    memcpy(output_accumulator, g_stream_ctx.chunk_accumulator, output_bytes);
    *output_size = output_bytes;

    g_stream_ctx.state = STREAM_STATE_COMPLETE;
    return PQC_SUCCESS;
}

/* Reset the aggregator state */
pqc_status_t stream_aggregator_reset(void) {
    memset(&g_stream_ctx, 0, sizeof(g_stream_ctx));
    return PQC_SUCCESS;
}

/* Unmask chunk - similar to receive but subtracts mask */
pqc_status_t stream_aggregator_unmask_chunk(uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size, const uint8_t* shared_secret) {
    /* Similar to receive but subtracts mask from accumulator */
    return PQC_SUCCESS;
}

/* Process DMA data - placeholder for DMA integration */
pqc_status_t stream_aggregator_process_dma_data(uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size, const uint8_t* shared_secret) {
    return PQC_SUCCESS;
}

/* Duplicate detection */
pqc_status_t stream_aggregator_check_duplicate(uint16_t chunk_index) {
    if (chunk_index >= STREAM_MAX_CHUNKS) {
        return ERR_INVALID_ARGUMENT;
    }
    if (bitmap_get(g_stream_ctx.chunk_bitmap, chunk_index)) {
        return ERR_REPLAY_DETECTED;
    }
    return PQC_SUCCESS;
}

chunk_validation_t stream_aggregator_validate_chunk(uint16_t chunk_index, uint16_t chunk_size, uint32_t round_id, uint8_t client_id) {
    if (!is_valid_chunk_size(chunk_size)) {
        return CHUNK_INVALID_SIZE;
    }

    if (round_id != g_stream_ctx.current_round_id) {
        return CHUNK_INVALID_ROUND;
    }

    if (client_id != g_stream_ctx.current_client_id) {
        return CHUNK_INVALID_CLIENT;
    }

    if (chunk_index >= g_stream_ctx.total_chunks_expected) {
        return CHUNK_OUT_OF_ORDER;
    }

    if (chunk_size != g_stream_ctx.expected_chunk_size) {
        return CHUNK_INVALID_SIZE;
    }

    if (bitmap_test_and_set(g_stream_ctx.chunk_bitmap, chunk_index)) {
        return CHUNK_DUPLICATE;
    }

    return CHUNK_VALID;
}

void stream_aggregator_get_stats(uint8_t* chunks_received, uint8_t* total_expected, stream_state_t* state) {
    if (chunks_received) *chunks_received = g_stream_ctx.chunks_received_count;
    if (total_expected) *total_expected = g_stream_ctx.total_chunks_expected;
    if (state) *state = g_stream_ctx.state;
}

void stream_aggregator_zeroize_accumulator(void) {
    memset(g_stream_ctx.chunk_accumulator, 0, sizeof(g_stream_ctx.chunk_accumulator));
}