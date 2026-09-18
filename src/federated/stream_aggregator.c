#include "stream_aggregator.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "mask_prg.h"
#include "kem_adapter.h"
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "telemetry.h"
#include <stdint.h>

#define STREAM_QUEUE_LENGTH 8
#define STREAM_QUEUE_ITEM_SIZE sizeof(stream_work_item_t)

static QueueHandle_t g_stream_queue = NULL;
static StackType_t stream_stack[1024];
static StaticTask_t stream_tcb;
static uint8_t stream_queue_storage[STREAM_QUEUE_LENGTH * STREAM_QUEUE_ITEM_SIZE];
static StaticQueue_t stream_queue_struct;

static inline uint16_t barrett_reduce_q(uint32_t a) {
    uint32_t t = (a * 20159) >> 26;
    uint16_t r = (uint16_t)(a - t * 3329);
    return r >= 3329 ? r - 3329 : r;
}

void stream_aggregator_init(void) {
    g_stream_queue = xQueueCreateStatic(STREAM_QUEUE_LENGTH, STREAM_QUEUE_ITEM_SIZE, stream_queue_storage, &stream_queue_struct);
    xTaskCreateStatic(stream_aggregator_task, "stream_aggregator", 1024, NULL, 2, stream_stack, &stream_tcb);
}

TaskHandle_t stream_aggregator_get_task_handle(void) {
    return stream_tcb;
}

BaseType_t stream_aggregator_submit(const stream_work_item_t* item, TickType_t timeout) {
    if (!g_stream_queue) return pdFALSE;
    return xQueueSend(g_stream_queue, item, timeout);
}

static void stream_aggregator_task(void* pvParameters) {
    stream_work_item_t item;
    while (1) {
        if (xQueueReceive(g_stream_queue, &item, portMAX_DELAY) == pdTRUE) {
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

pqc_status_t stream_aggregator_process_chunk(uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size, const uint8_t* shared_secret) {
    if (chunk_size > 256) return ERR_CHUNK_TOO_LARGE;
    if (chunk_size % 2 != 0) return ERR_CHUNK_TOO_SMALL;

    chunk_buffer_t* chunk_buf = scratch_get_chunk_buf();
    dma_double_buffer_t* dma_tx = scratch_get_dma_tx();

    uint8_t stream_seed[32];
    pqc_status_t ret = kem_adapter_derive_stream_mask_seed(
        shared_secret, client_id, round_id, chunk_index, stream_seed
    );
    if (ret != PQC_SUCCESS) return ret;

    mask_prg_init(stream_seed);
    int16_t mask[128];
    mask_prg_expand((uint8_t*)mask, chunk_size);

    int16_t* input = (int16_t*)chunk_buf->data;
    int16_t* output = (int16_t*)dma_tx->ping;
    size_t num_elements = chunk_size / 2;

    for (size_t i = 0; i < num_elements; i++) {
        int32_t sum = (int32_t)input[i] + (int32_t)mask[i];
        output[i] = (int16_t)barrett_reduce_q((uint32_t)sum);
    }

    crypto_zeroize(mask, sizeof(mask));
    crypto_zeroize(stream_seed, 32);
    return PQC_SUCCESS;
}

pqc_status_t stream_aggregator_unmask_chunk(uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size, const uint8_t* shared_secret) {
    if (chunk_size > 256) return ERR_CHUNK_TOO_LARGE;
    if (chunk_size % 2 != 0) return ERR_CHUNK_TOO_SMALL;

    chunk_buffer_t* chunk_buf = scratch_get_chunk_buf();
    dma_double_buffer_t* dma_tx = scratch_get_dma_tx();

    uint8_t stream_seed[32];
    pqc_status_t ret = kem_adapter_derive_stream_mask_seed(
        shared_secret, client_id, round_id, chunk_index, stream_seed
    );
    if (ret != PQC_SUCCESS) return ret;

    mask_prg_init(stream_seed);
    int16_t mask[128];
    mask_prg_expand((uint8_t*)mask, chunk_size);

    int16_t* input = (int16_t*)chunk_buf->data;
    int16_t* output = (int16_t*)dma_tx->ping;
    size_t num_elements = chunk_size / 2;

    for (size_t i = 0; i < num_elements; i++) {
        int32_t diff = (int32_t)input[i] - (int32_t)mask[i];
        output[i] = (int16_t)barrett_reduce_q((uint32_t)(diff + 3329));
    }

    crypto_zeroize(mask, sizeof(mask));
    crypto_zeroize(stream_seed, 32);
    return PQC_SUCCESS;
}
