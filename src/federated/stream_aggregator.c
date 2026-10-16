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
#include <stddef.h>
#include <string.h>
#include <limits.h>

#define STREAM_TASK_STACK_WORDS 1024u
#define STREAM_TASK_PRIORITY    2u
#define STREAM_MASK_SEED_SIZE   32u
#define STREAM_MODULUS          3329

static QueueHandle_t g_stream_queue = NULL;
static StackType_t stream_stack[STREAM_TASK_STACK_WORDS];
static StaticTask_t stream_tcb;
TaskHandle_t g_stream_task_handle = NULL;

static uint8_t stream_queue_storage[
    STREAM_QUEUE_LENGTH * sizeof(stream_work_item_t)
];
static StaticQueue_t stream_queue_struct;

dma_stream_bridge_t g_dma_bridge;
static stream_aggregator_ctx_t g_stream_ctx;
/* Caller-owned key material; must remain valid for the active DMA session. */
static const uint8_t *g_dma_shared_secret = NULL;
static uint16_t g_dma_session_sequence_base = 0u;

/* ------------------------------------------------------------------------- */
/* Helpers                                                                   */
/* ------------------------------------------------------------------------- */

static uint16_t mod_q(int32_t value)
{
    int32_t r = value % STREAM_MODULUS;
    if (r < 0) {
        r += STREAM_MODULUS;
    }
    return (uint16_t)r;
}

static int is_valid_chunk_size(uint16_t size)
{
    return size == STREAM_CHUNK_SIZE_64 ||
           size == STREAM_CHUNK_SIZE_128 ||
           size == STREAM_CHUNK_SIZE_256 ||
           size == STREAM_CHUNK_SIZE_512 ||
           size == STREAM_CHUNK_SIZE_1024;
}

static int bitmap_get(const uint8_t *bitmap, uint16_t index)
{
    return (bitmap[index / 8u] >> (index % 8u)) & 1u;
}

static void bitmap_set(uint8_t *bitmap, uint16_t index)
{
    bitmap[index / 8u] |= (uint8_t)(1u << (index % 8u));
}

/* Decode the wire representation explicitly; incoming data may be unaligned. */
static int16_t read_i16_le(const uint8_t *p)
{
    uint16_t v = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
    return (int16_t)v;
}

static void clear_session_data(void)
{
    crypto_zeroize(g_stream_ctx.chunk_accumulator,
                   sizeof(g_stream_ctx.chunk_accumulator));
    crypto_zeroize(g_stream_ctx.chunk_bitmap,
                   sizeof(g_stream_ctx.chunk_bitmap));
    g_stream_ctx.chunks_received_count = 0u;
    g_stream_ctx.last_activity_tick = 0u;
    g_stream_ctx.last_validation = CHUNK_VALID;
    g_stream_ctx.element_count = 0u;
}

static pqc_status_t derive_mask(
    const uint8_t *shared_secret,
    uint8_t client_id,
    uint32_t round_id,
    uint16_t chunk_index,
    uint16_t chunk_size,
    uint8_t *mask_bytes)
{
    uint8_t seed[STREAM_MASK_SEED_SIZE] = {0};
    mask_prg_ctx_t prg = {0};
    pqc_status_t status;

    if (shared_secret == NULL || mask_bytes == NULL ||
        chunk_size == 0u || (chunk_size % sizeof(int16_t)) != 0u) {
        return ERR_INVALID_ARGUMENT;
    }

    status = kem_adapter_derive_stream_mask_seed(
        shared_secret, client_id, round_id, chunk_index, seed);
    if (status != PQC_SUCCESS) {
        goto cleanup;
    }

    if (mask_prg_init(&prg, seed) != 0) {
        status = ERR_PRG_FAILED;
        goto cleanup;
    }

    if (mask_prg_get_bytes(&prg, mask_bytes, (size_t)chunk_size) != 0) {
        status = ERR_PRG_FAILED;
        mask_prg_cleanup(&prg);
        goto cleanup;
    }

    mask_prg_cleanup(&prg);
    status = PQC_SUCCESS;

cleanup:
    crypto_zeroize(seed, sizeof(seed));
    crypto_zeroize(&prg, sizeof(prg));
    if (status != PQC_SUCCESS) {
        crypto_zeroize(mask_bytes, (size_t)chunk_size);
    }
    return status;
}

/* ------------------------------------------------------------------------- */
/* RTOS task                                                                 */
/* ------------------------------------------------------------------------- */

static void stream_aggregator_task(void *pvParameters)
{
    stream_work_item_t item;
    (void)pvParameters;

    for (;;) {
        uint8_t *dma_data = NULL;
        uint16_t dma_length = 0u;
        uint16_t sequence = 0u;
        uint8_t buffer_index = 0u;

        /*
         * DMA sequence numbers are bridge-global. Translate them to a
         * session-local chunk index before handing the payload to the
         * normal validation/unmask path. The configured key and session
         * metadata must be valid for the lifetime of this session.
         */
        pqc_status_t dma_status = dma_stream_bridge_get_chunk(
            &g_dma_bridge,
            &dma_data,
            &dma_length,
            &sequence,
            &buffer_index,
            10u);

        if (dma_status == PQC_SUCCESS) {
            if (g_dma_shared_secret != NULL &&
                g_stream_ctx.state == STREAM_STATE_RECEIVING &&
                dma_length == g_stream_ctx.expected_chunk_size) {
                uint16_t session_chunk_index =
                    (uint16_t)(sequence - g_dma_session_sequence_base);

                (void)stream_aggregator_receive_chunk(
                    session_chunk_index,
                    dma_data,
                    dma_length,
                    g_stream_ctx.current_round_id,
                    g_stream_ctx.current_client_id,
                    g_dma_shared_secret);
            }

            /*
             * Release only after synchronous processing has returned.
             * The bridge zeroizes the physical buffer on release.
             */
            (void)dma_stream_bridge_release_buffer(
                &g_dma_bridge, buffer_index);
            continue;
        }

        if (g_stream_queue != NULL &&
            xQueueReceive(g_stream_queue, &item, pdMS_TO_TICKS(10u)) == pdTRUE) {
            uint32_t cycles;
            if (item.op == STREAM_OP_PROCESS) {
                telemetry_cycle_start();
                (void)stream_aggregator_process_chunk(
                    item.client_id, item.round_id, item.chunk_index,
                    item.chunk_size, item.shared_secret);
                cycles = telemetry_cycle_end();
                if (g_telemetry_session.round_count > 0u) {
                    telemetry_record_crypto(0, 0, 0, 0, cycles, 0);
                }
            } else if (item.op == STREAM_OP_UNMASK) {
                telemetry_cycle_start();
                (void)stream_aggregator_unmask_chunk(
                    item.client_id, item.round_id, item.chunk_index,
                    item.chunk_size, item.shared_secret);
                cycles = telemetry_cycle_end();
                if (g_telemetry_session.round_count > 0u) {
                    telemetry_record_crypto(0, 0, 0, 0, 0, cycles);
                }
            }
        }
    }
}

/* ------------------------------------------------------------------------- */
/* Initialization and queue                                                  */
/* ------------------------------------------------------------------------- */

void stream_aggregator_init(void)
{
    int16_t *registered_accumulator = g_stream_ctx.accumulator;
    size_t registered_capacity = g_stream_ctx.accumulator_size;

    memset(&g_stream_ctx, 0, sizeof(g_stream_ctx));
    g_stream_ctx.accumulator = registered_accumulator;
    g_stream_ctx.accumulator_size = registered_capacity;
    g_stream_ctx.state = STREAM_STATE_IDLE;
    g_dma_shared_secret = NULL;
    g_dma_session_sequence_base = 0u;

    g_stream_queue = xQueueCreateStatic(
        STREAM_QUEUE_LENGTH,
        sizeof(stream_work_item_t),
        stream_queue_storage,
        &stream_queue_struct);

    (void)dma_stream_bridge_init(&g_dma_bridge, 1000u);

    g_stream_task_handle = xTaskCreateStatic(
        stream_aggregator_task,
        "stream_aggregator",
        STREAM_TASK_STACK_WORDS,
        NULL,
        STREAM_TASK_PRIORITY,
        stream_stack,
        &stream_tcb);
}

TaskHandle_t stream_aggregator_get_task_handle(void)
{
    return g_stream_task_handle;
}

BaseType_t stream_aggregator_submit(
    const stream_work_item_t *item,
    TickType_t timeout)
{
    if (g_stream_queue == NULL || item == NULL ||
        (item->op != STREAM_OP_PROCESS && item->op != STREAM_OP_UNMASK) ||
        item->shared_secret == NULL) {
        return pdFALSE;
    }
    return xQueueSend(g_stream_queue, item, timeout);
}

/* ------------------------------------------------------------------------- */
/* Configuration and session lifecycle                                       */
/* ------------------------------------------------------------------------- */

pqc_status_t stream_aggregator_validate_chunk_size(uint16_t chunk_size)
{
    if (!is_valid_chunk_size(chunk_size) ||
        chunk_size > CHUNK_BUFFER_BYTES ||
        chunk_size > MAX_CHUNK_SIZE) {
        return ERR_CHUNK_TOO_LARGE;
    }
    return PQC_SUCCESS;
}

pqc_status_t stream_aggregator_set_output_buffer(
    int16_t *accumulator,
    size_t accumulator_bytes)
{
    if (accumulator == NULL || accumulator_bytes == 0u ||
        (accumulator_bytes % sizeof(int16_t)) != 0u) {
        return ERR_INVALID_ARGUMENT;
    }
    if (g_stream_ctx.state == STREAM_STATE_RECEIVING ||
        g_stream_ctx.state == STREAM_STATE_AGGREGATING) {
        return ERR_INVALID_STATE;
    }

    g_stream_ctx.accumulator = accumulator;
    g_stream_ctx.accumulator_size = accumulator_bytes;
    return PQC_SUCCESS;
}

pqc_status_t stream_aggregator_set_dma_shared_secret(
    const uint8_t *shared_secret)
{
    if (shared_secret == NULL) {
        return ERR_INVALID_ARGUMENT;
    }
    if (g_stream_ctx.state == STREAM_STATE_RECEIVING ||
        g_stream_ctx.state == STREAM_STATE_AGGREGATING) {
        return ERR_INVALID_STATE;
    }

    g_dma_shared_secret = shared_secret;
    return PQC_SUCCESS;
}

pqc_status_t stream_aggregator_start_session(
    uint32_t round_id,
    uint8_t client_id,
    uint16_t chunk_size,
    uint16_t total_chunks)
{
    size_t required_bytes;

    if (g_stream_ctx.state == STREAM_STATE_RECEIVING ||
        g_stream_ctx.state == STREAM_STATE_AGGREGATING) {
        return ERR_INVALID_STATE;
    }

    pqc_status_t status = stream_aggregator_validate_chunk_size(chunk_size);
    if (status != PQC_SUCCESS) {
        return status;
    }
    if (total_chunks == 0u || total_chunks > STREAM_MAX_CHUNKS) {
        return ERR_INVALID_ARGUMENT;
    }
    if ((size_t)total_chunks > SIZE_MAX / (size_t)chunk_size) {
        return ERR_BUFFER_TOO_SMALL;
    }

    required_bytes = (size_t)total_chunks * (size_t)chunk_size;

    if (g_stream_ctx.accumulator == NULL) {
        if (total_chunks != 1u ||
            required_bytes > sizeof(g_stream_ctx.chunk_accumulator)) {
            return ERR_BUFFER_TOO_SMALL;
        }
    } else if (g_stream_ctx.accumulator_size < required_bytes) {
        return ERR_BUFFER_TOO_SMALL;
    }

    clear_session_data();

    g_stream_ctx.current_round_id = round_id;
    g_stream_ctx.current_client_id = client_id;
    g_dma_session_sequence_base = g_dma_bridge.chunk_sequence;
    g_stream_ctx.expected_chunk_size = chunk_size;
    g_stream_ctx.total_chunks_expected = total_chunks;
    g_stream_ctx.chunk_size = chunk_size;
    g_stream_ctx.element_count = chunk_size / sizeof(int16_t);
    g_stream_ctx.state = STREAM_STATE_RECEIVING;
    g_stream_ctx.last_activity_tick = (uint32_t)xTaskGetTickCount();

    if (g_stream_ctx.accumulator != NULL) {
        crypto_zeroize(g_stream_ctx.accumulator, required_bytes);
    }

    return PQC_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Validation                                                                */
/* ------------------------------------------------------------------------- */

chunk_validation_t stream_aggregator_validate_chunk(
    uint16_t chunk_index,
    uint16_t chunk_size,
    uint32_t round_id,
    uint8_t client_id)
{
    if (stream_aggregator_validate_chunk_size(chunk_size) != PQC_SUCCESS ||
        chunk_size != g_stream_ctx.expected_chunk_size) {
        return CHUNK_INVALID_SIZE;
    }
    if (g_stream_ctx.state != STREAM_STATE_RECEIVING) {
        return CHUNK_OUT_OF_ORDER;
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
    if (bitmap_get(g_stream_ctx.chunk_bitmap, chunk_index)) {
        return CHUNK_DUPLICATE;
    }
    return CHUNK_VALID;
}

pqc_status_t stream_aggregator_check_duplicate(uint16_t chunk_index)
{
    if (chunk_index >= STREAM_MAX_CHUNKS) {
        return ERR_INVALID_ARGUMENT;
    }
    return bitmap_get(g_stream_ctx.chunk_bitmap, chunk_index)
        ? ERR_REPLAY_DETECTED : PQC_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Payload receive and chunk placement                                       */
/* ------------------------------------------------------------------------- */

pqc_status_t stream_aggregator_receive_chunk(
    uint16_t chunk_index,
    const uint8_t *masked_chunk,
    uint16_t chunk_size,
    uint32_t round_id,
    uint8_t client_id,
    const uint8_t *shared_secret)
{
    uint8_t mask_bytes[MAX_CHUNK_SIZE] = {0};
    size_t elements;
    size_t element_offset;
    int16_t *destination;
    pqc_status_t status;

    if (masked_chunk == NULL || shared_secret == NULL) {
        return ERR_INVALID_ARGUMENT;
    }
    if (chunk_size > MAX_CHUNK_SIZE || chunk_size > CHUNK_BUFFER_BYTES) {
        return ERR_CHUNK_TOO_LARGE;
    }
    if ((chunk_size % sizeof(int16_t)) != 0u) {
        return ERR_INVALID_ARGUMENT;
    }

    chunk_validation_t validation = stream_aggregator_validate_chunk(
        chunk_index, chunk_size, round_id, client_id);
    if (validation != CHUNK_VALID) {
        g_stream_ctx.last_validation = validation;
        switch (validation) {
            case CHUNK_DUPLICATE: return ERR_REPLAY_DETECTED;
            case CHUNK_INVALID_ROUND: return ERR_ROUND_MISMATCH;
            case CHUNK_INVALID_CLIENT: return ERR_CLIENT_ID_MISMATCH;
            case CHUNK_INVALID_SIZE: return ERR_CHUNK_TOO_LARGE;
            default: return ERR_INVALID_STATE;
        }
    }

    elements = (size_t)chunk_size / sizeof(int16_t);
    if ((size_t)chunk_index > SIZE_MAX / elements) {
        return ERR_BUFFER_TOO_SMALL;
    }
    element_offset = (size_t)chunk_index * elements;

    if (g_stream_ctx.accumulator != NULL) {
        size_t capacity_elements = g_stream_ctx.accumulator_size / sizeof(int16_t);
        if (element_offset > capacity_elements ||
            elements > capacity_elements - element_offset) {
            return ERR_BUFFER_TOO_SMALL;
        }
        destination = g_stream_ctx.accumulator + element_offset;
    } else {
        if (g_stream_ctx.total_chunks_expected != 1u ||
            element_offset != 0u ||
            elements > ARRAY_SIZE(g_stream_ctx.chunk_accumulator)) {
            return ERR_BUFFER_TOO_SMALL;
        }
        destination = g_stream_ctx.chunk_accumulator;
    }

    status = derive_mask(shared_secret, client_id, round_id,
                         chunk_index, chunk_size, mask_bytes);
    if (status != PQC_SUCCESS) {
        crypto_zeroize(mask_bytes, sizeof(mask_bytes));
        return status;
    }

    for (size_t i = 0u; i < elements; ++i) {
        int16_t masked_value = read_i16_le(masked_chunk + (2u * i));
        int16_t mask_value = read_i16_le(mask_bytes + (2u * i));
        destination[i] = (int16_t)mod_q((int32_t)masked_value -
                                        (int32_t)mask_value);
    }

    bitmap_set(g_stream_ctx.chunk_bitmap, chunk_index);
    g_stream_ctx.chunks_received_count++;
    g_stream_ctx.last_activity_tick = (uint32_t)xTaskGetTickCount();
    g_stream_ctx.last_validation = CHUNK_VALID;

    if (g_stream_ctx.chunks_received_count == g_stream_ctx.total_chunks_expected) {
        g_stream_ctx.state = STREAM_STATE_AGGREGATING;
    }

    crypto_zeroize(mask_bytes, sizeof(mask_bytes));
    return PQC_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Queue APIs without payload                                                */
/* ------------------------------------------------------------------------- */

/*
 * These APIs intentionally do not claim to process a payload: stream_work_item_t
 * carries no masked bytes. Payload processing must use receive_chunk() until
 * the queue contract is extended to carry owned/copied payload data.
 */
static pqc_status_t validate_metadata_only(
    uint8_t client_id,
    uint32_t round_id,
    uint16_t chunk_index,
    uint16_t chunk_size,
    const uint8_t *shared_secret)
{
    if (shared_secret == NULL) {
        return ERR_INVALID_ARGUMENT;
    }
    if (stream_aggregator_validate_chunk_size(chunk_size) != PQC_SUCCESS) {
        return ERR_CHUNK_TOO_LARGE;
    }
    if (g_stream_ctx.state != STREAM_STATE_RECEIVING) {
        return ERR_INVALID_STATE;
    }
    if (client_id != g_stream_ctx.current_client_id) {
        return ERR_CLIENT_ID_MISMATCH;
    }
    if (round_id != g_stream_ctx.current_round_id) {
        return ERR_ROUND_MISMATCH;
    }
    if (chunk_index >= g_stream_ctx.total_chunks_expected) {
        return ERR_INVALID_ARGUMENT;
    }
    return ERR_INVALID_STATE;
}

pqc_status_t stream_aggregator_process_chunk(
    uint8_t client_id,
    uint32_t round_id,
    uint16_t chunk_index,
    uint16_t chunk_size,
    const uint8_t *shared_secret)
{
    return validate_metadata_only(client_id, round_id, chunk_index,
                                  chunk_size, shared_secret);
}

pqc_status_t stream_aggregator_unmask_chunk(
    uint8_t client_id,
    uint32_t round_id,
    uint16_t chunk_index,
    uint16_t chunk_size,
    const uint8_t *shared_secret)
{
    return validate_metadata_only(client_id, round_id, chunk_index,
                                  chunk_size, shared_secret);
}

pqc_status_t stream_aggregator_process_dma_data(
    uint8_t client_id,
    uint32_t round_id,
    uint16_t chunk_index,
    uint16_t chunk_size,
    const uint8_t *shared_secret)
{
    return validate_metadata_only(client_id, round_id, chunk_index,
                                  chunk_size, shared_secret);
}

dma_stream_bridge_t *stream_aggregator_get_dma_bridge(void)
{
    return &g_dma_bridge;
}

/* ------------------------------------------------------------------------- */
/* Finalize, reset, stats                                                    */
/* ------------------------------------------------------------------------- */

pqc_status_t stream_aggregator_finalize_session(
    int16_t *output_accumulator,
    size_t *output_size)
{
    size_t required_bytes;

    if (output_accumulator == NULL || output_size == NULL) {
        return ERR_INVALID_ARGUMENT;
    }
    if (g_stream_ctx.state == STREAM_STATE_COMPLETE ||
        g_stream_ctx.state == STREAM_STATE_ERROR ||
        g_stream_ctx.state == STREAM_STATE_IDLE) {
        return ERR_INVALID_STATE;
    }
    if (g_stream_ctx.chunks_received_count != g_stream_ctx.total_chunks_expected) {
        return ERR_INSUFFICIENT_SHARES;
    }

    required_bytes = (size_t)g_stream_ctx.total_chunks_expected *
                     (size_t)g_stream_ctx.expected_chunk_size;

    if (g_stream_ctx.accumulator != NULL) {
        if (output_accumulator != g_stream_ctx.accumulator ||
            g_stream_ctx.accumulator_size < required_bytes) {
            return ERR_BUFFER_TOO_SMALL;
        }
        /* Data is already in the registered output buffer. */
    } else {
        if (g_stream_ctx.total_chunks_expected != 1u ||
            required_bytes > sizeof(g_stream_ctx.chunk_accumulator)) {
            return ERR_BUFFER_TOO_SMALL;
        }
        memcpy(output_accumulator, g_stream_ctx.chunk_accumulator, required_bytes);
    }

    *output_size = required_bytes;
    g_stream_ctx.state = STREAM_STATE_COMPLETE;
    return PQC_SUCCESS;
}

pqc_status_t stream_aggregator_reset(void)
{
    int16_t *registered_accumulator = g_stream_ctx.accumulator;
    size_t registered_capacity = g_stream_ctx.accumulator_size;

    if (registered_accumulator != NULL &&
        g_stream_ctx.total_chunks_expected != 0u &&
        g_stream_ctx.expected_chunk_size != 0u) {
        size_t used_bytes =
            (size_t)g_stream_ctx.total_chunks_expected *
            (size_t)g_stream_ctx.expected_chunk_size;
        if (used_bytes <= registered_capacity) {
            crypto_zeroize(registered_accumulator, used_bytes);
        }
    }

    crypto_zeroize(&g_stream_ctx, sizeof(g_stream_ctx));
    g_stream_ctx.accumulator = registered_accumulator;
    g_stream_ctx.accumulator_size = registered_capacity;
    g_stream_ctx.state = STREAM_STATE_IDLE;
    g_stream_ctx.last_validation = CHUNK_VALID;
    return PQC_SUCCESS;
}

void stream_aggregator_get_stats(
    uint8_t *chunks_received,
    uint8_t *total_expected,
    stream_state_t *state)
{
    if (chunks_received != NULL) {
        *chunks_received = g_stream_ctx.chunks_received_count > UINT8_MAX
            ? UINT8_MAX : (uint8_t)g_stream_ctx.chunks_received_count;
    }
    if (total_expected != NULL) {
        *total_expected = g_stream_ctx.total_chunks_expected > UINT8_MAX
            ? UINT8_MAX : (uint8_t)g_stream_ctx.total_chunks_expected;
    }
    if (state != NULL) {
        *state = g_stream_ctx.state;
    }
}

void stream_aggregator_zeroize_accumulator(void)
{
    crypto_zeroize(g_stream_ctx.chunk_accumulator,
                   sizeof(g_stream_ctx.chunk_accumulator));
    if (g_stream_ctx.accumulator != NULL &&
        g_stream_ctx.total_chunks_expected != 0u &&
        g_stream_ctx.expected_chunk_size != 0u) {
        size_t used_bytes =
            (size_t)g_stream_ctx.total_chunks_expected *
            (size_t)g_stream_ctx.expected_chunk_size;
        if (used_bytes <= g_stream_ctx.accumulator_size) {
            crypto_zeroize(g_stream_ctx.accumulator, used_bytes);
        }
    }
}
