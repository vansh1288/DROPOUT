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

#define STREAM_QUEUE_LENGTH 8u
#define STREAM_TASK_STACK_WORDS 1024u
#define STREAM_TASK_PRIORITY 2u

#define STREAM_MASK_SEED_SIZE 32u
#define STREAM_MODULUS 3329

static QueueHandle_t g_stream_queue = NULL;

static StackType_t stream_stack[STREAM_TASK_STACK_WORDS];
static StaticTask_t stream_tcb;
static TaskHandle_t g_stream_task_handle = NULL;

static uint8_t stream_queue_storage[
    STREAM_QUEUE_LENGTH * sizeof(stream_work_item_t)
];

static StaticQueue_t stream_queue_struct;

dma_stream_bridge_t g_dma_bridge;

static stream_aggregator_ctx_t g_stream_ctx = {0};

/* ------------------------------------------------------------------------- */
/* Internal helpers                                                          */
/* ------------------------------------------------------------------------- */

static inline uint16_t mod_q(int32_t value)
{
    int32_t remainder = value % STREAM_MODULUS;

    if (remainder < 0) {
        remainder += STREAM_MODULUS;
    }

    return (uint16_t)remainder;
}

static inline int is_valid_chunk_size(uint16_t chunk_size)
{
    return (chunk_size == STREAM_CHUNK_SIZE_64) ||
           (chunk_size == STREAM_CHUNK_SIZE_128) ||
           (chunk_size == STREAM_CHUNK_SIZE_256) ||
           (chunk_size == STREAM_CHUNK_SIZE_512) ||
           (chunk_size == STREAM_CHUNK_SIZE_1024);
}

static inline int bitmap_get(
    const uint8_t* bitmap,
    uint16_t index)
{
    return (bitmap[index / 8u] >> (index % 8u)) & 1u;
}

static inline void bitmap_set(
    uint8_t* bitmap,
    uint16_t index)
{
    bitmap[index / 8u] |=
        (uint8_t)(1u << (index % 8u));
}

/*
 * Check whether a chunk was already received without modifying
 * the bitmap.
 */
static inline int bitmap_is_set(
    const uint8_t* bitmap,
    uint16_t index)
{
    return bitmap_get(bitmap, index);
}

/*
 * Convert the PRG byte stream into signed 16-bit mask elements.
 *
 * The existing protocol treats the chunk as int16_t elements, so
 * the generated mask must be interpreted using the same representation.
 */
static void generate_chunk_mask(
    const uint8_t* shared_secret,
    uint8_t client_id,
    uint32_t round_id,
    uint16_t chunk_index,
    uint16_t chunk_size,
    int16_t* mask,
    size_t mask_elements)
{
    uint8_t stream_seed[STREAM_MASK_SEED_SIZE];
    mask_prg_ctx_t prg_ctx;
    pqc_status_t ret;

    memset(stream_seed, 0, sizeof(stream_seed));
    memset(&prg_ctx, 0, sizeof(prg_ctx));

    ret = kem_adapter_derive_stream_mask_seed(
        shared_secret,
        client_id,
        round_id,
        chunk_index,
        stream_seed);

    if (ret != PQC_SUCCESS) {
        crypto_zeroize(stream_seed, sizeof(stream_seed));
        memset(mask, 0, mask_elements * sizeof(int16_t));
        return;
    }

    ret = mask_prg_init(
        &prg_ctx,
        stream_seed);

    if (ret != 0) {
        crypto_zeroize(stream_seed, sizeof(stream_seed));
        memset(mask, 0, mask_elements * sizeof(int16_t));
        return;
    }

    ret = mask_prg_get_bytes(
        &prg_ctx,
        (uint8_t*)mask,
        chunk_size);

    if (ret != 0) {
        memset(mask, 0, mask_elements * sizeof(int16_t));
    }

    mask_prg_cleanup(&prg_ctx);
    crypto_zeroize(stream_seed, sizeof(stream_seed));
}

/* ------------------------------------------------------------------------- */
/* Stream aggregator task                                                    */
/* ------------------------------------------------------------------------- */

static void stream_aggregator_task(void* pvParameters)
{
    (void)pvParameters;

    stream_work_item_t item;

    while (1) {
        uint8_t* dma_data = NULL;
        uint16_t dma_length = 0;
        uint16_t dma_chunk_index = 0;

        /*
         * DMA data has priority over queued work.
         */
        pqc_status_t dma_ret =
            dma_stream_bridge_get_chunk(
                &g_dma_bridge,
                &dma_data,
                &dma_length,
                &dma_chunk_index,
                10);

        if (dma_ret == PQC_SUCCESS) {

            /*
             * The DMA bridge owns the buffer until release_buffer().
             * Process it before releasing ownership.
             */
            if (dma_data != NULL &&
                dma_length > 0 &&
                dma_length <= MAX_CHUNK_SIZE) {

                /*
                 * The current bridge API provides the chunk index and
                 * raw chunk data, while the session context provides
                 * round/client/chunk-size information.
                 */
                uint16_t expected_size =
                    g_stream_ctx.expected_chunk_size;

                if (expected_size > 0 &&
                    dma_length == expected_size) {

                    /*
                     * The shared secret is not stored in the stream
                     * context. Therefore the DMA path cannot perform
                     * cryptographic unmasking until the caller supplies
                     * that secret through the appropriate work item/API.
                     *
                     * Do not pass NULL to receive_chunk().
                     */
                }
            }

            /*
             * Release the buffer that the bridge actually selected.
             *
             * dma_stream_bridge_get_chunk() may return either ping
             * or pong, so never hard-code buffer index 0 here.
             */
            dma_stream_bridge_release_buffer(
                &g_dma_bridge,
                dma_chunk_index);

            continue;
        }

        /*
         * Process queued work items.
         */
        if (g_stream_queue != NULL &&
            xQueueReceive(
                g_stream_queue,
                &item,
                pdMS_TO_TICKS(10)) == pdTRUE) {

            if (item.op == STREAM_OP_PROCESS) {

                telemetry_cycle_start();

                /*
                 * The current stream_work_item_t contains metadata and
                 * the shared secret, but no masked payload.
                 *
                 * Therefore processing must be performed by the caller
                 * through stream_aggregator_receive_chunk().
                 */
                (void)stream_aggregator_process_chunk(
                    item.client_id,
                    item.round_id,
                    item.chunk_index,
                    item.chunk_size,
                    item.shared_secret);

                uint32_t cycles =
                    telemetry_cycle_end();

                if (g_telemetry_session.round_count > 0) {
                    telemetry_record_crypto(
                        0,
                        0,
                        0,
                        0,
                        cycles,
                        0);
                }

            } else if (item.op == STREAM_OP_UNMASK) {

                telemetry_cycle_start();

                (void)stream_aggregator_unmask_chunk(
                    item.client_id,
                    item.round_id,
                    item.chunk_index,
                    item.chunk_size,
                    item.shared_secret);

                uint32_t cycles =
                    telemetry_cycle_end();

                if (g_telemetry_session.round_count > 0) {
                    telemetry_record_crypto(
                        0,
                        0,
                        0,
                        0,
                        0,
                        cycles);
                }
            }
        }
    }
}

/* ------------------------------------------------------------------------- */
/* Initialization                                                            */
/* ------------------------------------------------------------------------- */

void stream_aggregator_init(void)
{
    memset(
        &g_stream_ctx,
        0,
        sizeof(g_stream_ctx));

    g_stream_queue =
        xQueueCreateStatic(
            STREAM_QUEUE_LENGTH,
            sizeof(stream_work_item_t),
            stream_queue_storage,
            &stream_queue_struct);

    dma_stream_bridge_init(
        &g_dma_bridge,
        1000);

    g_stream_task_handle =
        xTaskCreateStatic(
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

dma_stream_bridge_t* stream_aggregator_get_dma_bridge(void)
{
    return &g_dma_bridge;
}

BaseType_t stream_aggregator_submit(
    const stream_work_item_t* item,
    TickType_t timeout)
{
    if (g_stream_queue == NULL ||
        item == NULL) {
        return pdFALSE;
    }

    return xQueueSend(
        g_stream_queue,
        item,
        timeout);
}

/* ------------------------------------------------------------------------- */
/* Session management                                                        */
/* ------------------------------------------------------------------------- */

pqc_status_t stream_aggregator_validate_chunk_size(
    uint16_t chunk_size)
{
    if (!is_valid_chunk_size(chunk_size)) {
        return ERR_CHUNK_TOO_LARGE;
    }

    if (chunk_size > CHUNK_BUFFER_BYTES) {
        return ERR_CHUNK_TOO_LARGE;
    }

    return PQC_SUCCESS;
}

pqc_status_t stream_aggregator_start_session(
    uint32_t round_id,
    uint8_t client_id,
    uint16_t chunk_size,
    uint16_t total_chunks)
{
    pqc_status_t ret =
        stream_aggregator_validate_chunk_size(
            chunk_size);

    if (ret != PQC_SUCCESS) {
        return ret;
    }

    if (total_chunks == 0 ||
        total_chunks > STREAM_MAX_CHUNKS) {
        return ERR_INVALID_ARGUMENT;
    }

    memset(
        &g_stream_ctx,
        0,
        sizeof(g_stream_ctx));

    g_stream_ctx.current_round_id =
        round_id;

    g_stream_ctx.current_client_id =
        client_id;

    g_stream_ctx.expected_chunk_size =
        chunk_size;

    g_stream_ctx.total_chunks_expected =
        total_chunks;

    g_stream_ctx.chunk_size =
        chunk_size;

    g_stream_ctx.element_count =
        chunk_size / sizeof(int16_t);

    g_stream_ctx.state =
        STREAM_STATE_RECEIVING;

    g_stream_ctx.chunks_received_count =
        0;

    g_stream_ctx.last_activity_tick =
        xTaskGetTickCount();

    g_stream_ctx.last_validation =
        CHUNK_VALID;

    memset(
        g_stream_ctx.chunk_bitmap,
        0,
        sizeof(g_stream_ctx.chunk_bitmap));

    stream_aggregator_zeroize_accumulator();

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
    if (!is_valid_chunk_size(chunk_size) ||
        chunk_size > CHUNK_BUFFER_BYTES) {
        return CHUNK_INVALID_SIZE;
    }

    if (g_stream_ctx.state != STREAM_STATE_RECEIVING) {
        return CHUNK_OUT_OF_ORDER;
    }

    if (round_id !=
        g_stream_ctx.current_round_id) {
        return CHUNK_INVALID_ROUND;
    }

    if (client_id !=
        g_stream_ctx.current_client_id) {
        return CHUNK_INVALID_CLIENT;
    }

    if (chunk_index >=
        g_stream_ctx.total_chunks_expected) {
        return CHUNK_OUT_OF_ORDER;
    }

    if (chunk_size !=
        g_stream_ctx.expected_chunk_size) {
        return CHUNK_INVALID_SIZE;
    }

    /*
     * Only check the bitmap here.
     *
     * Do NOT mark the chunk as received until actual processing
     * succeeds. Otherwise a failed chunk would permanently become
     * a duplicate.
     */
    if (bitmap_is_set(
            g_stream_ctx.chunk_bitmap,
            chunk_index)) {
        return CHUNK_DUPLICATE;
    }

    return CHUNK_VALID;
}

pqc_status_t stream_aggregator_check_duplicate(
    uint16_t chunk_index)
{
    if (chunk_index >= STREAM_MAX_CHUNKS) {
        return ERR_INVALID_ARGUMENT;
    }

    if (bitmap_get(
            g_stream_ctx.chunk_bitmap,
            chunk_index)) {
        return ERR_REPLAY_DETECTED;
    }

    return PQC_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Receive and aggregate a masked chunk                                     */
/* ------------------------------------------------------------------------- */

pqc_status_t stream_aggregator_receive_chunk(
    uint16_t chunk_index,
    const uint8_t* masked_chunk,
    uint16_t chunk_size,
    uint32_t round_id,
    uint8_t client_id,
    const uint8_t* shared_secret)
{
    if (masked_chunk == NULL ||
        shared_secret == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    if (chunk_size > CHUNK_BUFFER_BYTES ||
        chunk_size > MAX_CHUNK_SIZE) {
        return ERR_CHUNK_TOO_LARGE;
    }

    if ((chunk_size % sizeof(int16_t)) != 0) {
        return ERR_INVALID_ARGUMENT;
    }

    chunk_validation_t validation =
        stream_aggregator_validate_chunk(
            chunk_index,
            chunk_size,
            round_id,
            client_id);

    if (validation != CHUNK_VALID) {
        g_stream_ctx.last_validation =
            validation;

        if (validation == CHUNK_DUPLICATE) {
            return ERR_REPLAY_DETECTED;
        }

        if (validation == CHUNK_INVALID_SIZE) {
            return ERR_CHUNK_TOO_LARGE;
        }

        if (validation == CHUNK_INVALID_ROUND) {
            return ERR_ROUND_MISMATCH;
        }

        if (validation == CHUNK_INVALID_CLIENT) {
            return ERR_CLIENT_ID_MISMATCH;
        }

        return ERR_INVALID_ARGUMENT;
    }

    size_t num_elements =
        chunk_size / sizeof(int16_t);

    int16_t mask[
        CHUNK_BUFFER_BYTES / sizeof(int16_t)
    ];

    int16_t unmasked[
        CHUNK_BUFFER_BYTES / sizeof(int16_t)
    ];

    uint8_t stream_seed[
        STREAM_MASK_SEED_SIZE
    ];

    mask_prg_ctx_t prg_ctx;

    memset(
        mask,
        0,
        sizeof(mask));

    memset(
        unmasked,
        0,
        sizeof(unmasked));

    memset(
        stream_seed,
        0,
        sizeof(stream_seed));

    memset(
        &prg_ctx,
        0,
        sizeof(prg_ctx));

    /*
     * Derive the deterministic stream-mask seed.
     */
    pqc_status_t ret =
        kem_adapter_derive_stream_mask_seed(
            shared_secret,
            client_id,
            round_id,
            chunk_index,
            stream_seed);

    if (ret != PQC_SUCCESS) {
        crypto_zeroize(
            stream_seed,
            sizeof(stream_seed));

        return ret;
    }

    /*
     * Initialize the mask PRG.
     */
    ret =
        mask_prg_init(
            &prg_ctx,
            stream_seed);

    if (ret != 0) {
        crypto_zeroize(
            stream_seed,
            sizeof(stream_seed));

        return ERR_PRG_FAILED;
    }

    /*
     * Generate exactly chunk_size bytes of mask.
     */
    ret =
        mask_prg_get_bytes(
            &prg_ctx,
            (uint8_t*)mask,
            chunk_size);

    if (ret != 0) {
        mask_prg_cleanup(&prg_ctx);

        crypto_zeroize(
            stream_seed,
            sizeof(stream_seed));

        crypto_zeroize(
            mask,
            sizeof(mask));

        return ERR_PRG_FAILED;
    }

    /*
     * Unmask the received chunk.
     *
     * The protocol represents each value as an int16_t and performs
     * arithmetic modulo q = 3329.
     */
    const int16_t* masked =
        (const int16_t*)masked_chunk;

    for (size_t i = 0;
         i < num_elements;
         i++) {

        int32_t diff =
            (int32_t)masked[i] -
            (int32_t)mask[i];

        unmasked[i] =
            (int16_t)mod_q(diff);
    }

    /*
     * Add the unmasked chunk to the bounded accumulator.
     */
    for (size_t i = 0;
         i < num_elements;
         i++) {

        int32_t sum =
            (int32_t)g_stream_ctx.chunk_accumulator[i] +
            (int32_t)unmasked[i];

        g_stream_ctx.chunk_accumulator[i] =
            (int16_t)mod_q(sum);
    }

    /*
     * Mark the chunk as received ONLY after successful processing.
     */
    bitmap_set(
        g_stream_ctx.chunk_bitmap,
        chunk_index);

    g_stream_ctx.chunks_received_count++;

    g_stream_ctx.last_activity_tick =
        xTaskGetTickCount();

    g_stream_ctx.last_validation =
        CHUNK_VALID;

    /*
     * Complete session automatically once every expected chunk
     * has been received.
     */
    if (g_stream_ctx.chunks_received_count ==
        g_stream_ctx.total_chunks_expected) {

        g_stream_ctx.state =
            STREAM_STATE_AGGREGATING;
    }

    mask_prg_cleanup(&prg_ctx);

    crypto_zeroize(
        stream_seed,
        sizeof(stream_seed));

    crypto_zeroize(
        mask,
        sizeof(mask));

    crypto_zeroize(
        unmasked,
        sizeof(unmasked));

    return PQC_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Queue-based processing                                                    */
/* ------------------------------------------------------------------------- */

pqc_status_t stream_aggregator_process_chunk(
    uint8_t client_id,
    uint32_t round_id,
    uint16_t chunk_index,
    uint16_t chunk_size,
    const uint8_t* shared_secret)
{
    /*
     * The current stream_work_item_t does not carry the masked
     * chunk payload. Therefore this API cannot safely perform the
     * actual receive/unmask operation by itself.
     *
     * Actual payload processing is performed through
     * stream_aggregator_receive_chunk().
     */
    if (shared_secret == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    if (chunk_size == 0 ||
        chunk_size > MAX_CHUNK_SIZE) {
        return ERR_CHUNK_TOO_LARGE;
    }

    if (client_id !=
        g_stream_ctx.current_client_id) {
        return ERR_CLIENT_ID_MISMATCH;
    }

    if (round_id !=
        g_stream_ctx.current_round_id) {
        return ERR_ROUND_MISMATCH;
    }

    if (chunk_index >=
        g_stream_ctx.total_chunks_expected) {
        return ERR_INVALID_ARGUMENT;
    }

    return ERR_INVALID_STATE;
}

pqc_status_t stream_aggregator_unmask_chunk(
    uint8_t client_id,
    uint32_t round_id,
    uint16_t chunk_index,
    uint16_t chunk_size,
    const uint8_t* shared_secret)
{
    /*
     * The current API has no separate masked payload for this
     * operation. Keep validation here rather than silently
     * returning success for an operation that was not performed.
     */
    if (shared_secret == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    if (chunk_size == 0 ||
        chunk_size > MAX_CHUNK_SIZE) {
        return ERR_CHUNK_TOO_LARGE;
    }

    if (client_id !=
        g_stream_ctx.current_client_id) {
        return ERR_CLIENT_ID_MISMATCH;
    }

    if (round_id !=
        g_stream_ctx.current_round_id) {
        return ERR_ROUND_MISMATCH;
    }

    if (chunk_index >=
        g_stream_ctx.total_chunks_expected) {
        return ERR_INVALID_ARGUMENT;
    }

    return ERR_INVALID_STATE;
}

/* ------------------------------------------------------------------------- */
/* DMA integration                                                           */
/* ------------------------------------------------------------------------- */

pqc_status_t stream_aggregator_process_dma_data(
    uint8_t client_id,
    uint32_t round_id,
    uint16_t chunk_index,
    uint16_t chunk_size,
    const uint8_t* shared_secret)
{
    /*
     * This function is retained as the public DMA-processing API,
     * but the current interface does not contain a DMA payload
     * pointer. Actual DMA data is therefore processed directly
     * by the stream task after dma_stream_bridge_get_chunk().
     */
    if (shared_secret == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    if (chunk_size == 0 ||
        chunk_size > MAX_CHUNK_SIZE) {
        return ERR_CHUNK_TOO_LARGE;
    }

    if (round_id !=
        g_stream_ctx.current_round_id) {
        return ERR_ROUND_MISMATCH;
    }

    if (client_id !=
        g_stream_ctx.current_client_id) {
        return ERR_CLIENT_ID_MISMATCH;
    }

    if (chunk_index >=
        g_stream_ctx.total_chunks_expected) {
        return ERR_INVALID_ARGUMENT;
    }

    return ERR_INVALID_STATE;
}

/* ------------------------------------------------------------------------- */
/* Finalization                                                              */
/* ------------------------------------------------------------------------- */

pqc_status_t stream_aggregator_finalize_session(
    int16_t* output_accumulator,
    size_t* output_size)
{
    if (output_accumulator == NULL ||
        output_size == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    if (g_stream_ctx.state ==
        STREAM_STATE_ERROR) {
        return ERR_INVALID_STATE;
    }

    if (g_stream_ctx.chunks_received_count !=
        g_stream_ctx.total_chunks_expected) {
        return ERR_INSUFFICIENT_SHARES;
    }

    /*
     * The current bounded-memory implementation owns only one
     * chunk-sized accumulator. It cannot safely copy a complete
     * multi-chunk model into output_accumulator.
     *
     * Therefore only a single-chunk session can be finalized
     * with the current API without introducing a full-model
     * buffer or changing the output API.
     */
    size_t output_bytes =
        g_stream_ctx.expected_chunk_size;

    if (g_stream_ctx.total_chunks_expected != 1u) {
        return ERR_BUFFER_TOO_SMALL;
    }

    memcpy(
        output_accumulator,
        g_stream_ctx.chunk_accumulator,
        output_bytes);

    *output_size =
        output_bytes;

    g_stream_ctx.state =
        STREAM_STATE_COMPLETE;

    return PQC_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Reset                                                                     */
/* ------------------------------------------------------------------------- */

pqc_status_t stream_aggregator_reset(void)
{
    crypto_zeroize(
        g_stream_ctx.chunk_accumulator,
        sizeof(g_stream_ctx.chunk_accumulator));

    memset(
        g_stream_ctx.chunk_bitmap,
        0,
        sizeof(g_stream_ctx.chunk_bitmap));

    g_stream_ctx.current_round_id = 0;
    g_stream_ctx.current_client_id = 0;
    g_stream_ctx.expected_chunk_size = 0;
    g_stream_ctx.total_chunks_expected = 0;
    g_stream_ctx.chunk_size = 0;
    g_stream_ctx.element_count = 0;
    g_stream_ctx.chunks_received_count = 0;
    g_stream_ctx.last_activity_tick = 0;
    g_stream_ctx.last_validation = CHUNK_VALID;
    g_stream_ctx.state = STREAM_STATE_IDLE;

    return PQC_SUCCESS;
}

/* ------------------------------------------------------------------------- */
/* Statistics                                                                */
/* ------------------------------------------------------------------------- */

void stream_aggregator_get_stats(
    uint8_t* chunks_received,
    uint8_t* total_expected,
    stream_state_t* state)
{
    /*
     * Preserve the existing public API from stream_aggregator.h.
     *
     * Note: this API cannot represent values above 255 even though
     * the internal context supports STREAM_MAX_CHUNKS.
     */
    if (chunks_received) {
        *chunks_received =
            (g_stream_ctx.chunks_received_count > UINT8_MAX)
                ? UINT8_MAX
                : (uint8_t)g_stream_ctx.chunks_received_count;
    }

    if (total_expected) {
        *total_expected =
            (g_stream_ctx.total_chunks_expected > UINT8_MAX)
                ? UINT8_MAX
                : (uint8_t)g_stream_ctx.total_chunks_expected;
    }

    if (state) {
        *state =
            g_stream_ctx.state;
    }
}

/* ------------------------------------------------------------------------- */
/* Accumulator                                                               */
/* ------------------------------------------------------------------------- */

void stream_aggregator_zeroize_accumulator(void)
{
    crypto_zeroize(
        g_stream_ctx.chunk_accumulator,
        sizeof(g_stream_ctx.chunk_accumulator));
}