#include "telemetry.h"
#include "memory_scratchpad.h"
#include "FreeRTOS.h"
#include "task.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

telemetry_session_t g_telemetry_session = {0};

static uint32_t g_cycle_start = 0;
static uint32_t g_round_start_tick = 0;
static uint32_t g_dropout_detect_tick = 0;
static uint32_t g_recovery_start_tick = 0;

/* ------------------------------------------------------------------------- */
/* Cortex-M cycle counter                                                    */
/* ------------------------------------------------------------------------- */

#if defined(__ARM_ARCH_7EM__) || \
    defined(__ARM_ARCH_8M_BASE__) || \
    defined(__ARM_ARCH_8M_MAIN__)

#define DEMCR_ADDR       0xE000EDFCu
#define DWT_BASE         0xE0001000u

#define DEMCR             (*(volatile uint32_t*)DEMCR_ADDR)
#define DWT_CTRL          (*(volatile uint32_t*)(DWT_BASE + 0x00u))
#define DWT_CYCCNT        (*(volatile uint32_t*)(DWT_BASE + 0x04u))

#define DEMCR_TRCENA      (1u << 24)
#define DWT_CTRL_CYCCNTENA (1u << 0)

static void dwt_init(void)
{
    DEMCR |= DEMCR_TRCENA;

    DWT_CYCCNT = 0;

    DWT_CTRL |= DWT_CTRL_CYCCNTENA;
}

static inline uint32_t dwt_read_cycles(void)
{
    return DWT_CYCCNT;
}

#else

static void dwt_init(void)
{
}

static inline uint32_t dwt_read_cycles(void)
{
    /*
     * Native/emulator builds without a Cortex-M DWT counter
     * cannot provide hardware cycle measurements.
     */
    return 0;
}

#endif

/* ------------------------------------------------------------------------- */
/* Memory measurement                                                        */
/* ------------------------------------------------------------------------- */

static uint32_t get_peak_sram(void)
{
    /*
     * These linker symbols are target-dependent. When available,
     * estimate the statically allocated SRAM span.
     */
    extern uint8_t _sdata;
    extern uint8_t _ebss;

    uintptr_t data_start =
        (uintptr_t)&_sdata;

    uintptr_t bss_end =
        (uintptr_t)&_ebss;

    if (bss_end <= data_start) {
        return 0;
    }

    return (uint32_t)(bss_end - data_start);
}

static uint32_t get_min_free_heap(void)
{
#if defined(configTOTAL_HEAP_SIZE)
    return xPortGetFreeHeapSize();
#else
    return 0;
#endif
}

static uint32_t get_largest_free_block(void)
{
#if defined(configUSE_HEAP_5)
    /*
     * The portable FreeRTOS API does not expose the largest free
     * block for every heap implementation. Use the currently
     * available heap amount rather than reporting a fabricated value.
     */
    return xPortGetFreeHeapSize();
#else
    return xPortGetFreeHeapSize();
#endif
}

static uint8_t check_heap_zero(void)
{
#if defined(configTOTAL_HEAP_SIZE)
    uint32_t free_heap =
        xPortGetFreeHeapSize();

    /*
     * A zero-free-heap condition indicates that the heap has been
     * completely consumed. This is a resource-exhaustion check,
     * not a general "no dynamic allocation happened" proof.
     */
    return (free_heap == 0u) ? 1u : 0u;
#else
    return 0u;
#endif
}

/* ------------------------------------------------------------------------- */
/* Initialization                                                            */
/* ------------------------------------------------------------------------- */

void telemetry_init(void)
{
    memset(
        &g_telemetry_session,
        0,
        sizeof(g_telemetry_session));

    g_cycle_start = 0;
    g_round_start_tick = 0;
    g_dropout_detect_tick = 0;
    g_recovery_start_tick = 0;

    dwt_init();
}

/* ------------------------------------------------------------------------- */
/* Cycle measurements                                                        */
/* ------------------------------------------------------------------------- */

void telemetry_cycle_start(void)
{
    g_cycle_start =
        dwt_read_cycles();
}

uint32_t telemetry_cycle_end(void)
{
    uint32_t end =
        dwt_read_cycles();

    uint32_t elapsed =
        end - g_cycle_start;

    g_cycle_start = 0;

    return elapsed;
}

void telemetry_start_cycle_measure(void)
{
    telemetry_cycle_start();
}

uint32_t telemetry_end_cycle_measure(void)
{
    return telemetry_cycle_end();
}

/* ------------------------------------------------------------------------- */
/* Crypto measurements                                                       */
/* ------------------------------------------------------------------------- */

void telemetry_record_crypto(
    uint32_t keygen,
    uint32_t encaps,
    uint32_t decaps,
    uint32_t hkdf,
    uint32_t mask_gen,
    uint32_t mask_apply)
{
    if (g_telemetry_session.round_count == 0) {
        return;
    }

    telemetry_round_t* round =
        &g_telemetry_session.rounds[
            g_telemetry_session.round_count - 1
        ];

    round->crypto.keygen_cycles =
        keygen;

    round->crypto.encaps_cycles =
        encaps;

    round->crypto.decaps_cycles =
        decaps;

    round->crypto.hkdf_cycles =
        hkdf;

    round->crypto.mask_gen_cycles =
        mask_gen;

    round->crypto.mask_apply_cycles =
        mask_apply;
}

/* ------------------------------------------------------------------------- */
/* Memory measurements                                                       */
/* ------------------------------------------------------------------------- */

void telemetry_update_memory(void)
{
    if (g_telemetry_session.round_count == 0) {
        return;
    }

    telemetry_round_t* round =
        &g_telemetry_session.rounds[
            g_telemetry_session.round_count - 1
        ];

    round->memory.peak_sram_bytes =
        get_peak_sram();

    round->memory.min_free_heap_bytes =
        get_min_free_heap();

    round->memory.largest_free_block_bytes =
        get_largest_free_block();

    round->memory.heap_zero_confirmed =
        check_heap_zero();
}

/* ------------------------------------------------------------------------- */
/* Stack measurements                                                        */
/* ------------------------------------------------------------------------- */

void telemetry_update_stacks(void)
{
    if (g_telemetry_session.round_count == 0) {
        return;
    }

    telemetry_round_t* round =
        &g_telemetry_session.rounds[
            g_telemetry_session.round_count - 1
        ];

    TaskStatus_t tasks[TELEMETRY_MAX_TASKS];

    UBaseType_t count =
        uxTaskGetSystemState(
            tasks,
            TELEMETRY_MAX_TASKS,
            NULL);

    if (count > TELEMETRY_MAX_TASKS) {
        count = TELEMETRY_MAX_TASKS;
    }

    round->stacks.task_count =
        (uint8_t)count;

    for (UBaseType_t i = 0;
         i < count;
         i++) {

        task_stack_info_t* info =
            &round->stacks.tasks[i];

        memset(
            info,
            0,
            sizeof(*info));

        if (tasks[i].pcTaskName != NULL) {
            strncpy(
                info->task_name,
                tasks[i].pcTaskName,
                sizeof(info->task_name) - 1u);

            info->task_name[
                sizeof(info->task_name) - 1u] = '\0';
        }

        /*
         * FreeRTOS exposes the remaining stack high-water mark
         * through TaskStatus_t. The exact configured stack depth
         * is not exposed by this API, so retain the existing
         * project convention of 1024 words.
         */
        info->stack_size_words = 1024u;

        info->high_water_mark_words =
            tasks[i].usStackHighWaterMark;

        if (info->stack_size_words >=
            info->high_water_mark_words) {

            info->current_usage_words =
                info->stack_size_words -
                info->high_water_mark_words;

        } else {
            info->current_usage_words = 0;
        }
    }
}

/* ------------------------------------------------------------------------- */
/* Round lifecycle                                                           */
/* ------------------------------------------------------------------------- */

void telemetry_round_start(uint32_t round_id)
{
    if (g_telemetry_session.round_count >=
        TELEMETRY_MAX_OPS) {
        return;
    }

    g_round_start_tick =
        xTaskGetTickCount();

    telemetry_round_t* round =
        &g_telemetry_session.rounds[
            g_telemetry_session.round_count
        ];

    memset(
        round,
        0,
        sizeof(*round));

    round->round_id =
        round_id;

    g_telemetry_session.round_count++;
}

void telemetry_round_end(
    uint8_t success,
    uint8_t accuracy)
{
    if (g_telemetry_session.round_count == 0) {
        return;
    }

    telemetry_round_t* round =
        &g_telemetry_session.rounds[
            g_telemetry_session.round_count - 1
        ];

    TickType_t now =
        xTaskGetTickCount();

    round->round_latency_ms =
        (uint32_t)now -
        (uint32_t)g_round_start_tick;

    if (g_dropout_detect_tick != 0) {
        round->dropout_detection_ms =
            (uint32_t)now -
            (uint32_t)g_dropout_detect_tick;
    } else {
        round->dropout_detection_ms = 0;
    }

    if (g_recovery_start_tick != 0) {
        round->recovery_latency_ms =
            (uint32_t)now -
            (uint32_t)g_recovery_start_tick;
    } else {
        round->recovery_latency_ms = 0;
    }

    round->aggregation_success =
        success;

    round->final_accuracy =
        accuracy;

    telemetry_update_memory();
    telemetry_update_stacks();
}

/* ------------------------------------------------------------------------- */
/* Network measurements                                                      */
/* ------------------------------------------------------------------------- */

void telemetry_record_network(
    uint32_t tx,
    uint32_t rx,
    uint32_t packets,
    uint32_t retrans,
    uint32_t fragments)
{
    if (g_telemetry_session.round_count == 0) {
        return;
    }

    telemetry_round_t* round =
        &g_telemetry_session.rounds[
            g_telemetry_session.round_count - 1
        ];

    round->bytes_tx =
        tx;

    round->bytes_rx =
        rx;

    round->packet_count =
        packets;

    round->retransmissions =
        retrans;

    round->fragment_count =
        fragments;
}

void telemetry_record_timing(
    uint32_t round_latency,
    uint32_t dropout_detect,
    uint32_t recovery)
{
    if (g_telemetry_session.round_count == 0) {
        return;
    }

    telemetry_round_t* round =
        &g_telemetry_session.rounds[
            g_telemetry_session.round_count - 1
        ];

    round->round_latency_ms =
        round_latency;

    round->dropout_detection_ms =
        dropout_detect;

    round->recovery_latency_ms =
        recovery;
}

/* ------------------------------------------------------------------------- */
/* Dropout/recovery timing                                                   */
/* ------------------------------------------------------------------------- */

void telemetry_dropout_detected(void)
{
    g_dropout_detect_tick =
        xTaskGetTickCount();
}

void telemetry_recovery_started(void)
{
    g_recovery_start_tick =
        xTaskGetTickCount();
}

/* ------------------------------------------------------------------------- */
/* Combined round telemetry                                                  */
/* ------------------------------------------------------------------------- */

void telemetry_record_round_telemetry(void)
{
    telemetry_update_memory();
    telemetry_update_stacks();
}

/* ------------------------------------------------------------------------- */
/* Telemetry serialization                                                   */
/* ------------------------------------------------------------------------- */

void telemetry_pack_round_complete(
    uint8_t* payload,
    size_t* payload_len)
{
    if (payload == NULL ||
        payload_len == NULL ||
        g_telemetry_session.round_count == 0) {
        return;
    }

    telemetry_round_t* round =
        &g_telemetry_session.rounds[
            g_telemetry_session.round_count - 1
        ];

    size_t offset = 0;

#define WRITE_U32(value)                     \
    do {                                     \
        uint32_t _v = (value);               \
        payload[offset++] =                 \
            (uint8_t)((_v >> 24) & 0xFFu);  \
        payload[offset++] =                 \
            (uint8_t)((_v >> 16) & 0xFFu);  \
        payload[offset++] =                 \
            (uint8_t)((_v >> 8) & 0xFFu);   \
        payload[offset++] =                 \
            (uint8_t)(_v & 0xFFu);           \
    } while (0)

    WRITE_U32(round->round_id);

    WRITE_U32(
        round->crypto.keygen_cycles);

    WRITE_U32(
        round->crypto.encaps_cycles);

    WRITE_U32(
        round->crypto.decaps_cycles);

    WRITE_U32(
        round->crypto.hkdf_cycles);

    WRITE_U32(
        round->crypto.mask_gen_cycles);

    WRITE_U32(
        round->crypto.mask_apply_cycles);

    WRITE_U32(
        round->memory.peak_sram_bytes);

    WRITE_U32(
        round->memory.min_free_heap_bytes);

    WRITE_U32(
        round->memory.largest_free_block_bytes);

    /*
     * Preserve the existing telemetry format:
     * serialize the first task's high-water mark.
     */
    if (round->stacks.task_count > 0) {
        WRITE_U32(
            round->stacks.tasks[0]
                .high_water_mark_words);
    } else {
        WRITE_U32(0);
    }

    payload[offset++] =
        round->memory.heap_zero_confirmed;

    payload[offset++] =
        round->aggregation_success;

    payload[offset++] =
        round->final_accuracy;

    payload[offset++] = 0;

#undef WRITE_U32

    *payload_len = offset;
}