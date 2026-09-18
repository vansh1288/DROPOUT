#include "telemetry.h"
#include "memory_scratchpad.h"
#include "FreeRTOS.h"
#include "task.h"
#include <string.h>

telemetry_session_t g_telemetry_session = {0};

static uint32_t g_cycle_start = 0;
static uint32_t g_round_start_tick = 0;
static uint32_t g_dropout_detect_tick = 0;
static uint32_t g_recovery_start_tick = 0;

#if defined(__ARM_ARCH_7EM__) || defined(__ARM_ARCH_8M_BASE__) || defined(__ARM_ARCH_8M_MAIN__)
#define DWT_BASE 0xE0001000
#define DWT_CTRL (*(volatile uint32_t*)(DWT_BASE + 0x0))
#define DWT_CYCCNT (*(volatile uint32_t*)(DWT_BASE + 0x4))
#define DWT_CTRL_CYCCNTENA (1 << 0)

static void dwt_init(void) {
    DWT_CTRL |= DWT_CTRL_CYCCNTENA;
}

static inline uint32_t dwt_read_cycles(void) {
    return DWT_CYCCNT;
}
#else
static inline void dwt_init(void) {}
static inline uint32_t dwt_read_cycles(void) { return 0; }
#endif

static uint32_t get_peak_sram(void) {
    extern uint8_t _estack;
    extern uint8_t _ebss;
    extern uint8_t _sdata;
    extern uint8_t _ebss;
    uint32_t total = (uint32_t)&_estack - (uint32_t)&_sdata;
    return total;
}

static uint32_t get_min_free_heap(void) {
    return xPortGetFreeHeapSize();
}

static uint32_t get_largest_free_block(void) {
    return xPortGetFreeHeapSize();
}

static int check_heap_zero(void) {
    extern uint8_t _sdata;
    extern uint8_t _ebss;
    extern uint8_t _estack;
    
    uint32_t static_used = (uint32_t)&_ebss - (uint32_t)&_sdata;
    uint32_t heap_used = configTOTAL_HEAP_SIZE - xPortGetFreeHeapSize();
    uint32_t total_dynamic = static_used + heap_used;
    
    return (total_dynamic == 0) ? 1 : 0;
}

void telemetry_init(void) {
    memset(&g_telemetry_session, 0, sizeof(telemetry_session_t));
    dwt_init();
}

void telemetry_cycle_start(void) {
    g_cycle_start = dwt_read_cycles();
}

uint32_t telemetry_cycle_end(void) {
    uint32_t end = dwt_read_cycles();
    uint32_t elapsed = end - g_cycle_start;
    g_cycle_start = 0;
    return elapsed;
}

void telemetry_record_crypto(uint32_t keygen, uint32_t encaps, uint32_t decaps, uint32_t hkdf, uint32_t mask_gen, uint32_t mask_apply) {
    if (g_telemetry_session.round_count > 0) {
        telemetry_round_t* round = &g_telemetry_session.rounds[g_telemetry_session.round_count - 1];
        round->crypto.keygen_cycles = keygen;
        round->crypto.encaps_cycles = encaps;
        round->crypto.decaps_cycles = decaps;
        round->crypto.hkdf_cycles = hkdf;
        round->crypto.mask_gen_cycles = mask_gen;
        round->crypto.mask_apply_cycles = mask_apply;
    }
}

void telemetry_update_memory(void) {
    if (g_telemetry_session.round_count > 0) {
        telemetry_round_t* round = &g_telemetry_session.rounds[g_telemetry_session.round_count - 1];
        round->memory.peak_sram_bytes = get_peak_sram();
        round->memory.min_free_heap_bytes = get_min_free_heap();
        round->memory.largest_free_block_bytes = get_largest_free_block();
        round->memory.heap_zero_confirmed = check_heap_zero();
    }
}

void telemetry_update_stacks(void) {
    if (g_telemetry_session.round_count > 0) {
        telemetry_round_t* round = &g_telemetry_session.rounds[g_telemetry_session.round_count - 1];
        TaskStatus_t tasks[TELEMETRY_MAX_TASKS];
        UBaseType_t count = uxTaskGetSystemState(tasks, TELEMETRY_MAX_TASKS, NULL);
        if (count > TELEMETRY_MAX_TASKS) count = TELEMETRY_MAX_TASKS;
        round->stacks.task_count = (uint8_t)count;
        for (UBaseType_t i = 0; i < count; i++) {
            task_stack_info_t* info = &round->stacks.tasks[i];
            strncpy(info->task_name, tasks[i].pcTaskName, 15);
            info->task_name[15] = 0;
            info->stack_size_words = 1024;
            info->high_water_mark_words = tasks[i].usStackHighWaterMark;
            info->current_usage_words = 1024 - tasks[i].usStackHighWaterMark;
        }
    }
}

void telemetry_round_start(uint32_t round_id) {
    if (g_telemetry_session.round_count < TELEMETRY_MAX_OPS) {
        g_round_start_tick = xTaskGetTickCount();
        telemetry_round_t* round = &g_telemetry_session.rounds[g_telemetry_session.round_count];
        round->round_id = round_id;
        g_telemetry_session.round_count++;
    }
}

void telemetry_round_end(uint8_t success, uint8_t accuracy) {
    if (g_telemetry_session.round_count > 0) {
        telemetry_round_t* round = &g_telemetry_session.rounds[g_telemetry_session.round_count - 1];
        round->round_latency_ms = xTaskGetTickCount() - g_round_start_tick;
        round->dropout_detection_ms = g_dropout_detect_tick ? (xTaskGetTickCount() - g_dropout_detect_tick) : 0;
        round->recovery_latency_ms = g_recovery_start_tick ? (xTaskGetTickCount() - g_recovery_start_tick) : 0;
        round->aggregation_success = success;
        round->final_accuracy = accuracy;
        telemetry_update_memory();
        telemetry_update_stacks();
    }
}

void telemetry_record_network(uint32_t tx, uint32_t rx, uint32_t packets, uint32_t retrans, uint32_t fragments) {
    if (g_telemetry_session.round_count > 0) {
        telemetry_round_t* round = &g_telemetry_session.rounds[g_telemetry_session.round_count - 1];
        round->bytes_tx = tx;
        round->bytes_rx = rx;
        round->packet_count = packets;
        round->retransmissions = retrans;
        round->fragment_count = fragments;
    }
}

void telemetry_record_timing(uint32_t round_latency, uint32_t dropout_detect, uint32_t recovery) {
    if (g_telemetry_session.round_count > 0) {
        telemetry_round_t* round = &g_telemetry_session.rounds[g_telemetry_session.round_count - 1];
        round->round_latency_ms = round_latency;
        round->dropout_detection_ms = dropout_detect;
        round->recovery_latency_ms = recovery;
    }
}

void telemetry_dropout_detected(void) {
    g_dropout_detect_tick = xTaskGetTickCount();
}

void telemetry_recovery_started(void) {
    g_recovery_start_tick = xTaskGetTickCount();
}

void telemetry_start_cycle_measure(void) {
    g_cycle_start = dwt_read_cycles();
}

uint32_t telemetry_end_cycle_measure(void) {
    uint32_t end = dwt_read_cycles();
    uint32_t elapsed = end - g_cycle_start;
    g_cycle_start = 0;
    return elapsed;
}

void telemetry_record_round_telemetry(void) {
    if (g_telemetry_session.round_count > 0) {
        telemetry_round_t* round = &g_telemetry_session.rounds[g_telemetry_session.round_count - 1];
        round->memory.peak_sram_bytes = get_peak_sram();
        round->memory.min_free_heap_bytes = xPortGetFreeHeapSize();
        round->memory.largest_free_block_bytes = 0;
        round->memory.heap_zero_confirmed = check_heap_zero();
        
        TaskStatus_t tasks[TELEMETRY_MAX_TASKS];
        UBaseType_t count = uxTaskGetSystemState(tasks, TELEMETRY_MAX_TASKS, NULL);
        if (count > TELEMETRY_MAX_TASKS) count = TELEMETRY_MAX_TASKS;
        round->stacks.task_count = (uint8_t)count;
        for (UBaseType_t i = 0; i < count; i++) {
            task_stack_info_t* info = &round->stacks.tasks[i];
            strncpy(info->task_name, tasks[i].pcTaskName, 15);
            info->task_name[15] = 0;
            info->stack_size_words = 1024;
            info->high_water_mark_words = tasks[i].usStackHighWaterMark;
            info->current_usage_words = 1024 - tasks[i].usStackHighWaterMark;
        }
    }
}

void telemetry_pack_round_complete(uint8_t* payload, size_t* payload_len) {
    if (g_telemetry_session.round_count == 0) return;
    telemetry_round_t* round = &g_telemetry_session.rounds[g_telemetry_session.round_count - 1];
    
    uint32_t offset = 0;
    payload[offset++] = (round->round_id >> 24) & 0xFF;
    payload[offset++] = (round->round_id >> 16) & 0xFF;
    payload[offset++] = (round->round_id >> 8) & 0xFF;
    payload[offset++] = round->round_id & 0xFF;
    
    payload[offset++] = (round->crypto.keygen_cycles >> 24) & 0xFF;
    payload[offset++] = (round->crypto.keygen_cycles >> 16) & 0xFF;
    payload[offset++] = (round->crypto.keygen_cycles >> 8) & 0xFF;
    payload[offset++] = round->crypto.keygen_cycles & 0xFF;
    
    payload[offset++] = (round->crypto.encaps_cycles >> 24) & 0xFF;
    payload[offset++] = (round->crypto.encaps_cycles >> 16) & 0xFF;
    payload[offset++] = (round->crypto.encaps_cycles >> 8) & 0xFF;
    payload[offset++] = round->crypto.encaps_cycles & 0xFF;
    
    payload[offset++] = (round->crypto.decaps_cycles >> 24) & 0xFF;
    payload[offset++] = (round->crypto.decaps_cycles >> 16) & 0xFF;
    payload[offset++] = (round->crypto.decaps_cycles >> 8) & 0xFF;
    payload[offset++] = round->crypto.decaps_cycles & 0xFF;
    
    payload[offset++] = (round->crypto.hkdf_cycles >> 24) & 0xFF;
    payload[offset++] = (round->crypto.hkdf_cycles >> 16) & 0xFF;
    payload[offset++] = (round->crypto.hkdf_cycles >> 8) & 0xFF;
    payload[offset++] = round->crypto.hkdf_cycles & 0xFF;
    
    payload[offset++] = (round->crypto.mask_gen_cycles >> 24) & 0xFF;
    payload[offset++] = (round->crypto.mask_gen_cycles >> 16) & 0xFF;
    payload[offset++] = (round->crypto.mask_gen_cycles >> 8) & 0xFF;
    payload[offset++] = round->crypto.mask_gen_cycles & 0xFF;
    
    payload[offset++] = (round->crypto.mask_apply_cycles >> 24) & 0xFF;
    payload[offset++] = (round->crypto.mask_apply_cycles >> 16) & 0xFF;
    payload[offset++] = (round->crypto.mask_apply_cycles >> 8) & 0xFF;
    payload[offset++] = round->crypto.mask_apply_cycles & 0xFF;
    
    payload[offset++] = (round->memory.peak_sram_bytes >> 24) & 0xFF;
    payload[offset++] = (round->memory.peak_sram_bytes >> 16) & 0xFF;
    payload[offset++] = (round->memory.peak_sram_bytes >> 8) & 0xFF;
    payload[offset++] = round->memory.peak_sram_bytes & 0xFF;
    
    payload[offset++] = (round->memory.min_free_heap_bytes >> 24) & 0xFF;
    payload[offset++] = (round->memory.min_free_heap_bytes >> 16) & 0xFF;
    payload[offset++] = (round->memory.min_free_heap_bytes >> 8) & 0xFF;
    payload[offset++] = round->memory.min_free_heap_bytes & 0xFF;
    
    payload[offset++] = (round->memory.largest_free_block_bytes >> 24) & 0xFF;
    payload[offset++] = (round->memory.largest_free_block_bytes >> 16) & 0xFF;
    payload[offset++] = (round->memory.largest_free_block_bytes >> 8) & 0xFF;
    payload[offset++] = round->memory.largest_free_block_bytes & 0xFF;
    
    payload[offset++] = (round->stacks.tasks[0].high_water_mark_words >> 24) & 0xFF;
    payload[offset++] = (round->stacks.tasks[0].high_water_mark_words >> 16) & 0xFF;
    payload[offset++] = (round->stacks.tasks[0].high_water_mark_words >> 8) & 0xFF;
    payload[offset++] = round->stacks.tasks[0].high_water_mark_words & 0xFF;
    
    payload[offset++] = round->memory.heap_zero_confirmed;
    payload[offset++] = round->aggregation_success;
    payload[offset++] = round->final_accuracy;
    payload[offset++] = 0;
    
    *payload_len = offset;
}
