#ifndef TELEMETRY_H
#define TELEMETRY_H

#include "protocol_types.h"
#include <stdint.h>

#define TELEMETRY_MAX_TASKS 8
#define TELEMETRY_MAX_OPS 16

typedef struct {
    uint32_t keygen_cycles;
    uint32_t encaps_cycles;
    uint32_t decaps_cycles;
    uint32_t hkdf_cycles;
    uint32_t mask_gen_cycles;
    uint32_t mask_apply_cycles;
} crypto_cycles_t;

typedef struct {
    uint32_t peak_sram_bytes;
    uint32_t min_free_heap_bytes;
    uint32_t largest_free_block_bytes;
    uint32_t heap_zero_confirmed;
} memory_stats_t;

typedef struct {
    char task_name[16];
    uint32_t stack_size_words;
    uint32_t high_water_mark_words;
    uint32_t current_usage_words;
} task_stack_info_t;

typedef struct {
    task_stack_info_t tasks[TELEMETRY_MAX_TASKS];
    uint8_t task_count;
} stack_stats_t;

typedef struct {
    uint32_t round_id;
    uint32_t round_latency_ms;
    uint32_t dropout_detection_ms;
    uint32_t recovery_latency_ms;
    uint32_t bytes_tx;
    uint32_t bytes_rx;
    uint32_t packet_count;
    uint32_t retransmissions;
    uint32_t fragment_count;
    crypto_cycles_t crypto;
    memory_stats_t memory;
    stack_stats_t stacks;
    uint8_t aggregation_success;
    uint8_t final_accuracy;
} telemetry_round_t;

typedef struct {
    telemetry_round_t rounds[TELEMETRY_MAX_OPS];
    uint8_t round_count;
} telemetry_session_t;

extern telemetry_session_t g_telemetry_session;

void telemetry_init(void);
void telemetry_cycle_start(void);
uint32_t telemetry_cycle_end(void);
void telemetry_record_crypto(uint32_t keygen, uint32_t encaps, uint32_t decaps, uint32_t hkdf, uint32_t mask_gen, uint32_t mask_apply);
void telemetry_update_memory(void);
void telemetry_update_stacks(void);
void telemetry_round_start(uint32_t round_id);
void telemetry_round_end(uint8_t success, uint8_t accuracy);
void telemetry_record_network(uint32_t tx, uint32_t rx, uint32_t packets, uint32_t retrans, uint32_t fragments);
void telemetry_record_timing(uint32_t round_latency, uint32_t dropout_detect, uint32_t recovery);
void telemetry_start_cycle_measure(void);
uint32_t telemetry_end_cycle_measure(void);
void telemetry_record_round_telemetry(void);

#endif
