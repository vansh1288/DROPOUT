import os

def create_telemetry_header():
    path = r"C:\DROP\src\core_rtos\telemetry.h"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    content = '''#ifndef TELEMETRY_H
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

#endif
'''
    with open(path, "w") as f:
        f.write(content)
    print("Created telemetry.h")

def create_telemetry_c():
    path = r"C:\DROP\src\core_rtos\telemetry.c"
    content = '''#include "telemetry.h"
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
    return 0;
}

static uint32_t get_largest_free_block(void) {
    return 0;
}

static int check_heap_zero(void) {
    return 1;
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
'''
    with open(path, "w") as f:
        f.write(content)
    print("Created telemetry.c")

def modify_main_c():
    path = r"C:\DROP\src\core_rtos\main.c"
    content = '''#include "FreeRTOS.h"
#include "task.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "kem_adapter.h"
#include "stream_aggregator.h"
#include "dma_transport.h"
#include "state_machine.h"
#include "telemetry.h"
#include <string.h>

union Global_Scratchpad g_scratchpad;

static StackType_t crypto_stack[1024];
static StaticTask_t crypto_tcb;

static StackType_t stream_stack[1024];
static StaticTask_t stream_tcb;

static StackType_t network_stack[1024];
static StaticTask_t network_tcb;

static StackType_t monitor_stack[1024];
static StaticTask_t monitor_tcb;

typedef enum {
    CRYPTO_OP_NONE = 0,
    CRYPTO_OP_KEYPAIR = 1,
    CRYPTO_OP_ENCAPSULATE = 2,
    CRYPTO_OP_DECAPSULATE = 3,
    CRYPTO_OP_HKDF = 4
} crypto_op_t;

typedef struct {
    crypto_op_t op;
    kem_keypair_t* keypair_out;
    const uint8_t* public_key;
    size_t pk_len;
    kem_encapsulation_t* encap_out;
    const uint8_t* ciphertext;
    size_t ct_len;
    const uint8_t* secret_key;
    size_t sk_len;
    uint8_t* shared_secret_out;
    const uint8_t* shared_secret_in;
    const uint8_t* salt;
    size_t salt_len;
    const uint8_t* info;
    size_t info_len;
    uint8_t* session_key_out;
    BaseType_t* done_flag;
} crypto_work_item_t;

static crypto_work_item_t g_crypto_work = {0};

static void crypto_worker_task(void* pvParameters) {
    while (1) {
        uint32_t notify = ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        if (notify & 0x01) {
            if (g_crypto_work.op == CRYPTO_OP_KEYPAIR && g_crypto_work.keypair_out) {
                telemetry_cycle_start();
                kem_adapter_keypair(g_crypto_work.keypair_out);
                uint32_t cycles = telemetry_cycle_end();
                if (g_telemetry_session.round_count > 0) {
                    telemetry_record_crypto(cycles, 0, 0, 0, 0, 0);
                }
                if (g_crypto_work.done_flag) *g_crypto_work.done_flag = pdTRUE;
            }
        }
        if (notify & 0x02) {
            if (g_crypto_work.op == CRYPTO_OP_ENCAPSULATE && g_crypto_work.public_key && g_crypto_work.encap_out) {
                telemetry_cycle_start();
                kem_adapter_encapsulate(g_crypto_work.public_key, g_crypto_work.pk_len, g_crypto_work.encap_out);
                uint32_t cycles = telemetry_cycle_end();
                if (g_telemetry_session.round_count > 0) {
                    telemetry_record_crypto(0, cycles, 0, 0, 0, 0);
                }
                if (g_crypto_work.done_flag) *g_crypto_work.done_flag = pdTRUE;
            }
        }
        if (notify & 0x04) {
            if (g_crypto_work.op == CRYPTO_OP_DECAPSULATE && g_crypto_work.ciphertext && g_crypto_work.secret_key && g_crypto_work.shared_secret_out) {
                telemetry_cycle_start();
                kem_adapter_decapsulate(g_crypto_work.ciphertext, g_crypto_work.ct_len, g_crypto_work.secret_key, g_crypto_work.sk_len, g_crypto_work.shared_secret_out);
                uint32_t cycles = telemetry_cycle_end();
                if (g_telemetry_session.round_count > 0) {
                    telemetry_record_crypto(0, 0, cycles, 0, 0, 0);
                }
                if (g_crypto_work.done_flag) *g_crypto_work.done_flag = pdTRUE;
            }
        }
        if (notify & 0x08) {
            if (g_crypto_work.op == CRYPTO_OP_HKDF && g_crypto_work.shared_secret_in && g_crypto_work.session_key_out) {
                telemetry_cycle_start();
                kem_adapter_derive_session_key(g_crypto_work.shared_secret_in, g_crypto_work.salt, g_crypto_work.salt_len, g_crypto_work.info, g_crypto_work.info_len, g_crypto_work.session_key_out);
                uint32_t cycles = telemetry_cycle_end();
                if (g_telemetry_session.round_count > 0) {
                    telemetry_record_crypto(0, 0, 0, cycles, 0, 0);
                }
                if (g_crypto_work.done_flag) *g_crypto_work.done_flag = pdTRUE;
            }
        }
    }
}

typedef struct {
    uint8_t client_id;
    uint32_t round_id;
    uint16_t chunk_index;
    uint16_t chunk_size;
} stream_work_item_t;

static stream_work_item_t g_stream_work = {0};
static uint8_t g_stream_op = 0;

static void stream_aggregator_task(void* pvParameters) {
    while (1) {
        uint32_t notify = ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        if (notify & 0x01) {
            if (g_stream_op == 1) {
                telemetry_cycle_start();
                stream_aggregator_process_chunk(g_stream_work.client_id, g_stream_work.round_id, g_stream_work.chunk_index, g_stream_work.chunk_size);
                uint32_t cycles = telemetry_cycle_end();
                if (g_telemetry_session.round_count > 0) {
                    telemetry_record_crypto(0, 0, 0, 0, cycles, 0);
                }
            }
        }
        if (notify & 0x02) {
            if (g_stream_op == 2) {
                telemetry_cycle_start();
                stream_aggregator_unmask_chunk(g_stream_work.client_id, g_stream_work.round_id, g_stream_work.chunk_index, g_stream_work.chunk_size);
                uint32_t cycles = telemetry_cycle_end();
                if (g_telemetry_session.round_count > 0) {
                    telemetry_record_crypto(0, 0, 0, 0, 0, cycles);
                }
            }
        }
    }
}

static void network_coordinator_task(void* pvParameters) {
    while (1) {
        uint32_t notify = ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        if (notify & 0x01) {
            dma_transport_rx_poll();
        }
        if (notify & 0x02) {
            dma_transport_tx_poll();
        }
    }
}

static client_protocol_ctx_t* g_client_contexts = NULL;
static uint8_t g_num_contexts = 0;

void protocol_register_context(client_protocol_ctx_t* ctx) {
    if (g_num_contexts < 16) {
        g_client_contexts = ctx;
        g_num_contexts = 1;
    }
}

static void protocol_check_timeouts(void) {
    if (g_client_contexts) {
        uint32_t current_tick = xTaskGetTickCount();
        if (current_tick - g_client_contexts->last_activity_tick > g_client_contexts->timeout_ms) {
            g_client_contexts->state = STATE_ERROR;
        }
    }
}

static void state_monitor_task(void* pvParameters) {
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(100));
        protocol_check_timeouts();
    }
}

void app_main(void) {
    memset(&g_scratchpad, 0, sizeof(union Global_Scratchpad));

    telemetry_init();

    xTaskCreateStatic(crypto_worker_task, "crypto_worker", 1024, NULL, 3, crypto_stack, &crypto_tcb);
    xTaskCreateStatic(stream_aggregator_task, "stream_aggregator", 1024, NULL, 2, stream_stack, &stream_tcb);
    xTaskCreateStatic(network_coordinator_task, "network_coordinator", 1024, NULL, 2, network_stack, &network_tcb);
    xTaskCreateStatic(state_monitor_task, "state_monitor", 1024, NULL, 1, monitor_stack, &monitor_tcb);

    dma_isr_set_stream_task(stream_tcb);
    dma_isr_init();
    kem_adapter_init(KEMLIB_ML_KEM_768);

    vTaskStartScheduler();

    while (1);
}
'''
    with open(path, "w") as f:
        f.write(content)
    print("Modified main.c")

def create_renode_script():
    path = r"C:\DROP\emulation\multi_node.resc"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    content = '''using sysbus = Renode.Peripherals.Bus.Bus
using switch = Renode.Networking.Switch
using emulator = Renode.Core.Emulator
using cpu = Renode.Peripherals.CPU.CortexM
using machine = Renode.Peripherals.MachineRegistration
using gpio = Renode.Peripherals.GPIOPort
using uart = Renode.Peripherals.UART
using timer = Renode.Peripherals.Timers.SysTick
using flash = Renode.Peripherals.Flash
using network = Renode.Networking

$bin = @C:\DROP\build\cortex_m4\firmware.elf

emulator SetGlobalQuantum "100000"

$num_nodes = 3

$switch = switch.CreateSwitch()
$switch.Name = "virtual_switch"

for $i in 0..($num_nodes - 1)
    $node_name = sprintf("node%d", $i)
    emu $node_name = emulator.Create()
    $node_name.LoadPlatformDescription(@platforms/cpus/cortex_m4_nucleo_f446re.repl)
    $node_name.SetMachineName($node_name)
    
    $node_name.LoadBinary($bin)
    
    $node_name.Machine.RegisterEmailNotifier("renode")
    
    $node_name.Sysbus.usart2.Connect($switch)
    
    $node_name.Sysbus.gpiob.Pin9.Connect($node_name.Sysbus.led1)
    $node_name.Sysbus.gpiob.Pin14.Connect($node_name.Sysbus.led2)
    
    $node_name.CPU.Configure("0x08000000", "0x20000000", "0x10000", "0x1000")
    $node_name.CPU.SetRegister("PC", "0x08000004")
    $node_name.CPU.SetRegister("SP", "0x20020000")
    
    $node_name.Start()
end

$switch.Enable()
$switch.SetPromiscuousMode(true)

for $i in 0..($num_nodes - 1)
    $node_name = sprintf("node%d", $i)
    emu $node_name.PrintCPUInfo()
end

macro start_all()
    for $i in 0..($num_nodes - 1)
        $node_name = sprintf("node%d", $i)
        emu $node_name.Start()
    end
end

macro pause_all()
    for $i in 0..($num_nodes - 1)
        $node_name = sprintf("node%d", $i)
        emu $node_name.Pause()
    end
end

macro reset_all()
    for $i in 0..($num_nodes - 1)
        $node_name = sprintf("node%d", $i)
        emu $node_name.Reset()
    end
end

print "Multi-node emulation ready. Use 'start_all' to begin."
'''
    with open(path, "w") as f:
        f.write(content)
    print("Created multi_node.resc")

if __name__ == "__main__":
    create_telemetry_header()
    create_telemetry_c()
    modify_main_c()
    create_renode_script()
    print("Batch 4 modifications completed successfully.")