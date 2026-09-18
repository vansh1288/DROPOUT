#include "FreeRTOS.h"
#include "task.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "kem_adapter.h"
#include "stream_aggregator.h"
#include "dma_transport.h"
#include "state_machine.h"
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
                kem_adapter_keypair(g_crypto_work.keypair_out);
                if (g_crypto_work.done_flag) *g_crypto_work.done_flag = pdTRUE;
            }
        }
        if (notify & 0x02) {
            if (g_crypto_work.op == CRYPTO_OP_ENCAPSULATE && g_crypto_work.public_key && g_crypto_work.encap_out) {
                kem_adapter_encapsulate(g_crypto_work.public_key, g_crypto_work.pk_len, g_crypto_work.encap_out);
                if (g_crypto_work.done_flag) *g_crypto_work.done_flag = pdTRUE;
            }
        }
        if (notify & 0x04) {
            if (g_crypto_work.op == CRYPTO_OP_DECAPSULATE && g_crypto_work.ciphertext && g_crypto_work.secret_key && g_crypto_work.shared_secret_out) {
                kem_adapter_decapsulate(g_crypto_work.ciphertext, g_crypto_work.ct_len, g_crypto_work.secret_key, g_crypto_work.sk_len, g_crypto_work.shared_secret_out);
                if (g_crypto_work.done_flag) *g_crypto_work.done_flag = pdTRUE;
            }
        }
        if (notify & 0x08) {
            if (g_crypto_work.op == CRYPTO_OP_HKDF && g_crypto_work.shared_secret_in && g_crypto_work.session_key_out) {
                kem_adapter_derive_session_key(g_crypto_work.shared_secret_in, g_crypto_work.salt, g_crypto_work.salt_len, g_crypto_work.info, g_crypto_work.info_len, g_crypto_work.session_key_out);
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
                stream_aggregator_process_chunk(g_stream_work.client_id, g_stream_work.round_id, g_stream_work.chunk_index, g_stream_work.chunk_size);
            }
        }
        if (notify & 0x02) {
            if (g_stream_op == 2) {
                stream_aggregator_unmask_chunk(g_stream_work.client_id, g_stream_work.round_id, g_stream_work.chunk_index, g_stream_work.chunk_size);
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