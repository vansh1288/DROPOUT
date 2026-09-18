import os

def read_file(path):
    with open(path, 'r') as f:
        return f.read()

def write_file(path, content):
    with open(path, 'w') as f:
        f.write(content)

# ============================================================
# 1. Create crypto_worker.c with queue-based architecture
# ============================================================
crypto_worker_c = '''#include "crypto_worker.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "kem_adapter.h"
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "telemetry.h"
#include <string.h>

#define CRYPTO_QUEUE_LENGTH 8
#define CRYPTO_QUEUE_ITEM_SIZE sizeof(crypto_work_item_t)

static QueueHandle_t g_crypto_queue = NULL;
static StackType_t crypto_stack[1024];
static StaticTask_t crypto_tcb;
static uint8_t crypto_queue_storage[CRYPTO_QUEUE_LENGTH * CRYPTO_QUEUE_ITEM_SIZE];
static StaticQueue_t crypto_queue_struct;

void crypto_worker_init(void) {
    g_crypto_queue = xQueueCreateStatic(CRYPTO_QUEUE_LENGTH, CRYPTO_QUEUE_ITEM_SIZE, crypto_queue_storage, &crypto_queue_struct);
    xTaskCreateStatic(crypto_worker_task, "crypto_worker", 1024, NULL, 3, crypto_stack, &crypto_tcb);
}

BaseType_t crypto_worker_submit(const crypto_work_item_t* item, TickType_t timeout) {
    if (!g_crypto_queue) return pdFALSE;
    return xQueueSend(g_crypto_queue, item, timeout);
}

static void crypto_worker_task(void* pvParameters) {
    crypto_work_item_t item;
    while (1) {
        if (xQueueReceive(g_crypto_queue, &item, portMAX_DELAY) == pdTRUE) {
            switch (item.op) {
                case CRYPTO_OP_KEYPAIR:
                    if (item.keypair_out) {
                        telemetry_cycle_start();
                        kem_adapter_keypair(item.keypair_out);
                        uint32_t cycles = telemetry_cycle_end();
                        if (g_telemetry_session.round_count > 0) {
                            telemetry_record_crypto(cycles, 0, 0, 0, 0, 0);
                        }
                        if (item.done_flag) *item.done_flag = pdTRUE;
                    }
                    break;
                case CRYPTO_OP_ENCAPSULATE:
                    if (item.public_key && item.encap_out) {
                        telemetry_cycle_start();
                        kem_adapter_encapsulate(item.public_key, item.pk_len, item.encap_out);
                        uint32_t cycles = telemetry_cycle_end();
                        if (g_telemetry_session.round_count > 0) {
                            telemetry_record_crypto(0, cycles, 0, 0, 0, 0);
                        }
                        if (item.done_flag) *item.done_flag = pdTRUE;
                    }
                    break;
                case CRYPTO_OP_DECAPSULATE:
                    if (item.ciphertext && item.secret_key && item.shared_secret_out) {
                        telemetry_cycle_start();
                        kem_adapter_decapsulate(item.ciphertext, item.ct_len, item.secret_key, item.sk_len, item.shared_secret_out);
                        uint32_t cycles = telemetry_cycle_end();
                        if (g_telemetry_session.round_count > 0) {
                            telemetry_record_crypto(0, 0, cycles, 0, 0, 0);
                        }
                        if (item.done_flag) *item.done_flag = pdTRUE;
                    }
                    break;
                case CRYPTO_OP_HKDF:
                    if (item.shared_secret_in && item.session_key_out) {
                        telemetry_cycle_start();
                        kem_adapter_derive_session_key(item.shared_secret_in, item.salt, item.salt_len, item.info, item.info_len, item.session_key_out);
                        uint32_t cycles = telemetry_cycle_end();
                        if (g_telemetry_session.round_count > 0) {
                            telemetry_record_crypto(0, 0, 0, cycles, 0, 0);
                        }
                        if (item.done_flag) *item.done_flag = pdTRUE;
                    }
                    break;
                default:
                    break;
            }
        }
    }
}
'''

crypto_worker_h = '''#ifndef CRYPTO_WORKER_H
#define CRYPTO_WORKER_H

#include "protocol_types.h"
#include "FreeRTOS.h"
#include <stdint.h>

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

void crypto_worker_init(void);
BaseType_t crypto_worker_submit(const crypto_work_item_t* item, TickType_t timeout);

#endif
'''

# ============================================================
# 2. Modify stream_aggregator.c with queue-based architecture
# ============================================================
stream_aggregator_c = '''#include "stream_aggregator.h"
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
'''

stream_aggregator_h = '''#ifndef STREAM_AGGREGATOR_H
#define STREAM_AGGREGATOR_H

#include "protocol_types.h"
#include "FreeRTOS.h"
#include <stdint.h>

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

void stream_aggregator_init(void);
TaskHandle_t stream_aggregator_get_task_handle(void);
BaseType_t stream_aggregator_submit(const stream_work_item_t* item, TickType_t timeout);
pqc_status_t stream_aggregator_process_chunk(uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size, const uint8_t* shared_secret);
pqc_status_t stream_aggregator_unmask_chunk(uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size, const uint8_t* shared_secret);

#endif
'''

# ============================================================
# 3. Modify main.c to use proper TaskHandle_t and queue initialization
# ============================================================
main_c = '''#include "FreeRTOS.h"
#include "task.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "kem_adapter.h"
#include "stream_aggregator.h"
#include "crypto_worker.h"
#include "dma_transport.h"
#include "state_machine.h"
#include "telemetry.h"
#include "dma_isr_handler.h"
#include <string.h>

union Global_Scratchpad g_scratchpad;

static StackType_t network_stack[1024];
static StaticTask_t network_tcb;

static StackType_t monitor_stack[1024];
static StaticTask_t monitor_tcb;

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

    crypto_worker_init();
    stream_aggregator_init();

    TaskHandle_t stream_task_handle = stream_aggregator_get_task_handle();
    dma_isr_set_stream_task(stream_task_handle);

    xTaskCreateStatic(network_coordinator_task, "network_coordinator", 1024, NULL, 2, network_stack, &network_tcb);
    xTaskCreateStatic(state_monitor_task, "state_monitor", 1024, NULL, 1, monitor_stack, &monitor_tcb);

    dma_isr_init();
    kem_adapter_init(KEMLIB_ML_KEM_768);

    vTaskStartScheduler();

    while (1);
}
'''

# ============================================================
# 4. Modify packet_codec.c with constant-time MAC comparison
# ============================================================
packet_codec_c = '''#include "packet_codec.h"
#include <tinycrypt/hmac.h>
#include <tinycrypt/sha256.h>
#include <string.h>

#define HEADER_SIZE 16
#define MAC_SIZE 32
#define MAC_OFFSET (HEADER_SIZE)
#define PAYLOAD_OFFSET (HEADER_SIZE + MAC_SIZE)

static void build_mac_data(const msg_header_t* hdr, const uint8_t* payload, size_t payload_len, uint8_t* mac_data) {
    size_t idx = 0;
    mac_data[idx++] = (hdr->protocol_version >> 24) & 0xFF;
    mac_data[idx++] = (hdr->protocol_version >> 16) & 0xFF;
    mac_data[idx++] = (hdr->protocol_version >> 8) & 0xFF;
    mac_data[idx++] = hdr->protocol_version & 0xFF;
    mac_data[idx++] = (hdr->round_id >> 24) & 0xFF;
    mac_data[idx++] = (hdr->round_id >> 16) & 0xFF;
    mac_data[idx++] = (hdr->round_id >> 8) & 0xFF;
    mac_data[idx++] = hdr->round_id & 0xFF;
    mac_data[idx++] = hdr->client_id;
    mac_data[idx++] = hdr->message_type;
    mac_data[idx++] = (hdr->sequence_number >> 8) & 0xFF;
    mac_data[idx++] = hdr->sequence_number & 0xFF;
    if (payload && payload_len > 0) {
        for (size_t i = 0; i < payload_len; i++) {
            mac_data[idx++] = payload[i];
        }
    }
}

pqc_status_t packet_codec_encode_header(const msg_header_t* hdr, uint8_t* out) {
    if (!hdr || !out) return ERR_INVALID_ARGUMENT;
    out[0] = (hdr->protocol_version >> 24) & 0xFF;
    out[1] = (hdr->protocol_version >> 16) & 0xFF;
    out[2] = (hdr->protocol_version >> 8) & 0xFF;
    out[3] = hdr->protocol_version & 0xFF;
    out[4] = (hdr->round_id >> 24) & 0xFF;
    out[5] = (hdr->round_id >> 16) & 0xFF;
    out[6] = (hdr->round_id >> 8) & 0xFF;
    out[7] = hdr->round_id & 0xFF;
    out[8] = hdr->client_id;
    out[9] = hdr->message_type;
    out[10] = (hdr->sequence_number >> 8) & 0xFF;
    out[11] = hdr->sequence_number & 0xFF;
    out[12] = (hdr->payload_length >> 8) & 0xFF;
    out[13] = hdr->payload_length & 0xFF;
    out[14] = (hdr->reserved >> 8) & 0xFF;
    out[15] = hdr->reserved & 0xFF;
    return PQC_SUCCESS;
}

pqc_status_t packet_codec_decode_header(const uint8_t* in, msg_header_t* hdr) {
    if (!in || !hdr) return ERR_INVALID_ARGUMENT;
    hdr->protocol_version = ((uint32_t)in[0] << 24) | ((uint32_t)in[1] << 16) | ((uint32_t)in[2] << 8) | in[3];
    hdr->round_id = ((uint32_t)in[4] << 24) | ((uint32_t)in[5] << 16) | ((uint32_t)in[6] << 8) | in[7];
    hdr->client_id = in[8];
    hdr->message_type = in[9];
    hdr->sequence_number = ((uint16_t)in[10] << 8) | in[11];
    hdr->payload_length = ((uint16_t)in[12] << 8) | in[13];
    hdr->reserved = ((uint16_t)in[14] << 8) | in[15];
    return PQC_SUCCESS;
}

pqc_status_t packet_codec_compute_mac(const uint8_t* key, const uint8_t* data, size_t data_len, uint8_t* mac) {
    if (!key || !data || !mac) return ERR_INVALID_ARGUMENT;
    struct tc_hmac_state_struct hmac;
    tc_hmac_set_key(&hmac, key, 32);
    tc_hmac_init(&hmac);
    tc_hmac_update(&hmac, data, data_len);
    tc_hmac_final(mac, MAC_SIZE, &hmac);
    return PQC_SUCCESS;
}

static int crypto_ct_memcmp(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) {
        diff |= a[i] ^ b[i];
    }
    return (int)diff;
}

pqc_status_t packet_codec_verify_mac(const uint8_t* key, const uint8_t* data, size_t data_len, const uint8_t* mac) {
    if (!key || !data || !mac) return ERR_INVALID_ARGUMENT;
    uint8_t expected_mac[MAC_SIZE];
    pqc_status_t ret = packet_codec_compute_mac(key, data, data_len, expected_mac);
    if (ret != PQC_SUCCESS) return ret;
    if (crypto_ct_memcmp(expected_mac, mac, MAC_SIZE) != 0) return ERR_AUTH_FAILED;
    return PQC_SUCCESS;
}

pqc_status_t packet_codec_encode_message(const msg_header_t* hdr, const uint8_t* payload, const uint8_t* mac_key, uint8_t* out, size_t* out_len) {
    if (!hdr || !out || !out_len || !mac_key) return ERR_INVALID_ARGUMENT;
    if (hdr->payload_length > 0 && !payload) return ERR_INVALID_ARGUMENT;
    pqc_status_t ret = packet_codec_encode_header(hdr, out);
    if (ret != PQC_SUCCESS) return ret;
    if (hdr->payload_length > 0) {
        memcpy(out + PAYLOAD_OFFSET, payload, hdr->payload_length);
    }
    uint8_t mac_data[12 + 1024];
    size_t mac_data_len = 12;
    build_mac_data(hdr, payload, hdr->payload_length, mac_data);
    mac_data_len += hdr->payload_length;
    uint8_t mac[MAC_SIZE];
    ret = packet_codec_compute_mac(mac_key, mac_data, mac_data_len, mac);
    if (ret != PQC_SUCCESS) return ret;
    memcpy(out + MAC_OFFSET, mac, MAC_SIZE);
    *out_len = PAYLOAD_OFFSET + hdr->payload_length;
    return PQC_SUCCESS;
}

pqc_status_t packet_codec_decode_message(const uint8_t* in, size_t in_len, const uint8_t* mac_key, msg_header_t* hdr, uint8_t* payload, size_t* payload_len) {
    if (!in || !hdr || !mac_key || in_len < PAYLOAD_OFFSET) return ERR_INVALID_ARGUMENT;
    pqc_status_t ret = packet_codec_decode_header(in, hdr);
    if (ret != PQC_SUCCESS) return ret;
    if (in_len < PAYLOAD_OFFSET + hdr->payload_length) return ERR_INVALID_ARGUMENT;
    uint8_t mac_data[12 + 1024];
    size_t mac_data_len = 12;
    build_mac_data(hdr, in + PAYLOAD_OFFSET, hdr->payload_length, mac_data);
    mac_data_len += hdr->payload_length;
    uint8_t received_mac[MAC_SIZE];
    memcpy(received_mac, in + MAC_OFFSET, MAC_SIZE);
    ret = packet_codec_verify_mac(mac_key, mac_data, mac_data_len, received_mac);
    if (ret != PQC_SUCCESS) return ret;
    if (hdr->payload_length > 0 && payload) {
        memcpy(payload, in + PAYLOAD_OFFSET, hdr->payload_length);
    }
    if (payload_len) *payload_len = hdr->payload_length;
    return PQC_SUCCESS;
}

pqc_status_t packet_codec_validate_sequence(const msg_header_t* hdr, uint16_t expected_seq) {
    if (!hdr) return ERR_INVALID_ARGUMENT;
    if (hdr->sequence_number != expected_seq) return ERR_SEQUENCE_MISMATCH;
    return PQC_SUCCESS;
}

pqc_status_t packet_codec_validate_round(const msg_header_t* hdr, uint32_t expected_round) {
    if (!hdr) return ERR_INVALID_ARGUMENT;
    if (hdr->round_id != expected_round) return ERR_ROUND_MISMATCH;
    return PQC_SUCCESS;
}

pqc_status_t packet_codec_validate_client(const msg_header_t* hdr, uint8_t expected_client) {
    if (!hdr) return ERR_INVALID_ARGUMENT;
    if (hdr->client_id != 0 && hdr->client_id != expected_client) return ERR_CLIENT_ID_MISMATCH;
    return PQC_SUCCESS;
}
'''

# ============================================================
# Write all files
# ============================================================
# Create crypto_worker.c and crypto_worker.h
write_file(r'C:\DROP\src\core_rtos\crypto_worker.c', crypto_worker_c)
write_file(r'C:\DROP\src\core_rtos\crypto_worker.h', crypto_worker_h)
print("Created crypto_worker.c and crypto_worker.h")

# Modify stream_aggregator.c and stream_aggregator.h
write_file(r'C:\DROP\src\federated\stream_aggregator.c', stream_aggregator_c)
write_file(r'C:\DROP\src\federated\stream_aggregator.h', stream_aggregator_h)
print("Modified stream_aggregator.c and stream_aggregator.h")

# Modify main.c
write_file(r'C:\DROP\src\core_rtos\main.c', main_c)
print("Modified main.c")

# Modify packet_codec.c
write_file(r'C:\DROP\src\network\packet_codec.c', packet_codec_c)
print("Modified packet_codec.c")

print("All modifications applied successfully")