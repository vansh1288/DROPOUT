import os

def fix_state_machine():
    path = r"C:\DROP\src\federated\state_machine.c"
    new_content = '''#include "protocol_types.h"
#include "memory_scratchpad.h"
#include "kem_adapter.h"
#include <stdint.h>
#include <string.h>

#define MAX_CLIENTS 16
#define STATE_TIMEOUT_MS 5000
#define LOCAL_TRAINING_DELAY_MS 100

static protocol_state_buffer_t* get_proto_state(void) {
    return scratch_get_proto_state();
}

static void mock_local_training(client_protocol_ctx_t* ctx) {
    for (volatile uint32_t i = 0; i < LOCAL_TRAINING_DELAY_MS * 1000; i++) {
        __asm__ volatile ("nop");
    }
    (void)ctx;
}

pqc_status_t state_machine_init(client_protocol_ctx_t* ctx, uint8_t client_id, uint32_t round_id) {
    if (!ctx) return ERR_INVALID_ARGUMENT;
    memset(ctx, 0, sizeof(client_protocol_ctx_t));
    ctx->client_id = client_id;
    ctx->current_round_id = round_id;
    ctx->state = STATE_ROUND_INIT;
    ctx->timeout_ms = STATE_TIMEOUT_MS;
    return PQC_SUCCESS;
}

pqc_status_t state_machine_transition(client_protocol_ctx_t* ctx, protocol_state_t new_state) {
    if (!ctx) return ERR_INVALID_ARGUMENT;
    if (ctx->state == STATE_ERROR) return ERR_INVALID_STATE;
    ctx->state = new_state;
    return PQC_SUCCESS;
}

pqc_status_t state_machine_handle_round_init(client_protocol_ctx_t* ctx, const msg_header_t* hdr, const uint8_t* payload) {
    if (!ctx || !hdr || hdr->message_type != MSG_TYPE_ROUND_INIT) return ERR_INVALID_ARGUMENT;
    if (hdr->round_id != ctx->current_round_id) return ERR_ROUND_MISMATCH;

    const uint8_t* p = payload;
    uint8_t expected_clients = *p++;
    uint8_t threshold = *p++;
    uint16_t chunk_size = (p[0] | (p[1] << 8)); p += 2;
    uint32_t model_size = (p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));

    ctx->chunk_ctx.round_id = hdr->round_id;
    ctx->chunk_ctx.client_id = ctx->client_id;
    ctx->chunk_ctx.chunk_size = chunk_size;
    ctx->chunk_ctx.model_total_bytes = model_size;
    ctx->chunk_ctx.total_chunks = (model_size + chunk_size - 1) / chunk_size;
    ctx->chunk_ctx.chunk_index = 0;
    ctx->chunk_ctx.bytes_processed = 0;

    return state_machine_transition(ctx, STATE_KEY_SETUP);
}

pqc_status_t state_machine_handle_key_setup(client_protocol_ctx_t* ctx, const msg_header_t* hdr, const uint8_t* payload) {
    if (!ctx || ctx->state != STATE_KEY_SETUP) return ERR_INVALID_STATE;
    if (hdr->message_type == MSG_TYPE_KEM_PUBLIC_KEY) {
        return kem_adapter_keypair(&ctx->kem_kp);
    }
    return ERR_INVALID_ARGUMENT;
}

pqc_status_t state_machine_handle_mask_setup(client_protocol_ctx_t* ctx, const msg_header_t* hdr, const uint8_t* payload) {
    if (!ctx || ctx->state != STATE_MASK_SETUP) return ERR_INVALID_STATE;
    return state_machine_transition(ctx, STATE_LOCAL_TRAINING);
}

pqc_status_t state_machine_handle_local_training(client_protocol_ctx_t* ctx, const msg_header_t* hdr, const uint8_t* payload) {
    if (!ctx || ctx->state != STATE_LOCAL_TRAINING) return ERR_INVALID_STATE;
    mock_local_training(ctx);
    return state_machine_transition(ctx, STATE_MASKED_UPDATE_STREAM);
}

pqc_status_t state_machine_handle_stream_chunk(client_protocol_ctx_t* ctx, const msg_header_t* hdr, const uint8_t* payload, uint16_t payload_len) {
    if (!ctx || ctx->state != STATE_MASKED_UPDATE_STREAM) return ERR_INVALID_STATE;
    if (hdr->sequence_number != ctx->chunk_ctx.chunk_index) return ERR_SEQUENCE_MISMATCH;
    if (payload_len != ctx->chunk_ctx.chunk_size && !(ctx->chunk_ctx.is_final_chunk && payload_len < ctx->chunk_ctx.chunk_size)) {
        return ERR_CHUNK_TOO_LARGE;
    }
    return PQC_SUCCESS;
}

pqc_status_t state_machine_handle_completion(client_protocol_ctx_t* ctx, const msg_header_t* hdr) {
    if (!ctx || ctx->state != STATE_MASKED_UPDATE_STREAM) return ERR_INVALID_STATE;
    if (hdr->message_type != MSG_TYPE_CLIENT_COMPLETE) return ERR_INVALID_ARGUMENT;
    return state_machine_transition(ctx, STATE_CLIENT_COMPLETION);
}

pqc_status_t state_machine_handle_dropout_notify(client_protocol_ctx_t* ctx, const msg_header_t* hdr, const uint8_t* payload) {
    if (!ctx || ctx->state != STATE_CLIENT_COMPLETION) return ERR_INVALID_STATE;
    if (hdr->message_type != MSG_TYPE_DROPOUT_NOTIFY) return ERR_INVALID_ARGUMENT;
    return state_machine_transition(ctx, STATE_MASK_RECOVERY);
}

pqc_status_t state_machine_handle_recovery_complete(client_protocol_ctx_t* ctx, const msg_header_t* hdr) {
    if (!ctx || ctx->state != STATE_MASK_RECOVERY) return ERR_INVALID_STATE;
    if (hdr->message_type != MSG_TYPE_RECOVERY_COMPLETE) return ERR_INVALID_ARGUMENT;
    return state_machine_transition(ctx, STATE_UNMASK);
}

pqc_status_t state_machine_handle_round_complete(client_protocol_ctx_t* ctx, const msg_header_t* hdr) {
    if (!ctx) return ERR_INVALID_ARGUMENT;
    if (hdr->message_type != MSG_TYPE_ROUND_COMPLETE) return ERR_INVALID_ARGUMENT;
    return state_machine_transition(ctx, STATE_ROUND_COMPLETE);
}

pqc_status_t state_machine_process_message(client_protocol_ctx_t* ctx, const msg_header_t* hdr, const uint8_t* payload, uint16_t payload_len) {
    if (!ctx || !hdr) return ERR_INVALID_ARGUMENT;
    if (hdr->round_id != ctx->current_round_id) return ERR_ROUND_MISMATCH;
    if (hdr->client_id != 0 && hdr->client_id != ctx->client_id) return ERR_CLIENT_ID_MISMATCH;

    switch (ctx->state) {
        case STATE_ROUND_INIT:
            return state_machine_handle_round_init(ctx, hdr, payload);
        case STATE_KEY_SETUP:
            return state_machine_handle_key_setup(ctx, hdr, payload);
        case STATE_MASK_SETUP:
            return state_machine_handle_mask_setup(ctx, hdr, payload);
        case STATE_LOCAL_TRAINING:
            return state_machine_handle_local_training(ctx, hdr, payload);
        case STATE_MASKED_UPDATE_STREAM:
            if (hdr->message_type == MSG_TYPE_MASK_CHUNK) {
                return state_machine_handle_stream_chunk(ctx, hdr, payload, payload_len);
            } else if (hdr->message_type == MSG_TYPE_CLIENT_COMPLETE) {
                return state_machine_handle_completion(ctx, hdr);
            }
            break;
        case STATE_CLIENT_COMPLETION:
            return state_machine_handle_dropout_notify(ctx, hdr, payload);
        case STATE_MASK_RECOVERY:
            return state_machine_handle_recovery_complete(ctx, hdr);
        case STATE_UNMASK:
            return state_machine_transition(ctx, STATE_FEDAVG);
        case STATE_FEDAVG:
            return state_machine_transition(ctx, STATE_ROUND_COMPLETE);
        default:
            break;
    }
    return ERR_INVALID_STATE;
}
'''
    with open(path, "w") as f:
        f.write(new_content)
    print("Fixed state_machine.c")

def create_packet_codec_h():
    path = r"C:\DROP\src\network\packet_codec.h"
    content = '''#ifndef PACKET_CODEC_H
#define PACKET_CODEC_H

#include "protocol_types.h"
#include <stdint.h>
#include <stddef.h>

#define MAC_SIZE 32
#define HEADER_SIZE 16
#define MAC_OFFSET (HEADER_SIZE - MAC_SIZE)

pqc_status_t packet_codec_encode_header(const msg_header_t* hdr, uint8_t* out);
pqc_status_t packet_codec_decode_header(const uint8_t* in, msg_header_t* hdr);
pqc_status_t packet_codec_encode_message(const msg_header_t* hdr, const uint8_t* payload, uint8_t* out, size_t* out_len);
pqc_status_t packet_codec_decode_message(const uint8_t* in, size_t in_len, msg_header_t* hdr, uint8_t* payload, size_t* payload_len);
pqc_status_t packet_codec_validate_sequence(const msg_header_t* hdr, uint16_t expected_seq);
pqc_status_t packet_codec_validate_round(const msg_header_t* hdr, uint32_t expected_round);
pqc_status_t packet_codec_validate_client(const msg_header_t* hdr, uint8_t expected_client);
pqc_status_t packet_codec_compute_mac(const uint8_t* key, const uint8_t* data, size_t data_len, uint8_t* mac);
pqc_status_t packet_codec_verify_mac(const uint8_t* key, const uint8_t* data, size_t data_len, const uint8_t* mac);

#endif
'''
    with open(path, "w") as f:
        f.write(content)
    print("Created packet_codec.h")

def fix_packet_codec_c():
    path = r"C:\DROP\src\network\packet_codec.c"
    new_content = '''#include "packet_codec.h"
#include <tinycrypt/hmac.h>
#include <tinycrypt/sha256.h>
#include <string.h>

#define HEADER_SIZE 16
#define MAC_SIZE 32

static void build_mac_data(const msg_header_t* hdr, uint8_t* mac_data) {
    mac_data[0] = (hdr->protocol_version >> 24) & 0xFF;
    mac_data[1] = (hdr->protocol_version >> 16) & 0xFF;
    mac_data[2] = (hdr->protocol_version >> 8) & 0xFF;
    mac_data[3] = hdr->protocol_version & 0xFF;
    mac_data[4] = (hdr->round_id >> 24) & 0xFF;
    mac_data[5] = (hdr->round_id >> 16) & 0xFF;
    mac_data[6] = (hdr->round_id >> 8) & 0xFF;
    mac_data[7] = hdr->round_id & 0xFF;
    mac_data[8] = hdr->client_id;
    mac_data[9] = hdr->message_type;
    mac_data[10] = (hdr->sequence_number >> 8) & 0xFF;
    mac_data[11] = hdr->sequence_number & 0xFF;
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

pqc_status_t packet_codec_verify_mac(const uint8_t* key, const uint8_t* data, size_t data_len, const uint8_t* mac) {
    if (!key || !data || !mac) return ERR_INVALID_ARGUMENT;
    uint8_t expected_mac[MAC_SIZE];
    pqc_status_t ret = packet_codec_compute_mac(key, data, data_len, expected_mac);
    if (ret != PQC_SUCCESS) return ret;
    for (size_t i = 0; i < MAC_SIZE; i++) {
        if (expected_mac[i] != mac[i]) return ERR_AUTH_FAILED;
    }
    return PQC_SUCCESS;
}

pqc_status_t packet_codec_encode_message(const msg_header_t* hdr, const uint8_t* payload, uint8_t* out, size_t* out_len) {
    if (!hdr || !out || !out_len) return ERR_INVALID_ARGUMENT;
    if (hdr->payload_length > 0 && !payload) return ERR_INVALID_ARGUMENT;
    pqc_status_t ret = packet_codec_encode_header(hdr, out);
    if (ret != PQC_SUCCESS) return ret;
    if (hdr->payload_length > 0) {
        memcpy(out + HEADER_SIZE, payload, hdr->payload_length);
    }
    *out_len = HEADER_SIZE + hdr->payload_length;
    return PQC_SUCCESS;
}

pqc_status_t packet_codec_decode_message(const uint8_t* in, size_t in_len, msg_header_t* hdr, uint8_t* payload, size_t* payload_len) {
    if (!in || !hdr || in_len < HEADER_SIZE) return ERR_INVALID_ARGUMENT;
    pqc_status_t ret = packet_codec_decode_header(in, hdr);
    if (ret != PQC_SUCCESS) return ret;
    if (in_len < HEADER_SIZE + hdr->payload_length) return ERR_INVALID_ARGUMENT;
    if (hdr->payload_length > 0 && payload) {
        memcpy(payload, in + HEADER_SIZE, hdr->payload_length);
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
    with open(path, "w") as f:
        f.write(new_content)
    print("Fixed packet_codec.c")

def create_impairment_c():
    path = r"C:\DROP\src\network\impairment.c"
    content = '''#include "impairment.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static impairment_config_t g_impairment_config = {0};
static uint32_t g_rng_state = 0xDEADBEEF;

static inline uint32_t rng_next(void) {
    g_rng_state = g_rng_state * 1664525 + 1013904223;
    return g_rng_state;
}

void impairment_init(const impairment_config_t* config) {
    if (!config) return;
    g_impairment_config = *config;
    if (config->seed) {
        g_rng_state = config->seed;
    }
}

void impairment_set_loss_rate(uint32_t loss_rate_ppm) {
    g_impairment_config.loss_rate_ppm = loss_rate_ppm;
}

void impairment_set_latency_ms(uint32_t min_latency_ms, uint32_t max_latency_ms) {
    g_impairment_config.min_latency_ms = min_latency_ms;
    g_impairment_config.max_latency_ms = max_latency_ms;
}

void impairment_set_jitter_ms(uint32_t jitter_ms) {
    g_impairment_config.jitter_ms = jitter_ms;
}

int impairment_should_drop(void) {
    if (g_impairment_config.loss_rate_ppm == 0) return 0;
    uint32_t r = rng_next() % 1000000;
    return r < g_impairment_config.loss_rate_ppm;
}

uint32_t impairment_get_latency_ms(void) {
    if (g_impairment_config.min_latency_ms == 0 && g_impairment_config.max_latency_ms == 0) return 0;
    uint32_t base = g_impairment_config.min_latency_ms;
    uint32_t range = g_impairment_config.max_latency_ms - g_impairment_config.min_latency_ms;
    uint32_t jitter = g_impairment_config.jitter_ms;
    uint32_t r = rng_next();
    uint32_t latency = base + (r % (range + 1));
    if (jitter > 0) {
        int32_t jitter_val = (int32_t)(rng_next() % (2 * jitter + 1)) - (int32_t)jitter;
        if ((int32_t)latency + jitter_val > 0) {
            latency = (uint32_t)((int32_t)latency + jitter_val);
        }
    }
    return latency;
}

void impairment_delay(uint32_t ms) {
    for (volatile uint32_t i = 0; i < ms * 10000; i++) {
        __asm__ volatile ("nop");
    }
}

pqc_status_t impairment_recv(int sock, uint8_t* buf, size_t len, size_t* received) {
    if (impairment_should_drop()) {
        *received = 0;
        return ERR_NETWORK_TIMEOUT;
    }
    uint32_t latency = impairment_get_latency_ms();
    if (latency > 0) impairment_delay(latency);
    return transport_recv(sock, buf, len, received);
}

pqc_status_t impairment_send(int sock, const uint8_t* buf, size_t len, size_t* sent) {
    if (impairment_should_drop()) {
        *sent = 0;
        return ERR_NETWORK_TIMEOUT;
    }
    uint32_t latency = impairment_get_latency_ms();
    if (latency > 0) impairment_delay(latency);
    return transport_send(sock, buf, len, sent);
}
'''
    with open(path, "w") as f:
        f.write(content)
    print("Created impairment.c")

def create_impairment_h():
    path = r"C:\DROP\src\network\impairment.h"
    content = '''#ifndef IMPAIRMENT_H
#define IMPAIRMENT_H

#include "protocol_types.h"
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t loss_rate_ppm;
    uint32_t min_latency_ms;
    uint32_t max_latency_ms;
    uint32_t jitter_ms;
    uint32_t seed;
} impairment_config_t;

void impairment_init(const impairment_config_t* config);
void impairment_set_loss_rate(uint32_t loss_rate_ppm);
void impairment_set_latency_ms(uint32_t min_latency_ms, uint32_t max_latency_ms);
void impairment_set_jitter_ms(uint32_t jitter_ms);
int impairment_should_drop(void);
uint32_t impairment_get_latency_ms(void);
void impairment_delay(uint32_t ms);
pqc_status_t impairment_recv(int sock, uint8_t* buf, size_t len, size_t* received);
pqc_status_t impairment_send(int sock, const uint8_t* buf, size_t len, size_t* sent);

#endif
'''
    with open(path, "w") as f:
        f.write(content)
    print("Created impairment.h")

if __name__ == "__main__":
    fix_state_machine()
    create_packet_codec_h()
    fix_packet_codec_c()
    create_impairment_c()
    create_impairment_h()
    print("Phase 2 modifications completed successfully.")