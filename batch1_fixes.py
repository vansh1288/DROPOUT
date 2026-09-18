def fix_mask_prg():
    path = r"C:\DROP\src\pqc_engine\mask_prg.c"
    content = '''#include "mask_prg.h"
#include <tinycrypt/aes.h>
#include <tinycrypt/ctr_mode.h>
#include <string.h>

static struct tc_aes_key_sched_struct g_aes_sched;
static uint8_t g_nonce[16];
static uint8_t g_ctr[16];
static int g_initialized = 0;

static void increment_ctr(void) {
    for (int i = 15; i >= 0; i--) {
        g_ctr[i]++;
        if (g_ctr[i] != 0) break;
    }
}

void mask_prg_init(const uint8_t seed[32]) {
    tc_aes256_set_encrypt_key(&g_aes_sched, seed);
    if (!g_initialized) {
        memset(g_nonce, 0, 16);
        memset(g_ctr, 0, 16);
        g_initialized = 1;
    }
}

void mask_prg_reseed(const uint8_t seed[32]) {
    tc_aes256_set_encrypt_key(&g_aes_sched, seed);
    memset(g_ctr, 0, 16);
}

void mask_prg_expand(uint8_t* out, size_t len) {
    size_t generated = 0;
    while (generated < len) {
        size_t chunk = len - generated;
        if (chunk > 16) chunk = 16;
        tc_ctr_mode(out + generated, chunk, g_nonce, g_ctr, &g_aes_sched);
        generated += chunk;
        increment_ctr();
    }
}

void mask_prg_get_bytes(uint8_t* out, size_t len) {
    mask_prg_expand(out, len);
}
'''
    with open(path, "w") as f:
        f.write(content)
    print("Fixed mask_prg.c")

def fix_stream_aggregator():
    path = r"C:\DROP\src\federated\stream_aggregator.c"
    content = '''#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "mask_prg.h"
#include "kem_adapter.h"
#include <stdint.h>

#define KYBER_Q 3329
#define CHUNK_ELEMENTS 128

static inline uint16_t barrett_reduce_q(uint32_t a) {
    uint32_t t = (a * 20159) >> 26;
    uint16_t r = (uint16_t)(a - t * KYBER_Q);
    return r >= KYBER_Q ? r - KYBER_Q : r;
}

pqc_status_t stream_aggregator_process_chunk(uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size, const uint8_t* shared_secret) {
    if (chunk_size > CHUNK_ELEMENTS * 2) return ERR_CHUNK_TOO_LARGE;
    if (chunk_size % 2 != 0) return ERR_CHUNK_TOO_SMALL;

    chunk_buffer_t* chunk_buf = scratch_get_chunk_buf();
    dma_double_buffer_t* dma_tx = scratch_get_dma_tx();

    uint8_t stream_seed[32];
    pqc_status_t ret = kem_adapter_derive_stream_mask_seed(
        shared_secret, client_id, round_id, chunk_index, stream_seed
    );
    if (ret != PQC_SUCCESS) return ret;

    mask_prg_init(stream_seed);
    int16_t mask[CHUNK_ELEMENTS];
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
    if (chunk_size > CHUNK_ELEMENTS * 2) return ERR_CHUNK_TOO_LARGE;
    if (chunk_size % 2 != 0) return ERR_CHUNK_TOO_SMALL;

    chunk_buffer_t* chunk_buf = scratch_get_chunk_buf();
    dma_double_buffer_t* dma_tx = scratch_get_dma_tx();

    uint8_t stream_seed[32];
    pqc_status_t ret = kem_adapter_derive_stream_mask_seed(
        shared_secret, client_id, round_id, chunk_index, stream_seed
    );
    if (ret != PQC_SUCCESS) return ret;

    mask_prg_init(stream_seed);
    int16_t mask[CHUNK_ELEMENTS];
    mask_prg_expand((uint8_t*)mask, chunk_size);

    int16_t* input = (int16_t*)chunk_buf->data;
    int16_t* output = (int16_t*)dma_tx->ping;
    size_t num_elements = chunk_size / 2;

    for (size_t i = 0; i < num_elements; i++) {
        int32_t diff = (int32_t)input[i] - (int32_t)mask[i];
        output[i] = (int16_t)barrett_reduce_q((uint32_t)(diff + KYBER_Q));
    }

    crypto_zeroize(mask, sizeof(mask));
    crypto_zeroize(stream_seed, 32);
    return PQC_SUCCESS;
}
'''
    with open(path, "w") as f:
        f.write(content)
    print("Fixed stream_aggregator.c")

def fix_packet_codec_h():
    path = r"C:\DROP\src\network\packet_codec.h"
    content = '''#ifndef PACKET_CODEC_H
#define PACKET_CODEC_H

#include "protocol_types.h"
#include <stdint.h>
#include <stddef.h>

#define MAC_SIZE 32
#define HEADER_SIZE 48

pqc_status_t packet_codec_encode_header(const msg_header_t* hdr, uint8_t* out);
pqc_status_t packet_codec_decode_header(const uint8_t* in, msg_header_t* hdr);
pqc_status_t packet_codec_encode_message(const msg_header_t* hdr, const uint8_t* payload, const uint8_t* mac_key, uint8_t* out, size_t* out_len);
pqc_status_t packet_codec_decode_message(const uint8_t* in, size_t in_len, const uint8_t* mac_key, msg_header_t* hdr, uint8_t* payload, size_t* payload_len);
pqc_status_t packet_codec_validate_sequence(const msg_header_t* hdr, uint16_t expected_seq);
pqc_status_t packet_codec_validate_round(const msg_header_t* hdr, uint32_t expected_round);
pqc_status_t packet_codec_validate_client(const msg_header_t* hdr, uint8_t expected_client);

#endif
'''
    with open(path, "w") as f:
        f.write(content)
    print("Fixed packet_codec.h")

def fix_packet_codec_c():
    path = r"C:\DROP\src\network\packet_codec.c"
    content = '''#include "packet_codec.h"
#include <tinycrypt/hmac.h>
#include <tinycrypt/sha256.h>
#include <string.h>

#define HEADER_SIZE 48
#define MAC_SIZE 32
#define MAC_OFFSET 16

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

pqc_status_t packet_codec_encode_message(const msg_header_t* hdr, const uint8_t* payload, const uint8_t* mac_key, uint8_t* out, size_t* out_len) {
    if (!hdr || !out || !out_len || !mac_key) return ERR_INVALID_ARGUMENT;
    if (hdr->payload_length > 0 && !payload) return ERR_INVALID_ARGUMENT;
    pqc_status_t ret = packet_codec_encode_header(hdr, out);
    if (ret != PQC_SUCCESS) return ret;
    if (hdr->payload_length > 0) {
        memcpy(out + HEADER_SIZE - MAC_SIZE, payload, hdr->payload_length);
    }
    uint8_t mac_data[12];
    build_mac_data(hdr, mac_data);
    uint8_t mac[MAC_SIZE];
    ret = packet_codec_compute_mac(mac_key, mac_data, 12, mac);
    if (ret != PQC_SUCCESS) return ret;
    memcpy(out + MAC_OFFSET, mac, MAC_SIZE);
    *out_len = HEADER_SIZE + hdr->payload_length;
    return PQC_SUCCESS;
}

pqc_status_t packet_codec_decode_message(const uint8_t* in, size_t in_len, const uint8_t* mac_key, msg_header_t* hdr, uint8_t* payload, size_t* payload_len) {
    if (!in || !hdr || !mac_key || in_len < HEADER_SIZE) return ERR_INVALID_ARGUMENT;
    pqc_status_t ret = packet_codec_decode_header(in, hdr);
    if (ret != PQC_SUCCESS) return ret;
    if (in_len < HEADER_SIZE + hdr->payload_length) return ERR_INVALID_ARGUMENT;
    uint8_t mac_data[12];
    build_mac_data(hdr, mac_data);
    uint8_t received_mac[MAC_SIZE];
    memcpy(received_mac, in + MAC_OFFSET, MAC_SIZE);
    ret = packet_codec_verify_mac(mac_key, mac_data, 12, received_mac);
    if (ret != PQC_SUCCESS) return ret;
    if (hdr->payload_length > 0 && payload) {
        memcpy(payload, in + HEADER_SIZE - MAC_SIZE, hdr->payload_length);
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
        f.write(content)
    print("Fixed packet_codec.c")

if __name__ == "__main__":
    fix_mask_prg()
    fix_stream_aggregator()
    fix_packet_codec_h()
    fix_packet_codec_c()
    print("Batch 1 modifications completed successfully.")