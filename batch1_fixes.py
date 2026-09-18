import os

def fix_dropout_protocol():
    path = r"C:\DROP\src\federated\dropout_protocol.c"
    content = '''#include "protocol_types.h"
#include "memory_scratchpad.h"
#include "crypto_memory.h"
#include <stdint.h>
#include <string.h>

#define FIELD_MODULUS 3329
#define BARRETT_MULTIPLIER 20159
#define BARRETT_SHIFT 26
#define SHAMIR_MAX_DEGREE 32
#define SHAMIR_SHARE_VALUE_BYTES 32

static inline uint16_t barrett_reduce(uint32_t a) {
    uint32_t t = (a * BARRETT_MULTIPLIER) >> BARRETT_SHIFT;
    uint16_t r = (uint16_t)(a - t * FIELD_MODULUS);
    return r >= FIELD_MODULUS ? r - FIELD_MODULUS : r;
}

static inline uint16_t gf3329_add(uint16_t a, uint16_t b) {
    uint16_t r = a + b;
    if (r >= FIELD_MODULUS) r -= FIELD_MODULUS;
    return r;
}

static inline uint16_t gf3329_sub(uint16_t a, uint16_t b) {
    return a >= b ? a - b : a + FIELD_MODULUS - b;
}

static inline uint16_t gf3329_mul(uint16_t a, uint16_t b) {
    return barrett_reduce((uint32_t)a * b);
}

static inline uint16_t gf3329_inv(uint16_t a) {
    uint32_t r = 1;
    uint32_t e = FIELD_MODULUS - 2;
    uint32_t base = a;
    while (e) {
        if (e & 1) r = barrett_reduce(r * base);
        base = barrett_reduce(base * base);
        e >>= 1;
    }
    return (uint16_t)r;
}

static void poly_eval(const uint16_t* coeffs, uint8_t threshold, uint16_t x, uint16_t* result) {
    uint16_t res = coeffs[0];
    uint16_t x_pow = x;
    for (uint8_t i = 1; i < threshold; i++) {
        uint16_t term = gf3329_mul(coeffs[i], x_pow);
        res = gf3329_add(res, term);
        x_pow = gf3329_mul(x_pow, x);
    }
    *result = res;
}

pqc_status_t shamir_gen_polynomial(const uint8_t* secret, uint8_t threshold, uint16_t* coeffs) {
    if (!secret || !coeffs || threshold == 0 || threshold > 32) return ERR_INVALID_ARGUMENT;
    for (int i = 0; i < 32; i++) {
        coeffs[i] = secret[i];
    }
    crypto_workspace_t* ws = scratch_get_crypto_ws();
    mask_prg_init((uint8_t*)ws);
    uint8_t rnd[32 * 32];
    mask_prg_expand(rnd, sizeof(rnd));
    for (uint8_t i = 1; i < threshold; i++) {
        for (int j = 0; j < 32; j++) {
            coeffs[i * 32 + j] = barrett_reduce(rnd[(i - 1) * 32 + j]);
        }
    }
    crypto_zeroize(ws, sizeof(crypto_workspace_t));
    return PQC_SUCCESS;
}

pqc_status_t shamir_eval_polynomial(const uint16_t* coeffs, uint8_t threshold, uint16_t x, uint8_t* y) {
    if (!coeffs || !y || threshold == 0) return ERR_INVALID_ARGUMENT;
    for (int j = 0; j < 32; j++) {
        const uint16_t* coeffs_j = &coeffs[j];
        poly_eval(coeffs_j, threshold, x, &y[j]);
    }
    return PQC_SUCCESS;
}

pqc_status_t shamir_gen_shares(const uint8_t* secret, uint8_t threshold, uint8_t num_shares, shamir_share_t* shares) {
    if (!secret || !shares || threshold == 0 || num_shares < threshold || num_shares > 255) return ERR_INVALID_ARGUMENT;
    if (threshold > 32) return ERR_INVALID_THRESHOLD;

    shamir_workspace_t* ws = scratch_get_shamir_ws();
    uint16_t* coeffs = (uint16_t*)ws->data;
    uint16_t* eval_points = (uint16_t*)&ws->data[32 * 32 * 2];
    uint8_t* share_values = &ws->data[32 * 32 * 2 + 256 * 2];

    pqc_status_t ret = shamir_gen_polynomial(secret, threshold, coeffs);
    if (ret != PQC_SUCCESS) return ret;

    for (uint8_t i = 0; i < num_shares; i++) {
        uint16_t x = i + 1;
        eval_points[i] = x;
        ret = shamir_eval_polynomial(coeffs, threshold, x, share_values + i * 32);
        if (ret != PQC_SUCCESS) return ret;
        shares[i].share_id = x;
        memcpy(shares[i].value, share_values + i * 32, 32);
    }

    crypto_zeroize(ws, sizeof(shamir_workspace_t));
    return PQC_SUCCESS;
}

pqc_status_t shamir_reconstruct_secret(const shamir_share_t* shares, uint8_t num_shares, uint8_t threshold, uint8_t* secret) {
    if (!shares || !secret || num_shares < threshold || threshold == 0) return ERR_INSUFFICIENT_SHARES;
    if (threshold > 32) return ERR_INVALID_THRESHOLD;

    for (uint8_t i = 0; i < num_shares; i++) {
        for (uint8_t j = i + 1; j < num_shares; j++) {
            if (shares[i].share_id == shares[j].share_id) return ERR_DUPLICATE_SHARE_ID;
        }
    }

    for (int j = 0; j < 32; j++) {
        uint16_t result = 0;
        for (uint8_t i = 0; i < num_shares; i++) {
            if (shares[i].share_id == 0) continue;
            uint16_t xi = shares[i].share_id;
            uint16_t yi = shares[i].value[j];
            uint16_t li = 1;
            for (uint8_t k = 0; k < num_shares; k++) {
                if (i == k) continue;
                if (shares[k].share_id == 0) continue;
                uint16_t xk = shares[k].share_id;
                uint16_t num = gf3329_mul(xk, li);
                uint16_t den = gf3329_sub(xk, xi);
                li = gf3329_mul(num, gf3329_inv(den));
            }
            result = gf3329_add(result, gf3329_mul(yi, li));
        }
        secret[j] = (uint8_t)result;
    }
    return PQC_SUCCESS;
}
'''
    with open(path, "w") as f:
        f.write(content)
    print("Fixed dropout_protocol.c")

def fix_protocol_bridge():
    path = r"C:\DROP\host_server\protocol_bridge.py"
    with open(path, "r") as f:
        content = f.read()
    content = content.replace('return encryptor.update(b"" * length) + encryptor.finalize()', 'return encryptor.update(b"\\x00" * length) + encryptor.finalize()')
    with open(path, "w") as f:
        f.write(content)
    print("Fixed protocol_bridge.py")

def fix_packet_codec_h():
    path = r"C:\DROP\src\network\packet_codec.h"
    content = '''#ifndef PACKET_CODEC_H
#define PACKET_CODEC_H

#include "protocol_types.h"
#include <stdint.h>
#include <stddef.h>

#define MAC_SIZE 32
#define HEADER_SIZE 16
#define MAC_OFFSET (HEADER_SIZE)

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

#define HEADER_SIZE 16
#define MAC_SIZE 32
#define MAC_OFFSET (HEADER_SIZE)
#define PAYLOAD_OFFSET (HEADER_SIZE + MAC_SIZE)

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
        memcpy(out + PAYLOAD_OFFSET, payload, hdr->payload_length);
    }
    uint8_t mac_data[12];
    build_mac_data(hdr, mac_data);
    uint8_t mac[MAC_SIZE];
    ret = packet_codec_compute_mac(mac_key, mac_data, 12, mac);
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
    uint8_t mac_data[12];
    build_mac_data(hdr, mac_data);
    uint8_t received_mac[MAC_SIZE];
    memcpy(received_mac, in + MAC_OFFSET, MAC_SIZE);
    ret = packet_codec_verify_mac(mac_key, mac_data, 12, received_mac);
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
    with open(path, "w") as f:
        f.write(content)
    print("Fixed packet_codec.c")

if __name__ == "__main__":
    fix_dropout_protocol()
    fix_protocol_bridge()
    fix_packet_codec_h()
    fix_packet_codec_c()
    print("Batch 1 modifications completed successfully.")