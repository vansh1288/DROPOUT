#include "packet_codec.h"
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
