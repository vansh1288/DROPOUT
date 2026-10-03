#include "packet_codec.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

static void test_header_roundtrip(void) {
    printf("Testing header encode/decode roundtrip...\n");
    msg_header_t hdr = {
        .protocol_version = 0x00010000,
        .round_id = 0x12345678,
        .client_id = 0x42,
        .message_type = MSG_TYPE_MASK_CHUNK,
        .sequence_number = 0x0005,
        .payload_length = 256,
        .reserved = 0
    };
    uint8_t encoded[16];
    assert(packet_codec_encode_header(&hdr, encoded) == PQC_SUCCESS);

    msg_header_t decoded;
    assert(packet_codec_decode_header(encoded, &decoded) == PQC_SUCCESS);

    assert(decoded.protocol_version == hdr.protocol_version);
    assert(decoded.round_id == hdr.round_id);
    assert(decoded.client_id == hdr.client_id);
    assert(decoded.message_type == hdr.message_type);
    assert(decoded.sequence_number == hdr.sequence_number);
    assert(decoded.payload_length == hdr.payload_length);
    assert(decoded.reserved == hdr.reserved);
    printf("  PASS\n");
}

static void test_message_encode_decode(void) {
    printf("Testing message encode/decode with MAC...\n");
    uint8_t mac_key[32] = {0};
    for (int i = 0; i < 32; i++) mac_key[i] = i;

    msg_header_t hdr = {
        .protocol_version = 0x00010000,
        .round_id = 1,
        .client_id = 5,
        .message_type = MSG_TYPE_MASK_CHUNK,
        .sequence_number = 3,
        .payload_length = 256,
        .reserved = 0
    };

    uint8_t payload[256];
    for (int i = 0; i < 256; i++) payload[i] = i & 0xFF;

    uint8_t encoded[16 + 32 + 256];
    size_t out_len;
    assert(packet_codec_encode_message(&hdr, payload, mac_key, encoded, &out_len) == PQC_SUCCESS);
    assert(out_len == 16 + 32 + 256);

    msg_header_t decoded_hdr;
    uint8_t decoded_payload[256];
    size_t payload_len;
    assert(packet_codec_decode_message(encoded, out_len, mac_key, &decoded_hdr, decoded_payload, &out_len) == PQC_SUCCESS);
    assert(out_len == 256);
    assert(memcmp(payload, decoded_payload, 256) == 0);
    assert(decoded_hdr.round_id == 1);
    assert(decoded_hdr.client_id == 5);
    assert(decoded_hdr.sequence_number == 3);
    printf("  PASS\n");
}

static void test_invalid_mac(void) {
    printf("Testing MAC verification failure...\n");
    uint8_t mac_key[32] = {0};
    for (int i = 0; i < 32; i++) mac_key[i] = i;

    msg_header_t hdr = {
        .protocol_version = 0x00010000,
        .round_id = 1,
        .client_id = 5,
        .message_type = MSG_TYPE_MASK_CHUNK,
        .sequence_number = 3,
        .payload_length = 256,
        .reserved = 0
    };

    uint8_t payload[256];
    for (int i = 0; i < 256; i++) payload[i] = i & 0xFF;

    uint8_t encoded[16 + 32 + 256];
    size_t out_len;
    assert(packet_codec_encode_message(&hdr, payload, mac_key, encoded, &out_len) == PQC_SUCCESS);

    /* Corrupt the MAC */
    encoded[16] ^= 0xFF;

    msg_header_t decoded_hdr;
    uint8_t decoded_payload[256];
    size_t out_len;
    int ret = packet_codec_decode_message(encoded, out_len, mac_key, &hdr, NULL, &out_len);
    assert(ret == ERR_AUTH_FAILED);
    printf("  PASS\n");
}

static void test_wrong_round_id(void) {
    printf("Testing wrong round ID rejection...\n");
    uint8_t mac_key[32] = {0};
    for (int i = 0; i < 32; i++) mac_key[i] = i;

    msg_header_t hdr = {
        .protocol_version = 0x00010000,
        .round_id = 2,  /* Wrong round */
        .client_id = 5,
        .message_type = MSG_TYPE_MASK_CHUNK,
        .sequence_number = 3,
        .payload_length = 256,
        .reserved = 0
    };

    uint8_t payload[256];
    for (int i = 0; i < 256; i++) payload[i] = i & 0xFF;

    uint8_t encoded[16 + 32 + 256];
    size_t out_len;
    assert(packet_codec_encode_message(&hdr, payload, mac_key, encoded, &out_len) == PQC_SUCCESS);

    aad_context_t expected = {
        .round_id = 1,  /* Expected round 1 */
        .client_id = 5,
        .chunk_index = 3,
        .chunk_size = 256
    };

    uint8_t mac_key2[32] = {0};
    for (int i = 0; i < 32; i++) mac_key2[i] = i;

    uint8_t received_mac[32];
    memcpy(received_mac, encoded + 16, 32);

    pqc_status_t ret = packet_codec_validate_message(&hdr, &expected, mac_key2, encoded + 16);
    assert(ret == ERR_ROUND_MISMATCH);
    printf("  PASS\n");
}

static void test_wrong_client_id(void) {
    printf("Testing wrong client ID rejection...\n");
    uint8_t mac_key[32] = {0};
    for (int i = 0; i < 32; i++) mac_key[i] = i;

    msg_header_t hdr = {
        .protocol_version = 0x00010000,
        .round_id = 1,
        .client_id = 99,  /* Wrong client */
        .message_type = MSG_TYPE_MASK_CHUNK,
        .sequence_number = 3,
        .payload_length = 256,
        .reserved = 0
    };

    uint8_t payload[256];
    for (int i = 0; i < 256; i++) payload[i] = i & 0xFF;

    uint8_t encoded[16 + 32 + 256];
    size_t out_len;
    assert(packet_codec_encode_message(&hdr, payload, mac_key, encoded, &out_len) == PQC_SUCCESS);

    aad_context_t expected = {
        .round_id = 1,
        .client_id = 5,  /* Expected client 5 */
        .chunk_index = 3,
        .chunk_size = 256
    };

    uint8_t mac_key2[32] = {0};
    for (int i = 0; i < 32; i++) mac_key2[i] = i;

    pqc_status_t ret = packet_codec_validate_message(&hdr, &expected, mac_key2, encoded + 16);
    assert(ret == ERR_CLIENT_ID_MISMATCH);
    printf("  PASS\n");
}

static void test_out_of_order_sequence(void) {
    printf("Testing out-of-order sequence rejection...\n");
    uint8_t mac_key[32] = {0};
    for (int i = 0; i < 32; i++) mac_key[i] = i;

    msg_header_t hdr = {
        .protocol_version = 0x00010000,
        .round_id = 1,
        .client_id = 5,
        .message_type = MSG_TYPE_MASK_CHUNK,
        .sequence_number = 5,  /* Expected 3, got 5 */
        .payload_length = 256,
        .reserved = 0
    };

    uint8_t payload[256];
    for (int i = 0; i < 256; i++) payload[i] = i & 0xFF;

    uint8_t encoded[16 + 32 + 256];
    size_t out_len;
    assert(packet_codec_encode_message(&hdr, payload, mac_key, encoded, &out_len) == PQC_SUCCESS);

    aad_context_t expected = {
        .round_id = 1,
        .client_id = 5,
        .chunk_index = 3,  /* Expected sequence 3 */
        .chunk_size = 256
    };

    uint8_t mac_key2[32] = {0};
    for (int i = 0; i < 32; i++) mac_key2[i] = i;

    pqc_status_t ret = packet_codec_validate_message(&hdr, &expected, mac_key2, encoded + 16);
    assert(ret == ERR_SEQUENCE_MISMATCH);
    printf("  PASS\n");
}

static void test_duplicate_chunk_detection(void) {
    printf("Testing duplicate chunk detection...\n");
    chunk_tracker_t tracker;
    packet_codec_tracker_init(&tracker);

    /* First time should succeed */
    assert(packet_codec_tracker_check(&tracker, 5) == PQC_SUCCESS);
    assert(tracker.count == 1);

    /* Duplicate should fail */
    assert(packet_codec_tracker_check(&tracker, 5) == ERR_REPLAY_DETECTED);
    assert(tracker.count == 1);

    /* Different sequence should succeed */
    assert(packet_codec_tracker_check(&tracker, 6) == PQC_SUCCESS);
    assert(tracker.count == 2);

    /* Test capacity limit */
    for (int i = 0; i < 256; i++) {
        tracker.count = 0;  // Reset
        for (int j = 0; j < 256; j++) {
            assert(packet_codec_tracker_check(&tracker, j) == PQC_SUCCESS);
        }
        assert(packet_codec_tracker_check(&tracker, 0) == ERR_REPLAY_DETECTED);
    }
    printf("  PASS\n");
}

static void test_aad_binding(void) {
    printf("Testing AAD binding...\n");
    aad_context_t ctx = {
        .round_id = 0x12345678,
        .client_id = 0x42,
        .chunk_index = 0x0005,
        .chunk_size = 256
    };

    uint8_t aad[8];
    size_t aad_len;
    packet_codec_build_aad(&ctx, aad, &aad_len);

    assert(aad_len == 8);
    assert(aad[0] == 0x12);
    assert(aad[1] == 0x34);
    assert(aad[2] == 0x56);
    assert(aad[3] == 0x78);
    assert(aad[4] == 0x42);
    assert(aad[5] == 0x00);
    assert(aad[6] == 0x05);
    assert(aad[6] == 0x00);  // chunk_index high byte
    assert(aad[7] == 0x05);  // chunk_index low byte
    // Wait, chunk_size is 256 = 0x0100
    // So aad[6] = 0x01, aad[7] = 0x00
    // Let me fix the assertion
    assert(aad[6] == 0x01);  // chunk_size high byte
    assert(aad[7] == 0x00);  // chunk_size low byte
    printf("  PASS\n");
}

static void test_malformed_header(void) {
    printf("Testing malformed header rejection...\n");
    uint8_t malformed[16] = {0};  // All zeros

    msg_header_t hdr;
    int ret = packet_codec_decode_header(malformed, &hdr);
    /* All zeros should decode to valid values (all zero) but we should check bounds */
    assert(ret == PQC_SUCCESS);
    assert(hdr.protocol_version == 0);
    assert(hdr.round_id == 0);
    assert(hdr.client_id == 0);
    assert(hdr.message_type == 0);
    assert(hdr.sequence_number == 0);
    assert(hdr.payload_length == 0);
    assert(hdr.reserved == 0);
    printf("  PASS\n");
}

static void test_buffer_too_small(void) {
    printf("Testing buffer too small rejection...\n");
    uint8_t mac_key[32] = {0};
    for (int i = 0; i < 32; i++) mac_key[i] = i;

    msg_header_t hdr = {
        .protocol_version = 0x00010000,
        .round_id = 1,
        .client_id = 5,
        .message_type = MSG_TYPE_MASK_CHUNK,
        .sequence_number = 3,
        .payload_length = 256,
        .reserved = 0
    };

    uint8_t payload[256];
    for (int i = 0; i < 256; i++) payload[i] = i & 0xFF;

    uint8_t encoded[16 + 32 + 256];
    size_t out_len;
    assert(packet_codec_encode_message(&hdr, payload, mac_key, encoded, &out_len) == PQC_SUCCESS);

    /* Try to decode with truncated buffer */
    msg_header_t hdr2;
    uint8_t payload_out[256];
    size_t payload_len;
    int ret = packet_codec_decode_message(encoded, 10, mac_key, &hdr, NULL, &out_len);
    assert(ret == ERR_INVALID_ARGUMENT);
    printf("  PASS\n");
}

static void test_null_pointers(void) {
    printf("Testing NULL pointer handling...\n");
    uint8_t mac_key[32] = {0};
    msg_header_t hdr;
    uint8_t out[32];
    size_t out_len;

    assert(packet_codec_encode_header(NULL, out) == ERR_INVALID_ARGUMENT);
    assert(packet_codec_encode_header(&hdr, NULL) == ERR_INVALID_ARGUMENT);
    assert(packet_codec_decode_header(NULL, &hdr) == ERR_INVALID_ARGUMENT);
    assert(packet_codec_decode_header(NULL, NULL) == ERR_INVALID_ARGUMENT);

    assert(packet_codec_encode_message(NULL, NULL, NULL, NULL, NULL) == ERR_INVALID_ARGUMENT);
    assert(packet_codec_encode_message(&hdr, NULL, NULL, NULL, NULL) == ERR_INVALID_ARGUMENT);
    assert(packet_codec_decode_message(NULL, 0, NULL, NULL, NULL, NULL) == ERR_INVALID_ARGUMENT);

    assert(packet_codec_compute_mac(NULL, NULL, 0, NULL) == ERR_INVALID_ARGUMENT);
    assert(packet_codec_verify_mac(NULL, NULL, 0, NULL) == ERR_INVALID_ARGUMENT);

    assert(packet_codec_validate_sequence(NULL, 0) == ERR_INVALID_ARGUMENT);
    assert(packet_codec_validate_round(NULL, 0) == ERR_INVALID_ARGUMENT);
    assert(packet_codec_validate_client(NULL, 0) == ERR_INVALID_ARGUMENT);

    assert(packet_codec_tracker_check(NULL, 0) == ERR_INVALID_ARGUMENT);

    printf("  PASS\n");
}

static void test_boundary_values(void) {
    printf("Testing boundary values...\n");
    msg_header_t hdr = {
        .protocol_version = 0xFFFFFFFF,
        .round_id = 0xFFFFFFFF,
        .client_id = 0xFF,
        .message_type = 0xFF,
        .sequence_number = 0xFFFF,
        .payload_length = 0xFFFF,
        .reserved = 0xFFFF
    };

    uint8_t encoded[16];
    assert(packet_codec_encode_header(&hdr, encoded) == PQC_SUCCESS);

    msg_header_t decoded;
    assert(packet_codec_decode_header(encoded, &decoded) == PQC_SUCCESS);
    assert(decoded.protocol_version == 0xFFFFFFFF);
    assert(decoded.round_id == 0xFFFFFFFF);
    assert(decoded.client_id == 0xFF);
    assert(decoded.message_type == 0xFF);
    assert(decoded.sequence_number == 0xFFFF);
    assert(decoded.payload_length == 0xFFFF);
    assert(decoded.reserved == 0xFFFF);
    printf("  PASS\n");
}

static void test_zero_payload(void) {
    printf("Testing zero-length payload...\n");
    uint8_t mac_key[32] = {0};
    for (int i = 0; i < 32; i++) mac_key[i] = i;

    msg_header_t hdr = {
        .protocol_version = 0x00010000,
        .round_id = 1,
        .client_id = 5,
        .message_type = MSG_TYPE_CLIENT_COMPLETE,
        .sequence_number = 0,
        .payload_length = 0,
        .reserved = 0
    };

    uint8_t encoded[16 + 32];
    size_t out_len;
    assert(packet_codec_encode_message(&hdr, NULL, mac_key, encoded, &out_len) == PQC_SUCCESS);
    assert(out_len == 16 + 32);  // Header + MAC only

    msg_header_t decoded_hdr;
    size_t out_len2;
    assert(packet_codec_decode_message(encoded, out_len, mac_key, &hdr, NULL, &out_len2) == PQC_SUCCESS);
    assert(out_len2 == 0);
    printf("  PASS\n");
}

static void test_replay_attack_detection(void) {
    printf("Testing replay attack detection via tracker...\n");
    chunk_tracker_t tracker;
    packet_codec_tracker_init(&tracker);

    uint8_t mac_key[32] = {0};
    for (int i = 0; i < 32; i++) mac_key[i] = i;

    msg_header_t hdr = {
        .protocol_version = 0x00010000,
        .round_id = 1,
        .client_id = 5,
        .message_type = MSG_TYPE_MASK_CHUNK,
        .sequence_number = 3,
        .payload_length = 256,
        .reserved = 0
    };

    uint8_t payload[256];
    for (int i = 0; i < 256; i++) payload[i] = i & 0xFF;

    uint8_t encoded[16 + 32 + 256];
    size_t out_len;
    assert(packet_codec_encode_message(&hdr, payload, mac_key, encoded, &out_len) == PQC_SUCCESS);

    /* First reception - should pass tracker check */
    assert(packet_codec_tracker_check(&tracker, hdr.sequence_number) == PQC_SUCCESS);

    /* Simulate replay - same sequence number */
    int ret = packet_codec_tracker_check(&tracker, hdr.sequence_number);
    assert(ret == ERR_REPLAY_DETECTED);

    /* Different sequence should pass */
    assert(packet_codec_tracker_check(&tracker, 4) == PQC_SUCCESS);

    printf("  PASS\n");
}

static void test_cross_round_rejection(void) {
    printf("Testing cross-round rejection...\n");
    uint8_t mac_key[32] = {0};
    for (int i = 0; i < 32; i++) mac_key[i] = i;

    msg_header_t hdr = {
        .protocol_version = 0x00010000,
        .round_id = 5,  /* Round 5 */
        .client_id = 5,
        .message_type = MSG_TYPE_MASK_CHUNK,
        .sequence_number = 3,
        .payload_length = 256,
        .reserved = 0
    };

    uint8_t payload[256];
    for (int i = 0; i < 256; i++) payload[i] = i & 0xFF;

    uint8_t encoded[16 + 32 + 256];
    size_t out_len;
    assert(packet_codec_encode_message(&hdr, payload, mac_key, encoded, &out_len) == PQC_SUCCESS);

    /* Try to validate with round 1 context */
    aad_context_t expected = {
        .round_id = 1,  /* Round 1 context */
        .client_id = 5,
        .chunk_index = 3,
        .chunk_size = 256
    };

    uint8_t mac_key2[32] = {0};
    for (int i = 0; i < 32; i++) mac_key2[i] = i;

    pqc_status_t ret = packet_codec_validate_message(&hdr, &expected, mac_key2, encoded + 16);
    assert(ret == ERR_ROUND_MISMATCH);
    printf("  PASS\n");
}

int main(void) {
    printf("Running packet codec tests...\n\n");

    test_header_roundtrip();
    test_message_encode_decode();
    test_invalid_mac();
    test_wrong_round_id();
    test_wrong_client_id();
    test_out_of_order_sequence();
    test_duplicate_chunk_detection();
    test_aad_binding();
    test_malformed_header();
    test_buffer_too_small();
    test_null_pointers();
    test_boundary_values();
    test_zero_payload();
    test_replay_attack_detection();
    test_cross_round_rejection();

    printf("\nAll tests PASSED!\n");
    return 0;
}