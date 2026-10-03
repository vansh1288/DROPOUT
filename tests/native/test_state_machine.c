#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "state_machine.h"
#include "protocol_types.h"
#include "memory_scratchpad.h"
#include "kem_adapter.h"
#include "mask_protocol.h"
#include "dropout_protocol.h"
#include "packet_codec.h"
#include "FreeRTOS.h"
#include "task.h"

static client_protocol_ctx_t g_test_ctx;

static void test_state_machine_init(void) {
    printf("Testing state_machine_init...\n");
    pqc_status_t ret = state_machine_init(&g_test_ctx, 5, 1);
    assert(ret == PQC_SUCCESS);
    assert(g_test_ctx.client_id == 5);
    assert(g_test_ctx.current_round_id == 1);
    assert(g_test_ctx.state == STATE_ROUND_INIT);
    printf("  PASS\n");
}

static void test_state_machine_transition(void) {
    printf("Testing state_machine_transition...\n");
    state_machine_init(&g_test_ctx, 5, 1);
    
    pqc_status_t ret = state_machine_transition(&g_test_ctx, STATE_KEY_SETUP);
    assert(ret == PQC_SUCCESS);
    assert(g_test_ctx.state == STATE_KEY_SETUP);
    
    ret = state_machine_transition(&g_test_ctx, STATE_MASK_SETUP);
    assert(ret == PQC_SUCCESS);
    assert(g_test_ctx.state == STATE_MASK_SETUP);
    
    ret = state_machine_transition(&g_test_ctx, STATE_ERROR);
    assert(ret == PQC_SUCCESS);
    assert(g_test_ctx.state == STATE_ERROR);
    
    ret = state_machine_transition(&g_test_ctx, STATE_ROUND_INIT);
    assert(ret == ERR_INVALID_STATE);
    printf("  PASS\n");
}

static void test_state_machine_round_init(void) {
    printf("Testing state_machine_handle_round_init...\n");
    state_machine_init(&g_test_ctx, 5, 1);
    
    uint8_t payload[8];
    payload[0] = 10;
    payload[1] = 3;
    payload[2] = 0;
    payload[3] = 1;
    payload[4] = 0;
    payload[5] = 0;
    payload[6] = 0;
    payload[7] = 1024;
    
    msg_header_t hdr = {
        .protocol_version = PROTOCOL_VERSION,
        .round_id = 1,
        .client_id = 5,
        .message_type = MSG_TYPE_ROUND_INIT,
        .sequence_number = 0,
        .payload_length = 8,
        .reserved = 0
    };
    
    pqc_status_t ret = state_machine_handle_round_init(&g_test_ctx, &hdr, payload);
    assert(ret == PQC_SUCCESS);
    assert(g_test_ctx.state == STATE_KEY_SETUP);
    assert(g_test_ctx.chunk_ctx.round_id == 1);
    assert(g_test_ctx.chunk_ctx.client_id == 5);
    assert(g_test_ctx.chunk_ctx.chunk_size == 256);
    assert(g_test_ctx.chunk_ctx.total_chunks == 4);
    assert(g_test_ctx.shamir_ctx.threshold == 3);
    assert(g_test_ctx.shamir_ctx.num_shares == 9);
    
    hdr.round_id = 2;
    ret = state_machine_handle_round_init(&g_test_ctx, &hdr, payload);
    assert(ret == ERR_ROUND_MISMATCH);
    
    hdr.round_id = 1;
    hdr.message_type = MSG_TYPE_KEM_PUBLIC_KEY;
    ret = state_machine_handle_round_init(&g_test_ctx, &hdr, payload);
    assert(ret == ERR_INVALID_ARGUMENT);
    printf("  PASS\n");
}

static void test_state_machine_key_setup(void) {
    printf("Testing state_machine_handle_key_setup...\n");
    state_machine_init(&g_test_ctx, 5, 1);
    g_test_ctx.state = STATE_KEY_SETUP;
    
    size_t pk_bytes, sk_bytes, ct_bytes, ss_bytes;
    kem_adapter_get_sizes(&pk_bytes, &sk_bytes, &ct_bytes, &ss_bytes);
    
    msg_header_t hdr = {
        .protocol_version = PROTOCOL_VERSION,
        .round_id = 1,
        .client_id = 5,
        .message_type = MSG_TYPE_KEM_PUBLIC_KEY,
        .sequence_number = 0,
        .payload_length = pk_bytes,
        .reserved = 0
    };
    
    pqc_status_t ret = state_machine_handle_key_setup(&g_test_ctx, &hdr, NULL);
    assert(ret == PQC_SUCCESS);
    
    hdr.message_type = MSG_TYPE_KEM_CIPHERTEXT;
    hdr.payload_length = ct_bytes;
    uint8_t ct[ct_bytes];
    memset(ct, 0xAA, ct_bytes);
    
    ret = state_machine_handle_key_setup(&g_test_ctx, &hdr, ct);
    assert(ret == PQC_SUCCESS);
    assert(g_test_ctx.state == STATE_MASK_SETUP);
    
    hdr.payload_length = ct_bytes - 1;
    ret = state_machine_handle_key_setup(&g_test_ctx, &hdr, ct);
    assert(ret == ERR_INVALID_ARGUMENT);
    printf("  PASS\n");
}

static void test_state_machine_mask_setup(void) {
    printf("Testing state_machine_handle_mask_setup...\n");
    state_machine_init(&g_test_ctx, 5, 1);
    g_test_ctx.state = STATE_MASK_SETUP;
    g_test_ctx.pairwise_ctx.num_peers = 0;
    
    size_t pk_bytes, sk_bytes, ct_bytes, ss_bytes;
    kem_adapter_get_sizes(&pk_bytes, &sk_bytes, &ct_bytes, &ss_bytes);
    
    msg_header_t hdr = {
        .protocol_version = PROTOCOL_VERSION,
        .round_id = 1,
        .client_id = 3,
        .message_type = MSG_TYPE_PAIRWISE_KEM_PUBKEY,
        .sequence_number = 0,
        .payload_length = pk_bytes,
        .reserved = 0
    };
    
    uint8_t pubkey[pk_bytes];
    memset(pubkey, 0x55, pk_bytes);
    
    pqc_status_t ret = state_machine_handle_mask_setup(&g_test_ctx, &hdr, pubkey);
    assert(ret == PQC_SUCCESS);
    assert(g_test_ctx.pairwise_ctx.num_peers == 1);
    assert(g_test_ctx.pairwise_ctx.peers[0].peer_client_id == 3);
    
    hdr.client_id = 7;
    ret = state_machine_handle_mask_setup(&g_test_ctx, &hdr, pubkey);
    assert(ret == PQC_SUCCESS);
    assert(g_test_ctx.pairwise_ctx.num_peers == 2);
    
    hdr.message_type = MSG_TYPE_PAIRWISE_KEM_CIPHERTEXT;
    hdr.payload_length = ct_bytes;
    uint8_t ct[ct_bytes];
    memset(ct, 0xAA, ct_bytes);
    
    ret = state_machine_handle_mask_setup(&g_test_ctx, &hdr, ct);
    assert(ret == PQC_SUCCESS);
    
    hdr.message_type = MSG_TYPE_PAIRWISE_CONFIRM;
    ret = state_machine_handle_mask_setup(&g_test_ctx, &hdr, NULL);
    assert(ret == PQC_SUCCESS);
    assert(g_test_ctx.state == STATE_LOCAL_TRAINING);
    
    hdr.message_type = MSG_TYPE_ERROR;
    ret = state_machine_handle_mask_setup(&g_test_ctx, &hdr, NULL);
    assert(ret == ERR_INVALID_ARGUMENT);
    printf("  PASS\n");
}

static void test_state_machine_local_training(void) {
    printf("Testing state_machine_handle_local_training...\n");
    state_machine_init(&g_test_ctx, 5, 1);
    g_test_ctx.state = STATE_LOCAL_TRAINING;
    
    msg_header_t hdr = {
        .protocol_version = PROTOCOL_VERSION,
        .round_id = 1,
        .client_id = 5,
        .message_type = MSG_TYPE_MASK_CHUNK,
        .sequence_number = 0,
        .payload_length = 256,
        .reserved = 0
    };
    
    pqc_status_t ret = state_machine_handle_local_training(&g_test_ctx, &hdr, NULL);
    assert(ret == PQC_SUCCESS);
    assert(g_test_ctx.state == STATE_MASKED_UPDATE_STREAM);
    printf("  PASS\n");
}

static void test_state_machine_stream_chunk(void) {
    printf("Testing state_machine_handle_stream_chunk...\n");
    state_machine_init(&g_test_ctx, 5, 1);
    g_test_ctx.state = STATE_MASKED_UPDATE_STREAM;
    g_test_ctx.chunk_ctx.chunk_index = 0;
    g_test_ctx.chunk_ctx.chunk_size = 256;
    g_test_ctx.chunk_ctx.total_chunks = 4;
    g_test_ctx.chunk_ctx.is_final_chunk = 0;
    
    size_t pk_bytes, sk_bytes, ct_bytes, ss_bytes;
    kem_adapter_get_sizes(&pk_bytes, &sk_bytes, &ct_bytes, &ss_bytes);
    
    g_test_ctx.pairwise_ctx.num_peers = 1;
    g_test_ctx.pairwise_ctx.peers[0].peer_client_id = 3;
    for (int i = 0; i < 32; i++) {
        g_test_ctx.pairwise_ctx.peers[0].mask_seed[i] = i;
    }
    
    msg_header_t hdr = {
        .protocol_version = PROTOCOL_VERSION,
        .round_id = 1,
        .client_id = 5,
        .message_type = MSG_TYPE_MASK_CHUNK,
        .sequence_number = 0,
        .payload_length = 256,
        .reserved = 0
    };
    
    uint8_t payload[256];
    for (int i = 0; i < 256; i++) payload[i] = i & 0xFF;
    
    pqc_status_t ret = state_machine_handle_stream_chunk(&g_test_ctx, &hdr, payload, 256);
    assert(ret == PQC_SUCCESS);
    assert(g_test_ctx.chunk_ctx.chunk_index == 1);
    assert(g_test_ctx.chunk_ctx.bytes_processed == 256);
    assert(g_test_ctx.chunk_ctx.is_final_chunk == 0);
    
    hdr.sequence_number = 1;
    ret = state_machine_handle_stream_chunk(&g_test_ctx, &hdr, payload, 256);
    assert(ret == PQC_SUCCESS);
    assert(g_test_ctx.chunk_ctx.chunk_index == 2);
    
    g_test_ctx.chunk_ctx.chunk_index = 3;
    g_test_ctx.chunk_ctx.is_final_chunk = 1;
    hdr.sequence_number = 3;
    hdr.payload_length = 128;
    ret = state_machine_handle_stream_chunk(&g_test_ctx, &hdr, payload, 128);
    assert(ret == PQC_SUCCESS);
    assert(g_test_ctx.chunk_ctx.is_final_chunk == 1);
    
    hdr.sequence_number = 2;
    ret = state_machine_handle_stream_chunk(&g_test_ctx, &hdr, payload, 256);
    assert(ret == ERR_SEQUENCE_MISMATCH);
    
    hdr.sequence_number = 3;
    hdr.payload_length = 256;
    ret = state_machine_handle_stream_chunk(&g_test_ctx, &hdr, payload, 256);
    assert(ret == ERR_CHUNK_TOO_LARGE);
    printf("  PASS\n");
}

static void test_state_machine_completion(void) {
    printf("Testing state_machine_handle_completion...\n");
    state_machine_init(&g_test_ctx, 5, 1);
    g_test_ctx.state = STATE_MASKED_UPDATE_STREAM;
    
    size_t pk_bytes, sk_bytes, ct_bytes, ss_bytes;
    kem_adapter_get_sizes(&pk_bytes, &sk_bytes, &ct_bytes, &ss_bytes);
    
    g_test_ctx.kem_kp.shared_secret_len = ss_bytes;
    for (int i = 0; i < ss_bytes; i++) {
        g_test_ctx.kem_kp.shared_secret[i] = i;
    }
    
    msg_header_t hdr = {
        .protocol_version = PROTOCOL_VERSION,
        .round_id = 1,
        .client_id = 5,
        .message_type = MSG_TYPE_CLIENT_COMPLETE,
        .sequence_number = 0,
        .payload_length = 0,
        .reserved = 0
    };
    
    pqc_status_t ret = state_machine_handle_completion(&g_test_ctx, &hdr);
    assert(ret == PQC_SUCCESS);
    assert(g_test_ctx.state == STATE_CLIENT_COMPLETION);
    
    hdr.message_type = MSG_TYPE_ERROR;
    ret = state_machine_handle_completion(&g_test_ctx, &hdr);
    assert(ret == ERR_INVALID_ARGUMENT);
    printf("  PASS\n");
}

static void test_state_machine_dropout_notify(void) {
    printf("Testing state_machine_handle_dropout_notify...\n");
    state_machine_init(&g_test_ctx, 5, 1);
    g_test_ctx.state = STATE_CLIENT_COMPLETION;
    
    msg_header_t hdr = {
        .protocol_version = PROTOCOL_VERSION,
        .round_id = 1,
        .client_id = 5,
        .message_type = MSG_TYPE_DROPOUT_NOTIFY,
        .sequence_number = 0,
        .payload_length = 0,
        .reserved = 0
    };
    
    pqc_status_t ret = state_machine_handle_dropout_notify(&g_test_ctx, &hdr, NULL);
    assert(ret == PQC_SUCCESS);
    assert(g_test_ctx.state == STATE_MASK_RECOVERY);
    
    hdr.message_type = MSG_TYPE_ERROR;
    ret = state_machine_handle_dropout_notify(&g_test_ctx, &hdr, NULL);
    assert(ret == ERR_INVALID_ARGUMENT);
    printf("  PASS\n");
}

static void test_state_machine_recovery_complete(void) {
    printf("Testing state_machine_handle_recovery_complete...\n");
    state_machine_init(&g_test_ctx, 5, 1);
    g_test_ctx.state = STATE_MASK_RECOVERY;
    
    msg_header_t hdr = {
        .protocol_version = PROTOCOL_VERSION,
        .round_id = 1,
        .client_id = 5,
        .message_type = MSG_TYPE_RECOVERY_COMPLETE,
        .sequence_number = 0,
        .payload_length = 0,
        .reserved = 0
    };
    
    pqc_status_t ret = state_machine_handle_recovery_complete(&g_test_ctx, &hdr);
    assert(ret == PQC_SUCCESS);
    assert(g_test_ctx.state == STATE_UNMASK);
    
    hdr.message_type = MSG_TYPE_ERROR;
    ret = state_machine_handle_recovery_complete(&g_test_ctx, &hdr);
    assert(ret == ERR_INVALID_ARGUMENT);
    printf("  PASS\n");
}

static void test_state_machine_round_complete(void) {
    printf("Testing state_machine_handle_round_complete...\n");
    state_machine_init(&g_test_ctx, 5, 1);
    g_test_ctx.state = STATE_FEDAVG;
    
    msg_header_t hdr = {
        .protocol_version = PROTOCOL_VERSION,
        .round_id = 1,
        .client_id = 5,
        .message_type = MSG_TYPE_ROUND_COMPLETE,
        .sequence_number = 0,
        .payload_length = 0,
        .reserved = 0
    };
    
    pqc_status_t ret = state_machine_handle_round_complete(&g_test_ctx, &hdr);
    assert(ret == PQC_SUCCESS);
    assert(g_test_ctx.state == STATE_ROUND_COMPLETE);
    
    hdr.message_type = MSG_TYPE_ERROR;
    ret = state_machine_handle_round_complete(&g_test_ctx, &hdr);
    assert(ret == ERR_INVALID_ARGUMENT);
    printf("  PASS\n");
}

static void test_state_machine_full_flow(void) {
    printf("Testing full state machine flow...\n");
    state_machine_init(&g_test_ctx, 5, 1);
    
    uint8_t payload[8] = {10, 3, 0, 1, 0, 0, 0, 1024};
    msg_header_t hdr = {
        .protocol_version = PROTOCOL_VERSION,
        .round_id = 1,
        .client_id = 5,
        .message_type = MSG_TYPE_ROUND_INIT,
        .sequence_number = 0,
        .payload_length = 8,
        .reserved = 0
    };
    
    state_machine_process_message(&g_test_ctx, &hdr, payload, 8);
    assert(g_test_ctx.state == STATE_KEY_SETUP);
    
    size_t pk_bytes, sk_bytes, ct_bytes, ss_bytes;
    kem_adapter_get_sizes(&pk_bytes, &sk_bytes, &ct_bytes, &ss_bytes);
    
    hdr.message_type = MSG_TYPE_KEM_PUBLIC_KEY;
    hdr.payload_length = pk_bytes;
    state_machine_process_message(&g_test_ctx, &hdr, NULL, 0);
    assert(g_test_ctx.state == STATE_KEY_SETUP);
    
    hdr.message_type = MSG_TYPE_KEM_CIPHERTEXT;
    hdr.payload_length = ct_bytes;
    uint8_t ct[ct_bytes];
    memset(ct, 0xAA, ct_bytes);
    state_machine_process_message(&g_test_ctx, &hdr, ct, ct_bytes);
    assert(g_test_ctx.state == STATE_MASK_SETUP);
    
    hdr.message_type = MSG_TYPE_PAIRWISE_KEM_PUBKEY;
    hdr.client_id = 3;
    hdr.payload_length = pk_bytes;
    uint8_t pubkey[pk_bytes];
    memset(pubkey, 0x55, pk_bytes);
    state_machine_process_message(&g_test_ctx, &hdr, pubkey, pk_bytes);
    assert(g_test_ctx.state == STATE_MASK_SETUP);
    
    hdr.message_type = MSG_TYPE_PAIRWISE_CONFIRM;
    hdr.payload_length = 0;
    state_machine_process_message(&g_test_ctx, &hdr, NULL, 0);
    assert(g_test_ctx.state == STATE_LOCAL_TRAINING);
    
    hdr.message_type = MSG_TYPE_MASK_CHUNK;
    hdr.client_id = 5;
    hdr.sequence_number = 0;
    hdr.payload_length = 256;
    g_test_ctx.chunk_ctx.chunk_index = 0;
    g_test_ctx.chunk_ctx.chunk_size = 256;
    g_test_ctx.chunk_ctx.total_chunks = 2;
    g_test_ctx.chunk_ctx.is_final_chunk = 0;
    g_test_ctx.pairwise_ctx.num_peers = 1;
    g_test_ctx.pairwise_ctx.peers[0].peer_client_id = 3;
    for (int i = 0; i < 32; i++) g_test_ctx.pairwise_ctx.peers[0].mask_seed[i] = i;
    
    uint8_t chunk_data[256];
    for (int i = 0; i < 256; i++) chunk_data[i] = i;
    state_machine_process_message(&g_test_ctx, &hdr, chunk_data, 256);
    assert(g_test_ctx.state == STATE_MASKED_UPDATE_STREAM);
    assert(g_test_ctx.chunk_ctx.chunk_index == 1);
    
    hdr.sequence_number = 1;
    g_test_ctx.chunk_ctx.is_final_chunk = 1;
    hdr.payload_length = 256;
    state_machine_process_message(&g_test_ctx, &hdr, chunk_data, 256);
    assert(g_test_ctx.chunk_ctx.chunk_index == 2);
    
    hdr.message_type = MSG_TYPE_CLIENT_COMPLETE;
    hdr.sequence_number = 0;
    hdr.payload_length = 0;
    g_test_ctx.kem_kp.shared_secret_len = ss_bytes;
    for (int i = 0; i < ss_bytes; i++) g_test_ctx.kem_kp.shared_secret[i] = i;
    state_machine_process_message(&g_test_ctx, &hdr, NULL, 0);
    assert(g_test_ctx.state == STATE_CLIENT_COMPLETION);
    
    hdr.message_type = MSG_TYPE_DROPOUT_NOTIFY;
    state_machine_process_message(&g_test_ctx, &hdr, NULL, 0);
    assert(g_test_ctx.state == STATE_MASK_RECOVERY);
    
    hdr.message_type = MSG_TYPE_RECOVERY_COMPLETE;
    state_machine_process_message(&g_test_ctx, &hdr, NULL, 0);
    assert(g_test_ctx.state == STATE_UNMASK);
    
    hdr.message_type = MSG_TYPE_ROUND_COMPLETE;
    g_test_ctx.state = STATE_FEDAVG;
    state_machine_process_message(&g_test_ctx, &hdr, NULL, 0);
    assert(g_test_ctx.state == STATE_ROUND_COMPLETE);
    printf("  PASS\n");
}

static void test_state_machine_invalid_transitions(void) {
    printf("Testing invalid state transitions...\n");
    state_machine_init(&g_test_ctx, 5, 1);
    
    msg_header_t hdr = {
        .protocol_version = PROTOCOL_VERSION,
        .round_id = 1,
        .client_id = 5,
        .message_type = MSG_TYPE_KEM_PUBLIC_KEY,
        .sequence_number = 0,
        .payload_length = 0,
        .reserved = 0
    };
    
    pqc_status_t ret = state_machine_process_message(&g_test_ctx, &hdr, NULL, 0);
    assert(ret == ERR_INVALID_STATE);
    
    g_test_ctx.state = STATE_ROUND_INIT;
    hdr.round_id = 2;
    ret = state_machine_process_message(&g_test_ctx, &hdr, NULL, 0);
    assert(ret == ERR_ROUND_MISMATCH);
    
    hdr.round_id = 1;
    hdr.client_id = 99;
    ret = state_machine_process_message(&g_test_ctx, &hdr, NULL, 0);
    assert(ret == ERR_CLIENT_ID_MISMATCH);
    printf("  PASS\n");
}

static void test_protocol_register_context(void) {
    printf("Testing protocol_register_context...\n");
    client_protocol_ctx_t ctx1, ctx2;
    state_machine_init(&ctx1, 1, 1);
    state_machine_init(&ctx2, 2, 1);
    
    protocol_register_context(&ctx1);
    protocol_register_context(&ctx2);
    printf("  PASS\n");
}

static void test_protocol_check_timeouts(void) {
    printf("Testing protocol_check_timeouts...\n");
    client_protocol_ctx_t ctx;
    state_machine_init(&ctx, 1, 1);
    ctx.state = STATE_KEY_SETUP;
    
    protocol_register_context(&ctx);
    protocol_check_timeouts();
    
    ctx.last_activity_tick = xTaskGetTickCount() - pdMS_TO_TICKS(20000);
    protocol_check_timeouts();
    assert(ctx.state == STATE_DROPOUT_DETECTION);
    printf("  PASS\n");
}

int main(void) {
    printf("Running State Machine Tests...\n\n");
    
    test_state_machine_init();
    test_state_machine_transition();
    test_state_machine_round_init();
    test_state_machine_key_setup();
    test_state_machine_mask_setup();
    test_state_machine_local_training();
    test_state_machine_stream_chunk();
    test_state_machine_completion();
    test_state_machine_dropout_notify();
    test_state_machine_recovery_complete();
    test_state_machine_round_complete();
    test_state_machine_full_flow();
    test_state_machine_invalid_transitions();
    test_protocol_register_context();
    test_protocol_check_timeouts();
    
    printf("\n=== ALL STATE MACHINE TESTS PASSED ===\n");
    return 0;
}