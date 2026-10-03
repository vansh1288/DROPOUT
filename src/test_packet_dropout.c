#include "mask_prg_mock.h"
#include "test_packet_codec.c"
#include "test_dropout_protocol.c"

int main(void) {
    printf("=== Running Member 3 Native Tests (Packet Codec + Dropout Protocol) ===\n\n");
    
    printf("--- Packet Codec Tests ---\n");
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
    
    printf("\n--- Dropout Protocol Tests ---\n");
    test_basic_recovery_3_of_5();
    test_duplicate_share_rejection();
    test_insufficient_shares();
    test_invalid_share_id();
    test_invalid_share_length();
    test_threshold_boundaries();
    test_recovery_mask_derivation();
    test_unmask_chunk();
    test_invalid_chunk_sizes();
    test_zeroize_cleanup();
    test_round_mismatch();
    test_cleanup_zeroizes();
    
    printf("\n=== ALL TESTS PASSED ===\n");
    return 0;
}