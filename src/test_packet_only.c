#include "mask_prg_mock.h"
#include "test_packet_codec.c"

int main(void) {
    printf("=== Running Packet Codec Tests ===\n\n");
    
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
    
    printf("\n=== ALL PACKET CODEC TESTS PASSED ===\n");
    return 0;
}