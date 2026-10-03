#include "freertos_mock.h"
#include "mask_prg_mock.h"

#include "test_dma_stream_bridge.c"
#include "test_dma_isr_handler.c"
#include "test_dma_transport.c"
#include "test_packet_codec.c"
#include "test_stream_aggregator.c"
#include "test_dropout_protocol.c"
#include "test_state_machine.c"
#include "test_error_paths.c"

int main(void)
{
    printf("=== Running All Member 3 Native Tests ===\n\n");

    printf("--- DMA Stream Bridge Tests ---\n");
    test_dma_stream_bridge_init();
    test_dma_stream_bridge_rx_complete();
    test_dma_stream_bridge_get_chunk();
    test_dma_stream_bridge_release_buffer();
    test_dma_stream_bridge_reseed();
    test_dma_stream_bridge_error_isr();
    test_dma_stream_bridge_buffer_ownership();
    test_dma_stream_bridge_buffer_exhaustion();
    test_dma_stream_bridge_chunk_ordering();
    test_dma_stream_bridge_chunk_exhaustion();
    test_dma_stream_bridge_stats();

    printf("\n--- DMA ISR Handler Tests ---\n");
    test_dma_isr_init();
    test_dma_isr_rx_complete();
    test_dma_isr_tx_complete();
    test_dma_isr_error();
    test_dma_isr_set_stream_task();
    test_dma_isr_start_rx();
    test_dma_isr_start_tx();
    test_dma_isr_buffer_switch();
    test_dma_isr_multiple_errors();

    printf("\n--- DMA Transport Tests ---\n");
    test_dma_transport_init();
    test_dma_transport_queue_tx();
    test_dma_transport_get_rx_data();
    test_dma_transport_rx_poll();
    test_dma_transport_tx_poll();
    test_dma_transport_impairment_drop();
    test_dma_transport_chunking();
    test_dma_transport_callbacks();
    test_dma_transport_multiple_chunks();

    printf("\n--- Packet Codec Tests ---\n");
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

    printf("\n--- Stream Aggregator Tests ---\n");
    test_stream_aggregator_init();
    test_stream_aggregator_start_session();
    test_stream_aggregator_validate_chunk_size();
    test_stream_aggregator_validate_chunk_valid();
    test_stream_aggregator_validate_chunk_invalid_size();
    test_stream_aggregator_validate_chunk_invalid_round();
    test_stream_aggregator_validate_chunk_invalid_client();
    test_stream_aggregator_validate_chunk_out_of_order();
    test_stream_aggregator_duplicate_rejection();
    test_stream_aggregator_receive_chunk();
    test_stream_aggregator_receive_chunk_invalid_args();
    test_stream_aggregator_finalize_session();
    test_stream_aggregator_finalize_insufficient_chunks();
    test_stream_aggregator_reset();
    test_stream_aggregator_zeroize();
    test_stream_aggregator_dma_bridge();
    test_stream_aggregator_boundary_chunks();
    test_stream_aggregator_different_chunk_sizes();
    test_stream_aggregator_work_queue();
    test_stream_aggregator_finalize_multichunk_rejection();

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
    test_recovery_info();

    printf("\n--- State Machine Tests ---\n");
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

    printf("\n--- Error Paths Tests ---\n");
    test_dma_stream_bridge_null_pointers();
    test_dma_stream_bridge_timeout();
    test_dma_stream_bridge_buffer_exhaustion();
    test_dma_stream_bridge_invalid_state_release();
    test_dma_isr_null_task_handle();
    test_dma_transport_invalid_state();
    test_dma_transport_null_pointers();
    test_stream_aggregator_null_pointers();
    test_stream_aggregator_buffer_exhaustion();
    test_stream_aggregator_timeout_session();
    test_packet_codec_null_pointers();
    test_packet_codec_buffer_too_small();
    test_packet_codec_invalid_mac();
    test_packet_codec_wrong_round_client_sequence();
    test_dropout_protocol_invalid_args();
    test_dropout_protocol_threshold_exhaustion();
    test_dma_transport_sock_errors();
    test_stream_aggregator_state_errors();
    test_crypto_zeroize();
    test_scratchpad_zeroize();
    test_region_zeroize();
    test_invalid_chunk_sizes_all();

    printf("\n=== ALL TESTS PASSED ===\n");

    return 0;
}