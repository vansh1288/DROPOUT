#include "mask_prg_mock.h"
#include "test_dropout_protocol.c"

int main(void) {
    printf("=== Running Dropout Protocol Tests ===\n\n");
    
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
    
    printf("\n=== ALL DROPOUT PROTOCOL TESTS PASSED ===\n");
    return 0;
}