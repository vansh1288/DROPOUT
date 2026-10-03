#include "dropout_protocol.h"
#include "shamir.h"
#include <assert.h>
#include <string.h>
#include <stdio.h>

/* Test 1: Basic recovery flow with threshold=3, 5 shares */
static void test_basic_recovery_3_of_5(void) {
    printf("Testing 3-of-5 recovery...\n");

    /* Initialize recovery for client 5, round 1, threshold 3 */
    assert(dropout_protocol_init_recovery(1, 5, 3) == PQC_SUCCESS);

    /* Create a test secret (64 bytes = 32 GF(3329) elements) */
    uint8_t original_secret[SHAMIR_SECRET_BYTES];
    for (int i = 0; i < SHAMIR_SECRET_ELEMENTS; i++) {
        uint16_t val = i + 1;
        original_secret[2*i] = val & 0xFF;
        original_secret[2*i+1] = (val >> 8) & 0xFF;
    }

    /* Generate 5 shares with threshold 3 */
    uint8_t share_x[5];
    uint8_t* share_y[5];
    uint8_t share_storage[5][SHAMIR_SHARE_VALUE_BYTES];

    /* Create polynomial: f(x) = secret + a1*x + a2*x^2 (threshold=3) */
    uint16_t secret_elements[SHAMIR_SECRET_ELEMENTS];
    for (int i = 0; i < SHAMIR_SECRET_ELEMENTS; i++) {
        secret_elements[i] = (uint16_t)original_secret[2*i] | ((uint16_t)original_secret[2*i+1] << 8);
    }

    /* Simple deterministic coefficients for testing */
    uint16_t coeffs[3][SHAMIR_SECRET_ELEMENTS];
    for (int elem = 0; elem < SHAMIR_SECRET_ELEMENTS; elem++) {
        coeffs[0][elem] = secret_elements[elem];
        coeffs[1][elem] = (elem + 1) % 3329;
        coeffs[2][elem] = (elem + 2) % 3329;
    }

    /* Evaluate at x=1,2,3,4,5 */
    for (int x = 1; x <= 5; x++) {
        share_x[x-1] = x;
        for (int elem = 0; elem < SHAMIR_SECRET_ELEMENTS; elem++) {
            uint16_t y = coeffs[0][elem];
            for (int d = 1; d < 3; d++) {
                uint16_t term = coeffs[d][elem];
                for (int p = 1; p <= d; p++) {
                    term = gf3329_mul(term, x);
                }
                y = gf3329_add(y, term);
            }
            share_storage[x-1][2*elem] = y & 0xFF;
            share_storage[x-1][2*elem+1] = (y >> 8) & 0xFF;
        }
    }

    /* Submit shares one by one */
    for (int i = 0; i < 5; i++) {
        pqc_status_t ret = dropout_protocol_submit_share(i+1, share_storage[i], SHAMIR_SHARE_VALUE_BYTES);
        if (i < 2) {
            assert(ret == PQC_SUCCESS);  // First 2 shares: not enough yet
        } else if (i == 2) {
            assert(ret == PQC_SUCCESS);  // 3rd share: threshold reached!
        } else {
            assert(ret == PQC_SUCCESS);  // Additional shares after threshold
        }
    }

    assert(dropout_protocol_is_recovery_complete() == 1);

    const uint8_t* recovered = dropout_protocol_get_recovered_secret();
    assert(recovered != NULL);
    assert(memcmp(recovered, original_secret, SHAMIR_SECRET_BYTES) == 0);

    printf("  PASS\n");
}

/* Test 2: Duplicate share rejection */
static void test_duplicate_share_rejection(void) {
    printf("Testing duplicate share rejection...\n");

    assert(dropout_protocol_init_recovery(1, 5, 3) == PQC_SUCCESS);

    uint8_t share[SHAMIR_SHARE_VALUE_BYTES] = {0};
    for (int i = 0; i < 64; i++) share[i] = i;

    assert(dropout_protocol_submit_share(1, share, 64) == PQC_SUCCESS);
    assert(dropout_protocol_submit_share(2, share, 64) == PQC_SUCCESS);
    assert(dropout_protocol_submit_share(3, share, 64) == PQC_SUCCESS);

    /* Duplicate share should be rejected */
    assert(dropout_protocol_submit_share(1, share, 64) == ERR_DUPLICATE_SHARE_ID);

    printf("  PASS\n");
}

/* Test 3: Insufficient shares */
static void test_insufficient_shares(void) {
    printf("Testing insufficient shares handling...\n");

    assert(dropout_protocol_init_recovery(1, 5, 4) == PQC_SUCCESS);

    uint8_t share[SHAMIR_SHARE_VALUE_BYTES] = {0};
    for (int i = 0; i < 64; i++) share[i] = i;

    /* Only 2 shares for threshold 4 */
    assert(dropout_protocol_submit_share(1, share, 64) == PQC_SUCCESS);
    assert(dropout_protocol_submit_share(2, share, 64) == PQC_SUCCESS);
    assert(dropout_protocol_submit_share(3, share, 64) == PQC_SUCCESS);

    /* Should not be complete yet */
    assert(dropout_protocol_is_recovery_complete() == 0);
    assert(dropout_protocol_get_recovered_secret() == NULL);

    /* 4th share should complete */
    assert(dropout_protocol_submit_share(4, share, 64) == PQC_SUCCESS);
    assert(dropout_protocol_is_recovery_complete() == 1);

    printf("  PASS\n");
}

/* Test 4: Invalid share ID (0 or duplicate) */
static void test_invalid_share_id(void) {
    printf("Testing invalid share ID handling...\n");

    assert(dropout_protocol_init_recovery(1, 5, 3) == PQC_SUCCESS);

    uint8_t share[64] = {0};

    /* Share ID 0 is invalid */
    assert(dropout_protocol_submit_share(0, share, 64) == ERR_INVALID_ARGUMENT);

    /* Valid share */
    assert(dropout_protocol_submit_share(1, share, 64) == PQC_SUCCESS);

    /* Duplicate ID */
    assert(dropout_protocol_submit_share(1, share, 64) == ERR_DUPLICATE_SHARE_ID);

    printf("  PASS\n");
}

/* Test 5: Invalid share length */
static void test_invalid_share_length(void) {
    printf("Testing invalid share length...\n");

    assert(dropout_protocol_init_recovery(1, 5, 3) == PQC_SUCCESS);

    uint8_t share[32] = {0};  // Only 32 bytes, need 64

    assert(dropout_protocol_submit_share(1, share, 32) == ERR_INVALID_ARGUMENT);
    assert(dropout_protocol_submit_share(1, share, 128) == ERR_INVALID_ARGUMENT);

    printf("  PASS\n");
}

/* Test 5: Threshold boundary (t=1 should work, t=0 invalid) */
static void test_threshold_boundaries(void) {
    printf("Testing threshold boundaries...\n");

    /* t=0 invalid */
    assert(dropout_protocol_init_recovery(1, 5, 0) == ERR_INVALID_THRESHOLD);

    /* t=1 valid */
    assert(dropout_protocol_init_recovery(1, 5, 1) == PQC_SUCCESS);

    uint8_t share[64] = {0};
    assert(dropout_protocol_submit_share(1, share, 64) == PQC_SUCCESS);
    assert(dropout_protocol_is_recovery_complete() == 1);

    /* Max threshold */
    assert(dropout_protocol_init_recovery(1, 5, 255) == PQC_SUCCESS);
    assert(dropout_protocol_init_recovery(1, 5, 256) == ERR_INVALID_THRESHOLD);

    printf("  PASS\n");
}

/* Test 6: Full recovery + mask derivation integration */
static void test_recovery_mask_derivation(void) {
    printf("Testing recovery + mask derivation integration...\n");

    assert(dropout_protocol_init_recovery(1, 5, 3) == PQC_SUCCESS);

    /* Create test secret and shares */
    uint8_t secret[SHAMIR_SECRET_BYTES] = {0};
    for (int i = 0; i < SHAMIR_SECRET_ELEMENTS; i++) {
        secret[2*i] = i & 0xFF;
        secret[2*i+1] = (i >> 8) & 0xFF;
    }

    /* Generate 3 shares with t=3 */
    uint8_t share_x[3] = {1, 2, 3};
    uint8_t share_y[3][64];

    for (int x = 1; x <= 3; x++) {
        for (int elem = 0; elem < SHAMIR_SECRET_ELEMENTS; elem++) {
            uint16_t y = gf3329_evaluate_polynomial(
                (uint16_t[]){secret[2*elem] | (secret[2*elem+1] << 8), 
                              123, 456}, 3, x);
            share_y[x-1][2*elem] = y & 0xFF;
            share_y[x-1][2*elem+1] = (y >> 8) & 0xFF;
        }
    }

    /* Submit shares */
    for (int i = 0; i < 3; i++) {
        assert(dropout_protocol_submit_share(i+1, share_y[i], 64) == PQC_SUCCESS);
    }

    assert(dropout_protocol_is_recovery_complete() == 1);

    /* Derive mask for recovery */
    int16_t mask[256];
    pqc_status_t ret = dropout_protocol_derive_mask_for_recovery(
        1,      /* round_id */
        0,      /* chunk_index */
        10,     /* peer_id */
        mask,
        256     /* chunk_size */
    );

    assert(ret == PQC_SUCCESS);

    /* Verify mask is not all zeros */
    int non_zero = 0;
    for (int i = 0; i < 128; i++) {
        if (mask[i] != 0) non_zero = 1;
    }
    assert(non_zero);

    printf("  PASS\n");
}

/* Test 7: Unmask chunk with recovered secret */
static void test_unmask_chunk(void) {
    printf("Testing unmask chunk with recovered secret...\n");

    assert(dropout_protocol_init_recovery(1, 5, 3) == PQC_SUCCESS);

    uint8_t secret[SHAMIR_SECRET_BYTES] = {0};
    for (int i = 0; i < SHAMIR_SECRET_ELEMENTS; i++) {
        secret[2*i] = i & 0xFF;
        secret[2*i+1] = (i >> 8) & 0xFF;
    }

    uint8_t share_x[3] = {1, 2, 3};
    uint8_t share_y[3][64];

    for (int x = 1; x <= 3; x++) {
        for (int elem = 0; elem < SHAMIR_SECRET_ELEMENTS; elem++) {
            uint16_t y = gf3329_evaluate_polynomial(
                (uint16_t[]){secret[2*elem] | (secret[2*elem+1] << 8), 123, 456}, 3, x);
            share_y[x-1][2*elem] = y & 0xFF;
            share_y[x-1][2*elem+1] = (y >> 8) & 0xFF;
        }
    }

    for (int i = 0; i < 3; i++) {
        assert(dropout_protocol_submit_share(i+1, share_y[i], 64) == PQC_SUCCESS);
    }

    /* Create test masked data */
    int16_t plaintext[128];
    for (int i = 0; i < 128; i++) plaintext[i] = i + 100;

    /* Mask it first (simulating the dropped client's masking) */
    int16_t masked[128];
    int16_t mask[128];
    uint8_t stream_seed[32];
    mask_prg_ctx_t prg_ctx;
    mask_prg_init(&prg_ctx, stream_seed);
    mask_prg_get_bytes(&prg_ctx, (uint8_t*)mask, 256);

    for (int i = 0; i < 128; i++) {
        int32_t sum = (int32_t)plaintext[i] + (int32_t)mask[i];
        masked[i] = (int16_t)mod_q(sum);
    }

    /* Now unmask using recovered secret */
    int16_t unmasked[128];
    pqc_status_t ret = dropout_protocol_unmask_chunk(
        NULL,  // Will use recovered secret internally
        1, 0, 5, 10,
        (int16_t*)masked,  // masked input
        unmasked,
        256
    );

    /* Should fail without recovered secret */
    assert(ret != PQC_SUCCESS || dropout_protocol_is_recovery_complete() == 0);

    /* Now do the full flow */
    for (int i = 0; i < 3; i++) {
        assert(dropout_protocol_submit_share(i+1, share_y[i], 64) == PQC_SUCCESS);
    }

    int16_t unmasked[128];
    int ret = dropout_protocol_unmask_chunk(
        NULL, 1, 0, 5, 10,
        (int16_t*)masked,  // This should be the masked data
        unmasked,
        256
    );

    /* Should work now */
    assert(ret == PQC_SUCCESS);

    printf("  PASS\n");
}

/* Test 8: Invalid chunk sizes */
static void test_invalid_chunk_sizes(void) {
    printf("Testing invalid chunk sizes...\n");

    int16_t mask[128];

    assert(dropout_protocol_derive_mask_for_recovery(1, 0, 10, mask, 32) == ERR_CHUNK_TOO_LARGE);
    assert(dropout_protocol_derive_mask_for_recovery(1, 0, 10, mask, 2048) == ERR_CHUNK_TOO_LARGE);
    assert(dropout_protocol_derive_mask_for_recovery(1, 0, 10, mask, 129) == ERR_CHUNK_TOO_LARGE);

    assert(dropout_protocol_derive_mask_for_recovery(1, 0, 10, mask, 64) == PQC_SUCCESS);
    assert(dropout_protocol_derive_mask_for_recovery(1, 0, 10, mask, 128) == PQC_SUCCESS);
    assert(dropout_protocol_derive_mask_for_recovery(1, 0, 10, mask, 256) == PQC_SUCCESS);
    assert(dropout_protocol_derive_mask_for_recovery(1, 0, 10, mask, 512) == PQC_SUCCESS);
    assert(dropout_protocol_derive_mask_for_recovery(1, 0, 10, mask, 1024) == PQC_SUCCESS);

    printf("  PASS\n");
}

/* Test 8: Zeroize cleanup */
static void test_zeroize_cleanup(void) {
    printf("Testing zeroize cleanup...\n");

    assert(dropout_protocol_init_recovery(1, 5, 3) == PQC_SUCCESS);

    uint8_t share[64] = {0xAA};
    assert(dropout_protocol_submit_share(1, share, 64) == PQC_SUCCESS);
    assert(dropout_protocol_submit_share(2, share, 64) == PQC_SUCCESS);
    assert(dropout_protocol_submit_share(3, share, 64) == PQC_SUCCESS);

    assert(dropout_protocol_is_recovery_complete() == 1);

    dropout_protocol_cleanup();

    assert(dropout_protocol_is_recovery_complete() == 0);
    assert(dropout_protocol_get_recovered_secret() == NULL);

    printf("  PASS\n");
}

/* Test 9: Round ID mismatch */
static void test_round_mismatch(void) {
    printf("Testing round ID mismatch...\n");

    assert(dropout_protocol_init_recovery(1, 5, 3) == PQC_SUCCESS);

    uint8_t share[64] = {0};
    for (int i = 0; i < 3; i++) {
        assert(dropout_protocol_submit_share(i+1, share, 64) == PQC_SUCCESS);
    }

    assert(dropout_protocol_is_recovery_complete() == 1);

    int16_t mask[128];
    /* Try to derive mask for round 2 when recovery was for round 1 */
    assert(dropout_protocol_derive_mask_for_recovery(2, 0, 10, mask, 256) == ERR_ROUND_MISMATCH);

    /* But should work for round 1 */
    assert(dropout_protocol_derive_mask_for_recovery(1, 0, 10, mask, 256) == PQC_SUCCESS);

    printf("  PASS\n");
}

/* Test 10: Cleanup zeroizes sensitive data */
static void test_cleanup_zeroizes(void) {
    printf("Testing cleanup zeroizes sensitive data...\n");

    assert(dropout_protocol_init_recovery(1, 5, 3) == PQC_SUCCESS);

    uint8_t share[64];
    for (int i = 0; i < 64; i++) share[i] = 0xAA;

    assert(dropout_protocol_submit_share(1, share, 64) == PQC_SUCCESS);
    assert(dropout_protocol_submit_share(2, share, 64) == PQC_SUCCESS);
    assert(dropout_protocol_submit_share(3, share, 64) == PQC_SUCCESS);

    const uint8_t* secret = dropout_protocol_get_recovered_secret();
    int non_zero = 0;
    for (int i = 0; i < 64; i++) if (secret[i] != 0) non_zero = 1;
    assert(non_zero);

    dropout_protocol_cleanup();

    /* After cleanup, secret should be zeroized */
    const uint8_t* after = dropout_protocol_get_recovered_secret();
    int all_zero = 1;
    for (int i = 0; i < 64; i++) if (after[i] != 0) all_zero = 0;
    assert(all_zero);

    printf("  PASS\n");
}

int main(void) {
    printf("Running dropout protocol integration tests...\n\n");

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

    printf("\n=== All dropout protocol tests PASSED ===\n");
    return 0;
}