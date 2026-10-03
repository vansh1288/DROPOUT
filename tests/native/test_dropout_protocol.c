#include "dropout_protocol.h"
#include "shamir.h"
#include "mask_prg.h"
#include "protocol_types.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

static void build_test_shares(
    const uint8_t* secret,
    uint8_t* share_ids,
    uint8_t share_values[][SHAMIR_SHARE_VALUE_BYTES],
    uint8_t count)
{
    uint16_t secret_elements[SHAMIR_SECRET_ELEMENTS];

    for (uint8_t i = 0; i < SHAMIR_SECRET_ELEMENTS; i++) {
        secret_elements[i] =
            (uint16_t)secret[2 * i] |
            ((uint16_t)secret[2 * i + 1] << 8);
    }

    /*
     * Deterministic degree-2 polynomial for each secret element:
     *
     * f(x) = secret + (i + 1)x + (i + 2)x^2
     *
     * This gives a 3-of-N Shamir test set.
     */
    for (uint8_t x = 1; x <= count; x++) {
        share_ids[x - 1] = x;

        for (uint8_t elem = 0;
             elem < SHAMIR_SECRET_ELEMENTS;
             elem++) {

            uint16_t coeffs[3];

            coeffs[0] = secret_elements[elem];
            coeffs[1] = (uint16_t)((elem + 1) % 3329);
            coeffs[2] = (uint16_t)((elem + 2) % 3329);

            uint16_t y =
                gf3329_evaluate_polynomial(coeffs, 3, x);

            share_values[x - 1][2 * elem] =
                (uint8_t)(y & 0xFF);

            share_values[x - 1][2 * elem + 1] =
                (uint8_t)((y >> 8) & 0xFF);
        }
    }
}


/* Test 1: Basic 3-of-5 recovery */
static void test_basic_recovery_3_of_5(void)
{
    printf("Testing 3-of-5 recovery...\n");

    assert(
        dropout_protocol_init_recovery(1, 5, 3)
        == PQC_SUCCESS
    );

    uint8_t original_secret[SHAMIR_SECRET_BYTES];

    for (uint8_t i = 0; i < SHAMIR_SECRET_ELEMENTS; i++) {
        uint16_t value = (uint16_t)(i + 1);

        original_secret[2 * i] =
            (uint8_t)(value & 0xFF);

        original_secret[2 * i + 1] =
            (uint8_t)((value >> 8) & 0xFF);
    }

    uint8_t share_ids[5];
    uint8_t share_values[5][SHAMIR_SHARE_VALUE_BYTES];

    build_test_shares(
        original_secret,
        share_ids,
        share_values,
        5
    );

    for (uint8_t i = 0; i < 3; i++) {
        assert(
            dropout_protocol_submit_share(
                share_ids[i],
                share_values[i],
                SHAMIR_SHARE_VALUE_BYTES
            ) == PQC_SUCCESS
        );
    }

    assert(dropout_protocol_is_recovery_complete() == 1);

    const uint8_t* recovered =
        dropout_protocol_get_recovered_secret();

    assert(recovered != NULL);

    assert(
        memcmp(
            recovered,
            original_secret,
            SHAMIR_SECRET_BYTES
        ) == 0
    );

    /*
     * Once recovery is complete, additional submissions are rejected
     * by the current implementation.
     */
    assert(
        dropout_protocol_submit_share(
            share_ids[3],
            share_values[3],
            SHAMIR_SHARE_VALUE_BYTES
        ) == ERR_INVALID_STATE
    );

    dropout_protocol_cleanup();

    printf("  PASS\n");
}


/* Test 2: Duplicate share rejection */
static void test_duplicate_share_rejection(void)
{
    printf("Testing duplicate share rejection...\n");

    assert(
        dropout_protocol_init_recovery(1, 5, 3)
        == PQC_SUCCESS
    );

    uint8_t share[SHAMIR_SHARE_VALUE_BYTES] = {0};

    assert(
        dropout_protocol_submit_share(
            1,
            share,
            SHAMIR_SHARE_VALUE_BYTES
        ) == PQC_SUCCESS
    );

    assert(
        dropout_protocol_submit_share(
            2,
            share,
            SHAMIR_SHARE_VALUE_BYTES
        ) == PQC_SUCCESS
    );

    assert(
        dropout_protocol_submit_share(
            1,
            share,
            SHAMIR_SHARE_VALUE_BYTES
        ) == ERR_DUPLICATE_SHARE_ID
    );

    dropout_protocol_cleanup();

    printf("  PASS\n");
}


/* Test 3: Insufficient shares */
static void test_insufficient_shares(void)
{
    printf("Testing insufficient shares handling...\n");

    assert(
        dropout_protocol_init_recovery(1, 5, 4)
        == PQC_SUCCESS
    );

    uint8_t secret[SHAMIR_SECRET_BYTES] = {0};
    uint8_t share_ids[4];
    uint8_t share_values[4][SHAMIR_SHARE_VALUE_BYTES];

    build_test_shares(
        secret,
        share_ids,
        share_values,
        4
    );

    for (uint8_t i = 0; i < 3; i++) {
        assert(
            dropout_protocol_submit_share(
                share_ids[i],
                share_values[i],
                SHAMIR_SHARE_VALUE_BYTES
            ) == PQC_SUCCESS
        );
    }

    assert(dropout_protocol_is_recovery_complete() == 0);
    assert(dropout_protocol_get_recovered_secret() == NULL);

    assert(
        dropout_protocol_submit_share(
            share_ids[3],
            share_values[3],
            SHAMIR_SHARE_VALUE_BYTES
        ) == PQC_SUCCESS
    );

    assert(dropout_protocol_is_recovery_complete() == 1);
    assert(dropout_protocol_get_recovered_secret() != NULL);

    dropout_protocol_cleanup();

    printf("  PASS\n");
}


/* Test 4: Invalid share ID */
static void test_invalid_share_id(void)
{
    printf("Testing invalid share ID handling...\n");

    assert(
        dropout_protocol_init_recovery(1, 5, 3)
        == PQC_SUCCESS
    );

    uint8_t share[SHAMIR_SHARE_VALUE_BYTES] = {0};

    assert(
        dropout_protocol_submit_share(
            0,
            share,
            SHAMIR_SHARE_VALUE_BYTES
        ) == ERR_INVALID_ARGUMENT
    );

    assert(
        dropout_protocol_submit_share(
            1,
            share,
            SHAMIR_SHARE_VALUE_BYTES
        ) == PQC_SUCCESS
    );

    assert(
        dropout_protocol_submit_share(
            1,
            share,
            SHAMIR_SHARE_VALUE_BYTES
        ) == ERR_DUPLICATE_SHARE_ID
    );

    dropout_protocol_cleanup();

    printf("  PASS\n");
}


/* Test 5: Invalid share length */
static void test_invalid_share_length(void)
{
    printf("Testing invalid share length...\n");

    assert(
        dropout_protocol_init_recovery(1, 5, 3)
        == PQC_SUCCESS
    );

    uint8_t share[SHAMIR_SHARE_VALUE_BYTES] = {0};

    assert(
        dropout_protocol_submit_share(
            1,
            share,
            SHAMIR_SHARE_VALUE_BYTES - 1
        ) == ERR_INVALID_ARGUMENT
    );

    assert(
        dropout_protocol_submit_share(
            1,
            share,
            SHAMIR_SHARE_VALUE_BYTES + 1
        ) == ERR_INVALID_ARGUMENT
    );

    assert(
        dropout_protocol_submit_share(
            1,
            NULL,
            SHAMIR_SHARE_VALUE_BYTES
        ) == ERR_INVALID_ARGUMENT
    );

    dropout_protocol_cleanup();

    printf("  PASS\n");
}


/* Test 6: Threshold boundaries */
static void test_threshold_boundaries(void)
{
    printf("Testing threshold boundaries...\n");

    assert(
        dropout_protocol_init_recovery(1, 5, 0)
        == ERR_INVALID_THRESHOLD
    );

    /*
     * MAX_RECOVERY_SHARES is 16, so 16 is the valid maximum.
     */
    assert(
        dropout_protocol_init_recovery(
            1,
            5,
            MAX_RECOVERY_SHARES
        ) == PQC_SUCCESS
    );

    assert(
        dropout_protocol_init_recovery(
            1,
            5,
            MAX_RECOVERY_SHARES + 1
        ) == ERR_INVALID_THRESHOLD
    );

    /*
     * Threshold 1 should complete recovery after one valid share.
     */
    assert(
        dropout_protocol_init_recovery(1, 5, 1)
        == PQC_SUCCESS
    );

    uint8_t secret[SHAMIR_SECRET_BYTES] = {0};
    uint8_t share_ids[1];
    uint8_t share_values[1][SHAMIR_SHARE_VALUE_BYTES];

    build_test_shares(
        secret,
        share_ids,
        share_values,
        1
    );

    assert(
        dropout_protocol_submit_share(
            share_ids[0],
            share_values[0],
            SHAMIR_SHARE_VALUE_BYTES
        ) == PQC_SUCCESS
    );

    assert(dropout_protocol_is_recovery_complete() == 1);

    dropout_protocol_cleanup();

    printf("  PASS\n");
}


/* Test 7: Recovery + mask derivation */
static void test_recovery_mask_derivation(void)
{
    printf("Testing recovery + mask derivation integration...\n");

    assert(
        dropout_protocol_init_recovery(1, 5, 3)
        == PQC_SUCCESS
    );

    uint8_t secret[SHAMIR_SECRET_BYTES] = {0};

    for (uint8_t i = 0; i < SHAMIR_SECRET_ELEMENTS; i++) {
        uint16_t value = (uint16_t)i;

        secret[2 * i] =
            (uint8_t)(value & 0xFF);

        secret[2 * i + 1] =
            (uint8_t)((value >> 8) & 0xFF);
    }

    uint8_t share_ids[3];
    uint8_t share_values[3][SHAMIR_SHARE_VALUE_BYTES];

    build_test_shares(
        secret,
        share_ids,
        share_values,
        3
    );

    for (uint8_t i = 0; i < 3; i++) {
        assert(
            dropout_protocol_submit_share(
                share_ids[i],
                share_values[i],
                SHAMIR_SHARE_VALUE_BYTES
            ) == PQC_SUCCESS
        );
    }

    assert(dropout_protocol_is_recovery_complete() == 1);

    int16_t mask[1024 / 2];

    pqc_status_t ret =
        dropout_protocol_derive_mask_for_recovery(
            1,
            0,
            10,
            mask,
            256
        );

    assert(ret == PQC_SUCCESS);

    int non_zero = 0;

    for (size_t i = 0; i < 128; i++) {
        if (mask[i] != 0) {
            non_zero = 1;
            break;
        }
    }

    assert(non_zero);

    dropout_protocol_cleanup();

    printf("  PASS\n");
}


/* Test 8: Unmask API validation and recovered-secret path */
static void test_unmask_chunk(void)
{
    printf("Testing unmask chunk with recovered secret...\n");

    assert(
        dropout_protocol_init_recovery(1, 5, 3)
        == PQC_SUCCESS
    );

    uint8_t secret[SHAMIR_SECRET_BYTES] = {0};

    for (uint8_t i = 0; i < SHAMIR_SECRET_ELEMENTS; i++) {
        uint16_t value = (uint16_t)i;

        secret[2 * i] =
            (uint8_t)(value & 0xFF);

        secret[2 * i + 1] =
            (uint8_t)((value >> 8) & 0xFF);
    }

    uint8_t share_ids[3];
    uint8_t share_values[3][SHAMIR_SHARE_VALUE_BYTES];

    build_test_shares(
        secret,
        share_ids,
        share_values,
        3
    );

    for (uint8_t i = 0; i < 3; i++) {
        assert(
            dropout_protocol_submit_share(
                share_ids[i],
                share_values[i],
                SHAMIR_SHARE_VALUE_BYTES
            ) == PQC_SUCCESS
        );
    }

    assert(dropout_protocol_is_recovery_complete() == 1);

    const uint8_t* recovered =
        dropout_protocol_get_recovered_secret();

    assert(recovered != NULL);

    int16_t masked[128] = {0};
    int16_t output[128] = {0};

    /*
     * The current implementation requires a non-NULL shared_secret.
     * Passing the recovered-secret pointer exercises its recovery path.
     */
    pqc_status_t ret =
        dropout_protocol_unmask_chunk(
            recovered,
            1,
            0,
            5,
            10,
            masked,
            output,
            256
        );

    assert(ret == PQC_SUCCESS);

    /*
     * Zero input should produce a deterministic modular negative mask.
     * We only require that the operation completed and produced bounded
     * field values.
     */
    for (size_t i = 0; i < 128; i++) {
        assert(output[i] >= 0);
        assert(output[i] < 3329);
    }

    /*
     * NULL shared secret must be rejected.
     */
    ret = dropout_protocol_unmask_chunk(
        NULL,
        1,
        0,
        5,
        10,
        masked,
        output,
        256
    );

    assert(ret == ERR_INVALID_ARGUMENT);

    dropout_protocol_cleanup();

    printf("  PASS\n");
}


/* Test 9: Invalid chunk sizes */
static void test_invalid_chunk_sizes(void)
{
    printf("Testing invalid chunk sizes...\n");

    assert(
        dropout_protocol_derive_mask_for_recovery(
            1, 0, 10, NULL, 32
        ) == ERR_INVALID_ARGUMENT
    );

    /*
     * Recovery must be initialized and completed before mask derivation.
     */
    assert(
        dropout_protocol_init_recovery(1, 5, 1)
        == PQC_SUCCESS
    );

    uint8_t secret[SHAMIR_SECRET_BYTES] = {0};
    uint8_t share_ids[1];
    uint8_t share_values[1][SHAMIR_SHARE_VALUE_BYTES];

    build_test_shares(
        secret,
        share_ids,
        share_values,
        1
    );

    assert(
        dropout_protocol_submit_share(
            1,
            share_values[0],
            SHAMIR_SHARE_VALUE_BYTES
        ) == PQC_SUCCESS
    );

    int16_t mask[1024 / 2];

    assert(
        dropout_protocol_derive_mask_for_recovery(
            1, 0, 10, mask, 32
        ) == ERR_CHUNK_TOO_LARGE
    );

    assert(
        dropout_protocol_derive_mask_for_recovery(
            1, 0, 10, mask, 2048
        ) == ERR_CHUNK_TOO_LARGE
    );

    assert(
        dropout_protocol_derive_mask_for_recovery(
            1, 0, 10, mask, 129
        ) == ERR_CHUNK_TOO_LARGE
    );

    assert(
        dropout_protocol_derive_mask_for_recovery(
            1, 0, 10, mask, 64
        ) == PQC_SUCCESS
    );

    assert(
        dropout_protocol_derive_mask_for_recovery(
            1, 0, 10, mask, 128
        ) == PQC_SUCCESS
    );

    assert(
        dropout_protocol_derive_mask_for_recovery(
            1, 0, 10, mask, 256
        ) == PQC_SUCCESS
    );

    assert(
        dropout_protocol_derive_mask_for_recovery(
            1, 0, 10, mask, 512
        ) == PQC_SUCCESS
    );

    assert(
        dropout_protocol_derive_mask_for_recovery(
            1, 0, 10, mask, 1024
        ) == PQC_SUCCESS
    );

    dropout_protocol_cleanup();

    printf("  PASS\n");
}


/* Test 10: Cleanup */
static void test_zeroize_cleanup(void)
{
    printf("Testing zeroize cleanup...\n");

    assert(
        dropout_protocol_init_recovery(1, 5, 3)
        == PQC_SUCCESS
    );

    uint8_t secret[SHAMIR_SECRET_BYTES] = {0x11};

    uint8_t share_ids[3];
    uint8_t share_values[3][SHAMIR_SHARE_VALUE_BYTES];

    build_test_shares(
        secret,
        share_ids,
        share_values,
        3
    );

    for (uint8_t i = 0; i < 3; i++) {
        assert(
            dropout_protocol_submit_share(
                share_ids[i],
                share_values[i],
                SHAMIR_SHARE_VALUE_BYTES
            ) == PQC_SUCCESS
        );
    }

    assert(dropout_protocol_is_recovery_complete() == 1);
    assert(dropout_protocol_get_recovered_secret() != NULL);

    dropout_protocol_cleanup();

    assert(dropout_protocol_is_recovery_complete() == 0);
    assert(dropout_protocol_get_recovered_secret() == NULL);

    printf("  PASS\n");
}


/* Test 11: Round mismatch */
static void test_round_mismatch(void)
{
    printf("Testing round ID mismatch...\n");

    assert(
        dropout_protocol_init_recovery(1, 5, 3)
        == PQC_SUCCESS
    );

    uint8_t secret[SHAMIR_SECRET_BYTES] = {0};
    uint8_t share_ids[3];
    uint8_t share_values[3][SHAMIR_SHARE_VALUE_BYTES];

    build_test_shares(
        secret,
        share_ids,
        share_values,
        3
    );

    for (uint8_t i = 0; i < 3; i++) {
        assert(
            dropout_protocol_submit_share(
                share_ids[i],
                share_values[i],
                SHAMIR_SHARE_VALUE_BYTES
            ) == PQC_SUCCESS
        );
    }

    assert(dropout_protocol_is_recovery_complete() == 1);

    int16_t mask[128];

    assert(
        dropout_protocol_derive_mask_for_recovery(
            2,
            0,
            10,
            mask,
            256
        ) == ERR_ROUND_MISMATCH
    );

    assert(
        dropout_protocol_derive_mask_for_recovery(
            1,
            0,
            10,
            mask,
            256
        ) == PQC_SUCCESS
    );

    dropout_protocol_cleanup();

    printf("  PASS\n");
}


/* Test 12: Recovery context information */
static void test_recovery_info(void)
{
    printf("Testing recovery context information...\n");

    assert(
        dropout_protocol_init_recovery(7, 9, 3)
        == PQC_SUCCESS
    );

    uint32_t round_id = 0;
    uint8_t client_id = 0;
    uint8_t threshold = 0;
    uint8_t shares_received = 0;

    dropout_protocol_get_info(
        &round_id,
        &client_id,
        &threshold,
        &shares_received
    );

    assert(round_id == 7);
    assert(client_id == 9);
    assert(threshold == 3);
    assert(shares_received == 0);

    uint8_t share[SHAMIR_SHARE_VALUE_BYTES] = {0};

    assert(
        dropout_protocol_submit_share(
            1,
            share,
            SHAMIR_SHARE_VALUE_BYTES
        ) == PQC_SUCCESS
    );

    dropout_protocol_get_info(
        &round_id,
        &client_id,
        &threshold,
        &shares_received
    );

    assert(round_id == 7);
    assert(client_id == 9);
    assert(threshold == 3);
    assert(shares_received == 1);

    dropout_protocol_cleanup();

    printf("  PASS\n");
}


int main(void)
{
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
    test_recovery_info();

    printf("\n=== All dropout protocol tests PASSED ===\n");

    return 0;
}