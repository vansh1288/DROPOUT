#include <assert.h>
#include <string.h>
#include "shamir.h"

static void test_shamir_3_of_5_reconstruction(void) {
    uint16_t shares_x[5] = {1, 2, 3, 4, 5};
    uint16_t shares_y[5][SHAMIR_SECRET_SIZE];
    uint16_t secret[SHAMIR_SECRET_SIZE] = {0x1234, 0x5678, 0x9abc, 0xdef0};
    uint16_t reconstructed[SHAMIR_SECRET_SIZE];
    uint16_t workspace[SHAMIR_WORKSPACE_SIZE];

    shamir_share(secret, shares_x, shares_y, 5, 3, workspace);

    uint16_t recon_x[3] = {1, 3, 5};
    uint16_t recon_y[3][SHAMIR_SECRET_SIZE];
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < SHAMIR_SECRET_SIZE; j++) {
            recon_y[i][j] = shares_y[recon_x[i] - 1][j];
        }
    }

    shamir_reconstruct(reconstructed, recon_x, recon_y, 3, workspace);
    assert(memcmp(reconstructed, secret, SHAMIR_SECRET_SIZE * sizeof(uint16_t)) == 0);
}

static void test_shamir_2_of_5_failed_reconstruction(void) {
    uint16_t shares_x[5] = {1, 2, 3, 4, 5};
    uint16_t shares_y[5][SHAMIR_SECRET_SIZE];
    uint16_t secret[SHAMIR_SECRET_SIZE] = {0x1234, 0x5678, 0x9abc, 0xdef0};
    uint16_t reconstructed[SHAMIR_SECRET_SIZE];
    uint16_t workspace[SHAMIR_WORKSPACE_SIZE];

    shamir_share(secret, shares_x, shares_y, 5, 3, workspace);

    uint16_t recon_x[2] = {1, 2};
    uint16_t recon_y[2][SHAMIR_SECRET_SIZE];
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < SHAMIR_SECRET_SIZE; j++) {
            recon_y[i][j] = shares_y[recon_x[i] - 1][j];
        }
    }

    int result = shamir_reconstruct(reconstructed, recon_x, recon_y, 2, workspace);
    assert(result != 0);
    assert(memcmp(reconstructed, secret, SHAMIR_SECRET_SIZE * sizeof(uint16_t)) != 0);
}

static void test_shamir_gf3329_field_operations(void) {
    uint16_t a = 0x1234;
    uint16_t b = 0x5678;
    uint16_t result;
    uint16_t workspace[SHAMIR_WORKSPACE_SIZE];

    result = gf3329_add(a, b);
    assert(result == gf3329_add(b, a));

    result = gf3329_sub(a, b);
    uint16_t check = gf3329_add(result, b);
    assert(check == a);

    result = gf3329_mul(a, b);
    assert(result == gf3329_mul(b, a));

    if (a != 0) {
        uint16_t inv = gf3329_inv(a);
        result = gf3329_mul(a, inv);
        assert(result == 1);
    }
}

static void test_shamir_different_thresholds(void) {
    uint16_t shares_x[7] = {1, 2, 3, 4, 5, 6, 7};
    uint16_t shares_y[7][SHAMIR_SECRET_SIZE];
    uint16_t secret[SHAMIR_SECRET_SIZE] = {0xaaaa, 0xbbbb, 0xcccc, 0xdddd};
    uint16_t reconstructed[SHAMIR_SECRET_SIZE];
    uint16_t workspace[SHAMIR_WORKSPACE_SIZE];

    shamir_share(secret, shares_x, shares_y, 7, 4, workspace);

    uint16_t recon_x[4] = {2, 4, 6, 7};
    uint16_t recon_y[4][SHAMIR_SECRET_SIZE];
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < SHAMIR_SECRET_SIZE; j++) {
            recon_y[i][j] = shares_y[recon_x[i] - 1][j];
        }
    }

    shamir_reconstruct(reconstructed, recon_x, recon_y, 4, workspace);
    assert(memcmp(reconstructed, secret, SHAMIR_SECRET_SIZE * sizeof(uint16_t)) == 0);
}

static void test_shamir_zero_secret(void) {
    uint16_t shares_x[5] = {1, 2, 3, 4, 5};
    uint16_t shares_y[5][SHAMIR_SECRET_SIZE];
    uint16_t secret[SHAMIR_SECRET_SIZE] = {0, 0, 0, 0};
    uint16_t reconstructed[SHAMIR_SECRET_SIZE];
    uint16_t workspace[SHAMIR_WORKSPACE_SIZE];

    shamir_share(secret, shares_x, shares_y, 5, 3, workspace);

    uint16_t recon_x[3] = {1, 2, 3};
    uint16_t recon_y[3][SHAMIR_SECRET_SIZE];
    for (int i = 0; i < 3; i++) {
        for (int j = 0; j < SHAMIR_SECRET_SIZE; j++) {
            recon_y[i][j] = shares_y[recon_x[i] - 1][j];
        }
    }

    shamir_reconstruct(reconstructed, recon_x, recon_y, 3, workspace);
    assert(memcmp(reconstructed, secret, SHAMIR_SECRET_SIZE * sizeof(uint16_t)) == 0);
}

int main(void) {
    test_shamir_3_of_5_reconstruction();
    test_shamir_2_of_5_failed_reconstruction();
    test_shamir_gf3329_field_operations();
    test_shamir_different_thresholds();
    test_shamir_zero_secret();
    return 0;
}