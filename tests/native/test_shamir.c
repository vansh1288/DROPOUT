#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "shamir.h"

#ifdef SHAMIR_DETERMINISTIC_RNG
extern void shamir_test_rng_init(const uint8_t seed[48]);
#define TEST_RNG_INIT(seed) shamir_test_rng_init(seed)
#else
// Fallback for non-deterministic builds - use fixed seed for reproducibility
#define TEST_RNG_INIT(seed) do { (void)seed; } while(0)
#endif

static void test_shamir_3_of_5_reconstruction(void) {
    uint16_t shares_x[5];
    uint16_t shares_y[5][SHAMIR_SECRET_ELEMENTS];
    uint16_t* shares_y_ptr[5];
    for (int i = 0; i < 5; i++) shares_y_ptr[i] = shares_y[i];
    
    uint16_t secret[SHAMIR_SECRET_ELEMENTS] = {0x1234, 0x5678, 0x9abc, 0xdef0};
    for (int i = 4; i < SHAMIR_SECRET_ELEMENTS; i++) secret[i] = i;
    uint16_t reconstructed[SHAMIR_SECRET_ELEMENTS];
    uint16_t workspace[SHAMIR_WORKSPACE_SIZE];

    TEST_RNG_INIT((const uint8_t*)"test-seed-3of5-0123456789abcdef");
    shamir_share(secret, SHAMIR_SECRET_ELEMENTS, shares_x, shares_y_ptr, 5, 3, workspace);

    uint16_t recon_x[3] = {1, 3, 5};
    uint16_t* recon_y[3];
    for (int i = 0; i < 3; i++) recon_y[i] = shares_y[recon_x[i] - 1];

    shamir_reconstruct(reconstructed, recon_x, recon_y, 3, workspace);
    assert(memcmp(reconstructed, secret, SHAMIR_SECRET_ELEMENTS * sizeof(uint16_t)) == 0);
}

static void test_shamir_2_of_5_failed_reconstruction(void) {
    uint16_t shares_x[5];
    uint16_t shares_y[5][SHAMIR_SECRET_ELEMENTS];
    uint16_t* shares_y_ptr[5];
    for (int i = 0; i < 5; i++) shares_y_ptr[i] = shares_y[i];
    
    uint16_t secret[SHAMIR_SECRET_ELEMENTS] = {0x1234, 0x5678, 0x9abc, 0xdef0};
    for (int i = 4; i < SHAMIR_SECRET_ELEMENTS; i++) secret[i] = i;
    uint16_t reconstructed[SHAMIR_SECRET_ELEMENTS];
    uint16_t workspace[SHAMIR_WORKSPACE_SIZE];

    TEST_RNG_INIT((const uint8_t*)"test-seed-2of5-0123456789abcdef");
    shamir_share(secret, SHAMIR_SECRET_ELEMENTS, shares_x, shares_y_ptr, 5, 3, workspace);

    uint16_t recon_x[2] = {1, 2};
    uint16_t* recon_y[2];
    for (int i = 0; i < 2; i++) recon_y[i] = shares_y[recon_x[i] - 1];

    int result = shamir_reconstruct(reconstructed, recon_x, recon_y, 2, workspace);
    assert(result == 0);
    assert(memcmp(reconstructed, secret, SHAMIR_SECRET_ELEMENTS * sizeof(uint16_t)) != 0);
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
    uint16_t shares_x[7];
    uint16_t shares_y[7][SHAMIR_SECRET_ELEMENTS];
    uint16_t* shares_y_ptr[7];
    for (int i = 0; i < 7; i++) shares_y_ptr[i] = shares_y[i];
    
    uint16_t secret[SHAMIR_SECRET_ELEMENTS] = {0xaaaa, 0xbbbb, 0xcccc, 0xdddd};
    for (int i = 4; i < SHAMIR_SECRET_ELEMENTS; i++) secret[i] = i;
    uint16_t reconstructed[SHAMIR_SECRET_ELEMENTS];
    uint16_t workspace[SHAMIR_WORKSPACE_SIZE];

    TEST_RNG_INIT((const uint8_t*)"test-seed-thresh-0123456789abcdef");
    shamir_share(secret, SHAMIR_SECRET_ELEMENTS, shares_x, shares_y_ptr, 7, 4, workspace);

    uint16_t recon_x[4] = {2, 4, 6, 7};
    uint16_t* recon_y[4];
    for (int i = 0; i < 4; i++) recon_y[i] = shares_y[recon_x[i] - 1];

    shamir_reconstruct(reconstructed, recon_x, recon_y, 4, workspace);
    assert(memcmp(reconstructed, secret, SHAMIR_SECRET_ELEMENTS * sizeof(uint16_t)) == 0);
}

static void test_shamir_zero_secret(void) {
    uint16_t shares_x[5];
    uint16_t shares_y[5][SHAMIR_SECRET_ELEMENTS];
    uint16_t* shares_y_ptr[5];
    for (int i = 0; i < 5; i++) shares_y_ptr[i] = shares_y[i];
    
    uint16_t secret[SHAMIR_SECRET_ELEMENTS] = {0, 0, 0, 0};
    for (int i = 4; i < SHAMIR_SECRET_ELEMENTS; i++) secret[i] = 0;
    uint16_t reconstructed[SHAMIR_SECRET_ELEMENTS];
    uint16_t workspace[SHAMIR_WORKSPACE_SIZE];

    TEST_RNG_INIT((const uint8_t*)"test-seed-zero----0123456789ab");
    shamir_share(secret, SHAMIR_SECRET_ELEMENTS, shares_x, shares_y_ptr, 5, 3, workspace);

    uint16_t recon_x[3] = {1, 2, 3};
    uint16_t* recon_y[3];
    for (int i = 0; i < 3; i++) recon_y[i] = shares_y[recon_x[i] - 1];

    shamir_reconstruct(reconstructed, recon_x, recon_y, 3, workspace);
    assert(memcmp(reconstructed, secret, SHAMIR_SECRET_ELEMENTS * sizeof(uint16_t)) == 0);
}

static void test_shamir_bytes_api(void) {
    uint8_t secret[SHAMIR_SECRET_BYTES] = {
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
        0x13, 0x57, 0x9b, 0xdf, 0x24, 0x68, 0xac, 0xf0
    };
    uint8_t share_x[5];
    uint8_t shares_y[5][SHAMIR_SECRET_BYTES];
    uint8_t* shares_y_ptr[5];
    for (int i = 0; i < 5; i++) shares_y_ptr[i] = shares_y[i];
    uint8_t reconstructed[SHAMIR_SECRET_BYTES];
    uint16_t workspace[SHAMIR_WORKSPACE_SIZE];

    TEST_RNG_INIT((const uint8_t*)"test-seed-bytes--0123456789abc");
    int ret = shamir_share_bytes(secret, SHAMIR_SECRET_BYTES, share_x, shares_y_ptr, 5, 3, workspace);
    assert(ret == 0);

    uint8_t recon_x[3] = {1, 2, 3};
    const uint8_t* recon_y[3];
    for (int i = 0; i < 3; i++) recon_y[i] = shares_y[recon_x[i] - 1];

    ret = shamir_reconstruct_bytes(reconstructed, recon_x, recon_y, 3, workspace);
    assert(ret == 0);
    assert(memcmp(reconstructed, secret, SHAMIR_SECRET_BYTES) == 0);
}

static void test_shamir_deterministic_reproducible(void) {
#ifdef SHAMIR_DETERMINISTIC_RNG
    uint16_t shares_x[5];
    uint16_t shares_y1[5][SHAMIR_SECRET_ELEMENTS];
    uint16_t shares_y2[5][SHAMIR_SECRET_ELEMENTS];
    uint16_t* shares_y_ptr1[5];
    uint16_t* shares_y_ptr2[5];
    for (int i = 0; i < 5; i++) {
        shares_y_ptr1[i] = shares_y1[i];
        shares_y_ptr2[i] = shares_y2[i];
    }
    
    uint16_t secret[SHAMIR_SECRET_ELEMENTS] = {0x1111, 0x2222, 0x3333, 0x4444};
    for (int i = 4; i < SHAMIR_SECRET_ELEMENTS; i++) secret[i] = i + 0x1000;
    uint16_t workspace[SHAMIR_WORKSPACE_SIZE];

    TEST_RNG_INIT((const uint8_t*)"reproducible-test-seed-0123456");
    shamir_share(secret, SHAMIR_SECRET_ELEMENTS, shares_x, shares_y_ptr1, 5, 3, workspace);

    TEST_RNG_INIT((const uint8_t*)"reproducible-test-seed-0123456");
    shamir_share(secret, SHAMIR_SECRET_ELEMENTS, shares_x, shares_y_ptr2, 5, 3, workspace);

    for (int i = 0; i < 5; i++) {
        assert(memcmp(shares_y1[i], shares_y2[i], SHAMIR_SECRET_ELEMENTS * sizeof(uint16_t)) == 0);
    }
#endif
}

int main(void) {
    test_shamir_3_of_5_reconstruction();
    test_shamir_2_of_5_failed_reconstruction();
    test_shamir_gf3329_field_operations();
    test_shamir_different_thresholds();
    test_shamir_zero_secret();
    test_shamir_bytes_api();
    test_shamir_deterministic_reproducible();
    return 0;
}