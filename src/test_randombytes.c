#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "randombytes.h"

static void test_randombytes_basic(void) {
    uint8_t buf[64];
    int ret = randombytes(buf, sizeof(buf));
    assert(ret == 0);
    // Verify not all zeros (extremely unlikely for CSPRNG)
    int all_zero = 1;
    for (size_t i = 0; i < sizeof(buf); i++) {
        if (buf[i] != 0) { all_zero = 0; break; }
    }
    assert(!all_zero);
    printf("test_randombytes_basic: PASS\n");
}

static void test_randombytes_different_calls(void) {
    uint8_t buf1[32], buf2[32];
    int ret1 = randombytes(buf1, sizeof(buf1));
    int ret2 = randombytes(buf2, sizeof(buf2));
    assert(ret1 == 0);
    assert(ret2 == 0);
    // Very unlikely to be equal
    assert(memcmp(buf1, buf2, 32) != 0);
    printf("test_randombytes_different_calls: PASS\n");
}

static void test_randombytes_null_buffer(void) {
    int ret = randombytes(NULL, 32);
    assert(ret == -2);
    printf("test_randombytes_null_buffer: PASS\n");
}

static void test_randombytes_zero_length(void) {
    uint8_t buf[32];
    int ret = randombytes(buf, 0);
    assert(ret == 0);
    printf("test_randombytes_zero_length: PASS\n");
}

static void test_randombytes_various_sizes(void) {
    for (size_t i = 1; i <= 100; i++) {
        uint8_t buf[100];
        int ret = randombytes(buf, i);
        assert(ret == 0);
    }
    printf("test_randombytes_various_sizes: PASS\n");
}

static void test_randombytes_deterministic_test(void) {
#if defined(SHAMIR_DETERMINISTIC_RNG) || defined(RANDOMBYTES_DETERMINISTIC_TEST)
    uint8_t buf1[32], buf2[32];
    extern void shamir_test_rng_init(const uint8_t seed[48]);
    uint8_t seed[48] = {0x01, 0x02, 0x03, 0x04};
    shamir_test_rng_init(seed);
    int ret1 = randombytes(buf1, 32);
    assert(ret1 == 0);
    shamir_test_rng_init(seed);
    int ret2 = randombytes(buf2, 32);
    assert(ret2 == 0);
    assert(memcmp(buf1, buf2, 32) == 0);
    printf("test_randombytes_deterministic_test: PASS\n");
#else
    printf("test_randombytes_deterministic_test: SKIPPED (not test build)\n");
#endif
}

int main(void) {
    printf("Running randombytes tests...\n");
    test_randombytes_basic();
    test_randombytes_different_calls();
    test_randombytes_null_buffer();
    test_randombytes_zero_length();
    test_randombytes_various_sizes();
    test_randombytes_deterministic_test();
    printf("\nAll randombytes tests PASSED\n");
    return 0;
}