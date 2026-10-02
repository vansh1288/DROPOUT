#include <assert.h>
#include <string.h>
#include "mask_prg.h"
#include <stdio.h>

static void test_mask_prg_basic(void) {
    printf("Testing mask_prg basic...\n");
    mask_prg_ctx_t ctx;
    uint8_t seed[32] = {0};
    for (int i = 0; i < 32; i++) seed[i] = i;

    int ret = mask_prg_init(&ctx, seed);
    assert(ret == 0);

    uint8_t out[64];
    ret = mask_prg_get_bytes(&ctx, out, 64);
    assert(ret == 0);

    mask_prg_cleanup(&ctx);
    printf("  PASS\n");
}

static void test_mask_prg_reseed(void) {
    printf("Testing mask_prg reseed...\n");
    mask_prg_ctx_t ctx;
    uint8_t seed1[32] = {0};
    uint8_t seed2[32] = {0};
    for (int i = 0; i < 32; i++) {
        seed1[i] = i;
        seed2[i] = i + 16;
    }

    int ret = mask_prg_init(&ctx, seed1);
    assert(ret == 0);

    uint8_t out1[32];
    ret = mask_prg_get_bytes(&ctx, out1, 32);
    assert(ret == 0);

    ret = mask_prg_reseed(&ctx, seed2);
    assert(ret == 0);

    uint8_t out2[32];
    ret = mask_prg_get_bytes(&ctx, out2, 32);
    assert(ret == 0);

    assert(memcmp(out1, out2, 32) != 0);

    ret = mask_prg_reseed(&ctx, seed1);
    assert(ret == 0);

    uint8_t out3[32];
    ret = mask_prg_get_bytes(&ctx, out3, 32);
    assert(ret == 0);

    assert(memcmp(out1, out3, 32) == 0);

    mask_prg_cleanup(&ctx);
    printf("  PASS\n");
}

static void test_mask_prg_chunked_vs_oneshot(void) {
    printf("Testing mask_prg chunked vs one-shot...\n");
    mask_prg_ctx_t ctx1, ctx2;
    uint8_t seed[32] = {0};
    for (int i = 0; i < 32; i++) seed[i] = i;

    int ret = mask_prg_init(&ctx1, seed);
    assert(ret == 0);
    ret = mask_prg_init(&ctx2, seed);
    assert(ret == 0);

    uint8_t oneshot[64];
    ret = mask_prg_get_bytes(&ctx1, oneshot, 64);
    assert(ret == 0);

    uint8_t chunked[64];
    ret = mask_prg_get_bytes(&ctx2, chunked, 32);
    assert(ret == 0);
    ret = mask_prg_get_bytes(&ctx2, chunked + 32, 32);
    assert(ret == 0);

    assert(memcmp(oneshot, chunked, 64) == 0);

    mask_prg_cleanup(&ctx1);
    mask_prg_cleanup(&ctx2);
    printf("  PASS\n");
}

static void test_mask_prg_independent_contexts(void) {
    printf("Testing mask_prg independent contexts...\n");
    mask_prg_ctx_t ctx1, ctx2;
    uint8_t seed[32] = {0};
    for (int i = 0; i < 32; i++) seed[i] = i;

    int ret = mask_prg_init(&ctx1, seed);
    assert(ret == 0);
    ret = mask_prg_init(&ctx2, seed);
    assert(ret == 0);

    uint8_t out1[32], out2[32];
    ret = mask_prg_get_bytes(&ctx1, out1, 32);
    assert(ret == 0);
    ret = mask_prg_get_bytes(&ctx2, out2, 32);
    assert(ret == 0);

    assert(memcmp(out1, out2, 32) == 0);

    uint8_t out3[32];
    ret = mask_prg_get_bytes(&ctx1, out3, 32);
    assert(ret == 0);
    ret = mask_prg_get_bytes(&ctx2, out3, 32);
    assert(ret == 0);
    assert(memcmp(out1, out2, 32) == 0);

    mask_prg_cleanup(&ctx1);
    mask_prg_cleanup(&ctx2);
    printf("  PASS\n");
}

static void test_mask_prg_error_cases(void) {
    printf("Testing mask_prg error cases...\n");
    mask_prg_ctx_t ctx;
    uint8_t seed[32] = {0};
    uint8_t out[32];

    int ret = mask_prg_init(NULL, seed);
    assert(ret == -1);

    ret = mask_prg_init(&ctx, NULL);
    assert(ret == -1);

    ret = mask_prg_init(&ctx, seed);
    assert(ret == 0);

    ret = mask_prg_get_bytes(NULL, out, 32);
    assert(ret == -1);

    ret = mask_prg_get_bytes(&ctx, NULL, 32);
    assert(ret == -1);

    ret = mask_prg_get_bytes(&ctx, out, 0);
    assert(ret == 0);

    mask_prg_ctx_t ctx2;
    ret = mask_prg_get_bytes(&ctx2, out, 32);
    assert(ret == -1);

    mask_prg_cleanup(&ctx);
    printf("  PASS\n");
}

static void test_mask_prg_boundary_lengths(void) {
    printf("Testing mask_prg boundary lengths...\n");
    uint8_t seed[32] = {0};
    for (int i = 0; i < 32; i++) seed[i] = i;

    size_t test_lengths[] = {1, 15, 16, 17, 31, 32, 33, 48, 63, 64, 65};
    size_t num_tests = sizeof(test_lengths) / sizeof(test_lengths[0]);

    for (size_t t = 0; t < num_tests; t++) {
        size_t len = test_lengths[t];
        printf("  Length %zu...\n", len);

        mask_prg_ctx_t ctx1, ctx2;
        int ret = mask_prg_init(&ctx1, seed);
        assert(ret == 0);
        ret = mask_prg_init(&ctx2, seed);
        assert(ret == 0);

        uint8_t oneshot[128];
        ret = mask_prg_get_bytes(&ctx1, oneshot, len);
        assert(ret == 0);

        uint8_t chunked[128];
        size_t chunk_size = len / 2;
        if (chunk_size == 0) chunk_size = 1;
        ret = mask_prg_get_bytes(&ctx2, chunked, chunk_size);
        assert(ret == 0);
        ret = mask_prg_get_bytes(&ctx2, chunked + chunk_size, len - chunk_size);
        assert(ret == 0);

        assert(memcmp(oneshot, chunked, len) == 0);

        mask_prg_cleanup(&ctx1);
        mask_prg_cleanup(&ctx2);
    }
    printf("  PASS\n");
}

static void test_mask_prg_nist_vector(void) {
    printf("Testing mask_prg NIST SP 800-38A vector...\n");
    /* NIST SP 800-38A Appendix F.5.1 AES-256-CTR
     * Key: 2b7e151628aed2a6abf7158809cf4f3c
     * IV:  f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff (16 bytes)
     * PT:  6bc1bee22e409f96e93d7e117393172a
     * CT:  874d6191b620e3261afe63f8a33c5e0c
     * Note: Our implementation uses zero nonce + separate counter.
     * We set the nonce to the NIST IV and counter to 0 to match. */

    mask_prg_ctx_t ctx;
    uint8_t seed[32] = {
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    };
    uint8_t expected_ct[16] = {
        0x87, 0x4d, 0x61, 0x91, 0xb6, 0x20, 0xe3, 0x26,
        0x1a, 0xfe, 0x63, 0xf8, 0xa3, 0x3c, 0x5e, 0x0c
    };
    uint8_t pt[16] = {
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
        0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a
    };
    uint8_t out[16];

    /* Manually set nonce to NIST IV since our init zeroes it */
    int ret = mask_prg_init(&ctx, seed);
    assert(ret == 0);
    uint8_t nist_iv[16] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9, 0xfa, 0xfb, 0xfc, 0xfd, 0xfe, 0xff
    };
    memcpy(ctx.nonce, nist_iv, 16);
    memset(ctx.ctr, 0, 16);
    ctx.block_offset = 0;

    uint8_t ct[16];
    ret = mask_prg_get_bytes(&ctx, ct, 16);
    assert(ret == 0);

    for (int i = 0; i < 16; i++) {
        out[i] = pt[i] ^ ct[i];
    }

    assert(memcmp(out, expected_ct, 16) == 0);

    mask_prg_cleanup(&ctx);
    printf("  PASS\n");
}

int main(void) {
    test_mask_prg_basic();
    test_mask_prg_reseed();
    test_mask_prg_chunked_vs_oneshot();
    test_mask_prg_independent_contexts();
    test_mask_prg_error_cases();
    test_mask_prg_boundary_lengths();
    test_mask_prg_nist_vector();
    printf("\nAll mask PRG tests passed!\n");
    return 0;
}