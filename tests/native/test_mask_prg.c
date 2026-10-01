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

int main(void) {
    test_mask_prg_basic();
    test_mask_prg_reseed();
    test_mask_prg_chunked_vs_oneshot();
    test_mask_prg_independent_contexts();
    test_mask_prg_error_cases();
    printf("\nAll mask PRG tests passed!\n");
    return 0;
}