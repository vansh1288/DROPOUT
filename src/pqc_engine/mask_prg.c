#include "mask_prg.h"
#include <tinycrypt/aes.h>
#include <tinycrypt/ctr_mode.h>
#include <string.h>

static void ctr_increment(uint8_t ctr[16]) {
    for (int i = 15; i >= 0; i--) {
        ctr[i]++;
        if (ctr[i] != 0) break;
    }
}

int mask_prg_init(mask_prg_ctx_t* ctx, const uint8_t seed[32]) {
    if (!ctx || !seed) return -1;
    tc_aes256_set_encrypt_key(&ctx->sched, seed);
    memset(ctx->nonce, 0, 16);
    memset(ctx->ctr, 0, 16);
    ctx->initialized = 1;
    return 0;
}

int mask_prg_reseed(mask_prg_ctx_t* ctx, const uint8_t seed[32]) {
    if (!ctx || !seed) return -1;
    tc_aes256_set_encrypt_key(&ctx->sched, seed);
    ctr_increment(ctx->nonce);
    memset(ctx->ctr, 0, 16);
    return 0;
}

int mask_prg_get_bytes(mask_prg_ctx_t* ctx, uint8_t* out, size_t len) {
    if (!ctx || !ctx->initialized || !out) return -1;

    size_t generated = 0;
    while (generated < len) {
        size_t chunk = len - generated;
        if (chunk > 16) chunk = 16;

        tc_ctr_mode(out + generated, chunk, ctx->nonce, ctx->ctr, &ctx->sched);
        generated += chunk;

        if (generated < len) {
            ctr_increment(ctx->ctr);
        }
    }
    return 0;
}

void mask_prg_cleanup(mask_prg_ctx_t* ctx) {
    if (!ctx) return;
    crypto_zeroize(&ctx->sched, sizeof(ctx->sched));
    crypto_zeroize(ctx->nonce, sizeof(ctx->nonce));
    crypto_zeroize(ctx->ctr, sizeof(ctx->ctr));
    ctx->initialized = 0;
}