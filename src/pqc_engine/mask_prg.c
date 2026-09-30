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

void mask_prg_init(mask_prg_ctx_t* ctx, const uint8_t seed[32]) {
    if (!ctx || !seed) return;
    tc_aes256_set_encrypt_key(&ctx->sched, seed);
    memset(ctx->nonce, 0, 16);
    memset(ctx->ctr, 0, 16);
    ctx->initialized = 1;
}

void mask_prg_reseed(mask_prg_ctx_t* ctx, const uint8_t seed[32]) {
    if (!ctx || !seed) return;
    tc_aes256_set_encrypt_key(&ctx->sched, seed);
    ctr_increment(ctx->nonce);
    memset(ctx->ctr, 0, 16);
}

void mask_prg_get_bytes(mask_prg_ctx_t* ctx, uint8_t* out, size_t len) {
    if (!ctx || !ctx->initialized || !out) return;

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
}