#ifndef MASK_PRG_MOCK_H
#define MASK_PRG_MOCK_H

#include "protocol_types.h"
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t dummy[32];
    int initialized;
} mask_prg_ctx_t;

static inline int mask_prg_init(mask_prg_ctx_t* ctx, const uint8_t seed[32]) {
    if (!ctx || !seed) return -1;
    ctx->initialized = 1;
    (void)seed;
    return 0;
}

static inline int mask_prg_reseed(mask_prg_ctx_t* ctx, const uint8_t seed[32]) {
    if (!ctx || !seed) return -1;
    (void)seed;
    return 0;
}

static inline int mask_prg_get_bytes(mask_prg_ctx_t* ctx, uint8_t* out, size_t len) {
    if (!ctx || !ctx->initialized || !out) return -1;
    for (size_t i = 0; i < len; i++) {
        out[i] = (uint8_t)(i & 0xFF);
    }
    return 0;
}

static inline void mask_prg_cleanup(mask_prg_ctx_t* ctx) {
    if (!ctx) return;
    ctx->initialized = 0;
}

#endif