#ifndef MASK_PRG_H
#define MASK_PRG_H

#include "protocol_types.h"
#include <stdint.h>
#include <stddef.h>

typedef struct {
    struct tc_aes_key_sched_struct sched;
    uint8_t nonce[16];
    uint8_t ctr[16];
    int initialized;
} mask_prg_ctx_t;

int mask_prg_init(mask_prg_ctx_t* ctx, const uint8_t seed[32]);
int mask_prg_reseed(mask_prg_ctx_t* ctx, const uint8_t seed[32]);
int mask_prg_get_bytes(mask_prg_ctx_t* ctx, uint8_t* out, size_t len);
void mask_prg_cleanup(mask_prg_ctx_t* ctx);

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif