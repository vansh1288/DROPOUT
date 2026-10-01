#ifndef MASK_PRG_H
#define MASK_PRG_H

#include "protocol_types.h"
#include <stdint.h>
#include <stddef.h>

typedef struct {
<<<<<<< HEAD
    struct tc_aes_key_sched_struct sched;
    uint8_t nonce[16];
    uint8_t ctr[16];
    int initialized;
} mask_prg_ctx_t;

void mask_prg_init(mask_prg_ctx_t* ctx, const uint8_t seed[32]);
void mask_prg_reseed(mask_prg_ctx_t* ctx, const uint8_t seed[32]);
void mask_prg_get_bytes(mask_prg_ctx_t* ctx, uint8_t* out, size_t len);

/* Backward-compatible simple API for legacy callers */
void mask_prg_simple_init(const uint8_t seed[32]);
void mask_prg_simple_expand(uint8_t* out, size_t len);

/* Cleanup function to zeroize sensitive context material */
void mask_prg_cleanup(mask_prg_ctx_t* ctx);

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif
=======
    uint8_t key[32];
    uint8_t nonce[16];
    uint32_t counter;
    uint8_t block[16];
    size_t block_pos;
} mask_prg_ctx_t;

void mask_prg_init(const uint8_t seed[32]);
void mask_prg_reseed(const uint8_t seed[32]);
void mask_prg_expand(uint8_t* out, size_t len);
void mask_prg_get_bytes(uint8_t* out, size_t len);
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4

#endif