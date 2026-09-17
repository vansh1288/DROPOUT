#ifndef MASK_PRG_H
#define MASK_PRG_H

#include "protocol_types.h"
#include <stdint.h>
#include <stddef.h>

typedef struct {
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

#endif