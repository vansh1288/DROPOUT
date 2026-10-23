#ifndef MASK_PRG_H
#define MASK_PRG_H

#include "protocol_types.h"
#include <stdint.h>
#include <stddef.h>

/**
 * Mask PRG Context for AES-256-CTR pseudorandom generation
 * 
 * Counter format (little-endian, 128-bit):
 * - ctx.ctr[0..15]: block counter, incremented after each 16-byte block
 * - ctx.nonce[0..15]: per-context nonce, incremented on reseed
 * - ctx.block_offset: bytes consumed from current block (0-15)
 * 
 * Stream generation: AES-256-CTR(nonce || counter) where:
 *   - nonce is fixed per context (set at init, advanced on reseed)
 *   - counter starts at 0, increments per 16-byte block
 *   - Partial block reads track offset for multi-call continuity
 * 
 * Thread safety: NOT thread-safe. Each context must be used by a single thread.
 */
typedef struct {
    struct tc_aes_key_sched_struct sched;
    uint8_t nonce[16];
    uint8_t ctr[16];
    int initialized;
    size_t block_offset;
} mask_prg_ctx_t;

/**
 * Initialize PRG with 32-byte seed (AES-256 key)
 * Sets nonce=0, counter=0, block_offset=0
 * @param ctx Context to initialize
 * @param seed 32-byte seed (key)
 * @return 0 on success, -1 on error
 */
int mask_prg_init(mask_prg_ctx_t* ctx, const uint8_t seed[32]);

/**
 * Reseed PRG with new key
 * Advances nonce, resets counter=0, block_offset=0
 * @param ctx Context to reseed
 * @param seed 32-byte seed (new key)
 * @return 0 on success, -1 on error
 */
int mask_prg_reseed(mask_prg_ctx_t* ctx, const uint8_t seed[32]);

/**
 * Generate pseudorandom bytes
 * Maintains stream continuity across multiple calls
 * @param ctx Initialized context
 * @param out Output buffer
 * @param len Number of bytes to generate
 * @return 0 on success, -1 on error
 */
int mask_prg_get_bytes(mask_prg_ctx_t* ctx, uint8_t* out, size_t len);

/**
 * Zeroize all sensitive state in context
 * @param ctx Context to clean up
 */
void mask_prg_cleanup(mask_prg_ctx_t* ctx);

#ifdef __cplusplus
extern "C" {
#endif

#ifdef __cplusplus
}
#endif

#endif