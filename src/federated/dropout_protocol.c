#include "protocol_types.h"
#include "memory_scratchpad.h"
#include "crypto_memory.h"
#include "kem_adapter.h"
#include "mask_prg.h"
#include "shamir.h"
#include <stdint.h>
#include <string.h>
#include <tinycrypt/hmac.h>

#define FIELD_MODULUS 3329
#define BARRETT_MULTIPLIER 20159
#define BARRETT_SHIFT 26
#define SHAMIR_MAX_THRESHOLD 32

static inline uint16_t barrett_reduce(uint32_t a) {
    uint32_t t = (a * BARRETT_MULTIPLIER) >> BARRETT_SHIFT;
    uint16_t r = (uint16_t)(a - t * FIELD_MODULUS);
    return r >= FIELD_MODULUS ? r - FIELD_MODULUS : r;
}

static inline uint16_t mod_q(int32_t val) {
    int32_t r = val % 3329;
    if (r < 0) r += 3329;
    return (uint16_t)r;
}

pqc_status_t dropout_protocol_derive_mask_for_recovery(const uint8_t* shamir_secret, uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint8_t peer_id, int16_t* mask, uint16_t chunk_size) {
    if (!shamir_secret || !mask) return ERR_INVALID_ARGUMENT;
    uint8_t pairwise_seed[32];
    pqc_status_t ret = kem_adapter_derive_pairwise_mask_seed(shamir_secret, client_id, peer_id, round_id, pairwise_seed);
    if (ret != PQC_SUCCESS) return ret;
    uint8_t stream_seed[32];
    ret = kem_adapter_derive_stream_mask_seed(pairwise_seed, client_id, round_id, chunk_index, stream_seed);
    if (ret != PQC_SUCCESS) return ret;
    mask_prg_ctx_t prg_ctx;
    mask_prg_init(&prg_ctx, stream_seed);
    mask_prg_get_bytes(&prg_ctx, (uint8_t*)mask, chunk_size * sizeof(int16_t));
    crypto_zeroize(stream_seed, 32);
    crypto_zeroize(pairwise_seed, 32);
    crypto_zeroize(&prg_ctx, sizeof(mask_prg_ctx_t));
    return PQC_SUCCESS;
}