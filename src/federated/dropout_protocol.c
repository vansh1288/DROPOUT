#include "protocol_types.h"
#include "memory_scratchpad.h"
#include "crypto_memory.h"
<<<<<<< HEAD
#include "kem_adapter.h"
#include "mask_prg.h"
#include "shamir.h"
=======
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4
#include <stdint.h>
#include <string.h>
#include <tinycrypt/hmac.h>

#define FIELD_MODULUS 3329
#define BARRETT_MULTIPLIER 20159
#define BARRETT_SHIFT 26
<<<<<<< HEAD
#define SHAMIR_MAX_THRESHOLD 32
=======
#define SHAMIR_MAX_DEGREE 32
#define SHAMIR_SHARE_VALUE_BYTES 32
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4

static inline uint16_t barrett_reduce(uint32_t a) {
    uint32_t t = (a * BARRETT_MULTIPLIER) >> BARRETT_SHIFT;
    uint16_t r = (uint16_t)(a - t * FIELD_MODULUS);
    return r >= FIELD_MODULUS ? r - FIELD_MODULUS : r;
}
<<<<<<< HEAD

=======
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4
static inline uint16_t mod_q(int32_t val) {
    int32_t r = val % 3329;
    if (r < 0) r += 3329;
    return (uint16_t)r;
}

<<<<<<< HEAD
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
=======
static void hkdf_expand_shamir(const uint8_t* secret, uint16_t* coeffs, uint8_t threshold) {
    uint8_t prk[32];
    uint8_t okm[32 * 32];
    uint8_t info[1] = {0};
    uint8_t zero_salt[32] = {0};
    struct tc_hmac_state_struct hmac;
    tc_hmac_set_key(&hmac, zero_salt, 32);
    tc_hmac_init(&hmac);
    tc_hmac_update(&hmac, secret, 32);
    tc_hmac_final(prk, 32, &hmac);
    uint8_t t[32];
    size_t t_len = 0;
    uint8_t ctr = 1;
    uint8_t* out = okm;
    size_t remaining = 32 * 32;
    tc_hmac_set_key(&hmac, prk, 32);
    while (remaining > 0) {
        tc_hmac_init(&hmac);
        if (t_len) tc_hmac_update(&hmac, t, t_len);
        tc_hmac_update(&hmac, info, 1);
        tc_hmac_update(&hmac, &ctr, 1);
        tc_hmac_final(t, 32, &hmac);
        t_len = 32;
        size_t chunk = remaining < 32 ? remaining : 32;
        for (size_t i = 0; i < chunk; i++) out[i] = t[i];
        out += chunk;
        remaining -= chunk;
        ctr++;
    }
    for (uint8_t i = 0; i < threshold; i++) {
        for (int j = 0; j < 32; j++) {
            uint16_t val = (uint16_t)(okm[i * 32 + j] | (okm[i * 32 + j + 1] << 8));
            coeffs[i * 32 + j] = mod_q(val);
        }
    }
    crypto_zeroize(prk, 32);
    crypto_zeroize(okm, 32 * 32);
    crypto_zeroize(t, 32);
}


static inline uint16_t gf3329_add(uint16_t a, uint16_t b) {
    uint16_t r = a + b;
    if (r >= FIELD_MODULUS) r -= FIELD_MODULUS;
    return r;
}

static inline uint16_t gf3329_sub(uint16_t a, uint16_t b) {
    return a >= b ? a - b : a + FIELD_MODULUS - b;
}

static inline uint16_t gf3329_mul(uint16_t a, uint16_t b) {
    return barrett_reduce((uint32_t)a * b);
}

static inline uint16_t gf3329_inv(uint16_t a) {
    uint32_t r = 1;
    uint32_t e = FIELD_MODULUS - 2;
    uint32_t base = a;
    while (e) {
        if (e & 1) r = barrett_reduce(r * base);
        base = barrett_reduce(base * base);
        e >>= 1;
    }
    return (uint16_t)r;
}

static void poly_eval(const uint16_t* coeffs, uint8_t threshold, uint16_t x, uint16_t* result) {
    uint16_t res = coeffs[0];
    uint16_t x_pow = x;
    for (uint8_t i = 1; i < threshold; i++) {
        uint16_t term = gf3329_mul(coeffs[i], x_pow);
        res = gf3329_add(res, term);
        x_pow = gf3329_mul(x_pow, x);
    }
    *result = res;
}

pqc_status_t shamir_gen_polynomial(const uint8_t* secret, uint8_t threshold, uint16_t* coeffs) {
    if (!secret || !coeffs || threshold == 0 || threshold > 32) return ERR_INVALID_ARGUMENT;
    crypto_workspace_t* ws = scratch_get_crypto_ws();
    hkdf_expand_shamir(secret, coeffs, threshold);
    crypto_zeroize(ws, sizeof(crypto_workspace_t));
    return PQC_SUCCESS;
}

pqc_status_t shamir_eval_polynomial(const uint16_t* coeffs, uint8_t threshold, uint16_t x, uint8_t* y) {
    if (!coeffs || !y || threshold == 0) return ERR_INVALID_ARGUMENT;
    for (int j = 0; j < 32; j++) {
        const uint16_t* coeffs_j = &coeffs[j];
        poly_eval(coeffs_j, threshold, x, &y[j]);
    }
    return PQC_SUCCESS;
}

pqc_status_t shamir_gen_shares(const uint8_t* secret, uint8_t threshold, uint8_t num_shares, shamir_share_t* shares) {
    if (!secret || !shares || threshold == 0 || num_shares < threshold || num_shares > 255) return ERR_INVALID_ARGUMENT;
    if (threshold > 32) return ERR_INVALID_THRESHOLD;

    shamir_workspace_t* ws = scratch_get_shamir_ws();
    uint16_t* coeffs = (uint16_t*)ws->data;
    uint16_t* eval_points = (uint16_t*)&ws->data[32 * 32 * 2];
    uint8_t* share_values = &ws->data[32 * 32 * 2 + 256 * 2];

    pqc_status_t ret = shamir_gen_polynomial(secret, threshold, coeffs);
    if (ret != PQC_SUCCESS) return ret;

    for (uint8_t i = 0; i < num_shares; i++) {
        uint16_t x = i + 1;
        eval_points[i] = x;
        ret = shamir_eval_polynomial(coeffs, threshold, x, share_values + i * 32);
        if (ret != PQC_SUCCESS) return ret;
        shares[i].share_id = x;
        memcpy(shares[i].value, share_values + i * 32, 32);
    }

    crypto_zeroize(ws, sizeof(shamir_workspace_t));
    return PQC_SUCCESS;
}

pqc_status_t shamir_reconstruct_secret(const shamir_share_t* shares, uint8_t num_shares, uint8_t threshold, uint8_t* secret) {
    if (!shares || !secret || num_shares < threshold || threshold == 0) return ERR_INSUFFICIENT_SHARES;
    if (threshold > 32) return ERR_INVALID_THRESHOLD;

    for (uint8_t i = 0; i < threshold; i++) {
        for (uint8_t j = i + 1; j < threshold; j++) {
            if (shares[i].share_id == shares[j].share_id) return ERR_DUPLICATE_SHARE_ID;
        }
    }

    for (int j = 0; j < 32; j++) {
        uint16_t result = 0;
        for (uint8_t i = 0; i < threshold; i++) {
            if (shares[i].share_id == 0) continue;
            uint16_t xi = shares[i].share_id;
            uint16_t yi = shares[i].value[j];
            uint16_t li = 1;
            for (uint8_t k = 0; k < threshold; k++) {
                if (i == k) continue;
                if (shares[k].share_id == 0) continue;
                uint16_t xk = shares[k].share_id;
                uint16_t num = xk;
                uint16_t den = gf3329_sub(xk, xi);
                li = gf3329_mul(li, gf3329_mul(num, gf3329_inv(den)));
            }
            result = gf3329_add(result, gf3329_mul(yi, li));
        }
        secret[j] = (uint8_t)result;
    }
    return PQC_SUCCESS;
}
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4
