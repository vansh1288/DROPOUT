#include "protocol_types.h"
#include "memory_scratchpad.h"
#include "crypto_memory.h"
#include <stdint.h>
#include <string.h>

#define GF256_ELEMENTS 256
#define SHAMIR_MAX_DEGREE 32

static const uint8_t gf256_log[GF256_ELEMENTS] = {
    0, 0, 25, 1, 50, 2, 26, 198, 75, 199, 27, 104, 51, 238, 223, 3,
    100, 4, 224, 14, 52, 141, 129, 239, 76, 113, 8, 200, 248, 105, 28, 193,
    125, 194, 29, 181, 249, 185, 39, 106, 77, 228, 166, 114, 154, 201, 9, 120,
    101, 47, 138, 5, 33, 15, 225, 36, 18, 220, 142, 130, 69, 53, 147, 240,
    174, 78, 180, 229, 11, 244, 202, 148, 12, 134, 211, 10, 21, 155, 159, 94,
    161, 102, 163, 48, 19, 144, 139, 230, 6, 119, 34, 112, 16, 221, 143, 184,
    70, 131, 56, 54, 149, 66, 241, 175, 192, 79, 95, 182, 231, 115, 168, 150,
    13, 135, 191, 212, 22, 96, 156, 23, 157, 160, 97, 98, 103, 164, 49, 187,
    20, 197, 145, 188, 140, 232, 7, 128, 121, 35, 127, 118, 37, 116, 214, 17,
    222, 209, 146, 179, 71, 61, 132, 133, 57, 55, 60, 151, 67, 242, 250, 176,
    195, 80, 245, 90, 183, 233, 116, 234, 117, 169, 152, 177, 14, 189, 136, 153,
    226, 81, 213, 99, 165, 50, 170, 255, 171, 24, 203, 254, 186, 123, 111, 108,
    30, 89, 253, 190, 124, 236, 196, 167, 172, 38, 208, 237, 62, 204, 235, 63
};

static const uint8_t gf256_exp[GF256_ELEMENTS] = {
    1, 2, 4, 8, 16, 32, 64, 128, 29, 58, 116, 232, 205, 135, 19, 38,
    76, 152, 45, 90, 180, 117, 234, 201, 143, 3, 6, 12, 24, 48, 96, 192,
    157, 39, 78, 156, 37, 74, 148, 53, 106, 212, 181, 119, 238, 193, 159, 35,
    70, 140, 5, 10, 20, 40, 80, 160, 93, 186, 105, 210, 185, 111, 222, 161,
    95, 190, 97, 194, 153, 47, 94, 188, 101, 202, 137, 15, 30, 60, 120, 240,
    253, 231, 211, 187, 107, 214, 177, 127, 254, 225, 223, 163, 91, 182, 113, 226,
    217, 175, 67, 134, 17, 34, 68, 136, 13, 26, 52, 104, 208, 189, 103, 206,
    129, 31, 62, 124, 248, 237, 199, 147, 59, 118, 236, 197, 151, 51, 102, 204,
    133, 23, 46, 92, 184, 109, 218, 169, 79, 158, 33, 66, 132, 21, 42, 84,
    168, 77, 154, 41, 82, 164, 85, 170, 73, 146, 57, 114, 228, 213, 183, 115,
    230, 209, 191, 99, 198, 145, 63, 126, 252, 229, 215, 179, 123, 246, 241, 255,
    227, 219, 171, 75, 150, 49, 98, 196, 149, 55, 110, 220, 165, 87, 174, 65, 130,
    25, 50, 100, 200, 141, 7, 14, 28, 56, 112, 224, 221, 167, 83, 166, 81, 162,
    89, 178, 121, 242, 249, 239, 195, 155, 43, 86, 172, 69, 138, 9, 18, 36,
    72, 144, 61, 122, 244, 245, 247, 243, 251, 235, 203, 139, 11, 22, 44, 88,
    176, 125, 250, 233, 207, 131, 27, 54, 108, 216, 173, 71, 142, 1, 2, 4
};

static inline uint8_t gf256_mul(uint8_t a, uint8_t b) {
    if (a == 0 || b == 0) return 0;
    return gf256_exp[(gf256_log[a] + gf256_log[b]) % 255];
}

static inline uint8_t gf256_div(uint8_t a, uint8_t b) {
    if (b == 0) return 0;
    if (a == 0) return 0;
    return gf256_exp[(255 + gf256_log[a] - gf256_log[b]) % 255];

static inline uint8_t gf256_inv(uint8_t a) {
    if (a == 0) return 0;
    return gf256_exp[255 - gf256_log[a]];
}

pqc_status_t shamir_gen_polynomial(const uint8_t* secret, uint8_t threshold, uint8_t* coeffs) {
    if (!secret || !coeffs || threshold == 0 || threshold > SHAMIR_MAX_DEGREE) return ERR_INVALID_ARGUMENT;
    coeffs[0] = secret[0];
    crypto_workspace_t* ws = scratch_get_crypto_ws();
    mask_prg_init((uint8_t*)ws);
    mask_prg_expand(&coeffs[1], threshold - 1);
    crypto_zeroize(ws, sizeof(crypto_workspace_t));
    return PQC_SUCCESS;
}

pqc_status_t shamir_eval_polynomial(const uint8_t* coeffs, uint8_t threshold, uint8_t x, uint8_t* y) {
    if (!coeffs || !y || threshold == 0) return ERR_INVALID_ARGUMENT;
    uint8_t result = coeffs[0];
    uint8_t x_pow = x;
    for (uint8_t i = 1; i < threshold; i++) {
        uint8_t term = gf256_mul(coeffs[i], x_pow);
        result ^= term;
        x_pow = gf256_mul(x_pow, x);
    }
    *y = result;
    return PQC_SUCCESS;
}

pqc_status_t shamir_gen_shares(const uint8_t* secret, uint8_t threshold, uint8_t num_shares, shamir_share_t* shares) {
    if (!secret || !shares || threshold == 0 || num_shares < threshold || num_shares > SHAMIR_MAX_SHARES) return ERR_INVALID_ARGUMENT;
    if (threshold > SHAMIR_MAX_DEGREE) return ERR_INVALID_THRESHOLD;

    shamir_workspace_t* ws = scratch_get_shamir_ws();
    uint8_t* coeffs = ws->data;
    uint8_t* eval_points = &ws->data[SHAMIR_MAX_DEGREE];
    uint8_t* share_values = &ws->data[SHAMIR_MAX_DEGREE + 256];

    pqc_status_t ret = shamir_gen_polynomial(secret, threshold, coeffs);
    if (ret != PQC_SUCCESS) return ret;

    for (uint8_t i = 0; i < num_shares; i++) {
        uint8_t x = i + 1;
        eval_points[i] = x;
        ret = shamir_eval_polynomial(coeffs, threshold, x, &share_values[i]);
        if (ret != PQC_SUCCESS) return ret;
        shares[i].share_id = x;
        shares[i].value[0] = share_values[i];
        for (int j = 1; j < SHAMIR_SHARE_VALUE_BYTES; j++) {
            shares[i].value[j] = 0;
        }
    }

    crypto_zeroize(ws, sizeof(shamir_workspace_t));
    return PQC_SUCCESS;
}

pqc_status_t shamir_reconstruct_secret(const shamir_share_t* shares, uint8_t num_shares, uint8_t threshold, uint8_t* secret) {
    if (!shares || !secret || num_shares < threshold || threshold == 0) return ERR_INSUFFICIENT_SHARES;
    if (threshold > SHAMIR_MAX_DEGREE) return ERR_INVALID_THRESHOLD;

    for (uint8_t i = 0; i < num_shares; i++) {
        for (uint8_t j = i + 1; j < num_shares; j++) {
            if (shares[i].share_id == shares[j].share_id) return ERR_DUPLICATE_SHARE_ID;
        }
    }

    uint8_t result = 0;
    for (uint8_t i = 0; i < num_shares; i++) {
        if (shares[i].share_id == 0) continue;
        uint8_t xi = shares[i].share_id;
        uint8_t yi = shares[i].value[0];
        uint8_t li = 1;
        for (uint8_t j = 0; j < num_shares; j++) {
            if (i == j) continue;
            if (shares[j].share_id == 0) continue;
            uint8_t xj = shares[j].share_id;
            uint8_t num = gf256_mul(xj, li);
            uint8_t den = (xj + xi) & 0xFF;
            li = gf256_div(num, den);
        }
        result ^= gf256_mul(yi, li);
    }
    *secret = result;
    return PQC_SUCCESS;
}