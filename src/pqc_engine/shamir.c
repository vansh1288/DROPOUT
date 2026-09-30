#include "shamir.h"
#include <string.h>

#define FIELD_MODULUS 3329
#define BARRETT_MULTIPLIER 20159
#define BARRETT_SHIFT 26

static inline uint16_t barrett_reduce(uint32_t a) {
    uint32_t t = (a * BARRETT_MULTIPLIER) >> BARRETT_SHIFT;
    uint16_t r = (uint16_t)(a - t * FIELD_MODULUS);
    return (r >= FIELD_MODULUS) ? (uint16_t)(r - FIELD_MODULUS) : r;
}

uint16_t gf3329_barrett_reduce(uint32_t a) {
    return barrett_reduce(a);
}

uint16_t gf3329_add(uint16_t a, uint16_t b) {
    uint16_t r = a + b;
    if (r >= FIELD_MODULUS) r -= FIELD_MODULUS;
    return r;
}

uint16_t gf3329_sub(uint16_t a, uint16_t b) {
    if (a >= b) return a - b;
    return a + FIELD_MODULUS - b;
}

uint16_t gf3329_mul(uint16_t a, uint16_t b) {
    return barrett_reduce((uint32_t)a * b);
}

uint16_t gf3329_inv(uint16_t a) {
    if (a == 0) return 0;
    uint16_t result = 1;
    uint16_t base = a;
    int exp = FIELD_MODULUS - 2;
    while (exp > 0) {
        if (exp & 1) result = gf3329_mul(result, base);
        base = gf3329_mul(base, base);
        exp >>= 1;
    }
    return result;
}

uint16_t gf3329_evaluate_polynomial(const uint16_t* coeffs, uint8_t degree, uint16_t x) {
    uint16_t result = 0;
    for (int i = degree - 1; i >= 0; i--) {
        result = gf3329_add(gf3329_mul(result, x), coeffs[i]);
    }
    return result;
}

int shamir_share(const uint16_t* secret, uint8_t secret_elements, uint16_t* share_x, uint16_t** share_y, uint8_t n, uint8_t t, uint16_t* workspace) {
    if (!secret || !share_x || !share_y || !workspace) return -1;
    if (n < t || t == 0 || n > SHAMIR_MAX_SHARES) return -1;
    if (secret_elements > SHAMIR_SECRET_ELEMENTS) return -1;

    uint16_t* coeffs = workspace;
    uint16_t* eval_points = workspace + t * secret_elements;

    for (uint8_t elem = 0; elem < secret_elements; elem++) {
        coeffs[elem * t] = secret[elem];
        for (uint8_t i = 1; i < t; i++) {
            coeffs[elem * t + i] = (uint16_t)(rand() % FIELD_MODULUS);
        }
    }

    for (uint8_t i = 0; i < n; i++) {
        share_x[i] = i + 1;
        for (uint8_t elem = 0; elem < secret_elements; elem++) {
            share_y[i][elem] = gf3329_evaluate_polynomial(&coeffs[elem * t], t, share_x[i]);
        }
    }

    return 0;
}

int shamir_reconstruct(uint16_t* secret, const uint16_t* share_x, uint16_t** share_y, uint8_t k, uint16_t* workspace) {
    if (!secret || !share_x || !share_y || !workspace) return -1;
    if (k < 2 || k > SHAMIR_MAX_SHARES) return -1;

    uint16_t* numerators = workspace;
    uint16_t* denominators = workspace + k;

    for (uint8_t elem = 0; elem < 32; elem++) {
        for (uint8_t i = 0; i < k; i++) {
            uint16_t num = 1;
            uint16_t den = 1;
            uint16_t xi = share_x[i];
            uint16_t yi = share_y[i][elem];

            for (uint8_t j = 0; j < k; j++) {
                if (i == j) continue;
                uint16_t xj = share_x[j];
                num = gf3329_mul(num, xj);
                uint16_t diff = gf3329_sub(xi, xj);
                den = gf3329_mul(den, diff);
            }

            uint16_t lagrange = gf3329_mul(num, gf3329_inv(den));
            if (i == 0) {
                secret[elem] = gf3329_mul(yi, lagrange);
            } else {
                secret[elem] = gf3329_add(secret[elem], gf3329_mul(yi, lagrange));
            }
        }
    }

    return 0;
}

int shamir_share_bytes(const uint8_t* secret, size_t secret_len, uint8_t* share_x, uint8_t** share_y, uint8_t n, uint8_t t, uint16_t* workspace) {
    if (!secret || !share_x || !share_y || !workspace) return -1;
    if (secret_len != SHAMIR_SECRET_BYTES) return -1;
    if (n < t || t == 0 || n > SHAMIR_MAX_SHARES) return -1;

    uint16_t secret_elements[SHAMIR_SECRET_ELEMENTS];
    for (uint8_t i = 0; i < SHAMIR_SECRET_ELEMENTS; i++) {
        secret_elements[i] = (uint16_t)(secret[2*i] | (secret[2*i + 1] << 8));
    }

    uint16_t* share_x16 = (uint16_t*)share_x;
    uint16_t** share_y16 = (uint16_t**)share_y;

    int ret = shamir_share(secret_elements, SHAMIR_SECRET_ELEMENTS, share_x16, share_y16, n, t, workspace);
    return ret;
}

int shamir_reconstruct_bytes(uint8_t* secret, const uint8_t* share_x, const uint8_t** share_y, uint8_t k, uint16_t* workspace) {
    if (!secret || !share_x || !share_y || !workspace) return -1;
    if (k < 2 || k > SHAMIR_MAX_SHARES) return -1;

    uint16_t secret_elements[SHAMIR_SECRET_ELEMENTS];
    uint16_t share_x16[SHAMIR_MAX_SHARES];
    uint16_t* share_y16[SHAMIR_MAX_SHARES];

    for (uint8_t i = 0; i < k; i++) {
        share_x16[i] = share_x[i];
        share_y16[i] = (uint16_t*)share_y[i];
    }

    int ret = shamir_reconstruct(secret_elements, share_x16, share_y16, k, workspace);
    if (ret != 0) return ret;

    for (uint8_t i = 0; i < SHAMIR_SECRET_ELEMENTS; i++) {
        secret[2*i] = secret_elements[i] & 0xFF;
        secret[2*i + 1] = (secret_elements[i] >> 8) & 0xFF;
    }

    return 0;
}