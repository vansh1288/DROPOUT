#ifndef SHAMIR_H
#define SHAMIR_H

#include <stdint.h>
#include <stddef.h>

#define SHAMIR_FIELD_MODULUS 3329
#define SHAMIR_BARRETT_MULTIPLIER 20159
#define SHAMIR_BARRETT_SHIFT 26
#define SHAMIR_SECRET_ELEMENTS 32
#define SHAMIR_SECRET_BYTES (SHAMIR_SECRET_ELEMENTS * 2)
#define SHAMIR_MAX_SHARES 255
#define SHAMIR_WORKSPACE_SIZE (SHAMIR_MAX_SHARES * SHAMIR_SECRET_ELEMENTS + 256)

#ifdef __cplusplus
extern "C" {
#endif

uint16_t gf3329_barrett_reduce(uint32_t a);
uint16_t gf3329_add(uint16_t a, uint16_t b);
uint16_t gf3329_sub(uint16_t a, uint16_t b);
uint16_t gf3329_mul(uint16_t a, uint16_t b);
uint16_t gf3329_inv(uint16_t a);

uint16_t gf3329_evaluate_polynomial(const uint16_t* coeffs, uint8_t degree, uint16_t x);

int shamir_share(const uint16_t* secret, uint8_t secret_elements, uint16_t* share_x, uint16_t** share_y, uint8_t n, uint8_t t, uint16_t* workspace);
int shamir_reconstruct(uint16_t* secret, const uint16_t* share_x, uint16_t** share_y, uint8_t k, uint16_t* workspace);

int shamir_share_bytes(const uint8_t* secret, size_t secret_len, uint8_t* share_x, uint8_t** share_y, uint8_t n, uint8_t t, uint16_t* workspace);
int shamir_reconstruct_bytes(uint8_t* secret, const uint8_t* share_x, const uint8_t** share_y, uint8_t k, uint16_t* workspace);

#ifdef __cplusplus
}
#endif

#endif