#ifndef HKDF_H
#define HKDF_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define HKDF_SHA256_MAX_OUTPUT_LEN 8192

int hkdf_sha256_extract(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t* prk);

int hkdf_sha256_expand(const uint8_t* prk, size_t prk_len, const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len);

int hkdf_sha256(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len);

#ifdef __cplusplus
}
#endif

#endif