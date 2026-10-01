#ifndef CRYPTO_MEMORY_H
#define CRYPTO_MEMORY_H

#include "protocol_types.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

void crypto_zeroize(volatile void* ptr, size_t len);
int crypto_ct_compare(const void* a, const void* b, size_t len);
void crypto_ct_copy(void* dst, const void* src, size_t len, int condition);
void crypto_zeroize_scratchpad_region(int region);
void crypto_zeroize_all_scratchpad(void);

#ifdef __cplusplus
}
#endif

#endif