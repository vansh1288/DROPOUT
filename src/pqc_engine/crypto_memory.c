#include "memory_scratchpad.h"
#include "protocol_types.h"
#include <string.h>

void crypto_zeroize(volatile void* ptr, size_t len) {
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (len--) {
        *p++ = 0;
    }
}

int crypto_ct_compare(const void* a, const void* b, size_t len) {
    const volatile uint8_t* pa = (const volatile uint8_t*)a;
    const volatile uint8_t* pb = (const volatile uint8_t*)b;
    uint8_t diff = 0;
    while (len--) {
        diff |= *pa++ ^ *pb++;
    }
    return (int)diff;
}

void crypto_ct_copy(void* dst, const void* src, size_t len, int condition) {
    uint8_t* d = (uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;
    uint8_t mask = (uint8_t)(-condition);
    while (len--) {
        *d = (*d & ~mask) | (*s & mask);
        d++;
        s++;
    }
}

void crypto_zeroize_scratchpad_region(scratch_region_t region) {
    scratch_zeroize_region(region);
}

void crypto_zeroize_all_scratchpad(void) {
    scratch_zeroize_all();
}
