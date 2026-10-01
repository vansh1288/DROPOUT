#ifndef RANDOMBYTES_H
#define RANDOMBYTES_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Fill buffer with cryptographically secure random bytes.
 *
 * @param output Buffer to fill with random bytes
 * @param len Number of bytes to generate
 * @return 0 on success, negative error code on failure
 *         -1: RNG hardware failure or unavailable
 *         -2: Invalid arguments
 */
int randombytes(uint8_t *output, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* RANDOMBYTES_H */