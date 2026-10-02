
#include "shamir.h"

#include <string.h>

/*
 * Canonical Shamir implementation over GF(3329).
 *
 * Secret representation:
 *   SHAMIR_SECRET_ELEMENTS uint16_t field elements.
 *
 * Byte representation:
 *   Each field element is encoded as two little-endian bytes.
 *
 * Shares:
 *   x coordinates are unique, nonzero field elements.
 *   y coordinates are field elements in [0, 3328].
 *
 * IMPORTANT:
 *   This module provides arithmetic and sharing primitives.
 *   Callers must provide cryptographically secure randombytes().
 */

#define FIELD_MODULUS SHAMIR_FIELD_MODULUS

extern int randombytes(uint8_t *output, size_t n);

#if defined(SHAMIR_DETERMINISTIC_RNG)
static uint8_t g_test_rng_seed[48] = {0};
static size_t g_test_rng_pos = 0;

static int test_randombytes(uint8_t *output, size_t n)
{
    if (output == NULL && n != 0) {
        return -1;
    }

    for (size_t i = 0; i < n; i++) {
        output[i] =
            g_test_rng_seed[g_test_rng_pos++ % sizeof(g_test_rng_seed)];
    }

    return 0;
}

#define RNG_FUNC test_randombytes

void shamir_test_rng_init(const uint8_t seed[48])
{
    if (seed != NULL) {
        memcpy(g_test_rng_seed, seed, sizeof(g_test_rng_seed));
    } else {
        memset(g_test_rng_seed, 0, sizeof(g_test_rng_seed));
    }

    g_test_rng_pos = 0;
}
#else
#define RNG_FUNC randombytes
#endif

static void secure_clear(void *ptr, size_t len)
{
    volatile uint8_t *p = (volatile uint8_t *)ptr;

    if (p == NULL) {
        return;
    }

    while (len-- != 0) {
        *p++ = 0;
    }
}

static int valid_field_element(uint16_t x)
{
    return x < FIELD_MODULUS;
}

/*
 * Barrett reduction for the range of inputs used here.
 * The largest multiplication is (3328 * 3328), which fits uint32_t.
 */
static inline uint16_t barrett_reduce(uint32_t a)
{
    uint32_t t =
        (a * SHAMIR_BARRETT_MULTIPLIER) >>
        SHAMIR_BARRETT_SHIFT;

    uint32_t r = a - t * FIELD_MODULUS;

    if (r >= FIELD_MODULUS) {
        r -= FIELD_MODULUS;
    }

    if (r >= FIELD_MODULUS) {
        r -= FIELD_MODULUS;
    }

    return (uint16_t)r;
}

uint16_t gf3329_barrett_reduce(uint32_t a)
{
    return barrett_reduce(a);
}

uint16_t gf3329_add(uint16_t a, uint16_t b)
{
    uint32_t r = (uint32_t)a + b;

    if (r >= FIELD_MODULUS) {
        r -= FIELD_MODULUS;
    }

    return (uint16_t)r;
}

uint16_t gf3329_sub(uint16_t a, uint16_t b)
{
    if (a >= b) {
        return (uint16_t)(a - b);
    }

    return (uint16_t)((uint32_t)a + FIELD_MODULUS - b);
}

uint16_t gf3329_mul(uint16_t a, uint16_t b)
{
    return barrett_reduce((uint32_t)a * b);
}

uint16_t gf3329_inv(uint16_t a)
{
    if (!valid_field_element(a) || a == 0) {
        return 0;
    }

    /* Fermat's little theorem: a^(q-2) mod q */
    uint16_t result = 1;
    uint16_t base = a;
    uint32_t exponent = FIELD_MODULUS - 2;

    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            result = gf3329_mul(result, base);
        }

        base = gf3329_mul(base, base);
        exponent >>= 1;
    }

    return result;
}

uint16_t gf3329_evaluate_polynomial(
    const uint16_t *coeffs,
    uint8_t degree,
    uint16_t x)
{
    if (coeffs == NULL || degree == 0 ||
        !valid_field_element(x)) {
        return 0;
    }

    uint16_t result = 0;

    /* Horner evaluation, coefficients stored low degree first. */
    for (int i = (int)degree - 1; i >= 0; i--) {
        if (!valid_field_element(coeffs[i])) {
            return 0;
        }

        result = gf3329_add(
            gf3329_mul(result, x),
            coeffs[i]);
    }

    return result;
}

/*
 * Generate uniformly distributed field elements using rejection
 * sampling. This avoids the modulo bias of random_value % 3329.
 *
 * Returns 0 on success, negative on failure.
 */
static int random_field_element(uint16_t *out)
{
    if (out == NULL) {
        return -1;
    }

    uint8_t buffer[2];

    /*
     * 3329 divides neither 65536 nor a convenient power of two.
     * Reject values >= floor(65536 / 3329) * 3329 = 63251.
     */
    const uint32_t limit =
        (65536U / FIELD_MODULUS) * FIELD_MODULUS;

    for (unsigned attempt = 0; attempt < 256; attempt++) {
        if (RNG_FUNC(buffer, sizeof(buffer)) != 0) {
            secure_clear(buffer, sizeof(buffer));
            return -2;
        }

        uint32_t value =
            (uint32_t)buffer[0] |
            ((uint32_t)buffer[1] << 8);

        if (value < limit) {
            *out = (uint16_t)(value % FIELD_MODULUS);
            secure_clear(buffer, sizeof(buffer));
            return 0;
        }
    }

    secure_clear(buffer, sizeof(buffer));
    return -3;
}

static int validate_sharing_args(
    const uint16_t *secret,
    uint8_t secret_elements,
    const uint16_t *share_x,
    uint16_t **share_y,
    uint8_t n,
    uint8_t t,
    const uint16_t *workspace)
{
    if (secret == NULL || share_x == NULL ||
        share_y == NULL || workspace == NULL) {
        return -1;
    }

    if (secret_elements == 0 ||
        secret_elements > SHAMIR_SECRET_ELEMENTS) {
        return -1;
    }

    if (t == 0 || n < t || n > SHAMIR_MAX_SHARES) {
        return -1;
    }

    if (t > n || t > FIELD_MODULUS - 1) {
        return -1;
    }

    for (uint8_t i = 0; i < n; i++) {
        if (share_y[i] == NULL) {
            return -1;
        }
    }

    for (uint8_t i = 0; i < secret_elements; i++) {
        if (!valid_field_element(secret[i])) {
            return -1;
        }
    }

    return 0;
}

static int validate_reconstruction_args(
    const uint16_t *share_x,
    uint16_t **share_y,
    uint8_t k,
    const uint16_t *workspace)
{
    if (share_x == NULL || share_y == NULL ||
        workspace == NULL) {
        return -1;
    }

    if (k < 2 || k > SHAMIR_MAX_SHARES) {
        return -1;
    }

    for (uint8_t i = 0; i < k; i++) {
        if (share_y[i] == NULL ||
            !valid_field_element(share_x[i]) ||
            share_x[i] == 0) {
            return -1;
        }

        for (uint8_t j = i + 1; j < k; j++) {
            if (share_x[i] == share_x[j]) {
                return -1;
            }
        }
    }

    return 0;
}

int shamir_share(
    const uint16_t *secret,
    uint8_t secret_elements,
    uint16_t *share_x,
    uint16_t **share_y,
    uint8_t n,
    uint8_t t,
    uint16_t *workspace)
{
    int rc = validate_sharing_args(
        secret, secret_elements, share_x,
        share_y, n, t, workspace);

    if (rc != 0) {
        return rc;
    }

    /*
     * Workspace layout:
     *   t * secret_elements coefficients
     *   Remaining space reserved by the public workspace contract.
     *
     * Coefficients for each secret element occupy one contiguous
     * block of t field elements.
     */
    size_t coeff_count = (size_t)t * secret_elements;

    if (coeff_count > SHAMIR_WORKSPACE_SIZE) {
        return -1;
    }

    memset(workspace, 0,
           SHAMIR_WORKSPACE_SIZE * sizeof(uint16_t));

    /* Validate caller-provided x coordinates for uniqueness. */
    for (uint8_t i = 0; i < n; i++) {
        if (share_x[i] == 0 ||
            !valid_field_element(share_x[i])) {
            rc = -1;
            goto cleanup;
        }

        for (uint8_t j = 0; j < i; j++) {
            if (share_x[i] == share_x[j]) {
                rc = -1;
                goto cleanup;
            }
        }
    }

    /*
     * Generate a fresh random polynomial for every secret element.
     * The constant coefficient is the secret field element.
     */
    for (uint8_t elem = 0; elem < secret_elements; elem++) {
        uint16_t *coeffs = &workspace[(size_t)elem * t];

        coeffs[0] = secret[elem];

        for (uint8_t degree = 1; degree < t; degree++) {
            rc = random_field_element(&coeffs[degree]);

            if (rc != 0) {
                goto cleanup;
            }
        }
    }

    /* Evaluate every polynomial at every participant x coordinate. */
    for (uint8_t i = 0; i < n; i++) {
        for (uint8_t elem = 0; elem < secret_elements; elem++) {
            const uint16_t *coeffs =
                &workspace[(size_t)elem * t];

            share_y[i][elem] =
                gf3329_evaluate_polynomial(
                    coeffs, t, share_x[i]);
        }
    }

    rc = 0;

cleanup:
    secure_clear(
        workspace,
        SHAMIR_WORKSPACE_SIZE * sizeof(uint16_t));

    if (rc != 0) {
        for (uint8_t i = 0; i < n; i++) {
            if (share_y[i] != NULL) {
                secure_clear(
                    share_y[i],
                    (size_t)secret_elements * sizeof(uint16_t));
            }
        }
    }

    return rc;
}

int shamir_reconstruct(
    uint16_t *secret,
    const uint16_t *share_x,
    uint16_t **share_y,
    uint8_t k,
    uint16_t *workspace)
{
    if (secret == NULL) {
        return -1;
    }

    int rc = validate_reconstruction_args(
        share_x, share_y, k, workspace);

    if (rc != 0) {
        return rc;
    }

    /*
     * The public reconstruction API reconstructs the fixed
     * SHAMIR_SECRET_ELEMENTS secret representation.
     *
     * Workspace is used to store Lagrange coefficients.
     */
    if (k > SHAMIR_WORKSPACE_SIZE) {
        return -1;
    }

    memset(workspace, 0,
           SHAMIR_WORKSPACE_SIZE * sizeof(uint16_t));
    memset(secret, 0,
           SHAMIR_SECRET_ELEMENTS * sizeof(uint16_t));

    /* Validate all share values before modifying the output. */
    for (uint8_t i = 0; i < k; i++) {
        for (uint8_t elem = 0;
             elem < SHAMIR_SECRET_ELEMENTS;
             elem++) {
            if (!valid_field_element(share_y[i][elem])) {
                rc = -1;
                goto cleanup;
            }
        }
    }

    /*
     * Compute Lagrange basis coefficients at x = 0:
     *
     *   L_i(0) = product(j != i)(-x_j) /
     *            product(j != i)(x_i - x_j)
     *
     * All operations are in GF(3329).
     */
    for (uint8_t i = 0; i < k; i++) {
        uint16_t numerator = 1;
        uint16_t denominator = 1;

        for (uint8_t j = 0; j < k; j++) {
            if (i == j) {
                continue;
            }

            numerator = gf3329_mul(
                numerator,
                gf3329_sub(0, share_x[j]));

            denominator = gf3329_mul(
                denominator,
                gf3329_sub(share_x[i], share_x[j]));
        }

        if (denominator == 0) {
            rc = -1;
            goto cleanup;
        }

        uint16_t inverse = gf3329_inv(denominator);

        if (inverse == 0) {
            rc = -1;
            goto cleanup;
        }

        workspace[i] =
            gf3329_mul(numerator, inverse);
    }

    /* Reconstruct each secret field element. */
    for (uint8_t elem = 0;
         elem < SHAMIR_SECRET_ELEMENTS;
         elem++) {
        uint16_t value = 0;

        for (uint8_t i = 0; i < k; i++) {
            value = gf3329_add(
                value,
                gf3329_mul(
                    share_y[i][elem],
                    workspace[i]));
        }

        secret[elem] = value;
    }

    rc = 0;

cleanup:
    secure_clear(
        workspace,
        SHAMIR_WORKSPACE_SIZE * sizeof(uint16_t));

    if (rc != 0) {
        secure_clear(
            secret,
            SHAMIR_SECRET_ELEMENTS * sizeof(uint16_t));
    }

    return rc;
}

/*
 * Byte-level interface.
 *
 * This implementation deliberately does not cast byte pointers
 * to uint16_t pointers. It performs explicit little-endian
 * conversion, avoiding alignment and aliasing assumptions.
 *
 * Caller-provided share_y[i] must point to at least
 * SHAMIR_SECRET_BYTES writable bytes for each share.
 */
int shamir_share_bytes(
    const uint8_t *secret,
    size_t secret_len,
    uint8_t *share_x,
    uint8_t **share_y,
    uint8_t n,
    uint8_t t,
    uint16_t *workspace)
{
    if (secret == NULL || share_x == NULL ||
        share_y == NULL || workspace == NULL) {
        return -1;
    }

    if (secret_len != SHAMIR_SECRET_BYTES ||
        t == 0 || n < t || n > SHAMIR_MAX_SHARES) {
        return -1;
    }

    for (uint8_t i = 0; i < n; i++) {
        if (share_y[i] == NULL) {
            return -1;
        }
    }

    uint16_t secret_elements[SHAMIR_SECRET_ELEMENTS];
    uint16_t x_coordinates[SHAMIR_MAX_SHARES];

    uint16_t *y_rows[SHAMIR_MAX_SHARES];

    /*
     * The caller's workspace holds the actual y-coordinate
     * rows for byte-oriented sharing.
     */
    size_t row_elements =
        (size_t)n * SHAMIR_SECRET_ELEMENTS;

    if (row_elements > SHAMIR_WORKSPACE_SIZE) {
        return -1;
    }

    for (uint8_t i = 0; i < SHAMIR_SECRET_ELEMENTS; i++) {
        secret_elements[i] =
            (uint16_t)secret[2U * i] |
            ((uint16_t)secret[2U * i + 1U] << 8);

        if (!valid_field_element(secret_elements[i])) {
            secure_clear(secret_elements, sizeof(secret_elements));
            return -1;
        }
    }

    memset(workspace, 0,
           SHAMIR_WORKSPACE_SIZE * sizeof(uint16_t));

    for (uint8_t i = 0; i < n; i++) {
        x_coordinates[i] = (uint16_t)i + 1U;
        y_rows[i] =
            &workspace[(size_t)i * SHAMIR_SECRET_ELEMENTS];
    }

    int rc = shamir_share(
        secret_elements,
        SHAMIR_SECRET_ELEMENTS,
        x_coordinates,
        y_rows,
        n,
        t,
        workspace + row_elements);

    if (rc != 0) {
        secure_clear(secret_elements, sizeof(secret_elements));
        secure_clear(x_coordinates, sizeof(x_coordinates));
        secure_clear(y_rows, sizeof(y_rows));
        secure_clear(workspace,
                     SHAMIR_WORKSPACE_SIZE * sizeof(uint16_t));
        return rc;
    }

    for (uint8_t i = 0; i < n; i++) {
        share_x[i] = (uint8_t)x_coordinates[i];

        for (uint8_t elem = 0;
             elem < SHAMIR_SECRET_ELEMENTS;
             elem++) {
            uint16_t value = y_rows[i][elem];

            share_y[i][2U * elem] =
                (uint8_t)(value & 0xFFU);

            share_y[i][2U * elem + 1U] =
                (uint8_t)(value >> 8);
        }
    }

    secure_clear(secret_elements, sizeof(secret_elements));
    secure_clear(x_coordinates, sizeof(x_coordinates));
    secure_clear(y_rows, sizeof(y_rows));
    secure_clear(workspace,
                 SHAMIR_WORKSPACE_SIZE * sizeof(uint16_t));

    return 0;
}

int shamir_reconstruct_bytes(
    uint8_t *secret,
    const uint8_t *share_x,
    const uint8_t **share_y,
    uint8_t k,
    uint16_t *workspace)
{
    if (secret == NULL || share_x == NULL ||
        share_y == NULL || workspace == NULL) {
        return -1;
    }

    if (k < 2 || k > SHAMIR_MAX_SHARES) {
        return -1;
    }

    uint16_t x_coordinates[SHAMIR_MAX_SHARES];
    uint16_t y_storage[
        SHAMIR_MAX_SHARES * SHAMIR_SECRET_ELEMENTS];

    uint16_t *y_rows[SHAMIR_MAX_SHARES];
    uint16_t secret_elements[SHAMIR_SECRET_ELEMENTS];

    memset(y_storage, 0, sizeof(y_storage));
    memset(secret_elements, 0, sizeof(secret_elements));

    int rc = 0;

    for (uint8_t i = 0; i < k; i++) {
        if (share_y[i] == NULL || share_x[i] == 0) {
            rc = -1;
            goto cleanup;
        }

        x_coordinates[i] = share_x[i];

        y_rows[i] =
            &y_storage[(size_t)i * SHAMIR_SECRET_ELEMENTS];

        for (uint8_t elem = 0;
             elem < SHAMIR_SECRET_ELEMENTS;
             elem++) {
            uint16_t value =
                (uint16_t)share_y[i][2U * elem] |
                ((uint16_t)share_y[i][2U * elem + 1U] << 8);

            if (!valid_field_element(value)) {
                rc = -1;
                goto cleanup;
            }

            y_rows[i][elem] = value;
        }
    }

    rc = shamir_reconstruct(
        secret_elements,
        x_coordinates,
        y_rows,
        k,
        workspace);

    if (rc != 0) {
        goto cleanup;
    }

    for (uint8_t elem = 0;
         elem < SHAMIR_SECRET_ELEMENTS;
         elem++) {
        secret[2U * elem] =
            (uint8_t)(secret_elements[elem] & 0xFFU);

        secret[2U * elem + 1U] =
            (uint8_t)(secret_elements[elem] >> 8);
    }

cleanup:
    if (rc != 0) {
        secure_clear(secret, SHAMIR_SECRET_BYTES);
    }

    secure_clear(x_coordinates, sizeof(x_coordinates));
    secure_clear(y_storage, sizeof(y_storage));
    secure_clear(y_rows, sizeof(y_rows));
    secure_clear(secret_elements, sizeof(secret_elements));

    return rc;
}