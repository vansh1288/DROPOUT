#include "shamir.h"

#include <string.h>

#define FIELD_MODULUS SHAMIR_FIELD_MODULUS

extern int randombytes(uint8_t *output, size_t n);

#if defined(SHAMIR_DETERMINISTIC_RNG)
static uint8_t g_test_rng_seed[48] = {0};
static size_t g_test_rng_pos = 0;

static int test_randombytes(uint8_t *output, size_t n)
{
    if (output == NULL) {
        return -1;
    }

    for (size_t i = 0; i < n; ++i) {
        output[i] = g_test_rng_seed[g_test_rng_pos++ % sizeof(g_test_rng_seed)];
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

uint16_t gf3329_barrett_reduce(uint32_t a)
{
    /* Correct for the full uint32_t input range; avoid intermediate overflow. */
    return (uint16_t)(a % FIELD_MODULUS);
}

uint16_t gf3329_add(uint16_t a, uint16_t b)
{
    return (uint16_t)(((uint32_t)(a % FIELD_MODULUS) +
                       (uint32_t)(b % FIELD_MODULUS)) % FIELD_MODULUS);
}

uint16_t gf3329_sub(uint16_t a, uint16_t b)
{
    uint16_t aa = (uint16_t)(a % FIELD_MODULUS);
    uint16_t bb = (uint16_t)(b % FIELD_MODULUS);

    return (aa >= bb)
        ? (uint16_t)(aa - bb)
        : (uint16_t)(aa + FIELD_MODULUS - bb);
}

uint16_t gf3329_mul(uint16_t a, uint16_t b)
{
    return (uint16_t)(((uint32_t)(a % FIELD_MODULUS) *
                       (uint32_t)(b % FIELD_MODULUS)) % FIELD_MODULUS);
}

uint16_t gf3329_inv(uint16_t a)
{
    uint16_t base = (uint16_t)(a % FIELD_MODULUS);
    uint16_t result = 1;
    uint32_t exponent = FIELD_MODULUS - 2u;

    if (base == 0) {
        return 0;
    }

    while (exponent > 0u) {
        if ((exponent & 1u) != 0u) {
            result = gf3329_mul(result, base);
        }
        base = gf3329_mul(base, base);
        exponent >>= 1u;
    }

    return result;
}

uint16_t gf3329_evaluate_polynomial(
    const uint16_t *coeffs,
    uint8_t degree,
    uint16_t x)
{
    uint16_t result = 0;

    if (coeffs == NULL || degree == 0) {
        return 0;
    }

    for (int i = (int)degree - 1; i >= 0; --i) {
        result = gf3329_add(gf3329_mul(result, x), coeffs[i]);
    }

    return result;
}

static int generate_random_coefficients(uint16_t *coeffs, size_t count)
{
    uint8_t bytes[2];

    if (count != 0 && coeffs == NULL) {
        return -1;
    }

    for (size_t i = 0; i < count; ++i) {
        if (RNG_FUNC(bytes, sizeof(bytes)) != 0) {
            memset(coeffs, 0, i * sizeof(*coeffs));
            memset(bytes, 0, sizeof(bytes));
            return -1;
        }

        /* Rejection sampling avoids modulo bias in the field coefficients. */
        uint16_t value;
        do {
            value = (uint16_t)((uint16_t)bytes[0] |
                               ((uint16_t)bytes[1] << 8));
            if (value < FIELD_MODULUS) {
                break;
            }
            if (RNG_FUNC(bytes, sizeof(bytes)) != 0) {
                memset(coeffs, 0, (i + 1u) * sizeof(*coeffs));
                memset(bytes, 0, sizeof(bytes));
                return -1;
            }
        } while (1);

        coeffs[i] = value;
    }

    memset(bytes, 0, sizeof(bytes));
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
    if (secret == NULL || share_x == NULL || share_y == NULL ||
        workspace == NULL) {
        return -1;
    }
    if (secret_elements != SHAMIR_SECRET_ELEMENTS ||
        t == 0 || n < t || n == 0 || n > SHAMIR_MAX_SHARES) {
        return -1;
    }

    for (uint16_t i = 0; i < n; ++i) {
        if (share_y[i] == NULL) {
            return -1;
        }
    }
    for (uint16_t elem = 0; elem < secret_elements; ++elem) {
        if (secret[elem] >= FIELD_MODULUS) {
            return -1;
        }
    }

    const size_t coeff_count = (size_t)secret_elements * (size_t)t;
    if (coeff_count > SHAMIR_WORKSPACE_SIZE) {
        return -1;
    }

    memset(workspace, 0, coeff_count * sizeof(*workspace));

    for (uint16_t elem = 0; elem < secret_elements; ++elem) {
        uint16_t *coeffs = &workspace[(size_t)elem * t];
        coeffs[0] = secret[elem];

        if (t > 1u &&
            generate_random_coefficients(&coeffs[1], (size_t)t - 1u) != 0) {
            memset(workspace, 0, coeff_count * sizeof(*workspace));
            for (uint16_t i = 0; i < n; ++i) {
                memset(share_y[i], 0,
                       (size_t)secret_elements * sizeof(*share_y[i]));
            }
            memset(share_x, 0, (size_t)n * sizeof(*share_x));
            return -1;
        }
    }

    for (uint16_t i = 0; i < n; ++i) {
        const uint16_t x = (uint16_t)(i + 1u);
        share_x[i] = x;

        for (uint16_t elem = 0; elem < secret_elements; ++elem) {
            const uint16_t *coeffs = &workspace[(size_t)elem * t];
            share_y[i][elem] = gf3329_evaluate_polynomial(coeffs, t, x);
        }
    }

    memset(workspace, 0, coeff_count * sizeof(*workspace));
    return 0;
}

int shamir_reconstruct(
    uint16_t *secret,
    const uint16_t *share_x,
    uint16_t **share_y,
    uint8_t k,
    uint16_t *workspace)
{
    if (secret == NULL || share_x == NULL || share_y == NULL ||
        workspace == NULL) {
        return -1;
    }
    if (k < 2u || k > SHAMIR_MAX_SHARES) {
        return -1;
    }

    for (uint16_t i = 0; i < k; ++i) {
        if (share_x[i] == 0 || share_x[i] >= FIELD_MODULUS ||
            share_y[i] == NULL) {
            return -1;
        }
        for (uint16_t j = 0; j < i; ++j) {
            if (share_x[i] == share_x[j]) {
                return -1;
            }
        }
    }

    for (uint16_t elem = 0; elem < SHAMIR_SECRET_ELEMENTS; ++elem) {
        uint16_t reconstructed = 0;

        for (uint16_t i = 0; i < k; ++i) {
            uint16_t numerator = 1;
            uint16_t denominator = 1;

            if (share_y[i][elem] >= FIELD_MODULUS) {
                memset(secret, 0,
                       SHAMIR_SECRET_ELEMENTS * sizeof(*secret));
                return -1;
            }

            for (uint16_t j = 0; j < k; ++j) {
                if (i == j) {
                    continue;
                }
                numerator = gf3329_mul(
                    numerator, gf3329_sub(0, share_x[j]));
                denominator = gf3329_mul(
                    denominator, gf3329_sub(share_x[i], share_x[j]));
            }

            if (denominator == 0) {
                memset(secret, 0,
                       SHAMIR_SECRET_ELEMENTS * sizeof(*secret));
                return -1;
            }

            const uint16_t lagrange = gf3329_mul(
                numerator, gf3329_inv(denominator));
            reconstructed = gf3329_add(
                reconstructed, gf3329_mul(share_y[i][elem], lagrange));
        }

        secret[elem] = reconstructed;
    }

    return 0;
}

int shamir_share_bytes(
    const uint8_t *secret,
    size_t secret_len,
    uint8_t *share_x,
    uint8_t **share_y,
    uint8_t n,
    uint8_t t,
    uint16_t *workspace)
{
    if (secret == NULL || share_x == NULL || share_y == NULL ||
        workspace == NULL || secret_len != SHAMIR_SECRET_BYTES ||
        t == 0 || n < t || n == 0 || n > SHAMIR_MAX_SHARES) {
        return -1;
    }

    for (uint16_t i = 0; i < n; ++i) {
        if (share_y[i] == NULL) {
            return -1;
        }
    }

    uint16_t secret_elements[SHAMIR_SECRET_ELEMENTS];
    for (uint16_t elem = 0; elem < SHAMIR_SECRET_ELEMENTS; ++elem) {
        secret_elements[elem] = (uint16_t)(
            (uint16_t)secret[2u * elem] |
            ((uint16_t)secret[2u * elem + 1u] << 8));

        /*
         * GF(3329) can only represent values 0..3328. This byte API encodes
         * each pair as one field element, so inputs outside that range cannot
         * be represented losslessly and must be rejected, not reduced.
         */
        if (secret_elements[elem] >= FIELD_MODULUS) {
            memset(secret_elements, 0, sizeof(secret_elements));
            return -1;
        }
    }

    for (uint16_t i = 0; i < n; ++i) {
    }

    /*
     * The byte API uses 1-byte x values and little-endian 16-bit y elements.
     * Implement directly to avoid alignment and pointer-array aliasing issues.
     */
    const size_t coeff_count = (size_t)t * SHAMIR_SECRET_ELEMENTS;
    if (coeff_count > SHAMIR_WORKSPACE_SIZE) {
        memset(secret_elements, 0, sizeof(secret_elements));
        return -1;
    }
    memset(workspace, 0, coeff_count * sizeof(*workspace));

    for (uint16_t elem = 0; elem < SHAMIR_SECRET_ELEMENTS; ++elem) {
        uint16_t *coeffs = &workspace[(size_t)elem * t];
        coeffs[0] = secret_elements[elem];

        if (t > 1u &&
            generate_random_coefficients(&coeffs[1], (size_t)t - 1u) != 0) {
            memset(secret_elements, 0, sizeof(secret_elements));
            memset(workspace, 0, coeff_count * sizeof(*workspace));
            for (uint16_t i = 0; i < n; ++i) {
                memset(share_y[i], 0, SHAMIR_SECRET_BYTES);
            }
            memset(share_x, 0, n);
            return -1;
        }
    }

    for (uint16_t i = 0; i < n; ++i) {
        const uint16_t x = (uint16_t)(i + 1u);
        share_x[i] = (uint8_t)x;

        for (uint16_t elem = 0; elem < SHAMIR_SECRET_ELEMENTS; ++elem) {
            const uint16_t *coeffs = &workspace[(size_t)elem * t];
            const uint16_t y = gf3329_evaluate_polynomial(coeffs, t, x);
            share_y[i][2u * elem] = (uint8_t)(y & 0xFFu);
            share_y[i][2u * elem + 1u] = (uint8_t)(y >> 8);
        }
    }

    memset(secret_elements, 0, sizeof(secret_elements));
    memset(workspace, 0, coeff_count * sizeof(*workspace));
    return 0;
}

int shamir_reconstruct_bytes(
    uint8_t *secret,
    const uint8_t *share_x,
    const uint8_t **share_y,
    uint8_t k,
    uint16_t *workspace)
{
    if (secret == NULL || share_x == NULL || share_y == NULL ||
        workspace == NULL || k < 2u || k > SHAMIR_MAX_SHARES) {
        return -1;
    }

    uint16_t x_values[SHAMIR_MAX_SHARES] = {0};
    uint16_t y_values[SHAMIR_MAX_SHARES] = {0};

    for (uint16_t i = 0; i < k; ++i) {
        if (share_x[i] == 0 || share_x[i] >= FIELD_MODULUS ||
            share_y[i] == NULL) {
            goto error;
        }
        x_values[i] = share_x[i];
        for (uint16_t j = 0; j < i; ++j) {
            if (x_values[i] == x_values[j]) {
                goto error;
            }
        }
    }

    for (uint16_t elem = 0; elem < SHAMIR_SECRET_ELEMENTS; ++elem) {
        uint16_t reconstructed = 0;

        for (uint16_t i = 0; i < k; ++i) {
            const size_t offset = (size_t)elem * sizeof(uint16_t);
            y_values[i] = (uint16_t)(
                (uint16_t)share_y[i][offset] |
                ((uint16_t)share_y[i][offset + 1u] << 8));

            if (y_values[i] >= FIELD_MODULUS) {
                goto error;
            }

            uint16_t numerator = 1;
            uint16_t denominator = 1;

            for (uint16_t j = 0; j < k; ++j) {
                if (i == j) {
                    continue;
                }
                numerator = gf3329_mul(
                    numerator, gf3329_sub(0, x_values[j]));
                denominator = gf3329_mul(
                    denominator, gf3329_sub(x_values[i], x_values[j]));
            }

            if (denominator == 0) {
                goto error;
            }

            const uint16_t lagrange = gf3329_mul(
                numerator, gf3329_inv(denominator));
            reconstructed = gf3329_add(
                reconstructed, gf3329_mul(y_values[i], lagrange));
        }

        secret[2u * elem] = (uint8_t)(reconstructed & 0xFFu);
        secret[2u * elem + 1u] = (uint8_t)(reconstructed >> 8);
    }

    memset(x_values, 0, sizeof(x_values));
    memset(y_values, 0, sizeof(y_values));
    return 0;

error:
    memset(secret, 0, SHAMIR_SECRET_BYTES);
    memset(x_values, 0, sizeof(x_values));
    memset(y_values, 0, sizeof(y_values));
    return -1;
}
