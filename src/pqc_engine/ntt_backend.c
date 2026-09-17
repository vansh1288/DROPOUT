#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "kem_adapter.h"
#include <stdint.h>

#define KYBER_Q 3329
#define KYBER_N 256
#define KYBER_ROOT_OF_UNITY 17

static const uint16_t zetas[KYBER_N] = {
    1, 1729, 2580, 3289, 2642, 630, 1897, 848,
    2192, 2775, 74, 2326, 2473, 1382, 2352, 2138,
    1447, 256, 1015, 1038, 2626, 1774, 2089, 1437,
    62, 2699, 462, 1071, 684, 1503, 2524, 2150,
    1125, 2349, 685, 885, 2477, 1138, 1983, 2013,
    1464, 355, 855, 2009, 1607, 1997, 2042, 286,
    2425, 1881, 1968, 1069, 2517, 367, 1984, 1297,
    319, 2003, 1289, 726, 2108, 568, 2188, 331,
    325, 1728, 2579, 3288, 2641, 629, 1896, 847,
    2191, 2774, 73, 2325, 2472, 1381, 2351, 2137,
    1446, 255, 1014, 1037, 2625, 1773, 2088, 1436,
    61, 2698, 461, 1070, 683, 1502, 2523, 2149,
    1124, 2348, 684, 884, 2476, 1137, 1982, 2012,
    1463, 354, 854, 2008, 1606, 1996, 2041, 285,
    2424, 1880, 1967, 1068, 2516, 366, 1983, 1296,
    318, 2002, 1288, 725, 2107, 567, 2187, 330,
    324, 1727, 2578, 3287, 2640, 628, 1895, 846,
    2190, 2773, 72, 2324, 2471, 1380, 2350, 2136,
    1445, 254, 1013, 1036, 2624, 1772, 2087, 1435,
    60, 2697, 460, 1069, 682, 1501, 2522, 2148,
    1123, 2347, 683, 883, 2475, 1136, 1981, 2011,
    1462, 353, 853, 2007, 1605, 1995, 2040, 284,
    2423, 1879, 1966, 1067, 2515, 365, 1982, 1295,
    317, 2001, 1287, 724, 2106, 566, 2186, 329,
    323, 1726, 2577, 3286, 2639, 627, 1894, 845,
    2189, 2772, 71, 2323, 2470, 1379, 2349, 2135,
    1444, 253, 1012, 1035, 2623, 1771, 2086, 1434,
    59, 2696, 459, 1068, 681, 1500, 2521, 2147,
    1122, 2346, 682, 882, 2474, 1135, 1980, 2010,
    1461, 352, 852, 2006, 1604, 1994, 2039, 283,
    2422, 1878, 1965, 1066, 2514, 364, 1981, 1294,
    316, 2000, 1286, 723, 2105, 565, 2185, 328
};

static inline uint16_t barrett_reduce(uint32_t a) {
    uint32_t t = (a * 20159) >> 26;
    uint16_t r = (uint16_t)(a - t * KYBER_Q);
    return r >= KYBER_Q ? r - KYBER_Q : r;
}

static inline uint16_t montgomery_reduce(uint32_t a) {
    uint32_t t = (a * 3327) & 0xFFFF;
    uint32_t u = (a + t * KYBER_Q) >> 16;
    return (uint16_t)(u >= KYBER_Q ? u - KYBER_Q : u);
}

static inline void ntt_butterfly(uint16_t* a, uint16_t* b, uint16_t zeta) {
    uint16_t t = montgomery_reduce((uint32_t)*b * zeta);
    uint16_t u = *a;
    *a = u + t;
    if (*a >= KYBER_Q) *a -= KYBER_Q;
    *b = u + KYBER_Q - t;
    if (*b >= KYBER_Q) *b -= KYBER_Q;
}

static inline void intt_butterfly(uint16_t* a, uint16_t* b, uint16_t zeta) {
    uint16_t u = *a;
    uint16_t v = *b;
    *a = u + v;
    if (*a >= KYBER_Q) *a -= KYBER_Q;
    *b = u + KYBER_Q - v;
    if (*b >= KYBER_Q) *b -= KYBER_Q;
    *b = montgomery_reduce((uint32_t)*b * zeta);
}

void ntt_forward(int16_t* poly) {
    uint16_t* a = (uint16_t*)poly;
    size_t len = 128;
    size_t start = 0;
    size_t k = 0;

    while (len > 0) {
        for (size_t i = start; i < KYBER_N; i += 2 * len) {
            for (size_t j = 0; j < len; j++) {
                ntt_butterfly(&a[i + j], &a[i + j + len], zetas[k++]);
            }
        }
        len >>= 1;
    }
}

void ntt_inverse(int16_t* poly) {
    uint16_t* a = (uint16_t*)poly;
    size_t len = 1;
    size_t k = 0;

    while (len < KYBER_N) {
        for (size_t i = 0; i < KYBER_N; i += 2 * len) {
            for (size_t j = 0; j < len; j++) {
                intt_butterfly(&a[i + j], &a[i + j + len], zetas[k++]);
            }
        }
        len <<= 1;
    }

    const uint16_t n_inv = 3303;
    for (size_t i = 0; i < KYBER_N; i++) {
        a[i] = montgomery_reduce((uint32_t)a[i] * n_inv);
    }
}

void ntt_mul_pointwise(int16_t* r, const int16_t* a, const int16_t* b) {
    for (size_t i = 0; i < KYBER_N; i++) {
        r[i] = (int16_t)montgomery_reduce((uint32_t)a[i] * b[i]);
    }
}

void ntt_base_mul(int16_t* r, const int16_t* a, const int16_t* b) {
    for (size_t i = 0; i < KYBER_N / 2; i++) {
        uint16_t a0 = (uint16_t)a[2*i];
        uint16_t a1 = (uint16_t)a[2*i+1];
        uint16_t b0 = (uint16_t)b[2*i];
        uint16_t b1 = (uint16_t)b[2*i+1];
        uint16_t zeta = zetas[2*i+1];

        uint32_t t0 = (uint32_t)a0 * b0;
        uint32_t t1 = (uint32_t)a1 * b1;
        uint32_t t2 = (uint32_t)a1 * b0;
        uint32_t t3 = (uint32_t)a0 * b1;

        uint16_t c0 = montgomery_reduce(t0 + montgomery_reduce(t1 * zeta));
        uint16_t c1 = montgomery_reduce(t2 + t3);

        r[2*i] = (int16_t)c0;
        r[2*i+1] = (int16_t)c1;
    }
}