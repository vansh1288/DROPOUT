#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define PQCLEAN_NAMESPACE PQCLEAN_MLKEM768_CLEAN
#include "deps/pqm4/mupq/pqclean/crypto_kem/ml-kem-768/clean/api.h"
#include "deps/pqm4/mupq/pqclean/crypto_kem/ml-kem-768/clean/kem.h"

static uint8_t kat_entropy[48];
static size_t kat_entropy_pos = 0;

void randombytes_init(const uint8_t *entropy, size_t len) {
    size_t copy_len = len < 48 ? len : 48;
    memcpy(kat_entropy, entropy, copy_len);
    kat_entropy_pos = 0;
}

int randombytes(uint8_t *buf, size_t len) {
    for (size_t i = 0; i < len; i++) {
        buf[i] = kat_entropy[kat_entropy_pos++ % 48];
    }
    return 0;
}

void print_array(const char *name, const uint8_t *arr, size_t len) {
    printf("static const uint8_t %s[%zu] = {\n", name, len);
    for (size_t i = 0; i < len; i++) {
        if (i % 8 == 0) printf("    ");
        printf("0x%02x", arr[i]);
        if (i != len - 1) printf(", ");
        if (i % 8 == 7 || i == len - 1) printf("\n");
    }
    printf("};\n\n");
}

int main() {
    uint8_t seed[48];
    for (int i = 0; i < 48; i++) seed[i] = i;
    randombytes_init(seed, 48);

    uint8_t pk[1184];
    uint8_t sk[2400];
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(pk, sk, seed);
    print_array("kat768_pk", pk, 1184);
    print_array("kat768_sk", sk, 2400);

    randombytes_init(seed, 48);
    uint8_t ct[1088];
    uint8_t ss[32];
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(ct, ss, pk, seed);
    print_array("kat768_ct", ct, 1088);
    print_array("kat768_ss", ss, 32);

    uint8_t ss2[32];
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss2, ct, sk);
    print_array("kat768_ss_dec", ss2, 32);

    if (memcmp(ss, ss2, 32) == 0) {
        printf("// KAT verification: PASS\n");
    } else {
        printf("// KAT verification: FAIL\n");
    }

    return 0;
}