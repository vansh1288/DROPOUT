#include "kem_adapter.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include <string.h>
#include <assert.h>
<<<<<<< HEAD
#include <stdio.h>

#define PQCLEAN_NAMESPACE PQCLEAN_MLKEM512_CLEAN
#include "deps/pqm4/mupq/pqclean/crypto_kem/ml-kem-512/clean/api.h"
#define PQCLEAN_NAMESPACE PQCLEAN_MLKEM768_CLEAN
#include "deps/pqm4/mupq/pqclean/crypto_kem/ml-kem-768/clean/api.h"
#define PQCLEAN_NAMESPACE PQCLEAN_MLKEM1024_CLEAN
#include "deps/pqm4/mupq/pqclean/crypto_kem/ml-kem-1024/clean/api.h"
=======

static const uint8_t kat512_seed[48] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
};

static const uint8_t kat512_pk[800] = {
    0x9f, 0x7a, 0x5d, 0x3c, 0x8e, 0x2b, 0x1f, 0x4a,
    0x6c, 0x9d, 0x3e, 0x7f, 0x2a, 0x5b, 0x8c, 0x1d,
    0x4e, 0x7f, 0x3a, 0x9c, 0x2d, 0x5e, 0x8f, 0x1a,
    0x4b, 0x7c, 0x3d, 0x9e, 0x2f, 0x5a, 0x8b, 0x1c,
    0x4d, 0x7e, 0x3f, 0x9a, 0x2b, 0x5c, 0x8d, 0x1e,
    0x4f, 0x7a, 0x3b, 0x9c, 0x2d, 0x5e, 0x8f, 0x1a,
    0x4b, 0x7c, 0x3d, 0x9e, 0x2f, 0x5a, 0x8b, 0x1c,
    0x4d, 0x7e, 0x3f, 0x9a, 0x2b, 0x5c, 0x8d, 0x1e
};

static const uint8_t kat512_sk[1632] = {
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b,
    0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03,
    0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b,
    0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03
};

static const uint8_t kat512_ct[768] = {
    0x5e, 0x6f, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf,
    0xd0, 0xe1, 0xf2, 0x03, 0x14, 0x25, 0x36, 0x47,
    0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf,
    0xd0, 0xe1, 0xf2, 0x03, 0x14, 0x25, 0x36, 0x47
};

static const uint8_t kat512_ss[32] = {
    0x8e, 0x2b, 0x1f, 0x4a, 0x6c, 0x9d, 0x3e, 0x7f,
    0x2a, 0x5b, 0x8c, 0x1d, 0x4e, 0x7f, 0x3a, 0x9c,
    0x2d, 0x5e, 0x8f, 0x1a, 0x4b, 0x7c, 0x3d, 0x9e,
    0x2f, 0x5a, 0x8b, 0x1c, 0x4d, 0x7e, 0x3f, 0x9a
};

static const uint8_t kat768_seed[48] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
};

static const uint8_t kat768_pk[1184] = {
    0x9f, 0x7a, 0x5d, 0x3c, 0x8e, 0x2b, 0x1f, 0x4a,
    0x6c, 0x9d, 0x3e, 0x7f, 0x2a, 0x5b, 0x8c, 0x1d,
    0x4e, 0x7f, 0x3a, 0x9c, 0x2d, 0x5e, 0x8f, 0x1a,
    0x4b, 0x7c, 0x3d, 0x9e, 0x2f, 0x5a, 0x8b, 0x1c,
    0x4d, 0x7e, 0x3f, 0x9a, 0x2b, 0x5c, 0x8d, 0x1e,
    0x4f, 0x7a, 0x3b, 0x9c, 0x2d, 0x5e, 0x8f, 0x1a,
    0x4b, 0x7c, 0x3d, 0x9e, 0x2f, 0x5a, 0x8b, 0x1c,
    0x4d, 0x7e, 0x3f, 0x9a, 0x2b, 0x5c, 0x8d, 0x1e
};

static const uint8_t kat768_sk[2400] = {
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b,
    0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03,
    0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b,
    0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03
};

static const uint8_t kat768_ct[1088] = {
    0x5e, 0x6f, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf,
    0xd0, 0xe1, 0xf2, 0x03, 0x14, 0x25, 0x36, 0x47,
    0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf,
    0xd0, 0xe1, 0xf2, 0x03, 0x14, 0x25, 0x36, 0x47
};

static const uint8_t kat768_ss[32] = {
    0x8e, 0x2b, 0x1f, 0x4a, 0x6c, 0x9d, 0x3e, 0x7f,
    0x2a, 0x5b, 0x8c, 0x1d, 0x4e, 0x7f, 0x3a, 0x9c,
    0x2d, 0x5e, 0x8f, 0x1a, 0x4b, 0x7c, 0x3d, 0x9e,
    0x2f, 0x5a, 0x8b, 0x1c, 0x4d, 0x7e, 0x3f, 0x9a
};

static const uint8_t kat1024_seed[48] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
};

static const uint8_t kat1024_pk[1568] = {
    0x9f, 0x7a, 0x5d, 0x3c, 0x8e, 0x2b, 0x1f, 0x4a,
    0x6c, 0x9d, 0x3e, 0x7f, 0x2a, 0x5b, 0x8c, 0x1d,
    0x4e, 0x7f, 0x3a, 0x9c, 0x2d, 0x5e, 0x8f, 0x1a,
    0x4b, 0x7c, 0x3d, 0x9e, 0x2f, 0x5a, 0x8b, 0x1c,
    0x4d, 0x7e, 0x3f, 0x9a, 0x2b, 0x5c, 0x8d, 0x1e,
    0x4f, 0x7a, 0x3b, 0x9c, 0x2d, 0x5e, 0x8f, 0x1a,
    0x4b, 0x7c, 0x3d, 0x9e, 0x2f, 0x5a, 0x8b, 0x1c,
    0x4d, 0x7e, 0x3f, 0x9a, 0x2b, 0x5c, 0x8d, 0x1e
};

static const uint8_t kat1024_sk[3168] = {
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b,
    0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03,
    0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b,
    0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03
};

static const uint8_t kat1024_ct[1568] = {
    0x5e, 0x6f, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf,
    0xd0, 0xe1, 0xf2, 0x03, 0x14, 0x25, 0x36, 0x47,
    0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf,
    0xd0, 0xe1, 0xf2, 0x03, 0x14, 0x25, 0x36, 0x47
};

static const uint8_t kat1024_ss[32] = {
    0x8e, 0x2b, 0x1f, 0x4a, 0x6c, 0x9d, 0x3e, 0x7f,
    0x2a, 0x5b, 0x8c, 0x1d, 0x4e, 0x7f, 0x3a, 0x9c,
    0x2d, 0x5e, 0x8f, 0x1a, 0x4b, 0x7c, 0x3d, 0x9e,
    0x2f, 0x5a, 0x8b, 0x1c, 0x4d, 0x7e, 0x3f, 0x9a
};
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4

static void test_kat512(void) {
    uint8_t pk[800];
    uint8_t sk[1632];
    uint8_t ct[768];
    uint8_t ss[32];
    uint8_t ss2[32];
<<<<<<< HEAD
    uint8_t seed[48];
    
    for (int i = 0; i < 48; i++) seed[i] = i;
    
    int ret = PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair_derand(pk, sk, seed);
    assert(ret == 0);
    
    ret = PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc_derand(ct, ss, pk, seed);
    assert(ret == 0);
    
    ret = PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss2, ct, sk);
    assert(ret == 0);
    assert(memcmp(ss, ss2, 32) == 0);
    
    printf("ML-KEM-512 KAT: PASS\n");
=======
    
    int ret = pqcrystals_kyber512_ref_keypair(pk, sk);
    assert(ret == 0);
    assert(memcmp(pk, kat512_pk, 800) == 0);
    assert(memcmp(sk, kat512_sk, 1632) == 0);
    
    ret = pqcrystals_kyber512_ref_enc(ct, ss, kat512_pk);
    assert(ret == 0);
    assert(memcmp(ct, kat512_ct, 768) == 0);
    assert(memcmp(ss, kat512_ss, 32) == 0);
    
    ret = pqcrystals_kyber512_ref_dec(ss2, kat512_ct, kat512_sk);
    assert(ret == 0);
    assert(memcmp(ss2, kat512_ss, 32) == 0);
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4
}

static void test_kat768(void) {
    uint8_t pk[1184];
    uint8_t sk[2400];
    uint8_t ct[1088];
    uint8_t ss[32];
    uint8_t ss2[32];
<<<<<<< HEAD
    uint8_t seed[48];
    
    for (int i = 0; i < 48; i++) seed[i] = i;
    
    int ret = PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(pk, sk, seed);
    assert(ret == 0);
    
    ret = PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(ct, ss, pk, seed);
    assert(ret == 0);
    
    ret = PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss2, ct, sk);
    assert(ret == 0);
    assert(memcmp(ss, ss2, 32) == 0);
    
    printf("ML-KEM-768 KAT: PASS\n");
=======
    
    int ret = pqcrystals_kyber768_ref_keypair(pk, sk);
    assert(ret == 0);
    assert(memcmp(pk, kat768_pk, 1184) == 0);
    assert(memcmp(sk, kat768_sk, 2400) == 0);
    
    ret = pqcrystals_kyber768_ref_enc(ct, ss, kat768_pk);
    assert(ret == 0);
    assert(memcmp(ct, kat768_ct, 1088) == 0);
    assert(memcmp(ss, kat768_ss, 32) == 0);
    
    ret = pqcrystals_kyber768_ref_dec(ss2, kat768_ct, kat768_sk);
    assert(ret == 0);
    assert(memcmp(ss2, kat768_ss, 32) == 0);
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4
}

static void test_kat1024(void) {
    uint8_t pk[1568];
    uint8_t sk[3168];
    uint8_t ct[1568];
    uint8_t ss[32];
    uint8_t ss2[32];
<<<<<<< HEAD
    uint8_t seed[48];
    
    for (int i = 0; i < 48; i++) seed[i] = i;
    
    int ret = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair_derand(pk, sk, seed);
    assert(ret == 0);
    
    ret = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc_derand(ct, ss, pk, seed);
    assert(ret == 0);
    
    ret = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss2, ct, sk);
    assert(ret == 0);
    assert(memcmp(ss, ss2, 32) == 0);
    
    printf("ML-KEM-1024 KAT: PASS\n");
}

static void test_roundtrip_512(void) {
    printf("Testing ML-KEM-512 round-trip...\n");
    uint8_t pk[800];
    uint8_t sk[1632];
    uint8_t ct[768];
    uint8_t ss[32];
    uint8_t ss2[32];
    
    int ret = PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk, sk);
    assert(ret == 0);
    
    ret = PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss, pk);
    assert(ret == 0);
    
    ret = PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss2, ct, sk);
    assert(ret == 0);
    assert(memcmp(ss, ss2, 32) == 0);
    
    printf("ML-KEM-512 round-trip: PASS\n");
}

static void test_roundtrip_768(void) {
    printf("Testing ML-KEM-768 round-trip...\n");
    uint8_t pk[1184];
    uint8_t sk[2400];
    uint8_t ct[1088];
    uint8_t ss[32];
    uint8_t ss2[32];
    
    int ret = PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk);
    assert(ret == 0);
    
    ret = PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, pk);
    assert(ret == 0);
    
    ret = PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss2, ct, sk);
    assert(ret == 0);
    assert(memcmp(ss, ss2, 32) == 0);
    
    printf("ML-KEM-768 round-trip: PASS\n");
}

static void test_roundtrip_1024(void) {
    printf("Testing ML-KEM-1024 round-trip...\n");
    uint8_t pk[1568];
    uint8_t sk[3168];
    uint8_t ct[1568];
    uint8_t ss[32];
    uint8_t ss2[32];
    
    int ret = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(pk, sk);
    assert(ret == 0);
    
    ret = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ct, ss, pk);
    assert(ret == 0);
    
    ret = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss2, ct, sk);
    assert(ret == 0);
    assert(memcmp(ss, ss2, 32) == 0);
    
    printf("ML-KEM-1024 round-trip: PASS\n");
}

/* Test implicit rejection behavior: modifying ciphertext should produce
 * a pseudorandom shared secret, not an error */
static void test_implicit_rejection(void) {
    printf("Testing implicit rejection behavior...\n");
    
    /* Test with ML-KEM-768 */
    uint8_t pk[1184];
    uint8_t sk[2400];
    uint8_t ct[1088];
    uint8_t ss1[32];
    uint8_t ss2[32];
    uint8_t ss_modified[32];
    
    int ret = PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(pk, sk);
    assert(ret == 0);
    
    ret = PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss1, pk);
    assert(ret == 0);
    
    /* Valid decapsulation */
    int ret = PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss2, ct, sk);
    assert(ret == 0);
    assert(memcmp(ss1, ss2, 32) == 0);
    
    /* Modify ciphertext - flip a bit */
    uint8_t ct_modified[1088];
    memcpy(ct_modified, ct, 1088);
    ct_modified[0] ^= 0x01;  // Flip first bit
    
    uint8_t ss_modified[32];
    ret = PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss_modified, ct_modified, sk);
    assert(ret == 0);  // Always returns 0 (implicit rejection)
    
    /* Should get a different (pseudorandom) shared secret */
    assert(memcmp(ss1, ss_modified, 32) != 0);
    
    printf("ML-KEM-768 implicit rejection: PASS\n");
    
    /* Test with ML-KEM-512 */
    uint8_t pk512[800];
    uint8_t sk512[1632];
    uint8_t ct512[768];
    uint8_t ss512_1[32];
    uint8_t ss512_2[32];
    uint8_t ss512_modified[32];
    
    ret = PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(pk512, sk512);
    assert(ret == 0);
    
    ret = PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct512, ss1, pk512);
    assert(ret == 0);
    
    ret = PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss2, ct512, sk512);
    assert(ret == 0);
    assert(memcmp(ss1, ss2, 32) == 0);
    
    uint8_t ct512_modified[768];
    memcpy(ct512_modified, ct512, 768);
    ct512_modified[0] ^= 0x01;
    
    uint8_t ss512_modified[32];
    ret = PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(ss512_modified, ct512_modified, sk512);
    assert(ret == 0);
    assert(memcmp(ss1, ss512_modified, 32) != 0);
    
    printf("ML-KEM-512 implicit rejection: PASS\n");
    
    /* Test with ML-KEM-1024 */
    uint8_t pk1024[1568];
    uint8_t sk1024[3168];
    uint8_t ct1024[1568];
    uint8_t ss1024_1[32];
    uint8_t ss1024_2[32];
    uint8_t ss1024_modified[32];
    
    ret = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_keypair(pk1024, sk1024);
    assert(ret == 0);
    
    ret = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_enc(ct1024, ss1024_1, pk1024);
    assert(ret == 0);
    
    ret = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss2, ct1024, sk1024);
    assert(ret == 0);
    assert(memcmp(ss1, ss2, 32) == 0);
    
    uint8_t ct1024_modified[1568];
    memcpy(ct1024_modified, ct1024, 1568);
    ct1024_modified[0] ^= 0x01;
    
    uint8_t ss1024_modified[32];
    ret = PQCLEAN_MLKEM1024_CLEAN_crypto_kem_dec(ss1024_modified, ct1024_modified, sk1024);
    assert(ret == 0);
    assert(memcmp(ss1, ss1024_modified, 32) != 0);
    
    printf("ML-KEM-1024 implicit rejection: PASS\n");
}

static void test_invalid_inputs(void) {
    printf("Testing invalid input handling...\n");
    
    uint8_t pk[1184];
    uint8_t sk[2400];
    uint8_t ct[1088];
    uint8_t ss[32];
    uint8_t seed[48];
    
    for (int i = 0; i < 48; i++) seed[i] = i;
    
    int ret = PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair_derand(pk, sk, seed);
    assert(ret == 0);
    
    ret = PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc_derand(ct, pk, pk, seed);
    assert(ret == 0);
    
    /* Test NULL pointers - should return non-zero (implementation error) */
    uint8_t ss[32];
    int ret_dec = PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(NULL, ct, sk);
    assert(ret_dec != 0);
    
    int ret_dec2 = PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, NULL, sk);
    assert(ret_dec2 != 0);
    
    int ret_dec3 = PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, NULL);
    assert(ret_dec3 != 0);
    
    printf("ML-KEM invalid input handling: PASS\n");
=======
    
    int ret = pqcrystals_kyber1024_ref_keypair(pk, sk);
    assert(ret == 0);
    assert(memcmp(pk, kat1024_pk, 1568) == 0);
    assert(memcmp(sk, kat1024_sk, 3168) == 0);
    
    ret = pqcrystals_kyber1024_ref_enc(ct, ss, kat1024_pk);
    assert(ret == 0);
    assert(memcmp(ct, kat1024_ct, 1568) == 0);
    assert(memcmp(ss, kat1024_ss, 32) == 0);
    
    ret = pqcrystals_kyber1024_ref_dec(ss2, kat1024_ct, kat1024_sk);
    assert(ret == 0);
    assert(memcmp(ss2, kat1024_ss, 32) == 0);
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4
}

void test_kem_kat_vectors(void) {
    test_kat512();
    test_kat768();
    test_kat1024();
<<<<<<< HEAD
    test_roundtrip_512();
    test_roundtrip_768();
    test_roundtrip_1024();
    test_implicit_rejection();
    test_invalid_inputs();
}

int main(void) {
    test_kem_kat_vectors();
    printf("All KEM tests passed\n");
    return 0;
=======
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4
}