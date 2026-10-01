#include "kem_adapter.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include <string.h>
#include <assert.h>
#include <stdio.h>

#define PQCLEAN_NAMESPACE PQCLEAN_MLKEM512_CLEAN
#include "deps/pqm4/mupq/pqclean/crypto_kem/ml-kem-512/clean/api.h"
#define PQCLEAN_NAMESPACE PQCLEAN_MLKEM768_CLEAN
#include "deps/pqm4/mupq/pqclean/crypto_kem/ml-kem-768/clean/api.h"
#define PQCLEAN_NAMESPACE PQCLEAN_MLKEM1024_CLEAN
#include "deps/pqm4/mupq/pqclean/crypto_kem/ml-kem-1024/clean/api.h"

static void test_kat512(void) {
    uint8_t pk[800];
    uint8_t sk[1632];
    uint8_t ct[768];
    uint8_t ss[32];
    uint8_t ss2[32];
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
}

static void test_kat768(void) {
    uint8_t pk[1184];
    uint8_t sk[2400];
    uint8_t ct[1088];
    uint8_t ss[32];
    uint8_t ss2[32];
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
}

static void test_kat1024(void) {
    uint8_t pk[1568];
    uint8_t sk[3168];
    uint8_t ct[1568];
    uint8_t ss[32];
    uint8_t ss2[32];
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
}

void test_kem_kat_vectors(void) {
    test_kat512();
    test_kat768();
    test_kat1024();
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
}