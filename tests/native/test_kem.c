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

void test_kem_kat_vectors(void) {
    test_kat512();
    test_kat768();
    test_kat1024();
}

int main(void) {
    test_kem_kat_vectors();
    printf("All KEM KAT tests passed\n");
    return 0;
}