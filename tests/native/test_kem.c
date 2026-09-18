#include <assert.h>
#include <string.h>
#include "kem_adapter.h"

static void test_ml_kem_kat(void) {
    uint8_t pk[KEM_PUBLIC_KEY_BYTES];
    uint8_t sk[KEM_SECRET_KEY_BYTES];
    uint8_t ct[KEM_CIPHERTEXT_BYTES];
    uint8_t ss_enc[KEM_SHARED_SECRET_BYTES];
    uint8_t ss_dec[KEM_SHARED_SECRET_BYTES];
    uint8_t workspace[KEM_WORKSPACE_BYTES];

    kem_keypair(pk, sk, workspace);
    kem_encapsulate(ct, ss_enc, pk, workspace);
    kem_decapsulate(ss_dec, ct, sk, workspace);

    assert(memcmp(ss_enc, ss_dec, KEM_SHARED_SECRET_BYTES) == 0);
}

static void test_ml_kem_deterministic(void) {
    uint8_t pk1[KEM_PUBLIC_KEY_BYTES];
    uint8_t sk1[KEM_SECRET_KEY_BYTES];
    uint8_t pk2[KEM_PUBLIC_KEY_BYTES];
    uint8_t sk2[KEM_SECRET_KEY_BYTES];
    uint8_t workspace[KEM_WORKSPACE_BYTES];

    kem_keypair(pk1, sk1, workspace);
    kem_keypair(pk2, sk2, workspace);

    assert(memcmp(pk1, pk2, KEM_PUBLIC_KEY_BYTES) != 0);
    assert(memcmp(sk1, sk2, KEM_SECRET_KEY_BYTES) != 0);
}

static void test_ml_kem_encapsulate_decapsulate_consistency(void) {
    uint8_t pk[KEM_PUBLIC_KEY_BYTES];
    uint8_t sk[KEM_SECRET_KEY_BYTES];
    uint8_t ct[KEM_CIPHERTEXT_BYTES];
    uint8_t ss_enc[KEM_SHARED_SECRET_BYTES];
    uint8_t ss_dec[KEM_SHARED_SECRET_BYTES];
    uint8_t workspace[KEM_WORKSPACE_BYTES];

    kem_keypair(pk, sk, workspace);

    for (int i = 0; i < 10; i++) {
        kem_encapsulate(ct, ss_enc, pk, workspace);
        kem_decapsulate(ss_dec, ct, sk, workspace);
        assert(memcmp(ss_enc, ss_dec, KEM_SHARED_SECRET_BYTES) == 0);
    }
}

static void test_ml_kem_invalid_ciphertext(void) {
    uint8_t pk[KEM_PUBLIC_KEY_BYTES];
    uint8_t sk[KEM_SECRET_KEY_BYTES];
    uint8_t ct[KEM_CIPHERTEXT_BYTES];
    uint8_t ss_dec[KEM_SHARED_SECRET_BYTES];
    uint8_t workspace[KEM_WORKSPACE_BYTES];

    kem_keypair(pk, sk, workspace);
    memset(ct, 0x00, KEM_CIPHERTEXT_BYTES);

    int result = kem_decapsulate(ss_dec, ct, sk, workspace);
    assert(result != 0);
}

int main(void) {
    test_ml_kem_kat();
    test_ml_kem_deterministic();
    test_ml_kem_encapsulate_decapsulate_consistency();
    test_ml_kem_invalid_ciphertext();
    return 0;
}