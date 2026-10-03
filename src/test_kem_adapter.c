#include "kem_adapter.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include <string.h>
#include <assert.h>
#include <stdio.h>

#define KEM_DETERMINISTIC_TEST
#define PQCLEAN_NAMESPACE PQCLEAN_MLKEM512_CLEAN
#include "deps/pqm4/mupq/pqclean/crypto_kem/ml-kem-512/clean/api.h"
#define PQCLEAN_NAMESPACE PQCLEAN_MLKEM768_CLEAN
#include "deps/pqm4/mupq/pqclean/crypto_kem/ml-kem-768/clean/api.h"
#define PQCLEAN_NAMESPACE PQCLEAN_MLKEM1024_CLEAN
#include "deps/pqm4/mupq/pqclean/crypto_kem/ml-kem-1024/clean/api.h"

static void test_adapter_init(void) {
    printf("Testing adapter init...\n");
    pqc_status_t ret;

    ret = kem_adapter_init(KEMLIB_ML_KEM_512);
    assert(ret == PQC_SUCCESS);
    assert(kem_adapter_get_variant() == KEMLIB_ML_KEM_512);

    ret = kem_adapter_init(KEMLIB_ML_KEM_768);
    assert(ret == PQC_SUCCESS);
    assert(kem_adapter_get_variant() == KEMLIB_ML_KEM_768);

    ret = kem_adapter_init(KEMLIB_ML_KEM_1024);
    assert(ret == PQC_SUCCESS);
    assert(kem_adapter_get_variant() == KEMLIB_ML_KEM_1024);

    ret = kem_adapter_init(3);
    assert(ret == ERR_INVALID_ARGUMENT);

    printf("  PASS\n");
}

static void test_adapter_get_sizes(void) {
    printf("Testing adapter get_sizes...\n");
    size_t pk, sk, ct, ss;

    kem_adapter_init(KEMLIB_ML_KEM_512);
    pqc_status_t ret = kem_adapter_get_sizes(&pk, &sk, &ct, &ss);
    assert(ret == PQC_SUCCESS);
    assert(pk == ML_KEM_512_PUBLIC_KEY_BYTES);
    assert(sk == ML_KEM_512_SECRET_KEY_BYTES);
    assert(ct == ML_KEM_512_CIPHERTEXT_BYTES);
    assert(ss == ML_KEM_512_SHARED_SECRET_BYTES);

    kem_adapter_init(KEMLIB_ML_KEM_768);
    ret = kem_adapter_get_sizes(&pk, &sk, &ct, &ss);
    assert(ret == PQC_SUCCESS);
    assert(pk == ML_KEM_768_PUBLIC_KEY_BYTES);
    assert(sk == ML_KEM_768_SECRET_KEY_BYTES);
    assert(ct == ML_KEM_768_CIPHERTEXT_BYTES);
    assert(ss == ML_KEM_768_SHARED_SECRET_BYTES);

    kem_adapter_init(KEMLIB_ML_KEM_1024);
    ret = kem_adapter_get_sizes(&pk, &sk, &ct, &ss);
    assert(ret == PQC_SUCCESS);
    assert(pk == ML_KEM_1024_PUBLIC_KEY_BYTES);
    assert(sk == ML_KEM_1024_SECRET_KEY_BYTES);
    assert(ct == ML_KEM_1024_CIPHERTEXT_BYTES);
    assert(ss == ML_KEM_1024_SHARED_SECRET_BYTES);

    ret = kem_adapter_get_sizes(NULL, &sk, &ct, &ss);
    assert(ret == ERR_INVALID_ARGUMENT);
    ret = kem_adapter_get_sizes(&pk, NULL, &ct, &ss);
    assert(ret == ERR_INVALID_ARGUMENT);
    ret = kem_adapter_get_sizes(&pk, &sk, NULL, &ss);
    assert(ret == ERR_INVALID_ARGUMENT);
    ret = kem_adapter_get_sizes(&pk, &sk, &ct, NULL);
    assert(ret == ERR_INVALID_ARGUMENT);

    printf("  PASS\n");
}

static void test_adapter_keypair_roundtrip(void) {
    printf("Testing adapter keypair roundtrip for all variants...\n");

    for (int v = 0; v < 3; v++) {
        kem_variant_t variant = (kem_variant_t)v;
        kem_adapter_init(variant);
        printf("  Variant %d...\n", variant);

        kem_keypair_t kp1, kp2;
        pqc_status_t ret = kem_adapter_keypair(&kp1);
        assert(ret == PQC_SUCCESS);
        assert(kp1.variant == variant);
        assert(kp1.public_key_len > 0);
        assert(kp1.secret_key_len > 0);
        assert(kp1.ciphertext_len > 0);
        assert(kp1.shared_secret_len == 32);

        ret = kem_adapter_keypair(&kp2);
        assert(ret == PQC_SUCCESS);
        assert(memcmp(kp1.public_key, kp2.public_key, kp1.public_key_len) != 0);
        assert(memcmp(kp1.secret_key, kp2.secret_key, kp1.secret_key_len) != 0);

        kem_encapsulation_t enc;
        ret = kem_adapter_encapsulate(kp1.public_key, kp1.public_key_len, &enc);
        assert(ret == PQC_SUCCESS);
        assert(enc.ciphertext_len == kp1.ciphertext_len);
        assert(enc.shared_secret_len == 32);

        uint8_t ss[32];
        ret = kem_adapter_decapsulate(enc.ciphertext, enc.ciphertext_len, kp1.secret_key, kp1.secret_key_len, ss);
        assert(ret == PQC_SUCCESS);

        ret = kem_adapter_verify_decapsulation(enc.shared_secret, ss);
        assert(ret == PQC_SUCCESS);

        crypto_zeroize(&kp1, sizeof(kp1));
        crypto_zeroize(&kp2, sizeof(kp2));
        crypto_zeroize(&enc, sizeof(enc));
        crypto_zeroize(ss, 32);
    }

    printf("  PASS\n");
}

static void test_adapter_invalid_inputs(void) {
    printf("Testing adapter invalid input handling...\n");

    kem_adapter_init(KEMLIB_ML_KEM_768);

    kem_keypair_t kp;
    kem_encapsulation_t enc;
    uint8_t ss[32];

    pqc_status_t ret = kem_adapter_keypair(NULL);
    assert(ret == ERR_INVALID_ARGUMENT);

    ret = kem_adapter_keypair(&kp);
    assert(ret == PQC_SUCCESS);

    ret = kem_adapter_encapsulate(NULL, kp.public_key_len, &enc);
    assert(ret == ERR_INVALID_ARGUMENT);

    ret = kem_adapter_encapsulate(kp.public_key, kp.public_key_len + 1, &enc);
    assert(ret == ERR_INVALID_ARGUMENT);

    ret = kem_adapter_encapsulate(kp.public_key, kp.public_key_len, NULL);
    assert(ret == ERR_INVALID_ARGUMENT);

    ret = kem_adapter_encapsulate(kp.public_key, kp.public_key_len, &enc);
    assert(ret == PQC_SUCCESS);

    ret = kem_adapter_decapsulate(NULL, enc.ciphertext_len, kp.secret_key, kp.secret_key_len, ss);
    assert(ret == ERR_INVALID_ARGUMENT);

    ret = kem_adapter_decapsulate(enc.ciphertext, enc.ciphertext_len + 1, kp.secret_key, kp.secret_key_len, ss);
    assert(ret == ERR_INVALID_ARGUMENT);

    ret = kem_adapter_decapsulate(enc.ciphertext, enc.ciphertext_len, NULL, kp.secret_key_len, ss);
    assert(ret == ERR_INVALID_ARGUMENT);

    ret = kem_adapter_decapsulate(enc.ciphertext, enc.ciphertext_len, kp.secret_key, kp.secret_key_len + 1, ss);
    assert(ret == ERR_INVALID_ARGUMENT);

    ret = kem_adapter_decapsulate(enc.ciphertext, enc.ciphertext_len, kp.secret_key, kp.secret_key_len, NULL);
    assert(ret == ERR_INVALID_ARGUMENT);

    ret = kem_adapter_decapsulate(enc.ciphertext, enc.ciphertext_len, kp.secret_key, kp.secret_key_len, ss);
    assert(ret == PQC_SUCCESS);

    ret = kem_adapter_verify_decapsulation(NULL, ss);
    assert(ret == ERR_INVALID_ARGUMENT);

    ret = kem_adapter_verify_decapsulation(enc.shared_secret, NULL);
    assert(ret == ERR_INVALID_ARGUMENT);

    ret = kem_adapter_verify_decapsulation(enc.shared_secret, ss);
    assert(ret == PQC_SUCCESS);

    uint8_t wrong_ss[32] = {0};
    ret = kem_adapter_verify_decapsulation(enc.shared_secret, wrong_ss);
    assert(ret == ERR_CRYPTO_FAILURE);

    crypto_zeroize(&kp, sizeof(kp));
    crypto_zeroize(&enc, sizeof(enc));
    crypto_zeroize(ss, 32);

    printf("  PASS\n");
}

static void test_adapter_derive_functions(void) {
    printf("Testing adapter derive functions...\n");

    kem_adapter_init(KEMLIB_ML_KEM_768);

    kem_keypair_t kp;
    kem_encapsulation_t enc;
    uint8_t ss[32];
    uint8_t out[32];

    pqc_status_t ret = kem_adapter_keypair(&kp);
    assert(ret == PQC_SUCCESS);

    ret = kem_adapter_encapsulate(kp.public_key, kp.public_key_len, &enc);
    assert(ret == PQC_SUCCESS);

    ret = kem_adapter_decapsulate(enc.ciphertext, enc.ciphertext_len, kp.secret_key, kp.secret_key_len, ss);
    assert(ret == PQC_SUCCESS);

    ret = kem_adapter_derive_session_key(ss, NULL, 0, (uint8_t*)"test", 4, out);
    assert(ret == PQC_SUCCESS);

    ret = kem_adapter_derive_session_key(ss, (uint8_t*)"salt", 4, (uint8_t*)"test", 4, out);
    assert(ret == PQC_SUCCESS);

    ret = kem_adapter_derive_pairwise_mask_seed(ss, 1, 2, 1, out);
    assert(ret == PQC_SUCCESS);

    ret = kem_adapter_derive_stream_mask_seed(ss, 1, 1, 0, out);
    assert(ret == PQC_SUCCESS);

    ret = kem_adapter_derive_shamir_secret(ss, 1, 1, out);
    assert(ret == PQC_SUCCESS);

    ret = kem_adapter_derive_session_key(NULL, NULL, 0, NULL, 0, out);
    assert(ret == ERR_INVALID_ARGUMENT);

    ret = kem_adapter_derive_session_key(ss, NULL, 0, NULL, 0, NULL);
    assert(ret == ERR_INVALID_ARGUMENT);

    crypto_zeroize(&kp, sizeof(kp));
    crypto_zeroize(&enc, sizeof(enc));
    crypto_zeroize(ss, 32);
    crypto_zeroize(out, 32);

    printf("  PASS\n");
}

static void test_adapter_derand(void) {
    printf("Testing adapter deterministic functions...\n");

    kem_adapter_init(KEMLIB_ML_KEM_768);

    uint8_t seed[48];
    for (int i = 0; i < 48; i++) seed[i] = i;

    kem_keypair_t kp1, kp2;
    pqc_status_t ret = kem_adapter_keypair_derand(&kp1, seed);
    assert(ret == PQC_SUCCESS);

    ret = kem_adapter_keypair_derand(&kp2, seed);
    assert(ret == PQC_SUCCESS);

    assert(memcmp(kp1.public_key, kp2.public_key, kp1.public_key_len) == 0);
    assert(memcmp(kp1.secret_key, kp2.secret_key, kp1.secret_key_len) == 0);

    kem_encapsulation_t enc1, enc2;
    ret = kem_adapter_encapsulate_derand(kp1.public_key, kp1.public_key_len, &enc1, seed);
    assert(ret == PQC_SUCCESS);

    ret = kem_adapter_encapsulate_derand(kp1.public_key, kp1.public_key_len, &enc2, seed);
    assert(ret == PQC_SUCCESS);

    assert(memcmp(enc1.ciphertext, enc2.ciphertext, enc1.ciphertext_len) == 0);
    assert(memcmp(enc1.shared_secret, enc2.shared_secret, enc1.shared_secret_len) == 0);

    ret = kem_adapter_keypair_derand(NULL, seed);
    assert(ret == ERR_INVALID_ARGUMENT);

    ret = kem_adapter_keypair_derand(&kp1, NULL);
    assert(ret == ERR_INVALID_ARGUMENT);

    ret = kem_adapter_encapsulate_derand(NULL, kp1.public_key_len, &enc1, seed);
    assert(ret == ERR_INVALID_ARGUMENT);

    ret = kem_adapter_encapsulate_derand(kp1.public_key, kp1.public_key_len, NULL, seed);
    assert(ret == ERR_INVALID_ARGUMENT);

    ret = kem_adapter_encapsulate_derand(kp1.public_key, kp1.public_key_len, &enc1, NULL);
    assert(ret == ERR_INVALID_ARGUMENT);

    crypto_zeroize(&kp1, sizeof(kp1));
    crypto_zeroize(&kp2, sizeof(kp2));
    crypto_zeroize(&enc1, sizeof(enc1));
    crypto_zeroize(&enc2, sizeof(enc2));

    printf("  PASS\n");
}

static void test_adapter_self_test(void) {
    printf("Testing adapter self_test...\n");

    for (int v = 0; v < 3; v++) {
        kem_adapter_init((kem_variant_t)v);
        pqc_status_t ret = kem_adapter_self_test();
        assert(ret == PQC_SUCCESS);
    }

    printf("  PASS\n");
}

int main(void) {
    test_adapter_init();
    test_adapter_get_sizes();
    test_adapter_keypair_roundtrip();
    test_adapter_invalid_inputs();
    test_adapter_derive_functions();
    test_adapter_derand();
    test_adapter_self_test();

    printf("\nAll adapter tests passed!\n");
    return 0;
}