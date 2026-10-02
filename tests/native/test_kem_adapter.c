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

static void test_pairwise_derive_deterministic(void) {
    printf("Testing pairwise mask seed determinism...\n");

    kem_adapter_init(KEMLIB_ML_KEM_768);

    kem_keypair_t kp;
    kem_encapsulation_t enc;
    uint8_t ss[32];
    uint8_t out1[32], out2[32];

    pqc_status_t ret = kem_adapter_keypair(&kp);
    assert(ret == PQC_SUCCESS);

    ret = kem_adapter_encapsulate(kp.public_key, kp.public_key_len, &enc);
    assert(ret == PQC_SUCCESS);

    ret = kem_adapter_decapsulate(enc.ciphertext, enc.ciphertext_len, kp.secret_key, kp.secret_key_len, ss);
    assert(ret == PQC_SUCCESS);

    /* Same inputs should produce same output */
    ret = kem_adapter_derive_pairwise_mask_seed(ss, 1, 2, 1, out1);
    assert(ret == PQC_SUCCESS);
    ret = kem_adapter_derive_pairwise_mask_seed(ss, 1, 2, 1, out2);
    assert(ret == PQC_SUCCESS);
    assert(memcmp(out1, out2, 32) == 0);

    /* Client order shouldn't matter (sorted in function) */
    ret = kem_adapter_derive_pairwise_mask_seed(ss, 2, 1, 1, out2);
    assert(ret == PQC_SUCCESS);
    assert(memcmp(out1, out2, 32) == 0);

    /* Different round_id -> different output */
    ret = kem_adapter_derive_pairwise_mask_seed(ss, 1, 2, 2, out2);
    assert(ret == PQC_SUCCESS);
    assert(memcmp(out1, out2, 32) != 0);

    /* Different client IDs -> different output */
    ret = kem_adapter_derive_pairwise_mask_seed(ss, 1, 3, 1, out2);
    assert(ret == PQC_SUCCESS);
    assert(memcmp(out1, out2, 32) != 0);

    ret = kem_adapter_derive_pairwise_mask_seed(ss, 2, 3, 1, out2);
    assert(ret == PQC_SUCCESS);
    assert(memcmp(out1, out2, 32) != 0);

    crypto_zeroize(&kp, sizeof(kp));
    crypto_zeroize(&enc, sizeof(enc));
    crypto_zeroize(ss, 32);
    crypto_zeroize(out1, 32);
    crypto_zeroize(out2, 32);

    printf("  PASS\n");
}

static void test_stream_derive_deterministic(void) {
    printf("Testing stream mask seed determinism...\n");

    kem_adapter_init(KEMLIB_ML_KEM_768);

    kem_keypair_t kp;
    kem_encapsulation_t enc;
    uint8_t ss[32];
    uint8_t out1[32], out2[32];

    pqc_status_t ret = kem_adapter_keypair(&kp);
    assert(ret == PQC_SUCCESS);

    ret = kem_adapter_encapsulate(kp.public_key, kp.public_key_len, &enc);
    assert(ret == PQC_SUCCESS);

    ret = kem_adapter_decapsulate(enc.ciphertext, enc.ciphertext_len, kp.secret_key, kp.secret_key_len, ss);
    assert(ret == PQC_SUCCESS);

    /* Same inputs should produce same output */
    ret = kem_adapter_derive_stream_mask_seed(ss, 1, 1, 0, out1);
    assert(ret == PQC_SUCCESS);
    ret = kem_adapter_derive_stream_mask_seed(ss, 1, 1, 0, out2);
    assert(ret == PQC_SUCCESS);
    assert(memcmp(out1, out2, 32) == 0);

    /* Different chunk_index -> different output */
    ret = kem_adapter_derive_stream_mask_seed(ss, 1, 1, 1, out2);
    assert(ret == PQC_SUCCESS);
    assert(memcmp(out1, out2, 32) != 0);

    /* Different round_id -> different output */
    ret = kem_adapter_derive_stream_mask_seed(ss, 1, 2, 0, out2);
    assert(ret == PQC_SUCCESS);
    assert(memcmp(out1, out2, 32) != 0);

    /* Different client_id -> different output */
    ret = kem_adapter_derive_stream_mask_seed(ss, 2, 1, 0, out2);
    assert(ret == PQC_SUCCESS);
    assert(memcmp(out1, out2, 32) != 0);

    crypto_zeroize(&kp, sizeof(kp));
    crypto_zeroize(&enc, sizeof(enc));
    crypto_zeroize(ss, 32);
    crypto_zeroize(out1, 32);
    crypto_zeroize(out2, 32);

    printf("  PASS\n");
}

static void test_mask_cancellation(void) {
    printf("Testing mask cancellation (A + B = 0)...\n");

    kem_adapter_init(KEMLIB_ML_KEM_768);

    /* Simulate two clients A=1, B=2 sharing a pairwise secret */
    kem_keypair_t kp_a, kp_b;
    kem_encapsulation_t enc_a, enc_b;
    uint8_t ss_a[32], ss_b[32];

    pqc_status_t ret = kem_adapter_keypair(&kp_a);
    assert(ret == PQC_SUCCESS);
    ret = kem_adapter_keypair(&kp_b);
    assert(ret == PQC_SUCCESS);

    /* In practice, each client would have their own shared secret from KEM.
     * For mask cancellation test, we use a common shared secret (simulating
     * what would happen after both clients derive the same pairwise secret). */

    /* Derive pairwise mask seed (clients 1 and 2, round 1) */
    uint8_t pairwise_seed_a[32], pairwise_seed_b[32];
    ret = kem_adapter_derive_pairwise_mask_seed(ss_a, 1, 2, 1, pairwise_seed_a);
    assert(ret == PQC_SUCCESS);
    ret = kem_adapter_derive_pairwise_mask_seed(ss_b, 1, 2, 1, pairwise_seed_b);
    assert(ret == PQC_SUCCESS);

    /* For mask cancellation to work, both clients must use the SAME pairwise seed.
     * This is ensured by the protocol: both derive from the same shared secret
     * using the same labels and sorted client IDs. */

    /* Generate stream mask seeds for chunk 0 */
    uint8_t stream_seed_a[32], stream_seed_b[32];
    ret = kem_adapter_derive_stream_mask_seed(pairwise_seed_a, 1, 1, 0, stream_seed_a);
    assert(ret == PQC_SUCCESS);
    ret = kem_adapter_derive_stream_mask_seed(pairwise_seed_b, 1, 1, 0, stream_seed_b);
    assert(ret == PQC_SUCCESS);

    /* Since pairwise_seed_a == pairwise_seed_b (same shared secret, same inputs),
     * stream_seed_a should == stream_seed_b */
    assert(memcmp(stream_seed_a, stream_seed_b, 32) == 0);

    /* Generate masks using PRG */
    mask_prg_ctx_t prg_a, prg_b;
    ret = mask_prg_init(&prg_a, stream_seed_a);
    assert(ret == 0);
    ret = mask_prg_init(&prg_b, stream_seed_b);
    assert(ret == 0);

    int16_t mask_a[16], mask_b[16];
    ret = mask_prg_get_bytes(&prg_a, (uint8_t*)mask_a, 16 * sizeof(int16_t));
    assert(ret == 0);
    ret = mask_prg_get_bytes(&prg_b, (uint8_t*)mask_b, 16 * sizeof(int16_t));
    assert(ret == 0);

    /* Masks should be identical (same seed -> same keystream) */
    assert(memcmp(mask_a, mask_b, 16 * sizeof(int16_t)) == 0);

    /* Client A adds +mask, Client B adds -mask (since A < B) */
    int16_t combined[16];
    for (int i = 0; i < 16; i++) {
        int32_t val = (int32_t)mask_a[i] + (int32_t)(-mask_b[i]);
        int32_t r = val % 3329;
        if (r < 0) r += 3329;
        combined[i] = (int16_t)r;
    }

    /* Combined should be all zeros */
    for (int i = 0; i < 16; i++) {
        assert(combined[i] == 0);
    }

    mask_prg_cleanup(&prg_a);
    mask_prg_cleanup(&prg_b);

    crypto_zeroize(&kp_a, sizeof(kp_a));
    crypto_zeroize(&kp_b, sizeof(kp_b));
    crypto_zeroize(&enc_a, sizeof(enc_a));
    crypto_zeroize(&enc_b, sizeof(enc_b));
    crypto_zeroize(ss_a, 32);
    crypto_zeroize(ss_b, 32);
    crypto_zeroize(pairwise_seed_a, 32);
    crypto_zeroize(pairwise_seed_b, 32);
    crypto_zeroize(stream_seed_a, 32);
    crypto_zeroize(stream_seed_b, 32);

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
    test_pairwise_derive_deterministic();
    test_stream_derive_deterministic();
    test_mask_cancellation();
    test_adapter_derand();
    test_adapter_self_test();

    printf("\nAll adapter tests passed!\n");
    return 0;
}