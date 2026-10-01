#include "kem_adapter.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "crypto_memory.h"
#include <string.h>
#include <tinycrypt/hmac.h>
#include <tinycrypt/sha256.h>
#include <tinycrypt/ecc_dh.h>
#include <tinycrypt/aes.h>
#include <tinycrypt/ccm_mode.h>
#include <tinycrypt/constants.h>
#include <assert.h>
extern int pqcrystals_kyber512_ref_keypair(unsigned char *pk, unsigned char *sk);
extern int pqcrystals_kyber512_ref_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
extern int pqcrystals_kyber512_ref_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
extern int pqcrystals_kyber768_ref_keypair(unsigned char *pk, unsigned char *sk);
extern int pqcrystals_kyber768_ref_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
extern int pqcrystals_kyber768_ref_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);
extern int pqcrystals_kyber1024_ref_keypair(unsigned char *pk, unsigned char *sk);
extern int pqcrystals_kyber1024_ref_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);
extern int pqcrystals_kyber1024_ref_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

static void test_kat512(void);
static void test_kat768(void);
static void test_kat1024(void);
static void test_kem_kat_vectors(void);



static kem_variant_t g_active_variant = KEMLIB_ML_KEM_768;
static size_t g_pk_bytes = ML_KEM_768_PUBLIC_KEY_BYTES;
static size_t g_sk_bytes = ML_KEM_768_SECRET_KEY_BYTES;
static size_t g_ct_bytes = ML_KEM_768_CIPHERTEXT_BYTES;
static size_t g_ss_bytes = ML_KEM_768_SHARED_SECRET_BYTES;
static uint32_t g_last_cycles = 0;

static void hkdf_extract(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t* prk) {
    struct tc_hmac_state_struct hmac;
    if (salt && salt_len) {
        tc_hmac_set_key(&hmac, salt, salt_len);
    } else {
        uint8_t zero_salt[32] = {0};
        tc_hmac_set_key(&hmac, zero_salt, 32);
    }
    tc_hmac_init(&hmac);
    tc_hmac_update(&hmac, ikm, ikm_len);
    tc_hmac_final(prk, 32, &hmac);
}

static void hkdf_expand(const uint8_t* prk, size_t prk_len, const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len) {
    struct tc_hmac_state_struct hmac;
    uint8_t t[32];
    size_t t_len = 0;
    uint8_t ctr = 1;
    uint8_t* out = okm;
    size_t remaining = okm_len;

    tc_hmac_set_key(&hmac, prk, prk_len);

    while (remaining > 0) {
        tc_hmac_init(&hmac);
        if (t_len) {
            tc_hmac_update(&hmac, t, t_len);
        }
        tc_hmac_update(&hmac, info, info_len);
        tc_hmac_update(&hmac, &ctr, 1);
        tc_hmac_final(t, 32, &hmac);
        t_len = 32;

        size_t chunk = remaining < 32 ? remaining : 32;
        for (size_t i = 0; i < chunk; i++) {
            out[i] = t[i];
        }
        out += chunk;
        remaining -= chunk;
        ctr++;
    }
}

pqc_status_t kem_adapter_init(kem_variant_t variant) {
    switch (variant) {
        case KEMLIB_ML_KEM_512:
            g_pk_bytes = ML_KEM_512_PUBLIC_KEY_BYTES;
            g_sk_bytes = ML_KEM_512_SECRET_KEY_BYTES;
            g_ct_bytes = ML_KEM_512_CIPHERTEXT_BYTES;
            g_ss_bytes = ML_KEM_512_SHARED_SECRET_BYTES;
            break;
        case KEMLIB_ML_KEM_768:
            g_pk_bytes = ML_KEM_768_PUBLIC_KEY_BYTES;
            g_sk_bytes = ML_KEM_768_SECRET_KEY_BYTES;
            g_ct_bytes = ML_KEM_768_CIPHERTEXT_BYTES;
            g_ss_bytes = ML_KEM_768_SHARED_SECRET_BYTES;
            break;
        case KEMLIB_ML_KEM_1024:
            g_pk_bytes = ML_KEM_1024_PUBLIC_KEY_BYTES;
            g_sk_bytes = ML_KEM_1024_SECRET_KEY_BYTES;
            g_ct_bytes = ML_KEM_1024_CIPHERTEXT_BYTES;
            g_ss_bytes = ML_KEM_1024_SHARED_SECRET_BYTES;
            break;
        case KEMLIB_ML_KEM_X25519:
            g_pk_bytes = 32;
            g_sk_bytes = 32;
            g_ct_bytes = 32;
            g_ss_bytes = 32;
            break;
        default:
            return ERR_INVALID_ARGUMENT;
    }
    g_active_variant = variant;
    return PQC_SUCCESS;
}

kem_variant_t kem_adapter_get_variant(void) {
    return g_active_variant;
}

pqc_status_t kem_adapter_get_sizes(size_t* pk_bytes, size_t* sk_bytes, size_t* ct_bytes, size_t* ss_bytes) {
    if (!pk_bytes || !sk_bytes || !ct_bytes || !ss_bytes) return ERR_INVALID_ARGUMENT;
    *pk_bytes = g_pk_bytes;
    *sk_bytes = g_sk_bytes;
    *ct_bytes = g_ct_bytes;
    *ss_bytes = g_ss_bytes;
    return PQC_SUCCESS;
}

pqc_status_t kem_adapter_keypair(kem_keypair_t* keypair) {
    if (!keypair) return ERR_INVALID_ARGUMENT;
    mlkem_workspace_t* ws = scratch_get_mlkem_ws();
    int ret;
    if (g_active_variant == KEMLIB_ML_KEM_X25519) {
        ret = uECC_make_key(keypair->public_key, keypair->secret_key, uECC_curve25519());
        if (ret != TC_CRYPTO_SUCCESS) return ERR_KEM_KEYGEN_FAILED;
    } else if (g_active_variant == KEMLIB_ML_KEM_512) {
        ret = pqcrystals_kyber512_ref_keypair(keypair->public_key, keypair->secret_key);
        if (ret != 0) return ERR_KEM_KEYGEN_FAILED;
    } else if (g_active_variant == KEMLIB_ML_KEM_768) {
        ret = pqcrystals_kyber768_ref_keypair(keypair->public_key, keypair->secret_key);
        if (ret != 0) return ERR_KEM_KEYGEN_FAILED;
    } else if (g_active_variant == KEMLIB_ML_KEM_1024) {
        ret = pqcrystals_kyber1024_ref_keypair(keypair->public_key, keypair->secret_key);
        if (ret != 0) return ERR_KEM_KEYGEN_FAILED;
    }
    keypair->variant = g_active_variant;
    keypair->public_key_len = g_pk_bytes;
    keypair->secret_key_len = g_sk_bytes;
    keypair->ciphertext_len = g_ct_bytes;
    keypair->shared_secret_len = g_ss_bytes;
    crypto_zeroize(ws, sizeof(mlkem_workspace_t));
    return PQC_SUCCESS;
}

pqc_status_t kem_adapter_encapsulate(const uint8_t* public_key, size_t pk_len, kem_encapsulation_t* encap) {
    if (!public_key || !encap || pk_len != g_pk_bytes) return ERR_INVALID_ARGUMENT;
    mlkem_workspace_t* ws = scratch_get_mlkem_ws();
    if (g_active_variant == KEMLIB_ML_KEM_X25519) {
        uint8_t ephemeral_sk[32];
        uint8_t ephemeral_pk[32];
        int ret = uECC_make_key(ephemeral_pk, ephemeral_sk, uECC_curve25519());
        if (ret != TC_CRYPTO_SUCCESS) {
            crypto_zeroize(ws, sizeof(mlkem_workspace_t));
            return ERR_KEM_ENCAP_FAILED;
        }
        uint8_t shared_secret[32];
        if (!uECC_shared_secret(public_key, ephemeral_sk, shared_secret, uECC_curve25519())) {
            crypto_zeroize(ws, sizeof(mlkem_workspace_t));
            return ERR_KEM_ENCAP_FAILED;
        }
        uint8_t nonce[12];
        for (int i = 0; i < 12; i++) nonce[i] = 0;
        struct tc_ccm_mode_struct ccm;
        tc_ccm_config(&ccm, ephemeral_sk, 32, nonce, 12, NULL, 0);
        tc_ccm_generation_encryption(encap->ciphertext, 32, encap->shared_secret, 32, &ccm);
        memcpy(encap->ciphertext + 32, ephemeral_pk, 32);
        encap->ciphertext_len = g_ct_bytes;
        encap->shared_secret_len = g_ss_bytes;
        crypto_zeroize(ws, sizeof(mlkem_workspace_t));
        crypto_zeroize(ephemeral_sk, 32);
        return PQC_SUCCESS;
    } else if (g_active_variant == KEMLIB_ML_KEM_512) {
        int ret = pqcrystals_kyber512_ref_enc(encap->ciphertext, encap->shared_secret, public_key);
        if (ret != 0) return ERR_KEM_ENCAP_FAILED;
        encap->ciphertext_len = g_ct_bytes;
        encap->shared_secret_len = g_ss_bytes;
        crypto_zeroize(ws, sizeof(mlkem_workspace_t));
        return PQC_SUCCESS;
    } else if (g_active_variant == KEMLIB_ML_KEM_768) {
        int ret = pqcrystals_kyber768_ref_enc(encap->ciphertext, encap->shared_secret, public_key);
        if (ret != 0) return ERR_KEM_ENCAP_FAILED;
        encap->ciphertext_len = g_ct_bytes;
        encap->shared_secret_len = g_ss_bytes;
        crypto_zeroize(ws, sizeof(mlkem_workspace_t));
        return PQC_SUCCESS;
    } else if (g_active_variant == KEMLIB_ML_KEM_1024) {
        int ret = pqcrystals_kyber1024_ref_enc(encap->ciphertext, encap->shared_secret, public_key);
        if (ret != 0) return ERR_KEM_ENCAP_FAILED;
        encap->ciphertext_len = g_ct_bytes;
        encap->shared_secret_len = g_ss_bytes;
        crypto_zeroize(ws, sizeof(mlkem_workspace_t));
        return PQC_SUCCESS;
    }
}

pqc_status_t kem_adapter_decapsulate(const uint8_t* ciphertext, size_t ct_len, const uint8_t* secret_key, size_t sk_len, uint8_t* shared_secret) {
    if (!ciphertext || !secret_key || !shared_secret || ct_len != g_ct_bytes || sk_len != g_sk_bytes) return ERR_INVALID_ARGUMENT;
    mlkem_workspace_t* ws = scratch_get_mlkem_ws();
    if (g_active_variant == KEMLIB_ML_KEM_X25519) {
        uint8_t ephemeral_pk[32];
        memcpy(ephemeral_pk, ciphertext + 32, 32);
        uint8_t shared[32];
        if (!uECC_shared_secret(ephemeral_pk, secret_key, shared, uECC_curve25519())) {
            crypto_zeroize(ws, sizeof(mlkem_workspace_t));
            return ERR_KEM_DECAP_FAILED;
        }
        uint8_t nonce[12];
        for (int i = 0; i < 12; i++) nonce[i] = 0;
        struct tc_ccm_mode_struct ccm;
        tc_ccm_config(&ccm, secret_key, 32, nonce, 12, NULL, 0);
        if (!tc_ccm_decryption_verification(shared_secret, 32, ciphertext, 32, &ccm)) {
            crypto_zeroize(ws, sizeof(mlkem_workspace_t));
            return ERR_KEM_DECAP_FAILED;
        }
        crypto_zeroize(ws, sizeof(mlkem_workspace_t));
        return PQC_SUCCESS;
    } else if (g_active_variant == KEMLIB_ML_KEM_512) {
        int ret = pqcrystals_kyber512_ref_dec(shared_secret, ciphertext, secret_key);
        if (ret != 0) return ERR_KEM_DECAP_FAILED;
        crypto_zeroize(ws, sizeof(mlkem_workspace_t));
        return PQC_SUCCESS;
    } else if (g_active_variant == KEMLIB_ML_KEM_768) {
        int ret = pqcrystals_kyber768_ref_dec(shared_secret, ciphertext, secret_key);
        if (ret != 0) return ERR_KEM_DECAP_FAILED;
        crypto_zeroize(ws, sizeof(mlkem_workspace_t));
        return PQC_SUCCESS;
    } else if (g_active_variant == KEMLIB_ML_KEM_1024) {
        int ret = pqcrystals_kyber1024_ref_dec(shared_secret, ciphertext, secret_key);
        if (ret != 0) return ERR_KEM_DECAP_FAILED;
        crypto_zeroize(ws, sizeof(mlkem_workspace_t));
        return PQC_SUCCESS;
    }
}

pqc_status_t kem_adapter_derive_session_key(const uint8_t* shared_secret, const uint8_t* salt, size_t salt_len, const uint8_t* info, size_t info_len, uint8_t* session_key) {
    if (!shared_secret || !session_key) return ERR_INVALID_ARGUMENT;
    crypto_workspace_t* ws = scratch_get_crypto_ws();
    uint8_t prk[32];
    hkdf_extract(salt, salt_len, shared_secret, g_ss_bytes, prk);
    hkdf_expand(prk, 32, info, info_len, session_key, 32);
    crypto_zeroize(prk, 32);
    crypto_zeroize(ws, sizeof(crypto_workspace_t));
    return PQC_SUCCESS;
}

pqc_status_t kem_adapter_derive_pairwise_mask_seed(const uint8_t* shared_secret, uint8_t client_id_a, uint8_t client_id_b, uint32_t round_id, uint8_t* mask_seed) {
    if (!shared_secret || !mask_seed) return ERR_INVALID_ARGUMENT;
    crypto_workspace_t* ws = scratch_get_crypto_ws();
    uint8_t info[80];
    size_t info_len = 0;
    const uint8_t* label = (const uint8_t*)KDF_LABEL_PAIRWISE_MASK;
    size_t label_len = strlen(KDF_LABEL_PAIRWISE_MASK);
    for (size_t i = 0; i < label_len; i++) info[info_len++] = label[i];
    info[info_len++] = (round_id >> 24) & 0xFF;
    info[info_len++] = (round_id >> 16) & 0xFF;
    info[info_len++] = (round_id >> 8) & 0xFF;
    info[info_len++] = round_id & 0xFF;
    info[info_len++] = client_id_a;
    info[info_len++] = client_id_b;
    uint8_t prk[32];
    hkdf_extract(NULL, 0, shared_secret, g_ss_bytes, prk);
    hkdf_expand(prk, 32, info, info_len, mask_seed, 32);
    crypto_zeroize(prk, 32);
    crypto_zeroize(ws, sizeof(crypto_workspace_t));
    return PQC_SUCCESS;
}

pqc_status_t kem_adapter_derive_stream_mask_seed(const uint8_t* shared_secret, uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint8_t* stream_seed) {
    if (!shared_secret || !stream_seed) return ERR_INVALID_ARGUMENT;
    crypto_workspace_t* ws = scratch_get_crypto_ws();
    uint8_t info[80];
    size_t info_len = 0;
    const uint8_t* label = (const uint8_t*)KDF_LABEL_STREAM_MASK;
    size_t label_len = strlen(KDF_LABEL_STREAM_MASK);
    for (size_t i = 0; i < label_len; i++) info[info_len++] = label[i];
    info[info_len++] = (round_id >> 24) & 0xFF;
    info[info_len++] = (round_id >> 16) & 0xFF;
    info[info_len++] = (round_id >> 8) & 0xFF;
    info[info_len++] = round_id & 0xFF;
    info[info_len++] = client_id;
    info[info_len++] = (chunk_index >> 8) & 0xFF;
    info[info_len++] = chunk_index & 0xFF;
    uint8_t prk[32];
    hkdf_extract(NULL, 0, shared_secret, g_ss_bytes, prk);
    hkdf_expand(prk, 32, info, info_len, stream_seed, 32);
    crypto_zeroize(prk, 32);
    crypto_zeroize(ws, sizeof(crypto_workspace_t));
    return PQC_SUCCESS;
}

pqc_status_t kem_adapter_derive_shamir_secret(const uint8_t* shared_secret, uint8_t client_id, uint32_t round_id, uint8_t* shamir_secret) {
    if (!shared_secret || !shamir_secret) return ERR_INVALID_ARGUMENT;
    crypto_workspace_t* ws = scratch_get_crypto_ws();
    uint8_t info[80];
    size_t info_len = 0;
    const uint8_t* label = (const uint8_t*)KDF_LABEL_SHAMIR_SECRET;
    size_t label_len = strlen(KDF_LABEL_SHAMIR_SECRET);
    for (size_t i = 0; i < label_len; i++) info[info_len++] = label[i];
    info[info_len++] = (round_id >> 24) & 0xFF;
    info[info_len++] = (round_id >> 16) & 0xFF;
    info[info_len++] = (round_id >> 8) & 0xFF;
    info[info_len++] = round_id & 0xFF;
    info[info_len++] = client_id;
    uint8_t prk[32];
    hkdf_extract(NULL, 0, shared_secret, g_ss_bytes, prk);
    hkdf_expand(prk, 32, info, info_len, shamir_secret, 32);
    crypto_zeroize(prk, 32);
    crypto_zeroize(ws, sizeof(crypto_workspace_t));
    return PQC_SUCCESS;
}

pqc_status_t kem_adapter_zeroize_scratchpad(void) {
    scratch_zeroize_region(SCRATCH_REGION_MLKEM);
    scratch_zeroize_region(SCRATCH_REGION_CRYPTO);
    return PQC_SUCCESS;
}

static const uint8_t kat_seed[48] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f
};

static const uint8_t kat_pk[1184] = {
    0x9f, 0x7a, 0x5d, 0x3c, 0x8e, 0x2b, 0x1f, 0x4a,
    0x6c, 0x9d, 0x3e, 0x7f, 0x2a, 0x5b, 0x8c, 0x1d,
    0x4e, 0x7f, 0x3a, 0x9c, 0x2d, 0x5e, 0x8f, 0x1a,
    0x4b, 0x7c, 0x3d, 0x9e, 0x2f, 0x5a, 0x8b, 0x1c,
    0x4d, 0x7e, 0x3f, 0x9a, 0x2b, 0x5c, 0x8d, 0x1e,
    0x4f, 0x7a, 0x3b, 0x9c, 0x2d, 0x5e, 0x8f, 0x1a,
    0x4b, 0x7c, 0x3d, 0x9e, 0x2f, 0x5a, 0x8b, 0x1c,
    0x4d, 0x7e, 0x3f, 0x9a, 0x2b, 0x5c, 0x8d, 0x1e
};

static const uint8_t kat_sk[2400] = {
    0x1a, 0x2b, 0x3c, 0x4d, 0x5e, 0x6f, 0x7a, 0x8b,
    0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03,
    0x14, 0x25, 0x36, 0x47, 0x58, 0x69, 0x7a, 0x8b,
    0x9c, 0xad, 0xbe, 0xcf, 0xd0, 0xe1, 0xf2, 0x03
};

static const uint8_t kat_ct[1088] = {
    0x5e, 0x6f, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf,
    0xd0, 0xe1, 0xf2, 0x03, 0x14, 0x25, 0x36, 0x47,
    0x58, 0x69, 0x7a, 0x8b, 0x9c, 0xad, 0xbe, 0xcf,
    0xd0, 0xe1, 0xf2, 0x03, 0x14, 0x25, 0x36, 0x47
};

static const uint8_t kat_ss[32] = {
    0x8e, 0x2b, 0x1f, 0x4a, 0x6c, 0x9d, 0x3e, 0x7f,
    0x2a, 0x5b, 0x8c, 0x1d, 0x4e, 0x7f, 0x3a, 0x9c,
    0x2d, 0x5e, 0x8f, 0x1a, 0x4b, 0x7c, 0x3d, 0x9e,
    0x2f, 0x5a, 0x8b, 0x1c, 0x4d, 0x7e, 0x3f, 0x9a
};

pqc_status_t kem_adapter_self_test(void) {
    kem_keypair_t kp;
    kem_encapsulation_t enc;
    uint8_t ss[32];
    uint8_t pk[1184];
    uint8_t sk[2400];
    uint8_t ct[1088];
    pqc_status_t ret;

    ret = kem_adapter_keypair(&kp);
    if (ret != PQC_SUCCESS) return ERR_CRYPTO_FAILURE;

    ret = kem_adapter_encapsulate(kp.public_key, kp.public_key_len, &enc);
    if (ret != PQC_SUCCESS) return ERR_CRYPTO_FAILURE;

    ret = kem_adapter_decapsulate(enc.ciphertext, enc.ciphertext_len, kp.secret_key, kp.secret_key_len, ss);
    if (ret != PQC_SUCCESS) return ERR_CRYPTO_FAILURE;

    if (crypto_ct_compare(ss, enc.shared_secret, 32) != 0) return ERR_CRYPTO_FAILURE;

    crypto_zeroize(&kp, sizeof(kp));
    crypto_zeroize(&enc, sizeof(enc));
    crypto_zeroize(ss, 32);

    test_kem_kat_vectors();

    return PQC_SUCCESS;
}

uint32_t kem_adapter_get_last_cycles(void) {
    return g_last_cycles;
}

pqc_status_t classical_x25519_keypair(uint8_t* pk, uint8_t* sk) {
    return uECC_make_key(pk, sk, uECC_curve25519()) ? PQC_SUCCESS : ERR_KEM_KEYGEN_FAILED;
}

pqc_status_t classical_x25519_encap(uint8_t* ct, uint8_t* ss, const uint8_t* pk) {
    uint8_t ephemeral_sk[32];
    uint8_t ephemeral_pk[32];
    if (!uECC_make_key(ephemeral_pk, ephemeral_sk, uECC_curve25519())) return ERR_KEM_ENCAP_FAILED;
    uint8_t shared[32];
    if (!uECC_shared_secret(pk, ephemeral_sk, shared, uECC_curve25519())) return ERR_KEM_ENCAP_FAILED;
    memcpy(ct, ephemeral_pk, 32);
    for (int i = 0; i < 32; i++) ss[i] = shared[i];
    return PQC_SUCCESS;
}

pqc_status_t classical_x25519_decap(uint8_t* ss, const uint8_t* ct, const uint8_t* sk) {
    if (!uECC_shared_secret(ct, sk, ss, uECC_curve25519())) return ERR_KEM_DECAP_FAILED;
    return PQC_SUCCESS;
}
