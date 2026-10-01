import os

def fix_stream_aggregator_c():
    path = r"C:\DROP\src\federated\stream_aggregator.c"
    content = '''#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "mask_prg.h"
#include "kem_adapter.h"
#include <stdint.h>

#define KYBER_Q 3329

static inline uint16_t barrett_reduce_q(uint32_t a) {
    uint32_t t = (a * 20159) >> 26;
    uint16_t r = (uint16_t)(a - t * KYBER_Q);
    return r >= KYBER_Q ? r - KYBER_Q : r;
}

pqc_status_t stream_aggregator_process_chunk(uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size, const uint8_t* shared_secret) {
    if (chunk_size > 256) return ERR_CHUNK_TOO_LARGE;
    if (chunk_size % 2 != 0) return ERR_CHUNK_TOO_SMALL;

    chunk_buffer_t* chunk_buf = scratch_get_chunk_buf();
    dma_double_buffer_t* dma_tx = scratch_get_dma_tx();

    uint8_t stream_seed[32];
    pqc_status_t ret = kem_adapter_derive_stream_mask_seed(
        shared_secret, client_id, round_id, chunk_index, stream_seed
    );
    if (ret != PQC_SUCCESS) return ret;

    mask_prg_init(stream_seed);
    int16_t mask[128];
    mask_prg_expand((uint8_t*)mask, chunk_size);

    int16_t* input = (int16_t*)chunk_buf->data;
    int16_t* output = (int16_t*)dma_tx->ping;
    size_t num_elements = chunk_size / 2;

    for (size_t i = 0; i < num_elements; i++) {
        int32_t sum = (int32_t)input[i] + (int32_t)mask[i];
        output[i] = (int16_t)barrett_reduce_q((uint32_t)sum);
    }

    crypto_zeroize(mask, sizeof(mask));
    crypto_zeroize(stream_seed, 32);
    return PQC_SUCCESS;
}

pqc_status_t stream_aggregator_unmask_chunk(uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size, const uint8_t* shared_secret) {
    if (chunk_size > 256) return ERR_CHUNK_TOO_LARGE;
    if (chunk_size % 2 != 0) return ERR_CHUNK_TOO_SMALL;

    chunk_buffer_t* chunk_buf = scratch_get_chunk_buf();
    dma_double_buffer_t* dma_tx = scratch_get_dma_tx();

    uint8_t stream_seed[32];
    pqc_status_t ret = kem_adapter_derive_stream_mask_seed(
        shared_secret, client_id, round_id, chunk_index, stream_seed
    );
    if (ret != PQC_SUCCESS) return ret;

    mask_prg_init(stream_seed);
    int16_t mask[128];
    mask_prg_expand((uint8_t*)mask, chunk_size);

    int16_t* input = (int16_t*)chunk_buf->data;
    int16_t* output = (int16_t*)dma_tx->ping;
    size_t num_elements = chunk_size / 2;

    for (size_t i = 0; i < num_elements; i++) {
        int32_t diff = (int32_t)input[i] - (int32_t)mask[i];
        output[i] = (int16_t)barrett_reduce_q((uint32_t)(diff + 3329));
    }

    crypto_zeroize(mask, sizeof(mask));
    crypto_zeroize(stream_seed, 32);
    return PQC_SUCCESS;
}
'''
    with open(path, "w") as f:
        f.write(content)
    print("Fixed stream_aggregator.c")

def fix_protocol_bridge_py():
    path = r"C:\DROP\host_server\protocol_bridge.py"
    with open(path, "r") as f:
        content = f.read()
    
    content = content.replace("DEFAULT_CHUNK_ELEMENTS = 128", "")
    content = content.replace("chunk_elements = round_state.chunk_size", "chunk_elements = round_state.chunk_size")
    
    with open(path, "w") as f:
        f.write(content)
    print("Fixed protocol_bridge.py")

def fix_kem_adapter_c():
    path = r"C:\DROP\src\pqc_engine\kem_adapter.c"
    content = '''#include "kem_adapter.h"
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
    if (g_active_variant == KEMLIB_ML_KEM_X25519) {
        int ret = uECC_make_key(keypair->public_key, keypair->secret_key, uECC_curve25519());
        if (ret != TC_CRYPTO_SUCCESS) return ERR_KEM_KEYGEN_FAILED;
    } else {
        int ret = KEM_KEYPAIR_FN(keypair->public_key, keypair->secret_key);
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
    } else {
        int ret = KEM_ENCAP_FN(encap->ciphertext, encap->shared_secret, public_key);
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
    } else {
        int ret = KEM_DECAP_FN(shared_secret, ciphertext, secret_key);
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
    hkdf_expand(prk, 32, (const uint8_t*)KDF_LABEL_SESSION_KEY, strlen(KDF_LABEL_SESSION_KEY), session_key, 32);
    crypto_zeroize(prk, 32);
    crypto_zeroize(ws, sizeof(crypto_workspace_t));
    return PQC_SUCCESS;
}

pqc_status_t kem_adapter_derive_pairwise_mask_seed(const uint8_t* shared_secret, uint8_t client_id_a, uint8_t client_id_b, uint32_t round_id, uint8_t* mask_seed) {
    if (!shared_secret || !mask_seed) return ERR_INVALID_ARGUMENT;
    crypto_workspace_t* ws = scratch_get_crypto_ws();
    uint8_t info[64];
    size_t info_len = 0;
    info[info_len++] = client_id_a;
    info[info_len++] = client_id_b;
    info[info_len++] = (round_id >> 24) & 0xFF;
    info[info_len++] = (round_id >> 16) & 0xFF;
    info[info_len++] = (round_id >> 8) & 0xFF;
    info[info_len++] = round_id & 0xFF;
    uint8_t prk[32];
    hkdf_extract(NULL, 0, shared_secret, g_ss_bytes, prk);
    hkdf_expand(prk, 32, (const uint8_t*)KDF_LABEL_PAIRWISE_MASK, strlen(KDF_LABEL_PAIRWISE_MASK), mask_seed, 32);
    crypto_zeroize(prk, 32);
    crypto_zeroize(ws, sizeof(crypto_workspace_t));
    return PQC_SUCCESS;
}

pqc_status_t kem_adapter_derive_stream_mask_seed(const uint8_t* shared_secret, uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint8_t* stream_seed) {
    if (!shared_secret || !stream_seed) return ERR_INVALID_ARGUMENT;
    crypto_workspace_t* ws = scratch_get_crypto_ws();
    uint8_t info[64];
    size_t info_len = 0;
    info[info_len++] = client_id;
    info[info_len++] = (round_id >> 24) & 0xFF;
    info[info_len++] = (round_id >> 16) & 0xFF;
    info[info_len++] = (round_id >> 8) & 0xFF;
    info[info_len++] = round_id & 0xFF;
    info[info_len++] = (chunk_index >> 8) & 0xFF;
    info[info_len++] = chunk_index & 0xFF;
    uint8_t prk[32];
    hkdf_extract(NULL, 0, shared_secret, g_ss_bytes, prk);
    hkdf_expand(prk, 32, (const uint8_t*)KDF_LABEL_STREAM_MASK, strlen(KDF_LABEL_STREAM_MASK), stream_seed, 32);
    crypto_zeroize(prk, 32);
    crypto_zeroize(ws, sizeof(crypto_workspace_t));
    return PQC_SUCCESS;
}

pqc_status_t kem_adapter_derive_shamir_secret(const uint8_t* shared_secret, uint8_t client_id, uint32_t round_id, uint8_t* shamir_secret) {
    if (!shared_secret || !shamir_secret) return ERR_INVALID_ARGUMENT;
    crypto_workspace_t* ws = scratch_get_crypto_ws();
    uint8_t info[64];
    size_t info_len = 0;
    info[info_len++] = client_id;
    info[info_len++] = (round_id >> 24) & 0xFF;
    info[info_len++] = (round_id >> 16) & 0xFF;
    info[info_len++] = (round_id >> 8) & 0xFF;
    info[info_len++] = round_id & 0xFF;
    uint8_t prk[32];
    hkdf_extract(NULL, 0, shared_secret, g_ss_bytes, prk);
    hkdf_expand(prk, 32, (const uint8_t*)KDF_LABEL_SHAMIR_SECRET, strlen(KDF_LABEL_SHAMIR_SECRET), shamir_secret, 32);
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
'''
    with open(path, "w") as f:
        f.write(content)
    print("Fixed kem_adapter.c")

def fix_kem_adapter_h():
    path = r"C:\DROP\src\pqc_engine\kem_adapter.h"
    content = '''#ifndef KEM_ADAPTER_H
#define KEM_ADAPTER_H

#include "protocol_types.h"
#include "memory_scratchpad.h"
#include <stdint.h>
#include <stddef.h>

#define KEM_ADAPTER_MAX_PK_BYTES   ML_KEM_1024_PUBLIC_KEY_BYTES
#define KEM_ADAPTER_MAX_SK_BYTES   ML_KEM_1024_SECRET_KEY_BYTES
#define KEM_ADAPTER_MAX_CT_BYTES   ML_KEM_1024_CIPHERTEXT_BYTES
#define KEM_ADAPTER_SS_BYTES       ML_KEM_1024_SHARED_SECRET_BYTES

#define KDF_LABEL_KEM_SHARED      "MLKEM-SharedSecret-v1"
#define KDF_LABEL_PAIRWISE_MASK   "SwiftAgg-PairwiseMask-v1"
#define KDF_LABEL_STREAM_MASK     "SwiftAgg-StreamMask-v1"
#define KDF_LABEL_SHAMIR_SECRET   "SwiftAgg-ShamirSecret-v1"
#define KDF_LABEL_SESSION_KEY     "FL-SessionKey-v1"

#define KEMLIB_ML_KEM_X25519 3

#ifdef __cplusplus
extern "C" {
#endif

pqc_status_t kem_adapter_init(kem_variant_t variant);
kem_variant_t kem_adapter_get_variant(void);
pqc_status_t kem_adapter_get_sizes(size_t* pk_bytes, size_t* sk_bytes, size_t* ct_bytes, size_t* ss_bytes);
pqc_status_t kem_adapter_keypair(kem_keypair_t* keypair);
pqc_status_t kem_adapter_encapsulate(const uint8_t* public_key, size_t pk_len, kem_encapsulation_t* encap);
pqc_status_t kem_adapter_decapsulate(const uint8_t* ciphertext, size_t ct_len, const uint8_t* secret_key, size_t sk_len, uint8_t* shared_secret);
pqc_status_t kem_adapter_derive_session_key(const uint8_t* shared_secret, const uint8_t* salt, size_t salt_len, const uint8_t* info, size_t info_len, uint8_t* session_key);
pqc_status_t kem_adapter_derive_pairwise_mask_seed(const uint8_t* shared_secret, uint8_t client_id_a, uint8_t client_id_b, uint32_t round_id, uint8_t* mask_seed);
pqc_status_t kem_adapter_derive_stream_mask_seed(const uint8_t* shared_secret, uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint8_t* stream_seed);
pqc_status_t kem_adapter_derive_shamir_secret(const uint8_t* shared_secret, uint8_t client_id, uint32_t round_id, uint8_t* shamir_secret);
pqc_status_t kem_adapter_zeroize_scratchpad(void);
pqc_status_t kem_adapter_self_test(void);
uint32_t kem_adapter_get_last_cycles(void);

pqc_status_t classical_x25519_keypair(uint8_t* pk, uint8_t* sk);
pqc_status_t classical_x25519_encap(uint8_t* ct, uint8_t* ss, const uint8_t* pk);
pqc_status_t classical_x25519_decap(uint8_t* ss, const uint8_t* ct, const uint8_t* sk);

#ifdef __cplusplus
}
#endif

#endif
'''
    with open(path, "w") as f:
        f.write(content)
    print("Fixed kem_adapter.h")

def fix_dma_transport_c():
    path = r"C:\DROP\src\network\dma_transport.c"
    content = '''#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "dma_isr_handler.h"
#include "transport.h"
#include "impairment.h"
#include <stdint.h>
#include <string.h>

#define DMA_CHUNK_SIZE 256

static int g_rx_sock = -1;
static int g_tx_sock = -1;
static uint8_t g_dma_rx_pending = 0;
static uint8_t g_dma_tx_pending = 0;
static impairment_config_t g_impairment_config = {0};

pqc_status_t dma_transport_init(int rx_sock, int tx_sock) {
    g_rx_sock = rx_sock;
    g_tx_sock = tx_sock;
    g_dma_rx_pending = 0;
    g_dma_tx_pending = 0;
    dma_isr_init();
    impairment_init(&g_impairment_config);
    return PQC_SUCCESS;
}

pqc_status_t dma_transport_set_impairment(const impairment_config_t* config) {
    if (!config) return ERR_INVALID_ARGUMENT;
    impairment_init(config);
    return PQC_SUCCESS;
}

pqc_status_t dma_transport_rx_poll(void) {
    if (g_rx_sock < 0 || g_dma_rx_pending) return ERR_INVALID_STATE;
    uint8_t* buf = dma_get_rx_buffer();
    size_t received;
    pqc_status_t ret = impairment_recv(g_rx_sock, buf, DMA_CHUNK_SIZE, &received);
    if (ret == PQC_SUCCESS && received > 0) {
        g_dma_rx_pending = 1;
        dma_isr_rx_complete();
    }
    return ret;
}

pqc_status_t dma_transport_tx_poll(void) {
    if (g_tx_sock < 0 || !g_dma_tx_pending) return ERR_INVALID_STATE;
    uint8_t* buf = dma_get_tx_buffer();
    size_t sent;
    pqc_status_t ret = impairment_send(g_tx_sock, buf, DMA_CHUNK_SIZE, &sent);
    if (ret == PQC_SUCCESS) {
        g_dma_tx_pending = 0;
        dma_isr_tx_complete();
    }
    return ret;
}

pqc_status_t dma_transport_queue_tx(const uint8_t* data, size_t len) {
    if (!data || len > DMA_CHUNK_SIZE || g_dma_tx_pending) return ERR_INVALID_ARGUMENT;
    uint8_t* buf = dma_get_tx_buffer();
    memcpy(buf, data, len);
    g_dma_tx_pending = 1;
    return PQC_SUCCESS;
}

pqc_status_t dma_transport_get_rx_data(uint8_t* out, size_t* len) {
    if (!out || !len || !g_dma_rx_pending) return ERR_INVALID_STATE;
    uint8_t* buf = dma_get_rx_buffer();
    *len = DMA_CHUNK_SIZE;
    memcpy(out, buf, DMA_CHUNK_SIZE);
    g_dma_rx_pending = 0;
    return PQC_SUCCESS;
}

void dma_transport_rx_complete_callback(void) {
    g_dma_rx_pending = 0;
}

void dma_transport_tx_complete_callback(void) {
    g_dma_tx_pending = 0;
}
'''
    with open(path, "w") as f:
        f.write(content)
    print("Fixed dma_transport.c")

def create_renode_script():
    path = r"C:\DROP\emulation\multi_node.resc"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    content = '''using sysbus = Renode.Peripherals.Bus.Bus
using switch = Renode.Networking.Switch
using emulator = Renode.Core.Emulator
using cpu = Renode.Peripherals.CPU.CortexM
using machine = Renode.Peripherals.MachineRegistration
using gpio = Renode.Peripherals.GPIOPort
using uart = Renode.Peripherals.UART
using timer = Renode.Peripherals.Timers.SysTick
using flash = Renode.Peripherals.Flash
using network = Renode.Networking

$bin = @C:\\DROP\\build\\cortex_m4\\firmware.elf

emulator SetGlobalQuantum "100000"

$num_nodes = 10

$switch = switch.CreateSwitch()
$switch.Name = "virtual_switch"

for $i in 0..($num_nodes - 1)
    $node_name = sprintf("node%d", $i)
    emu $node_name = emulator.Create()
    $node_name.LoadPlatformDescription(@platforms/cpus/cortex_m4_nucleo_f446re.repl)
    $node_name.SetMachineName($node_name)
    
    $node_name.LoadBinary($bin)
    
    $node_name.Machine.RegisterEmailNotifier("renode")
    
    $node_name.Sysbus.usart2.Connect($switch)
    
    $node_name.Sysbus.gpiob.Pin9.Connect($node_name.Sysbus.led1)
    $node_name.Sysbus.gpiob.Pin14.Connect($node_name.Sysbus.led2)
    
    $node_name.CPU.Configure("0x08000000", "0x20000000", "0x10000", "0x1000")
    $node_name.CPU.SetRegister("PC", "0x08000004")
    $node_name.CPU.SetRegister("SP", "0x20020000")
    
    $node_name.Start()
end

$switch.Enable()
$switch.SetPromiscuousMode(true)

for $i in 0..($num_nodes - 1)
    $node_name = sprintf("node%d", $i)
    emu $node_name.PrintCPUInfo()
end

macro start_all()
    for $i in 0..($num_nodes - 1)
        $node_name = sprintf("node%d", $i)
        emu $node_name.Start()
    end
end

macro pause_all()
    for $i in 0..($num_nodes - 1)
        $node_name = sprintf("node%d", $i)
        emu $node_name.Pause()
    end
end

macro reset_all()
    for $i in 0..($num_nodes - 1)
        $node_name = sprintf("node%d", $i)
        emu $node_name.Reset()
    end
end

print "Multi-node emulation ready. Use 'start_all' to begin."
'''
    with open(path, "w") as f:
        f.write(content)
    print("Created multi_node.resc")

if __name__ == "__main__":
    fix_stream_aggregator_c()
    fix_protocol_bridge_py()
    fix_kem_adapter_c()
    fix_kem_adapter_h()
    fix_dma_transport_c()
    create_renode_script()
    print("Batch 3 modifications completed successfully.")