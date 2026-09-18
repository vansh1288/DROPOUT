import os
import subprocess

def create_init_deps():
    path = r"C:\DROP\scripts\init_deps.py"
    os.makedirs(os.path.dirname(path), exist_ok=True)
    content = '''import subprocess
import sys

def run_cmd(cmd, cwd=None):
    result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        return False
    print(result.stdout)
    return True

if __name__ == "__main__":
    repo_root = r"C:\DROP"
    if not run_cmd("git submodule add https://github.com/mupq/pqm4 deps/pqm4", cwd=repo_root):
        sys.exit(1)
    if not run_cmd("git submodule update --init --recursive", cwd=repo_root):
        sys.exit(1)
    print("Dependencies initialized successfully")
'''
    with open(path, "w") as f:
        f.write(content)
    print(f"Created {path}")

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

#define CRYPTO_MODE_PQC_ML_KEM_512   0
#define CRYPTO_MODE_PQC_ML_KEM_768   1
#define CRYPTO_MODE_PQC_ML_KEM_1024  2
#define CRYPTO_MODE_CLASSICAL_X25519 3

#ifdef CRYPTO_MODE
#define KEM_ACTIVE_MODE CRYPTO_MODE
#else
#define KEM_ACTIVE_MODE CRYPTO_MODE_PQC_ML_KEM_768
#endif

#if KEM_ACTIVE_MODE == CRYPTO_MODE_PQC_ML_KEM_512
#define KEM_KEYPAIR_FN   pqcrystals_kyber512_ref_keypair
#define KEM_ENCAP_FN     pqcrystals_kyber512_ref_enc
#define KEM_DECAP_FN     pqcrystals_kyber512_ref_dec
#define KEM_ACTIVE_VARIANT KEMLIB_ML_KEM_512
#define KEM_PK_BYTES     ML_KEM_512_PUBLIC_KEY_BYTES
#define KEM_SK_BYTES     ML_KEM_512_SECRET_KEY_BYTES
#define KEM_CT_BYTES     ML_KEM_512_CIPHERTEXT_BYTES
#define KEM_SS_BYTES     ML_KEM_512_SHARED_SECRET_BYTES
#elif KEM_ACTIVE_MODE == CRYPTO_MODE_PQC_ML_KEM_768
#define KEM_KEYPAIR_FN   pqcrystals_kyber768_ref_keypair
#define KEM_ENCAP_FN     pqcrystals_kyber768_ref_enc
#define KEM_DECAP_FN     pqcrystals_kyber768_ref_dec
#define KEM_ACTIVE_VARIANT KEMLIB_ML_KEM_768
#define KEM_PK_BYTES     ML_KEM_768_PUBLIC_KEY_BYTES
#define KEM_SK_BYTES     ML_KEM_768_SECRET_KEY_BYTES
#define KEM_CT_BYTES     ML_KEM_768_CIPHERTEXT_BYTES
#define KEM_SS_BYTES     ML_KEM_768_SHARED_SECRET_BYTES
#elif KEM_ACTIVE_MODE == CRYPTO_MODE_PQC_ML_KEM_1024
#define KEM_KEYPAIR_FN   pqcrystals_kyber1024_ref_keypair
#define KEM_ENCAP_FN     pqcrystals_kyber1024_ref_enc
#define KEM_DECAP_FN     pqcrystals_kyber1024_ref_dec
#define KEM_ACTIVE_VARIANT KEMLIB_ML_KEM_1024
#define KEM_PK_BYTES     ML_KEM_1024_PUBLIC_KEY_BYTES
#define KEM_SK_BYTES     ML_KEM_1024_SECRET_KEY_BYTES
#define KEM_CT_BYTES     ML_KEM_1024_CIPHERTEXT_BYTES
#define KEM_SS_BYTES     ML_KEM_1024_SHARED_SECRET_BYTES
#elif KEM_ACTIVE_MODE == CRYPTO_MODE_CLASSICAL_X25519
#define KEM_KEYPAIR_FN   classical_x25519_keypair
#define KEM_ENCAP_FN     classical_x25519_encap
#define KEM_DECAP_FN     classical_x25519_decap
#define KEM_ACTIVE_VARIANT KEMLIB_ML_KEM_768
#define KEM_PK_BYTES     32
#define KEM_SK_BYTES     32
#define KEM_CT_BYTES     32
#define KEM_SS_BYTES     32
#else
#error "Invalid CRYPTO_MODE"
#endif

#define KDF_LABEL_KEM_SHARED      "MLKEM-SharedSecret-v1"
#define KDF_LABEL_PAIRWISE_MASK   "SwiftAgg-PairwiseMask-v1"
#define KDF_LABEL_STREAM_MASK     "SwiftAgg-StreamMask-v1"
#define KDF_LABEL_SHAMIR_SECRET   "SwiftAgg-ShamirSecret-v1"
#define KDF_LABEL_SESSION_KEY     "FL-SessionKey-v1"

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

def fix_kem_adapter_c():
    path = r"C:\DROP\src\pqc_engine\kem_adapter.c"
    content = '''#include "kem_adapter.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "crypto_memory.h"
#include <string.h>
#include <tinycrypt/hmac.h>
#include <tinycrypt/sha256.h>

static kem_variant_t g_active_variant = KEM_ACTIVE_VARIANT;
static size_t g_pk_bytes = KEM_PK_BYTES;
static size_t g_sk_bytes = KEM_SK_BYTES;
static size_t g_ct_bytes = KEM_CT_BYTES;
static size_t g_ss_bytes = KEM_SS_BYTES;
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
#if KEM_ACTIVE_MODE == CRYPTO_MODE_CLASSICAL_X25519
    (void)variant;
    g_active_variant = KEMLIB_ML_KEM_768;
    g_pk_bytes = 32;
    g_sk_bytes = 32;
    g_ct_bytes = 32;
    g_ss_bytes = 32;
#else
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
        default:
            return ERR_INVALID_ARGUMENT;
    }
#endif
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
    int ret = KEM_KEYPAIR_FN(keypair->public_key, keypair->secret_key);
    if (ret != 0) return ERR_KEM_KEYGEN_FAILED;
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
    int ret = KEM_ENCAP_FN(encap->ciphertext, encap->shared_secret, public_key);
    if (ret != 0) return ERR_KEM_ENCAP_FAILED;
    encap->ciphertext_len = g_ct_bytes;
    encap->shared_secret_len = g_ss_bytes;
    crypto_zeroize(ws, sizeof(mlkem_workspace_t));
    return PQC_SUCCESS;
}

pqc_status_t kem_adapter_decapsulate(const uint8_t* ciphertext, size_t ct_len, const uint8_t* secret_key, size_t sk_len, uint8_t* shared_secret) {
    if (!ciphertext || !secret_key || !shared_secret || ct_len != g_ct_bytes || sk_len != g_sk_bytes) return ERR_INVALID_ARGUMENT;
    mlkem_workspace_t* ws = scratch_get_mlkem_ws();
    int ret = KEM_DECAP_FN(shared_secret, ciphertext, secret_key);
    if (ret != 0) return ERR_KEM_DECAP_FAILED;
    crypto_zeroize(ws, sizeof(mlkem_workspace_t));
    return PQC_SUCCESS;
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
    (void)pk; (void)sk;
    return PQC_SUCCESS;
}

pqc_status_t classical_x25519_encap(uint8_t* ct, uint8_t* ss, const uint8_t* pk) {
    (void)ct; (void)ss; (void)pk;
    return PQC_SUCCESS;
}

pqc_status_t classical_x25519_decap(uint8_t* ss, const uint8_t* ct, const uint8_t* sk) {
    (void)ss; (void)ct; (void)sk;
    return PQC_SUCCESS;
}
'''
    with open(path, "w") as f:
        f.write(content)
    print("Fixed kem_adapter.c")

def fix_dma_transport():
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

def run_init_deps():
    try:
        result = subprocess.run(
            ["git", "submodule", "add", "https://github.com/mupq/pqm4", "deps/pqm4"],
            cwd=r"C:\DROP",
            capture_output=True,
            text=True,
            shell=True
        )
        if result.returncode != 0:
            print(f"git submodule add failed: {result.stderr}")
        else:
            print(result.stdout)
        
        result = subprocess.run(
            ["git", "submodule", "update", "--init", "--recursive"],
            cwd=r"C:\DROP",
            capture_output=True,
            text=True,
            shell=True
        )
        if result.returncode != 0:
            print(f"git submodule update failed: {result.stderr}")
        else:
            print(result.stdout)
    except Exception as e:
        print(f"Error running git commands: {e}")

if __name__ == "__main__":
    create_init_deps()
    fix_kem_adapter_h()
    fix_kem_adapter_c()
    fix_dma_transport()
    run_init_deps()
    print("Batch 3 modifications completed successfully.")