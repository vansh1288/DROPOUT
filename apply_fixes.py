import os

def modify_platformio_ini():
    path = r"C:\DROP\platformio.ini"
    with open(path, "r") as f:
        content = f.read()
    
    lib_deps_block = """lib_deps = 
    https://github.com/mupq/pqm4#main
    https://github.com/intel/tinycrypt#main"""
    
    content = content.replace(
        "[env:cortex_m4]\nplatform = ststm32",
        "[env:cortex_m4]\nplatform = ststm32\n" + lib_deps_block
    )
    content = content.replace(
        "[env:esp32c3]\nplatform = espressif32",
        "[env:esp32c3]\nplatform = espressif32\n" + lib_deps_block
    )
    
    with open(path, "w") as f:
        f.write(content)
    print("Modified platformio.ini")

def modify_kem_adapter_c():
    path = r"C:\DROP\src\pqc_engine\kem_adapter.c"
    new_content = '''#include "kem_adapter.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "crypto_memory.h"
#include <string.h>
#include <tinycrypt/hmac.h>
#include <tinycrypt/sha256.h>

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

pqc_status_t kem_adapter_self_test(void) {
    kem_keypair_t kp;
    kem_encapsulation_t enc;
    uint8_t ss[32];
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
'''
    with open(path, "w") as f:
        f.write(new_content)
    print("Modified kem_adapter.c")

def modify_mask_prg_c():
    path = r"C:\DROP\src\pqc_engine\mask_prg.c"
    new_content = '''#include "mask_prg.h"
#include <tinycrypt/aes.h>
#include <tinycrypt/ctr_mode.h>
#include <string.h>

static struct tc_aes_key_sched_struct g_aes_sched;
static uint8_t g_nonce[16] = {0};
static uint8_t g_ctr[16] = {0};

void mask_prg_init(const uint8_t seed[32]) {
    tc_aes256_set_encrypt_key(&g_aes_sched, seed);
    memset(g_nonce, 0, 16);
    memset(g_ctr, 0, 16);
}

void mask_prg_reseed(const uint8_t seed[32]) {
    mask_prg_init(seed);
}

void mask_prg_expand(uint8_t* out, size_t len) {
    size_t generated = 0;
    while (generated < len) {
        size_t chunk = len - generated;
        if (chunk > 16) chunk = 16;
        tc_ctr_mode(out + generated, chunk, g_nonce, g_ctr, &g_aes_sched);
        generated += chunk;
    }
}

void mask_prg_get_bytes(uint8_t* out, size_t len) {
    mask_prg_expand(out, len);
}
'''
    with open(path, "w") as f:
        f.write(new_content)
    print("Modified mask_prg.c")

def modify_crypto_memory_c():
    path = r"C:\DROP\src\pqc_engine\crypto_memory.c"
    new_content = '''#include "memory_scratchpad.h"
#include "protocol_types.h"
#include <string.h>

void crypto_zeroize(volatile void* ptr, size_t len) {
    volatile uint8_t* p = (volatile uint8_t*)ptr;
    while (len--) {
        *p++ = 0;
    }
}

int crypto_ct_compare(const void* a, const void* b, size_t len) {
    const volatile uint8_t* pa = (const volatile uint8_t*)a;
    const volatile uint8_t* pb = (const volatile uint8_t*)b;
    uint8_t diff = 0;
    while (len--) {
        diff |= *pa++ ^ *pb++;
    }
    return (int)diff;
}

void crypto_ct_copy(void* dst, const void* src, size_t len, int condition) {
    uint8_t* d = (uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;
    uint8_t mask = (uint8_t)(-condition);
    while (len--) {
        *d = (*d & ~mask) | (*s & mask);
        d++;
        s++;
    }
}

void crypto_zeroize_scratchpad_region(scratch_region_t region) {
    scratch_zeroize_region(region);
}

void crypto_zeroize_all_scratchpad(void) {
    scratch_zeroize_all();
}
'''
    with open(path, "w") as f:
        f.write(new_content)
    print("Modified crypto_memory.c")

def create_tinycrypt_config():
    path = r"C:\DROP\src\pqc_engine\tinycrypt_config.h"
    content = '''#ifndef TINYCRYPT_CONFIG_H
#define TINYCRYPT_CONFIG_H

#define TC_AES_256 1
#define TC_HMAC 1
#define TC_SHA256 1
#define TC_CTR_MODE 1

#define TC_NO_OPTIMIZATION 1
#define TC_NO_INLINE 1

#endif
'''
    with open(path, "w") as f:
        f.write(content)
    print("Created tinycrypt_config.h")

if __name__ == "__main__":
    modify_platformio_ini()
    modify_kem_adapter_c()
    modify_mask_prg_c()
    modify_crypto_memory_c()
    create_tinycrypt_config()
    print("All modifications applied successfully.")