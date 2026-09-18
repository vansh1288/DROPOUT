#ifndef KEM_ADAPTER_H
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
