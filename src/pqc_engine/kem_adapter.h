/**
 * @file kem_adapter.h
 * @brief ML-KEM Adapter Layer for Post-Quantum Key Establishment.
 *
 * Provides a hardware-agnostic interface to ML-KEM (FIPS 203) operations
 * using static buffers from the Global_Scratchpad. This adapter isolates
 * the protocol layer from the underlying PQC implementation (pqm4, liboqs,
 * or vendor SDK) and enforces zero-heap, constant-time operation.
 *
 * Supported Variants:
 *   - ML-KEM-512  (NIST Security Level 1)
 *   - ML-KEM-768  (NIST Security Level 3)
 *   - ML-KEM-1024 (NIST Security Level 5)
 *
 * MEMORY AUDIT:
 * ============================================================================
 * All working buffers sourced from Global_Scratchpad (memory_scratchpad.h):
 *   - mlkem_workspace_t (4096 bytes): NTT buffers, polynomial matrix, sampling
 *   - crypto_workspace_t (2048 bytes):  SHAKE256/AES contexts for KEM internals
 * NO dynamic allocation. NO stack-heavy recursion.
 * All functions are re-entrant only if called with distinct scratchpad instances.
 * ============================================================================
 *
 * CRYPTOGRAPHIC GROUNDING:
 * - KeyGen: FIPS 203 Section 5.1 (Algorithm 11)
 * - Encaps: FIPS 203 Section 5.2 (Algorithm 12)
 * - Decaps: FIPS 203 Section 5.3 (Algorithm 13)
 * - NTT:    Cooley-Tukey, 256-point, modulo q=3329 (FIPS 203 Section 4.3)
 * - Sampling: CBD (Centered Binomial Distribution) per FIPS 203 Section 4.4
 * - All modular reductions use Barrett/Montgomery per pqm4 reference.
 */

#ifndef KEM_ADAPTER_H
#define KEM_ADAPTER_H

#include "protocol_types.h"
#include "memory_scratchpad.h"
#include <stdint.h>
#include <stddef.h>

/* =========================================================================
 * External ML-KEM Implementation Symbols (Provided by pqm4 / liboqs / SDK)
 * ========================================================================= */
/* These are the raw ML-KEM functions the adapter wraps. The actual symbols
 * depend on the linked implementation. For pqm4 ML-KEM-768 reference: */
#if defined(USE_PQM4_KEM512)
    /* pqm4 uses pqcrystals_kyber512_ref_* for ML-KEM-512 */
    #define KEM_KEYPAIR_FN   pqcrystals_kyber512_ref_keypair
    #define KEM_ENCAP_FN     pqcrystals_kyber512_ref_enc
    #define KEM_DECAP_FN     pqcrystals_kyber512_ref_dec
#elif defined(USE_PQM4_KEM768)
    #define KEM_KEYPAIR_FN   pqcrystals_kyber768_ref_keypair
    #define KEM_ENCAP_FN     pqcrystals_kyber768_ref_enc
    #define KEM_DECAP_FN     pqcrystals_kyber768_ref_dec
#elif defined(USE_PQM4_KEM1024)
    #define KEM_KEYPAIR_FN   pqcrystals_kyber1024_ref_keypair
    #define KEM_ENCAP_FN     pqcrystals_kyber1024_ref_enc
    #define KEM_DECAP_FN     pqcrystals_kyber1024_ref_dec
#else
    /* Generic weak aliases - must be defined by linked library */
    extern int KEM_KEYPAIR_FN(uint8_t* pk, uint8_t* sk);
    extern int KEM_ENCAP_FN(uint8_t* ct, uint8_t* ss, const uint8_t* pk);
    extern int KEM_DECAP_FN(uint8_t* ss, const uint8_t* ct, const uint8_t* sk);
#endif

/* =========================================================================
 * Adapter Configuration
 * ========================================================================= */
#define KEM_ADAPTER_MAX_PK_BYTES   ML_KEM_1024_PUBLIC_KEY_BYTES
#define KEM_ADAPTER_MAX_SK_BYTES   ML_KEM_1024_SECRET_KEY_BYTES
#define KEM_ADAPTER_MAX_CT_BYTES   ML_KEM_1024_CIPHERTEXT_BYTES
#define KEM_ADAPTER_SS_BYTES       ML_KEM_1024_SHARED_SECRET_BYTES

/* =========================================================================
 * Key Derivation Function (KDF) Labels for Domain Separation
 * ========================================================================= */
#define KDF_LABEL_KEM_SHARED      "MLKEM-SharedSecret-v1"
#define KDF_LABEL_PAIRWISE_MASK   "SwiftAgg-PairwiseMask-v1"
#define KDF_LABEL_STREAM_MASK     "SwiftAgg-StreamMask-v1"
#define KDF_LABEL_SHAMIR_SECRET   "SwiftAgg-ShamirSecret-v1"
#define KDF_LABEL_SESSION_KEY     "FL-SessionKey-v1"

/* =========================================================================
 * Adapter API
 * ========================================================================= */

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the KEM adapter with a specific variant.
 *        Must be called before any other KEM function.
 * @param variant ML-KEM variant to use (512, 768, or 1024).
 * @return PQC_SUCCESS on success, negative error code on failure.
 */
pqc_status_t kem_adapter_init(kem_variant_t variant);

/**
 * @brief Get the currently active ML-KEM variant.
 * @return Active variant.
 */
kem_variant_t kem_adapter_get_variant(void);

/**
 * @brief Get parameter sizes for the active variant.
 * @param[out] pk_bytes   Public key size in bytes.
 * @param[out] sk_bytes   Secret key size in bytes.
 * @param[out] ct_bytes   Ciphertext size in bytes.
 * @param[out] ss_bytes   Shared secret size in bytes (always 32).
 * @return PQC_SUCCESS on success.
 */
pqc_status_t kem_adapter_get_sizes(size_t* pk_bytes, size_t* sk_bytes,
                                    size_t* ct_bytes, size_t* ss_bytes);

/**
 * @brief Generate an ML-KEM key pair.
 *        Uses scratchpad.mlkem_ws for NTT/polynomial workspace.
 *        Uses scratchpad.crypto_ws for SHAKE256/AES contexts.
 * @param[out] keypair Structure to receive keys (lengths set by function).
 * @return PQC_SUCCESS on success, ERR_KEM_KEYGEN_FAILED on failure.
 */
pqc_status_t kem_adapter_keypair(kem_keypair_t* keypair);

/**
 * @brief Encapsulate a shared secret to a peer's public key.
 *        Uses scratchpad.mlkem_ws and scratchpad.crypto_ws.
 * @param[in]  public_key Peer's public key (length per active variant).
 * @param[in]  pk_len     Length of public_key.
 * @param[out] encap      Structure to receive ciphertext and shared secret.
 * @return PQC_SUCCESS on success, ERR_KEM_ENCAP_FAILED on failure.
 */
pqc_status_t kem_adapter_encapsulate(const uint8_t* public_key, size_t pk_len,
                                      kem_encapsulation_t* encap);

/**
 * @brief Decapsulate a shared secret using local secret key.
 *        Uses scratchpad.mlkem_ws and scratchpad.crypto_ws.
 *        Implements implicit rejection (constant-time) per FIPS 203.
 * @param[in]  ciphertext Ciphertext from peer (length per active variant).
 * @param[in]  ct_len     Length of ciphertext.
 * @param[in]  secret_key Local secret key.
 * @param[in]  sk_len     Length of secret_key.
 * @param[out] shared_secret Output buffer (32 bytes).
 * @return PQC_SUCCESS on success, ERR_KEM_DECAP_FAILED on failure.
 */
pqc_status_t kem_adapter_decapsulate(const uint8_t* ciphertext, size_t ct_len,
                                      const uint8_t* secret_key, size_t sk_len,
                                      uint8_t* shared_secret);

/**
 * @brief Derive a session key from ML-KEM shared secret using HKDF-SHA256.
 *        Implements HKDF-Extract + HKDF-Expand per RFC 5869.
 *        Uses scratchpad.crypto_ws for HMAC context.
 * @param[in]  shared_secret  32-byte ML-KEM shared secret.
 * @param[in]  salt           Optional salt (can be NULL, len=0).
 * @param[in]  salt_len       Salt length.
 * @param[in]  info           Context binding info (e.g., round_id || client_ids).
 * @param[in]  info_len       Info length.
 * @param[out] session_key    Output buffer (32 bytes for AES-256).
 * @return PQC_SUCCESS on success, ERR_KDF_FAILED on failure.
 */
pqc_status_t kem_adapter_derive_session_key(const uint8_t* shared_secret,
                                             const uint8_t* salt, size_t salt_len,
                                             const uint8_t* info, size_t info_len,
                                             uint8_t* session_key);

/**
 * @brief Derive pairwise mask seed from shared secret (SwiftAgg).
 *        Domain-separated from session key derivation.
 * @param[in]  shared_secret  32-byte ML-KEM shared secret.
 * @param[in]  client_id_a    Lower client ID of the pair.
 * @param[in]  client_id_b    Higher client ID of the pair.
 * @param[in]  round_id       Current round identifier.
 * @param[out] mask_seed      Output buffer (32 bytes for PRG seed).
 * @return PQC_SUCCESS on success, ERR_KDF_FAILED on failure.
 */
pqc_status_t kem_adapter_derive_pairwise_mask_seed(const uint8_t* shared_secret,
                                                    uint8_t client_id_a,
                                                    uint8_t client_id_b,
                                                    uint32_t round_id,
                                                    uint8_t* mask_seed);

/**
 * @brief Derive streaming mask seed for chunked model updates.
 *        Domain-separated from pairwise and session keys.
 * @param[in]  shared_secret  32-byte ML-KEM shared secret (or session key).
 * @param[in]  client_id      Client identifier.
 * @param[in]  round_id       Current round identifier.
 * @param[in]  chunk_index    Chunk sequence number.
 * @param[out] stream_seed    Output buffer (32 bytes for PRG seed).
 * @return PQC_SUCCESS on success, ERR_KDF_FAILED on failure.
 */
pqc_status_t kem_adapter_derive_stream_mask_seed(const uint8_t* shared_secret,
                                                  uint8_t client_id,
                                                  uint32_t round_id,
                                                  uint16_t chunk_index,
                                                  uint8_t* stream_seed);

/**
 * @brief Derive Shamir secret sharing master secret from ML-KEM shared secret.
 *        Used for dropout recovery mask reconstruction.
 * @param[in]  shared_secret  32-byte ML-KEM shared secret.
 * @param[in]  client_id      Dropped client identifier.
 * @param[in]  round_id       Current round identifier.
 * @param[out] shamir_secret  Output buffer (32 bytes).
 * @return PQC_SUCCESS on success, ERR_KDF_FAILED on failure.
 */
pqc_status_t kem_adapter_derive_shamir_secret(const uint8_t* shared_secret,
                                               uint8_t client_id,
                                               uint32_t round_id,
                                               uint8_t* shamir_secret);

/**
 * @brief Zeroize all KEM-related sensitive material in scratchpad.
 *        Call after key establishment phase completes.
 * @return PQC_SUCCESS always.
 */
pqc_status_t kem_adapter_zeroize_scratchpad(void);

/**
 * @brief Perform known-answer test (KAT) for the active variant.
 *        Validates implementation against FIPS 203 test vectors.
 * @return PQC_SUCCESS if KAT passes, ERR_CRYPTO_FAILURE if not.
 */
pqc_status_t kem_adapter_self_test(void);

/**
 * @brief Get cycle count for last operation (if cycle counter available).
 *        Requires DWT_CYCCNT or equivalent hardware counter.
 * @return Cycle count, or 0 if not supported.
 */
uint32_t kem_adapter_get_last_cycles(void);

#ifdef __cplusplus
}
#endif

#endif /* KEM_ADAPTER_H */