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

<<<<<<< HEAD
=======
#define KEMLIB_ML_KEM_X25519 3

>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4
#ifdef __cplusplus
extern "C" {
#endif

<<<<<<< HEAD
/**
 * ML-KEM variant selection.
 * Only ML-KEM-512, ML-KEM-768, and ML-KEM-1024 are supported.
 * X25519 fallback has been removed.
 */
typedef enum {
    KEMLIB_ML_KEM_512  = 0,
    KEMLIB_ML_KEM_768  = 1,
    KEMLIB_ML_KEM_1024 = 2,
} kem_variant_t;

typedef struct {
    kem_variant_t variant;
    uint8_t public_key[ML_KEM_1024_PUBLIC_KEY_BYTES];
    uint8_t secret_key[ML_KEM_1024_SECRET_KEY_BYTES];
    size_t  public_key_len;
    size_t  secret_key_len;
    size_t  ciphertext_len;
    size_t  shared_secret_len;
} kem_keypair_t;

typedef struct {
    uint8_t ciphertext[ML_KEM_1024_CIPHERTEXT_BYTES];
    uint8_t shared_secret[ML_KEM_1024_SHARED_SECRET_BYTES];
    size_t  ciphertext_len;
    size_t  shared_secret_len;
} kem_encapsulation_t;

/**
 * Initialize the KEM adapter with the specified ML-KEM variant.
 * Must be called before any other KEM adapter functions.
 * 
 * @param variant ML-KEM variant to use (ML-KEM-512, ML-KEM-768, or ML-KEM-1024)
 * @return PQC_SUCCESS on success, ERR_INVALID_ARGUMENT if variant is not supported
 */
pqc_status_t kem_adapter_init(kem_variant_t variant);

/**
 * Get the currently active ML-KEM variant.
 * @return The currently active variant.
 */
kem_variant_t kem_adapter_get_variant(void);

/**
 * Get the buffer sizes for the current ML-KEM variant.
 * 
 * @param pk_bytes   Output: public key size in bytes
 * @param sk_bytes   Output: secret key size in bytes
 * @param ct_bytes   Output: ciphertext size in bytes
 * @param ss_bytes   Output: shared secret size in bytes
 * @return PQC_SUCCESS on success, ERR_INVALID_ARGUMENT if any output pointer is NULL
 */
pqc_status_t kem_adapter_get_sizes(size_t* pk_bytes, size_t* sk_bytes, size_t* ct_bytes, size_t* ss_bytes);

/**
 * Generate an ML-KEM key pair.
 * 
 * @param keypair  Output: generated key pair (public key, secret key, and metadata)
 * @return PQC_SUCCESS on success, ERR_KEM_KEYGEN_FAILED on key generation failure,
 *         ERR_INVALID_ARGUMENT if keypair is NULL
 */
pqc_status_t kem_adapter_keypair(kem_keypair_t* keypair);

/**
 * Encapsulate a shared secret using the provided public key.
 * 
 * @param public_key  Input: ML-KEM public key
 * @param pk_len      Input: length of public key (must match variant)
 * @param encap       Output: encapsulation result (ciphertext + shared secret)
 * @return PQC_SUCCESS on success, ERR_KEM_ENCAP_FAILED on encapsulation failure,
 *         ERR_INVALID_ARGUMENT for invalid arguments
 */
pqc_status_t kem_adapter_encapsulate(const uint8_t* public_key, size_t pk_len, kem_encapsulation_t* encap);

/**
 * Decapsulate a shared secret from a ciphertext using the private key.
 * 
 * IMPORTANT: ML-KEM decapsulation uses implicit rejection (FIPS 203).
 * - This function ALWAYS returns PQC_SUCCESS on success (returns 0 from underlying implementation)
 * - On ciphertext verification failure, a pseudorandom shared secret is returned in 'shared_secret'
 * - The caller MUST NOT assume the ciphertext was valid just because this function returns success
 * - Use kem_adapter_verify_decapsulation() to check if decapsulation succeeded
 * 
 * @param ciphertext  Input: ML-KEM ciphertext
 * @param ct_len      Input: length of ciphertext (must match variant)
 * @param secret_key  Input: ML-KEM private key
 * @param sk_len      Input: length of private key (must match variant)
 * @param shared_secret Output: derived shared secret (32 bytes)
 * @return PQC_SUCCESS on success, ERR_CRYPTO_FAILURE on implementation failure,
 *         ERR_INVALID_ARGUMENT for invalid arguments
 * @note Returns pseudorandom shared secret on ciphertext verification failure (implicit rejection)
 */
pqc_status_t kem_adapter_decapsulate(const uint8_t* ciphertext, size_t ct_len, const uint8_t* secret_key, size_t sk_len, uint8_t* shared_secret);

/**
 * Verify that a decapsulation result matches the expected shared secret.
 * Use this after kem_adapter_decapsulate() to verify the ciphertext was valid.
 * 
 * @param expected_ss  Expected shared secret (from encapsulation)
 * @param actual_ss    Actual shared secret (from decapsulation)
 * @return PQC_SUCCESS if secrets match, ERR_CRYPTO_FAILURE if they differ
 */
pqc_status_t kem_adapter_verify_decapsulation(const uint8_t* expected_ss, const uint8_t* actual_ss);

=======
pqc_status_t kem_adapter_init(kem_variant_t variant);
kem_variant_t kem_adapter_get_variant(void);
pqc_status_t kem_adapter_get_sizes(size_t* pk_bytes, size_t* sk_bytes, size_t* ct_bytes, size_t* ss_bytes);
pqc_status_t kem_adapter_keypair(kem_keypair_t* keypair);
pqc_status_t kem_adapter_encapsulate(const uint8_t* public_key, size_t pk_len, kem_encapsulation_t* encap);
pqc_status_t kem_adapter_decapsulate(const uint8_t* ciphertext, size_t ct_len, const uint8_t* secret_key, size_t sk_len, uint8_t* shared_secret);
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4
pqc_status_t kem_adapter_derive_session_key(const uint8_t* shared_secret, const uint8_t* salt, size_t salt_len, const uint8_t* info, size_t info_len, uint8_t* session_key);
pqc_status_t kem_adapter_derive_pairwise_mask_seed(const uint8_t* shared_secret, uint8_t client_id_a, uint8_t client_id_b, uint32_t round_id, uint8_t* mask_seed);
pqc_status_t kem_adapter_derive_stream_mask_seed(const uint8_t* shared_secret, uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint8_t* stream_seed);
pqc_status_t kem_adapter_derive_shamir_secret(const uint8_t* shared_secret, uint8_t client_id, uint32_t round_id, uint8_t* shamir_secret);
pqc_status_t kem_adapter_zeroize_scratchpad(void);
pqc_status_t kem_adapter_self_test(void);
uint32_t kem_adapter_get_last_cycles(void);

<<<<<<< HEAD
=======
pqc_status_t classical_x25519_keypair(uint8_t* pk, uint8_t* sk);
pqc_status_t classical_x25519_encap(uint8_t* ct, uint8_t* ss, const uint8_t* pk);
pqc_status_t classical_x25519_decap(uint8_t* ss, const uint8_t* ct, const uint8_t* sk);

>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4
#ifdef __cplusplus
}
#endif

#endif
