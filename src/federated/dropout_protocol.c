#include "protocol_types.h"
#include "memory_scratchpad.h"
#include "crypto_memory.h"
#include "kem_adapter.h"
#include "mask_prg.h"
#include "shamir.h"
#include "hkdf.h"
#include <stdint.h>
#include <string.h>

/* Derive a 32-byte key from the 64-byte Shamir secret using HKDF-SHA256
 * This allows using the recovered Shamir secret with ML-KEM APIs that expect 32-byte shared secrets
 */
static pqc_status_t derive_key_from_shamir_secret(const uint8_t* shamir_secret, uint8_t* derived_key) {
    if (!shamir_secret || !derived_key) {
        return ERR_INVALID_ARGUMENT;
    }

    /* Use HKDF-SHA256 to derive a 32-byte key from the 64-byte Shamir secret
     * Salt: empty (zero-filled)
     * IKM: the 64-byte Shamir secret
     * Info: "dropout-recovery-key"
     * Output: 32 bytes
     */
    static const uint8_t info[] = "dropout-recovery-key";
    uint8_t salt[32] = {0};  /* Empty salt = all zeros */

    int ret = hkdf_sha256(salt, 32, shamir_secret, SHAMIR_SECRET_BYTES, info, sizeof(info) - 1, derived_key, 32);
    if (ret != 0) {
        return ERR_KDF_FAILED;
    }
    return PQC_SUCCESS;
}

/* Shamir share structure as received over network */
typedef struct {
    uint8_t share_id;                    /* Share identifier (1-255) */
    uint8_t value[SHAMIR_SHARE_VALUE_BYTES];  /* 64 bytes = 32 elements * 2 bytes */
} shamir_recovery_share_t;

/* Recovery session context */
typedef struct {
    uint32_t round_id;
    uint8_t  client_id;           /* The dropped-out client being recovered */
    uint8_t  threshold;           /* Shamir threshold (t) */
    uint8_t  shares_received;     /* Number of shares collected */
    uint8_t  required_shares;     /* Threshold t */
    shamir_recovery_share_t shares[MAX_RECOVERY_SHARES];
    uint8_t  share_ids[MAX_RECOVERY_SHARES];  /* Track share IDs for duplicate detection */
    uint8_t  recovered_secret[SHAMIR_SECRET_BYTES];
    int      recovery_complete;
} dropout_recovery_ctx_t;

/* Global recovery context (one at a time per client) */
static dropout_recovery_ctx_t g_recovery_ctx = {0};

/* Initialize recovery session for a dropped-out client */
pqc_status_t dropout_protocol_init_recovery(
    uint32_t round_id,
    uint8_t  client_id,
    uint8_t  threshold
) {
    if (threshold == 0 || threshold > MAX_RECOVERY_SHARES) {
        return ERR_INVALID_THRESHOLD;
    }

    memset(&g_recovery_ctx, 0, sizeof(g_recovery_ctx));
    g_recovery_ctx.round_id = round_id;
    g_recovery_ctx.client_id = client_id;
    g_recovery_ctx.threshold = threshold;
    g_recovery_ctx.required_shares = threshold;
    g_recovery_ctx.shares_received = 0;
    g_recovery_ctx.recovery_complete = 0;

    return PQC_SUCCESS;
}

/* Submit a Shamir share for recovery
 * Returns PQC_SUCCESS on valid new share, ERR_DUPLICATE_SHARE_ID on duplicate,
 * ERR_INSUFFICIENT_SHARES if not enough shares yet, PQC_SUCCESS when threshold reached
 */
pqc_status_t dropout_protocol_submit_share(
    uint8_t share_id,
    const uint8_t* share_value,
    size_t share_len
) {
    if (!share_value || share_len != SHAMIR_SHARE_VALUE_BYTES) {
        return ERR_INVALID_ARGUMENT;
    }

    if (share_id == 0 || share_id > 255) {
        return ERR_INVALID_ARGUMENT;
    }

    if (g_recovery_ctx.recovery_complete) {
        return ERR_INVALID_STATE;
    }

    /* Check for duplicate share ID */
    for (uint8_t i = 0; i < g_recovery_ctx.shares_received; i++) {
        if (g_recovery_ctx.share_ids[i] == share_id) {
            return ERR_DUPLICATE_SHARE_ID;
        }
    }

    /* Check if we already have enough shares */
    if (g_recovery_ctx.shares_received >= g_recovery_ctx.required_shares) {
        return PQC_SUCCESS;
    }

    /* Store the share */
    uint8_t idx = g_recovery_ctx.shares_received;
    g_recovery_ctx.share_ids[idx] = share_id;
    memcpy(g_recovery_ctx.shares[idx].value, share_value, SHAMIR_SHARE_VALUE_BYTES);
    g_recovery_ctx.shares[idx].share_id = share_id;
    g_recovery_ctx.shares_received++;

    /* Check if we have enough shares to reconstruct */
    if (g_recovery_ctx.shares_received >= g_recovery_ctx.required_shares) {
        /* Reconstruct the secret */
        uint8_t* share_x = g_scratchpad.raw;  /* Use scratchpad for temp storage */
        uint8_t** share_y = (uint8_t**)(g_scratchpad.raw + MAX_RECOVERY_SHARES);
        uint16_t* workspace = (uint16_t*)(g_scratchpad.raw + MAX_RECOVERY_SHARES + MAX_RECOVERY_SHARES * 8);

        /* Prepare share_x and share_y arrays for reconstruction */
        for (uint8_t i = 0; i < g_recovery_ctx.shares_received; i++) {
            share_x[i] = g_recovery_ctx.share_ids[i];
            share_y[i] = g_recovery_ctx.shares[i].value;
        }

        int ret = shamir_reconstruct_bytes(
            g_recovery_ctx.recovered_secret,
            (const uint8_t*)share_x,
            (const uint8_t**)share_y,
            g_recovery_ctx.required_shares,
            workspace
        );

        if (ret != 0) {
            return ERR_SHAMIR_DECODE_FAILED;
        }

        g_recovery_ctx.recovery_complete = 1;
    }

    return PQC_SUCCESS;
}

/* Check if recovery is complete */
int dropout_protocol_is_recovery_complete(void) {
    return g_recovery_ctx.recovery_complete;
}

/* Get the recovered Shamir secret (64 bytes) */
const uint8_t* dropout_protocol_get_recovered_secret(void) {
    if (!g_recovery_ctx.recovery_complete) {
        return NULL;
    }
    return g_recovery_ctx.recovered_secret;
}

/* Derive mask for recovery using recovered Shamir secret
 * This connects the recovered secret to the mask generation pipeline
 */
pqc_status_t dropout_protocol_derive_mask_for_recovery(
    uint32_t round_id,
    uint16_t chunk_index,
    uint8_t peer_id,
    int16_t* mask,
    uint16_t chunk_size
) {
    if (!mask) return ERR_INVALID_ARGUMENT;
    if (!g_recovery_ctx.recovery_complete) {
        return ERR_INVALID_STATE;
    }

    if (!is_valid_chunk_size(chunk_size)) {
        return ERR_CHUNK_TOO_LARGE;
    }

    /* Derive 32-byte key from the 64-byte Shamir secret */
    uint8_t derived_key[32];
    pqc_status_t ret = derive_key_from_shamir_secret(g_recovery_ctx.recovered_secret, derived_key);
    if (ret != PQC_SUCCESS) {
        return ret;
    }

    /* Derive pairwise mask seed from derived key */
    uint8_t pairwise_seed[32];
    pqc_status_t ret = kem_adapter_derive_pairwise_mask_seed(
        derived_key,
        g_recovery_ctx.client_id,
        peer_id,
        round_id,
        pairwise_seed
    );
    if (ret != PQC_SUCCESS) {
        crypto_zeroize(derived_key, 32);
        return ret;
    }

    /* Derive stream mask seed for this chunk */
    uint8_t stream_seed[32];
    ret = kem_adapter_derive_stream_mask_seed(
        pairwise_seed,
        g_recovery_ctx.client_id,
        round_id,
        chunk_index,
        stream_seed
    );
    if (ret != PQC_SUCCESS) {
        crypto_zeroize(pairwise_seed, 32);
        crypto_zeroize(derived_key, 32);
        return ret;
    }

    /* Generate mask using mask PRG */
    mask_prg_ctx_t prg_ctx;
    int ret = mask_prg_init(&prg_ctx, stream_seed);
    if (ret != 0) {
        crypto_zeroize(stream_seed, 32);
        crypto_zeroize(pairwise_seed, 32);
        crypto_zeroize(derived_key, 32);
        return ERR_PRG_FAILED;
    }

    int ret = mask_prg_get_bytes(&prg_ctx, (uint8_t*)mask, chunk_size * sizeof(int16_t));
    if (ret != 0) {
        crypto_zeroize(stream_seed, 32);
        crypto_zeroize(pairwise_seed, 32);
        crypto_zeroize(derived_key, 32);
        mask_prg_cleanup(&prg_ctx);
        return ERR_PRG_FAILED;
    }

    /* Zeroize temporary secrets */
    crypto_zeroize(stream_seed, 32);
    crypto_zeroize(pairwise_seed, 32);
    crypto_zeroize(derived_key, 32);
    mask_prg_cleanup(&prg_ctx);

    return PQC_SUCCESS;
}

/* Apply recovered mask to unmask a chunk's data
 * This applies the recovered mask to unmask a chunk for a specific peer
 */
pqc_status_t dropout_protocol_unmask_chunk(
    const uint8_t* shared_secret,
    uint32_t round_id,
    uint16_t chunk_index,
    uint8_t client_id,
    uint8_t peer_id,
    const int16_t* masked_data,
    int16_t* unmasked_output,
    uint16_t chunk_size
) {
    if (!shared_secret || !masked_data || !unmasked_output) {
        return ERR_INVALID_ARGUMENT;
    }

    if (!is_valid_chunk_size(chunk_size)) {
        return ERR_CHUNK_TOO_LARGE;
    }

    uint8_t derived_key[32];
    uint8_t* key_to_use = (uint8_t*)shared_secret;
    int derived = 0;

    /* Check if we're in recovery mode and the shared_secret matches the recovered Shamir secret */
    if (g_recovery_ctx.recovery_complete && 
        shared_secret == g_recovery_ctx.recovered_secret) {
        /* Derive 32-byte key from the 64-byte Shamir secret */
        pqc_status_t ret = derive_key_from_shamir_secret(g_recovery_ctx.recovered_secret, derived_key);
        if (ret != PQC_SUCCESS) {
            return ret;
        }
        key_to_use = derived_key;
    } else {
        /* Assume shared_secret is already a 32-byte ML-KEM shared secret */
        /* No derivation needed */
    }

    /* Derive mask for the specific peer */
    uint8_t pairwise_seed[32];
    pqc_status_t ret = kem_adapter_derive_pairwise_mask_seed(
        key_to_use,
        client_id,
        peer_id,
        round_id,
        pairwise_seed
    );
    if (ret != PQC_SUCCESS) return ret;

    uint8_t stream_seed[32];
    ret = kem_adapter_derive_stream_mask_seed(
        (const uint8_t*)key_to_use,
        client_id,
        round_id,
        chunk_index,
        stream_seed
    );
    if (ret != PQC_SUCCESS) {
        crypto_zeroize(pairwise_seed, 32);
        return ret;
    }

    mask_prg_ctx_t prg_ctx;
    int ret = mask_prg_init(&prg_ctx, stream_seed);
    if (ret != 0) {
        crypto_zeroize(stream_seed, 32);
        crypto_zeroize(pairwise_seed, 32);
        return ERR_PRG_FAILED;
    }

    int16_t mask[CHUNK_BUFFER_BYTES / 2];
    ret = mask_prg_get_bytes(&prg_ctx, (uint8_t*)mask, chunk_size * sizeof(int16_t));
    if (ret != 0) {
        crypto_zeroize(stream_seed, 32);
        crypto_zeroize(pairwise_seed, 32);
        mask_prg_cleanup(&prg_ctx);
        return ERR_PRG_FAILED;
    }

    /* Unmask: unmasked = masked - mask (mod q) */
    const int16_t* masked = (const int16_t*)masked_data;
    int16_t* output = (int16_t*)unmasked_output;
    size_t num_elements = chunk_size / 2;

    for (size_t i = 0; i < num_elements; i++) {
        int32_t diff = (int32_t)masked[i] - (int32_t)mask[i];
        output[i] = (int16_t)mod_q(diff);
    }

    /* Zeroize temporary secrets */
    crypto_zeroize(stream_seed, 32);
    crypto_zeroize(pairwise_seed, 32);

    return PQC_SUCCESS;
}

/* Apply recovered mask to apply mask for a client's chunk
 * This is used when the recovered client needs to apply its mask to outgoing data
 */
pqc_status_t dropout_protocol_apply_recovered_mask(
    const int16_t* plaintext_chunk,
    int16_t* masked_output,
    uint32_t round_id,
    uint16_t chunk_index,
    uint8_t client_id,
    uint8_t peer_id,
    uint16_t chunk_size
) {
    /* This uses the recovered Shamir secret to generate the pairwise mask
     * and apply it to the plaintext chunk, producing masked output */
    return dropout_protocol_unmask_chunk(
        g_recovery_ctx.recovered_secret,
        round_id,
        chunk_index,
        client_id,
        peer_id,
        plaintext_chunk,
        masked_output,
        chunk_size
    );
}

/* Clean up recovery session - zeroize all sensitive data */
void dropout_protocol_cleanup(void) {
    crypto_zeroize(&g_recovery_ctx, sizeof(g_recovery_ctx));
}

/* Check if recovery is complete */
int dropout_protocol_is_complete(void) {
    return g_recovery_ctx.recovery_complete;
}

/* Get recovery context info */
void dropout_protocol_get_info(
    uint32_t* round_id,
    uint8_t* client_id,
    uint8_t* threshold,
    uint8_t* shares_received
) {
    if (round_id) *round_id = g_recovery_ctx.round_id;
    if (client_id) *client_id = g_recovery_ctx.client_id;
    if (threshold) *threshold = g_recovery_ctx.threshold;
    if (shares_received) *shares_received = g_recovery_ctx.shares_received;
}

/* Helper function to check if chunk size is valid */
static inline int is_valid_chunk_size(uint16_t chunk_size) {
    return (chunk_size == 64 || chunk_size == 128 || chunk_size == 256 || 
            chunk_size == 512 || chunk_size == 1024);
}