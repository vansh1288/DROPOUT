#ifndef DROPOUT_PROTOCOL_H
#define DROPOUT_PROTOCOL_H

#include "protocol_types.h"
#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum shares we can track for a single dropout recovery */
#define MAX_RECOVERY_SHARES 16

/* Initialize recovery session for a dropped-out client
 * @param round_id: The round ID for this recovery
 * @param client_id: The client ID of the dropped-out client
 * @param threshold: Shamir threshold (t) - minimum shares needed for reconstruction
 * @return PQC_SUCCESS on success, ERR_INVALID_THRESHOLD if threshold invalid
 */
pqc_status_t dropout_protocol_init_recovery(
    uint32_t round_id,
    uint8_t  client_id,
    uint8_t  threshold
);

/* Submit a Shamir share for recovery
 * @param share_id: Share identifier (1-255)
 * @param share_value: 64-byte share value (32 elements * 2 bytes)
 * @param share_len: Must be SHAMIR_SHARE_VALUE_BYTES (64)
 * @return PQC_SUCCESS on valid new share, ERR_DUPLICATE_SHARE_ID on duplicate,
 *         ERR_INSUFFICIENT_SHARES if not enough shares yet, PQC_SUCCESS when threshold reached
 */
pqc_status_t dropout_protocol_submit_share(
    uint8_t share_id,
    const uint8_t* share_value,
    size_t share_len
);

/* Check if recovery is complete (threshold reached) */
int dropout_protocol_is_recovery_complete(void);

/* Get the recovered Shamir secret (64 bytes = 32 GF(3329) elements) */
const uint8_t* dropout_protocol_get_recovered_secret(void);

/* Derive mask for recovery using recovered Shamir secret
 * This connects the recovered Shamir secret to the mask generation pipeline
 * @param round_id: Current round ID
 * @param chunk_index: Chunk index for stream mask derivation
 * @param peer_id: Peer client ID for pairwise mask derivation
 * @param mask: Output buffer for mask (chunk_size * 2 bytes)
 * @param chunk_size: Chunk size in bytes (must be valid: 64, 128, 256, 512, 1024)
 * @return PQC_SUCCESS on success, error code on failure
 */
pqc_status_t dropout_protocol_derive_mask_for_recovery(
    uint32_t round_id,
    uint16_t chunk_index,
    uint8_t peer_id,
    int16_t* mask,
    uint16_t chunk_size
);

/* Apply recovered mask to unmask a chunk's data
 * Uses recovered Shamir secret to derive mask and unmask chunk data
 * @param shared_secret: The recovered Shamir secret (64 bytes)
 * @param round_id: Current round ID
 * @param chunk_index: Chunk index for stream mask derivation
 * @param client_id: Local client ID
 * @param peer_id: Peer client ID for pairwise mask
 * @param masked_data: Input masked data (chunk_size bytes)
 * @param unmasked_output: Output buffer for unmasked data (chunk_size bytes)
 * @param chunk_size: Chunk size in bytes
 * @return PQC_SUCCESS on success, error code on failure
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
);

/* Apply recovered mask to a plaintext chunk (for outgoing data from recovered client)
 * @param shared_secret: The recovered Shamir secret
 * @param round_id: Current round ID
 * @param chunk_index: Chunk index
 * @param client_id: Local client ID
 * @param peer_id: Peer client ID for pairwise mask
 * @param plaintext_chunk: Input plaintext data
 * @param masked_output: Output masked data
 * @param chunk_size: Chunk size in bytes
 * @return PQC_SUCCESS on success
 */
pqc_status_t dropout_protocol_apply_recovered_mask(
    const uint8_t* shared_secret,
    uint32_t round_id,
    uint16_t chunk_index,
    uint8_t client_id,
    uint8_t peer_id,
    const int16_t* plaintext_chunk,
    int16_t* masked_output,
    uint16_t chunk_size
);

/* Clean up recovery session - zeroize all sensitive data */
void dropout_protocol_cleanup(void);

/* Check if recovery is complete */
int dropout_protocol_is_complete(void);

/* Get recovery context info */
void dropout_protocol_get_info(
    uint32_t* round_id,
    uint8_t* client_id,
    uint8_t* threshold,
    uint8_t* shares_received
);

#ifdef __cplusplus
}
#endif

#endif /* DROPOUT_PROTOCOL_H */