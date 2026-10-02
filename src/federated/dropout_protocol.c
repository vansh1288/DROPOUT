#include "protocol_types.h"
#include "memory_scratchpad.h"
#include "crypto_memory.h"
#include "kem_adapter.h"
#include "mask_prg.h"
#include "shamir.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

/*
 * Dropout recovery protocol
 *
 * Shamir operations are delegated to the canonical implementation in
 * src/pqc_engine/shamir.c.
 *
 * Share values are 64 bytes: 32 field elements, each encoded as
 * two bytes, as defined by SHAMIR_SECRET_BYTES.
 */

/*
 * Derive the pairwise mask for a dropped-out client.
 *
 * shamir_secret: reconstructed 32-byte pairwise secret
 * client_id:     surviving client's ID
 * round_id:      current federated round
 * chunk_index:   model update chunk index
 * peer_id:       dropped-out peer's ID
 * mask:          output mask buffer
 * chunk_size:    number of int16_t mask elements
 */
pqc_status_t dropout_protocol_derive_mask_for_recovery(
    const uint8_t *shamir_secret,
    uint8_t client_id,
    uint32_t round_id,
    uint16_t chunk_index,
    uint8_t peer_id,
    int16_t *mask,
    uint16_t chunk_size)
{
    if (shamir_secret == NULL || mask == NULL || chunk_size == 0) {
        return ERR_INVALID_ARGUMENT;
    }

    uint8_t pairwise_seed[SHA256_DIGEST_BYTES] = {0};
    uint8_t stream_seed[SHA256_DIGEST_BYTES] = {0};
    mask_prg_ctx_t prg_ctx;

    memset(&prg_ctx, 0, sizeof(prg_ctx));

    pqc_status_t ret = kem_adapter_derive_pairwise_mask_seed(
        shamir_secret,
        client_id,
        peer_id,
        round_id,
        pairwise_seed);

    if (ret != PQC_SUCCESS) {
        goto cleanup;
    }

    ret = kem_adapter_derive_stream_mask_seed(
        pairwise_seed,
        client_id,
        round_id,
        chunk_index,
        stream_seed);

    if (ret != PQC_SUCCESS) {
        goto cleanup;
    }

    mask_prg_init(&prg_ctx, stream_seed);

    mask_prg_get_bytes(
        &prg_ctx,
        (uint8_t *)mask,
        (size_t)chunk_size * sizeof(*mask));

cleanup:
    crypto_zeroize(stream_seed, sizeof(stream_seed));
    crypto_zeroize(pairwise_seed, sizeof(pairwise_seed));
    crypto_zeroize(&prg_ctx, sizeof(prg_ctx));

    if (ret != PQC_SUCCESS) {
        crypto_zeroize(mask, (size_t)chunk_size * sizeof(*mask));
    }

    return ret;
}

/*
 * Generate Shamir shares for a 64-byte secret.
 *
 * The secret is interpreted by the canonical byte-oriented Shamir API.
 * Each generated share is stored in the protocol's shamir_share_t.
 */
pqc_status_t dropout_protocol_generate_shares(
    const uint8_t *secret,
    uint8_t threshold,
    uint8_t num_shares,
    shamir_share_t *shares)
{
    if (secret == NULL || shares == NULL ||
        threshold == 0 ||
        threshold > SHAMIR_MAX_SHARES ||
        num_shares < threshold ||
        num_shares > SHAMIR_MAX_SHARES) {
        return ERR_INVALID_ARGUMENT;
    }

    shamir_workspace_t *ws = scratch_get_shamir_ws();
    if (ws == NULL) {
        return ERR_HEAP_EXHAUSTED;
    }

    uint8_t share_x[SHAMIR_MAX_SHARES] = {0};
    uint8_t share_y_storage[SHAMIR_MAX_SHARES][SHAMIR_SHARE_VALUE_BYTES];
    uint8_t *share_y[SHAMIR_MAX_SHARES] = {0};

    memset(share_y_storage, 0, sizeof(share_y_storage));

    for (uint16_t i = 0; i < num_shares; ++i) {
        share_y[i] = share_y_storage[i];
    }

    int result = shamir_share_bytes(
        secret,
        SHAMIR_SECRET_BYTES,
        share_x,
        share_y,
        num_shares,
        threshold,
        (uint16_t *)ws->data);

    if (result != 0) {
        crypto_zeroize(share_x, sizeof(share_x));
        crypto_zeroize(share_y_storage, sizeof(share_y_storage));
        crypto_zeroize(share_y, sizeof(share_y));
        return ERR_SHAMIR_ENCODE_FAILED;
    }

    for (uint16_t i = 0; i < num_shares; ++i) {
        shares[i].share_id = share_x[i];
        memcpy(
            shares[i].value,
            share_y_storage[i],
            SHAMIR_SHARE_VALUE_BYTES);
    }

    crypto_zeroize(share_x, sizeof(share_x));
    crypto_zeroize(share_y_storage, sizeof(share_y_storage));
    crypto_zeroize(share_y, sizeof(share_y));

    return PQC_SUCCESS;
}

/*
 * Reconstruct the original 64-byte secret from at least threshold shares.
 *
 * The caller supplies num_shares available shares. The canonical
 * reconstruction routine uses the first threshold shares.
 */
pqc_status_t dropout_protocol_reconstruct_secret(
    const shamir_share_t *shares,
    uint8_t num_shares,
    uint8_t threshold,
    uint8_t *secret)
{
    if (shares == NULL || secret == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    if (threshold == 0 ||
        threshold > SHAMIR_MAX_SHARES ||
        num_shares < threshold ||
        num_shares > SHAMIR_MAX_SHARES) {
        return ERR_INSUFFICIENT_SHARES;
    }

    shamir_workspace_t *ws = scratch_get_shamir_ws();
    if (ws == NULL) {
        return ERR_HEAP_EXHAUSTED;
    }

    uint8_t share_x[SHAMIR_MAX_SHARES] = {0};
    const uint8_t *share_y[SHAMIR_MAX_SHARES] = {0};

    for (uint16_t i = 0; i < num_shares; ++i) {
        if (shares[i].share_id == 0) {
            return ERR_INVALID_ARGUMENT;
        }

        for (uint16_t j = 0; j < i; ++j) {
            if (shares[i].share_id == shares[j].share_id) {
                return ERR_DUPLICATE_SHARE_ID;
            }
        }

        share_x[i] = shares[i].share_id;
        share_y[i] = shares[i].value;
    }

    int result = shamir_reconstruct_bytes(
        secret,
        share_x,
        share_y,
        threshold,
        (uint16_t *)ws->data);

    crypto_zeroize(share_x, sizeof(share_x));
    crypto_zeroize(share_y, sizeof(share_y));

    if (result != 0) {
        crypto_zeroize(secret, SHAMIR_SECRET_BYTES);
        return ERR_SHAMIR_DECODE_FAILED;
    }

    return PQC_SUCCESS;
}