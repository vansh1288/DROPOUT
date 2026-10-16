#include "protocol_types.h"
#include "memory_scratchpad.h"
#include "crypto_memory.h"
#include "kem_adapter.h"
#include "dropout_protocol.h"

#ifdef TEST_BUILD
#include "mask_prg_mock.h"
#else
#include "mask_prg.h"
#endif

#include "shamir.h"
#include "hkdf.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define DROPOUT_KEY_BYTES       32u
#define DROPOUT_SEED_BYTES      32u
#define DROPOUT_FIELD_MODULUS   3329

typedef struct {
    uint8_t share_id;
    uint8_t value[SHAMIR_SHARE_VALUE_BYTES];
} shamir_recovery_share_t;

typedef struct {
    uint32_t round_id;
    uint8_t client_id;
    uint8_t threshold;
    uint8_t shares_received;
    uint8_t required_shares;
    shamir_recovery_share_t shares[MAX_RECOVERY_SHARES];
    uint8_t share_ids[MAX_RECOVERY_SHARES];
    uint8_t recovered_secret[SHAMIR_SECRET_BYTES];
    int recovery_complete;
} dropout_recovery_ctx_t;

static dropout_recovery_ctx_t g_recovery_ctx;

static int is_valid_chunk_size(uint16_t chunk_size)
{
    return chunk_size == 64u ||
           chunk_size == 128u ||
           chunk_size == 256u ||
           chunk_size == 512u ||
           chunk_size == 1024u;
}

static int16_t mod_q(int32_t value)
{
    int32_t r = value % DROPOUT_FIELD_MODULUS;
    if (r < 0) {
        r += DROPOUT_FIELD_MODULUS;
    }
    return (int16_t)r;
}

/* The Shamir secret is 32 GF(3329) elements serialized as 64 bytes. */
static pqc_status_t derive_key_from_shamir_secret(
    const uint8_t *shamir_secret,
    uint8_t *derived_key)
{
    static const uint8_t info[] = "dropout-recovery-key";
    uint8_t salt[DROPOUT_KEY_BYTES] = {0};

    if (shamir_secret == NULL || derived_key == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    if (hkdf_sha256(
            salt, sizeof(salt),
            shamir_secret, SHAMIR_SECRET_BYTES,
            info, sizeof(info) - 1u,
            derived_key, DROPOUT_KEY_BYTES) != 0) {
        crypto_zeroize(salt, sizeof(salt));
        crypto_zeroize(derived_key, DROPOUT_KEY_BYTES);
        return ERR_KDF_FAILED;
    }

    crypto_zeroize(salt, sizeof(salt));
    return PQC_SUCCESS;
}

/*
 * Derive the same per-chunk seed used by both mask application and removal.
 * Pairwise seed derivation must be part of both paths; deriving the stream
 * seed directly from the original key would make the two masks differ.
 */
static pqc_status_t derive_pairwise_stream_seed(
    const uint8_t *key,
    uint8_t client_id,
    uint8_t peer_id,
    uint32_t round_id,
    uint16_t chunk_index,
    uint8_t stream_seed[DROPOUT_SEED_BYTES])
{
    uint8_t pairwise_seed[DROPOUT_SEED_BYTES] = {0};
    pqc_status_t status;

    status = kem_adapter_derive_pairwise_mask_seed(
        key, client_id, peer_id, round_id, pairwise_seed);
    if (status != PQC_SUCCESS) {
        crypto_zeroize(pairwise_seed, sizeof(pairwise_seed));
        crypto_zeroize(stream_seed, DROPOUT_SEED_BYTES);
        return status;
    }

    status = kem_adapter_derive_stream_mask_seed(
        pairwise_seed, client_id, round_id, chunk_index, stream_seed);

    crypto_zeroize(pairwise_seed, sizeof(pairwise_seed));
    if (status != PQC_SUCCESS) {
        crypto_zeroize(stream_seed, DROPOUT_SEED_BYTES);
    }
    return status;
}

/* Initialize one recovery session for one dropped-out client. */
pqc_status_t dropout_protocol_init_recovery(
    uint32_t round_id,
    uint8_t client_id,
    uint8_t threshold)
{
    if (threshold == 0u || threshold > MAX_RECOVERY_SHARES) {
        return ERR_INVALID_THRESHOLD;
    }

    crypto_zeroize(&g_recovery_ctx, sizeof(g_recovery_ctx));
    g_recovery_ctx.round_id = round_id;
    g_recovery_ctx.client_id = client_id;
    g_recovery_ctx.threshold = threshold;
    g_recovery_ctx.required_shares = threshold;
    return PQC_SUCCESS;
}

/* Submit a distinct share; reconstruct exactly when the threshold is met. */
pqc_status_t dropout_protocol_submit_share(
    uint8_t share_id,
    const uint8_t *share_value,
    size_t share_len)
{
    uint8_t *share_x;
    const uint8_t **share_y;
    uint16_t *workspace;
    size_t pointer_bytes;
    size_t workspace_offset;
    int ret;

    if (share_value == NULL || share_len != SHAMIR_SHARE_VALUE_BYTES ||
        share_id == 0u) {
        return ERR_INVALID_ARGUMENT;
    }
    if (g_recovery_ctx.required_shares == 0u) {
        return ERR_INVALID_STATE;
    }
    if (g_recovery_ctx.recovery_complete) {
        return ERR_INVALID_STATE;
    }

    for (uint8_t i = 0u; i < g_recovery_ctx.shares_received; ++i) {
        if (g_recovery_ctx.share_ids[i] == share_id) {
            return ERR_DUPLICATE_SHARE_ID;
        }
    }

    if (g_recovery_ctx.shares_received >= g_recovery_ctx.required_shares ||
        g_recovery_ctx.shares_received >= MAX_RECOVERY_SHARES) {
        return ERR_INVALID_STATE;
    }

    uint8_t index = g_recovery_ctx.shares_received;
    g_recovery_ctx.share_ids[index] = share_id;
    g_recovery_ctx.shares[index].share_id = share_id;
    memcpy(g_recovery_ctx.shares[index].value, share_value, share_len);
    g_recovery_ctx.shares_received++;

    if (g_recovery_ctx.shares_received < g_recovery_ctx.required_shares) {
        return PQC_SUCCESS;
    }

    /*
     * Use a scratchpad region with explicitly aligned, non-overlapping
     * arrays. The byte-share API requires one x-coordinate per share and
     * a pointer to each 64-byte y-value.
     */
    share_x = g_scratchpad.raw;
    pointer_bytes = (size_t)MAX_RECOVERY_SHARES * sizeof(*share_y);
    workspace_offset = MAX_RECOVERY_SHARES + pointer_bytes;
    workspace_offset = (workspace_offset + sizeof(uint16_t) - 1u) &
                       ~(sizeof(uint16_t) - 1u);

    if (workspace_offset + (size_t)SHAMIR_WORKSPACE_SIZE * sizeof(uint16_t) >
        sizeof(g_scratchpad.raw)) {
        crypto_zeroize(&g_recovery_ctx, sizeof(g_recovery_ctx));
        return ERR_BUFFER_TOO_SMALL;
    }

    share_y = (const uint8_t **)(void *)(g_scratchpad.raw + MAX_RECOVERY_SHARES);
    workspace = (uint16_t *)(void *)(g_scratchpad.raw + workspace_offset);

    for (uint8_t i = 0u; i < g_recovery_ctx.shares_received; ++i) {
        share_x[i] = g_recovery_ctx.shares[i].share_id;
        share_y[i] = g_recovery_ctx.shares[i].value;
    }

    ret = shamir_reconstruct_bytes(
        g_recovery_ctx.recovered_secret,
        share_x,
        share_y,
        g_recovery_ctx.required_shares,
        workspace);

    crypto_zeroize(g_scratchpad.raw, workspace_offset +
                   (size_t)SHAMIR_WORKSPACE_SIZE * sizeof(uint16_t));

    if (ret != 0) {
        crypto_zeroize(g_recovery_ctx.recovered_secret,
                       sizeof(g_recovery_ctx.recovered_secret));
        g_recovery_ctx.shares_received--;
        crypto_zeroize(&g_recovery_ctx.shares[index],
                       sizeof(g_recovery_ctx.shares[index]));
        g_recovery_ctx.share_ids[index] = 0u;
        return ERR_SHAMIR_DECODE_FAILED;
    }

    g_recovery_ctx.recovery_complete = 1;
    return PQC_SUCCESS;
}

int dropout_protocol_is_recovery_complete(void)
{
    return g_recovery_ctx.recovery_complete;
}

const uint8_t *dropout_protocol_get_recovered_secret(void)
{
    return g_recovery_ctx.recovery_complete
        ? g_recovery_ctx.recovered_secret : NULL;
}

/*
 * Produce chunk_size BYTES of mask into mask, where chunk_size is a byte
 * count as documented in dropout_protocol.h (not a count of int16 elements).
 */
pqc_status_t dropout_protocol_derive_mask_for_recovery(
    uint32_t round_id,
    uint16_t chunk_index,
    uint8_t peer_id,
    int16_t *mask,
    uint16_t chunk_size)
{
    uint8_t derived_key[DROPOUT_KEY_BYTES] = {0};
    uint8_t stream_seed[DROPOUT_SEED_BYTES] = {0};
    mask_prg_ctx_t prg_ctx;
    pqc_status_t status;

    memset(&prg_ctx, 0, sizeof(prg_ctx));

    if (mask == NULL) {
        return ERR_INVALID_ARGUMENT;
    }
    if (!g_recovery_ctx.recovery_complete) {
        return ERR_INVALID_STATE;
    }
    if (round_id != g_recovery_ctx.round_id) {
        return ERR_ROUND_MISMATCH;
    }
    if (!is_valid_chunk_size(chunk_size) ||
        (chunk_size % sizeof(int16_t)) != 0u) {
        return ERR_INVALID_ARGUMENT;
    }

    status = derive_key_from_shamir_secret(
        g_recovery_ctx.recovered_secret, derived_key);
    if (status != PQC_SUCCESS) {
        goto cleanup;
    }

    status = derive_pairwise_stream_seed(
        derived_key, g_recovery_ctx.client_id, peer_id,
        round_id, chunk_index, stream_seed);
    if (status != PQC_SUCCESS) {
        goto cleanup;
    }

    if (mask_prg_init(&prg_ctx, stream_seed) != 0) {
        status = ERR_PRG_FAILED;
        goto cleanup;
    }

    /* chunk_size is bytes, so do not multiply by sizeof(int16_t). */
    if (mask_prg_get_bytes(&prg_ctx, (uint8_t *)mask, chunk_size) != 0) {
        status = ERR_PRG_FAILED;
        mask_prg_cleanup(&prg_ctx);
        goto cleanup;
    }

    mask_prg_cleanup(&prg_ctx);
    status = PQC_SUCCESS;

cleanup:
    crypto_zeroize(derived_key, sizeof(derived_key));
    crypto_zeroize(stream_seed, sizeof(stream_seed));
    crypto_zeroize(&prg_ctx, sizeof(prg_ctx));
    if (status != PQC_SUCCESS) {
        crypto_zeroize(mask, chunk_size);
    }
    return status;
}

/*
 * Unmasking contract: chunk_size is bytes; buffers contain chunk_size/2
 * signed 16-bit field elements. The PRG emits exactly chunk_size mask bytes.
 * The seed derivation is shared with apply_recovered_mask().
 */
pqc_status_t dropout_protocol_unmask_chunk(
    const uint8_t *shared_secret,
    uint32_t round_id,
    uint16_t chunk_index,
    uint8_t client_id,
    uint8_t peer_id,
    const int16_t *masked_data,
    int16_t *unmasked_output,
    uint16_t chunk_size)
{
    uint8_t derived_key[DROPOUT_KEY_BYTES] = {0};
    const uint8_t *key = shared_secret;
    uint8_t stream_seed[DROPOUT_SEED_BYTES] = {0};
    uint8_t mask_bytes[MAX_CHUNK_SIZE] = {0};
    mask_prg_ctx_t prg_ctx;
    pqc_status_t status;
    size_t elements;

    memset(&prg_ctx, 0, sizeof(prg_ctx));

    if (shared_secret == NULL || masked_data == NULL ||
        unmasked_output == NULL) {
        return ERR_INVALID_ARGUMENT;
    }
    if (!is_valid_chunk_size(chunk_size) ||
        (chunk_size % sizeof(int16_t)) != 0u) {
        return ERR_INVALID_ARGUMENT;
    }

    /*
     * A pointer to the recovered secret means the caller supplied the
     * 64-byte Shamir secret. Other callers supply a 32-byte KEM key.
     * This preserves the existing API contract without reading beyond
     * the 32-byte key for ordinary callers.
     */
    if (g_recovery_ctx.recovery_complete &&
        shared_secret == g_recovery_ctx.recovered_secret) {
        status = derive_key_from_shamir_secret(
            g_recovery_ctx.recovered_secret, derived_key);
        if (status != PQC_SUCCESS) {
            goto cleanup;
        }
        key = derived_key;
    }

    status = derive_pairwise_stream_seed(
        key, client_id, peer_id, round_id, chunk_index, stream_seed);
    if (status != PQC_SUCCESS) {
        goto cleanup;
    }

    if (mask_prg_init(&prg_ctx, stream_seed) != 0) {
        status = ERR_PRG_FAILED;
        goto cleanup;
    }
    if (mask_prg_get_bytes(&prg_ctx, mask_bytes, chunk_size) != 0) {
        mask_prg_cleanup(&prg_ctx);
        status = ERR_PRG_FAILED;
        goto cleanup;
    }
    mask_prg_cleanup(&prg_ctx);

    elements = (size_t)chunk_size / sizeof(int16_t);
    for (size_t i = 0u; i < elements; ++i) {
        int32_t diff = (int32_t)masked_data[i] -
                       (int32_t)((int16_t)((uint16_t)mask_bytes[2u * i] |
                                           ((uint16_t)mask_bytes[2u * i + 1u] << 8)));
        unmasked_output[i] = mod_q(diff);
    }
    status = PQC_SUCCESS;

cleanup:
    crypto_zeroize(derived_key, sizeof(derived_key));
    crypto_zeroize(stream_seed, sizeof(stream_seed));
    crypto_zeroize(mask_bytes, sizeof(mask_bytes));
    crypto_zeroize(&prg_ctx, sizeof(prg_ctx));
    if (status != PQC_SUCCESS) {
        /* Do not expose partial output on an error. */
        crypto_zeroize(unmasked_output, chunk_size);
    }
    return status;
}

/* Apply a mask to plaintext: masked = plaintext + mask (mod q). */
pqc_status_t dropout_protocol_apply_recovered_mask(
    const uint8_t *shared_secret,
    uint32_t round_id,
    uint16_t chunk_index,
    uint8_t client_id,
    uint8_t peer_id,
    const int16_t *plaintext_chunk,
    int16_t *masked_output,
    uint16_t chunk_size)
{
    uint8_t derived_key[DROPOUT_KEY_BYTES] = {0};
    const uint8_t *key = shared_secret;
    uint8_t stream_seed[DROPOUT_SEED_BYTES] = {0};
    uint8_t mask_bytes[MAX_CHUNK_SIZE] = {0};
    mask_prg_ctx_t prg_ctx;
    pqc_status_t status;
    size_t elements;

    memset(&prg_ctx, 0, sizeof(prg_ctx));

    if (shared_secret == NULL || plaintext_chunk == NULL ||
        masked_output == NULL) {
        return ERR_INVALID_ARGUMENT;
    }
    if (!is_valid_chunk_size(chunk_size) ||
        (chunk_size % sizeof(int16_t)) != 0u) {
        return ERR_INVALID_ARGUMENT;
    }

    if (g_recovery_ctx.recovery_complete &&
        shared_secret == g_recovery_ctx.recovered_secret) {
        status = derive_key_from_shamir_secret(
            g_recovery_ctx.recovered_secret, derived_key);
        if (status != PQC_SUCCESS) {
            goto cleanup;
        }
        key = derived_key;
    }

    status = derive_pairwise_stream_seed(
        key, client_id, peer_id, round_id, chunk_index, stream_seed);
    if (status != PQC_SUCCESS) {
        goto cleanup;
    }

    if (mask_prg_init(&prg_ctx, stream_seed) != 0) {
        status = ERR_PRG_FAILED;
        goto cleanup;
    }
    if (mask_prg_get_bytes(&prg_ctx, mask_bytes, chunk_size) != 0) {
        mask_prg_cleanup(&prg_ctx);
        status = ERR_PRG_FAILED;
        goto cleanup;
    }
    mask_prg_cleanup(&prg_ctx);

    elements = (size_t)chunk_size / sizeof(int16_t);
    for (size_t i = 0u; i < elements; ++i) {
        uint16_t mask_value = (uint16_t)mask_bytes[2u * i] |
                              ((uint16_t)mask_bytes[2u * i + 1u] << 8);
        masked_output[i] = mod_q((int32_t)plaintext_chunk[i] +
                                 (int32_t)mask_value);
    }
    status = PQC_SUCCESS;

cleanup:
    crypto_zeroize(derived_key, sizeof(derived_key));
    crypto_zeroize(stream_seed, sizeof(stream_seed));
    crypto_zeroize(mask_bytes, sizeof(mask_bytes));
    crypto_zeroize(&prg_ctx, sizeof(prg_ctx));
    if (status != PQC_SUCCESS) {
        crypto_zeroize(masked_output, chunk_size);
    }
    return status;
}

void dropout_protocol_cleanup(void)
{
    crypto_zeroize(&g_recovery_ctx, sizeof(g_recovery_ctx));
}

int dropout_protocol_is_complete(void)
{
    return g_recovery_ctx.recovery_complete;
}

void dropout_protocol_get_info(
    uint32_t *round_id,
    uint8_t *client_id,
    uint8_t *threshold,
    uint8_t *shares_received)
{
    if (round_id != NULL) *round_id = g_recovery_ctx.round_id;
    if (client_id != NULL) *client_id = g_recovery_ctx.client_id;
    if (threshold != NULL) *threshold = g_recovery_ctx.threshold;
    if (shares_received != NULL) *shares_received = g_recovery_ctx.shares_received;
}
