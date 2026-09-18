#include "protocol_types.h"
#include "memory_scratchpad.h"
#include "kem_adapter.h"
#include "mask_prg.h"
#include <stdint.h>
#include <string.h>

static pairwise_context_t* get_pairwise_ctx(void) {
    protocol_state_buffer_t* proto = scratch_get_proto_state();
    return (pairwise_context_t*)proto->data;
}

static int16_t mod_q(int32_t val) {
    int32_t r = val % 3329;
    if (r < 0) {
        r += 3329;
    }
    return (int16_t)r;
}

pqc_status_t mask_protocol_init_pairwise(pairwise_context_t* ctx, uint8_t num_peers) {
    if (!ctx || num_peers > MAX_PEERS_PER_CLIENT) return ERR_INVALID_ARGUMENT;
    memset(ctx, 0, sizeof(pairwise_context_t));
    ctx->num_peers = num_peers;
    return PQC_SUCCESS;
}

pqc_status_t mask_protocol_derive_pairwise_seeds(pairwise_context_t* ctx, uint8_t local_id, const uint8_t* peer_kem_secrets, uint32_t round_id) {
    if (!ctx || !peer_kem_secrets || ctx->num_peers == 0) return ERR_INVALID_ARGUMENT;
    for (uint8_t i = 0; i < ctx->num_peers; i++) {
        uint8_t peer_id = ctx->peers[i].peer_client_id;
        uint8_t client_a = local_id;
        uint8_t client_b = peer_id;
        if (client_a > client_b) {
            uint8_t tmp = client_a;
            client_a = client_b;
            client_b = tmp;
        }
        pqc_status_t ret = kem_adapter_derive_pairwise_mask_seed(
            &peer_kem_secrets[i * ML_KEM_1024_SHARED_SECRET_BYTES],
            client_a, client_b, round_id,
            ctx->peers[i].mask_seed
        );
        if (ret != PQC_SUCCESS) return ret;
        memcpy(ctx->peers[i].shared_secret, &peer_kem_secrets[i * ML_KEM_1024_SHARED_SECRET_BYTES], ML_KEM_1024_SHARED_SECRET_BYTES);
    }
    return PQC_SUCCESS;
}

pqc_status_t mask_protocol_generate_chunk_mask(pairwise_context_t* ctx, uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size, int16_t* output_mask) {
    if (!ctx || !output_mask || chunk_size > 128) return ERR_INVALID_ARGUMENT;
    crypto_zeroize(output_mask, chunk_size * sizeof(int16_t));
    for (uint8_t i = 0; i < ctx->num_peers; i++) {
        uint8_t stream_seed[32];
        pqc_status_t ret = kem_adapter_derive_stream_mask_seed(
            ctx->peers[i].mask_seed, client_id, round_id, chunk_index, stream_seed
        );
        if (ret != PQC_SUCCESS) return ret;
        mask_prg_init(stream_seed);
        int16_t peer_mask[128];
        mask_prg_expand((uint8_t*)peer_mask, chunk_size * sizeof(int16_t));
        int32_t sign = (client_id < ctx->peers[i].peer_client_id) ? 1 : -1;
        for (uint16_t j = 0; j < chunk_size; j++) {
            int32_t val = (int32_t)output_mask[j] + sign * (int32_t)(peer_mask[j] % 3329);
            output_mask[j] = mod_q(val);
        }
        crypto_zeroize(peer_mask, sizeof(peer_mask));
        crypto_zeroize(stream_seed, 32);
    }
    return PQC_SUCCESS;
}

pqc_status_t mask_protocol_apply_mask(const int16_t* input, const int16_t* mask, uint16_t num_elements, int16_t* output) {
    if (!input || !mask || !output) return ERR_INVALID_ARGUMENT;
    for (uint16_t i = 0; i < num_elements; i++) {
        output[i] = mod_q((int32_t)input[i] + (int32_t)mask[i]);
    }
    return PQC_SUCCESS;
}

pqc_status_t mask_protocol_remove_mask(const int16_t* input, const int16_t* mask, uint16_t num_elements, int16_t* output) {
    if (!input || !mask || !output) return ERR_INVALID_ARGUMENT;
    for (uint16_t i = 0; i < num_elements; i++) {
        output[i] = mod_q((int32_t)input[i] - (int32_t)mask[i]);
    }
    return PQC_SUCCESS;
}

pqc_status_t mask_protocol_zeroize_pairwise(pairwise_context_t* ctx) {
    if (!ctx) return ERR_INVALID_ARGUMENT;
    crypto_zeroize(ctx, sizeof(pairwise_context_t));
    return PQC_SUCCESS;
}
