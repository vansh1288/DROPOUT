#ifndef MASK_PROTOCOL_H
#define MASK_PROTOCOL_H

#include "protocol_types.h"
#include <stdint.h>

#define CHUNK_BUFFER_BYTES 1024

#ifdef __cplusplus
extern "C" {
#endif

pqc_status_t mask_protocol_init_pairwise(pairwise_context_t* ctx, uint8_t num_peers);
pqc_status_t mask_protocol_derive_pairwise_seeds(pairwise_context_t* ctx, uint8_t local_id, const uint8_t* client_client_kem_secrets, uint32_t round_id);
pqc_status_t mask_protocol_generate_chunk_mask(pairwise_context_t* ctx, uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size, int16_t* output_mask);
pqc_status_t mask_protocol_apply_mask(const int16_t* input, const int16_t* mask, uint16_t num_elements, int16_t* output);
pqc_status_t mask_protocol_remove_mask(const int16_t* input, const int16_t* mask, uint16_t num_elements, int16_t* output);
pqc_status_t mask_protocol_zeroize_pairwise(pairwise_context_t* ctx);

#ifdef __cplusplus
}
#endif

#endif