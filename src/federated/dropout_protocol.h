#ifndef DROPOUT_PROTOCOL_H
#define DROPOUT_PROTOCOL_H

#include "protocol_types.h"
#include "shamir.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

pqc_status_t dropout_protocol_derive_mask_for_recovery(
    const uint8_t *shamir_secret,
    uint8_t client_id,
    uint32_t round_id,
    uint16_t chunk_index,
    uint8_t peer_id,
    int16_t *mask,
    uint16_t chunk_size);

pqc_status_t dropout_protocol_generate_shares(
    const uint8_t *secret,
    uint8_t threshold,
    uint8_t num_shares,
    shamir_share_t *shares);

pqc_status_t dropout_protocol_reconstruct_secret(
    const shamir_share_t *shares,
    uint8_t num_shares,
    uint8_t threshold,
    uint8_t *secret);

#ifdef __cplusplus
}
#endif

#endif /* DROPOUT_PROTOCOL_H */