#ifndef DROPOUT_PROTOCOL_H
#define DROPOUT_PROTOCOL_H

#include "protocol_types.h"
#include <stdint.h>

#define FIELD_MODULUS 3329
#define BARRETT_MULTIPLIER 20159
#define BARRETT_SHIFT 26
#define SHAMIR_MAX_THRESHOLD 32

#ifdef __cplusplus
extern "C" {
#endif

pqc_status_t dropout_protocol_derive_mask_for_recovery(const uint8_t* shamir_secret, uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint8_t peer_id, int16_t* mask, uint16_t chunk_size);

#ifdef __cplusplus
}
#endif

#endif