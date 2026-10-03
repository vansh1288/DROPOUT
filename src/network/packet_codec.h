#ifndef PACKET_CODEC_H
#define PACKET_CODEC_H

#include "protocol_types.h"
#include <stdint.h>
#include <stddef.h>

#define MAC_SIZE 32
#define HEADER_SIZE 16
#define MAC_OFFSET (HEADER_SIZE)

/* Maximum number of chunks we can track for duplicate detection */
#define MAX_TRACKED_CHUNKS 256

typedef struct {
    uint16_t sequence_numbers[MAX_TRACKED_CHUNKS];
    uint8_t count;
} chunk_tracker_t;

/* Initialize chunk tracker */
void packet_codec_tracker_init(chunk_tracker_t* tracker);

/* Check if chunk is duplicate, return PQC_SUCCESS if new, ERR_REPLAY_DETECTED if duplicate */
pqc_status_t packet_codec_tracker_check(chunk_tracker_t* tracker, uint16_t seq_num);

/* AAD (Additional Authenticated Data) context for authenticated encryption */
typedef struct {
    uint32_t round_id;
    uint8_t client_id;
    uint16_t chunk_index;
    uint16_t chunk_size;
} aad_context_t;

/* Build AAD from context for authenticated encryption */
void packet_codec_build_aad(const aad_context_t* ctx, uint8_t* aad, size_t* aad_len);

pqc_status_t packet_codec_encode_header(const msg_header_t* hdr, uint8_t* out);
pqc_status_t packet_codec_decode_header(const uint8_t* in, msg_header_t* hdr);
pqc_status_t packet_codec_encode_message(const msg_header_t* hdr, const uint8_t* payload, const uint8_t* mac_key, uint8_t* out, size_t* out_len);
pqc_status_t packet_codec_decode_message(const uint8_t* in, size_t in_len, const uint8_t* mac_key, msg_header_t* hdr, uint8_t* payload, size_t* payload_len);
pqc_status_t packet_codec_validate_sequence(const msg_header_t* hdr, uint16_t expected_seq);
pqc_status_t packet_codec_validate_round(const msg_header_t* hdr, uint32_t expected_round);
pqc_status_t packet_codec_validate_client(const msg_header_t* hdr, uint8_t expected_client);

/* Enhanced validation with AAD binding */
pqc_status_t packet_codec_validate_message(const msg_header_t* hdr, const aad_context_t* expected_aad, const uint8_t* mac_key, const uint8_t* received_mac);

#endif
