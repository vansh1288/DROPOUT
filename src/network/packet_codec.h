#ifndef PACKET_CODEC_H
#define PACKET_CODEC_H

#include "protocol_types.h"
#include <stdint.h>
#include <stddef.h>

#define MAC_SIZE 32
#define HEADER_SIZE 48

pqc_status_t packet_codec_encode_header(const msg_header_t* hdr, uint8_t* out);
pqc_status_t packet_codec_decode_header(const uint8_t* in, msg_header_t* hdr);
pqc_status_t packet_codec_encode_message(const msg_header_t* hdr, const uint8_t* payload, const uint8_t* mac_key, uint8_t* out, size_t* out_len);
pqc_status_t packet_codec_decode_message(const uint8_t* in, size_t in_len, const uint8_t* mac_key, msg_header_t* hdr, uint8_t* payload, size_t* payload_len);
pqc_status_t packet_codec_validate_sequence(const msg_header_t* hdr, uint16_t expected_seq);
pqc_status_t packet_codec_validate_round(const msg_header_t* hdr, uint32_t expected_round);
pqc_status_t packet_codec_validate_client(const msg_header_t* hdr, uint8_t expected_client);

#endif
