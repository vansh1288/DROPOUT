#ifndef STREAM_AGGREGATOR_H
#define STREAM_AGGREGATOR_H

#include "protocol_types.h"
#include <stdint.h>

pqc_status_t stream_aggregator_process_chunk(uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size);
pqc_status_t stream_aggregator_unmask_chunk(uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size);

#endif