#ifndef STREAM_AGGREGATOR_H
#define STREAM_AGGREGATOR_H

#include "protocol_types.h"
#include "FreeRTOS.h"
#include <stdint.h>

#define STREAM_OP_PROCESS 1
#define STREAM_OP_UNMASK 2

typedef struct {
    uint8_t op;
    uint8_t client_id;
    uint32_t round_id;
    uint16_t chunk_index;
    uint16_t chunk_size;
    const uint8_t* shared_secret;
} stream_work_item_t;

void stream_aggregator_init(void);
TaskHandle_t stream_aggregator_get_task_handle(void);
BaseType_t stream_aggregator_submit(const stream_work_item_t* item, TickType_t timeout);
pqc_status_t stream_aggregator_process_chunk(uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size, const uint8_t* shared_secret);
pqc_status_t stream_aggregator_unmask_chunk(uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size, const uint8_t* shared_secret);

#endif
