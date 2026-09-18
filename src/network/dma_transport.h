#ifndef DMA_TRANSPORT_H
#define DMA_TRANSPORT_H

#include "protocol_types.h"
#include <stdint.h>

pqc_status_t dma_transport_init(int rx_sock, int tx_sock);
pqc_status_t dma_transport_rx_poll(void);
pqc_status_t dma_transport_tx_poll(void);
pqc_status_t dma_transport_queue_tx(const uint8_t* data, size_t len);
pqc_status_t dma_transport_get_rx_data(uint8_t* out, size_t* len);
void dma_transport_rx_complete_callback(void);
void dma_transport_tx_complete_callback(void);

#endif