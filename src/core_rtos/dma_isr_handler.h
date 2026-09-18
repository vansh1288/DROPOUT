#ifndef DMA_ISR_HANDLER_H
#define DMA_ISR_HANDLER_H

#include "protocol_types.h"
#include "FreeRTOS.h"
#include <stdint.h>

void dma_isr_rx_complete(void);
void dma_isr_tx_complete(void);
void dma_isr_error(void);
void dma_isr_set_stream_task(TaskHandle_t handle);
void dma_isr_init(void);
pqc_status_t dma_isr_start_rx(void);
pqc_status_t dma_isr_start_tx(const uint8_t* data, uint16_t len);
uint8_t dma_isr_get_rx_active(void);
uint8_t dma_isr_get_tx_active(void);

#endif