
#ifndef DMA_ISR_HANDLER_H
#define DMA_ISR_HANDLER_H

#include "protocol_types.h"
#include "FreeRTOS.h"
#include "task.h"
#include <stdint.h>

/* DMA completion and error handlers */
void dma_isr_rx_complete(void);
void dma_isr_tx_complete(void);
void dma_isr_error(void);

/* Register the network coordinator task */
void dma_isr_set_network_task(TaskHandle_t handle);

/* Initialize DMA state and buffers */
void dma_isr_init(void);

/* Start DMA operations */
pqc_status_t dma_isr_start_rx(void);
pqc_status_t dma_isr_start_tx(const uint8_t *data, uint16_t len);

/* Access active DMA buffers */
uint8_t *dma_get_rx_buffer(void);
uint8_t *dma_get_tx_buffer(void);

/* Get active DMA buffer indices */
uint8_t dma_isr_get_rx_active(void);
uint8_t dma_isr_get_tx_active(void);

#endif /* DMA_ISR_HANDLER_H */