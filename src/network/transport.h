#ifndef TRANSPORT_H
#define TRANSPORT_H

#include "protocol_types.h"
#include <stdint.h>
#include <stddef.h>

#if defined(PLATFORM_STM32H7)
pqc_status_t dma_transport_stm32_init(void);
void dma_transport_stm32_set_stream_task(TaskHandle_t handle);
pqc_status_t dma_transport_stm32_start_rx(void);
pqc_status_t dma_transport_stm32_start_tx(const uint8_t *data, uint16_t len);
uint8_t dma_transport_stm32_get_rx_active(void);
uint8_t dma_transport_stm32_get_tx_active(void);
#elif defined(PLATFORM_ESP32)
pqc_status_t dma_transport_esp32_init(void);
void dma_transport_esp32_set_stream_task(TaskHandle_t handle);
pqc_status_t dma_transport_esp32_start_rx(void);
pqc_status_t dma_transport_esp32_start_tx(const uint8_t *data, uint16_t len);
uint8_t dma_transport_esp32_get_rx_active(void);
uint8_t dma_transport_esp32_get_tx_active(void);
#else
pqc_status_t transport_init(int rx_sock, int tx_sock);
pqc_status_t transport_set_impairment(const void *config);
pqc_status_t transport_rx_poll(void);
pqc_status_t transport_tx_poll(void);
pqc_status_t transport_queue_tx(const uint8_t *data, size_t len);
pqc_status_t transport_get_rx_data(uint8_t *out, size_t *len);
#endif

#endif