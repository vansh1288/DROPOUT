#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "dma_isr_handler.h"
#include "FreeRTOS.h"
#include "task.h"
#include "stm32h7xx_hal.h"
#include <stdint.h>
#include <string.h>

#define DMA_RX_STREAM DMA1_Stream0
#define DMA_TX_STREAM DMA1_Stream1
#define DMA_RX_CHANNEL DMA_CHANNEL_0
#define DMA_TX_CHANNEL DMA_CHANNEL_1
#define DMA_BUFFER_SIZE DMA_BUFFER_BYTES

static DMA_HandleTypeDef hdma_rx;
static DMA_HandleTypeDef hdma_tx;
static volatile uint8_t dma_rx_active = 0;
static volatile uint8_t dma_tx_active = 0;
static TaskHandle_t stream_task_handle = NULL;

static void dma_rx_complete_callback(DMA_HandleTypeDef *hdma) {
    BaseType_t higher_priority_task_woken = pdFALSE;
    dma_rx_active ^= 1u;
    if (stream_task_handle != NULL) {
        xTaskNotifyFromISR(stream_task_handle, 0x01, eSetBits, &higher_priority_task_woken);
    }
    portYIELD_FROM_ISR(higher_priority_task_woken);
}

static void dma_tx_complete_callback(DMA_HandleTypeDef *hdma) {
    BaseType_t higher_priority_task_woken = pdFALSE;
    dma_tx_active ^= 1u;
    if (stream_task_handle != NULL) {
        xTaskNotifyFromISR(stream_task_handle, 0x02, eSetBits, &higher_priority_task_woken);
    }
    portYIELD_FROM_ISR(higher_priority_task_woken);
}

static void dma_error_callback(DMA_HandleTypeDef *hdma) {
    BaseType_t higher_priority_task_woken = pdFALSE;
    if (stream_task_handle != NULL) {
        xTaskNotifyFromISR(stream_task_handle, 0x80, eSetBits, &higher_priority_task_woken);
    }
    portYIELD_FROM_ISR(higher_priority_task_woken);
}

static void dma_rx_config(uint8_t *buffer) {
    __HAL_DMA_DISABLE(&hdma_rx);
    hdma_rx.Instance = DMA_RX_STREAM;
    hdma_rx.Init.Request = DMA_REQUEST_ETH_RX;
    hdma_rx.Init.Direction = DMA_PERIPH_TO_MEMORY;
    hdma_rx.Init.PeriphInc = DMA_PINC_DISABLE;
    hdma_rx.Init.MemInc = DMA_MINC_ENABLE;
    hdma_rx.Init.PeriphDataAlignment = DMA_PDATAALIGN_BYTE;
    hdma_rx.Init.MemDataAlignment = DMA_MDATAALIGN_BYTE;
    hdma_rx.Init.Mode = DMA_CIRCULAR;
    hdma_rx.Init.Priority = DMA_PRIORITY_HIGH;
    hdma_rx.Init.FIFOMode = DMA_FIFOMODE_ENABLE;
    hdma_rx.Init.FIFOThreshold = DMA_FIFO_THRESHOLD_FULL;
    hdma_rx.Init.MemBurst = DMA_MBURST_INC4;
    hdma_rx.Init.PeriphBurst = DMA_PBURST_INC4;
    HAL_DMA_Init(&hdma_rx);
    __HAL_LINKDMA(&hdma_rx, Parent, hdma_rx);
    HAL_DMA_RegisterCallback(&hdma_rx, HAL_DMA_XFER_CPLT_CB_ID, dma_rx_complete_callback);
    HAL_DMA_RegisterCallback(&hdma_rx, HAL_DMA_XFER_ERROR_CB_ID, dma_error_callback);
    HAL_DMA_Start_IT(&hdma_rx, (uint32_t)&ETH->DMACurrentRxDesc->Buffer1Addr, (uint32_t)buffer, DMA_BUFFER_SIZE);
}

static void dma_tx_config(uint8_t *buffer, uint16_t len) {
    __HAL_DMA_DISABLE(&hdma_tx);
    hdma_tx.Instance = DMA_TX_STREAM;
    hdma_tx.Init.Request = DMA_REQUEST_ETH_TX;
    hdma_tx.Init.Direction = DMA_MEMORY_TO_PERIPH;
    hdma_tx.Init.PeriphInc = DMA_PINC_DISABLE;
    hdma_tx.Init.MemInc = DMA_MINC_ENABLE;
    hdma_tx.Init.PeriphDataAlignment = DMA_PDATAALIGN_BYTE;
    hdma_tx.Init.MemDataAlignment = DMA_MDATAALIGN_BYTE;
    hdma_tx.Init.Mode = DMA_NORMAL;
    hdma_tx.Init.Priority = DMA_PRIORITY_HIGH;
    hdma_tx.Init.FIFOMode = DMA_FIFOMODE_ENABLE;
    hdma_tx.Init.FIFOThreshold = DMA_FIFO_THRESHOLD_FULL;
    hdma_tx.Init.MemBurst = DMA_MBURST_INC4;
    hdma_tx.Init.PeriphBurst = DMA_PBURST_INC4;
    HAL_DMA_Init(&hdma_tx);
    __HAL_LINKDMA(&hdma_tx, Parent, hdma_tx);
    HAL_DMA_RegisterCallback(&hdma_tx, HAL_DMA_XFER_CPLT_CB_ID, dma_tx_complete_callback);
    HAL_DMA_RegisterCallback(&hdma_tx, HAL_DMA_XFER_ERROR_CB_ID, dma_error_callback);
    HAL_DMA_Start_IT(&hdma_tx, (uint32_t)buffer, (uint32_t)&ETH->DMACurrentTxDesc->Buffer1Addr, len);
}

pqc_status_t dma_transport_stm32_init(void) {
    __HAL_RCC_DMA1_CLK_ENABLE();
    HAL_NVIC_SetPriority(DMA1_Stream0_IRQn, 5, 0);
    HAL_NVIC_EnableIRQ(DMA1_Stream0_IRQn);
    HAL_NVIC_SetPriority(DMA1_Stream1_IRQn, 5, 0);
    HAL_NVIC_EnableIRQ(DMA1_Stream1_IRQn);
    dma_double_buffer_t *dma_rx = scratch_get_dma_rx();
    dma_double_buffer_t *dma_tx = scratch_get_dma_tx();
    crypto_zeroize(dma_rx->ping, DMA_BUFFER_BYTES);
    crypto_zeroize(dma_rx->pong, DMA_BUFFER_BYTES);
    crypto_zeroize(dma_tx->ping, DMA_BUFFER_BYTES);
    crypto_zeroize(dma_tx->pong, DMA_BUFFER_BYTES);
    dma_rx_config(dma_rx->ping);
    dma_isr_set_stream_task(stream_task_handle);
    return PQC_SUCCESS;
}

void dma_transport_stm32_set_stream_task(TaskHandle_t handle) {
    stream_task_handle = handle;
    dma_isr_set_stream_task(handle);
}

pqc_status_t dma_transport_stm32_start_rx(void) {
    return PQC_SUCCESS;
}

pqc_status_t dma_transport_stm32_start_tx(const uint8_t *data, uint16_t len) {
    if (len > DMA_BUFFER_SIZE) return ERR_CHUNK_TOO_LARGE;
    dma_double_buffer_t *dma_tx = scratch_get_dma_tx();
    uint8_t *active_buf = dma_tx_active ? dma_tx->pong : dma_tx->ping;
    memcpy(active_buf, data, len);
    dma_tx_config(active_buf, len);
    return PQC_SUCCESS;
}

uint8_t dma_transport_stm32_get_rx_active(void) {
    return dma_rx_active;
}

uint8_t dma_transport_stm32_get_tx_active(void) {
    return dma_tx_active;
}

void DMA1_Stream0_IRQHandler(void) {
    HAL_DMA_IRQHandler(&hdma_rx);
}

void DMA1_Stream1_IRQHandler(void) {
    HAL_DMA_IRQHandler(&hdma_tx);
}