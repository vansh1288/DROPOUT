#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "FreeRTOS.h"
#include "task.h"
#include "driver/gdma.h"
#include "hal/gdma_ll.h"
#include "esp_intr_alloc.h"
#include <stdint.h>

#define GDMA_TX_CHANNEL 0
#define GDMA_RX_CHANNEL 1

static gdma_channel_handle_t tx_channel = NULL;
static gdma_channel_handle_t rx_channel = NULL;
static volatile uint8_t dma_rx_active = 0;
static volatile uint8_t dma_tx_active = 0;
static TaskHandle_t stream_task_handle = NULL;
static gdma_descriptor_t tx_descriptors[2] __attribute__((aligned(4)));
static gdma_descriptor_t rx_descriptors[2] __attribute__((aligned(4)));
static intr_handle_t tx_intr_handle = NULL;
static intr_handle_t rx_intr_handle = NULL;

static bool IRAM_ATTR gdma_rx_eof_callback(gdma_channel_handle_t handle, const gdma_event_data_t *event, void *user_data) {
    BaseType_t higher_priority_task_woken = pdFALSE;
    dma_rx_active ^= 1u;
    if (stream_task_handle != NULL) {
        xTaskNotifyFromISR(stream_task_handle, 0x01, eSetBits, &higher_priority_task_woken);
    }
    return higher_priority_task_woken == pdTRUE;
}

static bool IRAM_ATTR gdma_tx_eof_callback(gdma_channel_handle_t handle, const gdma_event_data_t *event, void *user_data) {
    BaseType_t higher_priority_task_woken = pdFALSE;
    dma_tx_active ^= 1u;
    if (stream_task_handle != NULL) {
        xTaskNotifyFromISR(stream_task_handle, 0x02, eSetBits, &higher_priority_task_woken);
    }
    return higher_priority_task_woken == pdTRUE;
}

static void gdma_rx_descriptor_init(void) {
    dma_double_buffer_t *dma_rx = scratch_get_dma_rx();
    rx_descriptors[0].buffer = dma_rx->ping;
    rx_descriptors[0].dw0.size = DMA_BUFFER_BYTES;
    rx_descriptors[0].dw0.suc_eof = 1;
    rx_descriptors[0].next = &rx_descriptors[1];
    rx_descriptors[1].buffer = dma_rx->pong;
    rx_descriptors[1].dw0.size = DMA_BUFFER_BYTES;
    rx_descriptors[1].dw0.suc_eof = 1;
    rx_descriptors[1].next = &rx_descriptors[0];
}

static void gdma_tx_descriptor_init(void) {
    dma_double_buffer_t *dma_tx = scratch_get_dma_tx();
    tx_descriptors[0].buffer = dma_tx->ping;
    tx_descriptors[0].dw0.size = 0;
    tx_descriptors[0].dw0.suc_eof = 1;
    tx_descriptors[0].next = &tx_descriptors[1];
    tx_descriptors[1].buffer = dma_tx->pong;
    tx_descriptors[1].dw0.size = 0;
    tx_descriptors[1].dw0.suc_eof = 1;
    tx_descriptors[1].next = &tx_descriptors[0];
}

static void gdma_rx_config(void) {
    gdma_channel_alloc_config_t rx_alloc = {
        .direction = GDMA_CHANNEL_DIRECTION_RX,
        .channel_id = GDMA_RX_CHANNEL,
    };
    gdma_new_channel(&rx_alloc, &rx_channel);
    gdma_rx_descriptor_init();
    gdma_connect(rx_channel, GDMA_MAKE_TRIGGER(GDMA_TRIG_PERIPH_WIFI, 0));
    gdma_rx_event_callbacks_t rx_cbs = {
        .on_recv_eof = gdma_rx_eof_callback,
    };
    gdma_register_rx_event_callbacks(rx_channel, &rx_cbs, NULL);
    gdma_start(rx_channel, (intptr_t)&rx_descriptors[0]);
}

static void gdma_tx_config(void) {
    gdma_channel_alloc_config_t tx_alloc = {
        .direction = GDMA_CHANNEL_DIRECTION_TX,
        .channel_id = GDMA_TX_CHANNEL,
    };
    gdma_new_channel(&tx_alloc, &tx_channel);
    gdma_tx_descriptor_init();
    gdma_connect(tx_channel, GDMA_MAKE_TRIGGER(GDMA_TRIG_PERIPH_WIFI, 0));
    gdma_tx_event_callbacks_t tx_cbs = {
        .on_trans_eof = gdma_tx_eof_callback,
    };
    gdma_register_tx_event_callbacks(tx_channel, &tx_cbs, NULL);
}

pqc_status_t dma_transport_esp32_init(void) {
    dma_double_buffer_t *dma_rx = scratch_get_dma_rx();
    dma_double_buffer_t *dma_tx = scratch_get_dma_tx();
    crypto_zeroize(dma_rx->ping, DMA_BUFFER_BYTES);
    crypto_zeroize(dma_rx->pong, DMA_BUFFER_BYTES);
    crypto_zeroize(dma_tx->ping, DMA_BUFFER_BYTES);
    crypto_zeroize(dma_tx->pong, DMA_BUFFER_BYTES);
    gdma_rx_config();
    gdma_tx_config();
    return PQC_SUCCESS;
}

void dma_transport_esp32_set_stream_task(TaskHandle_t handle) {
    stream_task_handle = handle;
}

pqc_status_t dma_transport_esp32_start_rx(void) {
    return PQC_SUCCESS;
}

pqc_status_t dma_transport_esp32_start_tx(const uint8_t *data, uint16_t len) {
    if (len > DMA_BUFFER_BYTES) return ERR_CHUNK_TOO_LARGE;
    dma_double_buffer_t *dma_tx = scratch_get_dma_tx();
    uint8_t *active_buf = dma_tx_active ? dma_tx->pong : dma_tx->ping;
    gdma_descriptor_t *desc = dma_tx_active ? &tx_descriptors[1] : &tx_descriptors[0];
    desc->buffer = active_buf;
    desc->dw0.size = len;
    gdma_start(tx_channel, (intptr_t)desc);
    return PQC_SUCCESS;
}

uint8_t dma_transport_esp32_get_rx_active(void) {
    return dma_rx_active;
}

uint8_t dma_transport_esp32_get_tx_active(void) {
    return dma_tx_active;
}