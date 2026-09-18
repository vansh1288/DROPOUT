#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "dma_isr_handler.h"
#include "transport.h"
#include <stdint.h>
#include <string.h>

#define DMA_CHUNK_SIZE 256

static int g_rx_sock = -1;
static int g_tx_sock = -1;
static uint8_t g_dma_rx_pending = 0;
static uint8_t g_dma_tx_pending = 0;

pqc_status_t dma_transport_init(int rx_sock, int tx_sock) {
    g_rx_sock = rx_sock;
    g_tx_sock = tx_sock;
    g_dma_rx_pending = 0;
    g_dma_tx_pending = 0;
    dma_isr_init();
    return PQC_SUCCESS;
}

pqc_status_t dma_transport_rx_poll(void) {
    if (g_rx_sock < 0 || g_dma_rx_pending) return ERR_INVALID_STATE;
    uint8_t* buf = dma_get_rx_buffer();
    size_t received;
    pqc_status_t ret = transport_recv(g_rx_sock, buf, DMA_CHUNK_SIZE, &received);
    if (ret == PQC_SUCCESS && received > 0) {
        g_dma_rx_pending = 1;
        dma_isr_rx_complete();
    }
    return ret;
}

pqc_status_t dma_transport_tx_poll(void) {
    if (g_tx_sock < 0 || !g_dma_tx_pending) return ERR_INVALID_STATE;
    uint8_t* buf = dma_get_tx_buffer();
    size_t sent;
    pqc_status_t ret = transport_send(g_tx_sock, buf, DMA_CHUNK_SIZE, &sent);
    if (ret == PQC_SUCCESS) {
        g_dma_tx_pending = 0;
        dma_isr_tx_complete();
    }
    return ret;
}

pqc_status_t dma_transport_queue_tx(const uint8_t* data, size_t len) {
    if (!data || len > DMA_CHUNK_SIZE || g_dma_tx_pending) return ERR_INVALID_ARGUMENT;
    uint8_t* buf = dma_get_tx_buffer();
    memcpy(buf, data, len);
    g_dma_tx_pending = 1;
    return PQC_SUCCESS;
}

pqc_status_t dma_transport_get_rx_data(uint8_t* out, size_t* len) {
    if (!out || !len || !g_dma_rx_pending) return ERR_INVALID_STATE;
    uint8_t* buf = dma_get_rx_buffer();
    *len = DMA_CHUNK_SIZE;
    memcpy(out, buf, DMA_CHUNK_SIZE);
    g_dma_rx_pending = 0;
    return PQC_SUCCESS;
}

void dma_transport_rx_complete_callback(void) {
    g_dma_rx_pending = 0;
}

void dma_transport_tx_complete_callback(void) {
    g_dma_tx_pending = 0;
}