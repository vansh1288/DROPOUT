
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "dma_isr_handler.h"
#include "dma_transport.h"
#include "impairment.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define DMA_CHUNK_SIZE 256U

static int g_rx_sock = -1;
static int g_tx_sock = -1;

static volatile uint8_t g_dma_rx_pending = 0U;
static volatile uint8_t g_dma_tx_pending = 0U;

static size_t g_dma_rx_len = 0U;
static size_t g_dma_tx_len = 0U;
static size_t g_dma_tx_offset = 0U;

static impairment_config_t g_impairment_config = {0};

pqc_status_t dma_transport_init(int rx_sock, int tx_sock)
{
    if (rx_sock < 0 || tx_sock < 0) {
        return ERR_INVALID_ARGUMENT;
    }

    g_rx_sock = rx_sock;
    g_tx_sock = tx_sock;

    g_dma_rx_pending = 0U;
    g_dma_tx_pending = 0U;
    g_dma_rx_len = 0U;
    g_dma_tx_len = 0U;
    g_dma_tx_offset = 0U;

    /*
     * DMA buffers must already have been initialized by the
     * application startup sequence using dma_isr_init().
     * Do not reset DMA state here.
     */
    if (dma_get_rx_buffer() == NULL ||
        dma_get_tx_buffer() == NULL) {
        g_rx_sock = -1;
        g_tx_sock = -1;
        return ERR_INVALID_STATE;
    }

    impairment_init(&g_impairment_config);

    return PQC_SUCCESS;
}

pqc_status_t dma_transport_set_impairment(
    const impairment_config_t *config)
{
    if (config == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    if (config->loss_rate_ppm > 1000000U ||
        config->max_latency_ms < config->min_latency_ms) {
        return ERR_INVALID_ARGUMENT;
    }

    g_impairment_config = *config;
    impairment_init(&g_impairment_config);

    return PQC_SUCCESS;
}

pqc_status_t dma_transport_rx_poll(void)
{
    if (g_rx_sock < 0 || g_dma_rx_pending != 0U) {
        return ERR_INVALID_STATE;
    }

    uint8_t *buf = dma_get_rx_buffer();
    if (buf == NULL) {
        return ERR_INVALID_STATE;
    }

    size_t received = 0U;

    pqc_status_t ret = impairment_recv(
        g_rx_sock,
        buf,
        DMA_CHUNK_SIZE,
        &received
    );

    if (ret != PQC_SUCCESS) {
        return ret;
    }

    if (received > DMA_CHUNK_SIZE) {
        return ERR_INVALID_STATE;
    }

    if (received == 0U) {
        return PQC_SUCCESS;
    }

    g_dma_rx_len = received;
    g_dma_rx_pending = 1U;

    return PQC_SUCCESS;
}

pqc_status_t dma_transport_tx_poll(void)
{
    if (g_tx_sock < 0 || g_dma_tx_pending == 0U) {
        return ERR_INVALID_STATE;
    }

    if (g_dma_tx_len == 0U ||
        g_dma_tx_len > DMA_CHUNK_SIZE ||
        g_dma_tx_offset >= g_dma_tx_len) {
        return ERR_INVALID_STATE;
    }

    uint8_t *buf = dma_get_tx_buffer();
    if (buf == NULL) {
        return ERR_INVALID_STATE;
    }

    size_t remaining = g_dma_tx_len - g_dma_tx_offset;
    size_t sent = 0U;

    pqc_status_t ret = impairment_send(
        g_tx_sock,
        buf + g_dma_tx_offset,
        remaining,
        &sent
    );

    if (ret != PQC_SUCCESS) {
        return ret;
    }

    if (sent > remaining) {
        return ERR_INVALID_STATE;
    }

    if (sent == 0U) {
        return PQC_SUCCESS;
    }

    g_dma_tx_offset += sent;

    if (g_dma_tx_offset == g_dma_tx_len) {
        g_dma_tx_pending = 0U;
        g_dma_tx_len = 0U;
        g_dma_tx_offset = 0U;
    }

    return PQC_SUCCESS;
}

pqc_status_t dma_transport_queue_tx(
    const uint8_t *data,
    size_t len)
{
    if (data == NULL || len == 0U || len > DMA_CHUNK_SIZE) {
        return ERR_INVALID_ARGUMENT;
    }

    if (g_dma_tx_pending != 0U) {
        return ERR_INVALID_STATE;
    }

    uint8_t *buf = dma_get_tx_buffer();
    if (buf == NULL) {
        return ERR_INVALID_STATE;
    }

    memcpy(buf, data, len);

    g_dma_tx_len = len;
    g_dma_tx_offset = 0U;
    g_dma_tx_pending = 1U;

    return PQC_SUCCESS;
}

pqc_status_t dma_transport_get_rx_data(
    uint8_t *out,
    size_t *len)
{
    if (out == NULL || len == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    if (g_dma_rx_pending == 0U) {
        return ERR_INVALID_STATE;
    }

    if (g_dma_rx_len == 0U || g_dma_rx_len > DMA_CHUNK_SIZE) {
        return ERR_INVALID_STATE;
    }

    uint8_t *buf = dma_get_rx_buffer();
    if (buf == NULL) {
        return ERR_INVALID_STATE;
    }

    memcpy(out, buf, g_dma_rx_len);
    *len = g_dma_rx_len;

    g_dma_rx_pending = 0U;
    g_dma_rx_len = 0U;

    return PQC_SUCCESS;
}

void dma_transport_rx_complete_callback(void)
{
    g_dma_rx_pending = 0U;
    g_dma_rx_len = 0U;
}

void dma_transport_tx_complete_callback(void)
{
    g_dma_tx_pending = 0U;
    g_dma_tx_len = 0U;
    g_dma_tx_offset = 0U;
}