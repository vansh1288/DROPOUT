#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "dma_isr_handler.h"
#include "transport.h"
#include "impairment.h"

#include <stdint.h>
#include <string.h>

/*
 * DMA transport state.
 */
static int g_rx_sock = -1;
static int g_tx_sock = -1;

static volatile uint8_t g_dma_rx_pending = 0u;
static volatile uint8_t g_dma_tx_pending = 0u;


/*
 * Return the currently active RX buffer.
 *
 * The DMA ISR maintains the active buffer index.
 */
static uint8_t* dma_transport_get_rx_buffer(void)
{
    dma_double_buffer_t* dma_rx = scratch_get_dma_rx();

    return dma_isr_get_rx_active()
        ? dma_rx->pong
        : dma_rx->ping;
}


/*
 * Return the currently active TX buffer.
 */
static uint8_t* dma_transport_get_tx_buffer(void)
{
    dma_double_buffer_t* dma_tx = scratch_get_dma_tx();

    return dma_isr_get_tx_active()
        ? dma_tx->pong
        : dma_tx->ping;
}


/*
 * Initialize the DMA transport.
 */
pqc_status_t dma_transport_init(
    int rx_sock,
    int tx_sock)
{
    g_rx_sock = rx_sock;
    g_tx_sock = tx_sock;

    g_dma_rx_pending = 0u;
    g_dma_tx_pending = 0u;

    /*
     * dma_isr_init() resets DMA software state and clears the
     * underlying scratchpad DMA buffers.
     */
    dma_isr_init();

    impairment_init(&g_impairment_config);

    return PQC_SUCCESS;
}


/*
 * Configure transport impairment simulation.
 */
pqc_status_t dma_transport_set_impairment(
    const impairment_config_t* config)
{
    if (config == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    impairment_init(config);

    return PQC_SUCCESS;
}


/*
 * Poll the RX transport.
 */
pqc_status_t dma_transport_rx_poll(void)
{
    if (g_rx_sock < 0) {
        return ERR_INVALID_STATE;
    }

    if (g_dma_rx_pending != 0u) {
        return ERR_DMA_BUSY;
    }

    uint8_t* buf = dma_transport_get_rx_buffer();

    if (buf == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    size_t received = 0u;

    pqc_status_t ret = impairment_recv(
        g_rx_sock,
        buf,
        DMA_CHUNK_BYTES,
        &received
    );

    if (ret != PQC_SUCCESS) {
        return ret;
    }

    if (received == 0u) {
        return PQC_SUCCESS;
    }

    if (received > DMA_CHUNK_BYTES) {
        return ERR_CHUNK_TOO_LARGE;
    }

    /*
     * Mark the RX transfer as pending before publishing completion
     * to the DMA/stream layer.
     */
    g_dma_rx_pending = 1u;

    /*
     * The current DMA ISR interface uses DMA_CHUNK_BYTES as the
     * completion length. Exact transport-length propagation will be
     * handled when the packet/DMA framing layer is integrated.
     */
    dma_isr_rx_complete();

    return PQC_SUCCESS;
}


/*
 * Poll the TX transport.
 */
pqc_status_t dma_transport_tx_poll(void)
{
    if (g_tx_sock < 0) {
        return ERR_INVALID_STATE;
    }

    if (g_dma_tx_pending == 0u) {
        return ERR_INVALID_STATE;
    }

    uint8_t* buf = dma_transport_get_tx_buffer();

    if (buf == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    size_t sent = 0u;

    pqc_status_t ret = impairment_send(
        g_tx_sock,
        buf,
        DMA_CHUNK_BYTES,
        &sent
    );

    if (ret != PQC_SUCCESS) {
        return ret;
    }

    /*
     * Only mark TX complete when the complete DMA chunk was sent.
     */
    if (sent != DMA_CHUNK_BYTES) {
        return ERR_PACKET_FRAGMENTED;
    }

    g_dma_tx_pending = 0u;

    dma_isr_tx_complete();

    return PQC_SUCCESS;
}


/*
 * Queue data for TX.
 */
pqc_status_t dma_transport_queue_tx(
    const uint8_t* data,
    size_t len)
{
    if (data == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    if (len == 0u) {
        return ERR_INVALID_ARGUMENT;
    }

    if (len > DMA_CHUNK_BYTES) {
        return ERR_CHUNK_TOO_LARGE;
    }

    if (g_dma_tx_pending != 0u) {
        return ERR_DMA_BUSY;
    }

    uint8_t* buf = dma_transport_get_tx_buffer();

    if (buf == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    /*
     * Clear the entire DMA buffer first so data from a previous
     * shorter transmission cannot remain in unused space.
     */
    crypto_zeroize(
        buf,
        DMA_CHUNK_BYTES
    );

    memcpy(
        buf,
        data,
        len
    );

    g_dma_tx_pending = 1u;

    return PQC_SUCCESS;
}


/*
 * Retrieve completed RX data.
 */
pqc_status_t dma_transport_get_rx_data(
    uint8_t* out,
    size_t* len)
{
    if (out == NULL || len == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    if (g_dma_rx_pending == 0u) {
        return ERR_INVALID_STATE;
    }

    /*
     * dma_isr_rx_complete() toggles the active index after the
     * completed buffer is published.
     *
     * Therefore the completed RX buffer is the opposite of the
     * current active index.
     */
    dma_double_buffer_t* dma_rx = scratch_get_dma_rx();

    const uint8_t completed_idx =
        dma_isr_get_rx_active() ^ 1u;

    uint8_t* buf =
        completed_idx
            ? dma_rx->pong
            : dma_rx->ping;

    if (buf == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    /*
     * The current transport API does not retain the exact received
     * length. Until that metadata is propagated through the DMA
     * bridge, expose the configured DMA chunk size.
     */
    *len = DMA_CHUNK_BYTES;

    memcpy(
        out,
        buf,
        DMA_CHUNK_BYTES
    );

    /*
     * The consumer has copied the completed buffer, so the transport
     * may accept another RX transfer.
     */
    g_dma_rx_pending = 0u;

    return PQC_SUCCESS;
}


/*
 * RX completion callback.
 */
void dma_transport_rx_complete_callback(void)
{
    g_dma_rx_pending = 0u;
}


/*
 * TX completion callback.
 */
void dma_transport_tx_complete_callback(void)
{
    g_dma_tx_pending = 0u;
}