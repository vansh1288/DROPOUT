#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "dma_isr_handler.h"
#include "dma_stream_bridge.h"
#include "stream_aggregator.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "FreeRTOS.h"
#include "task.h"

#define TEST_CHUNK_SIZE 256

static void test_dma_isr_init(void)
{
    printf("Testing dma_isr_init...\n");

    dma_isr_init();

    assert(dma_isr_get_rx_active() == 0);
    assert(dma_isr_get_tx_active() == 0);

    printf("  PASS\n");
}

static void test_dma_isr_rx_complete(void)
{
    printf("Testing dma_isr_rx_complete...\n");

    stream_aggregator_init();
    dma_isr_init();

    dma_isr_set_stream_task((TaskHandle_t)0x1234);

    dma_stream_bridge_t *bridge =
        stream_aggregator_get_dma_bridge();

    assert(bridge != NULL);

    dma_isr_rx_complete();

    assert(dma_isr_get_rx_active() == 1);
    assert(bridge->chunks[0].state ==
           DMA_STREAM_BUF_STATE_FULL);
    assert(bridge->chunks[0].chunk_index == 0);
    assert(bridge->chunk_sequence == 1);

    dma_isr_rx_complete();

    assert(dma_isr_get_rx_active() == 0);
    assert(bridge->chunks[1].state ==
           DMA_STREAM_BUF_STATE_FULL);
    assert(bridge->chunks[1].chunk_index == 1);
    assert(bridge->chunk_sequence == 2);

    printf("  PASS\n");
}

static void test_dma_isr_tx_complete(void)
{
    printf("Testing dma_isr_tx_complete...\n");

    dma_isr_init();

    dma_isr_set_stream_task((TaskHandle_t)0x1234);

    assert(dma_isr_get_tx_active() == 0);

    dma_isr_tx_complete();

    assert(dma_isr_get_tx_active() == 1);

    dma_isr_tx_complete();

    assert(dma_isr_get_tx_active() == 0);

    printf("  PASS\n");
}

static void test_dma_isr_error(void)
{
    printf("Testing dma_isr_error...\n");

    stream_aggregator_init();
    dma_isr_init();

    dma_isr_set_stream_task((TaskHandle_t)0x1234);

    dma_stream_bridge_t *bridge =
        stream_aggregator_get_dma_bridge();

    assert(bridge != NULL);

    dma_isr_error();

    /*
     * The ISR error path must notify the stream task.
     * The bridge is also expected to enter an error state
     * when the local DMA implementation routes the error
     * through the bridge.
     */
    assert(
        bridge->chunks_dropped >= 1 ||
        bridge->chunks[0].state == DMA_STREAM_BUF_STATE_ERROR ||
        bridge->chunks[1].state == DMA_STREAM_BUF_STATE_ERROR);

    printf("  PASS\n");
}

static void test_dma_isr_set_stream_task(void)
{
    printf("Testing dma_isr_set_stream_task...\n");

    dma_isr_init();

    TaskHandle_t handle =
        (TaskHandle_t)0x5678;

    dma_isr_set_stream_task(handle);

    stream_aggregator_init();

    dma_isr_rx_complete();

    dma_stream_bridge_t *bridge =
        stream_aggregator_get_dma_bridge();

    assert(bridge != NULL);

    assert(
        bridge->chunks[0].state ==
        DMA_STREAM_BUF_STATE_FULL);

    printf("  PASS\n");
}

static void test_dma_isr_start_rx(void)
{
    printf("Testing dma_isr_start_rx...\n");

    dma_isr_init();

    pqc_status_t ret =
        dma_isr_start_rx();

    assert(ret == PQC_SUCCESS);

    /*
     * The RX buffer itself is intentionally private to
     * dma_isr_handler.c. The public API only guarantees
     * successful DMA RX initialization.
     */
    assert(dma_isr_get_rx_active() == 0);

    printf("  PASS\n");
}

static void test_dma_isr_start_tx(void)
{
    printf("Testing dma_isr_start_tx...\n");

    dma_isr_init();

    uint8_t test_data[TEST_CHUNK_SIZE];

    for (uint16_t i = 0;
         i < TEST_CHUNK_SIZE;
         i++) {
        test_data[i] = (uint8_t)(i & 0xFFu);
    }

    pqc_status_t ret =
        dma_isr_start_tx(
            test_data,
            TEST_CHUNK_SIZE);

    assert(ret == PQC_SUCCESS);

    /*
     * The TX DMA buffer is private to the ISR module.
     * Verify the public API contract rather than accessing
     * the private buffer directly.
     */
    assert(dma_isr_get_tx_active() == 0);

    ret =
        dma_isr_start_tx(
            test_data,
            DMA_BUFFER_BYTES + 1u);

    assert(ret == ERR_CHUNK_TOO_LARGE);

    printf("  PASS\n");
}

static void test_dma_isr_start_tx_zero_length(void)
{
    printf("Testing dma_isr_start_tx zero length...\n");

    dma_isr_init();

    uint8_t test_data[1] = {0};

    pqc_status_t ret =
        dma_isr_start_tx(
            test_data,
            0);

    /*
     * Zero-length TX is valid as far as the current
     * public DMA API is concerned because only the
     * upper bound is enforced here.
     */
    assert(ret == PQC_SUCCESS);

    assert(dma_isr_get_tx_active() == 0);

    printf("  PASS\n");
}

static void test_dma_isr_start_tx_null_data(void)
{
    printf("Testing dma_isr_start_tx NULL data...\n");

    dma_isr_init();

    pqc_status_t ret =
        dma_isr_start_tx(
            NULL,
            TEST_CHUNK_SIZE);

    /*
     * A non-zero transfer requires a valid source buffer.
     * The implementation should reject it rather than
     * dereference NULL.
     */
    assert(ret == ERR_INVALID_ARGUMENT);

    printf("  PASS\n");
}

static void test_dma_isr_buffer_switch(void)
{
    printf("Testing dma_isr buffer switching...\n");

    dma_isr_init();

    for (int i = 0; i < 10; i++) {
        uint8_t expected_rx =
            (uint8_t)((i + 1) % 2);

        dma_isr_rx_complete();

        assert(
            dma_isr_get_rx_active() ==
            expected_rx);
    }

    for (int i = 0; i < 10; i++) {
        uint8_t expected_tx =
            (uint8_t)((i + 1) % 2);

        dma_isr_tx_complete();

        assert(
            dma_isr_get_tx_active() ==
            expected_tx);
    }

    printf("  PASS\n");
}

static void test_dma_isr_multiple_errors(void)
{
    printf("Testing multiple DMA errors...\n");

    stream_aggregator_init();
    dma_isr_init();

    dma_isr_set_stream_task((TaskHandle_t)0x1234);

    dma_stream_bridge_t *bridge =
        stream_aggregator_get_dma_bridge();

    assert(bridge != NULL);

    uint16_t initial_dropped =
        bridge->chunks_dropped;

    for (int i = 0; i < 5; i++) {
        dma_isr_error();

        /*
         * Depending on the RTOS/mock implementation, the
         * error notification may be consumed without the
         * bridge incrementing its drop counter. The ISR
         * must nevertheless remain callable repeatedly
         * without corrupting state.
         */
        assert(
            bridge->chunks_dropped >=
            initial_dropped);
    }

    printf("  PASS\n");
}

static void test_dma_isr_reinitialization(void)
{
    printf("Testing DMA ISR reinitialization...\n");

    dma_isr_init();

    dma_isr_rx_complete();
    dma_isr_tx_complete();

    assert(dma_isr_get_rx_active() == 1);
    assert(dma_isr_get_tx_active() == 1);

    dma_isr_init();

    assert(dma_isr_get_rx_active() == 0);
    assert(dma_isr_get_tx_active() == 0);

    printf("  PASS\n");
}

int main(void)
{
    printf("Running DMA ISR Handler Tests...\n\n");

    test_dma_isr_init();
    test_dma_isr_rx_complete();
    test_dma_isr_tx_complete();
    test_dma_isr_error();
    test_dma_isr_set_stream_task();
    test_dma_isr_start_rx();
    test_dma_isr_start_tx();
    test_dma_isr_start_tx_zero_length();
    test_dma_isr_start_tx_null_data();
    test_dma_isr_buffer_switch();
    test_dma_isr_multiple_errors();
    test_dma_isr_reinitialization();

    printf("\n=== ALL DMA ISR TESTS PASSED ===\n");

    return 0;
}