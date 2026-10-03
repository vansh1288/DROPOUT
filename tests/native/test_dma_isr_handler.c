#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "dma_isr_handler.h"
#include "dma_stream_bridge.h"
#include "stream_aggregator.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"

#define TEST_CHUNK_SIZE 256

static dma_stream_bridge_t g_test_bridge;

static void test_dma_isr_init(void) {
    printf("Testing dma_isr_init...\n");
    dma_isr_init();
    assert(dma_isr_get_rx_active() == 0);
    assert(dma_isr_get_tx_active() == 0);
    printf("  PASS\n");
}

static void test_dma_isr_rx_complete(void) {
    printf("Testing dma_isr_rx_complete...\n");
    dma_stream_bridge_init(&g_test_bridge, 1000);
    dma_isr_set_stream_task((TaskHandle_t)0x1234);
    
    dma_isr_rx_complete();
    assert(dma_isr_get_rx_active() == 1);
    assert(g_test_bridge.chunks[0].state == DMA_STREAM_BUF_STATE_FULL);
    assert(g_test_bridge.chunks[0].chunk_index == 0);
    assert(g_test_bridge.chunk_sequence == 1);
    
    dma_isr_rx_complete();
    assert(dma_isr_get_rx_active() == 0);
    assert(g_test_bridge.chunks[1].state == DMA_STREAM_BUF_STATE_FULL);
    assert(g_test_bridge.chunks[1].chunk_index == 1);
    assert(g_test_bridge.chunk_sequence == 2);
    printf("  PASS\n");
}

static void test_dma_isr_tx_complete(void) {
    printf("Testing dma_isr_tx_complete...\n");
    dma_isr_init();
    dma_isr_set_stream_task((TaskHandle_t)0x1234);
    
    dma_isr_tx_complete();
    assert(dma_isr_get_tx_active() == 1);
    
    dma_isr_tx_complete();
    assert(dma_isr_get_tx_active() == 0);
    printf("  PASS\n");
}

static void test_dma_isr_error(void) {
    printf("Testing dma_isr_error...\n");
    dma_stream_bridge_init(&g_test_bridge, 1000);
    dma_isr_set_stream_task((TaskHandle_t)0x1234);
    
    dma_isr_error();
    assert(g_test_bridge.chunks[0].state == DMA_STREAM_BUF_STATE_ERROR);
    assert(g_test_bridge.chunks_dropped == 1);
    printf("  PASS\n");
}

static void test_dma_isr_set_stream_task(void) {
    printf("Testing dma_isr_set_stream_task...\n");
    TaskHandle_t handle = (TaskHandle_t)0x5678;
    dma_isr_set_stream_task(handle);
    dma_stream_bridge_init(&g_test_bridge, 1000);
    
    dma_isr_rx_complete();
    assert(g_test_bridge.chunks[0].state == DMA_STREAM_BUF_STATE_FULL);
    printf("  PASS\n");
}

static void test_dma_isr_start_rx(void) {
    printf("Testing dma_isr_start_rx...\n");
    dma_isr_init();
    pqc_status_t ret = dma_isr_start_rx();
    assert(ret == PQC_SUCCESS);
    uint8_t* buf = dma_get_rx_buffer();
    assert(buf != NULL);
    printf("  PASS\n");
}

static void test_dma_isr_start_tx(void) {
    printf("Testing dma_isr_start_tx...\n");
    dma_isr_init();
    uint8_t test_data[256];
    for (int i = 0; i < 256; i++) test_data[i] = i & 0xFF;
    
    pqc_status_t ret = dma_isr_start_tx(test_data, 256);
    assert(ret == PQC_SUCCESS);
    
    uint8_t* buf = dma_get_tx_buffer();
    assert(memcmp(buf, test_data, 256) == 0);
    
    ret = dma_isr_start_tx(test_data, DMA_BUFFER_BYTES + 1);
    assert(ret == ERR_CHUNK_TOO_LARGE);
    printf("  PASS\n");
}

static void test_dma_isr_buffer_switch(void) {
    printf("Testing dma_isr buffer switching...\n");
    dma_isr_init();
    
    for (int i = 0; i < 10; i++) {
        uint8_t* buf = dma_get_rx_buffer();
        assert(buf != NULL);
        dma_isr_rx_complete();
        assert(dma_isr_get_rx_active() == (i + 1) % 2);
    }
    
    for (int i = 0; i < 10; i++) {
        uint8_t* buf = dma_get_tx_buffer();
        assert(buf != NULL);
        dma_isr_tx_complete();
        assert(dma_isr_get_tx_active() == (i + 1) % 2);
    }
    printf("  PASS\n");
}

static void test_dma_isr_multiple_errors(void) {
    printf("Testing multiple DMA errors...\n");
    dma_stream_bridge_init(&g_test_bridge, 1000);
    dma_isr_set_stream_task((TaskHandle_t)0x1234);
    
    for (int i = 0; i < 5; i++) {
        dma_isr_error();
        assert(g_test_bridge.chunks_dropped == i + 1);
    }
    printf("  PASS\n");
}

int main(void) {
    printf("Running DMA ISR Handler Tests...\n\n");
    
    test_dma_isr_init();
    test_dma_isr_rx_complete();
    test_dma_isr_tx_complete();
    test_dma_isr_error();
    test_dma_isr_set_stream_task();
    test_dma_isr_start_rx();
    test_dma_isr_start_tx();
    test_dma_isr_buffer_switch();
    test_dma_isr_multiple_errors();
    
    printf("\n=== ALL DMA ISR TESTS PASSED ===\n");
    return 0;
}