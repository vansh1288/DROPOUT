#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "dma_transport.h"
#include "dma_isr_handler.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "impairment.h"
#include "FreeRTOS.h"
#include "task.h"

#define TEST_CHUNK_SIZE 256

static void test_dma_transport_init(void) {
    printf("Testing dma_transport_init...\n");
    pqc_status_t ret = dma_transport_init(-1, -1);
    assert(ret == PQC_SUCCESS);
    printf("  PASS\n");
}

static void test_dma_transport_queue_tx(void) {
    printf("Testing dma_transport_queue_tx...\n");
    dma_transport_init(-1, -1);
    
    uint8_t test_data[256];
    for (int i = 0; i < 256; i++) test_data[i] = i & 0xFF;
    
    pqc_status_t ret = dma_transport_queue_tx(test_data, 256);
    assert(ret == PQC_SUCCESS);
    
    uint8_t* buf = dma_get_tx_buffer();
    assert(memcmp(buf, test_data, 256) == 0);
    
    ret = dma_transport_queue_tx(test_data, 256);
    assert(ret == ERR_INVALID_ARGUMENT);
    
    ret = dma_transport_queue_tx(test_data, DMA_CHUNK_BYTES + 1);
    assert(ret == ERR_INVALID_ARGUMENT);
    
    ret = dma_transport_queue_tx(NULL, 256);
    assert(ret == ERR_INVALID_ARGUMENT);
    printf("  PASS\n");
}

static void test_dma_transport_get_rx_data(void) {
    printf("Testing dma_transport_get_rx_data...\n");
    dma_transport_init(-1, -1);
    
    uint8_t test_data[256];
    for (int i = 0; i < 256; i++) test_data[i] = i & 0xFF;
    
    uint8_t* rx_buf = dma_get_rx_buffer();
    memcpy(rx_buf, test_data, 256);
    dma_isr_rx_complete();
    
    uint8_t out[256];
    size_t len = 0;
    pqc_status_t ret = dma_transport_get_rx_data(out, &len);
    assert(ret == PQC_SUCCESS);
    assert(len == DMA_CHUNK_BYTES);
    assert(memcmp(out, test_data, 256) == 0);
    
    ret = dma_transport_get_rx_data(out, &len);
    assert(ret == ERR_INVALID_STATE);
    printf("  PASS\n");
}

static void test_dma_transport_rx_poll(void) {
    printf("Testing dma_transport_rx_poll...\n");
    dma_transport_init(-1, -1);
    
    impairment_config_t config = {0};
    config.drop_rate = 0.0;
    config.corrupt_rate = 0.0;
    config.latency_ms = 0;
    dma_transport_set_impairment(&config);
    
    uint8_t test_data[256];
    for (int i = 0; i < 256; i++) test_data[i] = i & 0xFF;
    
    uint8_t* rx_buf = dma_get_rx_buffer();
    memcpy(rx_buf, test_data, 256);
    
    pqc_status_t ret = dma_transport_rx_poll();
    assert(ret == PQC_SUCCESS);
    assert(dma_isr_get_rx_active() == 1);
    
    uint8_t out[256];
    size_t len = 0;
    ret = dma_transport_get_rx_data(out, &len);
    assert(ret == PQC_SUCCESS);
    assert(memcmp(out, test_data, 256) == 0);
    printf("  PASS\n");
}

static void test_dma_transport_tx_poll(void) {
    printf("Testing dma_transport_tx_poll...\n");
    dma_transport_init(-1, -1);
    
    impairment_config_t config = {0};
    config.drop_rate = 0.0;
    config.corrupt_rate = 0.0;
    config.latency_ms = 0;
    dma_transport_set_impairment(&config);
    
    uint8_t test_data[256];
    for (int i = 0; i < 256; i++) test_data[i] = i & 0xFF;
    
    pqc_status_t ret = dma_transport_queue_tx(test_data, 256);
    assert(ret == PQC_SUCCESS);
    
    ret = dma_transport_tx_poll();
    assert(ret == PQC_SUCCESS);
    assert(dma_isr_get_tx_active() == 1);
    printf("  PASS\n");
}

static void test_dma_transport_impairment_drop(void) {
    printf("Testing dma_transport impairment drop...\n");
    dma_transport_init(-1, -1);
    
    impairment_config_t config = {0};
    config.drop_rate = 1.0;
    config.corrupt_rate = 0.0;
    config.latency_ms = 0;
    dma_transport_set_impairment(&config);
    
    uint8_t test_data[256];
    for (int i = 0; i < 256; i++) test_data[i] = i & 0xFF;
    
    pqc_status_t ret = dma_transport_queue_tx(test_data, 256);
    assert(ret == PQC_SUCCESS);
    
    ret = dma_transport_tx_poll();
    assert(ret == PQC_SUCCESS);
    
    impairment_init(&config);
    dma_transport_set_impairment(&config);
    
    uint8_t* rx_buf = dma_get_rx_buffer();
    memcpy(rx_buf, test_data, 256);
    dma_isr_rx_complete();
    
    ret = dma_transport_rx_poll();
    assert(ret == ERR_NETWORK_TIMEOUT);
    printf("  PASS\n");
}

static void test_dma_transport_impairment_corrupt(void) {
    printf("Testing dma_transport impairment corruption...\n");
    dma_transport_init(-1, -1);
    
    impairment_config_t config = {0};
    config.drop_rate = 0.0;
    config.corrupt_rate = 1.0;
    config.latency_ms = 0;
    dma_transport_set_impairment(&config);
    
    uint8_t test_data[256];
    for (int i = 0; i < 256; i++) test_data[i] = i & 0xFF;
    
    pqc_status_t ret = dma_transport_queue_tx(test_data, 256);
    assert(ret == PQC_SUCCESS);
    
    ret = dma_transport_tx_poll();
    assert(ret == PQC_SUCCESS);
    
    impairment_init(&config);
    dma_transport_set_impairment(&config);
    
    uint8_t* rx_buf = dma_get_rx_buffer();
    memcpy(rx_buf, test_data, 256);
    dma_isr_rx_complete();
    
    ret = dma_transport_rx_poll();
    assert(ret == PQC_SUCCESS);
    
    uint8_t out[256];
    size_t len = 0;
    ret = dma_transport_get_rx_data(out, &len);
    assert(ret == PQC_SUCCESS);
    
    int corrupted = 0;
    for (int i = 0; i < 256; i++) {
        if (out[i] != test_data[i]) corrupted = 1;
    }
    assert(corrupted);
    printf("  PASS\n");
}

static void test_dma_transport_chunking(void) {
    printf("Testing dma_transport chunking...\n");
    dma_transport_init(-1, -1);
    
    impairment_config_t config = {0};
    config.drop_rate = 0.0;
    config.corrupt_rate = 0.0;
    config.latency_ms = 0;
    dma_transport_set_impairment(&config);
    
    for (int chunk = 0; chunk < 10; chunk++) {
        uint8_t test_data[256];
        for (int i = 0; i < 256; i++) test_data[i] = (chunk + i) & 0xFF;
        
        pqc_status_t ret = dma_transport_queue_tx(test_data, 256);
        assert(ret == PQC_SUCCESS);
        
        ret = dma_transport_tx_poll();
        assert(ret == PQC_SUCCESS);
        
        impairment_init(&config);
        dma_transport_set_impairment(&config);
        
        uint8_t* rx_buf = dma_get_rx_buffer();
        memcpy(rx_buf, test_data, 256);
        dma_isr_rx_complete();
        
        ret = dma_transport_rx_poll();
        assert(ret == PQC_SUCCESS);
        
        uint8_t out[256];
        size_t len = 0;
        ret = dma_transport_get_rx_data(out, &len);
        assert(ret == PQC_SUCCESS);
        assert(memcmp(out, test_data, 256) == 0);
    }
    printf("  PASS\n");
}

static void test_dma_transport_callbacks(void) {
    printf("Testing dma_transport callbacks...\n");
    dma_transport_init(-1, -1);
    
    dma_transport_rx_complete_callback();
    dma_transport_tx_complete_callback();
    printf("  PASS\n");
}

static void test_dma_transport_multiple_chunks(void) {
    printf("Testing multiple sequential chunks...\n");
    dma_transport_init(-1, -1);
    
    impairment_config_t config = {0};
    config.drop_rate = 0.0;
    config.corrupt_rate = 0.0;
    config.latency_ms = 0;
    dma_transport_set_impairment(&config);
    
    for (int i = 0; i < 20; i++) {
        uint8_t test_data[256];
        for (int j = 0; j < 256; j++) test_data[j] = (i + j) & 0xFF;
        
        pqc_status_t ret = dma_transport_queue_tx(test_data, 256);
        assert(ret == PQC_SUCCESS);
        
        ret = dma_transport_tx_poll();
        assert(ret == PQC_SUCCESS);
        
        impairment_init(&config);
        dma_transport_set_impairment(&config);
        
        uint8_t* rx_buf = dma_get_rx_buffer();
        memcpy(rx_buf, test_data, 256);
        dma_isr_rx_complete();
        
        ret = dma_transport_rx_poll();
        assert(ret == PQC_SUCCESS);
        
        uint8_t out[256];
        size_t len = 0;
        ret = dma_transport_get_rx_data(out, &len);
        assert(ret == PQC_SUCCESS);
        assert(memcmp(out, test_data, 256) == 0);
    }
    printf("  PASS\n");
}

int main(void) {
    printf("Running DMA Transport Tests...\n\n");
    
    test_dma_transport_init();
    test_dma_transport_queue_tx();
    test_dma_transport_get_rx_data();
    test_dma_transport_rx_poll();
    test_dma_transport_tx_poll();
    test_dma_transport_impairment_drop();
    test_dma_transport_impairment_corrupt();
    test_dma_transport_chunking();
    test_dma_transport_callbacks();
    test_dma_transport_multiple_chunks();
    
    printf("\n=== ALL DMA TRANSPORT TESTS PASSED ===\n");
    return 0;
}