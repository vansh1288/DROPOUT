#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "dma_stream_bridge.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "crypto_memory.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"

#define TEST_CHUNK_SIZE 256
#define TEST_NUM_CHUNKS 10

static dma_stream_bridge_t g_test_bridge;
static TaskHandle_t g_test_task_handle;

static void test_dma_stream_bridge_init(void) {
    printf("Testing dma_stream_bridge_init...\n");
    pqc_status_t ret = dma_stream_bridge_init(&g_test_bridge, 1000);
    assert(ret == PQC_SUCCESS);
    assert(g_test_bridge.chunks[0].state == DMA_STREAM_BUF_STATE_FREE);
    assert(g_test_bridge.chunks[1].state == DMA_STREAM_BUF_STATE_FREE);
    assert(g_test_bridge.active_idx == 0);
    assert(g_test_bridge.processing_idx == 0);
    assert(g_test_bridge.chunk_sequence == 0);
    printf("  PASS\n");
}

static void test_dma_stream_bridge_rx_complete(void) {
    printf("Testing dma_stream_bridge_rx_complete_isr...\n");
    uint8_t* buffer = NULL;
    uint16_t max_len = 0;

    pqc_status_t ret = dma_stream_bridge_get_rx_buffer(&g_test_bridge, &buffer, &max_len);
    assert(ret == PQC_SUCCESS);
    assert(buffer != NULL);
    assert(max_len == DMA_BUFFER_BYTES);

    BaseType_t ret_isr = dma_stream_bridge_rx_complete_isr(&g_test_bridge, TEST_CHUNK_SIZE);
    assert(ret_isr == pdTRUE);
    assert(g_test_bridge.chunks[0].state == DMA_STREAM_BUF_STATE_FULL);
    assert(g_test_bridge.chunks[0].length == TEST_CHUNK_SIZE);
    assert(g_test_bridge.chunks[0].chunk_index == 0);
    assert(g_test_bridge.active_idx == 1);
    printf("  PASS\n");
}

static void test_dma_stream_bridge_get_chunk(void) {
    printf("Testing dma_stream_bridge_get_chunk...\n");
    uint8_t* data = NULL;
    uint16_t length = 0;
    uint16_t chunk_index = 0;

    pqc_status_t ret = dma_stream_bridge_get_chunk(&g_test_bridge, &data, &length, &chunk_index, 1000);
    assert(ret == PQC_SUCCESS);
    assert(data != NULL);
    assert(length == TEST_CHUNK_SIZE);
    assert(chunk_index == 0);
    assert(g_test_bridge.chunks[0].state == DMA_STREAM_BUF_STATE_PROCESSING);
    assert(g_test_bridge.processing_idx == 1);
    assert(g_test_bridge.chunks_processed == 1);
    printf("  PASS\n");
}

static void test_dma_stream_bridge_release_buffer(void) {
    printf("Testing dma_stream_bridge_release_buffer...\n");
    pqc_status_t ret = dma_stream_bridge_release_buffer(&g_test_bridge, 0);
    assert(ret == PQC_SUCCESS);
    assert(g_test_bridge.chunks[0].state == DMA_STREAM_BUF_STATE_FREE);
    assert(g_test_bridge.chunks[0].length == 0);
    assert(g_test_bridge.chunks[0].chunk_index == 0);
    printf("  PASS\n");
}

static void test_dma_stream_bridge_reseed(void) {
    printf("Testing dma_stream_bridge reseed...\n");
    uint8_t* buffer = NULL;
    uint16_t max_len = 0;

    pqc_status_t ret = dma_stream_bridge_get_rx_buffer(&g_test_bridge, &buffer, &max_len);
    assert(ret == PQC_SUCCESS);

    BaseType_t ret_isr = dma_stream_bridge_rx_complete_isr(&g_test_bridge, TEST_CHUNK_SIZE);
    assert(ret_isr == pdTRUE);

    uint8_t* data = NULL;
    uint16_t length = 0;
    uint16_t chunk_index = 0;
    pqc_status_t ret_get = dma_stream_bridge_get_chunk(&g_test_bridge, &data, &length, &chunk_index, 1000);
    assert(ret_get == PQC_SUCCESS);

    ret = dma_stream_bridge_release_buffer(&g_test_bridge, 0);
    assert(ret == PQC_SUCCESS);

    ret = dma_stream_bridge_get_rx_buffer(&g_test_bridge, &buffer, &max_len);
    assert(ret == PQC_SUCCESS);

    ret = dma_stream_bridge_rx_complete_isr(&g_test_bridge, TEST_CHUNK_SIZE);
    assert(ret == pdTRUE);

    ret_get = dma_stream_bridge_get_chunk(&g_test_bridge, &data, &length, &chunk_index, 1000);
    assert(ret_get == PQC_SUCCESS);
    assert(chunk_index == 1);
    assert(g_test_bridge.active_idx == 1);
    assert(g_test_bridge.processing_idx == 1);

    ret = dma_stream_bridge_release_buffer(&g_test_bridge, 1);
    assert(ret == PQC_SUCCESS);
    printf("  PASS\n");
}

static void test_dma_stream_bridge_error_isr(void) {
    printf("Testing dma_stream_bridge_error_isr...\n");
    dma_stream_bridge_reset(&g_test_bridge);

    BaseType_t ret = dma_stream_bridge_error_isr(&g_test_bridge);
    assert(ret == pdTRUE);
    assert(g_test_bridge.chunks[0].state == DMA_STREAM_BUF_STATE_ERROR);
    assert(g_test_bridge.chunks_dropped == 1);
    printf("  PASS\n");
}

static void test_dma_stream_bridge_buffer_ownership(void) {
    printf("Testing buffer ownership and lifecycle...\n");
    dma_stream_bridge_reset(&g_test_bridge);

    uint8_t* buffer = NULL;
    uint16_t max_len = 0;

    // Get buffer
    pqc_status_t ret = dma_stream_bridge_get_rx_buffer(&g_test_bridge, &buffer, &max_len);
    assert(ret == PQC_SUCCESS);
    assert(buffer != NULL);

    // Simulate DMA fill
    for (int i = 0; i < 256; i++) {
        buffer[i] = i & 0xFF;
    }

    // Submit buffer
    BaseType_t ret_isr = dma_stream_bridge_rx_complete_isr(&g_test_bridge, 256);
    assert(ret_isr == pdTRUE);

    // Get chunk
    uint8_t* data = NULL;
    uint16_t length = 0;
    uint16_t chunk_index = 0;
    pqc_status_t ret_get = dma_stream_bridge_get_chunk(&g_test_bridge, &data, &length, &chunk_index, 1000);
    assert(ret_get == PQC_SUCCESS);
    assert(length == 256);

    // Verify data integrity
    for (int i = 0; i < 256; i++) {
        assert(data[i] == (i & 0xFF));
    }

    // Release buffer
    pqc_status_t ret_rel = dma_stream_bridge_release_buffer(&g_test_bridge, 0);
    assert(ret_rel == PQC_SUCCESS);

    // Get buffer again (should wrap around)
    ret = dma_stream_bridge_get_rx_buffer(&g_test_bridge, &buffer, &max_len);
    assert(ret == PQC_SUCCESS);

    // Fill second buffer
    for (int i = 0; i < 256; i++) {
        buffer[i] = (i + 100) & 0xFF;
    }

    ret = dma_stream_bridge_rx_complete_isr(&g_test_bridge, 256);
    assert(ret == pdTRUE);

    ret_get = dma_stream_bridge_get_chunk(&g_test_bridge, &data, &length, &chunk_index, 1000);
    assert(ret_get == PQC_SUCCESS);
    assert(chunk_index == 1);

    ret = dma_stream_bridge_release_buffer(&g_test_bridge, 1);
    assert(ret == PQC_SUCCESS);
    printf("  PASS\n");
}

static void test_dma_stream_bridge_buffer_exhaustion(void) {
    printf("Testing buffer exhaustion handling...\n");
    dma_stream_bridge_reset(&g_test_bridge);

    // Fill both buffers without releasing
    for (int i = 0; i < 2; i++) {
        uint8_t* buffer = NULL;
        uint16_t max_len = 0;
        pqc_status_t ret = dma_stream_bridge_get_rx_buffer(&g_test_bridge, &buffer, &max_len);
        assert(ret == PQC_SUCCESS);

        for (int j = 0; j < 256; j++) {
            buffer[j] = i & 0xFF;
        }

        BaseType_t ret_isr = dma_stream_bridge_rx_complete_isr(&g_test_bridge, 256);
        assert(ret_isr == pdTRUE);
    }

    // Third attempt should fail (both buffers full)
    uint8_t* buffer = NULL;
    uint16_t max_len = 0;
    pqc_status_t ret = dma_stream_bridge_get_rx_buffer(&g_test_bridge, &buffer, &max_len);
    assert(ret == ERR_BUFFER_TOO_SMALL);

    // After releasing one, should work again
    pqc_status_t ret_rel = dma_stream_bridge_release_buffer(&g_test_bridge, 0);
    assert(ret_rel == PQC_SUCCESS);

    uint8_t* buffer2 = NULL;
    uint16_t max_len2 = 0;
    pqc_status_t ret2 = dma_stream_bridge_get_rx_buffer(&g_test_bridge, &buffer2, &max_len2);
    assert(ret2 == PQC_SUCCESS);

    printf("  PASS\n");
}

static void test_dma_stream_bridge_chunk_ordering(void) {
    printf("Testing chunk ordering...\n");
    dma_stream_bridge_reset(&g_test_bridge);

    for (int i = 0; i < 10; i++) {
        uint8_t* buffer = NULL;
        uint16_t max_len = 0;
        pqc_status_t ret = dma_stream_bridge_get_rx_buffer(&g_test_bridge, &buffer, &max_len);
        assert(ret == PQC_SUCCESS);

        for (int j = 0; j < 256; j++) {
            buffer[j] = (i + j) & 0xFF;
        }

        BaseType_t ret_isr = dma_stream_bridge_rx_complete_isr(&g_test_bridge, 256);
        assert(ret_isr == pdTRUE);

        uint8_t* data = NULL;
        uint16_t length = 0;
        uint16_t chunk_index = 0;
        pqc_status_t ret_get = dma_stream_bridge_get_chunk(&g_test_bridge, &data, &length, &chunk_index, 1000);
        assert(ret_get == PQC_SUCCESS);
        assert(chunk_index == i);
        assert(length == 256);

        // Verify data integrity
        for (int j = 0; j < 256; j++) {
            assert(data[j] == ((i + j) & 0xFF));
        }

        dma_stream_bridge_release_buffer(&g_test_bridge, i % 2);
    }

    printf("  PASS\n");
}

static void test_dma_stream_bridge_chunk_exhaustion(void) {
    printf("Testing chunk sequence exhaustion...\n");
    dma_stream_bridge_t bridge;
    dma_stream_bridge_init(&bridge, 1000);

    // Simulate 65535 chunks (16-bit sequence wraps)
    for (uint16_t i = 0; i < 65535; i++) {
        uint8_t* buffer = NULL;
        uint16_t max_len = 0;
        pqc_status_t ret = dma_stream_bridge_get_rx_buffer(&bridge, &buffer, &max_len);
        assert(ret == PQC_SUCCESS);

        BaseType_t ret_isr = dma_stream_bridge_rx_complete_isr(&bridge, 256);
        assert(ret_isr == pdTRUE);

        uint8_t* data = NULL;
        uint16_t length = 0;
        uint16_t chunk_index = 0;
        pqc_status_t ret_get = dma_stream_bridge_get_chunk(&bridge, &data, &length, &chunk_index, 10);
        assert(ret_get == PQC_SUCCESS);
        assert(chunk_index == i);

        dma_stream_bridge_release_buffer(&bridge, i % 2);
    }

    // Next chunk should wrap to 0
    uint8_t* buffer = NULL;
    uint16_t max_len = 0;
    pqc_status_t ret = dma_stream_bridge_get_rx_buffer(&bridge, &buffer, &max_len);
    assert(ret == PQC_SUCCESS);

    BaseType_t ret_isr = dma_stream_bridge_rx_complete_isr(&bridge, 256);
    assert(ret_isr == pdTRUE);

    uint8_t* data = NULL;
    uint16_t length = 0;
    uint16_t chunk_index = 0;
    pqc_status_t ret_get = dma_stream_bridge_get_chunk(&bridge, &data, &length, &chunk_index, 10);
    assert(ret_get == PQC_SUCCESS);
    assert(chunk_index == 0);

    printf("  PASS\n");
}

static void test_dma_stream_bridge_stats(void) {
    printf("Testing statistics tracking...\n");
    dma_stream_bridge_reset(&g_test_bridge);

    uint16_t processed, dropped;
    pqc_status_t ret = dma_stream_bridge_get_stats(&g_test_bridge, &processed, &dropped);
    assert(ret == PQC_SUCCESS);
    assert(processed == 0);
    assert(dropped == 0);

    // Process some chunks
    for (int i = 0; i < 5; i++) {
        uint8_t* buffer = NULL;
        uint16_t max_len = 0;
        dma_stream_bridge_get_rx_buffer(&g_test_bridge, &buffer, &max_len);
        dma_stream_bridge_rx_complete_isr(&g_test_bridge, 256);
        uint8_t* data = NULL;
        uint16_t length = 0;
        uint16_t chunk_index = 0;
        dma_stream_bridge_get_chunk(&g_test_bridge, &data, &length, &chunk_index, 1000);
        dma_stream_bridge_release_buffer(&g_test_bridge, i % 2);
    }

    ret = dma_stream_bridge_get_stats(&g_test_bridge, &processed, &dropped);
    assert(ret == PQC_SUCCESS);
    assert(processed == 5);
    assert(dropped == 0);

    // Force a drop
    dma_stream_bridge_get_rx_buffer(&g_test_bridge, &buffer, &max_len);
    dma_stream_bridge_rx_complete_isr(&g_test_bridge, 256);
    dma_stream_bridge_get_rx_buffer(&g_test_bridge, &buffer, &max_len);
    dma_stream_bridge_rx_complete_isr(&g_test_bridge, 256);
    // Now both buffers full, next get should fail
    uint8_t* buffer2 = NULL;
    uint16_t max_len2 = 0;
    pqc_status_t ret2 = dma_stream_bridge_get_rx_buffer(&g_test_bridge, &buffer2, &max_len2);
    assert(ret2 == ERR_BUFFER_TOO_SMALL);

    ret = dma_stream_bridge_get_stats(&g_test_bridge, &processed, &dropped);
    assert(ret == PQC_SUCCESS);
    assert(dropped == 1);

    printf("  PASS\n");
}

int main(void) {
    printf("Running DMA Stream Bridge Tests...\n\n");

    test_dma_stream_bridge_init();
    test_dma_stream_bridge_rx_complete();
    test_dma_stream_bridge_get_chunk();
    test_dma_stream_bridge_release_buffer();
    test_dma_stream_bridge_reseed();
    test_dma_stream_bridge_error_isr();
    test_dma_stream_bridge_buffer_ownership();
    test_dma_stream_bridge_buffer_exhaustion();
    test_dma_stream_bridge_chunk_ordering();
    test_dma_stream_bridge_chunk_exhaustion();
    test_dma_stream_bridge_stats();

    printf("\n=== ALL TESTS PASSED ===\n");
    return 0;
}