#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "stream_aggregator.h"
#include "protocol_types.h"
#include "memory_scratchpad.h"
#include "kem_adapter.h"
#include "mask_prg.h"
#include "FreeRTOS.h"
#include "task.h"

#define TEST_CHUNK_SIZE 256
#define TEST_NUM_CHUNKS 10

static void test_stream_aggregator_init(void) {
    printf("Testing stream_aggregator_init...\n");
    stream_aggregator_init();
    
    uint8_t chunks_received, total_expected;
    stream_state_t state;
    stream_aggregator_get_stats(&chunks_received, &total_expected, &state);
    assert(chunks_received == 0);
    assert(total_expected == 0);
    assert(state == STREAM_STATE_IDLE);
    printf("  PASS\n");
}

static void test_stream_aggregator_start_session(void) {
    printf("Testing stream_aggregator_start_session...\n");
    stream_aggregator_init();
    
    uint8_t shared_secret[32] = {0};
    for (int i = 0; i < 32; i++) shared_secret[i] = i;
    
    pqc_status_t ret = stream_aggregator_start_session(1, 5, 256, 10);
    assert(ret == PQC_SUCCESS);
    
    uint8_t chunks_received, total_expected;
    stream_state_t state;
    stream_aggregator_get_stats(&chunks_received, &total_expected, &state);
    assert(chunks_received == 0);
    assert(total_expected == 10);
    assert(state == STREAM_STATE_RECEIVING);
    
    ret = stream_aggregator_start_session(1, 5, 33, 10);
    assert(ret == ERR_CHUNK_TOO_LARGE);
    
    ret = stream_aggregator_start_session(1, 5, 256, 0);
    assert(ret == ERR_INVALID_ARGUMENT);
    
    ret = stream_aggregator_start_session(1, 5, 256, STREAM_MAX_CHUNKS + 1);
    assert(ret == ERR_INVALID_ARGUMENT);
    printf("  PASS\n");
}

static void test_stream_aggregator_validate_chunk_size(void) {
    printf("Testing stream_aggregator_validate_chunk_size...\n");
    
    assert(stream_aggregator_validate_chunk_size(64) == PQC_SUCCESS);
    assert(stream_aggregator_validate_chunk_size(128) == PQC_SUCCESS);
    assert(stream_aggregator_validate_chunk_size(256) == PQC_SUCCESS);
    assert(stream_aggregator_validate_chunk_size(512) == PQC_SUCCESS);
    assert(stream_aggregator_validate_chunk_size(1024) == PQC_SUCCESS);
    
    assert(stream_aggregator_validate_chunk_size(32) == ERR_CHUNK_TOO_LARGE);
    assert(stream_aggregator_validate_chunk_size(129) == ERR_CHUNK_TOO_LARGE);
    assert(stream_aggregator_validate_chunk_size(2048) == ERR_CHUNK_TOO_LARGE);
    assert(stream_aggregator_validate_chunk_size(0) == ERR_CHUNK_TOO_LARGE);
    printf("  PASS\n");
}

static void test_stream_aggregator_validate_chunk_valid(void) {
    printf("Testing stream_aggregator_validate_chunk (valid)...\n");
    stream_aggregator_init();
    stream_aggregator_start_session(1, 5, 256, 10);
    
    chunk_validation_t validation = stream_aggregator_validate_chunk(0, 256, 1, 5);
    assert(validation == CHUNK_VALID);
    
    validation = stream_aggregator_validate_chunk(1, 256, 1, 5);
    assert(validation == CHUNK_VALID);
    
    validation = stream_aggregator_validate_chunk(9, 256, 1, 5);
    assert(validation == CHUNK_VALID);
    printf("  PASS\n");
}

static void test_stream_aggregator_validate_chunk_invalid_size(void) {
    printf("Testing stream_aggregator_validate_chunk (invalid size)...\n");
    stream_aggregator_init();
    stream_aggregator_start_session(1, 5, 256, 10);
    
    chunk_validation_t validation = stream_aggregator_validate_chunk(0, 128, 1, 5);
    assert(validation == CHUNK_INVALID_SIZE);
    
    validation = stream_aggregator_validate_chunk(0, 512, 1, 5);
    assert(validation == CHUNK_INVALID_SIZE);
    printf("  PASS\n");
}

static void test_stream_aggregator_validate_chunk_invalid_round(void) {
    printf("Testing stream_aggregator_validate_chunk (invalid round)...\n");
    stream_aggregator_init();
    stream_aggregator_start_session(1, 5, 256, 10);
    
    chunk_validation_t validation = stream_aggregator_validate_chunk(0, 256, 2, 5);
    assert(validation == CHUNK_INVALID_ROUND);
    
    validation = stream_aggregator_validate_chunk(0, 256, 0, 5);
    assert(validation == CHUNK_INVALID_ROUND);
    printf("  PASS\n");
}

static void test_stream_aggregator_validate_chunk_invalid_client(void) {
    printf("Testing stream_aggregator_validate_chunk (invalid client)...\n");
    stream_aggregator_init();
    stream_aggregator_start_session(1, 5, 256, 10);
    
    chunk_validation_t validation = stream_aggregator_validate_chunk(0, 256, 1, 3);
    assert(validation == CHUNK_INVALID_CLIENT);
    
    validation = stream_aggregator_validate_chunk(0, 256, 1, 99);
    assert(validation == CHUNK_INVALID_CLIENT);
    printf("  PASS\n");
}

static void test_stream_aggregator_validate_chunk_out_of_order(void) {
    printf("Testing stream_aggregator_validate_chunk (out of order)...\n");
    stream_aggregator_init();
    stream_aggregator_start_session(1, 5, 256, 10);
    
    chunk_validation_t validation = stream_aggregator_validate_chunk(10, 256, 1, 5);
    assert(validation == CHUNK_OUT_OF_ORDER);
    
    validation = stream_aggregator_validate_chunk(15, 256, 1, 5);
    assert(validation == CHUNK_OUT_OF_ORDER);
    printf("  PASS\n");
}

static void test_stream_aggregator_duplicate_rejection(void) {
    printf("Testing stream_aggregator duplicate rejection...\n");
    stream_aggregator_init();
    stream_aggregator_start_session(1, 5, 256, 10);
    
    chunk_validation_t validation = stream_aggregator_validate_chunk(5, 256, 1, 5);
    assert(validation == CHUNK_VALID);
    
    validation = stream_aggregator_validate_chunk(5, 256, 1, 5);
    assert(validation == CHUNK_DUPLICATE);
    
    pqc_status_t ret = stream_aggregator_check_duplicate(5);
    assert(ret == ERR_REPLAY_DETECTED);
    
    ret = stream_aggregator_check_duplicate(6);
    assert(ret == PQC_SUCCESS);
    
    validation = stream_aggregator_validate_chunk(6, 256, 1, 5);
    assert(validation == CHUNK_VALID);
    printf("  PASS\n");
}

static void test_stream_aggregator_receive_chunk(void) {
    printf("Testing stream_aggregator_receive_chunk...\n");
    stream_aggregator_init();
    stream_aggregator_start_session(1, 5, 256, 3);
    
    uint8_t shared_secret[32] = {0};
    for (int i = 0; i < 32; i++) shared_secret[i] = i;
    
    int16_t masked_chunk[128];
    for (int i = 0; i < 128; i++) masked_chunk[i] = i + 100;
    
    pqc_status_t ret = stream_aggregator_receive_chunk(0, (uint8_t*)masked_chunk, 256, 1, 5, shared_secret);
    assert(ret == PQC_SUCCESS);
    
    ret = stream_aggregator_receive_chunk(1, (uint8_t*)masked_chunk, 256, 1, 5, shared_secret);
    assert(ret == PQC_SUCCESS);
    
    ret = stream_aggregator_receive_chunk(2, (uint8_t*)masked_chunk, 256, 1, 5, shared_secret);
    assert(ret == PQC_SUCCESS);
    
    uint8_t chunks_received, total_expected;
    stream_state_t state;
    stream_aggregator_get_stats(&chunks_received, &total_expected, &state);
    assert(chunks_received == 3);
    assert(total_expected == 3);
    printf("  PASS\n");
}

static void test_stream_aggregator_receive_chunk_invalid_args(void) {
    printf("Testing stream_aggregator_receive_chunk (invalid args)...\n");
    stream_aggregator_init();
    stream_aggregator_start_session(1, 5, 256, 10);
    
    uint8_t shared_secret[32] = {0};
    int16_t masked_chunk[128] = {0};
    
    pqc_status_t ret = stream_aggregator_receive_chunk(0, NULL, 256, 1, 5, shared_secret);
    assert(ret == ERR_INVALID_ARGUMENT);
    
    ret = stream_aggregator_receive_chunk(0, (uint8_t*)masked_chunk, 256, 1, 5, NULL);
    assert(ret == ERR_INVALID_ARGUMENT);
    
    ret = stream_aggregator_receive_chunk(0, (uint8_t*)masked_chunk, 256, 2, 5, shared_secret);
    assert(ret == ERR_INVALID_ARGUMENT);
    
    ret = stream_aggregator_receive_chunk(0, (uint8_t*)masked_chunk, 128, 1, 5, shared_secret);
    assert(ret == ERR_INVALID_ARGUMENT);
    printf("  PASS\n");
}

static void test_stream_aggregator_finalize_session(void) {
    printf("Testing stream_aggregator_finalize_session...\n");
    stream_aggregator_init();
    stream_aggregator_start_session(1, 5, 256, 2);
    
    uint8_t shared_secret[32] = {0};
    for (int i = 0; i < 32; i++) shared_secret[i] = i;
    
    int16_t masked_chunk[128];
    for (int i = 0; i < 128; i++) masked_chunk[i] = i + 100;
    
    stream_aggregator_receive_chunk(0, (uint8_t*)masked_chunk, 256, 1, 5, shared_secret);
    stream_aggregator_receive_chunk(1, (uint8_t*)masked_chunk, 256, 1, 5, shared_secret);
    
    int16_t output[256];
    size_t output_size = 0;
    pqc_status_t ret = stream_aggregator_finalize_session(output, &output_size);
    assert(ret == PQC_SUCCESS);
    assert(output_size == 512);
    
    ret = stream_aggregator_finalize_session(output, &output_size);
    assert(ret == ERR_INVALID_STATE);
    printf("  PASS\n");
}

static void test_stream_aggregator_finalize_insufficient_chunks(void) {
    printf("Testing stream_aggregator_finalize_session (insufficient chunks)...\n");
    stream_aggregator_init();
    stream_aggregator_start_session(1, 5, 256, 3);
    
    uint8_t shared_secret[32] = {0};
    int16_t masked_chunk[128] = {0};
    
    stream_aggregator_receive_chunk(0, (uint8_t*)masked_chunk, 256, 1, 5, shared_secret);
    
    int16_t output[256];
    size_t output_size = 0;
    pqc_status_t ret = stream_aggregator_finalize_session(output, &output_size);
    assert(ret == ERR_INSUFFICIENT_SHARES);
    printf("  PASS\n");
}

static void test_stream_aggregator_reset(void) {
    printf("Testing stream_aggregator_reset...\n");
    stream_aggregator_init();
    stream_aggregator_start_session(1, 5, 256, 10);
    
    uint8_t shared_secret[32] = {0};
    int16_t masked_chunk[128] = {0};
    
    stream_aggregator_receive_chunk(0, (uint8_t*)masked_chunk, 256, 1, 5, shared_secret);
    
    pqc_status_t ret = stream_aggregator_reset();
    assert(ret == PQC_SUCCESS);
    
    uint8_t chunks_received, total_expected;
    stream_state_t state;
    stream_aggregator_get_stats(&chunks_received, &total_expected, &state);
    assert(chunks_received == 0);
    assert(total_expected == 0);
    assert(state == STREAM_STATE_IDLE);
    printf("  PASS\n");
}

static void test_stream_aggregator_zeroize(void) {
    printf("Testing stream_aggregator_zeroize_accumulator...\n");
    stream_aggregator_init();
    stream_aggregator_start_session(1, 5, 256, 10);
    
    uint8_t shared_secret[32] = {0};
    int16_t masked_chunk[128];
    for (int i = 0; i < 128; i++) masked_chunk[i] = i + 100;
    
    stream_aggregator_receive_chunk(0, (uint8_t*)masked_chunk, 256, 1, 5, shared_secret);
    
    stream_aggregator_zeroize_accumulator();
    
    int16_t output[256];
    size_t output_size = 0;
    pqc_status_t ret = stream_aggregator_finalize_session(output, &output_size);
    assert(ret == ERR_INSUFFICIENT_SHARES);
    printf("  PASS\n");
}

static void test_stream_aggregator_dma_bridge(void) {
    printf("Testing stream_aggregator_get_dma_bridge...\n");
    stream_aggregator_init();
    
    dma_stream_bridge_t* bridge = stream_aggregator_get_dma_bridge();
    assert(bridge != NULL);
    assert(bridge->chunks[0].state == DMA_STREAM_BUF_STATE_FREE);
    assert(bridge->chunks[1].state == DMA_STREAM_BUF_STATE_FREE);
    printf("  PASS\n");
}

static void test_stream_aggregator_boundary_chunks(void) {
    printf("Testing stream_aggregator boundary chunks...\n");
    stream_aggregator_init();
    stream_aggregator_start_session(1, 5, 256, 256);
    
    chunk_validation_t validation = stream_aggregator_validate_chunk(0, 256, 1, 5);
    assert(validation == CHUNK_VALID);
    
    validation = stream_aggregator_validate_chunk(255, 256, 1, 5);
    assert(validation == CHUNK_VALID);
    
    validation = stream_aggregator_validate_chunk(256, 256, 1, 5);
    assert(validation == CHUNK_OUT_OF_ORDER);
    printf("  PASS\n");
}

static void test_stream_aggregator_different_chunk_sizes(void) {
    printf("Testing stream_aggregator with different chunk sizes...\n");
    
    for (int chunk_size = 64; chunk_size <= 1024; chunk_size *= 2) {
        stream_aggregator_init();
        pqc_status_t ret = stream_aggregator_start_session(1, 5, chunk_size, 4);
        assert(ret == PQC_SUCCESS);
        
        uint8_t shared_secret[32] = {0};
        int16_t masked_chunk[512];
        for (int i = 0; i < chunk_size / 2; i++) masked_chunk[i] = i + 100;
        
        for (int i = 0; i < 4; i++) {
            ret = stream_aggregator_receive_chunk(i, (uint8_t*)masked_chunk, chunk_size, 1, 5, shared_secret);
            assert(ret == PQC_SUCCESS);
        }
        
        int16_t output[2048];
        size_t output_size = 0;
        ret = stream_aggregator_finalize_session(output, &output_size);
        assert(ret == PQC_SUCCESS);
        assert(output_size == chunk_size * 4);
    }
    printf("  PASS\n");
}

static void test_stream_aggregator_work_queue(void) {
    printf("Testing stream_aggregator work queue...\n");
    stream_aggregator_init();
    
    stream_work_item_t item = {
        .op = STREAM_OP_PROCESS,
        .client_id = 5,
        .round_id = 1,
        .chunk_index = 0,
        .chunk_size = 256,
        .shared_secret = NULL
    };
    
    BaseType_t ret = stream_aggregator_submit(&item, 100);
    assert(ret == pdTRUE);
    printf("  PASS\n");
}

int main(void) {
    printf("Running Stream Aggregator Tests...\n\n");
    
    test_stream_aggregator_init();
    test_stream_aggregator_start_session();
    test_stream_aggregator_validate_chunk_size();
    test_stream_aggregator_validate_chunk_valid();
    test_stream_aggregator_validate_chunk_invalid_size();
    test_stream_aggregator_validate_chunk_invalid_round();
    test_stream_aggregator_validate_chunk_invalid_client();
    test_stream_aggregator_validate_chunk_out_of_order();
    test_stream_aggregator_duplicate_rejection();
    test_stream_aggregator_receive_chunk();
    test_stream_aggregator_receive_chunk_invalid_args();
    test_stream_aggregator_finalize_session();
    test_stream_aggregator_finalize_insufficient_chunks();
    test_stream_aggregator_reset();
    test_stream_aggregator_zeroize();
    test_stream_aggregator_dma_bridge();
    test_stream_aggregator_boundary_chunks();
    test_stream_aggregator_different_chunk_sizes();
    test_stream_aggregator_work_queue();
    
    printf("\n=== ALL STREAM AGGREGATOR TESTS PASSED ===\n");
    return 0;
}