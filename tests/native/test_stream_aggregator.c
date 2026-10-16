
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "stream_aggregator.h"
#include "protocol_types.h"

#define TEST_CHUNK_SIZE 256u
#define TEST_NUM_CHUNKS 3u
#define TEST_SECRET_SIZE 32u

static uint8_t shared_secret[TEST_SECRET_SIZE];

static uint8_t masked_chunks[TEST_NUM_CHUNKS][TEST_CHUNK_SIZE];

static int16_t output_buffer[
    (TEST_NUM_CHUNKS * TEST_CHUNK_SIZE) / sizeof(int16_t)
];

static void prepare_test_data(void)
{
    for (size_t i = 0; i < sizeof(shared_secret); ++i) {
        shared_secret[i] = (uint8_t)(i + 1u);
    }

    for (size_t chunk = 0; chunk < TEST_NUM_CHUNKS; ++chunk) {
        for (size_t i = 0; i < TEST_CHUNK_SIZE; ++i) {
            masked_chunks[chunk][i] =
                (uint8_t)(chunk * 31u + i);
        }
    }

    memset(output_buffer, 0, sizeof(output_buffer));
}

static void reset_test_context(void)
{
    stream_aggregator_init();
    prepare_test_data();
}

static void test_initialization(void)
{
    printf("Testing initialization...\n");

    reset_test_context();

    uint8_t received = 0;
    uint8_t expected = 0;
    stream_state_t state = STREAM_STATE_ERROR;

    stream_aggregator_get_stats(
        &received,
        &expected,
        &state);

    assert(received == 0u);
    assert(expected == 0u);
    assert(state == STREAM_STATE_IDLE);

    printf("  PASS\n");
}

static void test_chunk_size_validation(void)
{
    printf("Testing chunk-size validation...\n");

    assert(stream_aggregator_validate_chunk_size(64u) == PQC_SUCCESS);
    assert(stream_aggregator_validate_chunk_size(128u) == PQC_SUCCESS);
    assert(stream_aggregator_validate_chunk_size(256u) == PQC_SUCCESS);
    assert(stream_aggregator_validate_chunk_size(512u) == PQC_SUCCESS);
    assert(stream_aggregator_validate_chunk_size(1024u) == PQC_SUCCESS);

    assert(stream_aggregator_validate_chunk_size(0u) == ERR_CHUNK_TOO_LARGE);
    assert(stream_aggregator_validate_chunk_size(33u) == ERR_CHUNK_TOO_LARGE);
    assert(stream_aggregator_validate_chunk_size(129u) == ERR_CHUNK_TOO_LARGE);
    assert(stream_aggregator_validate_chunk_size(2048u) == ERR_CHUNK_TOO_LARGE);

    printf("  PASS\n");
}

static void test_single_chunk_session(void)
{
    printf("Testing single-chunk session...\n");

    reset_test_context();

    assert(stream_aggregator_start_session(
        1u, 5u, TEST_CHUNK_SIZE, 1u) == PQC_SUCCESS);

    assert(stream_aggregator_receive_chunk(
        0u,
        masked_chunks[0],
        TEST_CHUNK_SIZE,
        1u,
        5u,
        shared_secret) == PQC_SUCCESS);

    int16_t output[TEST_CHUNK_SIZE / sizeof(int16_t)];
    size_t output_size = 0u;

    assert(stream_aggregator_finalize_session(
        output, &output_size) == PQC_SUCCESS);

    assert(output_size == TEST_CHUNK_SIZE);

    stream_state_t state;
    stream_aggregator_get_stats(NULL, NULL, &state);
    assert(state == STREAM_STATE_COMPLETE);

    assert(stream_aggregator_finalize_session(
        output, &output_size) == ERR_INVALID_STATE);

    printf("  PASS\n");
}

static void test_output_buffer_registration(void)
{
    printf("Testing output-buffer registration...\n");

    reset_test_context();

    assert(stream_aggregator_set_output_buffer(
        NULL, sizeof(output_buffer)) == ERR_INVALID_ARGUMENT);

    assert(stream_aggregator_set_output_buffer(
        output_buffer, 0u) == ERR_INVALID_ARGUMENT);

    assert(stream_aggregator_set_output_buffer(
        output_buffer, sizeof(output_buffer) - 1u)
        == ERR_INVALID_ARGUMENT);

    assert(stream_aggregator_set_output_buffer(
        output_buffer, sizeof(output_buffer)) == PQC_SUCCESS);

    /* A buffer cannot be changed after the session has started. */
    assert(stream_aggregator_start_session(
        2u, 5u, TEST_CHUNK_SIZE, TEST_NUM_CHUNKS) == PQC_SUCCESS);

    assert(stream_aggregator_set_output_buffer(
        output_buffer, sizeof(output_buffer)) == ERR_INVALID_STATE);

    printf("  PASS\n");
}

static void test_multichunk_requires_buffer(void)
{
    printf("Testing multi-chunk buffer requirement...\n");

    reset_test_context();

    assert(stream_aggregator_start_session(
        1u, 5u, TEST_CHUNK_SIZE, TEST_NUM_CHUNKS)
        == ERR_BUFFER_TOO_SMALL);

    printf("  PASS\n");
}

static void test_multichunk_capacity_validation(void)
{
    printf("Testing multi-chunk capacity validation...\n");

    reset_test_context();

    size_t insufficient_bytes =
        (TEST_NUM_CHUNKS * TEST_CHUNK_SIZE) - TEST_CHUNK_SIZE;

    assert(stream_aggregator_set_output_buffer(
        output_buffer, insufficient_bytes) == PQC_SUCCESS);

    assert(stream_aggregator_start_session(
        1u, 5u, TEST_CHUNK_SIZE, TEST_NUM_CHUNKS)
        == ERR_BUFFER_TOO_SMALL);

    reset_test_context();

    assert(stream_aggregator_set_output_buffer(
        output_buffer, sizeof(output_buffer)) == PQC_SUCCESS);

    assert(stream_aggregator_start_session(
        1u, 5u, TEST_CHUNK_SIZE, TEST_NUM_CHUNKS) == PQC_SUCCESS);

    printf("  PASS\n");
}

static void test_multichunk_receive_and_finalize(void)
{
    printf("Testing multi-chunk receive and finalization...\n");

    reset_test_context();

    assert(stream_aggregator_set_output_buffer(
        output_buffer, sizeof(output_buffer)) == PQC_SUCCESS);

    assert(stream_aggregator_start_session(
        7u, 5u, TEST_CHUNK_SIZE, TEST_NUM_CHUNKS) == PQC_SUCCESS);

    /*
     * Receive out of order to verify that each chunk is written
     * to its indexed output position rather than the same offset.
     */
    assert(stream_aggregator_receive_chunk(
        2u, masked_chunks[2], TEST_CHUNK_SIZE,
        7u, 5u, shared_secret) == PQC_SUCCESS);

    assert(stream_aggregator_receive_chunk(
        0u, masked_chunks[0], TEST_CHUNK_SIZE,
        7u, 5u, shared_secret) == PQC_SUCCESS);

    assert(stream_aggregator_receive_chunk(
        1u, masked_chunks[1], TEST_CHUNK_SIZE,
        7u, 5u, shared_secret) == PQC_SUCCESS);

    uint8_t received = 0;
    uint8_t expected = 0;
    stream_state_t state;

    stream_aggregator_get_stats(
        &received, &expected, &state);

    assert(received == TEST_NUM_CHUNKS);
    assert(expected == TEST_NUM_CHUNKS);
    assert(state == STREAM_STATE_AGGREGATING);

    int16_t final_output[
        (TEST_NUM_CHUNKS * TEST_CHUNK_SIZE) / sizeof(int16_t)
    ];

    size_t output_size = 0u;

    assert(stream_aggregator_finalize_session(
        final_output, &output_size) == PQC_SUCCESS);

    assert(output_size == TEST_NUM_CHUNKS * TEST_CHUNK_SIZE);

    /*
     * The caller's registered buffer and final output must contain
     * the same complete model data.
     */
    assert(memcmp(
        final_output,
        output_buffer,
        output_size) == 0);

    assert(stream_aggregator_finalize_session(
        final_output, &output_size) == ERR_INVALID_STATE);

    printf("  PASS\n");
}

static void test_duplicate_chunk_rejection(void)
{
    printf("Testing duplicate-chunk rejection...\n");

    reset_test_context();

    assert(stream_aggregator_start_session(
        1u, 5u, TEST_CHUNK_SIZE, 1u) == PQC_SUCCESS);

    assert(stream_aggregator_receive_chunk(
        0u, masked_chunks[0], TEST_CHUNK_SIZE,
        1u, 5u, shared_secret) == PQC_SUCCESS);

    assert(stream_aggregator_receive_chunk(
        0u, masked_chunks[0], TEST_CHUNK_SIZE,
        1u, 5u, shared_secret) == ERR_REPLAY_DETECTED);

    assert(stream_aggregator_check_duplicate(0u)
        == ERR_REPLAY_DETECTED);

    printf("  PASS\n");
}

static void test_receive_validation(void)
{
    printf("Testing receive validation...\n");

    reset_test_context();

    assert(stream_aggregator_start_session(
        1u, 5u, TEST_CHUNK_SIZE, 1u) == PQC_SUCCESS);

    assert(stream_aggregator_receive_chunk(
        0u, NULL, TEST_CHUNK_SIZE,
        1u, 5u, shared_secret) == ERR_INVALID_ARGUMENT);

    assert(stream_aggregator_receive_chunk(
        0u, masked_chunks[0], TEST_CHUNK_SIZE,
        1u, 5u, NULL) == ERR_INVALID_ARGUMENT);

    assert(stream_aggregator_receive_chunk(
        0u, masked_chunks[0], TEST_CHUNK_SIZE,
        2u, 5u, shared_secret) == ERR_ROUND_MISMATCH);

    assert(stream_aggregator_receive_chunk(
        0u, masked_chunks[0], TEST_CHUNK_SIZE,
        1u, 6u, shared_secret) == ERR_CLIENT_ID_MISMATCH);

    assert(stream_aggregator_receive_chunk(
        0u, masked_chunks[0], 128u,
        1u, 5u, shared_secret) == ERR_CHUNK_TOO_LARGE);

    assert(stream_aggregator_receive_chunk(
        1u, masked_chunks[0], TEST_CHUNK_SIZE,
        1u, 5u, shared_secret) == ERR_INVALID_ARGUMENT);

    printf("  PASS\n");
}

static void test_insufficient_chunks(void)
{
    printf("Testing finalization with missing chunks...\n");

    reset_test_context();

    assert(stream_aggregator_set_output_buffer(
        output_buffer, sizeof(output_buffer)) == PQC_SUCCESS);

    assert(stream_aggregator_start_session(
        1u, 5u, TEST_CHUNK_SIZE, TEST_NUM_CHUNKS) == PQC_SUCCESS);

    assert(stream_aggregator_receive_chunk(
        0u, masked_chunks[0], TEST_CHUNK_SIZE,
        1u, 5u, shared_secret) == PQC_SUCCESS);

    size_t output_size = 123u;

    assert(stream_aggregator_finalize_session(
        output_buffer, &output_size) == ERR_INSUFFICIENT_SHARES);

    assert(output_size == 0u);

    printf("  PASS\n");
}

static void test_reset_preserves_registered_buffer(void)
{
    printf("Testing reset and buffer registration...\n");

    reset_test_context();

    assert(stream_aggregator_set_output_buffer(
        output_buffer, sizeof(output_buffer)) == PQC_SUCCESS);

    assert(stream_aggregator_start_session(
        1u, 5u, TEST_CHUNK_SIZE, TEST_NUM_CHUNKS) == PQC_SUCCESS);

    assert(stream_aggregator_reset() == PQC_SUCCESS);

    /*
     * Reset should return the session to IDLE while retaining
     * the registered buffer for a subsequent session.
     */
    assert(stream_aggregator_start_session(
        2u, 5u, TEST_CHUNK_SIZE, TEST_NUM_CHUNKS) == PQC_SUCCESS);

    printf("  PASS\n");
}

static void test_invalid_session_parameters(void)
{
    printf("Testing invalid session parameters...\n");

    reset_test_context();

    assert(stream_aggregator_start_session(
        1u, 5u, 33u, 1u) == ERR_CHUNK_TOO_LARGE);

    assert(stream_aggregator_start_session(
        1u, 5u, TEST_CHUNK_SIZE, 0u) == ERR_INVALID_ARGUMENT);

    assert(stream_aggregator_start_session(
        1u, 5u, TEST_CHUNK_SIZE,
        STREAM_MAX_CHUNKS + 1u) == ERR_INVALID_ARGUMENT);

    printf("  PASS\n");
}
int main(void)
{
    printf("Running Stream Aggregator Tests...\n\n");

    test_initialization();
    test_chunk_size_validation();
    test_single_chunk_session();
    test_multichunk_requires_buffer();
    test_output_buffer_registration();
    test_multichunk_capacity_validation();
    test_multichunk_receive_and_finalize();
    test_duplicate_chunk_rejection();
    test_receive_validation();
    test_insufficient_chunks();
    test_reset_preserves_registered_buffer();
    test_invalid_session_parameters();

    printf("\n=== STREAM AGGREGATOR TESTS COMPLETED ===\n");

    return 0;
}
