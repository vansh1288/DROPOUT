#include <assert.h>
#include <string.h>
#include <stdio.h>

#include "dma_stream_bridge.h"
#include "dma_isr_handler.h"
#include "dma_transport.h"
#include "stream_aggregator.h"
#include "dropout_protocol.h"
#include "packet_codec.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "crypto_memory.h"
#include "FreeRTOS.h"
#include "task.h"

#define TEST_CHUNK_SIZE 256

static dma_stream_bridge_t g_test_bridge;

static void test_dma_stream_bridge_null_pointers(void)
{
    printf("Testing dma_stream_bridge NULL pointers...\n");

    pqc_status_t ret =
        dma_stream_bridge_init(NULL, 1000);

    assert(ret == ERR_INVALID_ARGUMENT);

    uint8_t *buffer = NULL;
    uint16_t max_len = 0;

    ret =
        dma_stream_bridge_get_rx_buffer(
            NULL,
            &buffer,
            &max_len);

    assert(ret == ERR_INVALID_ARGUMENT);

    ret =
        dma_stream_bridge_get_rx_buffer(
            &g_test_bridge,
            NULL,
            &max_len);

    assert(ret == ERR_INVALID_ARGUMENT);

    ret =
        dma_stream_bridge_get_rx_buffer(
            &g_test_bridge,
            &buffer,
            NULL);

    assert(ret == ERR_INVALID_ARGUMENT);

    BaseType_t ret_isr =
        dma_stream_bridge_rx_complete_isr(
            NULL,
            TEST_CHUNK_SIZE);

    assert(ret_isr == pdFALSE);

    ret_isr =
        dma_stream_bridge_error_isr(NULL);

    assert(ret_isr == pdFALSE);

    ret =
        dma_stream_bridge_submit_buffer(
            NULL,
            TEST_CHUNK_SIZE);

    assert(ret == ERR_INVALID_ARGUMENT);

    uint8_t *data = NULL;
    uint16_t length = 0;
    uint16_t chunk_index = 0;

    ret =
        dma_stream_bridge_get_chunk(
            NULL,
            &data,
            &length,
            &chunk_index,
            1000);

    assert(ret == ERR_INVALID_ARGUMENT);

    ret =
        dma_stream_bridge_get_chunk(
            &g_test_bridge,
            NULL,
            &length,
            &chunk_index,
            1000);

    assert(ret == ERR_INVALID_ARGUMENT);

    ret =
        dma_stream_bridge_get_chunk(
            &g_test_bridge,
            &data,
            NULL,
            &chunk_index,
            1000);

    assert(ret == ERR_INVALID_ARGUMENT);

    ret =
        dma_stream_bridge_get_chunk(
            &g_test_bridge,
            &data,
            &length,
            NULL,
            1000);

    assert(ret == ERR_INVALID_ARGUMENT);

    ret =
        dma_stream_bridge_release_buffer(
            NULL,
            0);

    assert(ret == ERR_INVALID_ARGUMENT);

    ret =
        dma_stream_bridge_release_buffer(
            &g_test_bridge,
            2);

    assert(ret == ERR_INVALID_ARGUMENT);

    uint16_t processed = 0;
    uint16_t dropped = 0;

    ret =
        dma_stream_bridge_get_stats(
            NULL,
            &processed,
            &dropped);

    assert(ret == ERR_INVALID_ARGUMENT);

    ret =
        dma_stream_bridge_get_stats(
            &g_test_bridge,
            NULL,
            &dropped);

    assert(ret == ERR_INVALID_ARGUMENT);

    ret =
        dma_stream_bridge_get_stats(
            &g_test_bridge,
            &processed,
            NULL);

    assert(ret == ERR_INVALID_ARGUMENT);

    ret =
        dma_stream_bridge_reset(NULL);

    assert(ret == ERR_INVALID_ARGUMENT);

    printf("  PASS\n");
}

static void test_dma_stream_bridge_timeout(void)
{
    printf("Testing dma_stream_bridge timeout...\n");

    assert(
        dma_stream_bridge_init(
            &g_test_bridge,
            10) == PQC_SUCCESS);

    uint8_t *data = NULL;
    uint16_t length = 0;
    uint16_t chunk_index = 0;

    pqc_status_t ret =
        dma_stream_bridge_get_chunk(
            &g_test_bridge,
            &data,
            &length,
            &chunk_index,
            5);

    assert(ret == ERR_NETWORK_TIMEOUT);

    printf("  PASS\n");
}

static void test_dma_stream_bridge_buffer_exhaustion(void)
{
    printf("Testing dma_stream_bridge buffer exhaustion...\n");

    assert(
        dma_stream_bridge_init(
            &g_test_bridge,
            1000) == PQC_SUCCESS);

    for (int i = 0; i < 2; i++) {
        uint8_t *buffer = NULL;
        uint16_t max_len = 0;

        pqc_status_t ret =
            dma_stream_bridge_get_rx_buffer(
                &g_test_bridge,
                &buffer,
                &max_len);

        assert(ret == PQC_SUCCESS);
        assert(buffer != NULL);
        assert(max_len >= TEST_CHUNK_SIZE);

        memset(
            buffer,
            (uint8_t)i,
            TEST_CHUNK_SIZE);

        BaseType_t ret_isr =
            dma_stream_bridge_rx_complete_isr(
                &g_test_bridge,
                TEST_CHUNK_SIZE);

        assert(ret_isr == pdTRUE);
    }

    /*
     * Both ping-pong buffers are full, so another RX
     * buffer cannot be allocated.
     */
    uint8_t *buffer = NULL;
    uint16_t max_len = 0;

    pqc_status_t ret =
        dma_stream_bridge_get_rx_buffer(
            &g_test_bridge,
            &buffer,
            &max_len);

    assert(ret == ERR_BUFFER_TOO_SMALL);

    uint16_t processed = 0;
    uint16_t dropped = 0;

    ret =
        dma_stream_bridge_get_stats(
            &g_test_bridge,
            &processed,
            &dropped);

    assert(ret == PQC_SUCCESS);
    assert(dropped >= 1);

    printf("  PASS\n");
}

static void test_dma_stream_bridge_invalid_state_release(void)
{
    printf("Testing dma_stream_bridge invalid state release...\n");

    assert(
        dma_stream_bridge_init(
            &g_test_bridge,
            1000) == PQC_SUCCESS);

    pqc_status_t ret =
        dma_stream_bridge_release_buffer(
            &g_test_bridge,
            0);

    assert(ret == ERR_INVALID_STATE);

    uint8_t *buffer = NULL;
    uint16_t max_len = 0;

    ret =
        dma_stream_bridge_get_rx_buffer(
            &g_test_bridge,
            &buffer,
            &max_len);

    assert(ret == PQC_SUCCESS);

    ret =
        dma_stream_bridge_submit_buffer(
            &g_test_bridge,
            TEST_CHUNK_SIZE);

    assert(ret == PQC_SUCCESS);

    uint8_t *data = NULL;
    uint16_t length = 0;
    uint16_t chunk_index = 0;

    ret =
        dma_stream_bridge_get_chunk(
            &g_test_bridge,
            &data,
            &length,
            &chunk_index,
            1000);

    assert(ret == PQC_SUCCESS);

    /*
     * The returned chunk is not necessarily buffer 1.
     * Releasing the opposite buffer must therefore fail.
     */
    uint8_t wrong_index =
        (chunk_index == 0) ? 1 : 0;

    ret =
        dma_stream_bridge_release_buffer(
            &g_test_bridge,
            wrong_index);

    assert(ret == ERR_INVALID_STATE);

    /*
     * Release the actual processing buffer.
     */
    ret =
        dma_stream_bridge_release_buffer(
            &g_test_bridge,
            (uint8_t)chunk_index);

    assert(ret == PQC_SUCCESS);

    printf("  PASS\n");
}

static void test_dma_isr_null_task_handle(void)
{
    printf("Testing dma_isr with NULL task handle...\n");

    assert(
        dma_stream_bridge_init(
            &g_test_bridge,
            1000) == PQC_SUCCESS);

    dma_isr_set_stream_task(NULL);

    BaseType_t ret =
        dma_stream_bridge_rx_complete_isr(
            &g_test_bridge,
            TEST_CHUNK_SIZE);

    assert(ret == pdTRUE);

    assert(
        g_test_bridge.chunks[0].state ==
        DMA_STREAM_BUF_STATE_FULL);

    ret =
        dma_stream_bridge_error_isr(
            &g_test_bridge);

    assert(ret == pdTRUE);

    printf("  PASS\n");
}

static void test_dma_transport_invalid_state(void)
{
    printf("Testing dma_transport invalid state...\n");

    assert(
        dma_transport_init(-1, -1) ==
        PQC_SUCCESS);

    uint8_t out[TEST_CHUNK_SIZE];
    size_t len = 0;

    pqc_status_t ret =
        dma_transport_get_rx_data(
            out,
            &len);

    assert(ret == ERR_INVALID_STATE);

    uint8_t test_data[TEST_CHUNK_SIZE] = {0};

    ret =
        dma_transport_queue_tx(
            test_data,
            TEST_CHUNK_SIZE);

    assert(ret == PQC_SUCCESS);

    ret =
        dma_transport_tx_poll();

    assert(ret == ERR_INVALID_STATE);

    printf("  PASS\n");
}

static void test_dma_transport_null_pointers(void)
{
    printf("Testing dma_transport NULL pointers...\n");

    assert(
        dma_transport_init(-1, -1) ==
        PQC_SUCCESS);

    uint8_t test_data[TEST_CHUNK_SIZE] = {0};

    pqc_status_t ret =
        dma_transport_queue_tx(
            NULL,
            TEST_CHUNK_SIZE);

    assert(ret == ERR_INVALID_ARGUMENT);

    ret =
        dma_transport_queue_tx(
            test_data,
            TEST_CHUNK_SIZE);

    assert(ret == PQC_SUCCESS);

    ret =
        dma_transport_queue_tx(
            test_data,
            DMA_CHUNK_BYTES + 1u);

    assert(ret == ERR_INVALID_ARGUMENT);

    uint8_t out[TEST_CHUNK_SIZE];
    size_t len = 0;

    ret =
        dma_transport_get_rx_data(
            NULL,
            &len);

    assert(ret == ERR_INVALID_ARGUMENT);

    ret =
        dma_transport_get_rx_data(
            out,
            NULL);

    assert(ret == ERR_INVALID_ARGUMENT);

    printf("  PASS\n");
}

static void test_stream_aggregator_null_pointers(void)
{
    printf("Testing stream_aggregator NULL pointers...\n");

    stream_aggregator_init();

    assert(
        stream_aggregator_start_session(
            1,
            5,
            TEST_CHUNK_SIZE,
            10) == PQC_SUCCESS);

    pqc_status_t ret =
        stream_aggregator_receive_chunk(
            0,
            NULL,
            TEST_CHUNK_SIZE,
            1,
            5,
            NULL);

    assert(ret == ERR_INVALID_ARGUMENT);

    int16_t chunk[TEST_CHUNK_SIZE / 2] = {0};

    ret =
        stream_aggregator_receive_chunk(
            0,
            (uint8_t *)chunk,
            TEST_CHUNK_SIZE,
            1,
            5,
            NULL);

    assert(ret == ERR_INVALID_ARGUMENT);

    ret =
        stream_aggregator_receive_chunk(
            0,
            (uint8_t *)chunk,
            TEST_CHUNK_SIZE,
            1,
            5,
            (uint8_t *)chunk);

    assert(ret == PQC_SUCCESS);

    int16_t output[TEST_CHUNK_SIZE / 2];
    size_t output_size = 0;

    ret =
        stream_aggregator_finalize_session(
            NULL,
            &output_size);

    assert(ret == ERR_INVALID_ARGUMENT);

    ret =
        stream_aggregator_finalize_session(
            output,
            NULL);

    assert(ret == ERR_INVALID_ARGUMENT);

    ret =
        stream_aggregator_validate_chunk_size(
            TEST_CHUNK_SIZE);

    assert(ret == PQC_SUCCESS);

    assert(
        stream_aggregator_reset() ==
        PQC_SUCCESS);

    chunk_validation_t validation =
        stream_aggregator_validate_chunk(
            0,
            TEST_CHUNK_SIZE,
            1,
            5);

    assert(validation == CHUNK_INVALID_ROUND);

    printf("  PASS\n");
}

static void test_stream_aggregator_buffer_exhaustion(void)
{
    printf("Testing stream_aggregator buffer/session bounds...\n");

    stream_aggregator_init();

    /*
     * STREAM_MAX_CHUNKS + 1 must be rejected by the
     * session-start API.
     */
    pqc_status_t ret =
        stream_aggregator_start_session(
            1,
            5,
            TEST_CHUNK_SIZE,
            STREAM_MAX_CHUNKS + 1u);

    assert(ret == ERR_INVALID_ARGUMENT);

    /*
     * A valid maximum session must still be accepted.
     */
    ret =
        stream_aggregator_start_session(
            1,
            5,
            TEST_CHUNK_SIZE,
            STREAM_MAX_CHUNKS);

    assert(ret == PQC_SUCCESS);

    printf("  PASS\n");
}

static void test_stream_aggregator_timeout_session(void)
{
    printf("Testing stream_aggregator session timeout...\n");

    stream_aggregator_init();

    assert(
        stream_aggregator_start_session(
            1,
            5,
            TEST_CHUNK_SIZE,
            3) == PQC_SUCCESS);

    uint8_t shared_secret[32] = {0};
    int16_t masked_chunk[TEST_CHUNK_SIZE / 2] = {0};

    assert(
        stream_aggregator_receive_chunk(
            0,
            (uint8_t *)masked_chunk,
            TEST_CHUNK_SIZE,
            1,
            5,
            shared_secret) == PQC_SUCCESS);

    int16_t output[TEST_CHUNK_SIZE / 2];
    size_t output_size = 0;

    pqc_status_t ret =
        stream_aggregator_finalize_session(
            output,
            &output_size);

    assert(ret == ERR_INSUFFICIENT_SHARES);

    printf("  PASS\n");
}

static void test_packet_codec_null_pointers(void)
{
    printf("Testing packet_codec NULL pointers...\n");

    msg_header_t hdr;
    uint8_t out[32];

    assert(
        packet_codec_encode_header(
            NULL,
            out) == ERR_INVALID_ARGUMENT);

    assert(
        packet_codec_encode_header(
            &hdr,
            NULL) == ERR_INVALID_ARGUMENT);

    assert(
        packet_codec_decode_header(
            NULL,
            &hdr) == ERR_INVALID_ARGUMENT);

    assert(
        packet_codec_decode_header(
            NULL,
            NULL) == ERR_INVALID_ARGUMENT);

    assert(
        packet_codec_encode_message(
            NULL,
            NULL,
            NULL,
            NULL,
            NULL) == ERR_INVALID_ARGUMENT);

    assert(
        packet_codec_encode_message(
            &hdr,
            NULL,
            NULL,
            NULL,
            NULL) == ERR_INVALID_ARGUMENT);

    assert(
        packet_codec_decode_message(
            NULL,
            0,
            NULL,
            NULL,
            NULL,
            NULL) == ERR_INVALID_ARGUMENT);

    assert(
        packet_codec_validate_sequence(
            NULL,
            0) == ERR_INVALID_ARGUMENT);

    assert(
        packet_codec_validate_round(
            NULL,
            0) == ERR_INVALID_ARGUMENT);

    assert(
        packet_codec_validate_client(
            NULL,
            0) == ERR_INVALID_ARGUMENT);

    assert(
        packet_codec_tracker_check(
            NULL,
            0) == ERR_INVALID_ARGUMENT);

    printf("  PASS\n");
}

static void test_packet_codec_buffer_too_small(void)
{
    printf("Testing packet_codec buffer too small...\n");

    uint8_t mac_key[32];

    for (int i = 0; i < 32; i++) {
        mac_key[i] = (uint8_t)i;
    }

    msg_header_t hdr = {
        .protocol_version = 0x00010000,
        .round_id = 1,
        .client_id = 5,
        .message_type = MSG_TYPE_MASK_CHUNK,
        .sequence_number = 3,
        .payload_length = TEST_CHUNK_SIZE,
        .reserved = 0
    };

    uint8_t payload[TEST_CHUNK_SIZE];

    for (int i = 0; i < TEST_CHUNK_SIZE; i++) {
        payload[i] = (uint8_t)(i & 0xFF);
    }

    uint8_t encoded[
        HEADER_SIZE +
        MAC_SIZE +
        TEST_CHUNK_SIZE
    ];

    size_t encoded_len = 0;

    assert(
        packet_codec_encode_message(
            &hdr,
            payload,
            mac_key,
            encoded,
            &encoded_len) == PQC_SUCCESS);

    msg_header_t decoded_hdr;
    uint8_t decoded_payload[TEST_CHUNK_SIZE];
    size_t decoded_len = 0;

    pqc_status_t ret =
        packet_codec_decode_message(
            encoded,
            10,
            mac_key,
            &decoded_hdr,
            decoded_payload,
            &decoded_len);

    assert(ret == ERR_INVALID_ARGUMENT);

    printf("  PASS\n");
}

static void test_packet_codec_invalid_mac(void)
{
    printf("Testing packet_codec invalid MAC...\n");

    uint8_t mac_key[32];

    for (int i = 0; i < 32; i++) {
        mac_key[i] = (uint8_t)i;
    }

    msg_header_t hdr = {
        .protocol_version = 0x00010000,
        .round_id = 1,
        .client_id = 5,
        .message_type = MSG_TYPE_MASK_CHUNK,
        .sequence_number = 3,
        .payload_length = TEST_CHUNK_SIZE,
        .reserved = 0
    };

    uint8_t payload[TEST_CHUNK_SIZE];

    for (int i = 0; i < TEST_CHUNK_SIZE; i++) {
        payload[i] = (uint8_t)(i & 0xFF);
    }

    uint8_t encoded[
        HEADER_SIZE +
        MAC_SIZE +
        TEST_CHUNK_SIZE
    ];

    size_t encoded_len = 0;

    assert(
        packet_codec_encode_message(
            &hdr,
            payload,
            mac_key,
            encoded,
            &encoded_len) == PQC_SUCCESS);

    /*
     * MAC begins at MAC_OFFSET.
     */
    encoded[MAC_OFFSET] ^= 0xFF;

    msg_header_t decoded_hdr;
    uint8_t decoded_payload[TEST_CHUNK_SIZE];
    size_t decoded_len = 0;

    pqc_status_t ret =
        packet_codec_decode_message(
            encoded,
            encoded_len,
            mac_key,
            &decoded_hdr,
            decoded_payload,
            &decoded_len);

    assert(ret == ERR_AUTH_FAILED);

    printf("  PASS\n");
}

static void test_packet_codec_wrong_round_client_sequence(void)
{
    printf("Testing packet_codec wrong round/client/sequence...\n");

    uint8_t mac_key[32];

    for (int i = 0; i < 32; i++) {
        mac_key[i] = (uint8_t)i;
    }

    msg_header_t hdr = {
        .protocol_version = 0x00010000,
        .round_id = 2,
        .client_id = 5,
        .message_type = MSG_TYPE_MASK_CHUNK,
        .sequence_number = 3,
        .payload_length = TEST_CHUNK_SIZE,
        .reserved = 0
    };

    uint8_t payload[TEST_CHUNK_SIZE];

    memset(
        payload,
        0xA5,
        sizeof(payload));

    uint8_t encoded[
        HEADER_SIZE +
        MAC_SIZE +
        TEST_CHUNK_SIZE
    ];

    size_t encoded_len = 0;

    assert(
        packet_codec_encode_message(
            &hdr,
            payload,
            mac_key,
            encoded,
            &encoded_len) == PQC_SUCCESS);

    aad_context_t expected = {
        .round_id = 1,
        .client_id = 5,
        .chunk_index = 3,
        .chunk_size = TEST_CHUNK_SIZE
    };

    pqc_status_t ret =
        packet_codec_validate_message(
            &hdr,
            &expected,
            mac_key,
            encoded + MAC_OFFSET);

    assert(ret == ERR_ROUND_MISMATCH);

    hdr.round_id = 1;
    hdr.client_id = 99;

    assert(
        packet_codec_encode_message(
            &hdr,
            payload,
            mac_key,
            encoded,
            &encoded_len) == PQC_SUCCESS);

    expected.client_id = 5;
    expected.round_id = 1;

    ret =
        packet_codec_validate_message(
            &hdr,
            &expected,
            mac_key,
            encoded + MAC_OFFSET);

    assert(ret == ERR_CLIENT_ID_MISMATCH);

    hdr.client_id = 5;
    hdr.sequence_number = 5;

    assert(
        packet_codec_encode_message(
            &hdr,
            payload,
            mac_key,
            encoded,
            &encoded_len) == PQC_SUCCESS);

    expected.client_id = 5;
    expected.round_id = 1;
    expected.chunk_index = 3;

    ret =
        packet_codec_validate_message(
            &hdr,
            &expected,
            mac_key,
            encoded + MAC_OFFSET);

    assert(ret == ERR_SEQUENCE_MISMATCH);

    printf("  PASS\n");
}

static void test_dropout_protocol_invalid_args(void)
{
    printf("Testing dropout_protocol invalid args...\n");

    assert(
        dropout_protocol_init_recovery(
            1,
            5,
            0) == ERR_INVALID_THRESHOLD);

    assert(
        dropout_protocol_init_recovery(
            1,
            5,
            16) == ERR_INVALID_THRESHOLD);

    assert(
        dropout_protocol_init_recovery(
            1,
            5,
            3) == PQC_SUCCESS);

    uint8_t share[64] = {0};

    assert(
        dropout_protocol_submit_share(
            1,
            share,
            32) == ERR_INVALID_ARGUMENT);

    assert(
        dropout_protocol_submit_share(
            1,
            share,
            128) == ERR_INVALID_ARGUMENT);

    assert(
        dropout_protocol_submit_share(
            0,
            share,
            64) == ERR_INVALID_ARGUMENT);

    assert(
        dropout_protocol_submit_share(
            1,
            share,
            64) == PQC_SUCCESS);

    assert(
        dropout_protocol_submit_share(
            1,
            share,
            64) == ERR_DUPLICATE_SHARE_ID);

    int16_t mask[TEST_CHUNK_SIZE / 2] = {0};

    assert(
        dropout_protocol_derive_mask_for_recovery(
            2,
            0,
            10,
            mask,
            TEST_CHUNK_SIZE) ==
        ERR_ROUND_MISMATCH);

    dropout_protocol_cleanup();

    assert(
        dropout_protocol_is_recovery_complete() == 0);

    assert(
        dropout_protocol_get_recovered_secret() == NULL);

    printf("  PASS\n");
}

static void test_dropout_protocol_threshold_exhaustion(void)
{
    printf("Testing dropout_protocol threshold exhaustion...\n");

    assert(
        dropout_protocol_init_recovery(
            1,
            5,
            16) == PQC_SUCCESS);

    uint8_t share[64] = {0};

    for (int i = 0; i < 15; i++) {
        assert(
            dropout_protocol_submit_share(
                (uint8_t)(i + 1),
                share,
                64) == PQC_SUCCESS);
    }

    assert(
        dropout_protocol_is_recovery_complete() == 0);

    assert(
        dropout_protocol_submit_share(
            16,
            share,
            64) == PQC_SUCCESS);

    assert(
        dropout_protocol_is_recovery_complete() == 1);

    /*
     * Additional valid shares are still structurally
     * accepted by the current protocol implementation.
     */
    assert(
        dropout_protocol_submit_share(
            17,
            share,
            64) == PQC_SUCCESS);

    dropout_protocol_cleanup();

    printf("  PASS\n");
}

static void test_dma_transport_sock_errors(void)
{
    printf("Testing dma_transport socket errors...\n");

    assert(
        dma_transport_init(-1, -1) ==
        PQC_SUCCESS);

    pqc_status_t ret =
        dma_transport_rx_poll();

    assert(ret == ERR_INVALID_STATE);

    uint8_t test_data[TEST_CHUNK_SIZE] = {0};

    ret =
        dma_transport_queue_tx(
            test_data,
            TEST_CHUNK_SIZE);

    assert(ret == PQC_SUCCESS);

    ret =
        dma_transport_tx_poll();

    assert(ret == ERR_INVALID_STATE);

    printf("  PASS\n");
}

static void test_stream_aggregator_state_errors(void)
{
    printf("Testing stream_aggregator state errors...\n");

    stream_aggregator_init();

    int16_t output[TEST_CHUNK_SIZE / 2];
    size_t output_size = 0;

    /*
     * No session has been started.
     */
    pqc_status_t ret =
        stream_aggregator_finalize_session(
            output,
            &output_size);

    assert(ret == ERR_INSUFFICIENT_SHARES);

    assert(
        stream_aggregator_start_session(
            1,
            5,
            TEST_CHUNK_SIZE,
            2) == PQC_SUCCESS);

    assert(
        stream_aggregator_reset() ==
        PQC_SUCCESS);

    /*
     * After reset the aggregator returns to IDLE.
     */
    ret =
        stream_aggregator_finalize_session(
            output,
            &output_size);

    assert(ret == ERR_INVALID_STATE);

    printf("  PASS\n");
}

static void test_crypto_zeroize(void)
{
    printf("Testing crypto_zeroize...\n");

    uint8_t buffer[64];

    memset(
        buffer,
        0xAA,
        sizeof(buffer));

    crypto_zeroize(
        buffer,
        sizeof(buffer));

    for (size_t i = 0; i < sizeof(buffer); i++) {
        assert(buffer[i] == 0);
    }

    printf("  PASS\n");
}

static void test_scratchpad_zeroize(void)
{
    printf("Testing scratchpad zeroize...\n");

    scratch_zeroize_all();

    volatile uint8_t *p =
        (volatile uint8_t *)g_scratchpad.raw;

    for (size_t i = 0;
         i < GLOBAL_SCRATCHPAD_BYTES;
         i++) {

        assert(p[i] == 0);
    }

    printf("  PASS\n");
}

static void test_region_zeroize(void)
{
    printf("Testing scratchpad region zeroize...\n");

    scratch_zeroize_region(
        SCRATCH_REGION_MLKEM);

    scratch_zeroize_region(
        SCRATCH_REGION_CRYPTO);

    scratch_zeroize_region(
        SCRATCH_REGION_DMA_RX);

    scratch_zeroize_region(
        SCRATCH_REGION_DMA_TX);

    scratch_zeroize_region(
        SCRATCH_REGION_CHUNK);

    scratch_zeroize_region(
        SCRATCH_REGION_SHAMIR);

    scratch_zeroize_region(
        SCRATCH_REGION_PROTO);

    printf("  PASS\n");
}

static void test_invalid_chunk_sizes_all(void)
{
    printf("Testing all invalid chunk sizes...\n");

    assert(
        stream_aggregator_validate_chunk_size(0) ==
        ERR_CHUNK_TOO_LARGE);

    assert(
        stream_aggregator_validate_chunk_size(1) ==
        ERR_CHUNK_TOO_LARGE);

    assert(
        stream_aggregator_validate_chunk_size(32) ==
        ERR_CHUNK_TOO_LARGE);

    assert(
        stream_aggregator_validate_chunk_size(63) ==
        ERR_CHUNK_TOO_LARGE);

    assert(
        stream_aggregator_validate_chunk_size(64) ==
        PQC_SUCCESS);

    assert(
        stream_aggregator_validate_chunk_size(65) ==
        ERR_CHUNK_TOO_LARGE);

    assert(
        stream_aggregator_validate_chunk_size(127) ==
        ERR_CHUNK_TOO_LARGE);

    assert(
        stream_aggregator_validate_chunk_size(128) ==
        PQC_SUCCESS);

    assert(
        stream_aggregator_validate_chunk_size(129) ==
        ERR_CHUNK_TOO_LARGE);

    assert(
        stream_aggregator_validate_chunk_size(255) ==
        ERR_CHUNK_TOO_LARGE);

    assert(
        stream_aggregator_validate_chunk_size(256) ==
        PQC_SUCCESS);

    assert(
        stream_aggregator_validate_chunk_size(257) ==
        ERR_CHUNK_TOO_LARGE);

    assert(
        stream_aggregator_validate_chunk_size(511) ==
        ERR_CHUNK_TOO_LARGE);

    assert(
        stream_aggregator_validate_chunk_size(512) ==
        PQC_SUCCESS);

    assert(
        stream_aggregator_validate_chunk_size(513) ==
        ERR_CHUNK_TOO_LARGE);

    assert(
        stream_aggregator_validate_chunk_size(1023) ==
        ERR_CHUNK_TOO_LARGE);

    assert(
        stream_aggregator_validate_chunk_size(1024) ==
        PQC_SUCCESS);

    assert(
        stream_aggregator_validate_chunk_size(1025) ==
        ERR_CHUNK_TOO_LARGE);

    assert(
        stream_aggregator_validate_chunk_size(2048) ==
        ERR_CHUNK_TOO_LARGE);

    printf("  PASS\n");
}

int main(void)
{
    printf(
        "Running Error Paths, Timeouts, "
        "Buffer Exhaustion Tests...\n\n");

    test_dma_stream_bridge_null_pointers();
    test_dma_stream_bridge_timeout();
    test_dma_stream_bridge_buffer_exhaustion();
    test_dma_stream_bridge_invalid_state_release();

    test_dma_isr_null_task_handle();

    test_dma_transport_invalid_state();
    test_dma_transport_null_pointers();

    test_stream_aggregator_null_pointers();
    test_stream_aggregator_buffer_exhaustion();
    test_stream_aggregator_timeout_session();

    test_packet_codec_null_pointers();
    test_packet_codec_buffer_too_small();
    test_packet_codec_invalid_mac();
    test_packet_codec_wrong_round_client_sequence();

    test_dropout_protocol_invalid_args();
    test_dropout_protocol_threshold_exhaustion();

    test_dma_transport_sock_errors();

    test_stream_aggregator_state_errors();

    test_crypto_zeroize();
    test_scratchpad_zeroize();
    test_region_zeroize();

    test_invalid_chunk_sizes_all();

    printf(
        "\n=== ALL ERROR PATHS TESTS PASSED ===\n");

    return 0;
}