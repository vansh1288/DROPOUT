#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sys/socket.h>
#include <unistd.h>

#include "dma_transport.h"
#include "dma_isr_handler.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "impairment.h"

#define TEST_CHUNK_SIZE DMA_CHUNK_BYTES

static int g_rx_pair[2];
static int g_tx_pair[2];

static void close_test_sockets(void)
{
    if (g_rx_pair[0] >= 0) {
        close(g_rx_pair[0]);
        g_rx_pair[0] = -1;
    }

    if (g_rx_pair[1] >= 0) {
        close(g_rx_pair[1]);
        g_rx_pair[1] = -1;
    }

    if (g_tx_pair[0] >= 0) {
        close(g_tx_pair[0]);
        g_tx_pair[0] = -1;
    }

    if (g_tx_pair[1] >= 0) {
        close(g_tx_pair[1]);
        g_tx_pair[1] = -1;
    }
}

static void setup_test_sockets(void)
{
    g_rx_pair[0] = -1;
    g_rx_pair[1] = -1;
    g_tx_pair[0] = -1;
    g_tx_pair[1] = -1;

    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, g_rx_pair) == 0);
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, g_tx_pair) == 0);
}

static void init_transport(void)
{
    setup_test_sockets();

    pqc_status_t ret = dma_transport_init(
        g_rx_pair[0],
        g_tx_pair[0]
    );

    assert(ret == PQC_SUCCESS);
}

static void test_dma_transport_init(void)
{
    printf("Testing dma_transport_init...\n");

    setup_test_sockets();

    pqc_status_t ret = dma_transport_init(
        g_rx_pair[0],
        g_tx_pair[0]
    );

    assert(ret == PQC_SUCCESS);

    close_test_sockets();

    printf("  PASS\n");
}

static void test_dma_transport_queue_tx(void)
{
    printf("Testing dma_transport_queue_tx...\n");

    init_transport();

    uint8_t test_data[TEST_CHUNK_SIZE];

    for (size_t i = 0; i < sizeof(test_data); i++) {
        test_data[i] = (uint8_t)(i & 0xFFu);
    }

    pqc_status_t ret =
        dma_transport_queue_tx(test_data, sizeof(test_data));

    assert(ret == PQC_SUCCESS);

    ret = dma_transport_queue_tx(test_data, sizeof(test_data));
    assert(ret == ERR_INVALID_ARGUMENT);

    uint8_t oversized[TEST_CHUNK_SIZE + 1];

    ret = dma_transport_queue_tx(
        oversized,
        sizeof(oversized)
    );

    assert(ret == ERR_INVALID_ARGUMENT);

    ret = dma_transport_queue_tx(NULL, sizeof(test_data));
    assert(ret == ERR_INVALID_ARGUMENT);

    close_test_sockets();

    printf("  PASS\n");
}

static void test_dma_transport_get_rx_data(void)
{
    printf("Testing dma_transport_get_rx_data...\n");

    init_transport();

    uint8_t test_data[TEST_CHUNK_SIZE];

    for (size_t i = 0; i < sizeof(test_data); i++) {
        test_data[i] = (uint8_t)(i & 0xFFu);
    }

    ssize_t written = send(
        g_rx_pair[1],
        test_data,
        sizeof(test_data),
        0
    );

    assert(written == (ssize_t)sizeof(test_data));

    pqc_status_t ret = dma_transport_rx_poll();
    assert(ret == PQC_SUCCESS);

    uint8_t out[TEST_CHUNK_SIZE];
    size_t len = 0;

    ret = dma_transport_get_rx_data(out, &len);

    assert(ret == PQC_SUCCESS);
    assert(len == TEST_CHUNK_SIZE);
    assert(memcmp(out, test_data, TEST_CHUNK_SIZE) == 0);

    ret = dma_transport_get_rx_data(out, &len);
    assert(ret == ERR_INVALID_STATE);

    close_test_sockets();

    printf("  PASS\n");
}

static void test_dma_transport_rx_poll(void)
{
    printf("Testing dma_transport_rx_poll...\n");

    init_transport();

    uint8_t test_data[TEST_CHUNK_SIZE];

    for (size_t i = 0; i < sizeof(test_data); i++) {
        test_data[i] = (uint8_t)((i * 3u) & 0xFFu);
    }

    ssize_t written = send(
        g_rx_pair[1],
        test_data,
        sizeof(test_data),
        0
    );

    assert(written == (ssize_t)sizeof(test_data));

    pqc_status_t ret = dma_transport_rx_poll();

    assert(ret == PQC_SUCCESS);
    assert(dma_isr_get_rx_active() == 1u);

    uint8_t out[TEST_CHUNK_SIZE];
    size_t len = 0;

    ret = dma_transport_get_rx_data(out, &len);

    assert(ret == PQC_SUCCESS);
    assert(len == TEST_CHUNK_SIZE);
    assert(memcmp(out, test_data, TEST_CHUNK_SIZE) == 0);

    close_test_sockets();

    printf("  PASS\n");
}

static void test_dma_transport_tx_poll(void)
{
    printf("Testing dma_transport_tx_poll...\n");

    init_transport();

    uint8_t test_data[TEST_CHUNK_SIZE];

    for (size_t i = 0; i < sizeof(test_data); i++) {
        test_data[i] = (uint8_t)((i + 17u) & 0xFFu);
    }

    pqc_status_t ret =
        dma_transport_queue_tx(test_data, sizeof(test_data));

    assert(ret == PQC_SUCCESS);

    ret = dma_transport_tx_poll();

    assert(ret == PQC_SUCCESS);
    assert(dma_isr_get_tx_active() == 1u);

    uint8_t received[TEST_CHUNK_SIZE];

    ssize_t read_count = recv(
        g_tx_pair[1],
        received,
        sizeof(received),
        0
    );

    assert(read_count == (ssize_t)sizeof(received));
    assert(memcmp(received, test_data, TEST_CHUNK_SIZE) == 0);

    close_test_sockets();

    printf("  PASS\n");
}

static void test_dma_transport_invalid_poll(void)
{
    printf("Testing invalid transport polling...\n");

    pqc_status_t ret = dma_transport_init(-1, -1);

    assert(ret == PQC_SUCCESS);

    ret = dma_transport_rx_poll();
    assert(ret == ERR_INVALID_STATE);

    ret = dma_transport_tx_poll();
    assert(ret == ERR_INVALID_STATE);

    uint8_t data[TEST_CHUNK_SIZE] = {0};

    ret = dma_transport_get_rx_data(data, NULL);
    assert(ret == ERR_INVALID_STATE);

    close_test_sockets();

    printf("  PASS\n");
}

static void test_dma_transport_impairment_drop(void)
{
    printf("Testing DMA transport impairment drop...\n");

    init_transport();

    impairment_config_t config = {0};

    config.loss_rate_ppm = 1000000u;
    config.min_latency_ms = 0;
    config.max_latency_ms = 0;
    config.jitter_ms = 0;
    config.seed = 1u;

    pqc_status_t ret =
        dma_transport_set_impairment(&config);

    assert(ret == PQC_SUCCESS);

    uint8_t test_data[TEST_CHUNK_SIZE] = {0};

    ssize_t written = send(
        g_rx_pair[1],
        test_data,
        sizeof(test_data),
        0
    );

    assert(written == (ssize_t)sizeof(test_data));

    ret = dma_transport_rx_poll();

    assert(ret == ERR_NETWORK_TIMEOUT);

    close_test_sockets();

    printf("  PASS\n");
}

static void test_dma_transport_impairment_no_drop(void)
{
    printf("Testing DMA transport without packet loss...\n");

    init_transport();

    impairment_config_t config = {0};

    config.loss_rate_ppm = 0;
    config.min_latency_ms = 0;
    config.max_latency_ms = 0;
    config.jitter_ms = 0;
    config.seed = 1u;

    pqc_status_t ret =
        dma_transport_set_impairment(&config);

    assert(ret == PQC_SUCCESS);

    uint8_t test_data[TEST_CHUNK_SIZE];

    for (size_t i = 0; i < sizeof(test_data); i++) {
        test_data[i] = (uint8_t)((i + 91u) & 0xFFu);
    }

    ssize_t written = send(
        g_rx_pair[1],
        test_data,
        sizeof(test_data),
        0
    );

    assert(written == (ssize_t)sizeof(test_data));

    ret = dma_transport_rx_poll();

    assert(ret == PQC_SUCCESS);

    uint8_t out[TEST_CHUNK_SIZE];
    size_t len = 0;

    ret = dma_transport_get_rx_data(out, &len);

    assert(ret == PQC_SUCCESS);
    assert(len == TEST_CHUNK_SIZE);
    assert(memcmp(out, test_data, TEST_CHUNK_SIZE) == 0);

    close_test_sockets();

    printf("  PASS\n");
}

static void test_dma_transport_chunking(void)
{
    printf("Testing DMA transport sequential chunks...\n");

    init_transport();

    impairment_config_t config = {0};
    config.loss_rate_ppm = 0;
    config.min_latency_ms = 0;
    config.max_latency_ms = 0;
    config.jitter_ms = 0;
    config.seed = 1u;

    pqc_status_t ret =
        dma_transport_set_impairment(&config);

    assert(ret == PQC_SUCCESS);

    for (int chunk = 0; chunk < 10; chunk++) {
        uint8_t test_data[TEST_CHUNK_SIZE];

        for (size_t i = 0; i < sizeof(test_data); i++) {
            test_data[i] =
                (uint8_t)((chunk + (int)i) & 0xFF);
        }

        ssize_t written = send(
            g_rx_pair[1],
            test_data,
            sizeof(test_data),
            0
        );

        assert(written == (ssize_t)sizeof(test_data));

        ret = dma_transport_rx_poll();

        assert(ret == PQC_SUCCESS);

        uint8_t out[TEST_CHUNK_SIZE];
        size_t len = 0;

        ret = dma_transport_get_rx_data(out, &len);

        assert(ret == PQC_SUCCESS);
        assert(len == TEST_CHUNK_SIZE);
        assert(memcmp(out, test_data, TEST_CHUNK_SIZE) == 0);
    }

    close_test_sockets();

    printf("  PASS\n");
}

static void test_dma_transport_callbacks(void)
{
    printf("Testing DMA transport callbacks...\n");

    init_transport();

    dma_transport_rx_complete_callback();
    dma_transport_tx_complete_callback();

    close_test_sockets();

    printf("  PASS\n");
}

static void test_dma_transport_multiple_chunks(void)
{
    printf("Testing multiple sequential chunks...\n");

    init_transport();

    impairment_config_t config = {0};
    config.loss_rate_ppm = 0;
    config.min_latency_ms = 0;
    config.max_latency_ms = 0;
    config.jitter_ms = 0;
    config.seed = 1234u;

    pqc_status_t ret =
        dma_transport_set_impairment(&config);

    assert(ret == PQC_SUCCESS);

    for (int i = 0; i < 20; i++) {
        uint8_t test_data[TEST_CHUNK_SIZE];

        for (size_t j = 0; j < sizeof(test_data); j++) {
            test_data[j] =
                (uint8_t)((i + (int)j) & 0xFF);
        }

        ssize_t written = send(
            g_rx_pair[1],
            test_data,
            sizeof(test_data),
            0
        );

        assert(written == (ssize_t)sizeof(test_data));

        ret = dma_transport_rx_poll();

        assert(ret == PQC_SUCCESS);

        uint8_t out[TEST_CHUNK_SIZE];
        size_t len = 0;

        ret = dma_transport_get_rx_data(out, &len);

        assert(ret == PQC_SUCCESS);
        assert(len == TEST_CHUNK_SIZE);
        assert(memcmp(out, test_data, TEST_CHUNK_SIZE) == 0);
    }

    close_test_sockets();

    printf("  PASS\n");
}

int main(void)
{
    printf("Running DMA Transport Tests...\n\n");

    test_dma_transport_init();
    test_dma_transport_queue_tx();
    test_dma_transport_get_rx_data();
    test_dma_transport_rx_poll();
    test_dma_transport_tx_poll();
    test_dma_transport_invalid_poll();
    test_dma_transport_impairment_drop();
    test_dma_transport_impairment_no_drop();
    test_dma_transport_chunking();
    test_dma_transport_callbacks();
    test_dma_transport_multiple_chunks();

    printf("\n=== ALL DMA TRANSPORT TESTS PASSED ===\n");

    return 0;
}