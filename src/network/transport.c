#include "transport.h"
#include "protocol_types.h"

#include <stdint.h>
#include <stddef.h>

#if !defined(STM32F446xx) && !defined(PLATFORM_STM32H7) && !defined(PLATFORM_ESP32)

#include "impairment.h"

#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#define MAX_SOCKETS 4u

static int g_sockets[MAX_SOCKETS] = {-1, -1, -1, -1};
static struct sockaddr_in g_addrs[MAX_SOCKETS];
static uint8_t g_socket_count = 0u;

static int transport_socket_set_nonblocking(int sock)
{
    int flags = fcntl(sock, F_GETFL, 0);

    if (flags < 0) {
        return -1;
    }

    return fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

pqc_status_t transport_init(int rx_sock, int tx_sock)
{
    (void)rx_sock;
    (void)tx_sock;

    for (uint8_t i = 0u; i < MAX_SOCKETS; ++i) {
        g_sockets[i] = -1;
    }

    g_socket_count = 0u;
    return PQC_SUCCESS;
}

pqc_status_t transport_set_impairment(const void *config)
{
    if (config == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    impairment_init((const impairment_config_t *)config);
    return PQC_SUCCESS;
}

pqc_status_t transport_rx_poll(void)
{
    return ERR_INVALID_STATE;
}

pqc_status_t transport_tx_poll(void)
{
    return ERR_INVALID_STATE;
}

pqc_status_t transport_queue_tx(const uint8_t *data, size_t len)
{
    (void)data;
    (void)len;
    return ERR_INVALID_STATE;
}

pqc_status_t transport_get_rx_data(uint8_t *out, size_t *len)
{
    (void)out;
    (void)len;
    return ERR_INVALID_STATE;
}

pqc_status_t transport_create_socket(const char *ip,
                                     uint16_t port,
                                     int *sock_fd)
{
    if (ip == NULL || sock_fd == NULL || g_socket_count >= MAX_SOCKETS) {
        return ERR_INVALID_ARGUMENT;
    }

    int sock = socket(AF_INET, SOCK_STREAM, 0);

    if (sock < 0) {
        return ERR_GENERIC;
    }

    if (transport_socket_set_nonblocking(sock) < 0) {
        close(sock);
        return ERR_GENERIC;
    }

    struct sockaddr_in addr = {0};

    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
        close(sock);
        return ERR_INVALID_ARGUMENT;
    }

    g_sockets[g_socket_count] = sock;
    g_addrs[g_socket_count] = addr;

    *sock_fd = sock;
    ++g_socket_count;

    return PQC_SUCCESS;
}

pqc_status_t transport_connect(int sock_fd)
{
    for (uint8_t i = 0u; i < MAX_SOCKETS; ++i) {
        if (g_sockets[i] == sock_fd) {
            int ret = connect(
                sock_fd,
                (struct sockaddr *)&g_addrs[i],
                sizeof(g_addrs[i])
            );

            if (ret < 0 && errno != EINPROGRESS) {
                return ERR_GENERIC;
            }

            return PQC_SUCCESS;
        }
    }

    return ERR_INVALID_ARGUMENT;
}

pqc_status_t transport_bind_listen(int sock_fd, int backlog)
{
    for (uint8_t i = 0u; i < MAX_SOCKETS; ++i) {
        if (g_sockets[i] == sock_fd) {
            if (bind(
                    sock_fd,
                    (struct sockaddr *)&g_addrs[i],
                    sizeof(g_addrs[i])) < 0) {
                return ERR_GENERIC;
            }

            if (listen(sock_fd, backlog) < 0) {
                return ERR_GENERIC;
            }

            return PQC_SUCCESS;
        }
    }

    return ERR_INVALID_ARGUMENT;
}

pqc_status_t transport_accept(int listen_sock, int *client_sock)
{
    if (client_sock == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    struct sockaddr_in client_addr;
    socklen_t addr_len = sizeof(client_addr);

    int client = accept(
        listen_sock,
        (struct sockaddr *)&client_addr,
        &addr_len
    );

    if (client < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return ERR_NETWORK_TIMEOUT;
        }

        return ERR_GENERIC;
    }

    if (transport_socket_set_nonblocking(client) < 0) {
        close(client);
        return ERR_GENERIC;
    }

    if (g_socket_count >= MAX_SOCKETS) {
        close(client);
        return ERR_BUFFER_TOO_SMALL;
    }

    g_sockets[g_socket_count] = client;
    ++g_socket_count;

    *client_sock = client;

    return PQC_SUCCESS;
}

pqc_status_t transport_send(int sock_fd,
                            const uint8_t *data,
                            size_t len,
                            size_t *sent)
{
    if (data == NULL || sent == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    ssize_t ret = send(sock_fd, data, len, MSG_NOSIGNAL);

    if (ret < 0) {
        *sent = 0u;

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return ERR_NETWORK_TIMEOUT;
        }

        return ERR_GENERIC;
    }

    *sent = (size_t)ret;
    return PQC_SUCCESS;
}

pqc_status_t transport_recv(int sock_fd,
                            uint8_t *buf,
                            size_t len,
                            size_t *received)
{
    if (buf == NULL || received == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    ssize_t ret = recv(sock_fd, buf, len, 0);

    if (ret < 0) {
        *received = 0u;

        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            return ERR_NETWORK_TIMEOUT;
        }

        return ERR_GENERIC;
    }

    if (ret == 0) {
        *received = 0u;
        return ERR_NETWORK_TIMEOUT;
    }

    *received = (size_t)ret;
    return PQC_SUCCESS;
}

pqc_status_t transport_close(int sock_fd)
{
    for (uint8_t i = 0u; i < MAX_SOCKETS; ++i) {
        if (g_sockets[i] == sock_fd) {
            close(sock_fd);
            g_sockets[i] = -1;
            return PQC_SUCCESS;
        }
    }

    return ERR_INVALID_ARGUMENT;
}

#else

/*
 * Embedded target:
 * POSIX socket transport is intentionally unavailable.
 * STM32/ESP32 use the DMA transport path instead.
 */

pqc_status_t transport_init(int rx_sock, int tx_sock)
{
    (void)rx_sock;
    (void)tx_sock;
    return PQC_SUCCESS;
}

pqc_status_t transport_set_impairment(const void *config)
{
    (void)config;
    return ERR_INVALID_STATE;
}

pqc_status_t transport_rx_poll(void)
{
    return ERR_INVALID_STATE;
}

pqc_status_t transport_tx_poll(void)
{
    return ERR_INVALID_STATE;
}

pqc_status_t transport_queue_tx(const uint8_t *data, size_t len)
{
    (void)data;
    (void)len;
    return ERR_INVALID_STATE;
}

pqc_status_t transport_get_rx_data(uint8_t *out, size_t *len)
{
    (void)out;
    (void)len;
    return ERR_INVALID_STATE;
}

#endif