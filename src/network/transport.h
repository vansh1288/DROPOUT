#ifndef TRANSPORT_H
#define TRANSPORT_H

#include "protocol_types.h"
#include <stdint.h>
#include <stddef.h>

pqc_status_t transport_init(void);
pqc_status_t transport_create_socket(const char* ip, uint16_t port, int* sock_fd);
pqc_status_t transport_connect(int sock_fd);
pqc_status_t transport_bind_listen(int sock_fd, int backlog);
pqc_status_t transport_accept(int listen_sock, int* client_sock);
pqc_status_t transport_send(int sock_fd, const uint8_t* data, size_t len, size_t* sent);
pqc_status_t transport_recv(int sock_fd, uint8_t* buf, size_t len, size_t* received);
pqc_status_t transport_close(int sock_fd);

#endif