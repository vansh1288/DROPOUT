#ifndef IMPAIRMENT_H
#define IMPAIRMENT_H

#include "protocol_types.h"
#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t loss_rate_ppm;
    uint32_t min_latency_ms;
    uint32_t max_latency_ms;
    uint32_t jitter_ms;
    uint32_t seed;
} impairment_config_t;

void impairment_init(const impairment_config_t* config);
void impairment_set_loss_rate(uint32_t loss_rate_ppm);
void impairment_set_latency_ms(uint32_t min_latency_ms, uint32_t max_latency_ms);
void impairment_set_jitter_ms(uint32_t jitter_ms);
int impairment_should_drop(void);
uint32_t impairment_get_latency_ms(void);
void impairment_delay(uint32_t ms);
pqc_status_t impairment_recv(int sock, uint8_t* buf, size_t len, size_t* received);
pqc_status_t impairment_send(int sock, const uint8_t* buf, size_t len, size_t* sent);

#endif
