#include "impairment.h"
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static impairment_config_t g_impairment_config = {0};
static uint32_t g_rng_state = 0xDEADBEEF;

static inline uint32_t rng_next(void) {
    g_rng_state = g_rng_state * 1664525 + 1013904223;
    return g_rng_state;
}

void impairment_init(const impairment_config_t* config) {
    if (!config) return;
    g_impairment_config = *config;
    if (config->seed) {
        g_rng_state = config->seed;
    }
}

void impairment_set_loss_rate(uint32_t loss_rate_ppm) {
    g_impairment_config.loss_rate_ppm = loss_rate_ppm;
}

void impairment_set_latency_ms(uint32_t min_latency_ms, uint32_t max_latency_ms) {
    g_impairment_config.min_latency_ms = min_latency_ms;
    g_impairment_config.max_latency_ms = max_latency_ms;
}

void impairment_set_jitter_ms(uint32_t jitter_ms) {
    g_impairment_config.jitter_ms = jitter_ms;
}

int impairment_should_drop(void) {
    if (g_impairment_config.loss_rate_ppm == 0) return 0;
    uint32_t r = rng_next() % 1000000;
    return r < g_impairment_config.loss_rate_ppm;
}

uint32_t impairment_get_latency_ms(void) {
    if (g_impairment_config.min_latency_ms == 0 && g_impairment_config.max_latency_ms == 0) return 0;
    uint32_t base = g_impairment_config.min_latency_ms;
    uint32_t range = g_impairment_config.max_latency_ms - g_impairment_config.min_latency_ms;
    uint32_t jitter = g_impairment_config.jitter_ms;
    uint32_t r = rng_next();
    uint32_t latency = base + (r % (range + 1));
    if (jitter > 0) {
        int32_t jitter_val = (int32_t)(rng_next() % (2 * jitter + 1)) - (int32_t)jitter;
        if ((int32_t)latency + jitter_val > 0) {
            latency = (uint32_t)((int32_t)latency + jitter_val);
        }
    }
    return latency;
}

void impairment_delay(uint32_t ms) {
    for (volatile uint32_t i = 0; i < ms * 10000; i++) {
        __asm__ volatile ("nop");
    }
}

pqc_status_t impairment_recv(int sock, uint8_t* buf, size_t len, size_t* received) {
    if (impairment_should_drop()) {
        *received = 0;
        return ERR_NETWORK_TIMEOUT;
    }
    uint32_t latency = impairment_get_latency_ms();
    if (latency > 0) impairment_delay(latency);
    return transport_recv(sock, buf, len, received);
}

pqc_status_t impairment_send(int sock, const uint8_t* buf, size_t len, size_t* sent) {
    if (impairment_should_drop()) {
        *sent = 0;
        return ERR_NETWORK_TIMEOUT;
    }
    uint32_t latency = impairment_get_latency_ms();
    if (latency > 0) impairment_delay(latency);
    return transport_send(sock, buf, len, sent);
}
