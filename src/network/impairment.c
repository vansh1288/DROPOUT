#include "impairment.h"
#include "transport.h"

#include <stdint.h>
#include <stddef.h>

static impairment_config_t g_impairment_config = {0};
static uint32_t g_rng_state = 0xDEADBEEFu;

static uint32_t rng_next(void)
{
    g_rng_state = (g_rng_state * 1664525u) + 1013904223u;
    return g_rng_state;
}

void impairment_init(const impairment_config_t *config)
{
    if (config == NULL) {
        return;
    }

    g_impairment_config = *config;

    if (g_impairment_config.loss_rate_ppm > 1000000u) {
        g_impairment_config.loss_rate_ppm = 1000000u;
    }

    if (g_impairment_config.max_latency_ms <
        g_impairment_config.min_latency_ms) {
        g_impairment_config.max_latency_ms =
            g_impairment_config.min_latency_ms;
    }

    if (config->seed != 0u) {
        g_rng_state = config->seed;
    }
}

void impairment_set_loss_rate(uint32_t loss_rate_ppm)
{
    if (loss_rate_ppm > 1000000u) {
        loss_rate_ppm = 1000000u;
    }

    g_impairment_config.loss_rate_ppm = loss_rate_ppm;
}

void impairment_set_latency_ms(uint32_t min_latency_ms,
                               uint32_t max_latency_ms)
{
    if (max_latency_ms < min_latency_ms) {
        max_latency_ms = min_latency_ms;
    }

    g_impairment_config.min_latency_ms = min_latency_ms;
    g_impairment_config.max_latency_ms = max_latency_ms;
}

void impairment_set_jitter_ms(uint32_t jitter_ms)
{
    g_impairment_config.jitter_ms = jitter_ms;
}

int impairment_should_drop(void)
{
    if (g_impairment_config.loss_rate_ppm == 0u) {
        return 0;
    }

    if (g_impairment_config.loss_rate_ppm >= 1000000u) {
        return 1;
    }

    return (rng_next() % 1000000u) <
           g_impairment_config.loss_rate_ppm;
}

uint32_t impairment_get_latency_ms(void)
{
    uint32_t min_latency = g_impairment_config.min_latency_ms;
    uint32_t max_latency = g_impairment_config.max_latency_ms;

    if (max_latency < min_latency) {
        max_latency = min_latency;
    }

    uint32_t latency = min_latency;

    if (max_latency > min_latency) {
        uint32_t range = max_latency - min_latency;
        latency += rng_next() % (range + 1u);
    }

    /*
     * Apply jitter without allowing signed/unsigned overflow.
     */
    if (g_impairment_config.jitter_ms > 0u) {
        uint32_t jitter = g_impairment_config.jitter_ms;

        if (jitter > 0x7FFFFFFEu) {
            jitter = 0x7FFFFFFEu;
        }

        uint32_t span = (jitter * 2u) + 1u;
        uint32_t random_offset = rng_next() % span;

        if (random_offset > jitter) {
            uint32_t positive = random_offset - jitter;

            if (latency <= UINT32_MAX - positive) {
                latency += positive;
            } else {
                latency = UINT32_MAX;
            }
        } else {
            uint32_t negative = jitter - random_offset;

            if (negative >= latency) {
                latency = 0u;
            } else {
                latency -= negative;
            }
        }
    }

    return latency;
}

void impairment_delay(uint32_t ms)
{
    /*
     * Delay is primarily intended for the native impairment model.
     * Avoid an overflowing loop counter.
     */
    volatile uint32_t iterations;

    if (ms == 0u) {
        return;
    }

    if (ms > (UINT32_MAX / 10000u)) {
        iterations = UINT32_MAX;
    } else {
        iterations = ms * 10000u;
    }

    for (volatile uint32_t i = 0u; i < iterations; ++i) {
#if defined(__GNUC__) || defined(__clang__)
        __asm__ volatile ("nop");
#endif
    }
}

pqc_status_t impairment_recv(int sock,
                             uint8_t *buf,
                             size_t len,
                             size_t *received)
{
    if (buf == NULL || received == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    *received = 0u;

    if (impairment_should_drop()) {
        return ERR_NETWORK_TIMEOUT;
    }

    uint32_t latency = impairment_get_latency_ms();

    if (latency > 0u) {
        impairment_delay(latency);
    }

    return transport_recv(sock, buf, len, received);
}

pqc_status_t impairment_send(int sock,
                             const uint8_t *buf,
                             size_t len,
                             size_t *sent)
{
    if (buf == NULL || sent == NULL) {
        return ERR_INVALID_ARGUMENT;
    }

    *sent = 0u;

    if (impairment_should_drop()) {
        return ERR_NETWORK_TIMEOUT;
    }

    uint32_t latency = impairment_get_latency_ms();

    if (latency > 0u) {
        impairment_delay(latency);
    }

    return transport_send(sock, buf, len, sent);
}