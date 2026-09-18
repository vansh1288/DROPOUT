#include "mask_prg.h"
#include <tinycrypt/aes.h>
#include <tinycrypt/ctr_mode.h>
#include <string.h>

static struct tc_aes_key_sched_struct g_aes_sched;
static uint8_t g_nonce[16];
static uint8_t g_ctr[16];
static int g_initialized = 0;

static void increment_ctr(void) {
    for (int i = 15; i >= 0; i--) {
        g_ctr[i]++;
        if (g_ctr[i] != 0) break;
    }
}

void mask_prg_init(const uint8_t seed[32]) {
    tc_aes256_set_encrypt_key(&g_aes_sched, seed);
    if (!g_initialized) {
        memset(g_nonce, 0, 16);
        memset(g_ctr, 0, 16);
        g_initialized = 1;
    } else {
        for (int i = 15; i >= 0; i--) {
            g_nonce[i]++;
            if (g_nonce[i] != 0) break;
        }
        memset(g_ctr, 0, 16);
    }
}

void mask_prg_reseed(const uint8_t seed[32]) {
    tc_aes256_set_encrypt_key(&g_aes_sched, seed);
    for (int i = 15; i >= 0; i--) {
        g_nonce[i]++;
        if (g_nonce[i] != 0) break;
    }
    memset(g_ctr, 0, 16);
}

void mask_prg_expand(uint8_t* out, size_t len) {
    size_t generated = 0;
    while (generated < len) {
        size_t chunk = len - generated;
        if (chunk > 16) chunk = 16;
        tc_ctr_mode(out + generated, chunk, g_nonce, g_ctr, &g_aes_sched);
        generated += chunk;
        increment_ctr();
    }
}

void mask_prg_get_bytes(uint8_t* out, size_t len) {
    mask_prg_expand(out, len);
}
