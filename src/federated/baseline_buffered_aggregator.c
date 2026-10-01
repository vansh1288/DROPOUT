#include "protocol_types.h"
#include "memory_scratchpad.h"
#include "kem_adapter.h"
#include <stdint.h>
#include <string.h>

#define MAX_MODEL_ELEMENTS 250000
#define CHUNK_ELEMENTS 128

static int16_t g_full_model_buffer[MAX_MODEL_ELEMENTS];
static int16_t g_mask_buffer[MAX_MODEL_ELEMENTS];
static int16_t g_aggregated_buffer[MAX_MODEL_ELEMENTS];
static uint32_t g_model_size = 0;
static uint8_t g_active = 0;

pqc_status_t baseline_buffered_init(uint32_t model_elements) {
    if (model_elements > MAX_MODEL_ELEMENTS) return ERR_BUFFER_TOO_SMALL;
    g_model_size = model_elements;
    g_active = 1;
    return PQC_SUCCESS;
}

pqc_status_t baseline_buffered_load_model(const int16_t* model) {
    if (!model || !g_active) return ERR_INVALID_ARGUMENT;
    memcpy(g_full_model_buffer, model, g_model_size * sizeof(int16_t));
    return PQC_SUCCESS;
}

pqc_status_t baseline_buffered_generate_mask(uint8_t client_id, uint32_t round_id) {
    if (!g_active) return ERR_INVALID_STATE;
    mlkem_workspace_t* ws = scratch_get_mlkem_ws();
    uint8_t seed[32];
    pqc_status_t ret = kem_adapter_derive_stream_mask_seed((uint8_t*)ws, client_id, round_id, 0, seed);
    if (ret != PQC_SUCCESS) return ret;
    mask_prg_init(seed);
    mask_prg_expand((uint8_t*)g_mask_buffer, g_model_size * sizeof(int16_t));
    crypto_zeroize(seed, 32);
    crypto_zeroize(ws, sizeof(mlkem_workspace_t));
    return PQC_SUCCESS;
}

pqc_status_t baseline_buffered_apply_mask(int16_t* output) {
    if (!output || !g_active) return ERR_INVALID_ARGUMENT;
    for (uint32_t i = 0; i < g_model_size; i++) {
        int32_t sum = (int32_t)g_full_model_buffer[i] + (int32_t)g_mask_buffer[i];
        output[i] = (int16_t)(sum % 3329);
    }
    return PQC_SUCCESS;
}

pqc_status_t baseline_buffered_aggregate(const int16_t* client_update, uint32_t weight) {
    if (!client_update || !g_active) return ERR_INVALID_ARGUMENT;
    for (uint32_t i = 0; i < g_model_size; i++) {
        int64_t val = (int64_t)g_aggregated_buffer[i] + (int64_t)client_update[i] * (int64_t)weight;
        g_aggregated_buffer[i] = (int16_t)(val % 3329);
    }
    return PQC_SUCCESS;
}

pqc_status_t baseline_buffered_finalize(uint32_t total_weight) {
    if (!g_active || total_weight == 0) return ERR_INVALID_ARGUMENT;
    for (uint32_t i = 0; i < g_model_size; i++) {
        g_aggregated_buffer[i] = (int16_t)((g_aggregated_buffer[i] / total_weight) % 3329);
    }
    return PQC_SUCCESS;
}

pqc_status_t baseline_buffered_get_result(int16_t* output) {
    if (!output || !g_active) return ERR_INVALID_ARGUMENT;
    memcpy(output, g_aggregated_buffer, g_model_size * sizeof(int16_t));
    return PQC_SUCCESS;
}

void baseline_buffered_zeroize(void) {
    crypto_zeroize(g_full_model_buffer, sizeof(g_full_model_buffer));
    crypto_zeroize(g_mask_buffer, sizeof(g_mask_buffer));
    crypto_zeroize(g_aggregated_buffer, sizeof(g_aggregated_buffer));
    g_active = 0;
}