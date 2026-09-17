#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "mask_prg.h"
#include <stdint.h>

#define KYBER_Q 3329
#define CHUNK_ELEMENTS 128

static inline uint16_t barrett_reduce_q(uint32_t a) {
    uint32_t t = (a * 20159) >> 26;
    uint16_t r = (uint16_t)(a - t * KYBER_Q);
    return r >= KYBER_Q ? r - KYBER_Q : r;
}

pqc_status_t stream_aggregator_process_chunk(uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size) {
    if (chunk_size > CHUNK_ELEMENTS * 2) return ERR_CHUNK_TOO_LARGE;
    if (chunk_size % 2 != 0) return ERR_CHUNK_TOO_SMALL;

    chunk_buffer_t* chunk_buf = scratch_get_chunk_buf();
    dma_double_buffer_t* dma_tx = scratch_get_dma_tx();
    mlkem_workspace_t* mlkem_ws = scratch_get_mlkem_ws();

    uint8_t stream_seed[32];
    pqc_status_t ret = kem_adapter_derive_stream_mask_seed(
        (uint8_t*)mlkem_ws, client_id, round_id, chunk_index, stream_seed
    );
    if (ret != PQC_SUCCESS) return ret;

    mask_prg_init(stream_seed);
    int16_t mask[CHUNK_ELEMENTS];
    mask_prg_expand((uint8_t*)mask, chunk_size);

    int16_t* input = (int16_t*)chunk_buf->data;
    int16_t* output = (int16_t*)dma_tx->ping;
    size_t num_elements = chunk_size / 2;

    for (size_t i = 0; i < num_elements; i++) {
        int32_t sum = (int32_t)input[i] + (int32_t)mask[i];
        output[i] = (int16_t)barrett_reduce_q((uint32_t)sum);
    }

    crypto_zeroize(mask, sizeof(mask));
    crypto_zeroize(stream_seed, 32);
    return PQC_SUCCESS;
}

pqc_status_t stream_aggregator_unmask_chunk(uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size) {
    if (chunk_size > CHUNK_ELEMENTS * 2) return ERR_CHUNK_TOO_LARGE;
    if (chunk_size % 2 != 0) return ERR_CHUNK_TOO_SMALL;

    chunk_buffer_t* chunk_buf = scratch_get_chunk_buf();
    dma_double_buffer_t* dma_tx = scratch_get_dma_tx();
    mlkem_workspace_t* mlkem_ws = scratch_get_mlkem_ws();

    uint8_t stream_seed[32];
    pqc_status_t ret = kem_adapter_derive_stream_mask_seed(
        (uint8_t*)mlkem_ws, client_id, round_id, chunk_index, stream_seed
    );
    if (ret != PQC_SUCCESS) return ret;

    mask_prg_init(stream_seed);
    int16_t mask[CHUNK_ELEMENTS];
    mask_prg_expand((uint8_t*)mask, chunk_size);

    int16_t* input = (int16_t*)chunk_buf->data;
    int16_t* output = (int16_t*)dma_tx->ping;
    size_t num_elements = chunk_size / 2;

    for (size_t i = 0; i < num_elements; i++) {
        int32_t diff = (int32_t)input[i] - (int32_t)mask[i];
        output[i] = (int16_t)barrett_reduce_q((uint32_t)(diff + KYBER_Q));
    }

    crypto_zeroize(mask, sizeof(mask));
    crypto_zeroize(stream_seed, 32);
    return PQC_SUCCESS;
}