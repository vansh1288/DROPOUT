#ifndef MEMORY_SCRATCHPAD_H
#define MEMORY_SCRATCHPAD_H

#include "protocol_types.h"
#include <stdint.h>
#include <stddef.h>

#define SCRATCH_ALIGNMENT         32u
#define MLKEM_WORKSPACE_BYTES     4096u
#define CRYPTO_WORKSPACE_BYTES    2048u
#define DMA_BUFFER_BYTES          1536u
#define CHUNK_BUFFER_BYTES        1024u
#define SHAMIR_WORKSPACE_BYTES    1024u
#define PROTOCOL_STATE_BYTES      512u

#define SCRATCH_PEAK_BYTES        MLKEM_WORKSPACE_BYTES

#define GLOBAL_SCRATCHPAD_BYTES   ( \
    MLKEM_WORKSPACE_BYTES + \
    CRYPTO_WORKSPACE_BYTES + \
    (2 * DMA_BUFFER_BYTES) + \
    (2 * DMA_BUFFER_BYTES) + \
    CHUNK_BUFFER_BYTES + \
    SHAMIR_WORKSPACE_BYTES + \
    PROTOCOL_STATE_BYTES \
)

#if defined(__GNUC__) || defined(__clang__)
#define SCRATCH_ALIGN  __attribute__((aligned(SCRATCH_ALIGNMENT)))
#elif defined(_MSC_VER)
#define SCRATCH_ALIGN  __declspec(align(SCRATCH_ALIGNMENT))
#else
#define SCRATCH_ALIGN
#endif

#define COMPILE_TIME_ASSERT(cond, msg) typedef char assert_##msg[(cond) ? 1 : -1]

typedef struct {
    uint8_t data[MLKEM_WORKSPACE_BYTES] SCRATCH_ALIGN;
} mlkem_workspace_t;

typedef struct {
    uint8_t data[CRYPTO_WORKSPACE_BYTES] SCRATCH_ALIGN;
} crypto_workspace_t;

typedef struct {
    uint8_t ping[DMA_BUFFER_BYTES] SCRATCH_ALIGN;
    uint8_t pong[DMA_BUFFER_BYTES] SCRATCH_ALIGN;
} dma_double_buffer_t;

typedef struct {
    uint8_t data[CHUNK_BUFFER_BYTES] SCRATCH_ALIGN;
} chunk_buffer_t;

typedef struct {
    uint8_t data[SHAMIR_WORKSPACE_BYTES] SCRATCH_ALIGN;
} shamir_workspace_t;

typedef struct {
    uint8_t data[PROTOCOL_STATE_BYTES] SCRATCH_ALIGN;
} protocol_state_buffer_t;

typedef union SCRATCH_ALIGN {
    struct {
        mlkem_workspace_t     mlkem_ws;
        crypto_workspace_t    crypto_ws;
        dma_double_buffer_t   dma_rx;
        dma_double_buffer_t   dma_tx;
        chunk_buffer_t        chunk_buf;
        shamir_workspace_t    shamir_ws;
        protocol_state_buffer_t proto_state;
    } regions;
    uint8_t raw[GLOBAL_SCRATCHPAD_BYTES];
} Global_Scratchpad;

COMPILE_TIME_ASSERT(sizeof(Global_Scratchpad) == GLOBAL_SCRATCHPAD_BYTES, Global_Scratchpad_size_mismatch);
COMPILE_TIME_ASSERT(sizeof(mlkem_workspace_t) == MLKEM_WORKSPACE_BYTES, mlkem_workspace_t_size_mismatch);
COMPILE_TIME_ASSERT(sizeof(crypto_workspace_t) == CRYPTO_WORKSPACE_BYTES, crypto_workspace_t_size_mismatch);
COMPILE_TIME_ASSERT(sizeof(dma_double_buffer_t) == 2 * DMA_BUFFER_BYTES, dma_double_buffer_t_size_mismatch);
COMPILE_TIME_ASSERT(sizeof(chunk_buffer_t) == CHUNK_BUFFER_BYTES, chunk_buffer_t_size_mismatch);
COMPILE_TIME_ASSERT(sizeof(shamir_workspace_t) == SHAMIR_WORKSPACE_BYTES, shamir_workspace_t_size_mismatch);
COMPILE_TIME_ASSERT(sizeof(protocol_state_buffer_t) == PROTOCOL_STATE_BYTES, protocol_state_buffer_t_size_mismatch);

extern Global_Scratchpad g_scratchpad;

static inline mlkem_workspace_t* scratch_get_mlkem_ws(void) {
    return &g_scratchpad.regions.mlkem_ws;
}

static inline crypto_workspace_t* scratch_get_crypto_ws(void) {
    return &g_scratchpad.regions.crypto_ws;
}

static inline dma_double_buffer_t* scratch_get_dma_rx(void) {
    return &g_scratchpad.regions.dma_rx;
}

static inline dma_double_buffer_t* scratch_get_dma_tx(void) {
    return &g_scratchpad.regions.dma_tx;
}

static inline uint8_t* scratch_get_dma_rx_active(size_t idx) {
    return (idx & 1u) ? g_scratchpad.regions.dma_rx.pong : g_scratchpad.regions.dma_rx.ping;
}

static inline uint8_t* scratch_get_dma_tx_active(size_t idx) {
    return (idx & 1u) ? g_scratchpad.regions.dma_tx.pong : g_scratchpad.regions.dma_tx.ping;
}

static inline chunk_buffer_t* scratch_get_chunk_buf(void) {
    return &g_scratchpad.regions.chunk_buf;
}

static inline shamir_workspace_t* scratch_get_shamir_ws(void) {
    return &g_scratchpad.regions.shamir_ws;
}

static inline protocol_state_buffer_t* scratch_get_proto_state(void) {
    return &g_scratchpad.regions.proto_state;
}

static inline void scratch_zeroize_all(void) {
    volatile uint8_t* p = (volatile uint8_t*)g_scratchpad.raw;
    for (size_t i = 0; i < GLOBAL_SCRATCHPAD_BYTES; i++) {
        p[i] = 0u;
    }
}

typedef enum {
    SCRATCH_REGION_MLKEM    = 0,
    SCRATCH_REGION_CRYPTO   = 1,
    SCRATCH_REGION_DMA_RX   = 2,
    SCRATCH_REGION_DMA_TX   = 3,
    SCRATCH_REGION_CHUNK    = 4,
    SCRATCH_REGION_SHAMIR   = 5,
    SCRATCH_REGION_PROTO    = 6,
} scratch_region_t;

#define OFFSET_OF(type, member) ((size_t)&((type*)0)->member)

static inline void scratch_zeroize_region(scratch_region_t region_type) {
    volatile uint8_t* base = (volatile uint8_t*)g_scratchpad.raw;
    size_t offset = 0;
    size_t len = 0;

    switch (region_type) {
        case SCRATCH_REGION_MLKEM:
            offset = OFFSET_OF(Global_Scratchpad, regions.mlkem_ws);
            len = MLKEM_WORKSPACE_BYTES;
            break;
        case SCRATCH_REGION_CRYPTO:
            offset = OFFSET_OF(Global_Scratchpad, regions.crypto_ws);
            len = CRYPTO_WORKSPACE_BYTES;
            break;
        case SCRATCH_REGION_DMA_RX:
            offset = OFFSET_OF(Global_Scratchpad, regions.dma_rx);
            len = 2 * DMA_BUFFER_BYTES;
            break;
        case SCRATCH_REGION_DMA_TX:
            offset = OFFSET_OF(Global_Scratchpad, regions.dma_tx);
            len = 2 * DMA_BUFFER_BYTES;
            break;
        case SCRATCH_REGION_CHUNK:
            offset = OFFSET_OF(Global_Scratchpad, regions.chunk_buf);
            len = CHUNK_BUFFER_BYTES;
            break;
        case SCRATCH_REGION_SHAMIR:
            offset = OFFSET_OF(Global_Scratchpad, regions.shamir_ws);
            len = SHAMIR_WORKSPACE_BYTES;
            break;
        case SCRATCH_REGION_PROTO:
            offset = OFFSET_OF(Global_Scratchpad, regions.proto_state);
            len = PROTOCOL_STATE_BYTES;
            break;
        default:
            return;
    }

    for (size_t i = 0; i < len; i++) {
        base[offset + i] = 0u;
    }
}

#define STACK_GUARD_PATTERN     0xA5A5A5A5u
#define STACK_GUARD_WORDS       4u

static inline void stack_guard_init(uint32_t* stack_base, size_t stack_words) {
    if (stack_words > STACK_GUARD_WORDS) {
        for (size_t i = 0; i < STACK_GUARD_WORDS; i++) {
            stack_base[i] = STACK_GUARD_PATTERN;
        }
    }
}

static inline int stack_guard_check(uint32_t* stack_base, size_t stack_words) {
    if (stack_words <= STACK_GUARD_WORDS) return 1;
    for (size_t i = 0; i < STACK_GUARD_WORDS; i++) {
        if (stack_base[i] != STACK_GUARD_PATTERN) return 0;
    }
    return 1;
}

#endif