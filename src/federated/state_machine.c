#include "protocol_types.h"
#include "memory_scratchpad.h"
#include "kem_adapter.h"
#include <stdint.h>
#include <string.h>

#define MAX_CLIENTS 16
#define STATE_TIMEOUT_MS 5000

static protocol_state_buffer_t* get_proto_state(void) {
    return scratch_get_proto_state();
}

pqc_status_t state_machine_init(client_protocol_ctx_t* ctx, uint8_t client_id, uint32_t round_id) {
    if (!ctx) return ERR_INVALID_ARGUMENT;
    memset(ctx, 0, sizeof(client_protocol_ctx_t));
    ctx->client_id = client_id;
    ctx->current_round_id = round_id;
    ctx->state = STATE_ROUND_INIT;
    ctx->timeout_ms = STATE_TIMEOUT_MS;
    return PQC_SUCCESS;
}

pqc_status_t state_machine_transition(client_protocol_ctx_t* ctx, protocol_state_t new_state) {
    if (!ctx) return ERR_INVALID_ARGUMENT;
    if (ctx->state == STATE_ERROR) return ERR_INVALID_STATE;
    ctx->state = new_state;
    return PQC_SUCCESS;
}

pqc_status_t state_machine_handle_round_init(client_protocol_ctx_t* ctx, const msg_header_t* hdr, const uint8_t* payload) {
    if (!ctx || !hdr || hdr->message_type != MSG_TYPE_ROUND_INIT) return ERR_INVALID_ARGUMENT;
    if (hdr->round_id != ctx->current_round_id) return ERR_ROUND_MISMATCH;

    const uint8_t* p = payload;
    uint8_t expected_clients = *p++;
    uint8_t threshold = *p++;
    uint16_t chunk_size = (p[0] | (p[1] << 8)); p += 2;
    uint32_t model_size = (p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));

    ctx->chunk_ctx.round_id = hdr->round_id;
    ctx->chunk_ctx.client_id = ctx->client_id;
    ctx->chunk_ctx.chunk_size = chunk_size;
    ctx->chunk_ctx.model_total_bytes = model_size;
    ctx->chunk_ctx.total_chunks = (model_size + chunk_size - 1) / chunk_size;
    ctx->chunk_ctx.chunk_index = 0;
    ctx->chunk_ctx.bytes_processed = 0;

    return state_machine_transition(ctx, STATE_KEY_SETUP);
}

pqc_status_t state_machine_handle_key_setup(client_protocol_ctx_t* ctx, const msg_header_t* hdr, const uint8_t* payload) {
    if (!ctx || ctx->state != STATE_KEY_SETUP) return ERR_INVALID_STATE;
    if (hdr->message_type == MSG_TYPE_KEM_PUBLIC_KEY) {
        return kem_adapter_keypair(&ctx->kem_kp);
    }
    return ERR_INVALID_ARGUMENT;
}

pqc_status_t state_machine_handle_mask_setup(client_protocol_ctx_t* ctx, const msg_header_t* hdr, const uint8_t* payload) {
    if (!ctx || ctx->state != STATE_MASK_SETUP) return ERR_INVALID_STATE;
    return state_machine_transition(ctx, STATE_LOCAL_TRAINING);
}

pqc_status_t state_machine_handle_stream_chunk(client_protocol_ctx_t* ctx, const msg_header_t* hdr, const uint8_t* payload, uint16_t payload_len) {
    if (!ctx || ctx->state != STATE_MASKED_UPDATE_STREAM) return ERR_INVALID_STATE;
    if (hdr->sequence_number != ctx->chunk_ctx.chunk_index) return ERR_SEQUENCE_MISMATCH;
    if (payload_len != ctx->chunk_ctx.chunk_size && !(ctx->chunk_ctx.is_final_chunk && payload_len < ctx->chunk_ctx.chunk_size)) {
        return ERR_CHUNK_TOO_LARGE;
    }
    return PQC_SUCCESS;
}

pqc_status_t state_machine_handle_completion(client_protocol_ctx_t* ctx, const msg_header_t* hdr) {
    if (!ctx || ctx->state != STATE_MASKED_UPDATE_STREAM) return ERR_INVALID_STATE;
    if (hdr->message_type != MSG_TYPE_CLIENT_COMPLETE) return ERR_INVALID_ARGUMENT;
    return state_machine_transition(ctx, STATE_CLIENT_COMPLETION);
}

pqc_status_t state_machine_handle_dropout_notify(client_protocol_ctx_t* ctx, const msg_header_t* hdr, const uint8_t* payload) {
    if (!ctx || ctx->state != STATE_CLIENT_COMPLETION) return ERR_INVALID_STATE;
    if (hdr->message_type != MSG_TYPE_DROPOUT_NOTIFY) return ERR_INVALID_ARGUMENT;
    return state_machine_transition(ctx, STATE_MASK_RECOVERY);
}

pqc_status_t state_machine_handle_recovery_complete(client_protocol_ctx_t* ctx, const msg_header_t* hdr) {
    if (!ctx || ctx->state != STATE_MASK_RECOVERY) return ERR_INVALID_STATE;
    if (hdr->message_type != MSG_TYPE_RECOVERY_COMPLETE) return ERR_INVALID_ARGUMENT;
    return state_machine_transition(ctx, STATE_UNMASK);
}

pqc_status_t state_machine_handle_round_complete(client_protocol_ctx_t* ctx, const msg_header_t* hdr) {
    if (!ctx) return ERR_INVALID_ARGUMENT;
    if (hdr->message_type != MSG_TYPE_ROUND_COMPLETE) return ERR_INVALID_ARGUMENT;
    return state_machine_transition(ctx, STATE_ROUND_COMPLETE);
}

pqc_status_t state_machine_process_message(client_protocol_ctx_t* ctx, const msg_header_t* hdr, const uint8_t* payload, uint16_t payload_len) {
    if (!ctx || !hdr) return ERR_INVALID_ARGUMENT;
    if (hdr->round_id != ctx->current_round_id) return ERR_ROUND_MISMATCH;
    if (hdr->client_id != 0 && hdr->client_id != ctx->client_id) return ERR_CLIENT_ID_MISMATCH;

    switch (ctx->state) {
        case STATE_ROUND_INIT:
            return state_machine_handle_round_init(ctx, hdr, payload);
        case STATE_KEY_SETUP:
            return state_machine_handle_key_setup(ctx, hdr, payload);
        case STATE_MASK_SETUP:
            return state_machine_handle_mask_setup(ctx, hdr, payload);
        case STATE_LOCAL_TRAINING:
            return state_machine_transition(ctx, STATE_MASKED_UPDATE_STREAM);
        case STATE_MASKED_UPDATE_STREAM:
            if (hdr->message_type == MSG_TYPE_MASK_CHUNK) {
                return state_machine_handle_stream_chunk(ctx, hdr, payload, payload_len);
            } else if (hdr->message_type == MSG_TYPE_CLIENT_COMPLETE) {
                return state_machine_handle_completion(ctx, hdr);
            }
            break;
        case STATE_CLIENT_COMPLETION:
            return state_machine_handle_dropout_notify(ctx, hdr, payload);
        case STATE_MASK_RECOVERY:
            return state_machine_handle_recovery_complete(ctx, hdr);
        case STATE_UNMASK:
            return state_machine_transition(ctx, STATE_FEDAVG);
        case STATE_FEDAVG:
            return state_machine_transition(ctx, STATE_ROUND_COMPLETE);
        default:
            break;
    }
    return ERR_INVALID_STATE;
}