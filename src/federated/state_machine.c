#include "protocol_types.h"
#include "memory_scratchpad.h"
#include "kem_adapter.h"
<<<<<<< HEAD
#include "mask_protocol.h"
#include "shamir.h"
#include "dropout_protocol.h"
#include "packet_codec.h"
#include "FreeRTOS.h"
#include "task.h"
#include "timers.h"
=======
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4
#include <stdint.h>
#include <string.h>

#define MAX_CLIENTS 16
#define STATE_TIMEOUT_MS 5000
#define LOCAL_TRAINING_DELAY_MS 100
<<<<<<< HEAD
#define DROPOUT_TIMEOUT_MS 10000
=======
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4

static protocol_state_buffer_t* get_proto_state(void) {
    return scratch_get_proto_state();
}

static void mock_local_training(client_protocol_ctx_t* ctx) {
    for (volatile uint32_t i = 0; i < LOCAL_TRAINING_DELAY_MS * 1000; i++) {
        __asm__ volatile ("nop");
    }
    (void)ctx;
}

<<<<<<< HEAD
static TimerHandle_t g_dropout_timer = NULL;
static client_protocol_ctx_t* g_registered_contexts[MAX_CLIENTS] = {0};
static uint8_t g_num_registered = 0;

=======
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4
pqc_status_t state_machine_init(client_protocol_ctx_t* ctx, uint8_t client_id, uint32_t round_id) {
    if (!ctx) return ERR_INVALID_ARGUMENT;
    memset(ctx, 0, sizeof(client_protocol_ctx_t));
    ctx->client_id = client_id;
    ctx->current_round_id = round_id;
    ctx->state = STATE_ROUND_INIT;
    ctx->timeout_ms = STATE_TIMEOUT_MS;
<<<<<<< HEAD
    ctx->last_activity_tick = xTaskGetTickCount();
=======
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4
    return PQC_SUCCESS;
}

pqc_status_t state_machine_transition(client_protocol_ctx_t* ctx, protocol_state_t new_state) {
    if (!ctx) return ERR_INVALID_ARGUMENT;
    if (ctx->state == STATE_ERROR) return ERR_INVALID_STATE;
    ctx->state = new_state;
<<<<<<< HEAD
    ctx->last_activity_tick = xTaskGetTickCount();
=======
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4
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
<<<<<<< HEAD
    ctx->chunk_ctx.is_final_chunk = 0;

    ctx->shamir_ctx.threshold = threshold;
    ctx->shamir_ctx.num_shares = expected_clients - 1;
=======
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4

    return state_machine_transition(ctx, STATE_KEY_SETUP);
}

pqc_status_t state_machine_handle_key_setup(client_protocol_ctx_t* ctx, const msg_header_t* hdr, const uint8_t* payload) {
    if (!ctx || ctx->state != STATE_KEY_SETUP) return ERR_INVALID_STATE;
<<<<<<< HEAD

    if (hdr->message_type == MSG_TYPE_KEM_PUBLIC_KEY) {
        return kem_adapter_keypair(&ctx->kem_kp);
    }

    if (hdr->message_type == MSG_TYPE_KEM_CIPHERTEXT) {
        if (hdr->payload_length != ctx->kem_kp.ciphertext_len) return ERR_INVALID_ARGUMENT;
        pqc_status_t ret = kem_adapter_decapsulate(
            payload, hdr->payload_length,
            ctx->kem_kp.secret_key, ctx->kem_kp.secret_key_len,
            ctx->kem_kp.shared_secret
        );
        if (ret != PQC_SUCCESS) return ret;
        ctx->kem_kp.shared_secret_len = ctx->kem_kp.shared_secret_len;
        return state_machine_transition(ctx, STATE_MASK_SETUP);
    }

=======
    if (hdr->message_type == MSG_TYPE_KEM_PUBLIC_KEY) {
        return kem_adapter_keypair(&ctx->kem_kp);
    }
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4
    return ERR_INVALID_ARGUMENT;
}

pqc_status_t state_machine_handle_mask_setup(client_protocol_ctx_t* ctx, const msg_header_t* hdr, const uint8_t* payload) {
    if (!ctx || ctx->state != STATE_MASK_SETUP) return ERR_INVALID_STATE;
<<<<<<< HEAD

    if (hdr->message_type == MSG_TYPE_PAIRWISE_KEM_PUBKEY) {
        if (hdr->payload_length != ML_KEM_768_PUBLIC_KEY_BYTES) return ERR_INVALID_ARGUMENT;
        uint8_t peer_id = hdr->client_id;
        for (uint8_t i = 0; i < ctx->pairwise_ctx.num_peers; i++) {
            if (ctx->pairwise_ctx.peers[i].peer_client_id == peer_id) {
                memcpy(ctx->pairwise_ctx.peers[i].shared_secret, payload, ML_KEM_768_PUBLIC_KEY_BYTES);
                return PQC_SUCCESS;
            }
        }
        if (ctx->pairwise_ctx.num_peers < MAX_PEERS_PER_CLIENT) {
            ctx->pairwise_ctx.peers[ctx->pairwise_ctx.num_peers].peer_client_id = peer_id;
            memcpy(ctx->pairwise_ctx.peers[ctx->pairwise_ctx.num_peers].shared_secret, payload, ML_KEM_768_PUBLIC_KEY_BYTES);
            ctx->pairwise_ctx.num_peers++;
        }
        return PQC_SUCCESS;
    }

    if (hdr->message_type == MSG_TYPE_PAIRWISE_KEM_CIPHERTEXT) {
        if (hdr->payload_length != ML_KEM_768_CIPHERTEXT_BYTES) return ERR_INVALID_ARGUMENT;
        uint8_t peer_id = hdr->client_id;
        uint8_t shared_secret[ML_KEM_768_SHARED_SECRET_BYTES];
        for (uint8_t i = 0; i < ctx->pairwise_ctx.num_peers; i++) {
            if (ctx->pairwise_ctx.peers[i].peer_client_id == peer_id) {
                pqc_status_t ret = kem_adapter_decapsulate(
                    payload, hdr->payload_length,
                    ctx->pairwise_ctx.peers[i].shared_secret, ML_KEM_768_PUBLIC_KEY_BYTES,
                    shared_secret
                );
                if (ret != PQC_SUCCESS) return ret;
                memcpy(ctx->pairwise_ctx.peers[i].shared_secret, shared_secret, ML_KEM_768_SHARED_SECRET_BYTES);
                return PQC_SUCCESS;
            }
        }
        return ERR_INVALID_ARGUMENT;
    }

    if (hdr->message_type == MSG_TYPE_PAIRWISE_CONFIRM) {
        uint8_t client_client_kem_secrets[MAX_PEERS_PER_CLIENT * ML_KEM_768_SHARED_SECRET_BYTES];
        for (uint8_t i = 0; i < ctx->pairwise_ctx.num_peers; i++) {
            memcpy(&client_client_kem_secrets[i * ML_KEM_768_SHARED_SECRET_BYTES],
                   ctx->pairwise_ctx.peers[i].shared_secret,
                   ML_KEM_768_SHARED_SECRET_BYTES);
        }
        pqc_status_t ret = mask_protocol_derive_pairwise_seeds(
            &ctx->pairwise_ctx, ctx->client_id,
            client_client_kem_secrets, ctx->current_round_id
        );
        if (ret != PQC_SUCCESS) return ret;
        return state_machine_transition(ctx, STATE_LOCAL_TRAINING);
    }

    return ERR_INVALID_ARGUMENT;
=======
    return state_machine_transition(ctx, STATE_LOCAL_TRAINING);
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4
}

pqc_status_t state_machine_handle_local_training(client_protocol_ctx_t* ctx, const msg_header_t* hdr, const uint8_t* payload) {
    if (!ctx || ctx->state != STATE_LOCAL_TRAINING) return ERR_INVALID_STATE;
    mock_local_training(ctx);
    return state_machine_transition(ctx, STATE_MASKED_UPDATE_STREAM);
}

pqc_status_t state_machine_handle_stream_chunk(client_protocol_ctx_t* ctx, const msg_header_t* hdr, const uint8_t* payload, uint16_t payload_len) {
    if (!ctx || ctx->state != STATE_MASKED_UPDATE_STREAM) return ERR_INVALID_STATE;
    if (hdr->sequence_number != ctx->chunk_ctx.chunk_index) return ERR_SEQUENCE_MISMATCH;
    if (payload_len != ctx->chunk_ctx.chunk_size && !(ctx->chunk_ctx.is_final_chunk && payload_len < ctx->chunk_ctx.chunk_size)) {
        return ERR_CHUNK_TOO_LARGE;
    }
<<<<<<< HEAD

    uint16_t chunk_elements = ctx->chunk_ctx.chunk_size / 2;
    int16_t mask[CHUNK_BUFFER_BYTES / 2];
    int16_t masked_chunk[CHUNK_BUFFER_BYTES / 2];

    pqc_status_t ret = mask_protocol_generate_chunk_mask(
        &ctx->pairwise_ctx, ctx->client_id,
        ctx->current_round_id, ctx->chunk_ctx.chunk_index,
        chunk_elements, mask
    );
    if (ret != PQC_SUCCESS) return ret;

    const int16_t* plaintext_chunk = (const int16_t*)payload;
    ret = mask_protocol_apply_mask(plaintext_chunk, mask, chunk_elements, masked_chunk);
    if (ret != PQC_SUCCESS) return ret;

    memcpy((void*)payload, masked_chunk, chunk_elements * sizeof(int16_t));

    ctx->chunk_ctx.chunk_index++;
    ctx->chunk_ctx.bytes_processed += payload_len;
    if (ctx->chunk_ctx.chunk_index >= ctx->chunk_ctx.total_chunks - 1) {
        ctx->chunk_ctx.is_final_chunk = 1;
    }

=======
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4
    return PQC_SUCCESS;
}

pqc_status_t state_machine_handle_completion(client_protocol_ctx_t* ctx, const msg_header_t* hdr) {
    if (!ctx || ctx->state != STATE_MASKED_UPDATE_STREAM) return ERR_INVALID_STATE;
    if (hdr->message_type != MSG_TYPE_CLIENT_COMPLETE) return ERR_INVALID_ARGUMENT;
<<<<<<< HEAD

    uint8_t shamir_secret[SHAMIR_SHARE_VALUE_BYTES];
    pqc_status_t ret = kem_adapter_derive_shamir_secret(
        ctx->kem_kp.shared_secret, ctx->client_id, ctx->current_round_id, shamir_secret
    );
    if (ret != PQC_SUCCESS) return ret;

    uint8_t share_x[MAX_CLIENTS];
    uint8_t share_y_buf[MAX_CLIENTS][SHAMIR_SHARE_VALUE_BYTES];
    uint8_t* share_y[MAX_CLIENTS];
    for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
        share_y[i] = share_y_buf[i];
    }
    uint16_t workspace[SHAMIR_WORKSPACE_SIZE];

    ret = shamir_share_bytes(
        shamir_secret, SHAMIR_SHARE_VALUE_BYTES,
        share_x, share_y,
        ctx->shamir_ctx.num_shares, ctx->shamir_ctx.threshold,
        workspace
    );
    if (ret != 0) return ERR_SHAMIR_ENCODE_FAILED;

    for (uint8_t i = 0; i < ctx->shamir_ctx.num_shares; i++) {
        shamir_share_t share;
        share.share_id = share_x[i];
        memcpy(share.value, share_y[i], SHAMIR_SHARE_VALUE_BYTES);

        msg_header_t share_hdr = {
            .protocol_version = PROTOCOL_VERSION,
            .round_id = ctx->current_round_id,
            .client_id = ctx->client_id,
            .message_type = MSG_TYPE_SHAMIR_SHARE,
            .sequence_number = i,
            .payload_length = sizeof(shamir_share_t),
            .reserved = 0
        };
        protocol_state_buffer_t* proto = get_proto_state();
        pqc_status_t send_ret = packet_codec_encode_message(&share_hdr, (uint8_t*)&share, ctx->session_key, proto->data, &proto->data[0]);
        (void)send_ret;
    }

=======
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4
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

<<<<<<< HEAD
static void dropout_timer_callback(TimerHandle_t xTimer) {
    (void)xTimer;
    for (uint8_t i = 0; i < g_num_registered; i++) {
        client_protocol_ctx_t* ctx = g_registered_contexts[i];
        if (ctx && ctx->state != STATE_ROUND_COMPLETE && ctx->state != STATE_ERROR) {
            uint32_t current_tick = xTaskGetTickCount();
            if (current_tick - ctx->last_activity_tick > pdMS_TO_TICKS(DROPOUT_TIMEOUT_MS)) {
                ctx->state = STATE_DROPOUT_DETECTION;
            }
        }
    }
}

void protocol_register_context(client_protocol_ctx_t* ctx) {
    if (g_num_registered < MAX_CLIENTS) {
        g_registered_contexts[g_num_registered++] = ctx;
        if (!g_dropout_timer) {
            g_dropout_timer = xTimerCreate("DropoutTimer", pdMS_TO_TICKS(1000), pdTRUE, NULL, dropout_timer_callback);
            if (g_dropout_timer) {
                xTimerStart(g_dropout_timer, 0);
            }
        }
    }
}

void protocol_check_timeouts(void) {
    uint32_t current_tick = xTaskGetTickCount();
    for (uint8_t i = 0; i < g_num_registered; i++) {
        client_protocol_ctx_t* ctx = g_registered_contexts[i];
        if (ctx && ctx->state != STATE_ROUND_COMPLETE && ctx->state != STATE_ERROR) {
            if (current_tick - ctx->last_activity_tick > pdMS_TO_TICKS(DROPOUT_TIMEOUT_MS)) {
                msg_header_t dropout_hdr = {
                    .protocol_version = PROTOCOL_VERSION,
                    .round_id = ctx->current_round_id,
                    .client_id = ctx->client_id,
                    .message_type = MSG_TYPE_DROPOUT_NOTIFY,
                    .sequence_number = 0,
                    .payload_length = 0,
                    .reserved = 0
                };
                protocol_state_buffer_t* proto = get_proto_state();
                pqc_status_t ret = packet_codec_encode_message(&dropout_hdr, NULL, ctx->session_key, proto->data, &proto->data[0]);
                (void)ret;
                ctx->state = STATE_DROPOUT_DETECTION;
            }
        }
    }
}

=======
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4
pqc_status_t state_machine_process_message(client_protocol_ctx_t* ctx, const msg_header_t* hdr, const uint8_t* payload, uint16_t payload_len) {
    if (!ctx || !hdr) return ERR_INVALID_ARGUMENT;
    if (hdr->round_id != ctx->current_round_id) return ERR_ROUND_MISMATCH;
    if (hdr->client_id != 0 && hdr->client_id != ctx->client_id) return ERR_CLIENT_ID_MISMATCH;

<<<<<<< HEAD
    ctx->last_activity_tick = xTaskGetTickCount();

=======
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4
    switch (ctx->state) {
        case STATE_ROUND_INIT:
            return state_machine_handle_round_init(ctx, hdr, payload);
        case STATE_KEY_SETUP:
            return state_machine_handle_key_setup(ctx, hdr, payload);
        case STATE_MASK_SETUP:
            return state_machine_handle_mask_setup(ctx, hdr, payload);
        case STATE_LOCAL_TRAINING:
            return state_machine_handle_local_training(ctx, hdr, payload);
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
<<<<<<< HEAD
}
=======
}
>>>>>>> 2875321eba292240b6900b9487a8c6ee820c76c4
