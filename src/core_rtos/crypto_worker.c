#include "crypto_worker.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "kem_adapter.h"
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "telemetry.h"
#include <string.h>

#define CRYPTO_QUEUE_LENGTH 8
#define CRYPTO_QUEUE_ITEM_SIZE sizeof(crypto_work_item_t)

static QueueHandle_t g_crypto_queue = NULL;
static StackType_t crypto_stack[1024];
static StaticTask_t crypto_tcb;
static uint8_t crypto_queue_storage[CRYPTO_QUEUE_LENGTH * CRYPTO_QUEUE_ITEM_SIZE];
static StaticQueue_t crypto_queue_struct;

void crypto_worker_init(void) {
    g_crypto_queue = xQueueCreateStatic(CRYPTO_QUEUE_LENGTH, CRYPTO_QUEUE_ITEM_SIZE, crypto_queue_storage, &crypto_queue_struct);
    xTaskCreateStatic(crypto_worker_task, "crypto_worker", 1024, NULL, 3, crypto_stack, &crypto_tcb);
}

BaseType_t crypto_worker_submit(const crypto_work_item_t* item, TickType_t timeout) {
    if (!g_crypto_queue) return pdFALSE;
    return xQueueSend(g_crypto_queue, item, timeout);
}

static void crypto_worker_task(void* pvParameters) {
    crypto_work_item_t item;
    while (1) {
        if (xQueueReceive(g_crypto_queue, &item, portMAX_DELAY) == pdTRUE) {
            switch (item.op) {
                case CRYPTO_OP_KEYPAIR:
                    if (item.keypair_out) {
                        telemetry_cycle_start();
                        kem_adapter_keypair(item.keypair_out);
                        uint32_t cycles = telemetry_cycle_end();
                        if (g_telemetry_session.round_count > 0) {
                            telemetry_record_crypto(cycles, 0, 0, 0, 0, 0);
                        }
                        if (item.done_flag) *item.done_flag = pdTRUE;
                    }
                    break;
                case CRYPTO_OP_ENCAPSULATE:
                    if (item.public_key && item.encap_out) {
                        telemetry_cycle_start();
                        kem_adapter_encapsulate(item.public_key, item.pk_len, item.encap_out);
                        uint32_t cycles = telemetry_cycle_end();
                        if (g_telemetry_session.round_count > 0) {
                            telemetry_record_crypto(0, cycles, 0, 0, 0, 0);
                        }
                        if (item.done_flag) *item.done_flag = pdTRUE;
                    }
                    break;
                case CRYPTO_OP_DECAPSULATE:
                    if (item.ciphertext && item.secret_key && item.shared_secret_out) {
                        telemetry_cycle_start();
                        kem_adapter_decapsulate(item.ciphertext, item.ct_len, item.secret_key, item.sk_len, item.shared_secret_out);
                        uint32_t cycles = telemetry_cycle_end();
                        if (g_telemetry_session.round_count > 0) {
                            telemetry_record_crypto(0, 0, cycles, 0, 0, 0);
                        }
                        if (item.done_flag) *item.done_flag = pdTRUE;
                    }
                    break;
                case CRYPTO_OP_HKDF:
                    if (item.shared_secret_in && item.session_key_out) {
                        telemetry_cycle_start();
                        kem_adapter_derive_session_key(item.shared_secret_in, item.salt, item.salt_len, item.info, item.info_len, item.session_key_out);
                        uint32_t cycles = telemetry_cycle_end();
                        if (g_telemetry_session.round_count > 0) {
                            telemetry_record_crypto(0, 0, 0, cycles, 0, 0);
                        }
                        if (item.done_flag) *item.done_flag = pdTRUE;
                    }
                    break;
                default:
                    break;
            }
        }
    }
}
