#include "crypto_worker.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "kem_adapter.h"
#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"
#include "telemetry.h"

#include <stdint.h>
#include <stddef.h>
#include <string.h>

#define CRYPTO_QUEUE_LENGTH       8u
#define CRYPTO_TASK_STACK_WORDS   1024u
#define CRYPTO_TASK_PRIORITY      3u

static QueueHandle_t g_crypto_queue = NULL;

static StackType_t crypto_stack[
    CRYPTO_TASK_STACK_WORDS
];

static StaticTask_t crypto_tcb;

static uint8_t crypto_queue_storage[
    CRYPTO_QUEUE_LENGTH * sizeof(crypto_work_item_t)
];

static StaticQueue_t crypto_queue_struct;

static TaskHandle_t g_crypto_task_handle = NULL;
static BaseType_t g_crypto_initialized = pdFALSE;

/* ------------------------------------------------------------------------- */
/* Internal helpers                                                          */
/* ------------------------------------------------------------------------- */

static void crypto_worker_set_result(
    crypto_work_item_t* item,
    pqc_status_t status)
{
    if (item == NULL) {
        return;
    }

    if (item->status_out != NULL) {
        *(item->status_out) = status;
    }

    if (item->done_flag != NULL) {
        *(item->done_flag) = pdTRUE;
    }
}

/* ------------------------------------------------------------------------- */
/* Worker task                                                               */
/* ------------------------------------------------------------------------- */

static void crypto_worker_task(void* pvParameters)
{
    (void)pvParameters;

    crypto_work_item_t item;

    for (;;) {

        memset(
            &item,
            0,
            sizeof(item));

        if (xQueueReceive(
                g_crypto_queue,
                &item,
                portMAX_DELAY) != pdTRUE) {
            continue;
        }

        pqc_status_t status =
            ERR_INVALID_ARGUMENT;

        switch (item.op) {

            /* ------------------------------------------------------------- */
            /* Key generation                                                */
            /* ------------------------------------------------------------- */

            case CRYPTO_OP_KEYPAIR:

                if (item.keypair_out == NULL) {
                    status = ERR_INVALID_ARGUMENT;
                    break;
                }

                telemetry_cycle_start();

                status =
                    kem_adapter_keypair(
                        item.keypair_out);

                {
                    uint32_t cycles =
                        telemetry_cycle_end();

                    if (g_telemetry_session.round_count > 0) {
                        telemetry_record_crypto(
                            cycles,
                            0,
                            0,
                            0,
                            0,
                            0);
                    }
                }

                break;

            /* ------------------------------------------------------------- */
            /* Encapsulation                                                  */
            /* ------------------------------------------------------------- */

            case CRYPTO_OP_ENCAPSULATE:

                if (item.public_key == NULL ||
                    item.encap_out == NULL ||
                    item.pk_len == 0) {

                    status =
                        ERR_INVALID_ARGUMENT;
                    break;
                }

                telemetry_cycle_start();

                status =
                    kem_adapter_encapsulate(
                        item.public_key,
                        item.pk_len,
                        item.encap_out);

                {
                    uint32_t cycles =
                        telemetry_cycle_end();

                    if (g_telemetry_session.round_count > 0) {
                        telemetry_record_crypto(
                            0,
                            cycles,
                            0,
                            0,
                            0,
                            0);
                    }
                }

                break;

            /* ------------------------------------------------------------- */
            /* Decapsulation                                                  */
            /* ------------------------------------------------------------- */

            case CRYPTO_OP_DECAPSULATE:

                if (item.ciphertext == NULL ||
                    item.secret_key == NULL ||
                    item.shared_secret_out == NULL ||
                    item.ct_len == 0 ||
                    item.sk_len == 0) {

                    status =
                        ERR_INVALID_ARGUMENT;
                    break;
                }

                telemetry_cycle_start();

                status =
                    kem_adapter_decapsulate(
                        item.ciphertext,
                        item.ct_len,
                        item.secret_key,
                        item.sk_len,
                        item.shared_secret_out);

                {
                    uint32_t cycles =
                        telemetry_cycle_end();

                    if (g_telemetry_session.round_count > 0) {
                        telemetry_record_crypto(
                            0,
                            0,
                            cycles,
                            0,
                            0,
                            0);
                    }
                }

                break;

            /* ------------------------------------------------------------- */
            /* Session-key derivation / HKDF                                  */
            /* ------------------------------------------------------------- */

            case CRYPTO_OP_HKDF:

                if (item.shared_secret_in == NULL ||
                    item.session_key_out == NULL) {

                    status =
                        ERR_INVALID_ARGUMENT;
                    break;
                }

                /*
                 * salt and info are optional for the adapter interface,
                 * so they are not rejected here.
                 */

                telemetry_cycle_start();

                status =
                    kem_adapter_derive_session_key(
                        item.shared_secret_in,
                        item.salt,
                        item.salt_len,
                        item.info,
                        item.info_len,
                        item.session_key_out);

                {
                    uint32_t cycles =
                        telemetry_cycle_end();

                    if (g_telemetry_session.round_count > 0) {
                        telemetry_record_crypto(
                            0,
                            0,
                            0,
                            cycles,
                            0,
                            0);
                    }
                }

                break;

            /* ------------------------------------------------------------- */
            /* Unsupported operation                                          */
            /* ------------------------------------------------------------- */

            case CRYPTO_OP_NONE:
            default:

                status =
                    ERR_INVALID_ARGUMENT;

                break;
        }

        /*
         * Always publish the operation result after processing.
         *
         * This prevents callers from waiting forever when an invalid
         * work item is submitted.
         */
        crypto_worker_set_result(
            &item,
            status);
    }
}

/* ------------------------------------------------------------------------- */
/* Initialization                                                            */
/* ------------------------------------------------------------------------- */

void crypto_worker_init(void)
{
    if (g_crypto_initialized == pdTRUE) {
        return;
    }

    g_crypto_queue =
        xQueueCreateStatic(
            CRYPTO_QUEUE_LENGTH,
            sizeof(crypto_work_item_t),
            crypto_queue_storage,
            &crypto_queue_struct);

    if (g_crypto_queue == NULL) {
        g_crypto_task_handle = NULL;
        g_crypto_initialized = pdFALSE;
        return;
    }

    g_crypto_task_handle =
        xTaskCreateStatic(
            crypto_worker_task,
            "crypto_worker",
            CRYPTO_TASK_STACK_WORDS,
            NULL,
            CRYPTO_TASK_PRIORITY,
            crypto_stack,
            &crypto_tcb);

    if (g_crypto_task_handle == NULL) {
        g_crypto_queue = NULL;
        g_crypto_initialized = pdFALSE;
        return;
    }

    g_crypto_initialized = pdTRUE;
}

/* ------------------------------------------------------------------------- */
/* Submit work                                                               */
/* ------------------------------------------------------------------------- */

BaseType_t crypto_worker_submit(
    const crypto_work_item_t* item,
    TickType_t timeout)
{
    if (g_crypto_initialized != pdTRUE ||
        g_crypto_queue == NULL ||
        item == NULL) {
        return pdFALSE;
    }

    return xQueueSend(
        g_crypto_queue,
        item,
        timeout);
}