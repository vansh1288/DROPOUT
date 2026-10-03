#include "FreeRTOS.h"
#include "task.h"
#include "queue.h"

#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "kem_adapter.h"
#include "stream_aggregator.h"
#include "crypto_worker.h"
#include "dma_transport.h"
#include "telemetry.h"
#include "dma_isr_handler.h"

#include <string.h>

/*
 * Global scratchpad.
 *
 * The scratchpad is initialized before any protocol/crypto subsystem
 * starts using it.
 */
union Global_Scratchpad g_scratchpad;

/*
 * Protocol context management.
 *
 * The contexts are owned by this RTOS/application layer and are accessed
 * by the state monitor task.
 */
static client_protocol_ctx_t g_client_contexts[MAX_CLIENTS] = {0};

/*
 * Network message structure used by the RTOS network queue.
 *
 * The type must be defined before NETWORK_QUEUE_ITEM_SIZE because the
 * queue storage size depends on sizeof(network_msg_t).
 */
typedef struct {
    uint32_t round_id;
    uint8_t client_id;
    uint8_t message_type;
    uint16_t sequence_number;
    uint16_t payload_length;
    uint8_t payload[256];
} network_msg_t;

/*
 * Network queue configuration.
 */
#define NETWORK_QUEUE_LENGTH      16u
#define NETWORK_QUEUE_ITEM_SIZE   sizeof(network_msg_t)

static QueueHandle_t g_network_queue = NULL;

static uint8_t network_queue_storage[
    NETWORK_QUEUE_LENGTH * NETWORK_QUEUE_ITEM_SIZE
];

static StaticQueue_t network_queue_struct;


/*
 * Register or update a protocol context.
 *
 * A client_id of zero is treated as an unused context slot.
 */
void protocol_register_context(client_protocol_ctx_t* ctx)
{
    if (ctx == NULL) {
        return;
    }

    for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
        if (g_client_contexts[i].client_id == 0u ||
            g_client_contexts[i].client_id == ctx->client_id) {

            g_client_contexts[i] = *ctx;
            return;
        }
    }
}


/*
 * Check protocol contexts for timeout.
 *
 * client_protocol_ctx_t::timeout_ms is expressed in milliseconds,
 * whereas xTaskGetTickCount() returns FreeRTOS ticks. Convert the
 * configured timeout before comparing the values.
 */
static void protocol_check_timeouts(void)
{
    const TickType_t current_tick = xTaskGetTickCount();

    for (uint8_t i = 0; i < MAX_CLIENTS; i++) {

        client_protocol_ctx_t* ctx = &g_client_contexts[i];

        if (ctx->client_id == 0u) {
            continue;
        }

        if (ctx->state == STATE_ROUND_COMPLETE ||
            ctx->state == STATE_ERROR) {
            continue;
        }

        const TickType_t timeout_ticks =
            pdMS_TO_TICKS(ctx->timeout_ms);

        if ((current_tick - ctx->last_activity_tick) >
            timeout_ticks) {

            ctx->state = STATE_ERROR;

            /*
             * Clear sensitive aggregation state when a protocol
             * context expires.
             */
            stream_aggregator_zeroize_accumulator();
        }
    }
}


/*
 * Network coordinator task.
 *
 * The DMA transport does not currently notify this task directly.
 * Therefore the task performs periodic polling instead of depending
 * on task-notification bits that may never be generated.
 */
static void network_coordinator_task(void* pvParameters)
{
    (void)pvParameters;

    for (;;) {

        /*
         * Poll the DMA/network transport periodically.
         */
        (void)dma_transport_rx_poll();
        (void)dma_transport_tx_poll();

        /*
         * Process any queued application-level network messages.
         *
         * Message handling will be integrated when the packet/transport
         * layer is finalized.
         */
        if (g_network_queue != NULL) {

            network_msg_t msg;

            if (xQueueReceive(
                    g_network_queue,
                    &msg,
                    0) == pdTRUE) {

                /*
                 * Packet/message handling is intentionally left to the
                 * transport validation layer.
                 */
                (void)msg;
            }
        }

        vTaskDelay(pdMS_TO_TICKS(10));
    }
}


/*
 * State monitor task.
 *
 * Performs periodic protocol timeout checking.
 */
static void state_monitor_task(void* pvParameters)
{
    (void)pvParameters;

    for (;;) {

        protocol_check_timeouts();

        vTaskDelay(pdMS_TO_TICKS(100));
    }
}


/*
 * Send a message to the network coordinator queue.
 */
BaseType_t network_queue_send(
    const network_msg_t* msg,
    TickType_t timeout)
{
    if (g_network_queue == NULL || msg == NULL) {
        return pdFALSE;
    }

    return xQueueSend(g_network_queue, msg, timeout);
}


/*
 * Main application entry point.
 */
void app_main(void)
{
    TaskHandle_t stream_task_handle;

    /*
     * 1. Initialize the global scratchpad first.
     */
    memset(
        &g_scratchpad,
        0,
        sizeof(union Global_Scratchpad)
    );

    /*
     * 2. Initialize telemetry before other subsystems so that
     *    initialization/runtime measurements are available.
     */
    telemetry_init();

    /*
     * 3. Initialize the KEM adapter.
     *
     *    This must happen before crypto worker and stream aggregator
     *    initialization because both depend on the crypto subsystem.
     */
    if (kem_adapter_init(KEMLIB_ML_KEM_768) != PQC_SUCCESS) {
        system_shutdown();
    }

    /*
     * 4. Initialize the crypto worker.
     *
     *    crypto_worker_init() creates its own queue and FreeRTOS task.
     *    Do not create another crypto task here.
     */
    crypto_worker_init();

    /*
     * 5. Initialize the streaming aggregator.
     *
     *    stream_aggregator_init() creates its own queue/task and
     *    initializes its DMA stream bridge.
     */
    stream_aggregator_init();

    /*
     * 6. Initialize DMA/network transport.
     *
     *    dma_transport_init() initializes the DMA ISR state internally.
     *    Therefore no separate dma_isr_init() call is required here.
     */
    if (dma_transport_init(-1, -1) != PQC_SUCCESS) {
        system_shutdown();
    }

    /*
     * 7. The DMA transport initialization resets the ISR task handle.
     *    Connect the DMA ISR to the stream aggregator task only after
     *    transport initialization has completed.
     */
    stream_task_handle = stream_aggregator_get_task_handle();

    if (stream_task_handle == NULL) {
        system_shutdown();
    }

    dma_isr_set_stream_task(stream_task_handle);

    /*
     * 8. Create the application-level network queue.
     */
    g_network_queue = xQueueCreateStatic(
        NETWORK_QUEUE_LENGTH,
        NETWORK_QUEUE_ITEM_SIZE,
        network_queue_storage,
        &network_queue_struct
    );

    if (g_network_queue == NULL) {
        system_shutdown();
    }

    /*
     * 9. Create the network coordinator task.
     *
     *    Crypto and stream tasks are already created by their respective
     *    subsystem initialization functions.
     */
    static StackType_t network_stack[1024];
    static StaticTask_t network_tcb;

    TaskHandle_t network_task_handle = xTaskCreateStatic(
        network_coordinator_task,
        "network_coord",
        1024,
        NULL,
        2,
        network_stack,
        &network_tcb
    );

    if (network_task_handle == NULL) {
        handle_task_creation_failure("network_coord");
    }

    /*
     * 10. Create the state monitor task.
     */
    static StackType_t monitor_stack[1024];
    static StaticTask_t monitor_tcb;

    TaskHandle_t monitor_task_handle = xTaskCreateStatic(
        state_monitor_task,
        "state_monitor",
        1024,
        NULL,
        1,
        monitor_stack,
        &monitor_tcb
    );

    if (monitor_task_handle == NULL) {
        handle_task_creation_failure("state_monitor");
    }

    /*
     * 11. Start the FreeRTOS scheduler.
     */
    vTaskStartScheduler();

    /*
     * Scheduler should never return.
     */
    for (;;) {
        /* System halted if scheduler exits unexpectedly. */
    }
}


/*
 * Shutdown/cleanup handler.
 */
void system_shutdown(void)
{
    /*
     * Disable task-level interrupts first.
     */
    taskDISABLE_INTERRUPTS();

    /*
     * Zeroize sensitive application state.
     */
    crypto_zeroize(
        &g_scratchpad,
        sizeof(union Global_Scratchpad)
    );

    stream_aggregator_zeroize_accumulator();

    crypto_zeroize(
        &g_client_contexts,
        sizeof(g_client_contexts)
    );

    /*
     * Reset DMA software state.
     *
     * This is a software reset/cleanup operation; actual hardware
     * peripheral shutdown will be handled in the DMA integration step.
     */
    dma_isr_init();

    /*
     * Suspend the scheduler and halt the system.
     */
    vTaskSuspendAll();

    for (;;) {
        __NOP();
    }
}


/*
 * Handle a FreeRTOS task creation failure.
 */
void handle_task_creation_failure(const char* task_name)
{
    (void)task_name;

    telemetry_record_error(ERR_HEAP_EXHAUSTED);

    system_shutdown();
}