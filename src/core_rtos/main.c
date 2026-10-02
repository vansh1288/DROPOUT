
#include "FreeRTOS.h"
#include "task.h"

#include "memory_scratchpad.h"
#include "protocol_types.h"
#include "kem_adapter.h"
#include "stream_aggregator.h"
#include "crypto_worker.h"
#include "dma_transport.h"
#include "state_machine.h"
#include "telemetry.h"
#include "dma_isr_handler.h"

#include <string.h>
#include <stdint.h>

#define NETWORK_STACK_SIZE       1024U
#define MONITOR_STACK_SIZE       1024U

#define NETWORK_TASK_PRIORITY    2U
#define MONITOR_TASK_PRIORITY    1U

#define DMA_NOTIFY_RX            0x01U
#define DMA_NOTIFY_TX            0x02U
#define DMA_NOTIFY_ERROR         0x80U

#define PROTOCOL_MAX_CONTEXTS    16U
#define PROTOCOL_MONITOR_PERIOD  100U

union Global_Scratchpad g_scratchpad;

static StackType_t network_stack[NETWORK_STACK_SIZE];
static StaticTask_t network_tcb;

static StackType_t monitor_stack[MONITOR_STACK_SIZE];
static StaticTask_t monitor_tcb;

/* Protocol context registration */
static client_protocol_ctx_t *g_client_contexts = NULL;
static uint8_t g_num_contexts = 0U;

/*
 * Network coordinator task.
 *
 * Handles notifications from the DMA ISR and delegates
 * transport processing to the task-context transport functions.
 *
 * Note: the transport polling functions must not invoke ISR-only
 * APIs. Actual hardware DMA completion must be signaled by the
 * target-specific DMA interrupt handler.
 */
static void network_coordinator_task(void *pvParameters)
{
    uint32_t notify = 0U;

    (void)pvParameters;

    for (;;) {
        BaseType_t notified = xTaskNotifyWait(
            0U,
            UINT32_MAX,
            &notify,
            portMAX_DELAY
        );

        if (notified != pdTRUE) {
            continue;
        }

        if ((notify & DMA_NOTIFY_ERROR) != 0U) {
            /*
             * TODO:
             * Implement target-specific DMA error recovery:
             * - Stop or reset the affected DMA channel.
             * - Record/report the error through telemetry.
             * - Restore buffer and transport state.
             * - Restart the operation when safe.
             */
        }

        if ((notify & DMA_NOTIFY_RX) != 0U) {
            /*
             * Task-context transport processing.
             * Check and handle the returned status when the
             * transport error policy is defined.
             */
            (void)dma_transport_rx_poll();
        }

        if ((notify & DMA_NOTIFY_TX) != 0U) {
            (void)dma_transport_tx_poll();
        }

        notify = 0U;
    }
}

/*
 * Register a protocol context.
 *
 * This implementation currently stores one context. Supporting
 * multiple contexts requires an actual context collection and
 * corresponding iteration in the timeout monitor.
 */
void protocol_register_context(client_protocol_ctx_t *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (g_client_contexts == NULL &&
        g_num_contexts < PROTOCOL_MAX_CONTEXTS) {
        g_client_contexts = ctx;
        g_num_contexts = 1U;
    }
}

/* Protocol timeout monitoring */
static void protocol_check_timeouts(void)
{
    if (g_client_contexts == NULL) {
        return;
    }

    uint32_t current_tick = (uint32_t)xTaskGetTickCount();

    uint32_t timeout_ticks = (uint32_t)pdMS_TO_TICKS(
        g_client_contexts->timeout_ms
    );

    uint32_t elapsed_ticks =
        current_tick - g_client_contexts->last_activity_tick;

    if (elapsed_ticks > timeout_ticks) {
        g_client_contexts->state = STATE_ERROR;
    }
}

/* State monitor task */
static void state_monitor_task(void *pvParameters)
{
    (void)pvParameters;

    for (;;) {
        vTaskDelay(pdMS_TO_TICKS(PROTOCOL_MONITOR_PERIOD));
        protocol_check_timeouts();
    }
}

/* Application entry point */
void app_main(void)
{
    TaskHandle_t network_task_handle;
    TaskHandle_t monitor_task_handle;

    /* Initialize global scratchpad */
    memset(&g_scratchpad, 0, sizeof(g_scratchpad));

    /* Reset protocol context registration */
    g_client_contexts = NULL;
    g_num_contexts = 0U;

    /* Initialize telemetry */
    telemetry_init();

    /*
     * Initialize DMA state and buffers before registering
     * the network task as the ISR notification target.
     */
    dma_isr_init();

    /* Initialize cryptographic components */
    kem_adapter_init(KEMLIB_ML_KEM_768);
    crypto_worker_init();

    /* Initialize stream aggregator */
    stream_aggregator_init();

    /*
     * Create network coordinator task.
     * Stack size is specified in StackType_t elements.
     */
    network_task_handle = xTaskCreateStatic(
        network_coordinator_task,
        "network_coordinator",
        NETWORK_STACK_SIZE,
        NULL,
        NETWORK_TASK_PRIORITY,
        network_stack,
        &network_tcb
    );

    if (network_task_handle == NULL) {
        return;
    }

    /* Register coordinator as the DMA ISR notification target */
    dma_isr_set_network_task(network_task_handle);

    /* Create state monitor task */
    monitor_task_handle = xTaskCreateStatic(
        state_monitor_task,
        "state_monitor",
        MONITOR_STACK_SIZE,
        NULL,
        MONITOR_TASK_PRIORITY,
        monitor_stack,
        &monitor_tcb
    );

    if (monitor_task_handle == NULL) {
        /*
         * Startup is incomplete. Do not start the scheduler
         * with only a subset of required application tasks.
         */
        return;
    }

    /* Start FreeRTOS scheduler */
    vTaskStartScheduler();

    /* Reached only if scheduler startup fails */
    for (;;) {
    }
}