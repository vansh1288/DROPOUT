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

union Global_Scratchpad g_scratchpad;

static StackType_t network_stack[1024];
static StaticTask_t network_tcb;

static StackType_t monitor_stack[1024];
static StaticTask_t monitor_tcb;

static void network_coordinator_task(void* pvParameters) {
    while (1) {
        uint32_t notify = ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        if (notify & 0x01) {
            dma_transport_rx_poll();
        }
        if (notify & 0x02) {
            dma_transport_tx_poll();
        }
    }
}

static client_protocol_ctx_t* g_client_contexts = NULL;
static uint8_t g_num_contexts = 0;

void protocol_register_context(client_protocol_ctx_t* ctx) {
    if (g_num_contexts < 16) {
        g_client_contexts = ctx;
        g_num_contexts = 1;
    }
}

static void protocol_check_timeouts(void) {
    if (g_client_contexts) {
        uint32_t current_tick = xTaskGetTickCount();
        if (current_tick - g_client_contexts->last_activity_tick > g_client_contexts->timeout_ms) {
            g_client_contexts->state = STATE_ERROR;
        }
    }
}

static void state_monitor_task(void* pvParameters) {
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(100));
        protocol_check_timeouts();
    }
}

void app_main(void) {
    memset(&g_scratchpad, 0, sizeof(union Global_Scratchpad));

    telemetry_init();

    crypto_worker_init();
    stream_aggregator_init();

    TaskHandle_t stream_task_handle = stream_aggregator_get_task_handle();
    dma_isr_set_stream_task(stream_task_handle);

    xTaskCreateStatic(network_coordinator_task, "network_coordinator", 1024, NULL, 2, network_stack, &network_tcb);
    xTaskCreateStatic(state_monitor_task, "state_monitor", 1024, NULL, 1, monitor_stack, &monitor_tcb);

    dma_isr_init();
    kem_adapter_init(KEMLIB_ML_KEM_768);

    vTaskStartScheduler();

    while (1);
}
