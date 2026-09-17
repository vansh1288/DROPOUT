#include "FreeRTOS.h"
#include "task.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include <string.h>

union Global_Scratchpad g_scratchpad;

static StackType_t crypto_stack[1024];
static StaticTask_t crypto_tcb;

static StackType_t stream_stack[1024];
static StaticTask_t stream_tcb;

static StackType_t network_stack[1024];
static StaticTask_t network_tcb;

static StackType_t monitor_stack[1024];
static StaticTask_t monitor_tcb;

static void crypto_worker_task(void* pvParameters) {
    while (1) {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    }
}

static void stream_aggregator_task(void* pvParameters) {
    while (1) {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    }
}

static void network_coordinator_task(void* pvParameters) {
    while (1) {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
    }
}

static void state_monitor_task(void* pvParameters) {
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }
}

void app_main(void) {
    memset(&g_scratchpad, 0, sizeof(union Global_Scratchpad));

    xTaskCreateStatic(crypto_worker_task, "crypto_worker", 1024, NULL, 3, crypto_stack, &crypto_tcb);
    xTaskCreateStatic(stream_aggregator_task, "stream_aggregator", 1024, NULL, 2, stream_stack, &stream_tcb);
    xTaskCreateStatic(network_coordinator_task, "network_coordinator", 1024, NULL, 2, network_stack, &network_tcb);
    xTaskCreateStatic(state_monitor_task, "state_monitor", 1024, NULL, 1, monitor_stack, &monitor_tcb);

    dma_isr_set_stream_task(stream_tcb);
    dma_isr_init();
    kem_adapter_init(KEMLIB_ML_KEM_768);

    vTaskStartScheduler();

    while (1);
}