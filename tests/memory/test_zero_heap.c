#include "FreeRTOS.h"
#include "task.h"
#include "memory_scratchpad.h"
#include "protocol_types.h"
#include <stdint.h>
#include <stddef.h>

#define SAFE_STACK_WATERMARK 128
#define HEAP_SAMPLE_COUNT 1000

static size_t g_initial_free_heap = 0;
static size_t g_max_heap_delta = 0;
static uint16_t g_min_stack_watermark = 0xFFFF;

static void check_heap_invariant(void) {
    size_t current = xPortGetFreeHeapSize();
    if (g_initial_free_heap == 0) {
        g_initial_free_heap = current;
    }
    size_t delta = (current > g_initial_free_heap) ? current - g_initial_free_heap : g_initial_free_heap - current;
    if (delta > g_max_heap_delta) {
        g_max_heap_delta = delta;
    }
}

static void check_stack_invariant(void) {
    TaskHandle_t tasks[4] = {
        xTaskGetHandle("crypto_worker"),
        xTaskGetHandle("stream_aggregator"),
        xTaskGetHandle("network_coordinator"),
        xTaskGetHandle("state_monitor")
    };
    for (int i = 0; i < 4; i++) {
        if (tasks[i] != NULL) {
            uint16_t hwm = uxTaskGetStackHighWaterMark(tasks[i]);
            if (hwm < g_min_stack_watermark) {
                g_min_stack_watermark = hwm;
            }
        }
    }
}

void test_zero_heap_setup(void) {
    g_initial_free_heap = xPortGetFreeHeapSize();
    g_max_heap_delta = 0;
    g_min_stack_watermark = 0xFFFF;
}

pqc_status_t test_zero_heap_during_streaming(void) {
    check_heap_invariant();
    check_stack_invariant();
    
    if (g_max_heap_delta > 0) {
        return ERR_HEAP_EXHAUSTED;
    }
    
    if (g_min_stack_watermark < SAFE_STACK_WATERMARK) {
        return ERR_STACK_OVERFLOW;
    }
    
    return PQC_SUCCESS;
}

void test_zero_heap_report(uint32_t* max_heap_delta, uint16_t* min_stack_watermark) {
    *max_heap_delta = g_max_heap_delta;
    *min_stack_watermark = g_min_stack_watermark;
}

void vApplicationMallocFailedHook(void) {
    while (1);
}

void vApplicationStackOverflowHook(TaskHandle_t xTask, char* pcTaskName) {
    (void)xTask;
    (void)pcTaskName;
    while (1);
}

void vApplicationIdleHook(void) {
    check_heap_invariant();
    check_stack_invariant();
}