#include "freertos_mock.h"
#include <stdio.h>

static uint32_t g_tick_count = 0;
static TaskHandle_t g_notify_task = NULL;
static uint32_t g_notify_value = 0;

void vTaskDelay(uint32_t ticks) {
    g_tick_count += ticks;
}

BaseType_t xTaskCreate(void* task_func, const char* name, uint32_t stack_depth, void* params, UBaseType_t priority, TaskHandle_t* handle) {
    *handle = (TaskHandle_t)0x1234;
    return pdPASS;
}

void vTaskDelete(TaskHandle_t task) {
    (void)task;
}

TaskHandle_t xTaskGetCurrentTaskHandle(void) {
    return (TaskHandle_t)0x1234;
}

uint32_t xTaskGetTickCount(void) {
    return g_tick_count;
}

uint32_t xTaskGetTickCountFromISR(void) {
    return g_tick_count;
}

BaseType_t xTaskNotifyFromISR(TaskHandle_t task, uint32_t value, eNotifyAction action, BaseType_t* higher_priority_task_woken) {
    (void)task;
    (void)action;
    g_notify_value |= value;
    if (higher_priority_task_woken) *higher_priority_task_woken = pdFALSE;
    return pdTRUE;
}

uint32_t ulTaskNotifyTake(BaseType_t clear_on_exit, uint32_t ticks_to_wait) {
    (void)clear_on_exit;
    (void)ticks_to_wait;
    uint32_t val = g_notify_value;
    g_notify_value = 0;
    return val;
}

void portYIELD_FROM_ISR(BaseType_t xHigherPriorityTaskWoken) {
    (void)xHigherPriorityTaskWoken;
}

QueueHandle_t xQueueCreate(UBaseType_t length, UBaseType_t item_size) {
    return (QueueHandle_t)0x5678;
}

QueueHandle_t xQueueCreateStatic(UBaseType_t length, UBaseType_t item_size, uint8_t* buffer, StaticQueue_t* queue) {
    (void)length; (void)item_size; (void)buffer; (void)queue;
    return (QueueHandle_t)0x5678;
}

BaseType_t xQueueSend(QueueHandle_t queue, const void* item, uint32_t timeout) {
    (void)queue; (void)item; (void)timeout;
    return pdTRUE;
}

BaseType_t xQueueReceive(QueueHandle_t queue, void* item, uint32_t timeout) {
    (void)queue; (void)item; (void)timeout;
    return pdFALSE;
}

BaseType_t xQueueSendFromISR(QueueHandle_t queue, const void* item, BaseType_t* higher_priority_task_woken) {
    (void)queue; (void)item;
    if (higher_priority_task_woken) *higher_priority_task_woken = pdFALSE;
    return pdTRUE;
}

BaseType_t xQueueReceiveFromISR(QueueHandle_t queue, void* item, BaseType_t* higher_priority_task_woken) {
    (void)queue; (void)item;
    if (higher_priority_task_woken) *higher_priority_task_woken = pdFALSE;
    return pdFALSE;
}

SemaphoreHandle_t xSemaphoreCreateBinary(void) {
    return (SemaphoreHandle_t)0x9ABC;
}

SemaphoreHandle_t xSemaphoreCreateMutex(void) {
    return (SemaphoreHandle_t)0x9ABC;
}

SemaphoreHandle_t xSemaphoreCreateCounting(UBaseType_t max_count, UBaseType_t initial_count) {
    (void)max_count; (void)initial_count;
    return (SemaphoreHandle_t)0x9ABC;
}

BaseType_t xSemaphoreTake(SemaphoreHandle_t semaphore, uint32_t timeout) {
    (void)semaphore; (void)timeout;
    return pdTRUE;
}

BaseType_t xSemaphoreGive(SemaphoreHandle_t semaphore) {
    (void)semaphore;
    return pdTRUE;
}

BaseType_t xSemaphoreGiveFromISR(SemaphoreHandle_t semaphore, BaseType_t* higher_priority_task_woken) {
    (void)semaphore;
    if (higher_priority_task_woken) *higher_priority_task_woken = pdFALSE;
    return pdTRUE;
}

TimerHandle_t xTimerCreate(const char* name, uint32_t period, BaseType_t auto_reload, void* id, void* callback) {
    (void)name; (void)period; (void)auto_reload; (void)id; (void)callback;
    return (TimerHandle_t)0xDEF0;
}

BaseType_t xTimerStart(TimerHandle_t timer, uint32_t timeout) {
    (void)timer; (void)timeout;
    return pdTRUE;
}