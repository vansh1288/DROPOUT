#ifndef FREERTOS_MOCK_H
#define FREERTOS_MOCK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef long BaseType_t;
typedef unsigned long UBaseType_t;
typedef void* TaskHandle_t;
typedef void* QueueHandle_t;
typedef void* SemaphoreHandle_t;
typedef void* TimerHandle_t;
typedef void* StaticQueue_t;
typedef void* StaticTask_t;
typedef void* StackType_t;

#define pdFALSE ((BaseType_t)0)
#define pdTRUE ((BaseType_t)1)
#define pdPASS (pdTRUE)
#define pdFAIL (pdFALSE)
#define portMAX_DELAY 0xFFFFFFFF

typedef enum {
    eSetBits = 0,
    eIncrement = 1,
    eSetValueWithOverwrite = 2,
    eSetValueWithoutOverwrite = 3
} eNotifyAction;

#define pdMS_TO_TICKS(x) ((x) * 1000 / 1000)

#define configUSE_MUTEXES 1
#define configUSE_RECURSIVE_MUTEXES 1
#define configUSE_COUNTING_SEMAPHORES 1

void vTaskDelay(uint32_t ticks);
BaseType_t xTaskCreate(void* task_func, const char* name, uint32_t stack_depth, void* params, UBaseType_t priority, TaskHandle_t* handle);
void vTaskDelete(TaskHandle_t task);
TaskHandle_t xTaskGetCurrentTaskHandle(void);
uint32_t xTaskGetTickCount(void);
uint32_t xTaskGetTickCountFromISR(void);
BaseType_t xTaskNotifyFromISR(TaskHandle_t task, uint32_t value, eNotifyAction action, BaseType_t* higher_priority_task_woken);
uint32_t ulTaskNotifyTake(BaseType_t clear_on_exit, uint32_t ticks_to_wait);
void portYIELD_FROM_ISR(BaseType_t xHigherPriorityTaskWoken);

QueueHandle_t xQueueCreate(UBaseType_t length, UBaseType_t item_size);
QueueHandle_t xQueueCreateStatic(UBaseType_t length, UBaseType_t item_size, uint8_t* buffer, StaticQueue_t* queue);
BaseType_t xQueueSend(QueueHandle_t queue, const void* item, uint32_t timeout);
BaseType_t xQueueReceive(QueueHandle_t queue, void* item, uint32_t timeout);
BaseType_t xQueueSendFromISR(QueueHandle_t queue, const void* item, BaseType_t* higher_priority_task_woken);
BaseType_t xQueueReceiveFromISR(QueueHandle_t queue, void* item, BaseType_t* higher_priority_task_woken);

SemaphoreHandle_t xSemaphoreCreateBinary(void);
SemaphoreHandle_t xSemaphoreCreateMutex(void);
SemaphoreHandle_t xSemaphoreCreateCounting(UBaseType_t max_count, UBaseType_t initial_count);
BaseType_t xSemaphoreTake(SemaphoreHandle_t semaphore, uint32_t timeout);
BaseType_t xSemaphoreGive(SemaphoreHandle_t semaphore);
BaseType_t xSemaphoreGiveFromISR(SemaphoreHandle_t semaphore, BaseType_t* higher_priority_task_woken);

TimerHandle_t xTimerCreate(const char* name, uint32_t period, BaseType_t auto_reload, void* id, void* callback);
BaseType_t xTimerStart(TimerHandle_t timer, uint32_t timeout);

#define taskENTER_CRITICAL()
#define taskEXIT_CRITICAL()

#define portYIELD() 

#ifdef __cplusplus
}
#endif

#endif