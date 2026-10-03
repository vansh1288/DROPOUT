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
#include "dma_stream_bridge.h"
#include <string.h>

union Global_Scratchpad g_scratchpad;

/* Task stacks and TCBs */
static StackType_t network_stack[1024];
static StaticTask_t network_tcb;

static StackType_t monitor_stack[1024];
static StaticTask_t monitor_tcb;

static StackType_t crypto_stack[1024];
static StaticTask_t crypto_tcb;

static StackType_t stream_stack[1024];
static StaticTask_t stream_tcb;

/* Protocol context management */
static client_protocol_ctx_t g_client_contexts[MAX_CLIENTS] = {0};
static uint8_t g_num_contexts = 0;

/* Queues for inter-task communication */
#define NETWORK_QUEUE_LENGTH 16
#define NETWORK_QUEUE_ITEM_SIZE sizeof(network_msg_t)

static QueueHandle_t g_network_queue = NULL;
static uint8_t network_queue_storage[NETWORK_QUEUE_LENGTH * NETWORK_QUEUE_ITEM_SIZE];
static StaticQueue_t network_queue_struct;

/* Protocol context registration */
void protocol_register_context(client_protocol_ctx_t* ctx) {
    if (!ctx) return;
    for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
        if (g_client_contexts[i].client_id == 0 || g_client_contexts[i].client_id == ctx->client_id) {
            g_client_contexts[i] = *ctx;
            return;
        }
    }
}

/* Protocol timeout checking */
static void protocol_check_timeouts(void) {
    uint32_t current_tick = xTaskGetTickCount();
    for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
        if (g_client_contexts[i].client_id != 0 &&
            g_client_contexts[i].state != STATE_ROUND_COMPLETE &&
            g_client_contexts[i].state != STATE_ERROR) {
            if (current_tick - g_client_contexts[i].last_activity_tick > g_client_contexts[i].timeout_ms) {
                g_client_contexts[i].state = STATE_ERROR;
                /* Buffer cleanup on timeout */
                stream_aggregator_zeroize_accumulator();
            }
        }
    }
}

/* Network coordinator task - handles DMA transport polling */
static void network_coordinator_task(void* pvParameters) {
    while (1) {
        uint32_t notify = ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(10));
        if (notify & 0x01) {
            dma_transport_rx_poll();
        }
        if (notify & 0x02) {
            dma_transport_tx_poll();
        }
        
        /* Process network queue if any */
        network_msg_t msg;
        if (xQueueReceive(g_network_queue, &msg, 0) == pdTRUE) {
            /* Handle network messages if needed */
        }
    }
}

/* State monitor task - checks for protocol timeouts */
static void state_monitor_task(void* pvParameters) {
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(100));
        protocol_check_timeouts();
        
        /* Check for stuck buffers and clean up */
        for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
            if (g_client_contexts[i].client_id != 0 &&
                g_client_contexts[i].state != STATE_ROUND_COMPLETE &&
                g_client_contexts[i].state != STATE_ERROR) {
                uint32_t current_tick = xTaskGetTickCount();
                if (current_tick - g_client_contexts[i].last_activity_tick > 
                    pdMS_TO_TICKS(STATE_TIMEOUT_MS)) {
                    /* Force cleanup on stuck state */
                    g_client_contexts[i].state = STATE_ERROR;
                    stream_aggregator_zeroize_accumulator();
                }
            }
        }
    }
}

/* Network message structure for queue */
typedef struct {
    uint32_t round_id;
    uint8_t client_id;
    uint8_t message_type;
    uint16_t sequence_number;
    uint16_t payload_length;
    uint8_t payload[256];
} network_msg_t;

/* Network message queue send */
BaseType_t network_queue_send(const network_msg_t* msg, TickType_t timeout) {
    if (!g_network_queue) return pdFALSE;
    return xQueueSend(g_network_queue, msg, timeout);
}

/* Main application entry point */
void app_main(void) {
    BaseType_t ret;
    
    /* 1. Initialize scratchpad (must be first) */
    memset(&g_scratchpad, 0, sizeof(union Global_Scratchpad));
    
    /* 2. Initialize telemetry (early for logging) */
    telemetry_init();
    
    /* 3. Initialize DMA subsystem */
    dma_isr_init();
    dma_isr_set_stream_task(NULL);  /* Will be set after stream aggregator init */
    
    /* 4. Initialize crypto dependencies */
    ret = kem_adapter_init(KEMLIB_ML_KEM_768);
    if (ret != PQC_SUCCESS) {
        /* Fatal error - cannot proceed without crypto */
        while (1) { vTaskDelay(portMAX_DELAY); }
    }
    
    /* 5. Initialize crypto worker (depends on kem_adapter) */
    ret = crypto_worker_init();
    if (ret != pdPASS) {
        while (1) { vTaskDelay(portMAX_DELAY); }
    }
    
    /* 6. Initialize stream aggregator (depends on kem_adapter) */
    stream_aggregator_init();
    
    /* 7. Initialize DMA transport (depends on DMA ISR) */
    ret = dma_transport_init(-1, -1);  /* Sockets will be set later */
    if (ret != PQC_SUCCESS) {
        while (1) { vTaskDelay(portMAX_DELAY); }
    }
    
    /* 8. Initialize stream aggregator */
    stream_aggregator_init();
    
    /* 9. Initialize DMA stream bridge */
    dma_stream_bridge_init(stream_aggregator_get_dma_bridge(), 1000);
    
    /* 10. Initialize DMA ISR and connect to stream aggregator task */
    dma_isr_init();
    TaskHandle_t stream_task_handle = stream_aggregator_get_task_handle();
    dma_isr_set_stream_task(stream_task_handle);
    
    /* 11. Create network queue for inter-task communication */
    g_network_queue = xQueueCreateStatic(NETWORK_QUEUE_LENGTH, 
                                          NETWORK_QUEUE_ITEM_SIZE, 
                                          (uint8_t*)network_queue_storage, 
                                          &network_queue_struct);
    if (!g_network_queue) {
        while (1) { vTaskDelay(portMAX_DELAY); }
    }
    
    /* 12. Create tasks (priority order: crypto=3, stream=2, network=2, monitor=1) */
    
    /* Stream processor task (priority 2) */
    static StackType_t stream_stack[1024];
    static StaticTask_t stream_tcb;
    ret = xTaskCreateStatic(stream_aggregator_task, "stream_proc", 1024, NULL, 2, stream_stack, &stream_tcb);
    if (ret == NULL) { while (1) { vTaskDelay(portMAX_DELAY); } }
    
    /* Crypto worker task (priority 3) - highest for crypto ops */
    static StackType_t crypto_stack[1024];
    static StaticTask_t crypto_tcb;
    ret = xTaskCreateStatic(crypto_worker_task, "crypto_worker", 1024, NULL, 3, crypto_stack, &crypto_tcb);
    if (ret == NULL) { while (1) { vTaskDelay(portMAX_DELAY); } }
    
    /* Network coordinator task (priority 2) */
    static StackType_t network_stack[1024];
    static StaticTask_t network_tcb;
    ret = xTaskCreateStatic(network_coordinator_task, "network_coord", 1024, NULL, 2, network_stack, &network_tcb);
    if (ret == NULL) { while (1) { vTaskDelay(portMAX_DELAY); } }
    
    /* State monitor task (priority 1) */
    static StackType_t monitor_stack[1024];
    static StaticTask_t monitor_tcb;
    ret = xTaskCreateStatic(state_monitor_task, "state_monitor", 1024, NULL, 1, monitor_stack, &monitor_tcb);
    if (ret == NULL) { while (1) { vTaskDelay(portMAX_DELAY); } }
    
    /* 13. Set stream task handle for DMA ISR callbacks */
    TaskHandle_t stream_task_handle = stream_aggregator_get_task_handle();
    dma_isr_set_stream_task(stream_task_handle);
    
    /* 13. Initialize DMA transport (now that queues/tasks are ready) */
    dma_isr_init();
    
    /* 14. Initialize KEM adapter (after all deps are ready) */
    pqc_status_t ret = kem_adapter_init(KEMLIB_ML_KEM_768);
    if (ret != PQC_SUCCESS) {
        while (1) { vTaskDelay(portMAX_DELAY); }
    }
    
    /* 15. Initialize DMA transport */
    ret = dma_transport_init(-1, -1);
    if (ret != PQC_SUCCESS) {
        while (1) { vTaskDelay(portMAX_DELAY); }
    }
    
    /* 16. Initialize DMA stream bridge */
    dma_stream_bridge_init(stream_aggregator_get_dma_bridge(), 1000);
    
    /* 17. Start FreeRTOS scheduler */
    vTaskStartScheduler();
    
    /* Should never reach here */
    while (1);
}

/* Shutdown/cleanup handler - called on fatal error or shutdown */
void system_shutdown(void) {
    /* Disable interrupts */
    taskDISABLE_INTERRUPTS();
    
    /* Zeroize all sensitive buffers */
    crypto_zeroize(&g_scratchpad, sizeof(union Global_Scratchpad));
    stream_aggregator_zeroize_accumulator();
    crypto_zeroize(&g_client_contexts, sizeof(g_client_contexts));
    
    /* Disable DMA */
    dma_isr_init();  /* Re-init to reset DMA state */
    
    /* Suspend all tasks */
    vTaskSuspendAll();
    
    /* Infinite loop - system halted */
    while (1) {
        __NOP();
    }
}

/* Error handler for task creation failures */
void handle_task_creation_failure(const char* task_name) {
    telemetry_record_error(ERR_HEAP_EXHAUSTED);
    system_shutdown();
}

/* Buffer cleanup on timeout - called from state_monitor_task */
void protocol_check_timeouts(void) {
    uint32_t current_tick = xTaskGetTickCount();
    for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
        if (g_client_contexts[i].client_id != 0 &&
            g_client_contexts[i].state != STATE_ROUND_COMPLETE &&
            g_client_contexts[i].state != STATE_ERROR) {
            if (current_tick - g_client_contexts[i].last_activity_tick > 
                g_client_contexts[i].timeout_ms) {
                g_client_contexts[i].state = STATE_ERROR;
                /* Cleanup buffers on timeout */
                stream_aggregator_zeroize_accumulator();
            }
        }
    }
}

/* Protocol context registration */
void protocol_register_context(client_protocol_ctx_t* ctx) {
    if (!ctx) return;
    for (uint8_t i = 0; i < MAX_CLIENTS; i++) {
        if (g_client_contexts[i].client_id == 0 || 
            g_client_contexts[i].client_id == ctx->client_id) {
            g_client_contexts[i] = *ctx;
            return;
        }
    }
}

#endif