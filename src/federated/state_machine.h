#ifndef STATE_MACHINE_H
#define STATE_MACHINE_H

#include "protocol_types.h"
#include <stdint.h>

pqc_status_t state_machine_init(client_protocol_ctx_t* ctx, uint8_t client_id, uint32_t round_id);
pqc_status_t state_machine_transition(client_protocol_ctx_t* ctx, protocol_state_t new_state);
pqc_status_t state_machine_process_message(client_protocol_ctx_t* ctx, const msg_header_t* hdr, const uint8_t* payload, uint16_t payload_len);
void protocol_register_context(client_protocol_ctx_t* ctx);
void protocol_check_timeouts(void);

#endif