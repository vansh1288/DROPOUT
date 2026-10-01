#ifndef CRYPTO_WORKER_H
#define CRYPTO_WORKER_H

#include "protocol_types.h"
#include "FreeRTOS.h"
#include <stdint.h>

typedef enum {
    CRYPTO_OP_NONE = 0,
    CRYPTO_OP_KEYPAIR = 1,
    CRYPTO_OP_ENCAPSULATE = 2,
    CRYPTO_OP_DECAPSULATE = 3,
    CRYPTO_OP_HKDF = 4
} crypto_op_t;

typedef struct {
    crypto_op_t op;
    kem_keypair_t* keypair_out;
    const uint8_t* public_key;
    size_t pk_len;
    kem_encapsulation_t* encap_out;
    const uint8_t* ciphertext;
    size_t ct_len;
    const uint8_t* secret_key;
    size_t sk_len;
    uint8_t* shared_secret_out;
    const uint8_t* shared_secret_in;
    const uint8_t* salt;
    size_t salt_len;
    const uint8_t* info;
    size_t info_len;
    uint8_t* session_key_out;
    BaseType_t* done_flag;
} crypto_work_item_t;

void crypto_worker_init(void);
BaseType_t crypto_worker_submit(const crypto_work_item_t* item, TickType_t timeout);

#endif
