#ifndef PROTOCOL_TYPES_H
#define PROTOCOL_TYPES_H

#include <stdint.h>
#include <stddef.h>

#define PROTOCOL_VERSION_MAJOR    1u
#define PROTOCOL_VERSION_MINOR    0u
#define PROTOCOL_VERSION_PATCH    0u
#define PROTOCOL_VERSION          ((PROTOCOL_VERSION_MAJOR << 16) | (PROTOCOL_VERSION_MINOR << 8) | PROTOCOL_VERSION_PATCH)

#define MAX_CLIENT_ID             0xFFu
#define MAX_ROUND_ID              0xFFFFFFFFu
#define MAX_CHUNK_SIZE            1024u
#define MIN_CHUNK_SIZE            64u
#define DEFAULT_CHUNK_SIZE        128u

#define ML_KEM_512_PUBLIC_KEY_BYTES   800u
#define ML_KEM_512_SECRET_KEY_BYTES   1632u
#define ML_KEM_512_CIPHERTEXT_BYTES   768u
#define ML_KEM_512_SHARED_SECRET_BYTES 32u

#define ML_KEM_768_PUBLIC_KEY_BYTES   1184u
#define ML_KEM_768_SECRET_KEY_BYTES   2400u
#define ML_KEM_768_CIPHERTEXT_BYTES   1088u
#define ML_KEM_768_SHARED_SECRET_BYTES 32u

#define ML_KEM_1024_PUBLIC_KEY_BYTES  1568u
#define ML_KEM_1024_SECRET_KEY_BYTES  3168u
#define ML_KEM_1024_CIPHERTEXT_BYTES  1568u
#define ML_KEM_1024_SHARED_SECRET_BYTES 32u

#define SHA256_DIGEST_BYTES       32u
#define AES256_KEY_BYTES          32u
#define AES256_IV_BYTES           16u
#define NONCE_BYTES               12u
#define AUTH_TAG_BYTES            16u

#define SHAMIR_MAX_SHARES         255u
#define SHAMIR_MAX_THRESHOLD      255u
#define SHAMIR_SHARE_ID_BYTES     1u
#define SHAMIR_SHARE_VALUE_BYTES  32u

#define MAX_MODEL_NAME_LEN        32u
#define MAX_FIRMWARE_VERSION_LEN  16u

#define MAX_PEERS_PER_CLIENT      16u

typedef enum {
    MSG_TYPE_KEM_PUBLIC_KEY     = 0x01,
    MSG_TYPE_KEM_CIPHERTEXT     = 0x02,
    MSG_TYPE_KEM_SHARED_SECRET  = 0x03,
    MSG_TYPE_PAIRWISE_INIT      = 0x10,
    MSG_TYPE_PAIRWISE_PUBKEY    = 0x11,
    MSG_TYPE_PAIRWISE_CIPHERTEXT = 0x12,
    MSG_TYPE_PAIRWISE_CONFIRM   = 0x13,
    MSG_TYPE_MASK_SEED          = 0x20,
    MSG_TYPE_MASK_CHUNK         = 0x21,
    MSG_TYPE_MASK_ACK           = 0x22,
    MSG_TYPE_CLIENT_COMPLETE    = 0x30,
    MSG_TYPE_DROPOUT_NOTIFY     = 0x31,
    MSG_TYPE_SHAMIR_SHARE       = 0x32,
    MSG_TYPE_RECOVERY_COMPLETE  = 0x33,
    MSG_TYPE_ROUND_INIT         = 0x40,
    MSG_TYPE_ROUND_COMPLETE     = 0x41,
    MSG_TYPE_ERROR              = 0xFF,
} msg_type_t;

typedef enum {
    STATE_ROUND_INIT        = 0x00,
    STATE_KEY_SETUP         = 0x01,
    STATE_MASK_SETUP        = 0x02,
    STATE_LOCAL_TRAINING    = 0x03,
    STATE_MASKED_UPDATE_STREAM = 0x04,
    STATE_CLIENT_COMPLETION = 0x05,
    STATE_AGGREGATION       = 0x06,
    STATE_DROPOUT_DETECTION = 0x07,
    STATE_MASK_RECOVERY     = 0x08,
    STATE_UNMASK            = 0x09,
    STATE_FEDAVG            = 0x0A,
    STATE_ROUND_COMPLETE    = 0x0B,
    STATE_ERROR             = 0xFF,
} protocol_state_t;

typedef enum {
    PQC_SUCCESS                 = 0,
    ERR_GENERIC                 = -1,
    ERR_INVALID_ARGUMENT        = -2,
    ERR_BUFFER_TOO_SMALL        = -3,
    ERR_INVALID_STATE           = -4,
    ERR_CRYPTO_FAILURE          = -5,
    ERR_AUTH_FAILED             = -6,
    ERR_REPLAY_DETECTED         = -7,
    ERR_SEQUENCE_MISMATCH       = -8,
    ERR_ROUND_MISMATCH          = -9,
    ERR_CLIENT_ID_MISMATCH      = -10,
    ERR_DMA_TIMEOUT             = -11,
    ERR_DMA_BUSY                = -12,
    ERR_NTT_FAILURE             = -13,
    ERR_KEM_KEYGEN_FAILED       = -14,
    ERR_KEM_ENCAP_FAILED        = -15,
    ERR_KEM_DECAP_FAILED        = -16,
    ERR_KDF_FAILED              = -17,
    ERR_PRG_FAILED              = -18,
    ERR_SHAMIR_ENCODE_FAILED    = -19,
    ERR_SHAMIR_DECODE_FAILED    = -20,
    ERR_INSUFFICIENT_SHARES     = -21,
    ERR_DUPLICATE_SHARE_ID      = -22,
    ERR_INVALID_THRESHOLD       = -23,
    ERR_CHUNK_TOO_LARGE         = -24,
    ERR_CHUNK_TOO_SMALL         = -25,
    ERR_MODEL_SIZE_MISMATCH     = -26,
    ERR_NETWORK_TIMEOUT         = -27,
    ERR_PACKET_FRAGMENTED       = -28,
    ERR_MTU_EXCEEDED            = -29,
    ERR_HEAP_EXHAUSTED          = -30,
    ERR_STACK_OVERFLOW          = -31,
} pqc_status_t;

typedef struct {
    uint32_t protocol_version;
    uint32_t round_id;
    uint8_t  client_id;
    uint8_t  message_type;
    uint16_t sequence_number;
    uint16_t payload_length;
    uint16_t reserved;
} msg_header_t;

#define COMPILE_TIME_ASSERT(cond, msg) typedef char assert_##msg[(cond) ? 1 : -1]
COMPILE_TIME_ASSERT(sizeof(msg_header_t) == 16, msg_header_t_must_be_16_bytes);

typedef enum {
    KEMLIB_ML_KEM_512  = 0,
    KEMLIB_ML_KEM_768  = 1,
    KEMLIB_ML_KEM_1024 = 2,
} kem_variant_t;

typedef struct {
    kem_variant_t variant;
    uint8_t public_key[ML_KEM_1024_PUBLIC_KEY_BYTES];
    uint8_t secret_key[ML_KEM_1024_SECRET_KEY_BYTES];
    size_t  public_key_len;
    size_t  secret_key_len;
    size_t  ciphertext_len;
    size_t  shared_secret_len;
} kem_keypair_t;

typedef struct {
    uint8_t ciphertext[ML_KEM_1024_CIPHERTEXT_BYTES];
    uint8_t shared_secret[ML_KEM_1024_SHARED_SECRET_BYTES];
    size_t  ciphertext_len;
    size_t  shared_secret_len;
} kem_encapsulation_t;

typedef struct {
    uint8_t peer_client_id;
    uint8_t shared_secret[ML_KEM_1024_SHARED_SECRET_BYTES];
    uint8_t mask_seed[SHA256_DIGEST_BYTES];
    int     is_initiator;
} pairwise_secret_t;

typedef struct {
    uint8_t num_peers;
    pairwise_secret_t peers[MAX_PEERS_PER_CLIENT];
} pairwise_context_t;

typedef struct {
    uint8_t share_id;
    uint8_t value[SHAMIR_SHARE_VALUE_BYTES];
} shamir_share_t;

typedef struct {
    uint8_t threshold;
    uint8_t num_shares;
    shamir_share_t shares[SHAMIR_MAX_SHARES];
    uint8_t secret[SHAMIR_SHARE_VALUE_BYTES];
} shamir_context_t;

typedef struct {
    uint32_t round_id;
    uint8_t  client_id;
    uint16_t chunk_index;
    uint16_t total_chunks;
    uint16_t chunk_size;
    uint32_t model_total_bytes;
    uint32_t bytes_processed;
    uint8_t  is_final_chunk;
} chunk_context_t;

typedef struct {
    uint8_t client_id;
    protocol_state_t state;
    uint32_t current_round_id;
    kem_keypair_t kem_kp;
    pairwise_context_t pairwise_ctx;
    chunk_context_t chunk_ctx;
    shamir_context_t shamir_ctx;
    uint8_t session_key[AES256_KEY_BYTES];
    uint32_t timeout_ms;
    uint32_t last_activity_tick;
} client_protocol_ctx_t;

typedef struct {
    uint32_t round_id;
    uint8_t expected_clients;
    uint8_t threshold;
    protocol_state_t state;
    uint32_t round_start_tick;
    uint32_t dropout_timeout_ms;
} server_protocol_ctx_t;

typedef struct {
    uint16_t mtu_bytes;
    uint32_t rx_timeout_ms;
    uint32_t tx_timeout_ms;
    uint8_t  enable_fragmentation;
    uint16_t max_fragment_size;
} transport_config_t;

#define MIN(a, b)  (((a) < (b)) ? (a) : (b))
#define MAX(a, b)  (((a) > (b)) ? (a) : (b))
#define ARRAY_SIZE(arr)  (sizeof(arr) / sizeof((arr)[0]))

static inline uint16_t htole16(uint16_t x) { return x; }
static inline uint32_t htole32(uint32_t x) { return x; }
static inline uint16_t le16toh(uint16_t x) { return x; }
static inline uint32_t le32toh(uint32_t x) { return x; }

#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#undef htole16
#undef htole32
#undef le16toh
#undef le32toh
static inline uint16_t htole16(uint16_t x) { return __builtin_bswap16(x); }
static inline uint32_t htole32(uint32_t x) { return __builtin_bswap32(x); }
static inline uint16_t le16toh(uint16_t x) { return __builtin_bswap16(x); }
static inline uint32_t le32toh(uint32_t x) { return __builtin_bswap32(x); }
#endif

#endif