# PQC Engine Public API Reference

**Branch:** `feature/member-1-crypto`  
**Directory:** `src/pqc_engine/`

---

## Table of Contents

1. [Return Codes](#return-codes)
2. [ML-KEM Buffer Sizes](#ml-kem-buffer-sizes)
3. [Shamir Secret Sharing (`shamir.h`)](#shamir-secret-sharing-shamirh)
4. [Random Bytes (`randombytes.h`)](#random-bytes-randombytesh)
5. [Mask PRG (`mask_prg.h`)](#mask-prg-mask_prgh)
6. [KEM Adapter (`kem_adapter.h`)](#kem-adapter-kem_adapterh)
7. [HKDF (`hkdf.h`)](#hkdf-hkdfh)
8. [Crypto Memory (`crypto_memory.h`)](#crypto-memory-crypto_memoryh)
9. [Memory Ownership & Cleanup Rules](#memory-ownership--cleanup-rules)

---

## Return Codes

All functions return `pqc_status_t` (defined in `protocol_types.h`):

| Code | Value | Description |
|------|-------|-------------|
| `PQC_SUCCESS` | 0 | Operation successful |
| `ERR_GENERIC` | -1 | Generic failure |
| `ERR_INVALID_ARGUMENT` | -2 | Invalid argument (NULL pointer, wrong size, etc.) |
| `ERR_BUFFER_TOO_SMALL` | -3 | Output buffer too small |
| `ERR_INVALID_STATE` | -4 | Invalid state for operation |
| `ERR_CRYPTO_FAILURE` | -5 | Cryptographic operation failed |
| `ERR_AUTH_FAILED` | -6 | Authentication failed |
| `ERR_REPLAY_DETECTED` | -7 | Replay attack detected |
| `ERR_SEQUENCE_MISMATCH` | -8 | Sequence number mismatch |
| `ERR_ROUND_MISMATCH` | -9 | Round ID mismatch |
| `ERR_CLIENT_ID_MISMATCH` | -10 | Client ID mismatch |
| `ERR_DMA_TIMEOUT` | -11 | DMA transfer timeout |
| `ERR_DMA_BUSY` | -12 | DMA busy |
| `ERR_NTT_FAILURE` | -13 | NTT operation failed |
| `ERR_KEM_KEYGEN_FAILED` | -14 | KEM key generation failed |
| `ERR_KEM_ENCAP_FAILED` | -15 | KEM encapsulation failed |
| `ERR_KEM_DECAP_FAILED` | -16 | KEM decapsulation failed |
| `ERR_KDF_FAILED` | -17 | Key derivation failed |
| `ERR_PRG_FAILED` | -18 | PRG generation failed |
| `ERR_SHAMIR_ENCODE_FAILED` | -19 | Shamir sharing failed |
| `ERR_SHAMIR_DECODE_FAILED` | -20 | Shamir reconstruction failed |
| `ERR_INSUFFICIENT_SHARES` | -21 | Not enough shares for reconstruction |
| `ERR_DUPLICATE_SHARE_ID` | -22 | Duplicate share ID |
| `ERR_INVALID_THRESHOLD` | -23 | Invalid threshold (t > n or t == 0) |
| `ERR_CHUNK_TOO_LARGE` | -24 | Chunk exceeds MAX_CHUNK_SIZE |
| `ERR_CHUNK_TOO_SMALL` | -25 | Chunk below MIN_CHUNK_SIZE |
| `ERR_MODEL_SIZE_MISMATCH` | -26 | Model size mismatch |
| `ERR_NETWORK_TIMEOUT` | -27 | Network timeout |
| `ERR_PACKET_FRAGMENTED` | -28 | Packet fragmented |
| `ERR_MTU_EXCEEDED` | -29 | MTU exceeded |
| `ERR_HEAP_EXHAUSTED` | -30 | Heap exhausted |
| `ERR_STACK_OVERFLOW` | -31 | Stack overflow |

---

## ML-KEM Buffer Sizes

Defined in `protocol_types.h`:

| Variant | Public Key | Secret Key | Ciphertext | Shared Secret |
|---------|------------|------------|------------|---------------|
| ML-KEM-512 | 800 bytes | 1632 bytes | 768 bytes | 32 bytes |
| ML-KEM-768 | 1184 bytes | 2400 bytes | 1088 bytes | 32 bytes |
| ML-KEM-1024 | 1568 bytes | 3168 bytes | 1568 bytes | 32 bytes |

**Maximum sizes** (used for stack allocation in `kem_adapter.h`):
- `KEM_ADAPTER_MAX_PK_BYTES` = 1568 (ML-KEM-1024)
- `KEM_ADAPTER_MAX_SK_BYTES` = 3168 (ML-KEM-1024)
- `KEM_ADAPTER_MAX_CT_BYTES` = 1568 (ML-KEM-1024)
- `KEM_ADAPTER_SS_BYTES` = 32 (all variants)

---

## Shamir Secret Sharing (`shamir.h`)

### Constants

```c
#define SHAMIR_FIELD_MODULUS       3329
#define SHAMIR_BARRETT_MULTIPLIER  20159
#define SHAMIR_BARRETT_SHIFT       26
#define SHAMIR_SECRET_ELEMENTS     32
#define SHAMIR_SECRET_BYTES        64        // 32 elements * 2 bytes
#define SHAMIR_MAX_SHARES          255
#define SHAMIR_WORKSPACE_SIZE      8416      // 255 * 32 + 256
```

### GF(3329) Arithmetic

```c
uint16_t gf3329_barrett_reduce(uint32_t a);
uint16_t gf3329_add(uint16_t a, uint16_t b);
uint16_t gf3329_sub(uint16_t a, uint16_t b);
uint16_t gf3329_mul(uint16_t a, uint16_t b);
uint16_t gf3329_inv(uint16_t a);          // Returns 0 if a == 0
uint16_t gf3329_evaluate_polynomial(const uint16_t* coeffs, uint8_t degree, uint16_t x);
```

All operations work in GF(3329). Elements are `uint16_t` in range [0, 3328].

### Share (Element-Based)

```c
int shamir_share(
    const uint16_t* secret,           // [in]  secret_elements elements
    uint8_t secret_elements,          // [in]  number of elements (<= 32)
    uint16_t* share_x,                // [out] x-coordinates (n elements)
    uint16_t** share_y,               // [out] y-coordinates (n * secret_elements)
    uint8_t n,                        // [in]  total shares (1-255)
    uint8_t t,                        // [in]  threshold (1-n)
    uint16_t* workspace               // [in]  workspace buffer (SHAMIR_WORKSPACE_SIZE)
);
```

**Returns:** `PQC_SUCCESS` or error code

```c
int shamir_reconstruct(
    uint16_t* secret,                 // [out] reconstructed secret (secret_elements)
    const uint16_t* share_x,          // [in]  x-coordinates (k elements)
    uint16_t** share_y,               // [in]  y-coordinates (k * secret_elements)
    uint8_t k,                        // [in]  number of shares (>= t)
    uint16_t* workspace               // [in]  workspace buffer
);
```

**Returns:** `PQC_SUCCESS` or error code

### Share (Byte-Based)

```c
int shamir_share_bytes(
    const uint8_t* secret,            // [in]  secret bytes (secret_len)
    size_t secret_len,                // [in]  secret length (must be 64)
    uint8_t* share_x,                 // [out] x-coordinates (n bytes)
    uint8_t** share_y,                // [out] share values (n * 64 bytes)
    uint8_t n,                        // [in]  total shares (1-255)
    uint8_t t,                        // [in]  threshold (1-n)
    uint16_t* workspace               // [in]  workspace buffer
);
```

```c
int shamir_reconstruct_bytes(
    uint8_t* secret,                  // [out] reconstructed secret (64 bytes)
    const uint8_t* share_x,           // [in]  x-coordinates (k bytes)
    const uint8_t** share_y,          // [in]  share values (k * 64 bytes)
    uint8_t k,                        // [in]  number of shares (>= t)
    uint16_t* workspace               // [in]  workspace buffer
);
```

**Byte format:** Each share value is 64 bytes = 32 `uint16_t` elements in little-endian.

---

## Random Bytes (`randombytes.h`)

```c
int randombytes(uint8_t* output, size_t len);
```

**Parameters:**
- `output` - Buffer to fill with random bytes
- `len` - Number of bytes to generate

**Returns:** `0` on success, negative on failure:
- `-1`: RNG hardware failure or unavailable
- `-2`: Invalid arguments (NULL output, len == 0)

**Note:** Uses platform CSPRNG. Must be initialized before use.

---

## Mask PRG (`mask_prg.h`)

### Context Structure

```c
typedef struct {
    struct tc_aes_key_sched_struct sched;  // AES-256 key schedule
    uint8_t nonce[16];                      // Per-context nonce
    uint8_t ctr[16];                        // Block counter (little-endian)
    int initialized;                        // Initialization flag
    size_t block_offset;                    // Bytes consumed in current block (0-15)
} mask_prg_ctx_t;
```

**Counter format:** 128-bit little-endian. `nonce || counter` where:
- `nonce`: Fixed per context, advanced on reseed
- `counter`: Starts at 0, increments per 16-byte block
- `block_offset`: Tracks partial block consumption for multi-call continuity

**Thread safety:** NOT thread-safe. Each context must be used by a single thread.

### Functions

```c
int mask_prg_init(mask_prg_ctx_t* ctx, const uint8_t seed[32]);
```
- Initializes PRG with 32-byte seed (AES-256 key)
- Sets `nonce=0`, `counter=0`, `block_offset=0`
- **Returns:** `0` on success, `-1` on error

```c
int mask_prg_reseed(mask_prg_ctx_t* ctx, const uint8_t seed[32]);
```
- Reseeds with new 32-byte key
- Advances nonce, resets `counter=0`, `block_offset=0`
- **Returns:** `0` on success, `-1` on error

```c
int mask_prg_get_bytes(mask_prg_ctx_t* ctx, uint8_t* out, size_t len);
```
- Generates pseudorandom bytes
- Maintains stream continuity across multiple calls
- **Returns:** `0` on success, `-1` on error

```c
void mask_prg_cleanup(mask_prg_ctx_t* ctx);
```
- Zeroizes all sensitive state in context (key schedule, nonce, counter)
- **Must be called** when context is no longer needed

---

## KEM Adapter (`kem_adapter.h`)

### Types (from `protocol_types.h`)

```c
typedef enum {
    KEMLIB_ML_KEM_512  = 0,
    KEMLIB_ML_KEM_768  = 1,
    KEMLIB_ML_KEM_1024 = 2,
} kem_variant_t;

typedef struct {
    kem_variant_t variant;
    uint8_t public_key[1568];
    uint8_t secret_key[3168];
    size_t  public_key_len;
    size_t  secret_key_len;
    size_t  ciphertext_len;
    size_t  shared_secret_len;
} kem_keypair_t;

typedef struct {
    uint8_t ciphertext[1568];
    uint8_t shared_secret[32];
    size_t  ciphertext_len;
    size_t  shared_secret_len;
} kem_encapsulation_t;
```

### Core Functions

```c
pqc_status_t kem_adapter_init(kem_variant_t variant);
```
- Initializes adapter with ML-KEM variant
- Must be called before any other KEM function
- **Returns:** `PQC_SUCCESS` or `ERR_INVALID_ARGUMENT`

```c
kem_variant_t kem_adapter_get_variant(void);
```
- Returns currently active variant

```c
pqc_status_t kem_adapter_get_sizes(size_t* pk_bytes, size_t* sk_bytes, size_t* ct_bytes, size_t* ss_bytes);
```
- Gets buffer sizes for current variant
- **Returns:** `PQC_SUCCESS` or `ERR_INVALID_ARGUMENT` (if any pointer is NULL)

```c
pqc_status_t kem_adapter_keypair(kem_keypair_t* keypair);
```
- Generates ML-KEM key pair
- Fills `keypair` with keys and metadata
- **Returns:** `PQC_SUCCESS`, `ERR_KEM_KEYGEN_FAILED`, or `ERR_INVALID_ARGUMENT`

```c
pqc_status_t kem_adapter_encapsulate(const uint8_t* public_key, size_t pk_len, kem_encapsulation_t* encap);
```
- Encapsulates shared secret using public key
- `pk_len` must match current variant
- **Returns:** `PQC_SUCCESS`, `ERR_KEM_ENCAP_FAILED`, or `ERR_INVALID_ARGUMENT`

```c
pqc_status_t kem_adapter_decapsulate(const uint8_t* ciphertext, size_t ct_len, const uint8_t* secret_key, size_t sk_len, uint8_t* shared_secret);
```
- Decapsulates shared secret from ciphertext using private key
- **IMPORTANT:** Uses implicit rejection (FIPS 203)
- Always returns `PQC_SUCCESS` on valid inputs
- On ciphertext verification failure, returns **pseudorandom** shared secret
- Caller **MUST** use `kem_adapter_verify_decapsulation()` to verify
- **Returns:** `PQC_SUCCESS` or `ERR_INVALID_ARGUMENT`

```c
pqc_status_t kem_adapter_verify_decapsulation(const uint8_t* expected_ss, const uint8_t* actual_ss);
```
- Verifies decapsulation result matches expected shared secret
- **Returns:** `PQC_SUCCESS` if match, `ERR_CRYPTO_FAILURE` if different

### Key Derivation Functions

```c
pqc_status_t kem_adapter_derive_session_key(const uint8_t* shared_secret, const uint8_t* salt, size_t salt_len, const uint8_t* info, size_t info_len, uint8_t* session_key);
```
- HKDF-SHA256 with custom salt/info
- Output: 32-byte session key
- **Returns:** `PQC_SUCCESS` or `ERR_INVALID_ARGUMENT`

```c
pqc_status_t kem_adapter_derive_pairwise_mask_seed(const uint8_t* shared_secret, uint8_t client_id_a, uint8_t client_id_b, uint32_t round_id, uint8_t* mask_seed);
```
- Derives 32-byte pairwise mask seed
- **HKDF-SHA256:**
  - IKM = `shared_secret` (32 bytes)
  - Salt = empty (32 zero bytes)
  - Info = `"SwiftAgg-PairwiseMask-v1"` || `round_id` (4 bytes, big-endian) || `min(client_id_a, client_id_b)` || `max(client_id_a, client_id_b)`
  - L = 32 bytes
- **Returns:** `PQC_SUCCESS` or `ERR_INVALID_ARGUMENT`

```c
pqc_status_t kem_adapter_derive_stream_mask_seed(const uint8_t* shared_secret, uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint8_t* stream_seed);
```
- Derives 32-byte stream mask seed
- **HKDF-SHA256:**
  - IKM = `shared_secret` (32 bytes)
  - Salt = empty (32 zero bytes)
  - Info = `"SwiftAgg-StreamMask-v1"` || `round_id` (4 bytes, big-endian) || `client_id` || `chunk_index` (2 bytes, big-endian)
  - L = 32 bytes
- **Returns:** `PQC_SUCCESS` or `ERR_INVALID_ARGUMENT`

```c
pqc_status_t kem_adapter_derive_shamir_secret(const uint8_t* shared_secret, uint8_t client_id, uint32_t round_id, uint8_t* shamir_secret);
```
- Derives 64-byte Shamir secret (32 GF(3329) elements)
- **HKDF-SHA256:**
  - IKM = `shared_secret` (32 bytes)
  - Salt = empty (32 zero bytes)
  - Info = `"SwiftAgg-ShamirSecret-v1"` || `round_id` (4 bytes, big-endian) || `client_id`
  - L = 64 bytes
- **Returns:** `PQC_SUCCESS` or `ERR_INVALID_ARGUMENT`

### Utility Functions

```c
pqc_status_t kem_adapter_zeroize_scratchpad(void);
```
- Zeroizes KEM workspace in global scratchpad
- **Returns:** `PQC_SUCCESS`

```c
pqc_status_t kem_adapter_self_test(void);
```
- Runs known-answer tests for current variant
- **Returns:** `PQC_SUCCESS` or error code

```c
uint32_t kem_adapter_get_last_cycles(void);
```
- Returns cycle count of last KEM operation

### Deterministic Test Interface (when `KEM_DETERMINISTIC_TEST` defined)

```c
pqc_status_t kem_adapter_keypair_derand(kem_keypair_t* keypair, const uint8_t seed[48]);
pqc_status_t kem_adapter_encapsulate_derand(const uint8_t* public_key, size_t pk_len, kem_encapsulation_t* encap, const uint8_t seed[48]);
```

---

## HKDF (`hkdf.h`)

```c
#define HKDF_SHA256_MAX_OUTPUT_LEN 8192
```

```c
int hkdf_sha256_extract(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t* prk);
```
- HKDF-Extract: PRK = HMAC-SHA256(salt, IKM)
- `prk` must be 32 bytes
- **Returns:** `0` on success, negative on failure

```c
int hkdf_sha256_expand(const uint8_t* prk, size_t prk_len, const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len);
```
- HKDF-Expand: OKM = HMAC-SHA256(PRK, info || counter)
- `okm_len` <= 8192
- **Returns:** `0` on success, negative on failure

```c
int hkdf_sha256(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len);
```
- Combined extract-and-expand
- **Returns:** `0` on success, negative on failure

---

## Crypto Memory (`crypto_memory.h`)

```c
void crypto_zeroize(volatile void* ptr, size_t len);
```
- Constant-time memory zeroization
- Compiler barrier prevents optimization
- **Use for all secret material cleanup**

```c
int crypto_ct_compare(const void* a, const void* b, size_t len);
```
- Constant-time memory comparison
- **Returns:** `1` if equal, `0` if different
- **Use for secret comparison** (keys, tags, secrets)

```c
void crypto_ct_copy(void* dst, const void* src, size_t len, int condition);
```
- Constant-time conditional copy
- Copies `src` to `dst` if `condition != 0`, else no-op
- Timing independent of `condition`

```c
void crypto_zeroize_scratchpad_region(int region);
```
- Zeroizes specific scratchpad region
- `region` values from `scratch_region_t`:
  - `SCRATCH_REGION_MLKEM` (0)
  - `SCRATCH_REGION_CRYPTO` (1)
  - `SCRATCH_REGION_DMA_RX` (2)
  - `SCRATCH_REGION_DMA_TX` (3)
  - `SCRATCH_REGION_CHUNK` (4)
  - `SCRATCH_REGION_SHAMIR` (5)
  - `SCRATCH_REGION_PROTO` (6)

```c
void crypto_zeroize_all_scratchpad(void);
```
- Zeroizes entire global scratchpad

---

## Memory Ownership & Cleanup Rules

### Global Scratchpad (from `memory_scratchpad.h`)

| Region | Size | Alignment | Purpose |
|--------|------|-----------|---------|
| MLKEM | 4096 bytes | 32 bytes | ML-KEM operations |
| CRYPTO | 2048 bytes | 32 bytes | General crypto workspace |
| DMA_RX | 3072 bytes | 32 bytes | Double-buffered RX (ping/pong) |
| DMA_TX | 3072 bytes | 32 bytes | Double-buffered TX (ping/pong) |
| CHUNK | 1024 bytes | 32 bytes | Chunk buffering |
| SHAMIR | 12288 bytes | 32 bytes | Shamir workspace |
| PROTO | 512 bytes | 32 bytes | Protocol state |

**Total:** ~26 KB

### Ownership Rules

1. **Caller allocates, callee fills:** Output buffers (`shared_secret`, `ciphertext`, `session_key`, `mask_seed`, `stream_seed`, `shamir_secret`)
2. **Caller allocates workspace:** `shamir_share/reconstruct` require caller-provided `workspace` buffer (SHAMIR_WORKSPACE_SIZE = 8416 uint16_t = 16832 bytes)
3. **Stack allocation preferred:** All fixed-size buffers should be stack-allocated when possible
4. **Zeroize on cleanup:** All secret material must be zeroized via `crypto_zeroize()` or `mask_prg_cleanup()`
5. **Scratchpad regions:** Use `scratch_get_*()` accessors; zeroize via `crypto_zeroize_scratchpad_region()` or `crypto_zeroize_all_scratchpad()`

### Key Lifecycles

| Key Type | Lifetime | Cleanup |
|----------|----------|---------|
| ML-KEM keypair | Round duration | `crypto_zeroize()` on secret key |
| Shared secret | Until mask derivation complete | `crypto_zeroize()` after `derive_*` calls |
| Pairwise mask seed | Round duration | `crypto_zeroize()` at round end |
| Stream mask seed | Chunk duration | `crypto_zeroize()` after chunk processing |
| Shamir secret | Until sharing complete | `crypto_zeroize()` after share distribution |
| Mask PRG context | Stream duration | `mask_prg_cleanup()` |

### Thread Safety

- **Global scratchpad:** NOT thread-safe. Use per-thread instances or external synchronization.
- **Mask PRG context:** NOT thread-safe. One context per thread.
- **KEM adapter:** NOT thread-safe (uses global scratchpad). Serialize calls or use per-thread instances.
- **HKDF, Shamir GF arithmetic:** Thread-safe (pure functions).
- **Crypto memory functions:** Thread-safe (operate on caller-provided buffers).

---

## KDF Labels (from `kem_adapter.h`)

```c
#define KDF_LABEL_KEM_SHARED      "MLKEM-SharedSecret-v1"
#define KDF_LABEL_PAIRWISE_MASK   "SwiftAgg-PairwiseMask-v1"
#define KDF_LABEL_STREAM_MASK     "SwiftAgg-StreamMask-v1"
#define KDF_LABEL_SHAMIR_SECRET   "SwiftAgg-ShamirSecret-v1"
#define KDF_LABEL_SESSION_KEY     "FL-SessionKey-v1"
```

All HKDF operations use SHA-256. Salt is typically 32 zero bytes unless specified otherwise.