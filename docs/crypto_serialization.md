# Crypto Serialization Reference

**Branch:** `feature/member-1-crypto`  
**Module:** Shamir Secret Sharing (`src/pqc_engine/shamir.h`, `src/core_rtos/protocol_types.h`)

---

## Share Serialization Format

### Wire Format (Network/Storage)

```
┌─────────────────────────────────────────────────────────────┐
│ Shamir Share (65 bytes total)                               │
├──────────────┬──────────────────────────────────────────────┤
│ Offset  Size │ Field                                        │
├──────────────┼──────────────────────────────────────────────┤
│ 0       1    │ share_id (uint8) — x-coordinate in GF(3329)  │
│ 1       64   │ value (uint8[64]) — 32 elements × uint16 LE  │
└──────────────┴──────────────────────────────────────────────┘
```

### Field Details

| Field | Type | Size | Description |
|-------|------|------|-------------|
| `share_id` | `uint8_t` | 1 byte | Share x-coordinate (1–255, non-zero). Maps to GF(3329) element. |
| `value` | `uint8_t[64]` | 64 bytes | 32 field elements, each `uint16_t` little-endian. Each element ∈ [0, 3328]. |

### GF(3329) Element Encoding

- **Modulus:** 3329 (prime, 0x0D01)
- **Representation:** 16-bit unsigned integer, little-endian byte order
- **Valid range:** 0 to 3328 (0x0CFF)
- **Barrett reduction:** Multiply by 20159 (0x4EBF), shift right 26 bits

```
uint16_t element = 0x1234;  // Example value
// Wire bytes (little-endian):
// Byte 0: 0x34
// Byte 1: 0x12
```

### Secret Encoding

The 32-element secret (64 bytes) is split into 32 `uint16_t` values in GF(3329):

```
Secret (64 bytes) = [e0_lo, e0_hi, e1_lo, e1_hi, ..., e31_lo, e31_hi]
Element i = (uint16_t)secret[2*i] | ((uint16_t)secret[2*i+1] << 8)
```

---

## API Serialization Contracts

### `shamir_share_bytes()`

```c
int shamir_share_bytes(
    const uint8_t* secret,     // [in]  Secret: 64 bytes (32 × uint16 LE)
    size_t secret_len,         // [in]  Must equal 64
    uint8_t* share_x,          // [out] Share IDs: n bytes (1 each)
    uint8_t** share_y,         // [out] Share values: n × 64 bytes
    uint8_t n,                 // [in]  Total shares (1–255)
    uint8_t t,                 // [in]  Threshold (1–n)
    uint16_t* workspace        // [in]  Workspace: SHAMIR_WORKSPACE_SIZE (8416 bytes)
);
```

#### Memory Ownership
| Parameter | Ownership | Lifetime | Alignment |
|-----------|-----------|----------|-----------|
| `secret` | Caller-owned, read-only | Must remain valid during call | 2-byte (uint16) |
| `share_x` | Caller-allocated, callee-filled | `n` bytes | 1-byte |
| `share_y` | **Callee-allocates** array of `n` pointers; each points to 64-byte buffer | Caller must free each `share_y[i]` and the array | 2-byte (uint16) |
| `workspace` | Caller-allocated | Must remain valid during call | 2-byte (uint16) |

#### Allocation Pattern (Typical Implementation)
```c
// Caller allocates:
uint8_t* share_x = malloc(n);
uint8_t** share_y = malloc(n * sizeof(uint8_t*));
for (uint8_t i = 0; i < n; i++) {
    share_y[i] = aligned_alloc(2, 64);  // 64 bytes, 2-byte aligned
}
uint16_t* workspace = aligned_alloc(2, SHAMIR_WORKSPACE_SIZE);

// Call:
shamir_share_bytes(secret, 64, share_x, share_y, n, t, workspace);

// Caller frees:
for (uint8_t i = 0; i < n; i++) free(share_y[i]);
free(share_y);
free(share_x);
free(workspace);
```

### `shamir_reconstruct_bytes()`

```c
int shamir_reconstruct_bytes(
    uint8_t* secret,           // [out] Reconstructed secret: 64 bytes
    const uint8_t* share_x,    // [in]  Share IDs: k bytes
    const uint8_t** share_y,   // [in]  Share values: k × 64 bytes
    uint8_t k,                 // [in]  Number of shares (≥t)
    uint16_t* workspace        // [in]  Workspace: SHAMIR_WORKSPACE_SIZE
);
```

#### Memory Ownership
| Parameter | Ownership | Lifetime | Alignment |
|-----------|-----------|----------|-----------|
| `secret` | Caller-allocated, callee-filled | 64 bytes | 2-byte |
| `share_x` | Caller-owned, read-only | `k` bytes | 1-byte |
| `share_y` | Caller-owned, read-only | Array of `k` pointers to 64-byte buffers | 2-byte |
| `workspace` | Caller-allocated | Must remain valid during call | 2-byte |

---

## Internal (Element-based) API

### `shamir_share()`

```c
int shamir_share(
    const uint16_t* secret,      // [in]  32 elements (already GF(3329))
    uint8_t secret_elements,     // [in]  ≤32
    uint16_t* share_x,           // [out] x-coordinates: n × uint16
    uint16_t** share_y,          // [out] y-coordinates: n × secret_elements × uint16
    uint8_t n, uint8_t t,
    uint16_t* workspace
);
```

- **No serialization** — operates on native `uint16_t` GF(3329) elements
- `share_x`: 16-bit x-coordinates (allows >255 shares internally, but protocol limits to 255)
- `share_y`: Callee allocates `n` arrays of `secret_elements` `uint16_t` each

### `shamir_reconstruct()`

```c
int shamir_reconstruct(
    uint16_t* secret,            // [out] secret_elements × uint16
    const uint16_t* share_x,     // [in]  k × uint16
    uint16_t** share_y,          // [in]  k × secret_elements × uint16
    uint8_t k,
    uint16_t* workspace
);
```

---

## Protocol Types Integration (`protocol_types.h`)

### `shamir_share_t` (65 bytes)
```c
typedef struct {
    uint8_t share_id;                    // 1 byte — x-coordinate (1–255)
    uint8_t value[SHAMIR_SHARE_VALUE_BYTES];  // 64 bytes — 32 × uint16 LE
} shamir_share_t;
```
**Size:** 65 bytes (no padding, packed)

### `shamir_context_t` (In-Memory Working State)
```c
typedef struct {
    uint8_t threshold;                   // t
    uint8_t num_shares;                  // n
    shamir_share_t shares[SHAMIR_MAX_SHARES];  // 255 × 65 = 16,575 bytes
    uint8_t secret[SHAMIR_SHARE_VALUE_BYTES];  // 64 bytes
} shamir_context_t;
```
**Total size:** ~16.6 KB

---

## Alignment Requirements

| Buffer | Required Alignment | Reason |
|--------|-------------------|--------|
| `secret` (uint8_t*) | 2-byte | Cast to `uint16_t*` for GF arithmetic |
| `share_y` elements | 2-byte | Each is 32 × `uint16_t` |
| `workspace` | 2-byte | Used as `uint16_t*` internally |
| `share_x` (byte API) | 1-byte | `uint8_t` array |
| `share_x` (element API) | 2-byte | `uint16_t` array |

**Scratchpad region:** `SCRATCH_REGION_SHAMIR` (12,288 bytes, 32-byte aligned)  
Provides `shamir_workspace_t` with `uint8_t data[SHAMIR_WORKSPACE_BYTES]` — use via `scratch_get_shamir_ws()`.

---

## Thread Safety

| Function | Thread-Safe? | Notes |
|----------|--------------|-------|
| `shamir_share_bytes` | **No** | Uses shared workspace; callee allocates `share_y` |
| `shamir_reconstruct_bytes` | **Yes** | Read-only inputs, distinct output buffer |
| `shamir_share` | **No** | Shared workspace, callee allocates |
| `shamir_reconstruct` | **Yes** | Read-only inputs, distinct output |
| GF arithmetic (`gf3329_*`) | **Yes** | Pure functions, no state |
| `mask_prg_get_bytes` | **No** | Context is mutable state |

**Rule:** Each thread must have its own `workspace` buffer and `mask_prg_ctx_t`.  
**Scratchpad:** Global scratchpad (`g_scratchpad`) is **not thread-safe** — use per-thread instances or serialize access.

---

## Error Codes (from `pqc_status_t`)

| Code | Value | When Returned |
|------|-------|---------------|
| `PQC_SUCCESS` | 0 | Normal completion |
| `ERR_INVALID_ARGUMENT` | -2 | NULL pointer, `secret_len != 64`, `n==0`, `t==0`, `t>n`, `k<t` |
| `ERR_BUFFER_TOO_SMALL` | -3 | Output buffer too small (internal) |
| `ERR_SHAMIR_ENCODE_FAILED` | -19 | Polynomial generation / evaluation failed |
| `ERR_SHAMIR_DECODE_FAILED` | -20 | Lagrange interpolation failed (singular matrix) |
| `ERR_INSUFFICIENT_SHARES` | -21 | `k < t` in reconstruct |
| `ERR_DUPLICATE_SHARE_ID` | -22 | Duplicate x-coordinate in shares |
| `ERR_INVALID_THRESHOLD` | -23 | `t > n` or `t > 255` |

---

## Serialization Examples

### Example: 3-of-5 Sharing (Byte API)

```c
// Secret: 64 bytes (32 GF(3329) elements)
uint8_t secret[64] = { ... };

// Allocate outputs
uint8_t share_x[5];
uint8_t* share_y[5];
for (int i = 0; i < 5; i++) share_y[i] = aligned_alloc(2, 64);
uint16_t workspace[SHAMIR_WORKSPACE_SIZE / 2];

// Share: n=5, t=3
shamir_share_bytes(secret, 64, share_x, share_y, 5, 3, workspace);

// Wire format per share (65 bytes each):
// share_x[0] = 0x01  share_y[0] = [64 bytes LE uint16]
// share_x[1] = 0x02  share_y[1] = [64 bytes LE uint16]
// ...

// Reconstruct from any 3 shares
uint8_t recv_x[3] = { share_x[0], share_x[2], share_x[4] };
uint8_t* recv_y[3] = { share_y[0], share_y[2], share_y[4] };
uint8_t recovered[64];
shamir_reconstruct_bytes(recovered, recv_x, (const uint8_t**)recv_y, 3, workspace);
// recovered == secret
```

### Network Transmission (Per Share)

```c
// Send single share (65 bytes)
void send_share(uint8_t share_id, uint8_t value[64]) {
    uint8_t packet[65];
    packet[0] = share_id;
    memcpy(packet + 1, value, 64);
    network_send(packet, 65);
}

// Receive single share
int recv_share(uint8_t* share_id, uint8_t value[64]) {
    uint8_t packet[65];
    if (network_recv(packet, 65) != 65) return -1;
    *share_id = packet[0];
    memcpy(value, packet + 1, 64);
    return 0;
}
```

---

## Constants Summary

| Constant | Value | Source |
|----------|-------|--------|
| `SHAMIR_FIELD_MODULUS` | 3329 | `shamir.h` |
| `SHAMIR_SECRET_ELEMENTS` | 32 | `shamir.h` |
| `SHAMIR_SECRET_BYTES` | 64 | `shamir.h` |
| `SHAMIR_SHARE_VALUE_BYTES` | 64 | `protocol_types.h` |
| `SHAMIR_MAX_SHARES` | 255 | `shamir.h` / `protocol_types.h` |
| `SHAMIR_WORKSPACE_SIZE` | 8416 | `shamir.h` |
| `SHAMIR_WORKSPACE_BYTES` | 12288 | `memory_scratchpad.h` (scratchpad region) |

---
*Generated from `src/pqc_engine/shamir.h` and `src/core_rtos/protocol_types.h` on branch `feature/member-1-crypto`*