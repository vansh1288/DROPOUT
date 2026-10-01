# Shamir Secret Sharing Share Format Specification

## Overview

This document defines the canonical share format for Shamir Secret Sharing as used in the DROPOUT project. The format must be identical between the embedded C implementation and the Python host implementation to ensure interoperability.

## Mathematical Foundation

- **Finite Field**: GF(3329) — prime field with modulus 3329
- **Secret Representation**: 32 field elements (each 0 ≤ element < 3329)
- **Threshold Scheme**: (t, n) where t ≤ n ≤ 255
- **Share Indices**: x ∈ {1, 2, ..., n} (1-indexed, non-zero)

## Share Structure

### In-Memory Representation (C)

```c
typedef struct {
    uint8_t share_id;           // 1 byte: share index (1-255)
    uint8_t value[64];          // 64 bytes: 32 field elements × 2 bytes each
} shamir_share_t;
```

### Serialized Wire Format

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0      | 1    | `share_id` | Share index (1-255), 1 byte |
| 1      | 64   | `value` | 32 field elements × 2 bytes (little-endian) |
| **Total** | **65** | | **Complete share payload** |

### Field Element Encoding

Each field element is a `uint16_t` in the range [0, 3328], encoded as **little-endian** (LE) 2-byte value:

```
Byte 0: element & 0xFF        (least significant byte)
Byte 1: (element >> 8) & 0xFF (most significant byte)
```

**Example**: Element value 0x1234 (4660 decimal)
- Byte 0: 0x34
- Byte 1: 0x12

### Share Value Layout (64 bytes)

```
Offset 0-1:   Element 0 (LSB first)
Offset 2-3:   Element 1
...
Offset 62-63: Element 31
```

Total: 32 elements × 2 bytes = 64 bytes

## Constants

| Constant | Value | Description |
|----------|-------|-------------|
| `SHAMIR_FIELD_MODULUS` | 3329 | Prime modulus |
| `SHAMIR_SECRET_ELEMENTS` | 32 | Number of field elements per secret |
| `SHAMIR_SECRET_BYTES` | 64 | Secret size in bytes (32 × 2) |
| `SHAMIR_SHARE_VALUE_BYTES` | 64 | Share value size in bytes |
| `SHAMIR_MAX_SHARES` | 255 | Maximum number of shares |
| `SHAMIR_MAX_THRESHOLD` | 255 | Maximum threshold |

## C API

### Share Generation

```c
int shamir_share_bytes(
    const uint8_t* secret,      // Input: 64-byte secret (32×uint16 LE)
    size_t secret_len,          // Must be SHAMIR_SECRET_BYTES (64)
    uint8_t* share_x,           // Output: n share indices (1..n)
    uint8_t** share_y,          // Output: n pointers to 64-byte share values
    uint8_t n,                  // Number of shares (n)
    uint8_t t,                  // Threshold (t)
    uint16_t* workspace         // Scratch buffer
);
```

### Share Reconstruction

```c
int shamir_reconstruct_bytes(
    uint8_t* secret,            // Output: 64-byte reconstructed secret
    const uint8_t* share_x,     // Input: k share indices
    const uint8_t** share_y,    // Input: k pointers to 64-byte share values
    uint8_t k,                  // Number of shares provided (k ≥ t)
    uint16_t* workspace         // Scratch buffer
);
```

### Return Values

- `0`: Success
- `-1`: Invalid arguments, RNG failure, or reconstruction failure

## Python API

```python
def reconstruct_secret_bytes(shares: List[Tuple[int, bytes]]) -> bytes:
    """
    Reconstruct secret from Shamir shares.
    
    Args:
        shares: List of (share_id, share_value) tuples
                share_id: int (1-255)
                share_value: bytes of length 64 (32 uint16 LE elements)
    
    Returns:
        bytes: 64-byte reconstructed secret (32 uint16 LE elements)
    """
```

### Share Format (Python)

```python
# Each share is a tuple:
(share_id: int, share_value: bytes)  # share_value is exactly 64 bytes

# Example share value decoding:
for elem_idx in range(32):
    val = share_value[elem_idx * 2] | (share_value[elem_idx * 2 + 1] << 8)
    # val is now the field element (0-3328)
```

### Secret Reconstruction (Python)

```python
secret_bytes = bytearray(64)
for i, val in enumerate(secret_elements):
    secret_bytes[2*i] = val & 0xFF
    secret_bytes[2*i + 1] = (val >> 8) & 0xFF
return bytes(secret_bytes)
```

## Serialization Examples

### Example Share (Hex)

```
Share ID: 0x05 (5)
Value (64 bytes = 32 elements):
  Element 0:  0x1234  → bytes: 34 12
  Element 1:  0x0001  → bytes: 01 00
  Element 2:  0x0CE7  → bytes: E7 0C
  ...
  Element 31: 0x0000  → bytes: 00 00

Wire format (65 bytes):
05 34 12 01 00 E7 0C ... 00 00
```

### Full Message Payload (MSG_TYPE_SHAMIR_SHARE)

```
Header (16 bytes) + Payload (65 bytes) + HMAC (32 bytes) = 113 bytes

Payload:
  Byte 0:        share_id (1 byte)
  Bytes 1-64:    share_value (64 bytes)
```

## C-Python Interoperability Rules

1. **Byte Order**: Little-endian for all multi-byte values
2. **Field Elements**: Always 32 elements per secret/share
3. **Element Range**: 0 to 3328 (inclusive)
3. **Share IDs**: 1-indexed, non-zero, unique per reconstruction set
4. **Serialization**: Direct memory copy of uint16_t array (LE)

## Validation Rules

### Input Validation (C)
- `secret_len == SHAMIR_SECRET_BYTES (64)` 
- `n ≥ t`, `t > 0`, `n ≤ 255`
- Share IDs non-zero and unique
- Share value buffers must be 64 bytes each

### Input Validation (Python)
- `len(share_value) == 64`
- All field elements < 3329
- Sufficient shares: `len(shares) >= threshold`

## Compile-Time Assertions

```c
// In protocol_types.h
#define SHAMIR_SECRET_ELEMENTS 32
#define SHAMIR_SECRET_BYTES (SHAMIR_SECRET_ELEMENTS * 2)  // 64
#define SHAMIR_SHARE_VALUE_BYTES SHAMIR_SECRET_BYTES       // 64

// In shamir.c
COMPILE_TIME_ASSERT(SHAMIR_SECRET_BYTES == 64, shamir_secret_bytes_must_be_64);
COMPILE_TIME_ASSERT(SHAMIR_SHARE_VALUE_BYTES == 64, shamir_share_value_bytes_must_be_64);
```

## Test Vectors

### Test 1: 3-of-5 Reconstruction
- Secret: 32 elements with known values
- n=5, t=3
- Any 3 shares reconstruct the secret

### Test 2: Byte API Round-trip
```c
uint8_t secret[64] = {...};
uint8_t share_x[5];
uint8_t share_y[5][64];
shamir_share_bytes(secret, 64, share_x, share_y, 5, 3, ws);
uint8_t recon[64];
shamir_reconstruct_bytes(recon, recon_x, recon_y, 3, ws);
assert(memcmp(secret, recon, 64) == 0);
```

### Test 3: C-Python Cross-Language
```python
# C generates shares using shamir_share_bytes()
# Python reconstructs using reconstruct_secret_bytes()
# Results must match byte-for-byte
```

## Error Handling

| Error Code | Condition |
|------------|-----------|
| `ERR_INVALID_ARGUMENT` | Null pointers, invalid lengths, bad thresholds |
| `ERR_SHAMIR_ENCODE_FAILED` | RNG failure during share generation |
| `ERR_SHAMIR_DECODE_FAILED` | Reconstruction failed (insufficient/malformed shares) |
| `ERR_INSUFFICIENT_SHARES` | `k < t` during reconstruction |
| `ERR_DUPLICATE_SHARE_ID` | Duplicate share indices in reconstruction set |
| `ERR_INVALID_THRESHOLD` | `t == 0` or `t > SHAMIR_MAX_THRESHOLD` |

## Security Considerations

1. **RNG Quality**: Coefficients must use cryptographically secure RNG (`randombytes()`)
2. **Zeroization**: Workspace buffers cleared after use (`crypto_zeroize()`)
3. **Constant-Time**: Reconstruction uses constant-time field operations
4. **No Secret Leakage**: Share values never logged or printed in production

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-10-01 | Initial specification; fixed share size to 64 bytes |