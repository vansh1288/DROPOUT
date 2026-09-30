# DROPOUT Cryptographic Design Document

## Overview

This document describes the cryptographic primitives used in the DROPOUT secure aggregation system, their implementation details, interfaces, and security considerations.

## 1. ML-KEM (Module-Lattice Key Encapsulation Mechanism)

### 1.1 Algorithm Selection

- **Algorithm**: ML-KEM-768 (FIPS 203, formerly Kyber-768)
- **Security Level**: NIST Level 3 (IND-CCA2)
- **Variants Supported**: ML-KEM-512, ML-KEM-768 (default), ML-KEM-1024
- **Implementation**: PQClean reference implementation (`deps/pqm4/mupq/pqclean/crypto_kem/ml-kem-768/clean/`)

### 1.2 Parameters

| Parameter | ML-KEM-512 | ML-KEM-768 | ML-KEM-1024 |
|-----------|------------|------------|-------------|
| Public Key | 800 bytes | 1184 bytes | 1568 bytes |
| Secret Key | 1632 bytes | 2400 bytes | 3168 bytes |
| Ciphertext | 768 bytes | 1088 bytes | 1568 bytes |
| Shared Secret | 32 bytes | 32 bytes | 32 bytes |

### 1.3 API

```c
// Initialize with variant
pqc_status_t kem_adapter_init(kem_variant_t variant);

// Key generation
pqc_status_t kem_adapter_keypair(kem_keypair_t* keypair);

// Encapsulation (client -> server)
pqc_status_t kem_adapter_encapsulate(const uint8_t* public_key, size_t pk_len, kem_encapsulation_t* encap);

// Decapsulation (server -> client)
pqc_status_t kem_adapter_decapsulate(const uint8_t* ciphertext, size_t ct_len, const uint8_t* secret_key, size_t sk_len, uint8_t* shared_secret);
```

### 1.4 Key Derivation from ML-KEM Shared Secret

All protocol keys are derived from ML-KEM shared secrets using HKDF-SHA256 with context separation labels:

| Purpose | Label |
|---------|-------|
| Session Key | `FL-SessionKey-v1` |
| Pairwise Mask Seed | `SwiftAgg-PairwiseMask-v1` |
| Stream Mask Seed | `SwiftAgg-StreamMask-v1` |
| Shamir Secret | `SwiftAgg-ShamirSecret-v1` |

### 1.5 Security Notes

- ML-KEM decapsulation returns success (0) even for invalid ciphertexts, producing a pseudorandom shared secret (FIPS 203 implicit rejection)
- Ephemeral keys per round provide forward secrecy
- All private keys zeroized after use via `crypto_zeroize()`

---

## 2. HKDF-SHA256 (RFC 5869)

### 2.1 Implementation

- **Standard**: RFC 5869 compliant
- **Hash**: SHA-256 via TinyCrypt
- **Location**: `src/pqc_engine/hkdf.c/h`

### 2.2 API

```c
// Extract step: PRK = HMAC-SHA256(salt, IKM)
int hkdf_sha256_extract(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t* prk);

// Expand step: OKM = HKDF-Expand(PRK, info, L)
int hkdf_sha256_expand(const uint8_t* prk, size_t prk_len, const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len);

// Combined: OKM = HKDF(salt, IKM, info, L)
int hkdf_sha256(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, const uint8_t* info, size_t info_len, uint8_t* okm, size_t okm_len);
```

### 2.3 Limits

- Maximum output length: 8192 bytes (255 × 32)
- PRK length: 32 bytes (SHA-256 output)

### 2.4 Test Vectors

All RFC 5869 test vectors (A.1-A.4) pass.

---

## 3. AES-CTR PRG (Pseudorandom Generator)

### 3.1 Design

- **Cipher**: AES-256 in CTR mode via TinyCrypt
- **Context-based**: Each mask stream uses independent `mask_prg_ctx_t`
- **Counter**: 128-bit big-endian counter, increments per 16-byte block
- **Nonce**: 128-bit, incremented on reseed

### 3.2 API

```c
typedef struct {
    struct tc_aes_key_sched_struct sched;
    uint8_t nonce[16];
    uint8_t ctr[16];
    int initialized;
} mask_prg_ctx_t;

void mask_prg_init(mask_prg_ctx_t* ctx, const uint8_t seed[32]);
void mask_prg_reseed(mask_prg_ctx_t* ctx, const uint8_t seed[32]);
void mask_prg_get_bytes(mask_prg_ctx_t* ctx, uint8_t* out, size_t len);
```

### 3.3 Usage in Protocol

Each client pair (A,B) derives a pairwise mask seed via HKDF, then expands it into a mask vector of length `chunk_size` (in 16-bit elements).

```c
// Pairwise mask for clients A < B
seed_AB = HKDF(K_AB, "SwiftAgg-PairwiseMask-v1" || A || B || round_id)
mask_AB = PRG(seed_AB, chunk_size * 2 bytes)

// Client A adds +mask_AB, Client B adds -mask_AB
```

### 3.4 Chunking Consistency

Generating N bytes in one call vs. multiple chunks produces identical output:
- Counter increments correctly per 16-byte block
- No double-increment bug (fixed from previous implementation)

---

## 4. Shamir Secret Sharing

### 4.1 Field Arithmetic

- **Field**: GF(3329) - same as ML-KEM/NTT prime
- **Reduction**: Barrett reduction (multiplier=20159, shift=26)
- **Elements**: 32 field elements per secret (64 bytes)
- **Max Shares**: 255 (8-bit share IDs)

### 4.2 API

```c
// Field operations
uint16_t gf3329_add(uint16_t a, uint16_t b);
uint16_t gf3329_sub(uint16_t a, uint16_t b);
uint16_t gf3329_mul(uint16_t a, uint16_t b);
uint16_t gf3329_inv(uint16_t a);

// Polynomial evaluation
uint16_t gf3329_evaluate_polynomial(const uint16_t* coeffs, uint8_t degree, uint16_t x);

// Share generation
int shamir_share(const uint16_t* secret, uint8_t secret_elements, uint16_t* share_x, uint16_t** share_y, uint8_t n, uint8_t t, uint16_t* workspace);

// Reconstruction (Lagrange at x=0)
int shamir_reconstruct(uint16_t* secret, const uint16_t* share_x, uint16_t** share_y, uint8_t k, uint16_t* workspace);

// Byte-level API (32 elements = 64 bytes)
int shamir_share_bytes(const uint8_t* secret, size_t secret_len, uint8_t* share_x, uint8_t** share_y, uint8_t n, uint8_t t, uint16_t* workspace);
int shamir_reconstruct_bytes(uint8_t* secret, const uint8_t* share_x, const uint8_t** share_y, uint8_t k, uint16_t* workspace);
```

### 4.3 Share Format

- **Share ID**: 1 byte (1-255, non-zero)
- **Share Value**: 64 bytes (32 × uint16 little-endian)
- **Threshold**: Configurable t ≤ n ≤ 255

### 4.4 Dropout Recovery

When client D drops out:
1. Surviving clients hold Shamir shares of D's pairwise secrets
2. Server collects ≥ t shares
3. Lagrange interpolation at x=0 recovers each `seed_Di`
4. Server regenerates dropout masks and applies with correct signs

### 4.5 Security Notes

- Information-theoretic security: < t shares reveal nothing about secret
- No authentication: malicious shares can cause incorrect reconstruction
- Protocol assumes honest-but-curious clients (Byzantine out of scope)
- Values must be < 3329 (field modulus)

---

## 5. Constant-Time Operations

### 5.1 Memory Zeroization

```c
void crypto_zeroize(volatile void* ptr, size_t len);
```
- Uses volatile pointer to prevent compiler optimization
- Called on all secret material after use

### 5.2 Constant-Time Compare

```c
int crypto_ct_compare(const void* a, const void* b, size_t len);
```
- Returns 0 if equal, non-zero if different
- No early exit, constant-time for fixed length

### 5.3 Constant-Time Conditional Copy

```c
void crypto_ct_copy(void* dst, const void* src, size_t len, int condition);
```
- Copies src to dst if condition != 0
- No branches on secret data

---

## 6. Memory Management

### 6.1 Static Scratchpad

All cryptographic operations use pre-allocated static memory regions:

| Region | Size | Purpose |
|--------|------|---------|
| MLKEM_WORKSPACE | 4096 bytes | ML-KEM keygen/encap/decap |
| CRYPTO_WORKSPACE | 2048 bytes | HKDF, PRG, Shamir |
| SHAMIR_WORKSPACE | 12288 bytes | Shamir share/reconstruct |
| DMA_BUFFERS | 2 × 1536 bytes | Network I/O |
| CHUNK_BUFFER | 1024 bytes | Model chunk processing |

### 6.2 No Dynamic Allocation

- No `malloc`/`free` in cryptographic code paths
- All buffers caller-provided or from static scratchpad
- Suitable for constrained embedded targets

---

## 7. Randomness

### 7.1 Source

- **Embedded (STM32)**: Hardware RNG via `randombytes()` in `deps/pqm4/common/randombytes.c`
- **Embedded (ESP32)**: ESP-IDF hardware RNG
- **Native (Testing)**: NIST KAT DRBG (deterministic for reproducibility)

### 7.2 Requirements

- ML-KEM key generation: 48 bytes entropy (2 × KYBER_SYMBYTES)
- ML-KEM encapsulation: 32 bytes entropy (KYBER_SYMBYTES)
- Shamir polynomial coefficients: cryptographically secure random

---

## 8. Cross-Language Compatibility

### 8.1 Python Reference (host_server/shamir_recovery.py)

- Identical GF(3329) arithmetic with Barrett reduction
- Same HKDF-SHA256 construction
- Same mask derivation logic
- Verified interoperable via Python unit tests

### 8.2 Serialization

- All multi-byte fields: big-endian (network order)
- Field elements: little-endian (uint16) within shares
- ML-KEM keys/ciphertexts: raw byte arrays per FIPS 203

---

## 9. Security Assumptions

| Primitive | Assumption |
|-----------|------------|
| ML-KEM-768 | Module-LWE hardness, IND-CCA2 |
| HKDF-SHA256 | SHA-256 PRF, HMAC-SHA256 SUF-CMA |
| AES-256-CTR | AES PRF security |
| Shamir SS | Information-theoretic (t-1 shares = zero info) |

---

## 10. Out-of-Scope / Future Work

- **Side-channel hardening**: Constant-time NTT, masking for power analysis
- **Byzantine clients**: Verifiable secret sharing, ZK proofs
- **Post-quantum signatures**: For authentication (currently symmetric)
- **Formal verification**: Protocol proofs in EasyCrypt/ProVerif

---

## 11. File Summary

| File | Purpose |
|------|---------|
| `src/pqc_engine/kem_adapter.c/h` | ML-KEM + KDF integration |
| `src/pqc_engine/hkdf.c/h` | RFC 5869 HKDF-SHA256 |
| `src/pqc_engine/mask_prg.c/h` | AES-CTR PRG context API |
| `src/pqc_engine/shamir.c/h` | Shamir SS over GF(3329) |
| `src/pqc_engine/crypto_memory.c/h` | Constant-time ops |
| `src/core_rtos/memory_scratchpad.h` | Static memory regions |
| `tests/native/test_kem.c` | ML-KEM KAT tests |
| `tests/native/test_hkdf.c` | RFC 5869 HKDF tests |
| `tests/native/test_shamir.c` | Shamir SS tests |
| `tests/unit/test_crypto.py` | Python reference tests |