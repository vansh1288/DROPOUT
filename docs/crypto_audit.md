# DROPOUT Cryptographic Primitives Audit

## Repository Structure

```
C:\DROP\
├── src/
│   ├── core_rtos/           # FreeRTOS tasks, protocol types, memory management
│   ├── federated/           # Aggregation protocols, state machines
│   ├── network/             # Transport, DMA, packet codec
│   └── pqc_engine/          # Cryptographic primitives (THIS WORKSTREAM)
│       ├── kem_adapter.c/h  # ML-KEM + HKDF + KDF integration layer
│       ├── mask_prg.c/h     # AES-CTR pseudorandom generator for masks
│       ├── crypto_memory.c/h # Constant-time memory operations
│       ├── ntt_backend.c    # NTT for Kyber (unused - pqclean used instead)
│       └── tinycrypt_config.h
├── deps/pqm4/               # PQM4 benchmarking framework (includes pqclean)
│   ├── mupq/pqclean/crypto_kem/ml-kem-768/clean/  # ML-KEM-768 reference impl
│   └── crypto_kem/ml-kem-768/m4fspeed/            # Cortex-M4 optimized impl
├── host_server/
│   └── shamir_recovery.py   # Python Shamir + HKDF + AES-CTR reference
├── tests/
│   ├── native/              # C unit tests (require hkdf.h, shamir.h)
│   │   ├── test_kem.c
│   │   ├── test_hkdf.c
│   │   └── test_shamir.c
│   └── unit/test_crypto.py  # Python unit tests
├── protocol/                # Protocol specs
└── docs/                    # Documentation (THIS FILE)
```

---

## Current Implementation Status

| Primitive | File(s) | Status | Notes |
|-----------|---------|--------|-------|
| **ML-KEM-768** | `kem_adapter.c/h` | **Partially Implemented** | Wrapper exists but function name mismatch with pqclean (`pqcrystals_kyber768_ref_*` vs `PQCLEAN_MLKEM768_CLEAN_crypto_kem_*`). KAT vectors are fake placeholders. |
| **HKDF-SHA256** | `kem_adapter.c` (static) | **Partially Implemented** | RFC 5869 compliant `hkdf_extract`/`hkdf_expand` implemented as `static` in `kem_adapter.c`. No standalone header/module. Tests expect `hkdf.h`. |
| **AES-CTR PRG** | `mask_prg.c/h` | **Partially Implemented** | Uses TinyCrypt. **Critical issues**: global state (not multi-instance), counter resets incorrectly on `mask_prg_expand` causing chunked output ≠ single-buffer output. Self-test vectors appear fabricated. |
| **Shamir SS** | `host_server/shamir_recovery.py` | **Missing C Implementation** | Python reference uses GF(3329) with Barrett reduction. C tests expect `shamir.h` with `shamir_share`, `shamir_reconstruct`, `gf3329_*` ops. |
| **X25519 Fallback** | `kem_adapter.c` | **Broken** | Uses AES-CCM incorrectly for KEM encapsulation. Not compatible with any standard. |
| **Constant-time ops** | `crypto_memory.c/h` | **Implemented** | `crypto_zeroize`, `crypto_ct_compare`, `crypto_ct_copy` - correct. |
| **Memory mgmt** | `memory_scratchpad.h` | **Implemented** | Static global scratchpad with regions - correct for embedded. |

---

## Identified Correctness & Security Issues

### 1. ML-KEM Function Name Mismatch (Critical)
**File**: `src/pqc_engine/kem_adapter.c:13-21`
```c
extern int pqcrystals_kyber512_ref_keypair(unsigned char *pk, unsigned char *sk);
```
**Actual pqclean symbols**: `PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair`
**Actual pqm4 symbols**: `crypto_kem_keypair`
**Impact**: Linker errors, cannot build.

### 2. Fake KAT Vectors (Critical)
**Files**: `kem_adapter.c:325-364`, `tests/native/test_kem.c`
All KAT public keys, secret keys, ciphertexts, shared secrets are repeating patterns (`0x9f, 0x7a...`, `0x1a, 0x2b...`), not real FIPS 203 test vectors.
**Impact**: Self-tests pass but verify nothing.

### 3. HKDF Not Exposed as Standalone Module (High)
**File**: `kem_adapter.c:37-78`
`hkdf_extract`/`hkdf_expand` are `static` - not callable by other modules or tests.
**Test file** `tests/native/test_hkdf.c` expects `hkdf.h` with `hkdf_sha256_extract`/`hkdf_sha256_expand`.

### 4. AES-CTR PRG Global State & Counter Bug (High)
**File**: `mask_prg.c:7-17, 43-56`
```c
static struct tc_aes_key_sched_struct g_aes_sched;
static uint8_t g_nonce[16];
static uint8_t g_ctr[16];  // Global counter - not per-instance
```
**Counter bug**: `mask_prg_expand` calls `tc_ctr_mode` then `increment_ctr()` once per 16-byte chunk. But `tc_ctr_mode` internally increments counter for each block. Result: counter advances 2x per chunk.
**Chunking bug**: Generating 32 bytes as `2×16` vs `1×32` produces different output.
**No multi-instance support**: Cannot generate independent mask streams for different client pairs.

### 5. X25519 Fallback Uses Wrong Construction (Medium)
**File**: `kem_adapter.c:155-178`
Uses `uECC_make_key` + `uECC_shared_secret` + AES-CCM encryption of shared secret with ephemeral key as nonce. This is **not** a standard KEM construction (should be ECIES or HPKE).
**Recommendation**: Remove or implement proper X25519-based KEM if needed.

### 6. Missing Shamir C Implementation (Critical)
**Files**: `tests/native/test_shamir.c`, `host_server/shamir_recovery.py`
C tests expect:
- `shamir.h` with `SHAMIR_SECRET_SIZE`, `SHAMIR_WORKSPACE_SIZE`
- `gf3329_add`, `gf3329_sub`, `gf3329_mul`, `gf3329_inv`
- `shamir_share`, `shamir_reconstruct`
Python uses GF(3329) with Barrett reduction (matching ML-KEM field).

### 7. No Error Handling for ML-KEM Decapsulation Failure Mode (Medium)
**File**: `kem_adapter.c:229-233`
ML-KEM decapsulation returns 0 on success **and** on ciphertext verification failure (produces pseudorandom secret). Current code treats non-zero return as error only. Need to document/handle this per FIPS 203.

---

## Existing Dependencies

| Dependency | Version/Source | License | Used For |
|------------|----------------|---------|----------|
| **pqclean ML-KEM-768** | `deps/pqm4/mupq/pqclean/crypto_kem/ml-kem-768/clean/` | CC0 / Apache-2.0 | ML-KEM reference implementation |
| **pqm4 Cortex-M4 ML-KEM-768** | `deps/pqm4/crypto_kem/ml-kem-768/m4fstack/` | CC0 / Apache-2.0 | Optimized Cortex-M4 implementation |
| **TinyCrypt** | GitHub `intel/tinycrypt` (via PlatformIO) | BSD-3-Clause | AES, SHA256, HMAC, CTR, CCM, ECC |
| **libopencm3** | `deps/pqm4/libopencm3` | LGPL-2.1 | STM32 RNG for `randombytes` |

---

## Files Needing Modification

| File | Action Required |
|------|-----------------|
| `src/pqc_engine/kem_adapter.c` | Fix extern declarations to match pqclean/pqm4 symbols; replace fake KATs |
| `src/pqc_engine/kem_adapter.h` | Add HKDF public API declarations; remove X25519 if not needed |
| `src/pqc_engine/hkdf.c/h` **(NEW)** | Extract HKDF from kem_adapter into standalone module |
| `src/pqc_engine/mask_prg.c/h` | Rewrite with per-instance context, fix counter handling |
| `src/pqc_engine/shamir.c/h` **(NEW)** | Implement Shamir SS in C (GF(3329)) |
| `tests/native/test_kem.c` | Replace fake KATs with real FIPS 203 vectors |
| `tests/native/test_hkdf.c` | Update to use new `hkdf.h` API |
| `tests/native/test_shamir.c` | Update to use new `shamir.h` API |
| `platformio.ini` | Ensure pqclean sources are included in build |

---

## Recommended Implementation Order

1. **ML-KEM Integration Fix** - Fix function names, link pqclean, add real KATs
2. **HKDF Module** - Extract to `hkdf.c/h`, expose public API, pass RFC 5869 vectors
3. **Shamir SS Module** - Implement `shamir.c/h` matching Python GF(3329)
4. **PRG Rewrite** - Fix `mask_prg.c` with context struct, proper CTR mode
5. **Test Infrastructure** - Update all test files, add integration tests
6. **Build Verification** - Compile for `native`, `cortex_m4`, `esp32c3`
7. **Documentation** - `crypto_design.md`, `crypto_test_results.md`

---

## Assumptions Needing Confirmation

1. **ML-KEM Variant**: Protocol docs specify ML-KEM-768 default. Confirm no need for 512/1024 variants in production.
2. **X25519 Fallback**: Is classical KEM fallback required? If so, use proper HPKE/ECIES construction.
3. **PRG Per-Instance vs Global**: Protocol derives separate seeds per client-pair/round/chunk. PRG must support multiple concurrent instances.
4. **Shamir Share Format**: Python uses 64-byte shares (32 GF(3329) elements × 2 bytes). Confirm this matches `SHAMIR_SHARE_VALUE_BYTES=32` in `protocol_types.h` (currently 32, but Python uses 64).
5. **Threshold Values**: Protocol uses configurable threshold. Shamir implementation must support arbitrary `t ≤ n ≤ 255`.
6. **Randomness Source**: Embedded targets use STM32 RNG / ESP32 RNG. Need platform-specific `randombytes` implementation.

---

## Next Steps

1. Create `hkdf.h/c` with public API
2. Create `shamir.h/c` with GF(3329) arithmetic
3. Fix `kem_adapter.c` to use correct pqclean symbols
4. Rewrite `mask_prg.c` with context-based API
5. Generate real ML-KEM-768 KAT vectors using pqclean
6. Update all test files
7. Build and run tests on native target