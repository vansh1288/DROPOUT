# Member 1 Initial Cryptographic Audit Report

## Repository: DROPOUT (Post-Quantum Dropout-Resilient Secure Aggregation)

**Date:** 2026-10-01  
**Auditor:** Member 1 - Cryptography & Secure Aggregation

---

## 1. Repository Structure Overview

```
C:\DROP\
├── src/
│   ├── core_rtos/           # FreeRTOS tasks, protocol types, memory mgmt
│   ├── federated/           # Aggregation protocols, state machines
│   ├── network/             # Transport, DMA, packet codec
│   └── pqc_engine/          # CRYPTOGRAPHIC PRIMITIVES (THIS WORKSTREAM)
│       ├── kem_adapter.c/h  # ML-KEM + HKDF + KDF integration layer
│       ├── hkdf.c/h         # RFC 5869 HKDF-SHA256
│       ├── mask_prg.c/h     # AES-CTR PRG for mask generation
│       ├── shamir.c/h       # Shamir Secret Sharing (GF(3329))
│       ├── crypto_memory.c/h # Constant-time memory ops
│       └── ntt_backend.c    # NTT for Kyber (unused)
├── deps/pqm4/               # PQM4 framework with PQClean implementations
├── host_server/             # Python host-side implementation
├── tests/                   # Unit and integration tests
└── docs/                    # Documentation
```

---

## 2. Cryptographic Implementation Status

| Primitive | File(s) | Status | Critical Issues |
|-----------|---------|--------|-----------------|
| **ML-KEM (512/768/1024)** | `kem_adapter.c/h` | ✅ Implemented | Uses PQClean symbols correctly |
| **HKDF-SHA256** | `hkdf.c/h` | ✅ Implemented | RFC 5869 compliant, proper error handling |
| **AES-CTR PRG** | `mask_prg.c/h` | ⚠️ Partially fixed | Global `g_simple_ctx` for backward compat; not thread-safe |
| **Shamir SS (GF(3329))** | `shamir.c/h` | ⚠️ Two implementations | **DUPLICATE**: `shamir.c` + `dropout_protocol.c` |
| **X25519 Fallback** | `kem_adapter.c` | ❌ Non-standard | AES-CCM construction is NOT a standard KEM |
| **Constant-time ops** | `crypto_memory.c/h` | ✅ Implemented | Proper volatile/ct operations |
| **Memory mgmt** | `memory_scratchpad.h` | ✅ Implemented | Static regions, compile-time checks |

---

## 3. Critical Issues Found

### 3.1 DUPLICATE Shamir Implementation (CRITICAL)

**Files:** `src/pqc_engine/shamir.c/h` vs `src/federated/dropout_protocol.c/h`

| Aspect | `shamir.c` | `dropout_protocol.c` |
|--------|------------|---------------------|
| Randomness | `randombytes()` (CSPRNG) | HKDF from secret (deterministic) |
| Field arithmetic | Barrett reduction | `mod_q()` using `%` operator |
| Lagrange numerator | `gf3329_sub(0, xj)` ✅ | `xk` (INCORRECT - missing negation) |
| Share format | 64 bytes (32×uint16) | 32 bytes only (truncated!) |
| API | `shamir_share/reconstruct_bytes` | `shamir_gen_shares/reconstruct_secret` |

**Production uses:** `dropout_protocol.c` via `state_machine.c:206` calling `shamir_gen_shares()`

**Impact:** Two different Shamir schemes in production. Protocol uses deterministic Shamir with HKDF-derived coefficients and broken Lagrange interpolation.

---

### 3.2 Shamir Share Size Mismatch (CRITICAL)

- `protocol_types.h:42`: `SHAMIR_SHARE_VALUE_BYTES = 32`
- Actual share value in `shamir.c`: 64 bytes (32 field elements × 2 bytes each)
- Python side (`shamir_recovery.py:59`): expects 64 bytes
- `dropout_protocol.c:143`: copies only 32 bytes to `shares[i].value`

**Impact:** Buffer overflow/truncation; Python-C interop broken.

---

### 3.3 Lagrange Interpolation Bug in `dropout_protocol.c` (CRITICAL)

Line 171: `uint16_t num = xk;` should be `num = gf3329_sub(0, xk)` (i.e., `-xk`)

This is the correct Lagrange numerator for interpolation at x=0. The current code computes wrong reconstruction.

---

### 3.3 X25519 Fallback Non-Standard (HIGH)

Lines 146-169 in `kem_adapter.c`: Uses `uECC_shared_secret` + AES-CCM with ephemeral key as key. This is **not** a standard KEM construction (should be ECIES/HPKE).

**Used at:** Lines 121-123, 146-169, 197-214, 344-361

---

### 3.4 ESP32-C3 Hardware RNG Not Implemented (HIGH)

`deps/pqm4/common/randombytes.c` only has STM32 hardware RNG support. For ESP32-C3 (ESP-IDF), it falls back to deterministic PRNG with `#warning`.

**Impact:** ESP32-C3 builds use non-cryptographic randomness.

---

### 3.5 `mask_prg_simple_*` Global State (MEDIUM)

- `g_simple_ctx` and `g_simple_initialized` are global static
- Not thread-safe for FreeRTOS multi-task use
- Used in: `mask_protocol.c`, `dropout_protocol.c`, `stream_aggregator.c`, `baseline_buffered_aggregator.c`

---

### 3.6 Shamir Lagrange Bug in `shamir.c` (FIXED?)

Line 135: `num = gf3329_mul(num, gf3329_sub(0, xj))` - This appears CORRECT (`-xj`)

But need to verify: Lagrange at x=0: `num = ∏(-xj)`, `den = ∏(xi - xj)`

Line 135: `num = gf3329_mul(num, gf3329_sub(0, xj))` ✅ CORRECT

---

### 3.7 Shamir Share Size Constant Mismatch (CRITICAL)

`protocol_types.h:42`: `#define SHAMIR_SHARE_VALUE_BYTES 32`
- Actual share value in `shamir.c`: 64 bytes (32 elements × 2 bytes)
- Python side: expects 64 bytes
- `dropout_protocol.c:143`: `memcpy(shares[i].value, share_values + i * 32, 32)` - only copies 32 bytes!

---

### 3.8 ML-KEM Decapsulation Failure Mode (MEDIUM)

`kem_adapter.c:221-222`: `ret != 0` returns error. But ML-KEM decapsulation returns 0 on BOTH success and implicit rejection (produces pseudorandom secret per FIPS 203).

---

## 4. Test Infrastructure Status

| Test Environment | Status |
|------------------|--------|
| `native_test` (Shamir) | Configured with `-DSHAMIR_DETERMINISTIC_RNG` |
| `native_test_kem` | Configured for ML-KEM KATs |
| `native_test_hkdf` | Configured for HKDF tests |
| Python tests | `tests/unit/test_crypto.py` - passes |
| Native compiler | Not available in environment |

---

## 5. Python-C Interop Issues

| Issue | C Side | Python Side |
|-------|--------|-------------|
| Share size | 32 bytes in struct, 64 actual | 64 bytes expected |
| Share format | 32 bytes in `shamir_share_t.value` | 64 bytes expected |
| Lagrange | `dropout_protocol` broken | Python correct (`-xj` numerator) |
| RNG | `shamir.c` uses `randombytes()` | Python uses `secrets.randbelow()` |

---

## 6. Build Configuration Issues

| Issue | Location |
|-------|----------|
| `native_test` includes `deps/pqm4/pqcrystals/kyber/ref` but not PQClean | `platformio.ini:96` |
| `native_test_kem` includes PQClean but not `common/randombytes.c` | `platformio.ini:125` |
| `-DSHAMIR_DETERMINISTIC_RNG` only on `native_test` | `platformio.ini:117` |

---

## 6. Summary of Required Fixes (Priority Order)

| Priority | Issue | Files to Modify |
|----------|-------|-----------------|
| 1 | Unify Shamir implementation | `shamir.c/h`, `dropout_protocol.c/h`, `state_machine.c`, `protocol_types.h` |
| 2 | Fix Shamir share size (32→64 bytes) | `protocol_types.h`, `dropout_protocol.c`, `shamir.c/h` |
| 3 | Fix Lagrange interpolation in `dropout_protocol.c` | `dropout_protocol.c:171` |
| 4 | Implement ESP32-C3 hardware RNG | `deps/pqm4/common/randombytes.c` |
| 5 | Remove/replace X25519 fallback | `kem_adapter.c/h` |
| 6 | Migrate `mask_prg_simple_*` to context API | `mask_prg.c/h`, `mask_protocol.c`, `dropout_protocol.c`, `stream_aggregator.c` |
| 7 | Fix ML-KEM decapsulation error handling | `kem_adapter.c:216-229` |
| 8 | Fix test build configs | `platformio.ini` |

---

## 7. Files to Create/Update

| File | Action |
|------|--------|
| `docs/member1_initial_audit.md` | This report |
| `docs/shamir_share_format.md` | Document share format |
| `docs/crypto_audit.md` | Update existing |
| `docs/crypto_test_results.md` | Update existing |
| `docs/crypto_design.md` | Update existing |
| `src/pqc_engine/shamir.c/h` | Canonical implementation |
| `src/federated/dropout_protocol.c/h` | Remove duplicate Shamir |
| `src/federated/state_machine.c` | Use canonical Shamir API |
| `src/core_rtos/protocol_types.h` | Fix `SHAMIR_SHARE_VALUE_BYTES` |
| `deps/pqm4/common/randombytes.c` | Add ESP32-C3 RNG |
| `src/pqc_engine/mask_prg.c/h` | Complete context API migration |
| `src/federated/*.c` | Migrate to context API |
| `tests/native/test_shamir.c` | Add comprehensive tests |
| `platformio.ini` | Fix build configs |
| `docs/crypto_audit.md` | Update |
| `docs/crypto_test_results.md` | Update |
| `docs/crypto_design.md` | Update |
| `docs/shamir_share_format.md` | Create |

---

## 8. Recommended Implementation Order

1. **Fix Shamir share size constant** (immediate - breaks C-Python interop)
2. **Unify Shamir implementation** - remove `dropout_protocol.c` duplicate, use `shamir.c/h` as canonical
3. **Fix Lagrange interpolation** in both implementations
4. **Implement ESP32-C3 RNG**
5. **Fix X25519 fallback** or remove
6. **Complete PRG context API migration**
7. **Fix ML-KEM decapsulation error handling**
8. **Add comprehensive tests**
9. **Update documentation**