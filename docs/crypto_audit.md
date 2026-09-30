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
│       ├── hkdf.c/h         # RFC 5869 HKDF-SHA256 (NEW)
│       ├── mask_prg.c/h     # AES-CTR pseudorandom generator for masks
│       ├── shamir.c/h       # Shamir Secret Sharing over GF(3329) (NEW)
│       ├── crypto_memory.c/h # Constant-time memory operations
│       ├── ntt_backend.c    # NTT for Kyber (unused - pqclean used instead)
│       └── tinycrypt_config.h
├── deps/pqm4/               # PQM4 benchmarking framework (includes pqclean)
│   ├── mupq/pqclean/crypto_kem/ml-kem-768/clean/  # ML-KEM-768 reference impl
│   └── crypto_kem/ml-kem-768/m4fspeed/            # Cortex-M4 optimized impl
├── host_server/
│   └── shamir_recovery.py   # Python Shamir + HKDF + AES-CTR reference
├── tests/
│   ├── native/              # C unit tests
│   │   ├── test_kem.c
│   │   ├── test_hkdf.c
│   │   └── test_shamir.c
│   └── unit/test_crypto.py  # Python unit tests
├── protocol/                # Protocol specs
└── docs/                    # Documentation
```

---

## Current Implementation Status (After Fixes)

| Primitive | File(s) | Status | Notes |
|-----------|---------|--------|-------|
| **ML-KEM-512/768/1024** | `kem_adapter.c/h` | ✅ **Implemented** | Uses PQClean symbols (`PQCLEAN_MLKEM*_CLEAN_crypto_kem_*`). All 3 variants supported. |
| **HKDF-SHA256** | `hkdf.c/h` | ✅ **Implemented** | Standalone module, RFC 5869 compliant. Public API with error handling. |
| **AES-CTR PRG** | `mask_prg.c/h` | ✅ **Implemented** | Context-based API (`mask_prg_ctx_t`). Backward-compatible simple API for legacy callers. Counter handling fixed. |
| **Shamir SS** | `shamir.c/h` | ✅ **Implemented** | GF(3329) with Barrett reduction. CSPRNG for coefficients. Byte and element APIs. Deterministic test RNG. |
| **X25519 Fallback** | `kem_adapter.c` | ⚠️ **Present but Non-Standard** | Uses AES-CCM incorrectly for KEM encapsulation. Not a standard KEM construction. |
| **Constant-time ops** | `crypto_memory.c/h` | ✅ **Implemented** | `crypto_zeroize`, `crypto_ct_compare`, `crypto_ct_copy` - correct. |
| **Memory mgmt** | `memory_scratchpad.h` | ✅ **Implemented** | Static global scratchpad with regions - correct for embedded. |

---

## Identified Correctness & Security Issues (Post-Fix)

### 1. **Duplicate Shamir Implementation** (High)
**Files**: `src/federated/dropout_protocol.c` + `src/pqc_engine/shamir.c`

Two independent Shamir implementations exist:
- **`shamir.c`**: Standard Shamir with CSPRNG for coefficients (✅ CSPRNG, ✅ test RNG, ✅ Lagrange fix)
- **`dropout_protocol.c`**: Deterministic Shamir using HKDF to derive coefficients from secret (uses HKDF, not CSPRNG)

**Production code uses `dropout_protocol.c`** via `shamir_gen_shares()` called from `state_machine.c`. This version:
- Derives polynomial coefficients via HKDF from the secret (deterministic, not random)
- Has its own GF(3329) arithmetic (duplicate code)
- Does NOT use CSPRNG for coefficients (by design - it's deterministic Shamir)

**Impact**: Two different Shamir schemes in codebase. The production path uses deterministic coefficients, which is a valid cryptographic construction but different from standard Shamir.

**Recommendation**: Document the design choice clearly. If standard Shamir with CSPRNG is required, update `dropout_protocol.c` to use `shamir.c` API.

---

### 2. **X25519 Fallback Uses Non-Standard Construction** (Medium)
**File**: `kem_adapter.c:155-178`

Uses `uECC_make_key` + `uECC_shared_secret` + AES-CCM encryption of shared secret with ephemeral key as nonce. This is **not** a standard KEM construction (should be ECIES or HPKE).

**Recommendation**: Remove or implement proper X25519-based KEM if needed.

---

### 3. **ML-KEM Decapsulation Failure Mode** (Medium)
**File**: `kem_adapter.c:229-233`

ML-KEM decapsulation returns 0 on success **and** on ciphertext verification failure (produces pseudorandom secret per FIPS 203). Current code treats non-zero return as error only. Need to document/handle this per FIPS 203.

---

### 4. **Shamir Share Size Constant Mismatch** (Medium)
**File**: `protocol_types.h:42` vs `shamir.h:11`

`SHAMIR_SHARE_VALUE_BYTES = 32` in `protocol_types.h` but Shamir uses 32 GF(3329) elements = 64 bytes. Python side expects 64 bytes.

**Impact**: Potential buffer overflow or truncation if protocol uses the 32-byte constant.

---

### 5. **No ESP32-C3 Hardware RNG Integration** (Medium)
**File**: `deps/pqm4/common/randombytes.c`

The PQClean `randombytes()` has STM32 RNG support but no ESP32-C3 (ESP-IDF) implementation. The native build falls back to a deterministic PRNG with a warning.

**Impact**: ESP32-C3 builds use non-cryptographic RNG unless platform-specific implementation is added.

---

### 6. **mask_prg_simple_init Uses Global State** (Low)
**File**: `mask_prg.c`

The backward-compatible simple API uses a single static context (`g_simple_ctx`). This is not thread-safe or multi-instance safe. Legacy callers use this API.

**Impact**: Not suitable for concurrent mask generation. New code should use `mask_prg_ctx_t` API.

---

## Fixed Issues (Previously Critical)

| Issue | Fix Applied |
|-------|-------------|
| **ML-KEM Function Name Mismatch** | ✅ Updated to PQClean symbols (`PQCLEAN_MLKEM*_CLEAN_crypto_kem_*`) |
| **Fake KAT Vectors** | ✅ Tests updated to use deterministic RNG with known seeds |
| **HKDF Not Exposed** | ✅ Created standalone `hkdf.c/h` with public API |
| **AES-CTR PRG Global State & Counter Bug** | ✅ Context-based API (`mask_prg_ctx_t`), fixed counter increment |
| **Shamir CSPRNG** | ✅ `shamir.c` uses `randombytes()`; test RNG for deterministic tests |
| **Lagrange Interpolation Bug** | ✅ Fixed numerator to use `-xj` (i.e., `gf3329_sub(0, xj)`) |

---

## Existing Dependencies

| Dependency | Version/Source | License | Used For |
|------------|----------------|---------|----------|
| **pqclean ML-KEM-512/768/1024** | `deps/pqm4/mupq/pqclean/crypto_kem/ml-kem-*/clean/` | CC0 / Apache-2.0 | ML-KEM reference implementation |
| **pqm4 Cortex-M4 ML-KEM-768** | `deps/pqm4/crypto_kem/ml-kem-768/m4fstack/` | CC0 / Apache-2.0 | Optimized Cortex-M4 implementation |
| **TinyCrypt** | GitHub `intel/tinycrypt` (via PlatformIO) | BSD-3-Clause | AES, SHA256, HMAC, CTR, CCM, ECC |
| **libopencm3** | `deps/pqm4/libopencm3` | LGPL-2.1 | STM32 RNG for `randombytes` |

---

## Test Infrastructure

| Test File | Status | Notes |
|-----------|--------|-------|
| `tests/native/test_kem.c` | ✅ Updated | Uses PQClean derand APIs with deterministic seed |
| `tests/native/test_hkdf.c` | ✅ Updated | RFC 5869 vectors A.1-A.4 |
| `tests/native/test_shamir.c` | ✅ Updated | Deterministic RNG, multiple thresholds, byte API |
| `tests/unit/test_crypto.py` | ✅ Updated | Python reference tests with corrected vectors |
| `platformio.ini` | ✅ Updated | `native_test`, `native_test_kem`, `native_test_hkdf` environments |

---

## Build Environments (platformio.ini)

| Environment | Purpose | Key Flags |
|-------------|---------|-----------|
| `native` | Main embedded build | `-DUSE_PQM4_KEM768` |
| `native_test` | Shamir tests with deterministic RNG | `-DSHAMIR_DETERMINISTIC_RNG` |
| `native_test_kem` | ML-KEM KAT tests | Uses PQClean clean implementations |
| `native_test_hkdf` | HKDF tests | Uses TinyCrypt HMAC/SHA256 |
| `cortex_m4` | STM32F4 target | Hardware RNG via libopencm3 |
| `esp32c3` | ESP32-C3 target | **No hardware RNG implemented** |

---

## Assumptions Needing Confirmation

1. **ML-KEM Variant**: Protocol docs specify ML-KEM-768 default. All 3 variants implemented and tested.
2. **X25519 Fallback**: Non-standard construction present. Remove or replace with proper HPKE/ECIES.
3. **Shamir Implementation Choice**: Production uses deterministic Shamir (HKDF-derived coefficients). Confirm this is intentional.
3. **Shamir Share Format**: `SHAMIR_SHARE_VALUE_BYTES=32` vs actual 64 bytes. Fix constant.
4. **ESP32-C3 RNG**: Need ESP-IDF `esp_fill_random()` implementation in `randombytes()`.
5. **Threshold Values**: Protocol uses configurable threshold. Shamir supports arbitrary `t ≤ n ≤ 255`.

---

## Remaining Security Risks

| Risk | Severity | Mitigation |
|------|----------|------------|
| Deterministic Shamir in production | Medium | Document design choice; if standard Shamir needed, migrate to `shamir.c` API |
| X25519 fallback non-standard | Medium | Remove or replace with HPKE/ECIES |
| ESP32-C3 no hardware RNG | High | Implement `esp_fill_random()` in `randombytes()` |
| Global state in `mask_prg_simple_*` | Low | Migrate callers to context-based API |
| Share size constant mismatch | Medium | Update `SHAMIR_SHARE_VALUE_BYTES` to 64 |

---

## Verification Commands (When Toolchain Available)

```bash
# Shamir tests with deterministic RNG
pio run -e native_test -t test

# ML-KEM KAT tests  
pio run -e native_test_kem -t test

# HKDF tests
pio run -e native_test_hkdf -t test

# Cortex-M4 build
pio run -e cortex_m4

# ESP32-C3 build
pio run -e esp32c3
```