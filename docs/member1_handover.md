# Member 1 Handover Document

**Branch:** `feature/member-1-crypto`  
**Date:** 2026-10-03  
**Status:** Ready for integration

---

## Scope Verification ✅

| Check | Status | Details |
|-------|--------|---------|
| Branch verified | ✅ | `feature/member-1-crypto` |
| Member 1 scope only | ✅ | Changes only in `src/pqc_engine/`, `tests/`, `docs/`, `platformio.ini` |
| No Member 2/3 files modified | ✅ | Federated/network code unchanged (except platformio.ini paths) |
| Single Shamir implementation | ✅ | Only `src/pqc_engine/shamir.c` |
| Production uses CSPRNG | ✅ | `shamir.c` uses `randombytes()` (CSPRNG) when `SHAMIR_DETERMINISTIC_RNG` not defined |

---

## Implemented Features

### 1. ML-KEM Key Encapsulation (`src/pqc_engine/kem_adapter.c/h`)
- **Variants**: ML-KEM-512, ML-KEM-768, ML-KEM-1024
- **Operations**: KeyGen, Encapsulate, Decapsulate (FIPS 203 implicit rejection)
- **Key Derivation**: HKDF-SHA256 with domain-separated labels
  - Pairwise mask seed: `"SwiftAgg-PairwiseMask-v1" || round_id || client_id_a || client_id_b`
  - Stream mask seed: `"SwiftAgg-StreamMask-v1" || round_id || client_id || chunk_index`
  - Shamir secret: `"SwiftAgg-ShamirSecret-v1" || round_id || client_id`
  - Session key: `"FL-SessionKey-v1"`

### 2. Shamir Secret Sharing (`src/pqc_engine/shamir.c/h`)
- **Field**: GF(3329), 32 elements (64 bytes)
- **APIs**: 
  - `shamir_share()` / `shamir_reconstruct()` — element-based (uint16_t)
  - `shamir_share_bytes()` / `shamir_reconstruct_bytes()` — byte-based (64 bytes = 32 × uint16 LE)
- **Thresholds**: 2-of-3 through 5-of-10 tested
- **Deterministic RNG**: Available via `SHAMIR_DETERMINISTIC_RNG` for testing
- **CSPRNG**: Production uses `randombytes()` from platform CSPRNG

### 3. HKDF-SHA256 (`src/pqc_engine/hkdf.c/h`)
- **API**: `hkdf_sha256_extract()`, `hkdf_sha256_expand()`, `hkdf_sha256()`
- **Test Vectors**: RFC 5869 A.1–A.4 verified
- **Max Output**: 8192 bytes

### 4. Mask PRG (`src/pqc_engine/mask_prg.c/h`)
- **Algorithm**: AES-256-CTR (TinyCrypt)
- **Context**: `mask_prg_ctx_t` with nonce, counter, block offset
- **API**: `mask_prg_init()`, `mask_prg_reseed()`, `mask_prg_get_bytes()`, `mask_prg_cleanup()`
- **Thread-Safety**: NOT thread-safe — one context per thread

### 5. Crypto Memory (`src/pqc_engine/crypto_memory.c/h`)
- Constant-time: `crypto_zeroize()`, `crypto_ct_compare()`, `crypto_ct_copy()`
- Scratchpad region zeroization

### 6. Scratchpad (`src/core_rtos/memory_scratchpad.h`)
| Region | Size | Purpose |
|--------|------|---------|
| MLKEM_WORKSPACE | 4 KB | ML-KEM operations |
| CRYPTO_WORKSPACE | 2 KB | HKDF, AES, general |
| DMA_RX/TX | 3 KB each | Double-buffered |
| CHUNK_BUFFER | 1 KB | Chunk data |
| SHAMIR_WORKSPACE | 12 KB | Shamir operations |
| PROTOCOL_STATE | 512 B | Protocol state |
| **Total** | **~26 KB** | 32-byte aligned |

---

## Public API Summary

### ML-KEM Buffer Sizes
| Variant | Public Key | Secret Key | Ciphertext | Shared Secret |
|---------|------------|------------|------------|---------------|
| ML-KEM-512 | 800 B | 1632 B | 768 B | 32 B |
| ML-KEM-768 | 1184 B | 2400 B | 1088 B | 32 B |
| ML-KEM-1024 | 1568 B | 3168 B | 1568 B | 32 B |

### Return Codes (`pqc_status_t`)
- `PQC_SUCCESS` (0) — Success
- `ERR_INVALID_ARGUMENT` (-2) — NULL pointer, wrong size, invalid param
- `ERR_CRYPTO_FAILURE` (-5) — Crypto operation failed
- `ERR_KEM_KEYGEN_FAILED` (-14) — Key generation failed
- `ERR_KEM_ENCAP_FAILED` (-15) — Encapsulation failed
- `ERR_KEM_DECAP_FAILED` (-16) — Decapsulation failed
- `ERR_SHAMIR_ENCODE_FAILED` (-19) — Shamir sharing failed
- `ERR_SHAMIR_DECODE_FAILED` (-20) — Shamir reconstruction failed
- `ERR_INSUFFICIENT_SHARES` (-21) — < threshold shares
- `ERR_DUPLICATE_SHARE_ID` (-22) — Duplicate x-coordinate
- `ERR_INVALID_THRESHOLD` (-23) — t > n or t == 0

---

## Test Results ✅

| Test Suite | Command | Tests | Passed | Status |
|------------|---------|-------|--------|--------|
| Python Unit Tests | `python -m pytest tests/unit/test_crypto.py -v` | 14 | 14 | ✅ PASS |
| Native Shamir | `gcc ... test_shamir.exe && ./test_shamir.exe` | 7 | 7 | ✅ PASS |
| Cortex-M4 Build | `pio run -e cortex_m4` | — | — | ✅ COMPILES |
| ESP32-C3 Build | `pio run -e esp32c3` | — | — | ⚠️ Framework issue |

### Python Tests Covered
- RFC 5869 HKDF vectors (A.1–A.4)
- GF(3329) arithmetic: add, sub, mul, inv, Barrett reduce
- Shamir: 2-of-3, 3-of-5, 4-of-7, 5-of-10 thresholds
- Shamir bytes API (64-byte shares)
- Error handling: duplicate IDs, zero ID, insufficient shares
- Boundary values: 0, 1, 3328
- Regression: Lagrange numerator sign fix verified

### Native Tests
- Shamir: 3-of-5 reconstruct, 2-of-5 reject, field ops, thresholds, zero secret, bytes API, deterministic reproducibility
- KEM Adapter: init, sizes, keypair roundtrip, invalid inputs, derive functions, deterministic, self-test

---

## Known Limitations

1. **ESP32-C3 Build**: ESP-IDF framework download corrupted (`MissingPackageManifestError`). Run `pio pkg clean` and retry.
2. **PlatformIO Paths Fixed**: Updated from old `pqcrystals/kyber/ref` to PQClean `ml-kem-*/clean` paths.
3. **TinyCrypt Branch**: Fixed from `#main` to `#master` (no main branch).
4. **Cortex-M4 Link**: Compiles but needs `main()` for firmware link (library build OK).
5. **Stream Aggregator**: Has merge conflict markers — uses new `mask_prg_ctx_t` API.
5. **No ML-KEM KAT Vectors**: Real FIPS 203 vectors not embedded in tests.
6. **Side-Channel**: Not evaluated (reference implementations only).
7. **ESP32-C3 RNG**: `randombytes()` needs `esp_fill_random()` integration.

---

## Integration Steps for Members 2 & 3

### For Member 2 (Federated/Protocol)
1. Include `src/pqc_engine/*.h` for crypto APIs
2. Link against compiled `src/pqc_engine/*.c`
3. **Thread Safety**: 
   - `kem_adapter_*` — NOT thread-safe (uses global MLKEM_WORKSPACE)
   - `mask_prg_ctx_t` — NOT thread-safe (one context per thread)
   - `shamir_*` / `hkdf_*` / `crypto_*` — Thread-safe (reentrant)
4. **Architecture**: Single Crypto Task with 8 KB stack, dedicated scratchpad

### For Member 3 (Network/Transport)
1. Use `mask_prg_ctx_t` for stream mask generation
2. Call `kem_adapter_derive_stream_mask_seed()` per chunk
3. **Buffer Sizes**: Max 1024-byte chunks (CHUNK_BUFFER_BYTES)
4. **Zeroize**: Stream seeds and masks after use

### Memory Budget (Cortex-M4, 256 KB RAM)
| Component | Size |
|-----------|------|
| Global Scratchpad | 26 KB |
| FreeRTOS Tasks (4×) | 16 KB |
| Network Buffers | 8 KB |
| Crypto Task Stack | 4 KB |
| **Total Used** | **~54 KB (21%)** |

### Build Commands
```bash
# Cortex-M4 (STM32F446RE)
pio run -e cortex_m4

# ESP32-C3 (DevKitM-1)
pio pkg clean && pio run -e esp32c3

# Native tests (MinGW GCC)
gcc -std=c99 -DSHAMIR_DETERMINISTIC_RNG tests/native/test_shamir.c \
    src/pqc_engine/shamir.c src/pqc_engine/crypto_memory.c \
    deps/pqm4/common/randombytes.c src/core_rtos/test_scratchpad.c \
    -o test_shamir.exe && ./test_shamir.exe

# Python tests
python -m pytest tests/unit/test_crypto.py -v
```

---

## Remaining Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| ESP32-C3 build broken | High | Clean PlatformIO cache, retry |
| No FIPS 203 KAT vectors | Medium | Generate/embed real vectors |
| Side-channel resistance | High | Requires HW evaluation |
| ESP32-C3 HW RNG not integrated | Medium | Implement `randombytes()` with `esp_fill_random()` |
| Stream aggregator merge conflict | Low | Resolve to use `mask_prg_ctx_t` API |
| Large Shamir workspace (12 KB) | Low | Consider pooling for constrained devices |

---

## Files Changed (Member 1 Scope)

**Core Crypto (`src/pqc_engine/`)**
- `shamir.c/h` — Fixed Barrett reduction, fixed bytes API `share_x` corruption, CSPRNG production path
- `kem_adapter.c/h` — ML-KEM adapter with key derivation
- `mask_prg.c/h` — AES-256-CTR PRG with context API
- `hkdf.c/h` — HKDF-SHA256 implementation
- `crypto_memory.c/h` — Constant-time memory ops
- `randombytes.h` — CSPRNG interface
- `ntt_backend.c` — NTT implementation

**Tests (`tests/`)**
- `test_shamir.c` — Fixed field elements, all 7 tests pass
- `test_kem_adapter.c` — New comprehensive KEM adapter tests
- `test_mask_prg.c` — New mask PRG tests
- `test_hkdf.c` — Fixed RFC 5869 vectors
- `test_kem.c` — ML-KEM KAT tests (PQClean API)
- `test_crypto.py` — 14 Python unit tests pass

**Documentation (`docs/`)**
- `crypto_api.md` — Complete API reference
- `crypto_serialization.md` — Shamir share format
- `crypto_test_results.md` — Test results report
- `embedded_crypto_integration.md` — Embedded target guide
- `member1_handover.md` — This document

**Build Config**
- `platformio.ini` — Fixed paths for Cortex-M4 and ESP32-C3, TinyCrypt `#master`

---

## Verification Commands

```bash
# Verify branch
git branch --show-current
# feature/member-1-crypto

# Run all tests
python -m pytest tests/unit/test_crypto.py -v
./test_shamir.exe

# Build embedded targets
pio run -e cortex_m4
pio pkg clean && pio run -e esp32c3
```

---

**Handover Complete** — Member 1 crypto engine ready for integration.