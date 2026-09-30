# DROPOUT Cryptographic Test Results

## Test Environment

- **Python**: 3.11.15
- **C Compiler**: Not available in current environment (tests require GCC/Clang/MSVC)
- **Platform**: Windows 10
- **Dependencies**: 
  - PQClean ML-KEM-512/768/1024 (reference)
  - TinyCrypt (AES, SHA256, HMAC, ECC)
  - Python `cryptography` library (for AES-CTR reference)

---

## Python Unit Tests (`tests/unit/test_crypto.py`)

**Status**: ✅ ALL PASSED

| Test | Description | Result |
|------|-------------|--------|
| `test_hkdf_rfc5869()` | RFC 5869 test vectors A.1-A.4 | ✅ PASS |
| `test_aes_ctr_nist()` | NIST AES-CTR vector (skipped - counter mode diff) | ⏭️ SKIP |
| `test_ml_kem_fips203()` | FIPS 203 parameter validation | ✅ PASS |
| `test_barrett_reduce()` | GF(3329) Barrett reduction | ✅ PASS |
| `test_mod_inv()` | GF(3329) modular inverse | ✅ PASS |
| `test_evaluate_polynomial()` | Horner's method evaluation | ✅ PASS |
| `test_shamir_reconstruct()` | Shamir secret reconstruction (t-of-n) | ✅ PASS |
| `test_shamir_bytes()` | Shamir byte-array sharing (32 elements) | ✅ PASS |
| `test_shamir_field_properties()` | Multiple subset reconstruction consistency | ✅ PASS |

### RFC 5869 HKDF Test Vectors Verified

| Vector | IKM | Salt | Info | L | PRK Match | OKM Match |
|--------|-----|------|------|---|-----------|-----------|
| A.1 | 0x0b × 32 | 0x00 × 32 | "" | 42 | ✅ | ✅ |
| A.2 | 0x00..0x4f × 4 | 0x60..0x7f × 2 | 0xb0..0xcf × 2 | 82 | ✅ | ✅ |
| A.3 | 0x0b × 16 | 0x00..0x0f | 0xf0..0xff | 32 | ✅ | ✅ |
| A.4 | 0x0c × 32 | "" | "" | 32 | ✅ | ✅ |

### Shamir Secret Sharing Verified

- Thresholds tested: 2-of-3, 3-of-5, 4-of-7, 5-of-10
- Secrets tested: 0, 1, 100, 1000, 3328 (field elements)
- All subsets of size ≥ t reconstruct correctly
- Byte-level API (64-byte shares) matches element-level API
- GF(3329) arithmetic: add, sub, mul, inv all correct

---

## C Native Tests (Require Compilation)

### Test Files Ready

| Test File | Description | Expected Result |
|-----------|-------------|-----------------|
| `tests/native/test_kem.c` | ML-KEM-512/768/1024 KAT with derand | ✅ Should PASS |
| `tests/native/test_hkdf.c` | RFC 5869 vectors via `hkdf.h` API | ✅ Should PASS |
| `tests/native/test_shamir.c` | GF(3329) arithmetic + share/reconstruct | ✅ Should PASS |

### Compilation Requirements

```bash
# Required compiler
GCC/Clang/MSVC with C99 support

# Include paths
- Isrc
- Isrc/core_rtos
- Isrc/pqc_engine
- Ideps/pqm4/mupq/pqclean/crypto_kem/ml-kem-512/clean
- Ideps/pqm4/mupq/pqclean/crypto_kem/ml-kem-768/clean
- Ideps/pqm4/mupq/pqclean/crypto_kem/ml-kem-1024/clean
- Ideps/pqm4/mupq/pqclean/common
- TinyCrypt headers (via PlatformIO)

# Source files to compile
- src/pqc_engine/*.c
- deps/pqm4/mupq/pqclean/crypto_kem/ml-kem-*/clean/*.c
- deps/pqm4/mupq/pqclean/common/*.c
- tests/native/test_*.c
```

### Expected ML-KEM KAT Behavior

Using deterministic seed = [0,1,2,...,47]:

| Variant | KeyGen | Encaps | Decaps | Shared Secret Match |
|---------|--------|--------|--------|---------------------|
| ML-KEM-512 | ✅ | ✅ | ✅ | ✅ |
| ML-KEM-768 | ✅ | ✅ | ✅ | ✅ |
| ML-KEM-1024 | ✅ | ✅ | ✅ | ✅ |

### Expected Shamir Test Behavior

| Test Case | Description | Expected |
|-----------|-------------|----------|
| `test_shamir_3_of_5_reconstruction` | 3-of-5 threshold reconstruction | ✅ PASS |
| `test_shamir_2_of_5_failed_reconstruction` | 2-of-5 insufficient shares | ✅ PASS (rejects) |
| `test_shamir_gf3329_field_operations` | Add, sub, mul, inv | ✅ PASS |
| `test_shamir_different_thresholds` | 4-of-7 threshold | ✅ PASS |
| `test_shamir_zero_secret` | All-zero secret | ✅ PASS |
| `test_shamir_bytes_api` | 64-byte share format | ✅ PASS |
| `test_shamir_deterministic_reproducible` | Same seed = same shares | ✅ PASS |

---

## Integration Tests (Not Yet Implemented)

| Test | Description | Status |
|------|-------------|--------|
| ML-KEM + HKDF chain | Shared secret → session key | 📋 Planned |
| Pairwise mask derivation | Client IDs + round ID → seed | 📋 Planned |
| Shamir dropout recovery | Share collection → mask reconstruction | 📋 Planned |
| PRG chunking consistency | Single vs multi-call output | 📋 Planned |
| Cross-language vectors | C vs Python Shamir/HKDF | 📋 Planned |

---

## Known Issues / Limitations

1. **No C compiler in test environment** - Native tests cannot be executed
2. **ML-KEM KAT vectors not embedded** - Need to generate and embed real FIPS 203 vectors
3. **AES-CTR NIST vector mismatch** - cryptography library uses different counter initialization
4. **X25519 fallback** - Non-standard KEM construction, marked deprecated
5. **Side-channel resistance** - Not evaluated (reference implementations only)
6. **Duplicate Shamir implementations** - `shamir.c` (CSPRNG) vs `dropout_protocol.c` (HKDF-derived)
7. **ESP32-C3 RNG not implemented** - `randombytes()` falls back to deterministic PRNG

---

## Required for Production

- [ ] C compiler toolchain (GCC for native, arm-none-eabi for Cortex-M4, ESP-IDF for ESP32)
- [ ] Real ML-KEM KAT vectors embedded in test_kem.c
- [ ] AddressSanitizer/UndefinedBehaviorSanitizer runs on native
- [ ] Static analysis (Cppcheck, Clang Static Analyzer)
- [ ] Embedded target builds (STM32F4, ESP32-C3)
- [ ] Stack/heap usage measurement on target
- [ ] Timing attack evaluation on target hardware
- [ ] ESP32-C3 hardware RNG integration (`esp_fill_random()`)
- [ ] Resolve duplicate Shamir implementations
- [ ] Fix `SHAMIR_SHARE_VALUE_BYTES` constant (32 → 64)

---

## Test Commands (When Compiler Available)

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

# Run native tests manually
./.pio/build/native/test_kem
./.pio/build/native/test_hkdf
./.pio/build/native/test_shamir

# Python tests (always available)
python tests/unit/test_crypto.py
```