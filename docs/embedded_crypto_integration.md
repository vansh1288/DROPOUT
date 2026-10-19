# Embedded Crypto Integration Guide

**Branch:** `feature/member-1-crypto`  
**Based on:** pqm4 benchmarks + platformio.ini analysis + src/pqc_engine/ code

---

## Supported Targets

| Target | Platform | Framework | Board | Status |
|--------|----------|-----------|-------|--------|
| **Cortex-M4** | ST STM32 | STM32Cube | NUCLEO-F446RE | ⚠️ Needs path fixes |
| **ESP32-C3** | Espressif | ESP-IDF | ESP32-C3-DevKitM-1 | ⚠️ Needs path fixes |
| **Native (x86_64)** | Linux/Windows | native | host | ✅ Working |

---

## Cortex-M4 (STM32F446RE) - ML-KEM-768 Benchmarks

From `deps/pqm4/benchmarks.csv` (m4fstack implementation = stack-optimized):

### Cycle Counts (160 MHz Cortex-M4F)

| Operation | Cycles (mean) | Time @ 160 MHz |
|-----------|---------------|----------------|
| KeyGen | 644,195 | 4.0 ms |
| Encapsulate | 664,654 | 4.2 ms |
| Decapsulate | 714,194 | 4.5 ms |

### Memory Footprint (m4fstack)

| Operation | Stack (bytes) | Peak Stack |
|-----------|---------------|------------|
| KeyGen | 2,820 | ~3 KB |
| Encapsulate | 2,860 | ~3 KB |
| Decapsulate | 2,844 | ~3 KB |

### Flash/ROM (m4fstack)
- `.text`: 13,320 bytes
- `.data`: 0 bytes
- `.bss`: 0 bytes
- **Total**: ~13 KB

### Hardware Acceleration
- **FPU used**: Yes (DSP instructions for NTT)
- **Implementation**: `m4fstack` (stack-optimized) or `m4fspeed` (speed-optimized)

---

## ESP32-C3 (RISC-V) - Estimates

No pqm4 benchmarks for RISC-V ESP32-C3 yet. Estimates based on:

| Metric | Estimate | Basis |
|--------|----------|-------|
| KeyGen | ~1.5M cycles | ~2.3x Cortex-M4 (no DSP) |
| Encapsulate | ~1.5M cycles | ~2.3x Cortex-M4 |
| Decapsulate | ~1.6M cycles | ~2.3x Cortex-M4 |
| Stack (peak) | ~6-8 KB | 2x Cortex-M4 (larger register file) |
| Flash | ~15-20 KB | Clean impl larger than m4fstack |

**Note**: ESP32-C3 lacks DSP instructions; NTT runs in pure software.

---

## Scratchpad Requirements (from `src/core_rtos/memory_scratchpad.h`)

| Region | Size | Alignment | Purpose |
|--------|------|-----------|---------|
| MLKEM_WORKSPACE | 4,096 bytes | 32 bytes | ML-KEM operations |
| CRYPTO_WORKSPACE | 2,048 bytes | 32 bytes | HKDF, AES, general crypto |
| DMA_RX (double) | 3,072 bytes | 32 bytes | DMA receive ping/pong |
| DMA_TX (double) | 3,072 bytes | 32 bytes | DMA transmit ping/pong |
| CHUNK_BUFFER | 1,024 bytes | 32 bytes | Chunk buffering |
| SHAMIR_WORKSPACE | 12,288 bytes | 32 bytes | Shamir share/reconstruct |
| PROTOCOL_STATE | 512 bytes | 32 bytes | Protocol state |
| **TOTAL** | **~26 KB** | 32 bytes | **Global scratchpad** |

### Per-Operation Stack (additional to scratchpad)

| Operation | Additional Stack |
|-----------|------------------|
| `kem_adapter_keypair` | ~1 KB |
| `kem_adapter_encapsulate` | ~1 KB |
| `kem_adapter_decapsulate` | ~1 KB |
| `shamir_share_bytes` | ~500 bytes |
| `shamir_reconstruct_bytes` | ~500 bytes |
| `mask_prg_get_bytes` | ~200 bytes |
| HKDF operations | ~500 bytes |

---

## Thread-Safety Constraints (for Member 3)

### NOT Thread-Safe (Require Serialization)

| Component | Reason | Mitigation |
|-----------|--------|------------|
| `kem_adapter_*` | Uses global MLKEM_WORKSPACE | Mutex or single crypto task |
| `mask_prg_ctx_t` | Internal state (nonce, counter, block_offset) | One context per task |
| Global scratchpad (`g_scratchpad`) | Shared regions | Per-task scratchpad or mutex |
| `randombytes()` | Platform-dependent | Verify HW RNG thread safety |

### Thread-Safe (Reentrant)

| Component | Reason |
|-----------|--------|
| `gf3329_*` arithmetic | Pure functions, no state |
| `hkdf_sha256_*` | Pure functions, caller buffers |
| `crypto_zeroize/crypto_ct_*` | Caller-provided buffers |
| `shamir_reconstruct*` | Read-only inputs, distinct output |

### Recommended Architecture for Member 3

```
┌─────────────────────────────────────────────────────────────┐
│                    Crypto Task (Single Thread)              │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │ KEM Ops     │  │ Mask PRG    │  │ Shamir/HKDF         │  │
│  │ (mutex)     │  │ (per-ctx)   │  │ (reentrant)         │  │
│  └─────────────┘  └─────────────┘  └─────────────────────┘  │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ Dedicated Scratchpad (26 KB)                           │  │
│  └────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Recommended Task Boundaries

### Task 1: Crypto Task (High Priority)
- **Stack**: 8 KB minimum (4 KB scratchpad + 4 KB call frames)
- **Responsibilities**: All KEM operations, mask PRG management
- **Inputs**: Network task → crypto requests via queue
- **Outputs**: Shared secrets, mask seeds → network/aggregation tasks

### Task 2: Network Task (Normal Priority)
- **Responsibilities**: Packet codec, DMA transport, reliability
- **No crypto**: Forwards crypto requests to Crypto Task

### Task 3: Aggregation/Protocol Task (Normal Priority)
- **Responsibilities**: State machine, Shamir reconstruction, FedAvg
- **Uses**: Shamir/HKDF (reentrant) - can call directly or via Crypto Task

### Task 4: Application Task (Low Priority)
- **Responsibilities**: Local training, model management
- **No direct crypto access**

---

## PlatformIO Configuration Fixes Needed

### Cortex-M4 (`cortex_m4` env)
```ini
build_src_filter = +<src/pqc_engine/*.c> +<deps/pqm4/mupq/pqclean/crypto_kem/ml-kem-768/clean/*.c> +<deps/pqm4/common/*.c>
lib_deps = 
    https://github.com/intel/tinycrypt#main
build_flags = 
    -DUSE_PQM4_KEM768
    -Iinclude -Isrc -Isrc/pqc_engine -Ideps/pqm4/mupq/pqclean/crypto_kem/ml-kem-768/clean -Ideps/pqm4/common
```

### ESP32-C3 (`esp32c3` env)
```ini
build_src_filter = +<src/pqc_engine/*.c> +<deps/pqm4/mupq/pqclean/crypto_kem/ml-kem-768/clean/*.c> +<deps/pqm4/common/*.c>
lib_deps = 
    https://github.com/intel/tinycrypt#main
build_flags = 
    -DUSE_PQM4_KEM768
    -Iinclude -Isrc -Isrc/pqc_engine -Ideps/pqm4/mupq/pqclean/crypto_kem/ml-kem-768/clean -Ideps/pqm4/common
```

**Key changes from current:**
- Use `ml-kem-768/clean` not `pqcrystals/kyber/ref`
- Add TinyCrypt as lib_dep (for AES/HMAC in KEM)
- Correct include paths for PQClean

---

## Memory Budget Summary (Cortex-M4, 256 KB RAM)

| Component | Size | Notes |
|-----------|------|-------|
| Global Scratchpad | 26 KB | Static allocation |
| FreeRTOS tasks (4 × 4 KB) | 16 KB | Minimal stacks |
| Network buffers | 8 KB | DMA double-buffer |
| Crypto Task extra stack | 4 KB | KEM call frames |
| Application/heap | ~200 KB | Remaining |
| **Total Used** | **~54 KB** | **21% of RAM** |

---

## Integration Checklist for Member 3

- [ ] Verify FreeRTOS heap size ≥ 64 KB
- [ ] Allocate global scratchpad in `.bss` (32-byte aligned)
- [ ] Create Crypto Task with 8 KB stack
- [ ] Implement crypto request queue (mutex + queue)
- [ ] Initialize ML-KEM variant at startup: `kem_adapter_init(KEMLIB_ML_KEM_768)`
- [ ] Verify HW RNG available on target (`randombytes()` implementation)
- [ ] Test full round-trip: KeyGen → Encapsulate → Decapsulate → Verify
- [ ] Benchmark actual cycle counts on hardware

---

## Known Limitations

1. **PlatformIO paths broken** - Current config uses old `pqcrystals/kyber/ref` paths
2. **TinyCrypt missing** - Required for AES/HMAC in ML-KEM clean impl
3. **ESP32-C3 RNG** - `randombytes()` needs `esp_fill_random()` integration
4. **No hardware AES on STM32F4** - TinyCrypt software AES used
5. **Shamir workspace large** - 12 KB; consider pooling for memory-constrained devices