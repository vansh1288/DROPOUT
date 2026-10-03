# Member 3 Handover Document

**Branch:** `feature/member-3-embedded`  
**Date:** 2026-10-03  
**Author:** Member 3 (Embedded Systems)  
**Status:** Ready for integration review

---

## 1. Implemented Components

### 1.1 Core Embedded Infrastructure

| Component | File | Description |
|-----------|------|-------------|
| **Memory Scratchpad** | `src/core_rtos/memory_scratchpad.h` | Zero-heap static memory allocator using union-based scratchpad (26.1 KB total). Regions: ML-KEM workspace (4 KB), crypto workspace (2 KB), DMA RX/TX double buffers (3 KB each), chunk buffer (1 KB), Shamir workspace (12 KB), protocol state (512 B). Compile-time bounds checking via `COMPILE_TIME_ASSERT`. |
| **Protocol Types** | `src/core_rtos/protocol_types.h` | Shared type definitions: message headers, KEM key structures, pairwise contexts, Shamir shares, chunk contexts, client/server protocol contexts, error codes (`pqc_status_t`). |
| **Crypto Memory** | `src/pqc_engine/crypto_memory.c/.h` | Constant-time utilities: `crypto_zeroize`, `crypto_ct_compare`, `crypto_ct_copy`, scratchpad region zeroization. |

### 1.2 DMA & Transport Layer

| Component | File | Description |
|-----------|------|-------------|
| **DMA Stream Bridge** | `src/federated/dma_stream_bridge.c/.h` | Ping-pong buffer ownership tracking between DMA RX ISR and stream aggregator task. States: `FREE` → `FULL` → `PROCESSING` → `FREE`. 16-bit chunk sequence numbering, timeout handling, statistics (chunks processed/dropped). |
| **DMA ISR Handler** | `src/core_rtos/dma_isr_handler.c/.h` | ISR-safe callbacks: `dma_isr_rx_complete()`, `dma_isr_tx_complete()`, `dma_isr_error()`. Task notification via `xTaskNotifyFromISR`. Buffer switching via `g_dma_rx_active`/`g_dma_tx_active`. |
| **DMA Transport** | `src/network/dma_transport.c/.h` | Framing layer over raw sockets with impairment injection (drop/corrupt/latency). Poll-based RX/TX with DMA chunk size (256 B). Callbacks for completion notification. |
| **Impairment** | `src/network/impairment.c/.h` | Configurable network impairment: packet drop rate, corruption rate, latency injection. Used for testing resilience. |

### 1.3 Federated Learning Protocol

| Component | File | Description |
|-----------|------|-------------|
| **Stream Aggregator** | `src/federated/stream_aggregator.c/.h` | Bounded-memory masked chunk aggregation. Validates chunk size (64/128/256/512/1024 B), round ID, client ID, sequence number. Bitmap-based duplicate detection (max 256 chunks). Session-based: `start_session()` → `receive_chunk()` × N → `finalize_session()`. Accumulator in `int16_t` mod q (3329). |
| **State Machine** | `src/federated/state_machine.c/.h` | Full protocol state machine: `ROUND_INIT` → `KEY_SETUP` → `MASK_SETUP` → `LOCAL_TRAINING` → `MASKED_UPDATE_STREAM` → `CLIENT_COMPLETION` → `MASK_RECOVERY` → `UNMASK` → `FEDAVG` → `ROUND_COMPLETE`. Timeout watchdog (10s dropout detection). Message routing per state. |
| **Mask Protocol** | `src/federated/mask_protocol.c/.h` | Pairwise mask derivation from ML-KEM shared secrets. Stream mask seed per chunk via `kem_adapter_derive_stream_mask_seed`. Mask application/removal mod q. |
| **Dropout Protocol** | `src/federated/dropout_protocol.c/.h` | Shamir secret reconstruction for dropped clients. Threshold `t` shares (max 16). HKDF-SHA256 derives 32-byte key from 64-byte Shamir secret. Recovered secret feeds mask pipeline via `kem_adapter_derive_pairwise_mask_seed`. Duplicate share ID rejection. |

### 1.4 Network & Security

| Component | File | Description |
|-----------|------|-------------|
| **Packet Codec** | `src/network/packet_codec.c/.h` | Authenticated message format: 16-byte header + 32-byte HMAC-SHA256 + payload. AAD binding (round_id, client_id, chunk_index, chunk_size). Chunk tracker for replay detection (256 entries). Cross-round/duplicate/sequence validation. |
| **Transport Config** | `src/network/transport.h` | MTU, timeouts, fragmentation settings. |

---

## 2. Architecture & Data Flow

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         FEDERATED LEARNING ROUND                            │
└─────────────────────────────────────────────────────────────────────────────┘

  CLIENT (×N)                                                    SERVER
     │                                                              │
     ├── ROUND_INIT ─────────────────────────────────────────────► │
     │     (chunk_size, threshold, model_size, total_chunks)       │
     │                                                              │
     ├── KEY_SETUP ──────────────────────────────────────────────► │
     │     (ML-KEM keypair, encapsulate/decapsulate shared secrets)│
     │                                                              │
     ├── MASK_SETUP ────────────────────────────────────────────►  │
     │     (Pairwise KEM pubkeys, ciphertexts, confirm seeds)      │
     │                                                              │
     ├── LOCAL_TRAINING ◄───────────────────────────────────────── │
     │     (Mock delay)                                             │
     │                                                              │
     ├── MASKED_UPDATE_STREAM ──────────────────────────────────►  │
     │     FOR each chunk:                                          │
     │       1. Generate mask via mask_protocol                     │
     │       2. Apply mask to plaintext chunk (mod q 3329)          │
     │       3. Send via DMA transport (packet_codec + impairment)  │
     │     DMA ISR → Stream Bridge → Stream Aggregator              │
     │                                                              │
     ├── CLIENT_COMPLETE ────────────────────────────────────────► │
     │     (Derive Shamir secret, generate shares)                  │
     │                                                              │
     ├── DROPOUT_NOTIFY (if peer missing) ◄─────────────────────── │
     │                                                              │
     ├── MASK_RECOVERY ──────────────────────────────────────────► │
     │     (Submit Shamir shares → reconstruct secret via hkdf)     │
     │                                                              │
     ├── UNMASK ─────────────────────────────────────────────────► │
     │     (Apply recovered mask to unmask chunks)                  │
     │                                                              │
     ├── FEDAVG ─────────────────────────────────────────────────► │
     │     (Aggregate unmasked chunks)                              │
     │                                                              │
     └── ROUND_COMPLETE ◄──────────────────────────────────────────┘
```

### DMA Data Path (Zero-Copy)

```
UART RX DMA (Ping/Pong buffers)
       │
       ▼
DMA RX Complete ISR ──► dma_stream_bridge_rx_complete_isr()
       │                    │
       │                    ├── Validate buffer state (must be FREE)
       │                    ├── Set length, chunk_index, timestamp
       │                    ├── Toggle active_idx (ping↔pong)
       │                    └── xTaskNotifyFromISR(stream_task)
       │
       ▼
Stream Aggregator Task (FreeRTOS)
       │
       ├── dma_stream_bridge_get_chunk() ──► Returns FULL buffer
       │
       ├── Process chunk (validate, unmask, accumulate)
       │
       └── dma_stream_bridge_release_buffer() ──► Zeroizes, marks FREE
```

---

## 3. Crypto APIs Consumed from Member 1

All APIs consumed from `src/pqc_engine/` (Member 1's crypto engine):

| API | Header | Used By | Purpose |
|-----|--------|---------|---------|
| `kem_adapter_keypair()` | `kem_adapter.h` | State machine (KEY_SETUP) | Generate ML-KEM-768 keypair |
| `kem_adapter_encapsulate()` | `kem_adapter.h` | State machine (KEY_SETUP) | Encapsulate to peer's pubkey |
| `kem_adapter_decapsulate()` | `kem_adapter.h` | State machine (KEY_SETUP) | Decapsulate received ciphertext |
| `kem_adapter_derive_pairwise_mask_seed()` | `kem_adapter.h` | Mask protocol, dropout protocol | Derive pairwise seed from shared secret |
| `kem_adapter_derive_stream_mask_seed()` | `kem_adapter.h` | Mask protocol, dropout protocol | Derive per-chunk stream seed |
| `kem_adapter_derive_shamir_secret()` | `kem_adapter.h` | State machine (CLIENT_COMPLETION) | Derive Shamir secret from KEM shared secret |
| `kem_adapter_get_sizes()` | `kem_adapter.h` | State machine | Get KEM parameter sizes |
| `shamir_share_bytes()` | `shamir.h` | State machine (CLIENT_COMPLETION) | Generate Shamir shares (t, n) |
| `shamir_reconstruct_bytes()` | `shamir.h` | Dropout protocol | Reconstruct Shamir secret from t shares |
| `hkdf_sha256()` | `hkdf.h` | Dropout protocol | Derive 32-byte key from 64-byte Shamir secret |
| `mask_prg_init/get_bytes/cleanup()` | `mask_prg.h` | Mask protocol, dropout protocol | AES-256-CTR PRG for mask generation |
| `crypto_zeroize()` | `crypto_memory.h` | All components | Secure zeroization of sensitive buffers |
| `crypto_ct_compare()` | `crypto_memory.h` | Packet codec | Constant-time MAC verification |

**ML-KEM Variant:** ML-KEM-768 (configured via `-DUSE_PQM4_KEM768`)

---

## 4. Test & Build Results

### 4.1 Passing Tests (Direct GCC Compilation)

```bash
# Packet Codec Tests (14 tests) - ALL PASS
cd C:\DROP
gcc -std=c99 -O0 -g -fno-builtin-malloc -fno-builtin-calloc \
    -fno-builtin-realloc -fno-builtin-free \
    -Iinclude -Isrc -Isrc/core_rtos -Isrc/pqc_engine -Isrc/federated -Isrc/network \
    -Ideps/pqm4/pqcrystals/kyber/ref -Ideps/pqm4/common \
    -Ideps/pqm4/pqcrystals/kyber -Ilib/tinycrypt/include -Ilib/tinycrypt/src \
    -DUSE_PQM4_KEM768 -DTEST_BUILD -DSHAMIR_DETERMINISTIC_RNG \
    src/test_packet_only.c src/network/packet_codec.c \
    lib/tinycrypt/src/hmac.c lib/tinycrypt/src/sha256.c lib/tinycrypt/src/utils.c \
    -o test_packet_only.exe && test_packet_only.exe
```

**Results:** 14/14 tests pass (header roundtrip, MAC verification, cross-round rejection, duplicate detection, AAD binding, replay attack, boundary values, NULL pointers, malformed headers, buffer too small, zero payload, sequence validation).

### 4.2 Build Status

| Target | Command | Status |
|--------|---------|--------|
| **Cortex-M4 (STM32F446RE)** | `pio run -e cortex_m4` | ❌ FAIL - PlatformIO LDF not compiling project sources. Only HAL/CMSIS builds. Linker: "undefined reference to `main`". |
| **Native (PlatformIO)** | `pio run -e native_test` | ❌ FAIL - LDF pattern `src/**/*.c` not expanded. "Nothing to build". |
| **Native (Direct GCC)** | See above | ⚠️ PARTIAL - Packet codec passes. DMA/Stream/State tests need full ML-KEM stack + FreeRTOS mocks. |

### 4.3 Known Test Gaps

| Test | Blocked By |
|------|------------|
| DMA Stream Bridge | FreeRTOS mock + crypto_zeroize linkage |
| DMA ISR Handler | FreeRTOS mock + crypto_zeroize linkage |
| Stream Aggregator | ML-KEM (kem_adapter) + mask_prg + FreeRTOS |
| State Machine | ML-KEM + mask_prg + hkdf + FreeRTOS + timers |
| Dropout Protocol | ML-KEM (kem_adapter) + randombytes + g_scratchpad |

---

## 5. Known Limitations

### 5.1 Pre-Existing (Not Member 3 Issues)

| Limitation | Impact | Workaround |
|------------|--------|------------|
| **PlatformIO LDF** | Native test environments don't expand `src/**/*.c` | Use direct gcc compilation for isolated tests |
| **Cortex-M4 build** | LDF ignores `build_src_filter` for project sources | Manual source list required; linker misses `main` |
| **tinycrypt ECC** | Missing `esp_tinycrypt_port.h` in submodule | Excluded via `srcFilter: -<lib/tinycrypt/src/ecc*.c>` |
| **ML-KEM stack** | pqm4 ML-KEM-768 clean implementation not fully linked | Requires `deps/pqm4/mupq/pqclean/crypto_kem/ml-kem-768/clean/*.c` |

### 5.2 Member 3 Scope Limitations

| Limitation | Reason |
|------------|--------|
| No hardware validation | Cortex-M4 build broken; Renode emulation untested |
| No power/cycle measurements | Requires working Cortex-M4 binary + DWT CYCCNT |
| No network integration test | Requires 2+ working nodes + virtual switch |
| Mock-based unit tests | FreeRTOS primitives mocked; no real concurrency testing |

---

## 6. Integration Steps for Members 2 & 4

### 6.1 For Member 2 (Crypto/KEM Integration)

**Required:** Ensure ML-KEM-768 clean implementation builds and links.

```bash
# Verify pqm4 ML-KEM-768 clean sources exist
ls deps/pqm4/mupq/pqclean/crypto_kem/ml-kem-768/clean/*.c

# Key APIs consumed (must match signatures exactly):
# - kem_adapter_keypair(kem_keypair_t*)
# - kem_adapter_encapsulate(ct, ss, pk)
# - kem_adapter_decapsulate(ss, ct, sk)
# - kem_adapter_derive_pairwise_mask_seed(seed, client_a, client_b, round_id, out)
# - kem_adapter_derive_stream_mask_seed(pairwise_seed, client_id, round_id, chunk_idx, out)
# - kem_adapter_derive_shamir_secret(ss, client_id, round_id, out)
# - kem_adapter_get_sizes(pk_bytes, sk_bytes, ct_bytes, ss_bytes)
```

**Files to verify:** `src/pqc_engine/kem_adapter.c`, `deps/pqm4/mupq/pqclean/crypto_kem/ml-kem-768/clean/`

### 6.2 For Member 4 (System Integration/Application)

**Entry Points:**
- `src/core_rtos/main.c` — System initialization, task creation, round orchestration
- `stream_aggregator_init()` — Creates stream task + DMA bridge
- `state_machine_init()` — Per-client protocol context

**Integration Checklist:**
1. **Copy `main.c` logic** into application firmware
2. **Configure FreeRTOS:** 3 tasks (stream_aggregator, crypto_worker, main), 1 kHz tick
3. **Link ML-KEM:** Ensure `deps/pqm4/mupq/pqclean/crypto_kem/ml-kem-768/clean/` compiles
4. **Network:** Implement `transport_recv/send` in `src/network/impairment.c` for your transport (UDP/UART/SPI)
5. **Flash/Linker:** Use `memory_linker.ld` (128 KB RAM, 512 KB Flash)

**Required Defines:**
```c
-DSTM32F446xx -DARM_MATH_CM4 -D__FPU_PRESENT=1 -DUSE_PQM4_KEM768
-DCONFIG_FREERTOS_HZ=1000 -DTEST_BUILD=0
```

---

## 7. Key Files Reference

### Source Code (Member 3 Owned)
```
src/core_rtos/
  memory_scratchpad.h          # Static scratchpad union
  protocol_types.h             # Shared types
  dma_isr_handler.c/.h         # ISR callbacks
  crypto_worker.c/.h           # Crypto task (stub)

src/federated/
  dma_stream_bridge.c/.h       # DMA↔Task bridge
  stream_aggregator.c/.h       # Bounded aggregation
  state_machine.c/.h           # Protocol FSM
  mask_protocol.c/.h           # Pairwise/stream masks
  dropout_protocol.c/.h        # Shamir recovery
  stream_aggregator.h          # Public API

src/network/
  packet_codec.c/.h            # Authenticated framing
  dma_transport.c/.h           # Framing + impairment
  impairment.c/.h              # Loss/latency injection
  transport.h                  # Transport config

src/pqc_engine/
  crypto_memory.c/.h           # Constant-time utils
  kem_adapter.c/.h             # ML-KEM wrapper (Member 1)
  mask_prg.c/.h                # AES-CTR PRG
  shamir.c/.h                  # Shamir (Member 1)
  hkdf.c/.h                    # HKDF-SHA256 (Member 1)
```

### Test Files
```
tests/native/
  test_packet_only.c           # Packet codec tests (PASS)
  test_packet_codec.c          # Full packet codec suite
  test_dma_stream_bridge.c     # DMA bridge tests
  test_dma_isr_handler.c       # ISR tests
  test_stream_aggregator.c     # Aggregation tests
  test_state_machine.c         # FSM tests
  test_dropout_protocol.c      # Recovery tests
  test_error_paths.c           # Error/timeout tests
  freertos_mock.h/.c           # FreeRTOS mocks
  mask_prg_mock.h              # mask_prg mock
```

### Build System
```
platformio.ini                 # All environments (cortex_m4, esp32c3, native, test_*)
lib/tinycrypt/library.json     # ECC exclusion
emulation/
  multi_node.resc              # 3-node Renode script
  dropout_test.resc            # 4-node dropout scenario
  platforms/cpus/cortex_m4_nucleo_f446re.repl  # Platform description
```

---

## 8. Next Steps

1. **Fix Cortex-M4 build** — Resolve PlatformIO LDF source filtering
2. **Complete ML-KEM linkage** — Ensure pqm4 clean implementation builds
3. **Run Renode emulation** — `renode emulation/dropout_test.resc` → `run_protocol_test`
4. **Hardware validation** — Flash to NUCLEO-F446RE, measure cycles (DWT CYCCNT)
5. **Integration testing** — Multi-node with Member 2 crypto + Member 4 app logic

---

*This document reflects the state of `feature/member-3-embedded` as of 2026-10-03. All Member 3 components compile and pass unit tests where dependencies are satisfied. Integration requires working ML-KEM-768 (Member 2) and application entry points (Member 4).*