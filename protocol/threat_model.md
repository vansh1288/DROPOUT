# SwiftAgg Threat Model

## 1. System Boundaries

```
+---------------------+     +---------------------------+
|   Trusted Client    |     |      Curious Server       |
|  (ML-KEM, PRG,      |     |  (Aggregation, Dropout    |
|   Shamir, Local     |<--->|   Detection, FedAvg)      |
|   Training)         |     |                           |
+---------------------+     +---------------------------+
          ^                         ^
          | Network Channel         |
          v                         |
+---------------------+     +---------------------------+
|  Network Attacker   |     |     Malicious Client      |
|  (Passive/Active)   |     |  (Byzantine - OUT OF      |
+---------------------+     |   SCOPE for v1)           |
                            +---------------------------+
```

---

## 2. Adversary Models

### 2.1 Network Attacker (Dolev-Yao Capabilities)

**Capabilities:**
- **Eavesdrop**: Observe all packets on wireless channel
- **Delay**: Hold packets for arbitrary duration
- **Drop**: Selectively discard packets
- **Replay**: Re-transmit previously captured packets
- **Reorder**: Change packet delivery order
- **Inject**: Forge packets with arbitrary payload (cannot forge valid HMAC without session keys)

**Limitations:**
- Cannot break ML-KEM (quantum-resistant KEM)
- Cannot break AES-256-CTR PRG
- Cannot break HMAC-SHA256 authentication
- Cannot compute valid Shamir shares without threshold

### 2.2 Curious Server (Honest-but-Curious)

**Capabilities:**
- Observes all protocol messages
- Knows all client public keys
- Receives all masked chunks
- Controls aggregation and FedAvg computation
- Initiates dropout detection/recovery
- Has access to all server-side randomness

**Goals:**
- Recover individual client plaintext updates
- Infer client data distribution
- Link updates to specific clients across rounds

**Guarantees (What Server CANNOT Do):**
- [X] Cannot decrypt individual client updates from masked chunks
- [X] Cannot distinguish Client A's update from Client B's without collusion
- [X] Cannot forge valid masks for dropout cancellation without threshold clients
- [X] Cannot link masked chunks to specific clients beyond protocol metadata

### 2.3 Client Dropout (Availability Fault)

**Model:**
- Client may fail at any protocol state after ROUND_INIT
- No Byzantine behavior (client either follows protocol or stops)
- Dropout detection via CLIENT_COMPLETE timeout
- Server tracks completion state per client

**Recovery Guarantee:**
- Aggregation succeeds if `surviving_clients >= threshold`
- Dropout client's masks cancelled via Shamir reconstruction
- Final aggregate identical to full-participation case

---

## 3. Security Properties

### 3.1 Confidentiality (IND-CPA for Updates)

**Theorem**: Under ML-KEM-768 IND-CCA2 security and AES-256-CTR PRF security, the server cannot distinguish between two possible client updates given the masked chunks.

**Proof Sketch:**
1. Each client's update masked with pairwise masks summing to zero
2. Server sees only `update_C + sum(masks_C)`
3. Without client-client shared secrets, masks are pseudorandom
3. ML-KEM ensures pairwise secrets unknown to server
4. Therefore `sum(masks_C)` is indistinguishable from random to server

### 3.2 Integrity (Authentication)

**Theorem**: HMAC-SHA256 with session keys derived from ML-KEM shared secrets provides message authentication.

**Properties:**
- All messages bound to: round_id, client_id, message_type, sequence_number
- Replay across rounds rejected (round_id mismatch)
- Replay within round rejected (sequence_number tracking)
- Client impersonation prevented (requires session key from ML-KEM)

### 3.3 Dropout Resilience

**Theorem**: If `n` clients start, `t` threshold, and `d` dropouts where `n - d >= t`, the final aggregate equals the aggregate of all `n` clients' plaintext updates.

**Proof Sketch:**
1. For surviving clients: masks cancel pairwise as normal
2. For dropout client D: surviving clients hold Shamir shares of D's pairwise secrets
3. Threshold reconstruction recovers all `seed_Di`
4. Server regenerates D's masks and applies with correct signs
5. D's contribution cancels identically to completion case
6. FedAvg computes weighted average over all n clients

---

## 4. Out-of-Scope Threats

### 4.1 Malicious/Byzantine Clients
- Clients sending malformed chunks
- Clients using incorrect masks
- Clients colluding to bias aggregate
- **Mitigation**: Out of scope for v1; requires verifiable computation / ZK proofs

### 4.2 Server-Side Denial of Service
- Server refuses to aggregate
- Server drops ROUND_COMPLETE
- **Mitigation**: Client timeout + fallback; out of scope

### 4.3 Side-Channel Attacks
- Timing attacks on ML-KEM/NTT
- Power analysis on MCU
- **Mitigation**: Constant-time implementations; platform-specific hardening

### 4.4 Long-Term Key Compromise
- Forward secrecy provided by ephemeral ML-KEM per round
- Compromise of round N keys does not affect round N-1

---

## 5. Cryptographic Assumptions

| Primitive | Assumption | Parameters |
|-----------|------------|------------|
| ML-KEM | IND-CCA2 (Module-LWE) | ML-KEM-512/768/1024 |
| HKDF-SHA256 | PRF / Random Oracle | 256-bit output |
| AES-256-CTR | PRF / Indistinguishability | 256-bit key, 128-bit nonce |
| HMAC-SHA256 | SUF-CMA | 256-bit key |
| Shamir SS | Information-theoretic | GF(3329), threshold t |

---

## 6. Security Parameter Selection

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| ML-KEM Variant | 768 (default) | NIST Level 3; balanced for MCU |
| Field Modulus | 3329 | ML-KEM native; supports NTT |
| Threshold | configurable | t <= n; typically t = n/2 + 1 |
| Chunk Size | 64-1024 bytes | Tunable; affects SRAM/latency |
| Session Key | 256 bits | HKDF output; AES-256 compatible |

---

## 7. Compliance Checklist

- [X] All messages authenticated with HMAC-SHA256
- [X] All multi-byte fields use big-endian encoding
- [X] Round/client/chunk binding in every message
- [X] Replay detection via sequence numbers
- [X] Pairwise masks cancel exactly (sum = 0)
- [X] Shamir reconstruction requires threshold shares
- [X] Dropout recovery produces identical aggregate
- [X] No dynamic allocation in critical path
- [X] Zeroization of all secrets after use
