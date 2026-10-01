# SwiftAgg Protocol Specification

## 1. Protocol States

The protocol operates through 12 explicit states. Each client and the server maintain independent state machines synchronized through message exchanges.

| State ID | State Name | Description |
|----------|------------|-------------|
| 0x00 | ROUND_INIT | Server broadcasts round parameters (expected clients, threshold, chunk size, model size) |
| 0x01 | KEY_SETUP | Clients generate ML-KEM keypairs; server encapsulates to each client |
| 0x02 | MASK_SETUP | Pairwise mask seeds derived via HKDF from client-client KEM shared secrets |
| 0x03 | LOCAL_TRAINING | Clients perform local model training |
| 0x04 | MASKED_UPDATE_STREAM | Clients stream chunked masked updates to server |
| 0x05 | CLIENT_COMPLETION | Client signals completion with sample count |
| 0x06 | AGGREGATION | Server aggregates received masked chunks |
| 0x07 | DROPOUT_DETECTION | Server detects missing clients via timeout/completion check |
| 0x08 | MASK_RECOVERY | Surviving clients reconstruct dropout client's Shamir shares |
| 0x09 | UNMASK | Server cancels dropout masks using reconstructed pairwise seeds |
| 0x0A | FEDAVG | Server computes weighted FedAvg over unmasked chunks |
| 0x0B | ROUND_COMPLETE | Server broadcasts aggregated model to all clients |

### State Transitions

```
ROUND_INIT -> KEY_SETUP -> MASK_SETUP -> LOCAL_TRAINING -> MASKED_UPDATE_STREAM
    -> CLIENT_COMPLETION -> AGGREGATION
    -> (if dropout) DROPOUT_DETECTION -> MASK_RECOVERY -> UNMASK
    -> FEDAVG -> ROUND_COMPLETE
```

---

## 2. Masking Equations

### Pairwise Mask Construction

For each pair of clients (A, B) where A < B:

1. **Shared Secret Establishment**: Client A and Client B perform ML-KEM key exchange to establish shared secret `K_AB`

2. **Mask Seed Derivation**: 
   ```
   seed_AB = HKDF(K_AB, "SwiftAgg-PairwiseMask-v1" || A || B || round_id)
   ```

3. **PRG Expansion**: Each client expands the seed into a mask vector of length `chunk_size`:
   ```
   mask_AB = PRG(seed_AB, chunk_size)
   ```

4. **Sign Assignment**:
   - Client A (lower ID): adds `+mask_AB`
   - Client B (higher ID): adds `-mask_AB`

### Mask Cancellation Proof

For any pair (A, B) where A < B:

```
Client A contribution: +mask_AB
Client B contribution: -mask_AB
Sum: mask_AB(A) + mask_AB(B) = +mask_AB - mask_AB = 0
```

### Aggregate Mask Cancellation

For client C with peers P1, P2, ..., Pn:

```
total_mask_C = sum_{i} sign(C, Pi) * mask_{C,Pi}

Sum over all clients:
sum_C total_mask_C = sum_{all pairs (A,B)} (mask_AB(A) + mask_AB(B))
                   = sum_{all pairs (A,B)} 0
                   = 0
```

### Dropout Mask Recovery

When client D drops out:
1. Surviving clients hold Shamir shares of D's pairwise secrets
2. Threshold reconstruction recovers each `seed_Di` for peer Pi
3. Server regenerates `mask_Di` for each peer Pi
4. Server applies `sign(D, Pi) * mask_Di` to aggregate
5. Result: dropout client's masks cancel as if D had completed

---

## 3. Message Flow Summary

| Phase | Sender | Receiver | Message Type |
|-------|--------|----------|--------------|
| Round Init | Server | All | ROUND_INIT |
| Key Setup | Client | Server | KEM_PUBLIC_KEY |
| Key Setup | Server | Client | KEM_CIPHERTEXT |
| Mask Setup | Client <-> Client | (implicit) | (pairwise KEM) |
| Stream | Client | Server | MASK_CHUNK |
| Complete | Client | Server | CLIENT_COMPLETE |
| Dropout | Server | Survivors | DROPOUT_NOTIFY |
| Recovery | Survivor | Server | SHAMIR_SHARE |
| Recovery Complete | Server | All | RECOVERY_COMPLETE |
| Unmask/Aggregate | Server | Internal | - |
| Result | Server | All | ROUND_COMPLETE |

---

## 4. Security Properties

1. **Server Privacy**: Server never sees individual plaintext updates
2. **Dropout Resilience**: Aggregation completes if surviving clients >= threshold
3. **Replay Protection**: All messages bound to round_id, client_id, sequence_number
4. **Forward Secrecy**: Ephemeral ML-KEM keys per round
5. **Collusion Resistance**: Requires threshold clients to reconstruct dropout masks
