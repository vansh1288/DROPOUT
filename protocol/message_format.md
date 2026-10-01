# SwiftAgg Message Format Specification

## 1. Fixed Header Format

Every protocol message begins with a fixed 16-byte header followed by variable-length payload and optional authentication tag.

```
+------------------+------------------+------------------+------------------+
| protocol_version |                  round_id                   |
|    (4 bytes)     |                  (4 bytes)                   |
+------------------+------------------+------------------+------------------+
|  client_id (1B)  | message_type (1B)|       sequence_number (2 bytes)        |
+------------------+------------------+------------------+------------------+
|       payload_length (2 bytes)       |       reserved (2 bytes)        |
+--------------------------------------+----------------------------------+
```

### Header Field Definitions

| Field | Size | Type | Endianness | Description |
|-------|------|------|------------|-------------|
| protocol_version | 4 bytes | uint32 | Big-endian | Protocol version (0x00010000) |
| round_id | 4 bytes | uint32 | Big-endian | Federated round identifier |
| client_id | 1 byte | uint8 | - | Originating client (0 = server) |
| message_type | 1 byte | uint8 | - | Message type enum (see below) |
| sequence_number | 2 bytes | uint16 | Big-endian | Chunk index or message sequence |
| payload_length | 2 bytes | uint16 | Big-endian | Payload length in bytes |
| reserved | 2 bytes | uint16 | Big-endian | Reserved for future use (zero) |

---

## 2. Message Types

| Type | Hex | Name | Direction | Payload Description |
|------|-----|------|-----------|---------------------|
| 0x40 | 64 | ROUND_INIT | Server->Client | expected_clients(1), threshold(1), chunk_size(2), model_size(4) |
| 0x01 | 1 | KEM_PUBLIC_KEY | Client->Server | ML-KEM public key (800/1184/1568 bytes) |
| 0x02 | 2 | KEM_CIPHERTEXT | Server->Client | ML-KEM ciphertext + shared secret (768/1088/1568 bytes) |
| 0x21 | 33 | MASK_CHUNK | Client->Server | Masked chunk data (chunk_size * 2 bytes) |
| 0x30 | 48 | CLIENT_COMPLETE | Client->Server | sample_count (4 bytes) |
| 0x31 | 49 | DROPOUT_NOTIFY | Server->Client | dropout_client_id (1 byte) |
| 0x32 | 50 | SHAMIR_SHARE | Client->Server | share_id (1), share_value (64 bytes) |
| 0x33 | 51 | RECOVERY_COMPLETE | Server->Client | - |
| 0x41 | 65 | ROUND_COMPLETE | Server->Client | Aggregated chunk + telemetry (64 bytes) |
| 0xFF | 255 | ERROR | Any | error_code (1 byte) |

---

## 3. Payload Structures

### ROUND_INIT Payload (10 bytes)
```
Byte 0:          expected_clients (uint8)
Byte 1:          threshold (uint8)
Bytes 2-3:       chunk_size (uint16, big-endian)
Bytes 4-7:       model_size (uint32, big-endian)
Bytes 8-9:       reserved (uint16, zero)
```

### MASK_CHUNK Payload (chunk_size * 2 bytes)
```
Array of int16 values (chunk_size elements), each encoded as 2 bytes big-endian
Total payload length = chunk_size * 2 bytes
```

### CLIENT_COMPLETE Payload (4 bytes)
```
Bytes 0-3: sample_count (uint32, big-endian)
```

### SHAMIR_SHARE Payload (65 bytes)
```
Byte 0:          share_id (uint8, 1-255)
Bytes 1-64:      share_value (64 bytes = 32 GF(3329) elements * 2 bytes)
```

### ROUND_COMPLETE Payload (variable + 64 bytes telemetry)
```
Chunk data:      chunk_size * 2 bytes (int16 array)
Telemetry:       64 bytes (see Telemetry Format below)
```

---

## 4. Authentication Tag

All messages include a 32-byte HMAC-SHA256 tag appended after payload:

```
Tag = HMAC-SHA256(session_key, 
                  protocol_version || round_id || client_id || message_type || 
                  sequence_number || payload)
```

Where `session_key` is derived via HKDF from the client-server ML-KEM shared secret.

---

## 5. Endianness Rules

**All multi-byte fields use big-endian (network) byte order:**

| Field | Encoding |
|-------|----------|
| protocol_version | `(v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF` |
| round_id | Same as above |
| chunk_size | `(v >> 8) & 0xFF, v & 0xFF` |
| sequence_number | `(v >> 8) & 0xFF, v & 0xFF` |
| payload_length | `(v >> 8) & 0xFF, v & 0xFF` |
| model_size | `(v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF` |
| sample_count | Same as model_size |
| int16 array elements | `(v >> 8) & 0xFF, v & 0xFF` |

**Single-byte fields (client_id, message_type, share_id) have no endianness.**

---

## 6. Complete Message Wire Format

```
[16-byte Header][N-byte Payload][32-byte HMAC Tag]
```

Total message length = 16 + payload_length + 32 bytes.

### Example: ROUND_INIT (server->client, chunk_size=128, model_size=1024)

Header (16 bytes):
```
00 01 00 00  00 00 00 01  01  40  00 00  00 0A  00 00
|---proto---|  |---round---|id|type|seq |  len  |rsrv|

Payload (10 bytes):
05 03  00 80  00 00 04 00  00 00
|exp|thr|chunk=128|  model=1024 |rsrv|

HMAC Tag (32 bytes): [computed over header + payload]
```

---

## 7. Chunk Size Constraints

- Minimum: 64 bytes (32 int16 elements)
- Maximum: 1024 bytes (512 int16 elements)
- Must be multiple of 2 bytes (int16 alignment)
- Negotiated per round via ROUND_INIT
- All clients in a round use identical chunk_size
