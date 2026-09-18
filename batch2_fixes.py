def fix_shamir_recovery():
    path = r"C:\DROP\host_server\shamir_recovery.py"
    content = '''import secrets
import hmac
import hashlib
from typing import List, Tuple, Dict

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

FIELD_MODULUS = 3329
BARRETT_MULTIPLIER = 20159
BARRETT_SHIFT = 26
CHUNK_ELEMENTS = 128
CHUNK_BYTES = CHUNK_ELEMENTS * 2

def barrett_reduce(a: int) -> int:
    t = (a * BARRETT_MULTIPLIER) >> BARRETT_SHIFT
    r = a - t * FIELD_MODULUS
    if r >= FIELD_MODULUS:
        r -= FIELD_MODULUS
    return r

def mod_inv(a: int, p: int = FIELD_MODULUS) -> int:
    return pow(a, p - 2, p)

def evaluate_polynomial(coeffs: List[int], x: int, p: int = FIELD_MODULUS) -> int:
    result = 0
    for coeff in reversed(coeffs):
        result = barrett_reduce(result * x + coeff)
    return result

def generate_shares(secret: int, n: int, t: int) -> List[Tuple[int, int]]:
    if t > n:
        raise ValueError("Threshold cannot exceed number of shares")
    if secret < 0 or secret >= FIELD_MODULUS:
        raise ValueError("Secret must be in field range")
    
    coeffs = [secret]
    for _ in range(t - 1):
        coeffs.append(secrets.randbelow(FIELD_MODULUS))
    
    shares = []
    for i in range(1, n + 1):
        x = i
        y = evaluate_polynomial(coeffs, x)
        shares.append((x, y))
    return shares

def reconstruct_secret(shares: List[Tuple[int, int]]) -> int:
    if len(shares) < 2:
        raise ValueError("Need at least 2 shares to reconstruct")
    
    secret = 0
    p = FIELD_MODULUS
    
    for i, (xi, yi) in enumerate(shares):
        numerator = 1
        denominator = 1
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            numerator = barrett_reduce(numerator * (-xj % p))
            denominator = barrett_reduce(denominator * ((xi - xj) % p))
        
        lagrange_coeff = barrett_reduce(numerator * mod_inv(denominator, p))
        secret = barrett_reduce(secret + yi * lagrange_coeff)
    
    return secret

def generate_shares_bytes(secret_bytes: bytes, n: int, t: int) -> List[Tuple[int, bytes]]:
    shares_by_byte = []
    for b in secret_bytes:
        shares = generate_shares(b, n, t)
        shares_by_byte.append(shares)
    
    result = []
    for i in range(n):
        x = shares_by_byte[0][i][0]
        y_bytes = bytes(shares_by_byte[j][i][1] for j in range(len(secret_bytes)))
        result.append((x, y_bytes))
    return result

def reconstruct_secret_bytes(shares: List[Tuple[int, bytes]]) -> bytes:
    if not shares:
        raise ValueError("No shares provided")
    num_bytes = len(shares[0][1])
    secret_bytes = bytearray(num_bytes)
    
    for byte_idx in range(num_bytes):
        byte_shares = [(x, y[byte_idx]) for x, y in shares]
        secret_bytes[byte_idx] = reconstruct_secret(byte_shares)
    
    return bytes(secret_bytes)

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = bytes(32)
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    okm = b""
    t = b""
    ctr = 1
    while len(okm) < length:
        h = hmac.new(prk, t + info + bytes([ctr]), hashlib.sha256)
        t = h.digest()
        okm += t
        ctr += 1
    return okm[:length]

def aes_ctr_stream(key: bytes, nonce: bytes, length: int) -> bytes:
    if not CRYPTO_AVAILABLE:
        raise RuntimeError("cryptography library not available")
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(b"\x00" * length) + encryptor.finalize()

def generate_mask_from_seed(seed: bytes, length: int) -> List[int]:
    stream = aes_ctr_stream(seed, bytes(16), length)
    masks = []
    for i in range(0, len(stream), 2):
        if i + 1 < len(stream):
            val = (stream[i] | (stream[i+1] << 8)) % FIELD_MODULUS
            masks.append(val)
        elif i < len(stream):
            val = stream[i] % FIELD_MODULUS
            masks.append(val)
    return masks

def derive_pairwise_mask_seed(shared_secret: bytes, client_a: int, client_b: int, round_id: int) -> bytes:
    info = bytes([client_a, client_b]) + round_id.to_bytes(4, 'big')
    prk = hkdf_extract(b"", shared_secret)
    return hkdf_expand(prk, b"SwiftAgg-PairwiseMask-v1" + info, 32)

def derive_stream_mask_seed(shared_secret: bytes, client_id: int, round_id: int, chunk_index: int) -> bytes:
    info = bytes([client_id]) + round_id.to_bytes(4, 'big') + chunk_index.to_bytes(2, 'big')
    prk = hkdf_extract(b"", shared_secret)
    return hkdf_expand(prk, b"SwiftAgg-StreamMask-v1" + info, 32)

def recover_dropped_client_pairwise_seeds(dropped_client_shared_secret: bytes, round_id: int, peer_ids: List[int], dropped_client_id: int) -> Dict[int, bytes]:
    recovered_seeds = {}
    for peer_id in peer_ids:
        seed = derive_pairwise_mask_seed(dropped_client_shared_secret, min(dropped_client_id, peer_id), max(dropped_client_id, peer_id), round_id)
        recovered_seeds[peer_id] = seed
    return recovered_seeds

def recover_dropped_client_masks(dropped_client_shared_secret: bytes, round_id: int, peer_ids: List[int], dropped_client_id: int, num_chunks: int, chunk_size: int) -> Dict[int, List[int]]:
    recovered_masks = {}
    chunk_bytes = chunk_size * 2
    pairwise_seeds = recover_dropped_client_pairwise_seeds(dropped_client_shared_secret, round_id, peer_ids, dropped_client_id)
    
    for chunk_idx in range(num_chunks):
        combined_mask = [0] * CHUNK_ELEMENTS
        for peer_id in peer_ids:
            seed = pairwise_seeds[peer_id]
            stream_seed = derive_stream_mask_seed(seed, dropped_client_id, round_id, chunk_idx)
            peer_mask = generate_mask_from_seed(stream_seed, chunk_bytes)
            sign = 1 if dropped_client_id < peer_id else -1
            for i in range(min(CHUNK_ELEMENTS, chunk_size)):
                combined_mask[i] = (combined_mask[i] + sign * peer_mask[i]) % FIELD_MODULUS
        recovered_masks[chunk_idx] = combined_mask
    return recovered_masks
'''
    with open(path, "w") as f:
        f.write(content)
    print("Fixed shamir_recovery.py")

def fix_protocol_bridge():
    path = r"C:\DROP\host_server\protocol_bridge.py"
    content = '''import asyncio
import struct
import hashlib
import hmac
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    try:
        import pqcrypto.kem.kyber768 as pq_kem
        OQS_AVAILABLE = False
    except ImportError:
        OQS_AVAILABLE = None

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

PROTOCOL_VERSION = 0x00010000
MSG_TYPE_ROUND_INIT = 0x40
MSG_TYPE_KEM_PUBLIC_KEY = 0x01
MSG_TYPE_KEM_CIPHERTEXT = 0x02
MSG_TYPE_MASK_CHUNK = 0x21
MSG_TYPE_CLIENT_COMPLETE = 0x30
MSG_TYPE_DROPOUT_NOTIFY = 0x31
MSG_TYPE_RECOVERY_COMPLETE = 0x33
MSG_TYPE_ROUND_COMPLETE = 0x41

DEFAULT_CHUNK_ELEMENTS = 128
HEADER_FORMAT = ">IIBBHHH"
HEADER_SIZE = 16

KDF_LABEL_PAIRWISE_MASK = b"SwiftAgg-PairwiseMask-v1"
KDF_LABEL_STREAM_MASK = b"SwiftAgg-StreamMask-v1"
KDF_LABEL_SHAMIR_SECRET = b"SwiftAgg-ShamirSecret-v1"
KDF_LABEL_SESSION_KEY = b"FL-SessionKey-v1"

FIELD_MODULUS = 3329

@dataclass
class MessageHeader:
    protocol_version: int
    round_id: int
    client_id: int
    message_type: int
    sequence_number: int
    payload_length: int
    reserved: int

@dataclass
class ClientState:
    client_id: int
    round_id: int
    public_key: Optional[bytes] = None
    shared_secret: Optional[bytes] = None
    expected_chunks: int = 0
    received_chunks: Dict[int, bytes] = field(default_factory=dict)
    completed: bool = False
    pairwise_seeds: Dict[int, bytes] = field(default_factory=dict)
    stream_seeds: Dict[int, bytes] = field(default_factory=dict)

@dataclass
class RoundState:
    round_id: int
    expected_clients: int
    threshold: int
    chunk_size: int
    model_size: int
    clients: Dict[int, ClientState] = field(default_factory=dict)
    stage: str = "INIT"
    dropout_clients: List[int] = field(default_factory=list)
    unmasked_chunks: Dict[int, List[int]] = field(default_factory=dict)

class ProtocolBridge:
    def __init__(self, host: str = "0.0.0.0", port: int = 8888):
        self.host = host
        self.port = port
        self.rounds: Dict[int, RoundState] = {}
        self.current_round_id: int = 0
        self.server: Optional[asyncio.Server] = None
        self.client_writers: Dict[int, asyncio.StreamWriter] = {}

    async def start(self):
        self.server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        async with self.server:
            await self.server.serve_forever()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        try:
            while True:
                header_data = await reader.readexactly(HEADER_SIZE)
                if not header_data:
                    break
                header = self._parse_header(header_data)
                payload = await reader.readexactly(header.payload_length)
                await self._dispatch_message(header, payload, writer)
        except asyncio.IncompleteReadError:
            pass
        except ConnectionResetError:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    def _parse_header(self, data: bytes) -> MessageHeader:
        values = struct.unpack(HEADER_FORMAT, data)
        return MessageHeader(*values)

    def _build_header(
        self,
        message_type: int,
        round_id: int,
        client_id: int,
        sequence_number: int,
        payload_length: int,
    ) -> bytes:
        return struct.pack(
            HEADER_FORMAT,
            PROTOCOL_VERSION,
            round_id,
            client_id,
            message_type,
            sequence_number,
            payload_length,
            0,
        )

    async def _dispatch_message(
        self,
        header: MessageHeader,
        payload: bytes,
        writer: asyncio.StreamWriter,
    ):
        if header.message_type == MSG_TYPE_KEM_PUBLIC_KEY:
            await self._handle_public_key(header, payload, writer)
        elif header.message_type == MSG_TYPE_MASK_CHUNK:
            await self._handle_mask_chunk(header, payload)
        elif header.message_type == MSG_TYPE_CLIENT_COMPLETE:
            await self._handle_client_complete(header)
        elif header.message_type == MSG_TYPE_DROPOUT_NOTIFY:
            await self._handle_dropout_notify(header, payload)
        elif header.message_type == MSG_TYPE_ROUND_INIT:
            await self._handle_round_init(header, payload)

    async def _handle_round_init(
        self, header: MessageHeader, payload: bytes
    ):
        if header.round_id in self.rounds:
            return
        p = 0
        expected_clients = payload[p]; p += 1
        threshold = payload[p]; p += 1
        chunk_size = (payload[p] | (payload[p+1] << 8)); p += 2
        model_size = (payload[p] | (payload[p+1] << 8) | (payload[p+2] << 16) | (payload[p+3] << 24))
        round_state = RoundState(
            round_id=header.round_id,
            expected_clients=expected_clients,
            threshold=threshold,
            chunk_size=chunk_size,
            model_size=model_size,
        )
        self.rounds[header.round_id] = round_state
        self.current_round_id = header.round_id

    async def _handle_public_key(
        self, header: MessageHeader, payload: bytes, writer: asyncio.StreamWriter
    ):
        round_state = self.rounds.get(header.round_id)
        if not round_state:
            return
        client_state = round_state.clients.get(header.client_id)
        if not client_state:
            client_state = ClientState(
                client_id=header.client_id, round_id=header.round_id
            )
            round_state.clients[header.client_id] = client_state
        client_state.public_key = payload
        self.client_writers[header.client_id] = writer

    async def _handle_mask_chunk(
        self, header: MessageHeader, payload: bytes
    ):
        round_state = self.rounds.get(header.round_id)
        if not round_state:
            return
        client_state = round_state.clients.get(header.client_id)
        if not client_state:
            return
        expected_chunk_bytes = round_state.chunk_size * 2
        if len(payload) != expected_chunk_bytes:
            return
        client_state.received_chunks[header.sequence_number] = payload

    async def _handle_client_complete(self, header: MessageHeader):
        round_state = self.rounds.get(header.round_id)
        if not round_state:
            return
        client_state = round_state.clients.get(header.client_id)
        if client_state:
            client_state.completed = True
            await self._check_round_completion(round_state)

    async def _handle_dropout_notify(self, header: MessageHeader, payload: bytes):
        round_state = self.rounds.get(header.round_id)
        if not round_state:
            return
        if header.client_id not in round_state.dropout_clients:
            round_state.dropout_clients.append(header.client_id)
        await self._trigger_recovery(round_state)
        await self._check_round_completion(round_state)

    def _hkdf_extract(self, salt: bytes, ikm: bytes) -> bytes:
        if not salt:
            salt = bytes(32)
        return hmac.new(salt, ikm, hashlib.sha256).digest()

    def _hkdf_expand(self, prk: bytes, info: bytes, length: int) -> bytes:
        okm = b""
        t = b""
        ctr = 1
        while len(okm) < length:
            h = hmac.new(prk, t + info + bytes([ctr]), hashlib.sha256)
            t = h.digest()
            okm += t
            ctr += 1
        return okm[:length]

    def _derive_pairwise_seed(self, shared_secret: bytes, client_a: int, client_b: int, round_id: int) -> bytes:
        info = bytes([client_a, client_b]) + round_id.to_bytes(4, 'big')
        prk = self._hkdf_extract(b"", shared_secret)
        return self._hkdf_expand(prk, KDF_LABEL_PAIRWISE_MASK + info, 32)

    def _derive_stream_seed(self, shared_secret: bytes, client_id: int, round_id: int, chunk_index: int) -> bytes:
        info = bytes([client_id]) + round_id.to_bytes(4, 'big') + chunk_index.to_bytes(2, 'big')
        prk = self._hkdf_extract(b"", shared_secret)
        return self._hkdf_expand(prk, KDF_LABEL_STREAM_MASK + info, 32)

    def _derive_shamir_secret(self, shared_secret: bytes, client_id: int, round_id: int) -> bytes:
        info = bytes([client_id]) + round_id.to_bytes(4, 'big')
        prk = self._hkdf_extract(b"", shared_secret)
        return self._hkdf_expand(prk, KDF_LABEL_SHAMIR_SECRET + info, 32)

    def _encapsulate(self, pubkey: bytes) -> Tuple[bytes, bytes]:
        if OQS_AVAILABLE is True:
            with oqs.KeyEncapsulation("Kyber768") as kem:
                ct, ss = kem.encap_secret(pubkey)
                return ct, ss
        elif OQS_AVAILABLE is False:
            ct, ss = pq_kem.encapsulate(pubkey)
            return ct, ss
        else:
            raise RuntimeError("No PQC library available")

    def _aes_ctr_stream(self, key: bytes, nonce: bytes, length: int) -> bytes:
        if not CRYPTO_AVAILABLE:
            raise RuntimeError("cryptography library not available")
        cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
        encryptor = cipher.encryptor()
        return encryptor.update(b"\x00" * length) + encryptor.finalize()

    def _generate_mask_from_seed(self, seed: bytes, length: int) -> List[int]:
        stream = self._aes_ctr_stream(seed, bytes(16), length)
        masks = []
        for i in range(0, len(stream), 2):
            if i + 1 < len(stream):
                val = (stream[i] | (stream[i+1] << 8)) % FIELD_MODULUS
                masks.append(val)
            elif i < len(stream):
                val = stream[i] % FIELD_MODULUS
                masks.append(val)
        return masks

    async def _setup_keys_and_masks(self, round_state: RoundState):
        for client_id, client_state in round_state.clients.items():
            if client_state.public_key and not client_state.shared_secret:
                ct, ss = self._encapsulate(client_state.public_key)
                client_state.shared_secret = ss
                header = self._build_header(
                    MSG_TYPE_KEM_CIPHERTEXT,
                    round_state.round_id,
                    0,
                    0,
                    len(ct),
                )
                writer = self.client_writers.get(client_id)
                if writer:
                    writer.write(header + ct)
                    await writer.drain()
        for client_id, client_state in round_state.clients.items():
            if client_state.shared_secret:
                for peer_id, peer_state in round_state.clients.items():
                    if peer_id != client_id and peer_state.shared_secret:
                        seed = self._derive_pairwise_seed(client_state.shared_secret, min(client_id, peer_id), max(client_id, peer_id), round_state.round_id)
                        client_state.pairwise_seeds[peer_id] = seed
        round_state.stage = "MASK_SETUP"

    async def _check_round_completion(self, round_state: RoundState):
        completed = sum(
            1 for c in round_state.clients.values() if c.completed
        )
        surviving = round_state.expected_clients - len(round_state.dropout_clients)
        if completed >= surviving and surviving >= round_state.threshold:
            round_state.stage = "AGGREGATION"
            await self._aggregate_and_broadcast(round_state)
        elif surviving < round_state.threshold:
            round_state.stage = "ERROR"
            await self._handle_round_failure(round_state)

    async def _handle_round_failure(self, round_state: RoundState):
        for client_id, writer in self.client_writers.items():
            if not writer.is_closing():
                header = self._build_header(
                    MSG_TYPE_ERROR,
                    round_state.round_id,
                    0,
                    0,
                    0,
                )
                writer.write(header)
                await writer.drain()

    async def _trigger_recovery(self, round_state: RoundState):
        from shamir_recovery import reconstruct_secret_bytes
        for dropout_id in round_state.dropout_clients:
            shares = []
            for client_id, client_state in round_state.clients.items():
                if client_id == dropout_id:
                    continue
                if client_state.shared_secret:
                    shamir_secret = self._derive_shamir_secret(client_state.shared_secret, dropout_id, round_state.round_id)
                    shares.append((client_id, shamir_secret))
            if len(shares) >= round_state.threshold:
                recovered = reconstruct_secret_bytes(shares)
                round_state.clients[dropout_id].shared_secret = recovered

    def _unmask_aggregated_chunks(self, round_state: RoundState) -> Dict[int, List[int]]:
        num_chunks = round_state.model_size // round_state.chunk_size
        chunk_elements = round_state.chunk_size
        unmasked_chunks: Dict[int, List[int]] = {}
        for i in range(num_chunks):
            unmasked_chunks[i] = [0] * chunk_elements

        for client_id, client_state in round_state.clients.items():
            if client_id in round_state.dropout_clients:
                continue
            for seq_num, chunk_data in client_state.received_chunks.items():
                if seq_num >= num_chunks:
                    continue
                values = struct.unpack(f">{chunk_elements}h", chunk_data)
                for i, val in enumerate(values):
                    unmasked_chunks[seq_num][i] = (
                        unmasked_chunks[seq_num][i] + val
                    ) % FIELD_MODULUS

        for dropout_id in round_state.dropout_clients:
            dropout_state = round_state.clients.get(dropout_id)
            if not dropout_state or not dropout_state.shared_secret:
                continue
            all_peer_ids = [cid for cid in round_state.clients.keys() if cid != dropout_id]
            from shamir_recovery import recover_dropped_client_masks
            recovered_masks = recover_dropped_client_masks(
                dropout_state.shared_secret,
                round_state.round_id,
                all_peer_ids,
                dropout_id,
                num_chunks,
                chunk_elements
            )
            for seq_num in range(num_chunks):
                if seq_num in recovered_masks:
                    for i in range(chunk_elements):
                        unmasked_chunks[seq_num][i] = (
                            unmasked_chunks[seq_num][i] + recovered_masks[seq_num][i]
                        ) % FIELD_MODULUS

        return unmasked_chunks

    async def _aggregate_and_broadcast(self, round_state: RoundState):
        await self._setup_keys_and_masks(round_state)
        await self._trigger_recovery(round_state)
        unmasked_chunks = self._unmask_aggregated_chunks(round_state)
        round_state.unmasked_chunks = unmasked_chunks

        for client_id, writer in self.client_writers.items():
            for seq_num in range(round_state.model_size // round_state.chunk_size):
                chunk_elements = round_state.chunk_size
                result = struct.pack(
                    f">{chunk_elements}h", *unmasked_chunks[seq_num]
                )
                header = self._build_header(
                    MSG_TYPE_ROUND_COMPLETE,
                    round_state.round_id,
                    0,
                    seq_num,
                    len(result),
                )
                writer.write(header + result)
                await writer.drain()
'''
    with open(path, "w") as f:
        f.write(content)
    print("Fixed protocol_bridge.py")

def fix_mask_protocol():
    path = r"C:\DROP\src\federated\mask_protocol.c"
    content = '''#include "protocol_types.h"
#include "memory_scratchpad.h"
#include "kem_adapter.h"
#include "mask_prg.h"
#include <stdint.h>
#include <string.h>

static pairwise_context_t* get_pairwise_ctx(void) {
    protocol_state_buffer_t* proto = scratch_get_proto_state();
    return (pairwise_context_t*)proto->data;
}

static int16_t mod_q(int32_t val) {
    int32_t r = val % 3329;
    if (r < 0) {
        r += 3329;
    }
    return (int16_t)r;
}

pqc_status_t mask_protocol_init_pairwise(pairwise_context_t* ctx, uint8_t num_peers) {
    if (!ctx || num_peers > MAX_PEERS_PER_CLIENT) return ERR_INVALID_ARGUMENT;
    memset(ctx, 0, sizeof(pairwise_context_t));
    ctx->num_peers = num_peers
    return PQC_SUCCESS;
}

pqc_status_t mask_protocol_derive_pairwise_seeds(pairwise_context_t* ctx, uint8_t local_id, const uint8_t* kem_shared_secrets, uint32_t round_id) {
    if (!ctx || !kem_shared_secrets || ctx->num_peers == 0) return ERR_INVALID_ARGUMENT;
    for (uint8_t i = 0; i < ctx->num_peers; i++) {
        uint8_t peer_id = ctx->peers[i].peer_client_id;
        uint8_t client_a = local_id;
        uint8_t client_b = peer_id;
        if (client_a > client_b) {
            uint8_t tmp = client_a;
            client_a = client_b;
            client_b = tmp;
        }
        pqc_status_t ret = kem_adapter_derive_pairwise_mask_seed(
            &kem_shared_secrets[i * ML_KEM_1024_SHARED_SECRET_BYTES],
            client_a, client_b, round_id,
            ctx->peers[i].mask_seed
        );
        if (ret != PQC_SUCCESS) return ret;
        memcpy(ctx->peers[i].shared_secret, &kem_shared_secrets[i * ML_KEM_1024_SHARED_SECRET_BYTES], ML_KEM_1024_SHARED_SECRET_BYTES);
    }
    return PQC_SUCCESS;
}

pqc_status_t mask_protocol_generate_chunk_mask(pairwise_context_t* ctx, uint8_t client_id, uint32_t round_id, uint16_t chunk_index, uint16_t chunk_size, int16_t* output_mask) {
    if (!ctx || !output_mask || chunk_size > 128) return ERR_INVALID_ARGUMENT;
    crypto_zeroize(output_mask, chunk_size * sizeof(int16_t));
    for (uint8_t i = 0; i < ctx->num_peers; i++) {
        uint8_t stream_seed[32];
        pqc_status_t ret = kem_adapter_derive_stream_mask_seed(
            ctx->peers[i].mask_seed, client_id, round_id, chunk_index, stream_seed
        );
        if (ret != PQC_SUCCESS) return ret;
        mask_prg_init(stream_seed);
        int16_t peer_mask[128];
        mask_prg_expand((uint8_t*)peer_mask, chunk_size * sizeof(int16_t));
        int32_t sign = (client_id < ctx->peers[i].peer_client_id) ? 1 : -1;
        for (uint16_t j = 0; j < chunk_size; j++) {
            int32_t val = (int32_t)output_mask[j] + sign * (int32_t)(peer_mask[j] % 3329);
            output_mask[j] = mod_q(val);
        }
        crypto_zeroize(peer_mask, sizeof(peer_mask));
        crypto_zeroize(stream_seed, 32);
    }
    return PQC_SUCCESS;
}

pqc_status_t mask_protocol_apply_mask(const int16_t* input, const int16_t* mask, uint16_t num_elements, int16_t* output) {
    if (!input || !mask || !output) return ERR_INVALID_ARGUMENT;
    for (uint16_t i = 0; i < num_elements; i++) {
        output[i] = mod_q((int32_t)input[i] + (int32_t)mask[i]);
    }
    return PQC_SUCCESS;
}

pqc_status_t mask_protocol_remove_mask(const int16_t* input, const int16_t* mask, uint16_t num_elements, int16_t* output) {
    if (!input || !mask || !output) return ERR_INVALID_ARGUMENT;
    for (uint16_t i = 0; i < num_elements; i++) {
        output[i] = mod_q((int32_t)input[i] - (int32_t)mask[i]);
    }
    return PQC_SUCCESS;
}

pqc_status_t mask_protocol_zeroize_pairwise(pairwise_context_t* ctx) {
    if (!ctx) return ERR_INVALID_ARGUMENT;
    crypto_zeroize(ctx, sizeof(pairwise_context_t));
    return PQC_SUCCESS;
}
'''
    with open(path, "w") as f:
        f.write(content)
    print("Fixed mask_protocol.c")

if __name__ == "__main__":
    fix_shamir_recovery()
    fix_protocol_bridge()
    fix_mask_protocol()
    print("Batch 2 modifications completed successfully.")