import asyncio
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
        return encryptor.update(b" " * length) + encryptor.finalize()

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
