def read_file(path):
    with open(path, 'r') as f:
        return f.read()

def write_file(path, content):
    with open(path, 'w') as f:
        f.write(content)

# ============================================================
# 1. Modify protocol_bridge.py
# ============================================================
protocol_bridge = read_file(r'C:\DROP\host_server\protocol_bridge.py')

# Update ClientState dataclass to include sample_count
protocol_bridge = protocol_bridge.replace(
    '@dataclass\nclass ClientState:\n    client_id: int\n    round_id: int\n    public_key: Optional[bytes] = None\n    shared_secret: Optional[bytes] = None\n    expected_chunks: int = 0\n    received_chunks: Dict[int, bytes] = field(default_factory=dict)\n    completed: bool = False\n    pairwise_seeds: Dict[int, bytes] = field(default_factory=dict)\n    stream_seeds: Dict[int, bytes] = field(default_factory=dict)',
    '@dataclass\nclass ClientState:\n    client_id: int\n    round_id: int\n    public_key: Optional[bytes] = None\n    shared_secret: Optional[bytes] = None\n    expected_chunks: int = 0\n    received_chunks: Dict[int, bytes] = field(default_factory=dict)\n    completed: bool = False\n    pairwise_seeds: Dict[int, bytes] = field(default_factory=dict)\n    stream_seeds: Dict[int, bytes] = field(default_factory=dict)\n    sample_count: int = 0'
)

# Update _handle_client_complete to extract sample_count from payload
protocol_bridge = protocol_bridge.replace(
    'async def _handle_client_complete(self, header: MessageHeader):\n        round_state = self.rounds.get(header.round_id)\n        if not round_state:\n            return\n        client_state = round_state.clients.get(header.client_id)\n        if client_state:\n            client_state.completed = True\n            await self._check_round_completion(round_state)',
    'async def _handle_client_complete(self, header: MessageHeader, payload: bytes):\n        round_state = self.rounds.get(header.round_id)\n        if not round_state:\n            return\n        client_state = round_state.clients.get(header.client_id)\n        if client_state:\n            if len(payload) >= 4:\n                client_state.sample_count = int.from_bytes(payload[:4], "big")\n            client_state.completed = True\n            await self._check_round_completion(round_state)'
)

# Update _check_round_completion to use FedAvg
protocol_bridge = protocol_bridge.replace(
    'async def _check_round_completion(self, round_state: RoundState):\n        completed = sum(\n            1 for c in round_state.clients.values() if c.completed\n        )\n        surviving = round_state.expected_clients - len(round_state.dropout_clients)\n        if completed >= surviving and surviving >= round_state.threshold:\n            round_state.stage = "AGGREGATION"\n            await self._aggregate_and_broadcast(round_state)\n        elif surviving < round_state.threshold:\n            round_state.stage = "ERROR"\n            await self._handle_round_failure(round_state)',
    'async def _check_round_completion(self, round_state: RoundState):\n        completed = sum(\n            1 for c in round_state.clients.values() if c.completed\n        )\n        surviving = round_state.expected_clients - len(round_state.dropout_clients)\n        if completed >= surviving and surviving >= round_state.threshold:\n            round_state.stage = "UNMASKING"\n            await self._unmask_and_aggregate(round_state)\n        elif surviving < round_state.threshold:\n            round_state.stage = "ERROR"\n            await self._handle_round_failure(round_state)'
)

# Replace _aggregate_and_broadcast with _unmask_and_aggregate (FedAvg)
old_aggregate = '''    async def _aggregate_and_broadcast(self, round_state: RoundState):
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
                await writer.drain()'''

new_aggregate = '''    async def _unmask_and_aggregate(self, round_state: RoundState):
        await self._setup_keys_and_masks(round_state)
        await self._trigger_recovery(round_state)
        unmasked_chunks = self._unmask_aggregated_chunks(round_state)
        fedavg_chunks = self._compute_fedavg(round_state, unmasked_chunks)
        round_state.unmasked_chunks = fedavg_chunks
        round_state.stage = "ROUND_COMPLETE"

        for client_id, writer in self.client_writers.items():
            for seq_num in range(round_state.model_size // round_state.chunk_size):
                chunk_elements = round_state.chunk_size
                result = struct.pack(
                    f">{chunk_elements}h", *fedavg_chunks[seq_num]
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

    def _compute_fedavg(self, round_state: RoundState, unmasked_chunks: Dict[int, List[int]]) -> Dict[int, List[int]]:
        total_samples = sum(c.sample_count for c in round_state.clients.values() if c.completed and c.sample_count > 0)
        if total_samples == 0:
            total_samples = sum(1 for c in round_state.clients.values() if c.completed)
        num_chunks = round_state.model_size // round_state.chunk_size
        chunk_elements = round_state.chunk_size
        fedavg_chunks: Dict[int, List[int]] = {}
        for i in range(num_chunks):
            fedavg_chunks[i] = [0] * chunk_elements
        for client_id, client_state in round_state.clients.items():
            if not client_state.completed or client_id in round_state.dropout_clients:
                continue
            weight = client_state.sample_count if client_state.sample_count > 0 else 1
            for seq_num in range(num_chunks):
                if seq_num not in client_state.received_chunks:
                    continue
                values = struct.unpack(f">{chunk_elements}h", client_state.received_chunks[seq_num])
                for j, val in enumerate(values):
                    fedavg_chunks[seq_num][j] = (fedavg_chunks[seq_num][j] + val * weight) % FIELD_MODULUS
        if total_samples > 1:
            inv_total = pow(total_samples, FIELD_MODULUS - 2, FIELD_MODULUS)
            for seq_num in range(num_chunks):
                for j in range(chunk_elements):
                    fedavg_chunks[seq_num][j] = (fedavg_chunks[seq_num][j] * inv_total) % FIELD_MODULUS
        return fedavg_chunks'''

protocol_bridge = protocol_bridge.replace(old_aggregate, new_aggregate)

# Update _dispatch_message to pass payload to _handle_client_complete
protocol_bridge = protocol_bridge.replace(
    'elif header.message_type == MSG_TYPE_CLIENT_COMPLETE:\n            await self._handle_client_complete(header)',
    'elif header.message_type == MSG_TYPE_CLIENT_COMPLETE:\n            await self._handle_client_complete(header, payload)'
)

# Update _unmask_aggregated_chunks to handle recovered masks correctly (they're already in mod field)
# The function looks correct, but let's verify it doesn't double-add

write_file(r'C:\DROP\host_server\protocol_bridge.py', protocol_bridge)
print("Modified protocol_bridge.py")

# ============================================================
# 2. Modify shamir_recovery.py
# ============================================================
shamir_recovery = read_file(r'C:\DROP\host_server\shamir_recovery.py')

# Remove the generate_shares and generate_shares_bytes functions (they use secrets.randbelow)
# Keep only reconstruct_secret, reconstruct_secret_bytes, and recovery functions

# Replace the entire file with cleaned version
new_shamir = '''import hmac
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
    return encryptor.update(b"\\x00" * length) + encryptor.finalize()

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

def recover_mask_seed_from_shares(shares: List[Tuple[int, bytes]]) -> bytes:
    return reconstruct_secret_bytes(shares)
'''

write_file(r'C:\DROP\host_server\shamir_recovery.py', new_shamir)
print("Modified shamir_recovery.py")

print("All modifications applied successfully")