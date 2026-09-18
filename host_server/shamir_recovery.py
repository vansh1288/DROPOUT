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

def recover_mask_seed_from_shares(shares: List[Tuple[int, bytes]]) -> bytes:
    return reconstruct_secret_bytes(shares)
