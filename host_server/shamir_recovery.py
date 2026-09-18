import secrets
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

def recover_dropped_client_masks(dropped_client_shared_secret: bytes, round_id: int, peer_ids: List[int], dropped_client_id: int, num_chunks: int) -> Dict[int, List[int]]:
    recovered_masks = {}
    for chunk_idx in range(num_chunks):
        combined_mask = [0] * CHUNK_ELEMENTS
        for peer_id in peer_ids:
            seed_info = bytes([min(dropped_client_id, peer_id), max(dropped_client_id, peer_id)]) + round_id.to_bytes(4, 'big') + chunk_idx.to_bytes(2, 'big')
            prk = hmac.new(b"", dropped_client_shared_secret, hashlib.sha256).digest()
            stream_seed = hkdf_expand(prk, b"SwiftAgg-StreamMask-v1" + seed_info, 32)
            peer_mask = generate_mask_from_seed(stream_seed, CHUNK_BYTES)
            sign = 1 if dropped_client_id < peer_id else -1
            for i in range(CHUNK_ELEMENTS):
                combined_mask[i] = (combined_mask[i] + sign * peer_mask[i]) % FIELD_MODULUS
        recovered_masks[chunk_idx] = combined_mask
    return recovered_masks

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
