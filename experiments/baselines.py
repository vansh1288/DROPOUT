import os
import sys
import subprocess
import hashlib
import hmac
import secrets
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

try:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    CLASSICAL_CRYPTO_AVAILABLE = True
except ImportError:
    CLASSICAL_CRYPTO_AVAILABLE = False

FIELD_MODULUS = 3329
CHUNK_ELEMENTS = 128
CHUNK_BYTES = CHUNK_ELEMENTS * 2

@dataclass
class ClassicalKeyPair:
    private_key: X25519PrivateKey
    public_key: bytes

@dataclass
class ClassicalSharedSecret:
    shared_secret: bytes
    session_key: bytes

def classical_keypair() -> ClassicalKeyPair:
    if not CLASSICAL_CRYPTO_AVAILABLE:
        raise RuntimeError("Classical crypto not available")
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    return ClassicalKeyPair(private_key=private_key, public_key=public_key)

def classical_ecdh(private_key: X25519PrivateKey, peer_public_key: bytes) -> bytes:
    if not CLASSICAL_CRYPTO_AVAILABLE:
        raise RuntimeError("Classical crypto not available")
    peer_key = X25519PublicKey.from_public_bytes(peer_public_key)
    shared = private_key.exchange(peer_key)
    return shared

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt if salt else b"\x00" * 32,
        info=b"",
        backend=default_backend()
    )
    return hkdf.derive(ikm)

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=b"",
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(prk)

def derive_session_key(shared_secret: bytes, salt: bytes = b"", info: bytes = b"") -> bytes:
    prk = hkdf_extract(salt, shared_secret)
    return hkdf_expand(prk, info + b"FL-SessionKey-v1", 32)

def derive_pairwise_seed(shared_secret: bytes, client_a: int, client_b: int, round_id: int) -> bytes:
    info = bytes([client_a, client_b]) + round_id.to_bytes(4, 'big')
    prk = hkdf_extract(b"", shared_secret)
    return hkdf_expand(prk, b"SwiftAgg-PairwiseMask-v1" + info, 32)

def derive_stream_seed(shared_secret: bytes, client_id: int, round_id: int, chunk_index: int) -> bytes:
    info = bytes([client_id]) + round_id.to_bytes(4, 'big') + chunk_index.to_bytes(2, 'big')
    prk = hkdf_extract(b"", shared_secret)
    return hkdf_expand(prk, b"SwiftAgg-StreamMask-v1" + info, 32)

def derive_shamir_secret(shared_secret: bytes, client_id: int, round_id: int) -> bytes:
    info = bytes([client_id]) + round_id.to_bytes(4, 'big')
    prk = hkdf_extract(b"", shared_secret)
    return hkdf_expand(prk, b"SwiftAgg-ShamirSecret-v1" + info, 32)

def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    if not CLASSICAL_CRYPTO_AVAILABLE:
        raise RuntimeError("Classical crypto not available")
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return ciphertext[:-16], ciphertext[-16:]

def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    if not CLASSICAL_CRYPTO_AVAILABLE:
        raise RuntimeError("Classical crypto not available")
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, aad)

def aes_ctr_stream(key: bytes, nonce: bytes, length: int) -> bytes:
    if not CLASSICAL_CRYPTO_AVAILABLE:
        raise RuntimeError("Classical crypto not available")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
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

def shamir_generate_shares(secret: int, n: int, t: int) -> List[Tuple[int, int]]:
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
        y = 0
        for coeff in reversed(coeffs):
            y = (y * x + coeff) % FIELD_MODULUS
        shares.append((x, y))
    return shares

def shamir_reconstruct_secret(shares: List[Tuple[int, int]]) -> int:
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
            numerator = (numerator * (-xj)) % p
            denominator = (denominator * (xi - xj)) % p
        
        inv_denom = pow(denominator, p - 2, p)
        lagrange_coeff = (numerator * inv_denom) % p
        secret = (secret + yi * lagrange_coeff) % p
    
    return secret

def shamir_generate_shares_bytes(secret_bytes: bytes, n: int, t: int) -> List[Tuple[int, bytes]]:
    shares_by_byte = []
    for b in secret_bytes:
        shares = shamir_generate_shares(b, n, t)
        shares_by_byte.append(shares)
    
    result = []
    for i in range(n):
        x = shares_by_byte[0][i][0]
        y_bytes = bytes(shares_by_byte[j][i][1] for j in range(len(secret_bytes)))
        result.append((x, y_bytes))
    return result

def shamir_reconstruct_secret_bytes(shares: List[Tuple[int, bytes]]) -> bytes:
    if not shares:
        raise ValueError("No shares provided")
    num_bytes = len(shares[0][1])
    secret_bytes = bytearray(num_bytes)
    
    for byte_idx in range(num_bytes):
        byte_shares = [(x, y[byte_idx]) for x, y in shares]
        secret_bytes[byte_idx] = shamir_reconstruct_secret(byte_shares)
    
    return bytes(secret_bytes)

class CryptoMode:
    PQC = "pqc"
    CLASSICAL = "classical"

def get_crypto_mode() -> str:
    return os.environ.get("CRYPTO_MODE", CryptoMode.PQC).lower()

def is_classical_mode() -> bool:
    return get_crypto_mode() == CryptoMode.CLASSICAL

def is_pqc_mode() -> bool:
    return get_crypto_mode() == CryptoMode.PQC
