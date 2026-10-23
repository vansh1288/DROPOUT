"""
host_server/shamir_recovery.py

Two Shamir secret-sharing schemes coexist here deliberately, for two
different kinds of data:

  1. Z_3329 (prime-field) Shamir -- for values that are ALREADY field
     elements in the same ring ML-KEM/the mask arithmetic uses (e.g.
     reconstructing per-chunk mask *values* directly). evaluate_polynomial/
     reconstruct_secret/split_secret_element operate here.

  2. GF(2^8) (byte-exact) Shamir -- for splitting and exactly recovering
     the raw 32-byte KEM shared secret itself. A raw secret byte can be
     anywhere in [0, 255]; packing two such bytes into a little-endian
     uint16 and reducing mod 3329 (as scheme 1 would require) is LOSSY --
     multiple raw values collapse onto the same reduced element, so scheme
     1 cannot losslessly reconstruct arbitrary secret bytes. Use
     split_shared_secret / reconstruct_shared_secret for that instead.

Bug fixes applied in this revision (see protocol_bridge.py's accompanying
notes for the fuller writeup):
  - reconstruct_secret's Lagrange numerator now correctly negates xj
    (numerator = -xj, not xj) -- this was an unresolved merge conflict
    where one branch had the sign bug.
  - split_secret_element / split_secret_bytes added: nothing in the prior
    version of this file could actually SPLIT a secret, only reconstruct,
    so dropout recovery had nothing legitimate to reconstruct FROM.
  - split_shared_secret / reconstruct_shared_secret added (GF(256),
    byte-exact) for the raw shared-secret-recovery use case specifically.
  - Share-index validation (reject index 0, reject duplicate indices)
    restored from the HEAD side of the merge conflict and applied
    consistently to both schemes.
"""

import hashlib
import hmac
import secrets
from typing import Dict, List, Tuple

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# ---------------------------------------------------------------------------
# Scheme 1: Z_3329 prime-field Shamir, for field-element-valued data
# (mask values). NOT for raw secret bytes -- see split_shared_secret below.
# ---------------------------------------------------------------------------

FIELD_MODULUS = 3329
BARRETT_MULTIPLIER = 20159
BARRETT_SHIFT = 26
CHUNK_ELEMENTS = 128
CHUNK_BYTES = CHUNK_ELEMENTS * 2
SECRET_ELEMENTS = 32
SECRET_FIELD_BYTES = SECRET_ELEMENTS * 2  # 64: 32 little-endian uint16 field elements


def barrett_reduce(a: int) -> int:
    t = (a * BARRETT_MULTIPLIER) >> BARRETT_SHIFT
    r = a - t * FIELD_MODULUS
    if r >= FIELD_MODULUS:
        r -= FIELD_MODULUS
    if r < 0:
        r += FIELD_MODULUS
    return r


def mod_inv(a: int, p: int = FIELD_MODULUS) -> int:
    a_reduced = a % p
    if a_reduced == 0:
        raise ZeroDivisionError("cannot invert 0 in Z_p")
    return pow(a_reduced, p - 2, p)


def evaluate_polynomial(coeffs: List[int], x: int, p: int = FIELD_MODULUS) -> int:
    """Horner's method: coeffs[0] is the constant term (the secret)."""
    result = 0
    for coeff in reversed(coeffs):
        result = barrett_reduce(result * x + coeff)
    return result


def _validate_share_indices(indices: List[int], field: int = FIELD_MODULUS) -> None:
    if any(x % field == 0 for x in indices):
        raise ValueError("share index cannot be 0 (0 is reserved for the secret itself)")
    if len(set(indices)) != len(indices):
        raise ValueError("duplicate share indices among supplied shares")


def reconstruct_secret(shares: List[Tuple[int, int]]) -> int:
    """Lagrange interpolation at x=0 over Z_3329. FIXED: numerator uses the
    correctly negated (-xj), matching the standard Lagrange-at-0 formula
    L_i(0) = prod_{j!=i} (0 - x_j) / (x_i - x_j)."""
    if len(shares) < 2:
        raise ValueError("need at least 2 shares to reconstruct")
    _validate_share_indices([x for x, _ in shares])

    secret = 0
    p = FIELD_MODULUS
    for i, (xi, yi) in enumerate(shares):
        numerator = 1
        denominator = 1
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            numerator = (numerator * (-xj)) % p
            denominator = (denominator * ((xi - xj) % p)) % p
        lagrange_coeff = (numerator * mod_inv(denominator, p)) % p
        secret = (secret + yi * lagrange_coeff) % p
    return secret


def split_secret_element(secret_value: int, num_shares: int, threshold: int) -> List[Tuple[int, int]]:
    """Splits one field element (0 <= secret_value < 3329) into num_shares
    points on a random degree-(threshold-1) polynomial whose constant term
    is secret_value. Coefficients are drawn via `secrets` (CSPRNG)."""
    if not (0 <= secret_value < FIELD_MODULUS):
        raise ValueError(f"secret_value must be in [0, {FIELD_MODULUS})")
    if threshold < 2:
        raise ValueError("threshold must be >= 2")
    if num_shares < threshold:
        raise ValueError("num_shares must be >= threshold")
    if num_shares >= FIELD_MODULUS - 1:
        raise ValueError(f"at most {FIELD_MODULUS - 2} shares are representable with nonzero x-coordinates")

    coeffs = [secret_value] + [secrets.randbelow(FIELD_MODULUS) for _ in range(threshold - 1)]
    return [(x, evaluate_polynomial(coeffs, x)) for x in range(1, num_shares + 1)]


def split_secret_bytes(secret_bytes: bytes, num_shares: int, threshold: int) -> List[Tuple[int, bytes]]:
    """Splits a SECRET_FIELD_BYTES (64-byte / 32-element) buffer of ALREADY-
    FIELD-VALUED data. Each little-endian uint16 element is reduced mod
    3329 before splitting -- meaning this function is lossy for arbitrary
    byte buffers and must only be used on genuinely field-valued data
    (e.g. a vector of mask values), never on raw KEM secret bytes."""
    if len(secret_bytes) != SECRET_FIELD_BYTES:
        raise ValueError(f"secret must be exactly {SECRET_FIELD_BYTES} bytes ({SECRET_ELEMENTS} field elements)")

    elements = [
        (secret_bytes[i * 2] | (secret_bytes[i * 2 + 1] << 8)) % FIELD_MODULUS
        for i in range(SECRET_ELEMENTS)
    ]
    per_share_y: Dict[int, bytearray] = {x: bytearray(SECRET_FIELD_BYTES) for x in range(1, num_shares + 1)}
    for elem_idx, value in enumerate(elements):
        for x, y in split_secret_element(value, num_shares, threshold):
            per_share_y[x][elem_idx * 2] = y & 0xFF
            per_share_y[x][elem_idx * 2 + 1] = (y >> 8) & 0xFF
    return [(x, bytes(per_share_y[x])) for x in range(1, num_shares + 1)]


def reconstruct_secret_bytes(shares: List[Tuple[int, bytes]]) -> bytes:
    """Inverse of split_secret_bytes. See its docstring re: lossiness --
    do not use this to recover a raw KEM secret, only field-valued data."""
    if not shares:
        raise ValueError("no shares provided")
    share_value_len = len(shares[0][1])
    if share_value_len != SECRET_FIELD_BYTES:
        raise ValueError(f"share value must be {SECRET_FIELD_BYTES} bytes ({SECRET_ELEMENTS} field elements)")

    secret_elements = [0] * SECRET_ELEMENTS
    for elem_idx in range(SECRET_ELEMENTS):
        elem_shares = []
        for x, y in shares:
            val = y[elem_idx * 2] | (y[elem_idx * 2 + 1] << 8)
            elem_shares.append((x, val % FIELD_MODULUS))
        secret_elements[elem_idx] = reconstruct_secret(elem_shares)

    secret_bytes = bytearray(SECRET_FIELD_BYTES)
    for i, val in enumerate(secret_elements):
        secret_bytes[i * 2] = val & 0xFF
        secret_bytes[i * 2 + 1] = (val >> 8) & 0xFF
    return bytes(secret_bytes)


# ---------------------------------------------------------------------------
# Scheme 2: GF(2^8) byte-exact Shamir, for the raw 32-byte KEM shared secret
# ---------------------------------------------------------------------------

RAW_SECRET_BYTES = 32  # The raw length of an ML-KEM shared secret.
_GF256_REDUCTION_BYTE = 0x1B  # AES/Rijndael polynomial x^8+x^4+x^3+x+1, low byte of x^8's reduction.


def _gf256_mul(a: int, b: int) -> int:
    """Carry-less multiply + reduce, the standard AES MixColumns algorithm.
    Chosen specifically because it needs no precomputed log/antilog table."""
    result = 0
    x = a & 0xFF
    y = b
    for _ in range(8):
        if y & 0x1:
            result ^= x
        carry = x & 0x80
        x = (x << 1) & 0xFF
        if carry:
            x ^= _GF256_REDUCTION_BYTE
        y >>= 1
    return result & 0xFF


def _gf256_pow(a: int, exponent: int) -> int:
    result = 1
    base = a & 0xFF
    e = exponent
    while e > 0:
        if e & 0x1:
            result = _gf256_mul(result, base)
        base = _gf256_mul(base, base)
        e >>= 1
    return result


def _gf256_inv(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError("GF(256) zero element has no multiplicative inverse")
    return _gf256_pow(a, 254)  # Group order 255, so a^254 == a^-1.


def split_shared_secret(secret: bytes, num_shares: int, threshold: int) -> List[Tuple[int, bytes]]:
    """Splits a raw RAW_SECRET_BYTES (32-byte) KEM shared secret into
    num_shares GF(256) shares, losslessly (every byte 0..255 is a valid
    field element here, unlike scheme 1's mod-3329 reduction)."""
    if len(secret) != RAW_SECRET_BYTES:
        raise ValueError(f"secret must be exactly {RAW_SECRET_BYTES} bytes")
    if threshold < 2:
        raise ValueError("threshold must be >= 2")
    if num_shares < threshold:
        raise ValueError("num_shares must be >= threshold")
    if num_shares > 255:
        raise ValueError("GF(256) supports at most 255 shares")

    coefficients: List[bytes] = [secrets.token_bytes(RAW_SECRET_BYTES) for _ in range(threshold - 1)]
    shares: List[Tuple[int, bytes]] = []
    for x in range(1, num_shares + 1):
        y = bytearray(RAW_SECRET_BYTES)
        for byte_pos in range(RAW_SECRET_BYTES):
            acc = 0
            for coeff_bytes in reversed(coefficients):
                acc = _gf256_mul(acc, x) ^ coeff_bytes[byte_pos]
            acc = _gf256_mul(acc, x) ^ secret[byte_pos]
            y[byte_pos] = acc
        shares.append((x, bytes(y)))
    return shares


def reconstruct_shared_secret(shares: List[Tuple[int, bytes]], threshold: int) -> bytes:
    """Lagrange interpolation at x=0 over GF(256). Exact inverse of
    split_shared_secret -- recovers the original 32 raw bytes exactly."""
    distinct_x = {x for x, _ in shares}
    if len(distinct_x) != len(shares):
        raise ValueError("duplicate share indices among supplied shares")
    if any(x == 0 for x, _ in shares):
        raise ValueError("share index cannot be 0")
    if len(shares) < threshold:
        raise ValueError(f"need at least {threshold} shares, got {len(shares)}")

    working = shares[:threshold]
    recovered = bytearray(RAW_SECRET_BYTES)
    for byte_pos in range(RAW_SECRET_BYTES):
        secret_byte = 0
        for i, (xi, yi) in enumerate(working):
            numerator = 1
            denominator = 1
            for k, (xk, _) in enumerate(working):
                if k == i:
                    continue
                numerator = _gf256_mul(numerator, xk)        # (0 - xk) == xk in GF(2)
                denominator = _gf256_mul(denominator, xi ^ xk)  # (xi - xk) == xi XOR xk
            coeff = _gf256_mul(numerator, _gf256_inv(denominator))
            secret_byte ^= _gf256_mul(yi[byte_pos], coeff)
        recovered[byte_pos] = secret_byte
    return bytes(recovered)


# ---------------------------------------------------------------------------
# KDF / mask-generation plumbing (unchanged from the prior version)
# ---------------------------------------------------------------------------

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
            val = (stream[i] | (stream[i + 1] << 8)) % FIELD_MODULUS
            masks.append(val)
        elif i < len(stream):
            val = stream[i] % FIELD_MODULUS
            masks.append(val)
    return masks


def derive_pairwise_mask_seed(shared_secret: bytes, client_a: int, client_b: int, round_id: int) -> bytes:
    info = bytes([client_a, client_b]) + round_id.to_bytes(4, "big")
    prk = hkdf_extract(b"", shared_secret)
    return hkdf_expand(prk, b"SwiftAgg-PairwiseMask-v1" + info, 32)


def derive_stream_mask_seed(shared_secret: bytes, client_id: int, round_id: int, chunk_index: int) -> bytes:
    info = bytes([client_id]) + round_id.to_bytes(4, "big") + chunk_index.to_bytes(2, "big")
    prk = hkdf_extract(b"", shared_secret)
    return hkdf_expand(prk, b"SwiftAgg-StreamMask-v1" + info, 32)


def recover_dropped_client_pairwise_seeds(
    dropped_client_shared_secret: bytes, round_id: int, peer_ids: List[int], dropped_client_id: int
) -> Dict[int, bytes]:
    return {
        peer_id: derive_pairwise_mask_seed(
            dropped_client_shared_secret, min(dropped_client_id, peer_id), max(dropped_client_id, peer_id), round_id
        )
        for peer_id in peer_ids
    }


def recover_dropped_client_masks(
    dropped_client_shared_secret: bytes,
    round_id: int,
    peer_ids: List[int],
    dropped_client_id: int,
    num_chunks: int,
    chunk_size: int,
) -> Dict[int, List[int]]:
    recovered_masks = {}
    chunk_bytes = chunk_size * 2
    pairwise_seeds = recover_dropped_client_pairwise_seeds(
        dropped_client_shared_secret, round_id, peer_ids, dropped_client_id
    )
    for chunk_idx in range(num_chunks):
        combined_mask = [0] * chunk_size
        for peer_id in peer_ids:
            seed = pairwise_seeds[peer_id]
            stream_seed = derive_stream_mask_seed(seed, dropped_client_id, round_id, chunk_idx)
            peer_mask = generate_mask_from_seed(stream_seed, chunk_bytes)
            sign = 1 if dropped_client_id < peer_id else -1
            for i in range(chunk_size):
                combined_mask[i] = (combined_mask[i] + sign * peer_mask[i]) % FIELD_MODULUS
        recovered_masks[chunk_idx] = combined_mask
    return recovered_masks
