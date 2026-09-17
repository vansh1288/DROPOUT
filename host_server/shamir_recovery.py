import secrets
from typing import List, Tuple, Dict

FIELD_MODULUS = 3329

def mod_inv(a: int, p: int = FIELD_MODULUS) -> int:
    return pow(a, p - 2, p)

def evaluate_polynomial(coeffs: List[int], x: int, p: int = FIELD_MODULUS) -> int:
    result = 0
    for coeff in reversed(coeffs):
        result = (result * x + coeff) % p
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
            numerator = (numerator * (-xj)) % p
            denominator = (denominator * (xi - xj)) % p
        
        lagrange_coeff = (numerator * mod_inv(denominator, p)) % p
        secret = (secret + yi * lagrange_coeff) % p
    
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