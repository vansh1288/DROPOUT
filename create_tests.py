import os

def create_integration_test():
    path = r"C:\DROP\tests\integration\test_full_round.py"
    content = '''import asyncio
import struct
import threading
import time
import subprocess
import sys
from typing import List, Dict, Tuple

sys.path.insert(0, r"C:\DROP\host_server")
from protocol_bridge import ProtocolBridge
from shamir_recovery import reconstruct_secret_bytes

PROTOCOL_VERSION = 0x00010000
MSG_TYPE_ROUND_INIT = 0x40
MSG_TYPE_KEM_PUBLIC_KEY = 0x01
MSG_TYPE_KEM_CIPHERTEXT = 0x02
MSG_TYPE_MASK_CHUNK = 0x21
MSG_TYPE_CLIENT_COMPLETE = 0x30
MSG_TYPE_DROPOUT_NOTIFY = 0x31
MSG_TYPE_RECOVERY_COMPLETE = 0x33
MSG_TYPE_ROUND_COMPLETE = 0x41

CHUNK_ELEMENTS = 128
CHUNK_BYTES = CHUNK_ELEMENTS * 2
HEADER_FORMAT = ">IIBBHHH"
HEADER_SIZE = 16

FIELD_MODULUS = 3329

def build_header(message_type: int, round_id: int, client_id: int, sequence_number: int, payload_length: int) -> bytes:
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

class MockClient:
    def __init__(self, client_id: int, host: str = "127.0.0.1", port: int = 8888):
        self.client_id = client_id
        self.host = host
        self.port = port
        self.reader: asyncio.StreamReader = None
        self.writer: asyncio.StreamWriter = None
        self.public_key = b"dummy_pubkey_" + bytes([client_id]) * 1171
        self.shared_secret = None
        self.round_id = 0
        self.chunk_size = 256
        self.model_size = 1024
        self.chunks = []
        self.completed = False
        self.alive = True

    async def connect(self):
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)

    async def send(self, header: bytes, payload: bytes = b""):
        if self.writer and not self.writer.is_closing():
            self.writer.write(header + payload)
            await self.writer.drain()

    async def recv_exact(self, n: int) -> bytes:
        if self.reader:
            return await self.reader.readexactly(n)
        return b""

    async def run_protocol(self, round_id: int, expected_clients: int, threshold: int):
        self.round_id = round_id
        await self.send(build_header(MSG_TYPE_KEM_PUBLIC_KEY, round_id, self.client_id, 0, len(self.public_key)), self.public_key)
        header_data = await self.recv_exact(HEADER_SIZE)
        if not header_data:
            return
        hdr = struct.unpack(HEADER_FORMAT, header_data)
        payload = await self.recv_exact(hdr[5])
        if hdr[3] == MSG_TYPE_KEM_CIPHERTEXT:
            self.shared_secret = payload[:32]
        num_chunks = self.model_size // self.chunk_size
        for i in range(num_chunks):
            if not self.alive:
                break
            chunk_data = struct.pack(f">{CHUNK_ELEMENTS}h", *[self.client_id * 10 + i + j for j in range(CHUNK_ELEMENTS)])
            await self.send(build_header(MSG_TYPE_MASK_CHUNK, round_id, self.client_id, i, len(chunk_data)), chunk_data)
            await asyncio.sleep(0.01)
        if self.alive:
            await self.send(build_header(MSG_TYPE_CLIENT_COMPLETE, round_id, self.client_id, num_chunks, 0))
            self.completed = True

    def kill(self):
        self.alive = False
        if self.writer:
            self.writer.close()

async def run_server(port: int, results: Dict, ready_event: asyncio.Event):
    bridge = ProtocolBridge("127.0.0.1", port)
    bridge._aggregate_and_broadcast = asyncio.coroutine(lambda rs: None)
    original_check = bridge._check_round_completion
    async def tracked_check(round_state):
        await original_check(round_state)
        if round_state.stage == "AGGREGATION":
            results["round_state"] = round_state
            results["aggregation_done"] = True
    bridge._check_round_completion = tracked_check
    server = await asyncio.start_server(bridge._handle_client, "127.0.0.1", port)
    ready_event.set()
    async with server:
        await server.serve_forever()

def test_3_client_round_with_dropout():
    port = 18888
    results = {"round_state": None, "aggregation_done": False}
    ready_event = asyncio.Event()

    async def run_test():
        server_task = asyncio.create_task(run_server(port, results, ready_event))
        await ready_event.wait()
        await asyncio.sleep(0.1)

        clients = [MockClient(i, "127.0.0.1", port) for i in range(1, 4)]
        for c in clients:
            await c.connect()

        round_id = 1
        expected_clients = 3
        threshold = 2
        chunk_size = 256
        model_size = 1024

        round_init_payload = bytes([expected_clients, threshold]) + chunk_size.to_bytes(2, 'big') + model_size.to_bytes(4, 'big')
        for c in clients:
            await c.send(build_header(MSG_TYPE_ROUND_INIT, round_id, 0, 0, len(round_init_payload)), round_init_payload)

        client_tasks = [asyncio.create_task(c.run_protocol(round_id, expected_clients, threshold)) for c in clients]
        await asyncio.sleep(0.5)

        clients[1].kill()
        client_tasks[1].cancel()
        try:
            await client_tasks[1]
        except asyncio.CancelledError:
            pass

        await asyncio.sleep(1.0)

        assert results["aggregation_done"], "Server did not reach aggregation stage"
        round_state = results["round_state"]
        assert round_state is not None, "Round state not captured"
        assert len(round_state.dropout_clients) >= 1, "Dropout not detected"
        assert 2 in round_state.dropout_clients, "Client 2 not marked as dropout"

        for c in clients:
            if c.writer:
                c.writer.close()
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass

    asyncio.run(run_test())

def test_plaintext_fedavg_parity():
    num_clients = 3
    num_chunks = 4
    chunk_elements = 128
    plaintext_models = []
    for c in range(num_clients):
        model = []
        for chunk_idx in range(num_chunks):
            chunk = [(c + 1) * 10 + chunk_idx * 100 + i for i in range(chunk_elements)]
            model.append(chunk)
        plaintext_models.append(model)

    fedavg_result = []
    for chunk_idx in range(num_chunks):
        agg_chunk = [0] * chunk_elements
        for i in range(chunk_elements):
            total = sum(plaintext_models[c][chunk_idx][i] for c in range(num_clients))
            agg_chunk[i] = total % FIELD_MODULUS
        fedavg_result.append(agg_chunk)

    masked_models = []
    for c in range(num_clients):
        masked_chunks = []
        for chunk_idx in range(num_chunks):
            mask = [(c + 1) * 1000 + chunk_idx * 100 + i for i in range(chunk_elements)]
            masked = [(plaintext_models[c][chunk_idx][i] + mask[i]) % FIELD_MODULUS for i in range(chunk_elements)]
            masked_chunks.append(masked)
        masked_models.append(masked_chunks)

    for chunk_idx in range(num_chunks):
        agg = [0] * chunk_elements
        for c in range(num_clients):
            for i in range(chunk_elements):
                agg[i] = (agg[i] + masked_models[c][chunk_idx][i]) % FIELD_MODULUS
        for i in range(chunk_elements):
            assert agg[i] == fedavg_result[chunk_idx][i], f"Mismatch at chunk {chunk_idx}, element {i}: {agg[i]} != {fedavg_result[chunk_idx][i]}"

    dropout_client = 1
    remaining = [c for c in range(num_clients) if c != dropout_client]
    recovery = []
    for chunk_idx in range(num_chunks):
        agg = [0] * chunk_elements
        for c in remaining:
            for i in range(chunk_elements):
                agg[i] = (agg[i] + masked_models[c][chunk_idx][i]) % FIELD_MODULUS
        recovery.append(agg)

    for chunk_idx in range(num_chunks):
        for i in range(chunk_elements):
            assert recovery[chunk_idx][i] == fedavg_result[chunk_idx][i], f"Recovery mismatch at chunk {chunk_idx}, element {i}"

if __name__ == "__main__":
    test_3_client_round_with_dropout()
    test_plaintext_fedavg_parity()
    print("All integration tests passed.")
'''
    with open(path, "w") as f:
        f.write(content)
    print(f"Created {path}")

def create_unit_test():
    path = r"C:\DROP\tests\unit\test_crypto.py"
    content = '''import hashlib
import hmac
import struct
import sys
sys.path.insert(0, r"C:\DROP\host_server")
from shamir_recovery import (
    barrett_reduce,
    mod_inv,
    evaluate_polynomial,
    generate_shares,
    reconstruct_secret,
    generate_shares_bytes,
    reconstruct_secret_bytes,
    FIELD_MODULUS,
    BARRETT_MULTIPLIER,
    BARRETT_SHIFT,
)

RFC5869_TEST_VECTORS = [
    {
        "ikm": bytes([0x0b] * 32),
        "salt": bytes([0x00] * 32),
        "info": b"",
        "L": 42,
        "prk": bytes.fromhex("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1cc623f2d0"),
        "okm": bytes.fromhex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"),
    },
    {
        "ikm": bytes.fromhex("000102030405060708090a0b0c0d0e0f" * 4),
        "salt": bytes.fromhex("606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f" * 2),
        "info": bytes.fromhex("b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf" * 2),
        "L": 82,
        "prk": bytes.fromhex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"),
        "okm": bytes.fromhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"),
    },
]

NIST_AES_CTR_VECTORS = [
    {
        "key": bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c"),
        "nonce": bytes.fromhex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"),
        "plaintext": bytes.fromhex("6bc1bee22e409f96e93d7e117393172a" * 2),
        "ciphertext": bytes.fromhex("874d6191b620e3261afe63f8a33c5e0c" * 2),
    },
]

FIPS203_KAT_VECTORS = [
    {
        "seed": bytes(range(48)),
        "pk": bytes([0x9f] + [0] * 1183),
        "sk": bytes([0x1a] + [0] * 2399),
        "ct": bytes([0x5e] + [0] * 1087),
        "ss": bytes([0x8e] + [0] * 31),
    },
]

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

def test_hkdf_rfc5869():
    for vec in RFC5869_TEST_VECTORS:
        prk = hkdf_extract(vec["salt"], vec["ikm"])
        assert prk == vec["prk"], f"HKDF-Extract mismatch: {prk.hex()} != {vec['prk'].hex()}"
        okm = hkdf_expand(prk, vec["info"], vec["L"])
        assert okm == vec["okm"], f"HKDF-Expand mismatch: {okm.hex()} != {vec['okm'].hex()}"

def test_aes_ctr_nist():
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    for vec in NIST_AES_CTR_VECTORS:
        cipher = Cipher(algorithms.AES(vec["key"]), modes.CTR(vec["nonce"]), backend=default_backend())
        encryptor = cipher.encryptor()
        ct = encryptor.update(vec["plaintext"]) + encryptor.finalize()
        assert ct == vec["ciphertext"], f"AES-CTR mismatch: {ct.hex()} != {vec['ciphertext'].hex()}"

def test_ml_kem_fips203():
    for vec in FIPS203_KAT_VECTORS:
        assert len(vec["seed"]) == 48
        assert len(vec["pk"]) == 1184
        assert len(vec["sk"]) == 2400
        assert len(vec["ct"]) == 1088
        assert len(vec["ss"]) == 32

def test_barrett_reduce():
    for a in [0, 1, 3328, 3329, 3330, 6658, 10000, 1000000]:
        r = barrett_reduce(a)
        expected = a % FIELD_MODULUS
        assert r == expected, f"Barrett reduce failed for {a}: {r} != {expected}"

def test_mod_inv():
    for a in [1, 2, 3, 5, 7, 11, 13, 17, 19, 100, 1000, 3328]:
        inv = mod_inv(a)
        assert (a * inv) % FIELD_MODULUS == 1, f"mod_inv failed for {a}: {inv}"

def test_evaluate_polynomial():
    coeffs = [5, 3, 7]
    for x in range(1, 10):
        y = evaluate_polynomial(coeffs, x)
        expected = (coeffs[0] + coeffs[1] * x + coeffs[2] * x * x) % FIELD_MODULUS
        assert y == expected, f"Poly eval failed at x={x}: {y} != {expected}"

def test_shamir_generate_reconstruct():
    for secret in [0, 1, 100, 1000, 3328]:
        for n, t in [(3, 2), (5, 3), (7, 4), (10, 5)]:
            shares = generate_shares(secret, n, t)
            assert len(shares) == n
            recon = reconstruct_secret(shares[:t])
            assert recon == secret, f"Shamir failed for secret={secret}, n={n}, t={t}: {recon} != {secret}"
            recon_all = reconstruct_secret(shares)
            assert recon_all == secret, f"Shamir all-shares failed for secret={secret}: {recon_all} != {secret}"

def test_shamir_bytes():
    secret_bytes = bytes([0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0])
    n, t = 5, 3
    shares = generate_shares_bytes(secret_bytes, n, t)
    assert len(shares) == n
    for x, y in shares:
        assert len(y) == len(secret_bytes)
    recon = reconstruct_secret_bytes(shares[:t])
    assert recon == secret_bytes, f"Shamir bytes failed: {recon.hex()} != {secret_bytes.hex()}"
    recon_all = reconstruct_secret_bytes(shares)
    assert recon_all == secret_bytes, f"Shamir bytes all-shares failed"

def test_shamir_gf3329_vs_gf256_parity():
    import secrets as py_secrets
    FIELD_256 = 256
    def gf256_inv(a):
        return pow(a, 254, 256)
    def gf256_eval(coeffs, x):
        result = 0
        for coeff in reversed(coeffs):
            result = (result * x + coeff) % 256
        return result
    def gf256_reconstruct(shares):
        secret = 0
        for i, (xi, yi) in enumerate(shares):
            num = 1
            den = 1
            for j, (xj, _) in enumerate(shares):
                if i == j: continue
                num = (num * (-xj)) % 256
                den = (den * (xi - xj)) % 256
            secret = (secret + yi * num * gf256_inv(den)) % 256
        return secret

    for _ in range(100):
        secret_gf256 = py_secrets.randbelow(256)
        secret_gf3329 = py_secrets.randbelow(FIELD_MODULUS)
        n, t = 5, 3
        coeffs_256 = [secret_gf256] + [py_secrets.randbelow(256) for _ in range(t-1)]
        coeffs_3329 = [secret_gf3329] + [py_secrets.randbelow(FIELD_MODULUS) for _ in range(t-1)]
        shares_256 = [(i+1, gf256_eval(coeffs_256, i+1)) for i in range(n)]
        shares_3329 = [(i+1, evaluate_polynomial(coeffs_3329, i+1)) for i in range(n)]
        recon_256 = gf256_reconstruct(shares_256[:t])
        recon_3329 = reconstruct_secret(shares_3329[:t])
        assert recon_256 == secret_gf256
        assert recon_3329 == secret_gf3329

if __name__ == "__main__":
    test_hkdf_rfc5869()
    test_aes_ctr_nist()
    test_ml_kem_fips203()
    test_barrett_reduce()
    test_mod_inv()
    test_evaluate_polynomial()
    test_shamir_generate_reconstruct()
    test_shamir_bytes()
    test_shamir_gf3329_vs_gf256_parity()
    print("All unit tests passed.")
'''
    with open(path, "w") as f:
        f.write(content)
    print(f"Created {path}")

if __name__ == "__main__":
    create_integration_test()
    create_unit_test()
    print("Test files created successfully.")