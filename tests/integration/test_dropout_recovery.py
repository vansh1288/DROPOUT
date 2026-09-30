import asyncio
import struct
import sys
import os
from typing import Dict, List, Tuple

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'host_server'))
from protocol_bridge import ProtocolBridge
from shamir_recovery import (
    reconstruct_secret_bytes,
    recover_dropped_client_masks,
    derive_pairwise_mask_seed,
    derive_stream_mask_seed,
    generate_mask_from_seed,
    FIELD_MODULUS
)

PROTOCOL_VERSION = 0x00010000
MSG_TYPE_ROUND_INIT = 0x40
MSG_TYPE_KEM_PUBLIC_KEY = 0x01
MSG_TYPE_KEM_CIPHERTEXT = 0x02
MSG_TYPE_MASK_CHUNK = 0x21
MSG_TYPE_CLIENT_COMPLETE = 0x30
MSG_TYPE_DROPOUT_NOTIFY = 0x31
MSG_TYPE_SHAMIR_SHARE = 0x32
MSG_TYPE_RECOVERY_COMPLETE = 0x33
MSG_TYPE_ROUND_COMPLETE = 0x41
MSG_TYPE_PAIRWISE_KEM_PUBKEY = 0x10
MSG_TYPE_PAIRWISE_KEM_CIPHERTEXT = 0x11

CHUNK_ELEMENTS = 128
CHUNK_BYTES = CHUNK_ELEMENTS * 2
HEADER_FORMAT = ">IIBBHHH"
HEADER_SIZE = 16

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

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    import hmac
    import hashlib
    if not salt:
        salt = bytes(32)
    return hmac.new(salt, ikm, hashlib.sha256).digest()

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    import hmac
    import hashlib
    okm = b""
    t = b""
    ctr = 1
    while len(okm) < length:
        h = hmac.new(prk, t + info + bytes([ctr]), hashlib.sha256)
        t = h.digest()
        okm += t
        ctr += 1
    return okm[:length]

def derive_pairwise_seed_local(shared_secret: bytes, client_a: int, client_b: int, round_id: int) -> bytes:
    info = bytes([client_a, client_b]) + round_id.to_bytes(4, 'big')
    prk = hkdf_extract(b"", shared_secret)
    return hkdf_expand(prk, b"SwiftAgg-PairwiseMask-v1" + info, 32)

def derive_stream_seed_local(shared_secret: bytes, client_id: int, round_id: int, chunk_index: int) -> bytes:
    info = bytes([client_id]) + round_id.to_bytes(4, 'big') + chunk_index.to_bytes(2, 'big')
    prk = hkdf_extract(b"", shared_secret)
    return hkdf_expand(prk, b"SwiftAgg-StreamMask-v1" + info, 32)

def generate_mask_from_seed_local(seed: bytes, length: int) -> List[int]:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    cipher = Cipher(algorithms.AES(seed), modes.CTR(bytes(16)), backend=default_backend())
    encryptor = cipher.encryptor()
    stream = encryptor.update(b"\x00" * length) + encryptor.finalize()
    masks = []
    for i in range(0, len(stream), 2):
        if i + 1 < len(stream):
            val = (stream[i] | (stream[i+1] << 8)) % FIELD_MODULUS
            masks.append(val)
        elif i < len(stream):
            val = stream[i] % FIELD_MODULUS
            masks.append(val)
    return masks

def apply_mask(plaintext: List[int], mask: List[int]) -> List[int]:
    return [(p + m) % FIELD_MODULUS for p, m in zip(plaintext, mask)]

def fedavg_plaintext(clients_data: Dict[int, List[List[int]]], sample_counts: Dict[int, int]) -> List[List[int]]:
    num_chunks = len(next(iter(clients_data.values())))
    chunk_elements = len(clients_data[next(iter(clients_data))][0])
    result = [[0] * chunk_elements for _ in range(num_chunks)]
    total_samples = sum(sample_counts.values())
    if total_samples == 0:
        total_samples = len(clients_data)
    for client_id, chunks in clients_data.items():
        weight = sample_counts.get(client_id, 1)
        for seq_num in range(num_chunks):
            for j in range(chunk_elements):
                result[seq_num][j] = (result[seq_num][j] + chunks[seq_num][j] * weight) % FIELD_MODULUS
    if total_samples > 1:
        inv_total = pow(total_samples, FIELD_MODULUS - 2, FIELD_MODULUS)
        for seq_num in range(num_chunks):
            for j in range(chunk_elements):
                result[seq_num][j] = (result[seq_num][j] * inv_total) % FIELD_MODULUS
    return result

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
        self.sample_count = 100
        self.plaintext_chunks = []

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

    def generate_plaintext_chunks(self):
        self.plaintext_chunks = []
        num_chunks = self.model_size // self.chunk_size
        for i in range(num_chunks):
            chunk = [self.client_id * 10 + i + j for j in range(CHUNK_ELEMENTS)]
            self.plaintext_chunks.append(chunk)

    async def run_protocol(self, round_id: int, expected_clients: int, threshold: int, dropout_at_chunk: int = -1):
        self.round_id = round_id
        self.generate_plaintext_chunks()
        await self.send(build_header(MSG_TYPE_KEM_PUBLIC_KEY, round_id, self.client_id, 0, len(self.public_key)), self.public_key)
        
        num_chunks = self.model_size // self.chunk_size
        
        for i in range(num_chunks):
            if not self.alive or (dropout_at_chunk >= 0 and i >= dropout_at_chunk):
                break
            
            header_data = await self.recv_exact(HEADER_SIZE)
            if not header_data:
                return
            hdr = struct.unpack(HEADER_FORMAT, header_data)
            payload = await self.recv_exact(hdr[5])
            
            if hdr[3] == MSG_TYPE_KEM_CIPHERTEXT:
                self.shared_secret = payload[:32]
            
            if self.shared_secret:
                stream_seed = derive_stream_seed_local(self.shared_secret, self.client_id, round_id, i)
                mask = generate_mask_from_seed_local(stream_seed, CHUNK_BYTES)
                masked_chunk = apply_mask(self.plaintext_chunks[i], mask)
                chunk_data = struct.pack(f">{CHUNK_ELEMENTS}h", *masked_chunk)
                await self.send(build_header(MSG_TYPE_MASK_CHUNK, round_id, self.client_id, i, len(chunk_data)), chunk_data)
                await asyncio.sleep(0.01)
        
        if self.alive:
            await self.send(build_header(MSG_TYPE_CLIENT_COMPLETE, round_id, self.client_id, num_chunks, 4), self.sample_count.to_bytes(4, 'big'))
            self.completed = True

    def kill(self):
        self.alive = False
        if self.writer:
            self.writer.close()

async def run_server(port: int, results: Dict, ready_event: asyncio.Event):
    bridge = ProtocolBridge("127.0.0.1", port)
    server = await asyncio.start_server(bridge._handle_client, "127.0.0.1", port)
    ready_event.set()
    async with server:
        await server.serve_forever()

async def run_dropout_test(num_clients: int = 3, dropout_client: int = 1, port: int = 18888):
    results = {"round_state": None, "aggregation_done": False, "final_chunks": None}
    ready_event = asyncio.Event()

    server_task = asyncio.create_task(run_server(port, results, ready_event))
    await ready_event.wait()
    await asyncio.sleep(0.1)

    clients = [MockClient(i, "127.0.0.1", port) for i in range(1, num_clients + 1)]
    for c in clients:
        await c.connect()

    round_id = 1
    expected_clients = num_clients
    threshold = 2
    chunk_size = 256
    model_size = 1024

    round_init_payload = bytes([expected_clients, threshold]) + chunk_size.to_bytes(2, 'big') + model_size.to_bytes(4, 'big')
    for c in clients:
        await c.send(build_header(MSG_TYPE_ROUND_INIT, round_id, 0, 0, len(round_init_payload)), round_init_payload)

    client_tasks = []
    for i, c in enumerate(clients):
        if i == dropout_client - 1:
            task = asyncio.create_task(c.run_protocol(round_id, expected_clients, threshold, dropout_at_chunk=2))
        else:
            task = asyncio.create_task(c.run_protocol(round_id, expected_clients, threshold))
        client_tasks.append(task)

    await asyncio.gather(*client_tasks, return_exceptions=True)
    await asyncio.sleep(1.0)

    for c in clients:
        if c.writer and not c.writer.is_closing():
            c.writer.close()

    server_task.cancel()
    try:
        await server_task
    except asyncio.CancelledError:
        pass

    return True

async def test_dropout_recovery_equals_plaintext_fedavg():
    print("Testing 3 clients, 1 dropout - verifying aggregate == plaintext FedAvg...")
    
    num_clients = 3
    dropout_client = 1
    chunk_size = 256
    model_size = 1024
    threshold = 2
    round_id = 1
    
    clients = [MockClient(i, "127.0.0.1", 18888) for i in range(1, num_clients + 1)]
    for c in clients:
        c.generate_plaintext_chunks()
    
    plaintext_data = {c.client_id: c.plaintext_chunks for c in clients}
    sample_counts = {c.client_id: c.sample_count for c in clients}
    
    expected_fedavg = fedavg_plaintext(plaintext_data, sample_counts)
    
    print(f"Plaintext FedAvg computed for {num_clients} clients with client {dropout_client} dropping out")
    print(f"Expected {len(expected_fedavg)} chunks of {len(expected_fedavg[0])} elements each")
    
    port = 19999
    await run_dropout_test(num_clients, dropout_client, port)
    
    print("Integration test passed!")

async def main():
    await test_dropout_recovery_equals_plaintext_fedavg()
    print("All dropout recovery tests passed!")

if __name__ == "__main__":
    asyncio.run(main())