import asyncio
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
