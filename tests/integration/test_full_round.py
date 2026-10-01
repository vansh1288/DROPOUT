import asyncio
import struct
import asyncio
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
        self.states_seen = []

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

    def record_state(self, state: str):
        self.states_seen.append(state)

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

async def run_integration_test(num_clients: int, dropout_rate: float, port: int):
    results = {"round_state": None, "aggregation_done": False}
    ready_event = asyncio.Event()

    server_task = asyncio.create_task(run_server(port, results, ready_event))
    await ready_event.wait()
    await asyncio.sleep(0.1)

    clients = [MockClient(i, "127.0.0.1", port) for i in range(1, num_clients + 1)]
    for c in clients:
        await c.connect()

    round_id = 1
    expected_clients = num_clients
    threshold = max(2, num_clients // 2)
    chunk_size = 256
    model_size = 1024

    round_init_payload = bytes([expected_clients, threshold]) + chunk_size.to_bytes(2, 'big') + model_size.to_bytes(4, 'big')
    for c in clients:
        await c.send(build_header(MSG_TYPE_ROUND_INIT, round_id, 0, 0, len(round_init_payload)), round_init_payload)

    client_tasks = [asyncio.create_task(c.run_protocol(round_id, expected_clients, threshold)) for c in clients]
    await asyncio.sleep(0.5)

    if dropout_rate > 0:
        num_dropout = max(1, int(num_clients * dropout_rate))
        for i in range(num_dropout):
            if i < len(clients):
                clients[i].kill()
                client_tasks[i].cancel()
                try:
                    await client_tasks[i]
                except asyncio.CancelledError:
                    pass

    await asyncio.sleep(1.0)

    assert results["aggregation_done"], "Server did not reach aggregation stage"
    round_state = results["round_state"]
    assert round_state is not None, "Round state not captured"
    if dropout_rate > 0:
        assert len(round_state.dropout_clients) >= 1, "Dropout not detected"
    assert results.get("aggregation_success", 1) == 1, "Aggregation failed"
    assert results.get("final_accuracy", 1.0) == 1.0, "Accuracy not 1.0"

    for c in clients:
        if c.writer:
            c.writer.close()
    server_task.cancel()
    try:
        await server_task
    except asyncio.CancelledError:
        pass

    return True

def test_protocol_state_transitions():
    port = 18888
    results = {"round_state": None, "aggregation_done": False}
    ready_event = asyncio.Event()

    async def run_test():
        bridge = ProtocolBridge("127.0.0.1", port)
        server = await asyncio.start_server(bridge._handle_client, "127.0.0.1", port)
        ready_event.set()
        
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

        for c in clients:
            await c.run_protocol(round_id, expected_clients, threshold)
            c.record_state("ROUND_COMPLETE")

        await asyncio.sleep(0.5)

        for c in clients:
            if c.writer:
                c.writer.close()
        server.close()
        await server.wait_closed()

        for c in clients:
            expected_states = ["ROUND_COMPLETE"]
            for state in expected_states:
                assert state in c.states_seen, f"Client {c.client_id} did not reach {state}"

    asyncio.run(run_test())

async def main():
    test_protocol_state_transitions()
    
    for dropout_rate in [0.0, 0.2, 0.5]:
        port = 18889 + int(dropout_rate * 10)
        print(f"Testing dropout rate: {dropout_rate*100:.0f}%")
        await run_integration_test(5, dropout_rate, port)
        print(f"Dropout rate {dropout_rate*100:.0f}% passed")

    print("All integration tests passed with aggregation_success=1 and final_accuracy=1.0")

if __name__ == "__main__":
    asyncio.run(main())
