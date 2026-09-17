import asyncio
import struct
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field

PROTOCOL_VERSION = 0x00010000
MSG_TYPE_ROUND_INIT = 0x40
MSG_TYPE_KEM_PUBLIC_KEY = 0x01
MSG_TYPE_MASK_CHUNK = 0x21
MSG_TYPE_CLIENT_COMPLETE = 0x30
MSG_TYPE_DROPOUT_NOTIFY = 0x31
MSG_TYPE_ROUND_COMPLETE = 0x41

CHUNK_ELEMENTS = 128
CHUNK_BYTES = CHUNK_ELEMENTS * 2
HEADER_FORMAT = ">IIBBHHH"
HEADER_SIZE = 16

@dataclass
class MessageHeader:
    protocol_version: int
    round_id: int
    client_id: int
    message_type: int
    sequence_number: int
    payload_length: int
    reserved: int

@dataclass
class ClientState:
    client_id: int
    round_id: int
    public_key: Optional[bytes] = None
    shared_secret: Optional[bytes] = None
    expected_chunks: int = 0
    received_chunks: Dict[int, bytes] = field(default_factory=dict)
    completed: bool = False

@dataclass
class RoundState:
    round_id: int
    expected_clients: int
    threshold: int
    chunk_size: int
    model_size: int
    clients: Dict[int, ClientState] = field(default_factory=dict)
    stage: str = "INIT"

class ProtocolBridge:
    def __init__(self, host: str = "0.0.0.0", port: int = 8888):
        self.host = host
        self.port = port
        self.rounds: Dict[int, RoundState] = {}
        self.current_round_id: int = 0
        self.server: Optional[asyncio.Server] = None
        self.client_writers: Dict[int, asyncio.StreamWriter] = {}

    async def start(self):
        self.server = await asyncio.start_server(
            self._handle_client, self.host, self.port
        )
        async with self.server:
            await self.server.serve_forever()

    async def _handle_client(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ):
        try:
            while True:
                header_data = await reader.readexactly(HEADER_SIZE)
                if not header_data:
                    break
                header = self._parse_header(header_data)
                payload = await reader.readexactly(header.payload_length)
                await self._dispatch_message(header, payload, writer)
        except asyncio.IncompleteReadError:
            pass
        except ConnectionResetError:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    def _parse_header(self, data: bytes) -> MessageHeader:
        values = struct.unpack(HEADER_FORMAT, data)
        return MessageHeader(*values)

    def _build_header(
        self,
        message_type: int,
        round_id: int,
        client_id: int,
        sequence_number: int,
        payload_length: int,
    ) -> bytes:
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

    async def _dispatch_message(
        self,
        header: MessageHeader,
        payload: bytes,
        writer: asyncio.StreamWriter,
    ):
        if header.message_type == MSG_TYPE_KEM_PUBLIC_KEY:
            await self._handle_public_key(header, payload)
        elif header.message_type == MSG_TYPE_MASK_CHUNK:
            await self._handle_mask_chunk(header, payload)
        elif header.message_type == MSG_TYPE_CLIENT_COMPLETE:
            await self._handle_client_complete(header)
        else:
            pass

    async def _handle_public_key(
        self, header: MessageHeader, payload: bytes
    ):
        round_state = self.rounds.get(header.round_id)
        if not round_state:
            return
        client_state = round_state.clients.get(header.client_id)
        if not client_state:
            client_state = ClientState(
                client_id=header.client_id, round_id=header.round_id
            )
            round_state.clients[header.client_id] = client_state
        client_state.public_key = payload
        self.client_writers[header.client_id] = writer

    async def _handle_mask_chunk(
        self, header: MessageHeader, payload: bytes
    ):
        round_state = self.rounds.get(header.round_id)
        if not round_state:
            return
        client_state = round_state.clients.get(header.client_id)
        if not client_state:
            return
        if len(payload) != CHUNK_BYTES:
            return
        client_state.received_chunks[header.sequence_number] = payload

    async def _handle_client_complete(self, header: MessageHeader):
        round_state = self.rounds.get(header.round_id)
        if not round_state:
            return
        client_state = round_state.clients.get(header.client_id)
        if client_state:
            client_state.completed = True
            await self._check_round_completion(round_state)

    async def _check_round_completion(self, round_state: RoundState):
        completed = sum(
            1 for c in round_state.clients.values() if c.completed
        )
        if completed >= round_state.expected_clients:
            round_state.stage = "AGGREGATION"
            await self._aggregate_and_broadcast(round_state)

    async def _aggregate_and_broadcast(self, round_state: RoundState):
        num_chunks = round_state.model_size // round_state.chunk_size
        aggregated_chunks: Dict[int, List[int]] = {}
        for i in range(num_chunks):
            aggregated_chunks[i] = [0] * CHUNK_ELEMENTS
        for client_state in round_state.clients.values():
            if not client_state.completed:
                continue
            for seq_num, chunk_data in client_state.received_chunks.items():
                if seq_num >= num_chunks:
                    continue
                values = struct.unpack(f">{CHUNK_ELEMENTS}h", chunk_data)
                for i, val in enumerate(values):
                    aggregated_chunks[seq_num][i] = (
                        aggregated_chunks[seq_num][i] + val
                    ) % 3329
        for client_id, writer in self.client_writers.items():
            for seq_num in range(num_chunks):
                result = struct.pack(
                    f">{CHUNK_ELEMENTS}h", *aggregated_chunks[seq_num]
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