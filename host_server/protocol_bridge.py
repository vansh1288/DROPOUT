"""
host_server/protocol_bridge.py

Host-side reference implementation of the DROPOUT wire protocol: an
asyncio TCP server that coordinates one or more federated rounds.

Assumed library versions:
    Python >= 3.9
    cryptography (optional, only required if the 0x01/0x02 server-client
        KEM path and AES-CTR mask generation are exercised)
    oqs (optional) or pqcrypto (optional) -- at least one real ML-KEM
        backend is required for the 0x01/0x02 server-client session-key
        path; neither is required for pure protocol/relay testing.

This revision adds the validation layer that was still missing after the
previous privacy-bug fix: protocol_version checking, per-client
sequence-number replay rejection, a payload-size sanity guard (a client
claiming an absurd payload_length previously had the server block
indefinitely in readexactly()), and dispatch wrapped so that a malformed
message from one client degrades to an error reply on that connection
rather than raising unhandled inside the connection's task. RoundState's
free-form `stage` string is replaced with client_manager.RoundStage, with
transitions enforced through transition_round_stage() at each lifecycle
point rather than assigned ad hoc.

Pairwise key establishment remains relay-only (the server never computes
or stores a pairwise secret itself), and real Shamir shares (not
HKDF-derived pseudo-shares) drive dropout recovery -- see
client_manager.py and shamir_recovery.py for that history.
"""

import asyncio
import struct
from typing import Any, Dict, Optional, Tuple

try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    try:
        import pqcrypto.kem.kyber768 as pq_kem
        OQS_AVAILABLE = False
    except ImportError:
        OQS_AVAILABLE = None

from client_manager import (
    InvalidStateError,
    MalformedMessageError,
    ProtocolError,
    ProtocolVersionError,
    ReplayError,
    RoundStage,
    RoundState,
    UnknownClientError,
    UnknownRoundError,
    get_or_create_client,
    pair_key,
    transition_round_stage,
)
from shamir_recovery import (
    FIELD_MODULUS,
    RAW_SECRET_BYTES,
    derive_stream_mask_seed,
    generate_mask_from_seed,
    reconstruct_shared_secret,
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
MSG_TYPE_RECOVERY_SHARE_REQUEST = 0x34
MSG_TYPE_RECOVERY_SHARE_REPLY = 0x35
MSG_TYPE_PAIRWISE_KEM_PUBKEY = 0x10
MSG_TYPE_PAIRWISE_KEM_CIPHERTEXT = 0x11
MSG_TYPE_ROUND_COMPLETE = 0x41
MSG_TYPE_ERROR = 0xFE

HEADER_FORMAT = ">IIBBHHH"  # version(4) round_id(4) client_id(1) msg_type(1) seq(2) payload_len(2) reserved(2)
HEADER_SIZE = 16

# A client announcing an absurd payload_length previously made the server
# block in readexactly() until that many bytes arrived (or the connection
# died) -- effectively a trivial resource-exhaustion/hang vector. The
# largest legitimate payload in this protocol is a mask chunk
# (chunk_size * 2 bytes); 8 KiB gives generous headroom above any
# realistic chunk_size while still rejecting bogus claims immediately.
MAX_PAYLOAD_BYTES = 8192

# Error codes carried in a MSG_TYPE_ERROR reply's single payload byte, so a
# client (or a test) can distinguish WHY a message was rejected instead of
# just knowing that it was.
ERROR_CODE_VERSION_MISMATCH = 0x01
ERROR_CODE_REPLAY = 0x02
ERROR_CODE_UNKNOWN_ROUND = 0x03
ERROR_CODE_UNKNOWN_CLIENT = 0x04
ERROR_CODE_INVALID_STATE = 0x05
ERROR_CODE_MALFORMED = 0x06
ERROR_CODE_ROUND_FAILURE = 0x07
ERROR_CODE_RECOVERY_IMPOSSIBLE = 0x08

_ERROR_CODE_BY_EXCEPTION = {
    ProtocolVersionError: ERROR_CODE_VERSION_MISMATCH,
    ReplayError: ERROR_CODE_REPLAY,
    UnknownRoundError: ERROR_CODE_UNKNOWN_ROUND,
    UnknownClientError: ERROR_CODE_UNKNOWN_CLIENT,
    InvalidStateError: ERROR_CODE_INVALID_STATE,
    MalformedMessageError: ERROR_CODE_MALFORMED,
}


class MessageHeader:
    __slots__ = ("protocol_version", "round_id", "client_id", "message_type", "sequence_number", "payload_length", "reserved")

    def __init__(self, protocol_version, round_id, client_id, message_type, sequence_number, payload_length, reserved):
        self.protocol_version = protocol_version
        self.round_id = round_id
        self.client_id = client_id
        self.message_type = message_type
        self.sequence_number = sequence_number
        self.payload_length = payload_length
        self.reserved = reserved


class ProtocolBridge:
    def __init__(self, host: str = "0.0.0.0", port: int = 8888):
        self.host = host
        self.port = port
        self.rounds: Dict[int, RoundState] = {}
        self.current_round_id: int = 0
        self.server: Optional[asyncio.Server] = None
        self.client_writers: Dict[int, asyncio.StreamWriter] = {}

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle_client, self.host, self.port)
        async with self.server:
            await self.server.serve_forever()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                header_data = await reader.readexactly(HEADER_SIZE)
                if not header_data:
                    break
                header = self._parse_header(header_data)

                if header.payload_length > MAX_PAYLOAD_BYTES:
                    await self._send_error(writer, header, ERROR_CODE_MALFORMED)
                    break

                payload = await reader.readexactly(header.payload_length)

                try:
                    await self._validate_and_dispatch(header, payload, writer)
                except ProtocolError as exc:
                    error_code = _ERROR_CODE_BY_EXCEPTION.get(type(exc), ERROR_CODE_MALFORMED)
                    await self._send_error(writer, header, error_code)
                except (struct.error, IndexError, ValueError):
                    await self._send_error(writer, header, ERROR_CODE_MALFORMED)
        except asyncio.IncompleteReadError:
            pass
        except ConnectionResetError:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def _send_error(self, writer: asyncio.StreamWriter, header: MessageHeader, error_code: int) -> None:
        if writer.is_closing():
            return
        payload = struct.pack(">B", error_code)
        hdr = self._build_header(MSG_TYPE_ERROR, header.round_id, 0, 0, len(payload))
        writer.write(hdr + payload)
        await writer.drain()

    def _parse_header(self, data: bytes) -> MessageHeader:
        return MessageHeader(*struct.unpack(HEADER_FORMAT, data))

    def _build_header(
        self, message_type: int, round_id: int, client_id: int, sequence_number: int, payload_length: int
    ) -> bytes:
        return struct.pack(
            HEADER_FORMAT, PROTOCOL_VERSION, round_id, client_id, message_type, sequence_number, payload_length, 0
        )

    # ------------------------------------------------------------------
    # Validation layer
    # ------------------------------------------------------------------

    async def _validate_and_dispatch(self, header: MessageHeader, payload: bytes, writer: asyncio.StreamWriter) -> None:
        if header.protocol_version != PROTOCOL_VERSION:
            raise ProtocolVersionError(f"protocol_version {header.protocol_version:#x} != expected {PROTOCOL_VERSION:#x}")

        if header.message_type == MSG_TYPE_ROUND_INIT:
            # ROUND_INIT is exempt from the round-exists/replay checks
            # below, since it's what CREATES the round in the first place.
            await self._handle_round_init(header, payload)
            return

        round_state = self.rounds.get(header.round_id)
        if round_state is None:
            raise UnknownRoundError(f"round_id {header.round_id} has no active round")

        client_state = round_state.clients.get(header.client_id)
        if client_state is not None:
            # Replay guard: strictly increasing sequence numbers per
            # (round_id, client_id). A brand-new client (not yet in
            # round_state.clients) has no prior sequence to replay against
            # yet, so this only applies from a client's second message on.
            if header.sequence_number <= client_state.last_sequence_number:
                raise ReplayError(
                    f"sequence_number {header.sequence_number} <= last accepted "
                    f"{client_state.last_sequence_number} for client_id {header.client_id}"
                )

        await self._dispatch_message(header, payload, writer, round_state)

        # Only record the new high-water mark AFTER successful handling, so
        # a message that raised mid-processing can still be legitimately
        # retried rather than being permanently replay-blocked by its own
        # failed attempt.
        client_state = round_state.clients.get(header.client_id)
        if client_state is not None:
            client_state.last_sequence_number = header.sequence_number

    async def _dispatch_message(
        self, header: MessageHeader, payload: bytes, writer: asyncio.StreamWriter, round_state: RoundState
    ) -> None:
        if header.message_type == MSG_TYPE_KEM_PUBLIC_KEY:
            await self._handle_public_key(header, payload, writer, round_state)
        elif header.message_type == MSG_TYPE_PAIRWISE_KEM_PUBKEY:
            await self._handle_pairwise_pubkey(header, payload, round_state)
        elif header.message_type == MSG_TYPE_PAIRWISE_KEM_CIPHERTEXT:
            await self._handle_pairwise_ciphertext(header, payload, round_state)
        elif header.message_type == MSG_TYPE_MASK_CHUNK:
            await self._handle_mask_chunk(header, payload, round_state)
        elif header.message_type == MSG_TYPE_CLIENT_COMPLETE:
            await self._handle_client_complete(header, payload, round_state)
        elif header.message_type == MSG_TYPE_DROPOUT_NOTIFY:
            await self._handle_dropout_notify(header, payload, round_state)
        elif header.message_type == MSG_TYPE_SHAMIR_SHARE:
            await self._handle_shamir_share_distribution(header, payload, round_state)
        elif header.message_type == MSG_TYPE_RECOVERY_SHARE_REPLY:
            await self._handle_recovery_share_reply(header, payload, round_state)
        else:
            raise MalformedMessageError(f"unrecognized message_type {header.message_type:#x}")

    # ------------------------------------------------------------------
    # Round / client bookkeeping
    # ------------------------------------------------------------------

    async def _handle_round_init(self, header: MessageHeader, payload: bytes) -> None:
        if header.round_id in self.rounds:
            return
        if len(payload) != 8:
            raise MalformedMessageError(f"ROUND_INIT payload must be 8 bytes, got {len(payload)}")
        expected_clients, threshold, chunk_size, model_size = struct.unpack("<BBHI", payload)
        if threshold < 1 or threshold > expected_clients:
            raise MalformedMessageError(f"invalid threshold {threshold} for expected_clients {expected_clients}")
        if chunk_size == 0 or model_size == 0:
            raise MalformedMessageError("chunk_size and model_size must both be nonzero")

        self.rounds[header.round_id] = RoundState(
            round_id=header.round_id, expected_clients=expected_clients,
            threshold=threshold, chunk_size=chunk_size, model_size=model_size,
        )
        self.current_round_id = header.round_id

    # ------------------------------------------------------------------
    # Server-client KEM (0x01/0x02) -- legitimate server-side secret,
    # unrelated to pairwise masking.
    # ------------------------------------------------------------------

    def _encapsulate(self, pubkey: bytes) -> Tuple[bytes, bytes]:
        if OQS_AVAILABLE is True:
            with oqs.KeyEncapsulation("Kyber768") as kem:
                return kem.encap_secret(pubkey)
        elif OQS_AVAILABLE is False:
            return pq_kem.encrypt(pubkey)
        raise RuntimeError("no PQC KEM backend available (install `oqs` or `pqcrypto`)")

    async def _handle_public_key(
        self, header: MessageHeader, payload: bytes, writer: asyncio.StreamWriter, round_state: RoundState
    ) -> None:
        if not payload:
            raise MalformedMessageError("PUBLIC_KEY payload must not be empty")
        if len(round_state.clients) >= round_state.expected_clients and header.client_id not in round_state.clients:
            raise InvalidStateError(f"round {round_state.round_id} already has its expected_clients registered")

        is_first_client = len(round_state.clients) == 0
        client_state = get_or_create_client(round_state, header.client_id)
        client_state.public_key = payload
        self.client_writers[header.client_id] = writer

        if round_state.stage == RoundStage.INIT and is_first_client:
            transition_round_stage(round_state, RoundStage.KEY_SETUP)

        if OQS_AVAILABLE is not None and client_state.shared_secret is None:
            ciphertext, shared_secret = self._encapsulate(payload)
            client_state.shared_secret = shared_secret
            ct_header = self._build_header(MSG_TYPE_KEM_CIPHERTEXT, header.round_id, 0, 0, len(ciphertext))
            writer.write(ct_header + ciphertext)
            await writer.drain()

        round_init_payload = struct.pack(
            "<BBHI", round_state.expected_clients, round_state.threshold, round_state.chunk_size, round_state.model_size
        )
        hdr = self._build_header(MSG_TYPE_ROUND_INIT, round_state.round_id, 0, 0, len(round_init_payload))
        writer.write(hdr + round_init_payload)
        await writer.drain()

        await self._relay_pairwise_pubkeys(round_state, header.client_id)

        if len(round_state.clients) >= round_state.expected_clients and round_state.stage == RoundStage.KEY_SETUP:
            transition_round_stage(round_state, RoundStage.MASK_SETUP)

    # ------------------------------------------------------------------
    # Pairwise KEM relay (0x10/0x11)
    # ------------------------------------------------------------------

    async def _relay_pairwise_pubkeys(self, round_state: RoundState, new_client_id: int) -> None:
        new_client = round_state.clients[new_client_id]
        if new_client.public_key is None:
            return
        new_writer = self.client_writers.get(new_client_id)

        for peer_id, peer_state in round_state.clients.items():
            if peer_id == new_client_id or peer_state.public_key is None:
                continue
            peer_writer = self.client_writers.get(peer_id)

            if new_writer is not None:
                payload = struct.pack(">B", peer_id) + peer_state.public_key
                hdr = self._build_header(MSG_TYPE_PAIRWISE_KEM_PUBKEY, round_state.round_id, 0, 0, len(payload))
                new_writer.write(hdr + payload)
                await new_writer.drain()

            if peer_writer is not None:
                payload = struct.pack(">B", new_client_id) + new_client.public_key
                hdr = self._build_header(MSG_TYPE_PAIRWISE_KEM_PUBKEY, round_state.round_id, 0, 0, len(payload))
                peer_writer.write(hdr + payload)
                await peer_writer.drain()

    async def _handle_pairwise_pubkey(self, header: MessageHeader, payload: bytes, round_state: RoundState) -> None:
        await self._relay_pairwise_pubkeys(round_state, header.client_id)

    async def _handle_pairwise_ciphertext(self, header: MessageHeader, payload: bytes, round_state: RoundState) -> None:
        if len(payload) < 2:
            raise MalformedMessageError("PAIRWISE_KEM_CIPHERTEXT payload too short to contain a target id + ciphertext")
        target_peer_id = payload[0]
        if target_peer_id not in round_state.clients:
            raise UnknownClientError(f"pairwise ciphertext targets unknown client_id {target_peer_id}")
        ciphertext = payload[1:]
        target_writer = self.client_writers.get(target_peer_id)
        if target_writer is None:
            return
        hdr = self._build_header(MSG_TYPE_PAIRWISE_KEM_CIPHERTEXT, round_state.round_id, header.client_id, 0, len(ciphertext))
        target_writer.write(hdr + ciphertext)
        await target_writer.drain()

    # ------------------------------------------------------------------
    # Masked update streaming
    # ------------------------------------------------------------------

    async def _handle_mask_chunk(self, header: MessageHeader, payload: bytes, round_state: RoundState) -> None:
        client_state = round_state.clients.get(header.client_id)
        if client_state is None:
            raise UnknownClientError(f"client_id {header.client_id} is not registered in round {round_state.round_id}")
        # Payload: chunk_idx(2, big-endian) + chunk_size*2 bytes of masked
        # data. chunk_idx is NOT the header's sequence_number -- that field
        # is a pure per-client anti-replay counter, unrelated to a chunk's
        # position in the model update (see mock_client.py's streaming
        # code for the full explanation of why these must stay separate).
        if len(payload) != 2 + round_state.chunk_size * 2:
            raise MalformedMessageError(
                f"mask chunk payload must be exactly {2 + round_state.chunk_size * 2} bytes "
                f"(2-byte chunk_idx + {round_state.chunk_size * 2}-byte data), got {len(payload)}"
            )
        chunk_idx = struct.unpack(">H", payload[:2])[0]
        chunk_data = payload[2:]
        num_chunks = round_state.model_size // round_state.chunk_size
        if chunk_idx >= num_chunks:
            raise MalformedMessageError(f"chunk_idx {chunk_idx} out of range for {num_chunks} chunks this round")
        if round_state.stage == RoundStage.INIT:
            # Genuinely too early: this client hasn't even announced its
            # own public key yet, so it cannot legitimately have a
            # pairwise secret to mask with -- unlike KEY_SETUP/MASK_SETUP
            # below, there's no race that makes this one benign.
            raise InvalidStateError("mask chunk received before this round's key setup began")
        if round_state.stage in (RoundStage.COMPLETE, RoundStage.ABORTED):
            raise InvalidStateError(f"mask chunk received after round reached terminal stage {round_state.stage.name}")
        if round_state.stage in (RoundStage.KEY_SETUP, RoundStage.MASK_SETUP):
            transition_round_stage(round_state, RoundStage.MASKED_UPDATE_STREAM)
        client_state.received_chunks[chunk_idx] = chunk_data

    async def _handle_client_complete(self, header: MessageHeader, payload: bytes, round_state: RoundState) -> None:
        client_state = round_state.clients.get(header.client_id)
        if client_state is None:
            raise UnknownClientError(f"client_id {header.client_id} is not registered in round {round_state.round_id}")
        if len(payload) < 4:
            raise MalformedMessageError("CLIENT_COMPLETE payload must contain at least a 4-byte sample_count")
        client_state.sample_count = int.from_bytes(payload[:4], "big")
        client_state.completed = True
        await self._check_round_completion(round_state)

    def _dropout_recovery_status(self, round_state: RoundState) -> Tuple[set, set]:
        """For every (dropout, surviving-peer) pair whose leftover mask
        term would need cancelling, classifies that pair as:
          - already recovered (excluded from both returned sets),
          - BLOCKED: no share_holders metadata exists for it at all, so it
            can never be recovered (distribution never happened, e.g. the
            degenerate case where fewer than `threshold` OTHER clients
            were available to hold shares), or
          - PENDING: shares were distributed, but fewer than `threshold`
            RECOVERY_SHARE_REPLY messages have arrived yet.
        Returns (blocked_pairs, pending_pairs).
        """
        needed = set()
        for dropout_id in round_state.dropout_clients:
            for peer_id in round_state.clients:
                if peer_id == dropout_id or peer_id in round_state.dropout_clients:
                    continue
                needed.add(pair_key(dropout_id, peer_id))

        unresolved = needed - set(round_state.recovered_pairwise_secrets.keys())
        blocked = {pk for pk in unresolved if pk not in round_state.share_holders}
        pending = unresolved - blocked
        return blocked, pending

    async def _check_round_completion(self, round_state: RoundState) -> None:
        if round_state.dropout_clients:
            blocked, pending = self._dropout_recovery_status(round_state)
            if blocked:
                # Completing anyway would silently produce a WRONG
                # aggregate (the dropout's leftover mask term never gets
                # cancelled) rather than an honest failure -- abort
                # instead, per "Dropout recovery uses real protocol
                # shares, not mock values" in the project's definition of
                # done.
                if round_state.stage != RoundStage.ABORTED:
                    transition_round_stage(round_state, RoundStage.ABORTED)
                await self._handle_round_failure(round_state, ERROR_CODE_RECOVERY_IMPOSSIBLE)
                return
            if pending:
                return  # Wait for more RECOVERY_SHARE_REPLY messages; re-checked each time one arrives.

        completed = sum(1 for c in round_state.clients.values() if c.completed)
        surviving = round_state.expected_clients - len(round_state.dropout_clients)
        if completed >= surviving and surviving >= round_state.threshold:
            if round_state.stage not in (RoundStage.UNMASK, RoundStage.COMPLETE):
                transition_round_stage(round_state, RoundStage.UNMASK)
            await self._unmask_and_aggregate(round_state)
        elif surviving < round_state.threshold:
            if round_state.stage != RoundStage.ABORTED:
                transition_round_stage(round_state, RoundStage.ABORTED)
            await self._handle_round_failure(round_state, ERROR_CODE_ROUND_FAILURE)

    async def _handle_round_failure(self, round_state: RoundState, error_code: int = ERROR_CODE_ROUND_FAILURE) -> None:
        for writer in self.client_writers.values():
            if not writer.is_closing():
                header = self._build_header(MSG_TYPE_ERROR, round_state.round_id, 0, 0, 1)
                writer.write(header + struct.pack(">B", error_code))
                await writer.drain()

    # ------------------------------------------------------------------
    # Dropout + Shamir recovery
    # ------------------------------------------------------------------

    async def _handle_dropout_notify(self, header: MessageHeader, payload: bytes, round_state: RoundState) -> None:
        if len(payload) != 1:
            raise MalformedMessageError("DROPOUT_NOTIFY payload must be exactly 1 byte (the dropped client_id)")
        dropped_client_id = payload[0]
        if dropped_client_id not in round_state.clients:
            raise UnknownClientError(f"DROPOUT_NOTIFY names unknown client_id {dropped_client_id}")

        if round_state.stage == RoundStage.MASKED_UPDATE_STREAM:
            transition_round_stage(round_state, RoundStage.DROPOUT_DETECTION)

        client_state = round_state.clients[dropped_client_id]
        client_state.dropped = True
        if dropped_client_id not in round_state.dropout_clients:
            round_state.dropout_clients.append(dropped_client_id)

        if round_state.stage == RoundStage.DROPOUT_DETECTION:
            transition_round_stage(round_state, RoundStage.MASK_RECOVERY)
        await self._trigger_recovery(round_state)
        await self._check_round_completion(round_state)

    async def _handle_shamir_share_distribution(self, header: MessageHeader, payload: bytes, round_state: RoundState) -> None:
        if len(payload) != 4 + RAW_SECRET_BYTES:
            raise MalformedMessageError(
                f"SHAMIR_SHARE distribution payload must be {4 + RAW_SECRET_BYTES} bytes, got {len(payload)}"
            )
        target_holder_id, owner_id, peer_id, x_coordinate = payload[0], payload[1], payload[2], payload[3]
        y_value = payload[4:]

        target_writer = self.client_writers.get(target_holder_id)
        if target_writer is not None:
            relay_payload = struct.pack(">BBB", owner_id, peer_id, x_coordinate) + y_value
            hdr = self._build_header(MSG_TYPE_SHAMIR_SHARE, round_state.round_id, 0, 0, len(relay_payload))
            target_writer.write(hdr + relay_payload)
            await target_writer.drain()

        round_state.share_holders.setdefault(pair_key(owner_id, peer_id), set()).add(target_holder_id)

    async def _handle_recovery_share_reply(self, header: MessageHeader, payload: bytes, round_state: RoundState) -> None:
        if len(payload) != 3 + RAW_SECRET_BYTES:
            raise MalformedMessageError(
                f"RECOVERY_SHARE_REPLY payload must be {3 + RAW_SECRET_BYTES} bytes, got {len(payload)}"
            )
        owner_id, peer_id, x_coordinate = payload[0], payload[1], payload[2]
        y_value = payload[3:]
        key = pair_key(owner_id, peer_id)
        round_state.recovery_shares.setdefault(key, []).append((x_coordinate, bytes(y_value)))
        await self._try_reconstruct_pairwise_secret(round_state, key)
        await self._check_round_completion(round_state)

    async def _try_reconstruct_pairwise_secret(self, round_state: RoundState, pair_key_: Tuple[int, int]) -> None:
        shares = round_state.recovery_shares.get(pair_key_, [])
        if len(shares) < round_state.threshold or pair_key_ in round_state.recovered_pairwise_secrets:
            return
        try:
            secret = reconstruct_shared_secret(shares[: round_state.threshold], round_state.threshold)
        except ValueError:
            return
        round_state.recovered_pairwise_secrets[pair_key_] = secret

    async def _trigger_recovery(self, round_state: RoundState) -> None:
        for dropout_id in round_state.dropout_clients:
            for pk, holders in round_state.share_holders.items():
                if dropout_id not in pk or pk in round_state.recovery_requested:
                    continue
                owner_id, peer_id = pk
                for holder_id in holders:
                    holder_writer = self.client_writers.get(holder_id)
                    if holder_writer is None:
                        continue
                    request_payload = struct.pack(">BB", owner_id, peer_id)
                    hdr = self._build_header(MSG_TYPE_RECOVERY_SHARE_REQUEST, round_state.round_id, 0, 0, len(request_payload))
                    holder_writer.write(hdr + request_payload)
                    await holder_writer.drain()
                round_state.recovery_requested.add(pk)

    def _recovered_mask_for_dropout_peer(self, round_state: RoundState, dropout_id: int, peer_id: int, chunk_idx: int):
        pair_secret = round_state.recovered_pairwise_secrets.get(pair_key(dropout_id, peer_id))
        if pair_secret is None:
            return None
        canonical_id = min(dropout_id, peer_id)
        stream_seed = derive_stream_mask_seed(pair_secret, canonical_id, round_state.round_id, chunk_idx)
        return generate_mask_from_seed(stream_seed, round_state.chunk_size * 2)

    # ------------------------------------------------------------------
    # Unmasking and FedAvg aggregation
    # ------------------------------------------------------------------

    def _unmask_client_chunks(self, round_state: RoundState):
        num_chunks = round_state.model_size // round_state.chunk_size
        chunk_elements = round_state.chunk_size
        client_unmasked: Dict[int, Dict[int, list]] = {}

        for client_id, client_state in round_state.clients.items():
            if client_id in round_state.dropout_clients:
                continue
            client_unmasked[client_id] = {}
            for seq_num, chunk_data in client_state.received_chunks.items():
                if seq_num >= num_chunks:
                    continue
                values = struct.unpack(f">{chunk_elements}h", chunk_data)
                client_unmasked[client_id][seq_num] = list(values)

        for dropout_id in round_state.dropout_clients:
            for peer_id, peer_unmasked in client_unmasked.items():
                sign = 1 if peer_id < dropout_id else -1
                for seq_num in list(peer_unmasked.keys()):
                    mask = self._recovered_mask_for_dropout_peer(round_state, dropout_id, peer_id, seq_num)
                    if mask is None:
                        continue
                    peer_unmasked[seq_num] = [
                        (val - sign * mask[i]) % FIELD_MODULUS for i, val in enumerate(peer_unmasked[seq_num])
                    ]

        return client_unmasked

    def _compute_fedavg(self, round_state: RoundState, client_unmasked):
        total_samples = sum(
            c.sample_count for c in round_state.clients.values()
            if c.completed and c.sample_count > 0 and c.client_id in client_unmasked
        )
        if total_samples == 0:
            total_samples = sum(1 for c in round_state.clients.values() if c.completed and c.client_id in client_unmasked)

        num_chunks = round_state.model_size // round_state.chunk_size
        chunk_elements = round_state.chunk_size
        fedavg_chunks: Dict[int, list] = {i: [0] * chunk_elements for i in range(num_chunks)}

        for client_id, chunks in client_unmasked.items():
            client_state = round_state.clients.get(client_id)
            if not client_state or not client_state.completed:
                continue
            weight = client_state.sample_count if client_state.sample_count > 0 else 1
            for seq_num, values in chunks.items():
                if seq_num >= num_chunks:
                    continue
                for j, val in enumerate(values):
                    fedavg_chunks[seq_num][j] = (fedavg_chunks[seq_num][j] + val * weight) % FIELD_MODULUS

        if total_samples > 1:
            inv_total = pow(total_samples, FIELD_MODULUS - 2, FIELD_MODULUS)
            for seq_num in range(num_chunks):
                for j in range(chunk_elements):
                    fedavg_chunks[seq_num][j] = (fedavg_chunks[seq_num][j] * inv_total) % FIELD_MODULUS

        return fedavg_chunks

    async def _unmask_and_aggregate(self, round_state: RoundState) -> None:
        client_unmasked = self._unmask_client_chunks(round_state)
        fedavg_chunks = self._compute_fedavg(round_state, client_unmasked)

        num_chunks = round_state.model_size // round_state.chunk_size
        for seq_num in range(num_chunks):
            if seq_num not in fedavg_chunks:
                return

        round_state.unmasked_chunks = fedavg_chunks
        if round_state.stage != RoundStage.COMPLETE:
            transition_round_stage(round_state, RoundStage.COMPLETE)

        telemetry_payload = self._pack_telemetry(self._collect_telemetry(round_state))
        for writer in self.client_writers.values():
            for seq_num in range(num_chunks):
                result = struct.pack(f">{round_state.chunk_size}h", *fedavg_chunks[seq_num])
                hdr = self._build_header(
                    MSG_TYPE_ROUND_COMPLETE, round_state.round_id, 0, seq_num, len(result) + len(telemetry_payload)
                )
                writer.write(hdr + result + telemetry_payload)
                await writer.drain()

    def _collect_telemetry(self, round_state: RoundState) -> Dict[str, Any]:
        return {
            "round_id": round_state.round_id,
            "keygen_cycles": 0, "encaps_cycles": 0, "decaps_cycles": 0, "hkdf_cycles": 0,
            "mask_gen_cycles": 0, "mask_apply_cycles": 0, "peak_sram": 0, "min_free_heap": 0,
            "largest_free_block": 0, "stack_high_water": 0, "heap_zero": False,
            "bytes_tx": round_state.model_size * len(round_state.clients),
            "bytes_rx": round_state.model_size,
            "packets": len(round_state.clients) * (round_state.model_size // round_state.chunk_size),
            "retransmissions": 0, "fragments": 0, "aggregation_success": 1, "final_accuracy": 1.0,
        }

    def _pack_telemetry(self, telemetry: Dict[str, Any]) -> bytes:
        return struct.pack(
            ">IIIIIIIIIIIIIIBBBB",
            telemetry["round_id"], telemetry["keygen_cycles"], telemetry["encaps_cycles"],
            telemetry["decaps_cycles"], telemetry["hkdf_cycles"], telemetry["mask_gen_cycles"],
            telemetry["mask_apply_cycles"], telemetry["peak_sram"], telemetry["min_free_heap"],
            telemetry["largest_free_block"], telemetry["stack_high_water"], 0, 0, 0,
            1 if telemetry["heap_zero"] else 0, telemetry["aggregation_success"],
            int(telemetry["final_accuracy"] * 255), 0,
        )
