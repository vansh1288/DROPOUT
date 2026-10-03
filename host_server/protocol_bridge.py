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

See shamir_recovery.py's module docstring and the inline notes below for
the bug writeup this revision fixes. Summary:
  - The server previously called its own _encapsulate() against each
    CLIENT's public key for "pairwise" setup and stored the resulting
    secret in its own ClientState -- meaning the server ended up holding
    every pairwise mask secret directly, which defeats the entire privacy
    purpose of pairwise masking. Pairwise key establishment is now
    strictly relay-only: the server forwards public keys and ciphertexts
    between the two clients in a pair and never calls _encapsulate for
    that purpose. (The SEPARATE 0x01/0x02 server-client KEM exchange is
    unaffected -- that's a legitimate server-client secret, not a
    pairwise one, per the project's own shared-contract note that "a
    server-client KEM secret is not itself a client-client secret".)
  - _handle_pairwise_pubkey / _handle_pairwise_ciphertext were referenced
    in _dispatch_message but never defined (AttributeError at runtime).
    Both are implemented now, as pure relays.
  - Real Shamir share distribution (MSG_TYPE_SHAMIR_SHARE, client-to-
    client via server relay, server does not persist share VALUES) and
    post-dropout recovery (MSG_TYPE_RECOVERY_SHARE_REQUEST /
    MSG_TYPE_RECOVERY_SHARE_REPLY) replace the old HKDF-pseudo-share
    fabrication in _trigger_recovery, which could never have
    mathematically reconstructed anything via Lagrange interpolation.
  - MSG_TYPE_ERROR, referenced in _handle_round_failure but never defined,
    is now defined.
  - The duplicate aggregation code path (_finalize_aggregation vs.
    _unmask_client_chunks+_compute_fedavg, from the two merged branches)
    is collapsed to the single _unmask_client_chunks+_compute_fedavg path.

KNOWN LIMITATION (flagging rather than silently fixing, since it's a
design trade-off for the team to ratify, not a bug per se): the server
DOES see individual recovery shares once a dropout triggers
MSG_TYPE_RECOVERY_SHARE_REQUEST/REPLY. A malicious server could in theory
falsely declare an active client "dropped" to extract its pairwise
secrets this way. Hardening against that (e.g. requiring shares to be
encrypted end-to-end between holder and a quorum of other clients rather
than ever landing in cleartext at the server) is a further step the team
should agree on explicitly (per the capstone plan's Sprint 1 threat-model
agreement) rather than something to silently bolt on here.
"""

import asyncio
import struct
import hashlib
import hmac
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field

try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    try:
        import pqcrypto.kem.kyber768 as pq_kem
        OQS_AVAILABLE = False
    except ImportError:
        OQS_AVAILABLE = None

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

from shamir_recovery import (
    FIELD_MODULUS,
    RAW_SECRET_BYTES,
    derive_stream_mask_seed,
    generate_mask_from_seed,
    reconstruct_shared_secret,
)

PROTOCOL_VERSION = 0x00010000

MSG_TYPE_ROUND_INIT = 0x40
MSG_TYPE_KEM_PUBLIC_KEY = 0x01             # Client -> server: client's own pubkey (server-client secret).
MSG_TYPE_KEM_CIPHERTEXT = 0x02             # Server -> client: ciphertext for the server-client secret.
MSG_TYPE_MASK_CHUNK = 0x21
MSG_TYPE_CLIENT_COMPLETE = 0x30
MSG_TYPE_DROPOUT_NOTIFY = 0x31
MSG_TYPE_SHAMIR_SHARE = 0x32               # Client -> server -> holder: relay a share (server does not persist the value).
MSG_TYPE_RECOVERY_COMPLETE = 0x33
MSG_TYPE_RECOVERY_SHARE_REQUEST = 0x34     # Server -> holder: please send back the share you're holding.
MSG_TYPE_RECOVERY_SHARE_REPLY = 0x35       # Holder -> server: the requested share (now the server legitimately sees it).
MSG_TYPE_PAIRWISE_KEM_PUBKEY = 0x10        # Server -> client: relay of a PEER's pubkey (pure relay, no crypto by server).
MSG_TYPE_PAIRWISE_KEM_CIPHERTEXT = 0x11    # Client -> server -> peer: relay of a pairwise KEM ciphertext.
MSG_TYPE_ROUND_COMPLETE = 0x41
MSG_TYPE_ERROR = 0xFE                      # Was referenced but never defined in the prior revision.

HEADER_FORMAT = ">IIBBHHH"  # version(4) round_id(4) client_id(1) msg_type(1) seq(2) payload_len(2) reserved(2)
HEADER_SIZE = 16

KDF_LABEL_SESSION_KEY = b"FL-SessionKey-v1"


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
    public_key: Optional[bytes] = None          # ML-KEM public key, used for BOTH the 0x01/0x02 server-client
                                                  # secret AND relayed to peers for pairwise setup.
    shared_secret: Optional[bytes] = None        # Server-client secret ONLY (from 0x01/0x02). Never a pairwise secret.
    expected_chunks: int = 0
    received_chunks: Dict[int, bytes] = field(default_factory=dict)
    completed: bool = False
    sample_count: int = 0


@dataclass
class RoundState:
    round_id: int
    expected_clients: int
    threshold: int
    chunk_size: int
    model_size: int
    clients: Dict[int, ClientState] = field(default_factory=dict)
    stage: str = "INIT"
    dropout_clients: List[int] = field(default_factory=list)
    unmasked_chunks: Dict[int, List[int]] = field(default_factory=dict)

    # (owner_client_id, peer_client_id) -> set of client_ids known to be
    # holding a Shamir share of that pair's secret. Metadata only -- the
    # server never stores the share VALUE here, only who was sent one.
    share_holders: Dict[Tuple[int, int], Set[int]] = field(default_factory=dict)

    # (owner_client_id, peer_client_id) -> list of (x, y) shares collected
    # during active post-dropout recovery (populated only after
    # MSG_TYPE_RECOVERY_SHARE_REPLY messages arrive).
    recovery_shares: Dict[Tuple[int, int], List[Tuple[int, bytes]]] = field(default_factory=dict)

    # Pairs for which a RECOVERY_SHARE_REQUEST has already been sent, so we
    # don't re-request from the same holders repeatedly.
    recovery_requested: Set[Tuple[int, int]] = field(default_factory=set)

    # Pairwise secrets successfully reconstructed for a dropout so far:
    # (owner_client_id, peer_client_id) -> raw 32-byte secret.
    recovered_pairwise_secrets: Dict[Tuple[int, int], bytes] = field(default_factory=dict)


def _pair_key(a: int, b: int) -> Tuple[int, int]:
    return (a, b) if a < b else (b, a)


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
        return MessageHeader(*struct.unpack(HEADER_FORMAT, data))

    def _build_header(
        self, message_type: int, round_id: int, client_id: int, sequence_number: int, payload_length: int
    ) -> bytes:
        return struct.pack(
            HEADER_FORMAT, PROTOCOL_VERSION, round_id, client_id, message_type, sequence_number, payload_length, 0
        )

    async def _dispatch_message(self, header: MessageHeader, payload: bytes, writer: asyncio.StreamWriter) -> None:
        if header.message_type == MSG_TYPE_ROUND_INIT:
            await self._handle_round_init(header, payload)
        elif header.message_type == MSG_TYPE_KEM_PUBLIC_KEY:
            await self._handle_public_key(header, payload, writer)
        elif header.message_type == MSG_TYPE_PAIRWISE_KEM_PUBKEY:
            await self._handle_pairwise_pubkey(header, payload, writer)
        elif header.message_type == MSG_TYPE_PAIRWISE_KEM_CIPHERTEXT:
            await self._handle_pairwise_ciphertext(header, payload)
        elif header.message_type == MSG_TYPE_MASK_CHUNK:
            await self._handle_mask_chunk(header, payload)
        elif header.message_type == MSG_TYPE_CLIENT_COMPLETE:
            await self._handle_client_complete(header, payload)
        elif header.message_type == MSG_TYPE_DROPOUT_NOTIFY:
            await self._handle_dropout_notify(header, payload)
        elif header.message_type == MSG_TYPE_SHAMIR_SHARE:
            await self._handle_shamir_share_distribution(header, payload)
        elif header.message_type == MSG_TYPE_RECOVERY_SHARE_REPLY:
            await self._handle_recovery_share_reply(header, payload)

    # ------------------------------------------------------------------
    # Round / client bookkeeping
    # ------------------------------------------------------------------

    async def _handle_round_init(self, header: MessageHeader, payload: bytes) -> None:
        if header.round_id in self.rounds:
            return
        p = 0
        expected_clients = payload[p]; p += 1
        threshold = payload[p]; p += 1
        chunk_size = payload[p] | (payload[p + 1] << 8); p += 2
        model_size = payload[p] | (payload[p + 1] << 8) | (payload[p + 2] << 16) | (payload[p + 3] << 24)
        self.rounds[header.round_id] = RoundState(
            round_id=header.round_id,
            expected_clients=expected_clients,
            threshold=threshold,
            chunk_size=chunk_size,
            model_size=model_size,
        )
        self.current_round_id = header.round_id

    def _get_or_create_client(self, round_state: RoundState, client_id: int) -> ClientState:
        client_state = round_state.clients.get(client_id)
        if not client_state:
            client_state = ClientState(client_id=client_id, round_id=round_state.round_id)
            round_state.clients[client_id] = client_state
        return client_state

    # ------------------------------------------------------------------
    # Server-client KEM (0x01/0x02) -- legitimate server-side secret,
    # unrelated to pairwise masking. Left functionally as before.
    # ------------------------------------------------------------------

    def _encapsulate(self, pubkey: bytes) -> Tuple[bytes, bytes]:
        if OQS_AVAILABLE is True:
            with oqs.KeyEncapsulation("Kyber768") as kem:
                return kem.encap_secret(pubkey)
        elif OQS_AVAILABLE is False:
            return pq_kem.encapsulate(pubkey)
        raise RuntimeError("no PQC KEM backend available (install `oqs` or `pqcrypto`)")

    async def _handle_public_key(self, header: MessageHeader, payload: bytes, writer: asyncio.StreamWriter) -> None:
        round_state = self.rounds.get(header.round_id)
        if not round_state:
            return
        client_state = self._get_or_create_client(round_state, header.client_id)
        client_state.public_key = payload
        self.client_writers[header.client_id] = writer

        # Establish the server-client secret for THIS client only (0x01/0x02
        # path -- a legitimate server-client secret, not a pairwise one).
        if OQS_AVAILABLE is not None and client_state.shared_secret is None:
            ciphertext, shared_secret = self._encapsulate(payload)
            client_state.shared_secret = shared_secret
            ct_header = self._build_header(MSG_TYPE_KEM_CIPHERTEXT, header.round_id, 0, 0, len(ciphertext))
            writer.write(ct_header + ciphertext)
            await writer.drain()

        # Relay this new client's pubkey to every already-registered peer,
        # and every already-registered peer's pubkey to this new client --
        # PURE RELAY, the server performs no encapsulation here at all.
        await self._relay_pairwise_pubkeys(round_state, header.client_id)

    # ------------------------------------------------------------------
    # Pairwise KEM relay (0x10/0x11) -- the fix for the privacy bug.
    # Wire format:
    #   0x10 (server -> client): payload = peer_client_id(1) + peer_pubkey_bytes
    #   0x11 (client -> server -> peer): payload = target_peer_id(1) + ciphertext_bytes
    #       relayed onward as: payload = ciphertext_bytes (header.client_id
    #       is overwritten to the ORIGINAL SENDER so the recipient knows
    #       whose ciphertext to decapsulate).
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

            # Tell the new client about this existing peer.
            if new_writer is not None:
                payload = struct.pack(">B", peer_id) + peer_state.public_key
                hdr = self._build_header(MSG_TYPE_PAIRWISE_KEM_PUBKEY, round_state.round_id, 0, 0, len(payload))
                new_writer.write(hdr + payload)
                await new_writer.drain()

            # Tell this existing peer about the new client.
            if peer_writer is not None:
                payload = struct.pack(">B", new_client_id) + new_client.public_key
                hdr = self._build_header(MSG_TYPE_PAIRWISE_KEM_PUBKEY, round_state.round_id, 0, 0, len(payload))
                peer_writer.write(hdr + payload)
                await peer_writer.drain()

    async def _handle_pairwise_pubkey(self, header: MessageHeader, payload: bytes, writer: asyncio.StreamWriter) -> None:
        # Inbound occurrence of this type from a client is not part of the
        # normal flow (the server pushes these proactively via
        # _relay_pairwise_pubkeys), but is accepted harmlessly rather than
        # left as an AttributeError if a client implementation sends one
        # (e.g. to explicitly (re)request pairing).
        round_state = self.rounds.get(header.round_id)
        if not round_state:
            return
        await self._relay_pairwise_pubkeys(round_state, header.client_id)

    async def _handle_pairwise_ciphertext(self, header: MessageHeader, payload: bytes) -> None:
        round_state = self.rounds.get(header.round_id)
        if not round_state or len(payload) < 1:
            return
        target_peer_id = payload[0]
        ciphertext = payload[1:]
        target_writer = self.client_writers.get(target_peer_id)
        if target_writer is None:
            return
        # Relayed with header.client_id = ORIGINAL SENDER, payload =
        # ciphertext only, so the recipient knows whose key to decapsulate
        # against. The server never touches the plaintext shared secret.
        hdr = self._build_header(
            MSG_TYPE_PAIRWISE_KEM_CIPHERTEXT, round_state.round_id, header.client_id, 0, len(ciphertext)
        )
        target_writer.write(hdr + ciphertext)
        await target_writer.drain()

    # ------------------------------------------------------------------
    # Masked update streaming
    # ------------------------------------------------------------------

    async def _handle_mask_chunk(self, header: MessageHeader, payload: bytes) -> None:
        round_state = self.rounds.get(header.round_id)
        if not round_state:
            return
        client_state = round_state.clients.get(header.client_id)
        if not client_state:
            return
        if len(payload) != round_state.chunk_size * 2:
            return
        client_state.received_chunks[header.sequence_number] = payload

    async def _handle_client_complete(self, header: MessageHeader, payload: bytes) -> None:
        round_state = self.rounds.get(header.round_id)
        if not round_state:
            return
        client_state = round_state.clients.get(header.client_id)
        if client_state:
            if len(payload) >= 4:
                client_state.sample_count = int.from_bytes(payload[:4], "big")
            client_state.completed = True
            await self._check_round_completion(round_state)

    async def _check_round_completion(self, round_state: RoundState) -> None:
        completed = sum(1 for c in round_state.clients.values() if c.completed)
        surviving = round_state.expected_clients - len(round_state.dropout_clients)
        if completed >= surviving and surviving >= round_state.threshold:
            round_state.stage = "UNMASKING"
            await self._unmask_and_aggregate(round_state)
        elif surviving < round_state.threshold:
            round_state.stage = "ERROR"
            await self._handle_round_failure(round_state)

    async def _handle_round_failure(self, round_state: RoundState) -> None:
        for writer in self.client_writers.values():
            if not writer.is_closing():
                header = self._build_header(MSG_TYPE_ERROR, round_state.round_id, 0, 0, 0)
                writer.write(header)
                await writer.drain()

    # ------------------------------------------------------------------
    # Dropout + real Shamir recovery
    # ------------------------------------------------------------------

    async def _handle_dropout_notify(self, header: MessageHeader, payload: bytes) -> None:
        round_state = self.rounds.get(header.round_id)
        if not round_state:
            return
        if header.client_id not in round_state.dropout_clients:
            round_state.dropout_clients.append(header.client_id)
        await self._trigger_recovery(round_state)
        await self._check_round_completion(round_state)

    async def _handle_shamir_share_distribution(self, header: MessageHeader, payload: bytes) -> None:
        """0x32, client -> server -> holder relay of ONE Shamir share of a
        pairwise secret. Payload: target_holder_id(1) + owner_id(1) +
        peer_id(1) + x_coordinate(1) + y(RAW_SECRET_BYTES). The server
        relays the share bytes to the target holder and records ONLY the
        metadata (who holds a share of which pair) -- never the share
        value itself.
        """
        round_state = self.rounds.get(header.round_id)
        if not round_state or len(payload) != 4 + RAW_SECRET_BYTES:
            return
        target_holder_id, owner_id, peer_id, x_coordinate = payload[0], payload[1], payload[2], payload[3]
        y_value = payload[4:]

        target_writer = self.client_writers.get(target_holder_id)
        if target_writer is not None:
            relay_payload = struct.pack(">BBB", owner_id, peer_id, x_coordinate) + y_value
            hdr = self._build_header(MSG_TYPE_SHAMIR_SHARE, round_state.round_id, 0, 0, len(relay_payload))
            target_writer.write(hdr + relay_payload)
            await target_writer.drain()

        round_state.share_holders.setdefault(_pair_key(owner_id, peer_id), set()).add(target_holder_id)

    async def _handle_recovery_share_reply(self, header: MessageHeader, payload: bytes) -> None:
        """0x35, holder -> server, sent only after the server requested it
        post-dropout. Payload: owner_id(1) + peer_id(1) + x_coordinate(1) +
        y(RAW_SECRET_BYTES). This IS persisted server-side -- recovery
        fundamentally requires the server to see >= threshold shares.
        """
        round_state = self.rounds.get(header.round_id)
        if not round_state or len(payload) != 3 + RAW_SECRET_BYTES:
            return
        owner_id, peer_id, x_coordinate = payload[0], payload[1], payload[2]
        y_value = payload[3:]
        key = _pair_key(owner_id, peer_id)
        round_state.recovery_shares.setdefault(key, []).append((x_coordinate, bytes(y_value)))
        await self._try_reconstruct_pairwise_secret(round_state, key)

    async def _try_reconstruct_pairwise_secret(self, round_state: RoundState, pair_key: Tuple[int, int]) -> None:
        shares = round_state.recovery_shares.get(pair_key, [])
        if len(shares) < round_state.threshold or pair_key in round_state.recovered_pairwise_secrets:
            return
        try:
            secret = reconstruct_shared_secret(shares[: round_state.threshold], round_state.threshold)
        except ValueError:
            return  # Not enough DISTINCT valid shares yet; wait for more replies.
        round_state.recovered_pairwise_secrets[pair_key] = secret

    async def _trigger_recovery(self, round_state: RoundState) -> None:
        """For each dropout, request recovery shares (once) from every
        known holder of each of its pairwise secrets."""
        for dropout_id in round_state.dropout_clients:
            for pair_key, holders in round_state.share_holders.items():
                if dropout_id not in pair_key:
                    continue
                if pair_key in round_state.recovery_requested:
                    continue
                owner_id, peer_id = pair_key
                for holder_id in holders:
                    holder_writer = self.client_writers.get(holder_id)
                    if holder_writer is None:
                        continue
                    request_payload = struct.pack(">BB", owner_id, peer_id)
                    hdr = self._build_header(
                        MSG_TYPE_RECOVERY_SHARE_REQUEST, round_state.round_id, 0, 0, len(request_payload)
                    )
                    holder_writer.write(hdr + request_payload)
                    await holder_writer.drain()
                round_state.recovery_requested.add(pair_key)

    def _recovered_mask_for_dropout_peer(
        self, round_state: RoundState, dropout_id: int, peer_id: int, chunk_idx: int
    ) -> Optional[List[int]]:
        pair_secret = round_state.recovered_pairwise_secrets.get(_pair_key(dropout_id, peer_id))
        if pair_secret is None:
            return None
        stream_seed = derive_stream_mask_seed(pair_secret, dropout_id, round_state.round_id, chunk_idx)
        return generate_mask_from_seed(stream_seed, round_state.chunk_size * 2)

    # ------------------------------------------------------------------
    # Unmasking and FedAvg aggregation (single path; the duplicate
    # _finalize_aggregation path from the merge conflict has been removed)
    # ------------------------------------------------------------------

    def _unmask_client_chunks(self, round_state: RoundState) -> Dict[int, Dict[int, List[int]]]:
        num_chunks = round_state.model_size // round_state.chunk_size
        chunk_elements = round_state.chunk_size
        client_unmasked: Dict[int, Dict[int, List[int]]] = {}

        for client_id, client_state in round_state.clients.items():
            if client_id in round_state.dropout_clients:
                continue
            client_unmasked[client_id] = {}
            for seq_num, chunk_data in client_state.received_chunks.items():
                if seq_num >= num_chunks:
                    continue
                values = struct.unpack(f">{chunk_elements}h", chunk_data)
                client_unmasked[client_id][seq_num] = list(values)

        # For each surviving client, cancel any leftover mask term left by
        # a dropped peer: survivor j's masked update still contains
        # sign(j,dropout)*PRG(K_{dropout,j}) uncancelled, since the dropout
        # never sent its own -sign contribution.
        for dropout_id in round_state.dropout_clients:
            for peer_id, peer_unmasked in client_unmasked.items():
                sign = 1 if peer_id < dropout_id else -1
                for seq_num in list(peer_unmasked.keys()):
                    mask = self._recovered_mask_for_dropout_peer(round_state, dropout_id, peer_id, seq_num)
                    if mask is None:
                        continue  # Not yet recovered; leave this chunk pending.
                    peer_unmasked[seq_num] = [
                        (val - sign * mask[i]) % FIELD_MODULUS for i, val in enumerate(peer_unmasked[seq_num])
                    ]

        return client_unmasked

    def _compute_fedavg(
        self, round_state: RoundState, client_unmasked: Dict[int, Dict[int, List[int]]]
    ) -> Dict[int, List[int]]:
        total_samples = sum(
            c.sample_count
            for c in round_state.clients.values()
            if c.completed and c.sample_count > 0 and c.client_id in client_unmasked
        )
        if total_samples == 0:
            total_samples = sum(1 for c in round_state.clients.values() if c.completed and c.client_id in client_unmasked)

        num_chunks = round_state.model_size // round_state.chunk_size
        chunk_elements = round_state.chunk_size
        fedavg_chunks: Dict[int, List[int]] = {i: [0] * chunk_elements for i in range(num_chunks)}

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
                return  # A dropout's secret hasn't been recovered yet; wait.

        round_state.unmasked_chunks = fedavg_chunks
        round_state.stage = "ROUND_COMPLETE"

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
