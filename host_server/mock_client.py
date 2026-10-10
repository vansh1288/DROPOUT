"""
host_server/mock_client.py

A reference/test client for the DROPOUT host-only simulation. Despite the
name, the KEM crypto here is REAL (ML-KEM-768 via `oqs` or `pqcrypto`, same
backend-detection pattern as protocol_bridge.py's server-client path) --
"mock" refers only to the model update itself, which is randomly generated
rather than coming from an actual training step, matching the plan's
Sprint 2 "mock crypto" allowance for round-management testing (the mock
here is the DATA, not the cryptography).

This revision replaces a prior version that used X25519 ECDH for pairwise
agreement (mismatched with the server's ML-KEM-based design) and never
sent any MSG_TYPE_SHAMIR_SHARE at all (meaning dropout recovery had
nothing real to reconstruct from). Fixed here:
  - Pairwise secrets are now established via real ML-KEM, with a fixed
    lower-id-initiates rule so both sides of a pair derive the identical
    secret (only one side may encapsulate, or the two sides would derive
    two DIFFERENT secrets instead of matching ones).
  - Each pairwise secret is Shamir-split (GF(256), byte-exact -- see
    shamir_recovery.split_shared_secret) and distributed to every OTHER
    known client as a potential future recovery holder.
  - RECOVERY_SHARE_REQUEST is handled by replying with whatever share this
    client is holding for the requested pair, if any.
  - The per-chunk stream seed is derived using min(my_id, peer_id) as the
    canonical label for BOTH sides of a pair, matching the server's
    recovery-side fix in protocol_bridge.py's _recovered_mask_for_dropout_peer
    (previously this label was inconsistent between the live-masking and
    recovery code paths, which would have made cancellation silently
    produce the wrong aggregate instead of raising an error).

Assumed library versions:
    Python >= 3.9
    oqs (python-oqs) OR pqcrypto -- at least one real ML-KEM-768 backend
        is required; this client raises at startup if neither is
        importable, rather than silently falling back to non-PQC crypto
        (unlike the server's optional 0x01/0x02 path, pairwise correctness
        here is the entire point of the exercise).
"""

from __future__ import annotations

import asyncio
import struct
import sys
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, Tuple

try:
    import oqs
    OQS_AVAILABLE = True
except ImportError:
    try:
        import pqcrypto.kem.kyber768 as pq_kem
        OQS_AVAILABLE = False
    except ImportError:
        raise RuntimeError(
            "mock_client.py requires a real ML-KEM-768 backend: install either "
            "`oqs` (liboqs-python) or `pqcrypto`."
        )

from shamir_recovery import (
    FIELD_MODULUS,
    RAW_SECRET_BYTES,
    derive_stream_mask_seed,
    generate_mask_from_seed,
    split_shared_secret,
)

HEADER_FORMAT = ">IIBBHHH"
HEADER_SIZE = 16
PROTOCOL_VERSION = 0x00010000

MSG_TYPE_ROUND_INIT = 0x40
MSG_TYPE_KEM_PUBLIC_KEY = 0x01
MSG_TYPE_KEM_CIPHERTEXT = 0x02
MSG_TYPE_MASK_CHUNK = 0x21
MSG_TYPE_CLIENT_COMPLETE = 0x30
MSG_TYPE_DROPOUT_NOTIFY = 0x31
MSG_TYPE_SHAMIR_SHARE = 0x32
MSG_TYPE_RECOVERY_SHARE_REQUEST = 0x34
MSG_TYPE_RECOVERY_SHARE_REPLY = 0x35
MSG_TYPE_PAIRWISE_KEM_PUBKEY = 0x10
MSG_TYPE_PAIRWISE_KEM_CIPHERTEXT = 0x11
MSG_TYPE_ROUND_COMPLETE = 0x41
MSG_TYPE_ERROR = 0xFE

SHAMIR_THRESHOLD_FALLBACK = 2  # Used only if the round's own threshold is unusable as a share threshold.


def _pair_key(a: int, b: int) -> Tuple[int, int]:
    return (a, b) if a < b else (b, a)


def _kem_generate_keypair() -> Tuple[bytes, object]:
    """Returns (public_key_bytes, secret_key_handle). The secret key
    handle's type differs by backend (an oqs.KeyEncapsulation context vs.
    raw pqcrypto secret key bytes) -- _kem_decapsulate below branches on
    OQS_AVAILABLE to use it correctly either way."""
    if OQS_AVAILABLE:
        kem = oqs.KeyEncapsulation("Kyber768")
        public_key = kem.generate_keypair()
        return public_key, kem  # `kem` itself holds the secret key internally.
    else:
        public_key, secret_key = pq_kem.keypair()
        return public_key, secret_key


def _kem_encapsulate(peer_public_key: bytes) -> Tuple[bytes, bytes]:
    if OQS_AVAILABLE:
        with oqs.KeyEncapsulation("Kyber768") as kem:
            return kem.encap_secret(peer_public_key)
    else:
        return pq_kem.encrypt(peer_public_key)  # pqcrypto returns (ciphertext, shared_secret)


def _kem_decapsulate(secret_key_handle: object, ciphertext: bytes) -> bytes:
    if OQS_AVAILABLE:
        return secret_key_handle.decap_secret(ciphertext)  # `secret_key_handle` is the oqs.KeyEncapsulation context.
    else:
        return pq_kem.decrypt(secret_key_handle, ciphertext)


@dataclass
class RoundConfig:
    expected_clients: int
    threshold: int
    chunk_size: int
    model_size: int

    @property
    def num_chunks(self) -> int:
        return self.model_size // self.chunk_size


@dataclass
class ClientSession:
    client_id: int
    round_id: int
    public_key: bytes
    secret_key_handle: object

    round_config: Optional[RoundConfig] = None
    pairwise_secrets: Dict[int, bytes] = field(default_factory=dict)       # peer_id -> raw 32-byte secret
    known_peer_pubkeys: Dict[int, bytes] = field(default_factory=dict)     # peer_id -> pubkey, for log/debug only
    shares_distributed_for: Set[int] = field(default_factory=set)         # peer_ids whose pair secret we've already split+sent
    held_shares: Dict[Tuple[int, int], Tuple[int, bytes]] = field(default_factory=dict)  # pair_key -> (x, y)
    plaintext_chunks: Dict[int, list] = field(default_factory=dict)       # chunk_idx -> list[int] "model update"
    sample_count: int = 100  # Arbitrary mock sample count for FedAvg weighting.


def _generate_mock_plaintext_chunk(chunk_size: int) -> list:
    """Generates a deterministic-looking but random mock model-update chunk,
    as field elements in [0, FIELD_MODULUS). Real training data plugs in
    here later -- this is the "mock" the module docstring refers to."""
    import secrets as _secrets
    return [_secrets.randbelow(FIELD_MODULUS) for _ in range(chunk_size)]


def _stream_seed_for_peer(session: ClientSession, peer_id: int, chunk_idx: int) -> bytes:
    """Canonical stream-seed derivation: ALWAYS keyed on min(my_id, peer_id),
    never on "whichever side is computing this right now" -- both live
    parties in a pair must derive the identical value for cancellation to
    work, and the identity of a future dropout can't be known in advance."""
    pair_secret = session.pairwise_secrets[peer_id]
    canonical_id = min(session.client_id, peer_id)
    return derive_stream_mask_seed(pair_secret, canonical_id, session.round_id, chunk_idx)


def _signed_mask_contribution(session: ClientSession, peer_id: int, chunk_idx: int, chunk_size: int) -> list:
    """SwiftAgg-style convention: the lower-id party of a pair ADDS the
    mask, the higher-id party SUBTRACTS it, so the two cancel when summed
    at the server."""
    stream_seed = _stream_seed_for_peer(session, peer_id, chunk_idx)
    mask = generate_mask_from_seed(stream_seed, chunk_size * 2)
    sign = 1 if session.client_id < peer_id else -1
    return [sign * m for m in mask]


class MockClient:
    def __init__(self, client_id: int, round_id: int, host: str, port: int, simulate_crash_after_sharing: bool = False):
        self.client_id = client_id
        self.round_id = round_id
        self.host = host
        self.port = port
        self.reader: Optional[asyncio.StreamReader] = None
        self.writer: Optional[asyncio.StreamWriter] = None
        self.session: Optional[ClientSession] = None
        self._sequence_counter = 0
        # Test/simulation hook: when True, this client completes pairing
        # and Shamir share distribution normally, then stops (as if it
        # crashed) instead of ever streaming -- a deterministic way to
        # exercise dropout recovery, instead of racing a task-cancellation
        # against this client's own real async progress.
        self.simulate_crash_after_sharing = simulate_crash_after_sharing

    def _next_sequence(self) -> int:
        self._sequence_counter += 1
        return self._sequence_counter

    async def _send(self, message_type: int, payload: bytes) -> None:
        header = struct.pack(
            HEADER_FORMAT, PROTOCOL_VERSION, self.round_id, self.client_id,
            message_type, self._next_sequence(), len(payload), 0,
        )
        self.writer.write(header + payload)
        await self.writer.drain()

    async def run(self) -> None:
        self.reader, self.writer = await asyncio.open_connection(self.host, self.port)
        public_key, secret_key_handle = _kem_generate_keypair()
        self.session = ClientSession(
            client_id=self.client_id, round_id=self.round_id,
            public_key=public_key, secret_key_handle=secret_key_handle,
        )

        await self._send(MSG_TYPE_KEM_PUBLIC_KEY, public_key)

        try:
            while True:
                header_data = await self.reader.readexactly(HEADER_SIZE)
                _, round_id, sender_client_id, message_type, seq, payload_len, _ = struct.unpack(
                    HEADER_FORMAT, header_data
                )
                payload = await self.reader.readexactly(payload_len)
                await self._handle_message(message_type, sender_client_id, payload)
        except asyncio.IncompleteReadError:
            pass
        except ConnectionResetError:
            pass
        finally:
            self.writer.close()
            await self.writer.wait_closed()

    async def _handle_message(self, message_type: int, sender_client_id: int, payload: bytes) -> None:
        session = self.session
        assert session is not None

        if message_type == MSG_TYPE_ROUND_INIT:
            expected_clients, threshold, chunk_size, model_size = struct.unpack("<BBHI", payload)
            session.round_config = RoundConfig(expected_clients, threshold, chunk_size, model_size)

        elif message_type == MSG_TYPE_KEM_CIPHERTEXT:
            # Server-client secret (0x01/0x02 path) -- decapsulated for
            # completeness but not used for masking (masking only ever
            # uses pairwise, client-to-client secrets).
            _kem_decapsulate(session.secret_key_handle, payload)

        elif message_type == MSG_TYPE_PAIRWISE_KEM_PUBKEY:
            peer_id = payload[0]
            peer_pubkey = payload[1:]
            session.known_peer_pubkeys[peer_id] = peer_pubkey
            if peer_id in session.pairwise_secrets:
                return  # Already paired with this peer.
            if session.client_id < peer_id:
                # Lower id initiates: encapsulate against the peer's
                # pubkey, keep the resulting secret, send the ciphertext
                # for the peer to decapsulate.
                ciphertext, shared_secret = _kem_encapsulate(peer_pubkey)
                session.pairwise_secrets[peer_id] = shared_secret
                await self._send(MSG_TYPE_PAIRWISE_KEM_CIPHERTEXT, struct.pack(">B", peer_id) + ciphertext)
                await self._maybe_distribute_shares(session, peer_id)
            # else: higher id waits for the initiator's ciphertext (next branch).

        elif message_type == MSG_TYPE_PAIRWISE_KEM_CIPHERTEXT:
            peer_id = sender_client_id
            shared_secret = _kem_decapsulate(session.secret_key_handle, payload)
            session.pairwise_secrets[peer_id] = shared_secret
            await self._maybe_distribute_shares(session, peer_id)

        elif message_type == MSG_TYPE_SHAMIR_SHARE:
            owner_id, peer_id, x_coordinate = payload[0], payload[1], payload[2]
            y_value = payload[3:]
            session.held_shares[_pair_key(owner_id, peer_id)] = (x_coordinate, bytes(y_value))

        elif message_type == MSG_TYPE_RECOVERY_SHARE_REQUEST:
            owner_id, peer_id = payload[0], payload[1]
            held = session.held_shares.get(_pair_key(owner_id, peer_id))
            if held is not None:
                x_coordinate, y_value = held
                reply_payload = struct.pack(">BBB", owner_id, peer_id, x_coordinate) + y_value
                await self._send(MSG_TYPE_RECOVERY_SHARE_REPLY, reply_payload)

        elif message_type == MSG_TYPE_ROUND_COMPLETE:
            pass  # Aggregate result arrived; a real client would apply it to its local model here.

        await self._maybe_start_streaming(session)

    async def _maybe_distribute_shares(self, session: ClientSession, peer_id: int) -> None:
        """Once a pairwise secret with `peer_id` is established, Shamir-
        split it and send one share to every OTHER known client (not the
        pair's own two members, who already know the secret directly).
        Requires at least `threshold` other known clients to be meaningful;
        with fewer, recovery for this pair simply isn't possible and we
        say so rather than silently skipping without explanation.
        """
        if peer_id in session.shares_distributed_for or session.round_config is None:
            return
        threshold = session.round_config.threshold or SHAMIR_THRESHOLD_FALLBACK

        other_client_ids = sorted(
            cid for cid in session.known_peer_pubkeys if cid not in (session.client_id, peer_id)
        )
        if len(other_client_ids) < threshold:
            print(
                f"[client {session.client_id}] only {len(other_client_ids)} other known clients "
                f"(need >= {threshold}) -- skipping Shamir distribution for pair with {peer_id}; "
                f"this pair's secret will NOT be recoverable if either side drops.",
                file=sys.stderr,
            )
            session.shares_distributed_for.add(peer_id)
            return

        secret = session.pairwise_secrets[peer_id]
        shares = split_shared_secret(secret, num_shares=len(other_client_ids), threshold=threshold)
        owner_id, other_id = _pair_key(session.client_id, peer_id)
        for (x_coordinate, y_value), holder_id in zip(shares, other_client_ids):
            distribution_payload = (
                struct.pack(">BBB", holder_id, owner_id, other_id) + struct.pack(">B", x_coordinate) + y_value
            )
            await self._send(MSG_TYPE_SHAMIR_SHARE, distribution_payload)

        session.shares_distributed_for.add(peer_id)

    async def _maybe_start_streaming(self, session: ClientSession) -> None:
        """Begins masked-update streaming once this client has an
        established pairwise secret with every other expected client. A
        production client would want a timeout/partial-pairing fallback
        here; this reference client keeps it simple and waits for full
        pairing, which is fine for a host-only simulation with a fixed,
        known client count.
        """
        if session.round_config is None or session.plaintext_chunks:
            return  # No round config yet, or streaming already started.
        if len(session.pairwise_secrets) < session.round_config.expected_clients - 1:
            return
        if self.simulate_crash_after_sharing:
            # Pretend this client crashed right after finishing pairing +
            # share distribution, before ever streaming -- the connection
            # stays open (a real crash wouldn't politely close it either),
            # the test harness is responsible for forcibly closing it.
            return

        num_chunks = session.round_config.num_chunks
        chunk_size = session.round_config.chunk_size
        for chunk_idx in range(num_chunks):
            plaintext = _generate_mock_plaintext_chunk(chunk_size)
            session.plaintext_chunks[chunk_idx] = plaintext

            masked = list(plaintext)
            for peer_id in session.pairwise_secrets:
                contribution = _signed_mask_contribution(session, peer_id, chunk_idx, chunk_size)
                masked = [(m + c) % FIELD_MODULUS for m, c in zip(masked, contribution)]

            # IMPORTANT: the header's sequence_number is a pure per-client
            # anti-replay counter (strictly increasing across EVERY
            # message type this client sends, enforced server-side), not a
            # chunk index -- a chunk's position must be carried in the
            # PAYLOAD instead, or the server's reassembly ends up keying
            # received_chunks by an unrelated counter value and discards
            # every real chunk as "out of range" (num_chunks is small;
            # the anti-replay sequence number is not).
            masked_bytes = struct.pack(f">{chunk_size}h", *masked)
            chunk_payload = struct.pack(">H", chunk_idx) + masked_bytes
            await self._send(MSG_TYPE_MASK_CHUNK, chunk_payload)

        await self._send(MSG_TYPE_CLIENT_COMPLETE, session.sample_count.to_bytes(4, "big"))


def main() -> None:
    if len(sys.argv) < 5:
        print("usage: mock_client.py <client_id> <round_id> <host> <port>", file=sys.stderr)
        sys.exit(1)
    client_id = int(sys.argv[1])
    round_id = int(sys.argv[2])
    host = sys.argv[3]
    port = int(sys.argv[4])
    asyncio.run(MockClient(client_id, round_id, host, port).run())


if __name__ == "__main__":
    main()
