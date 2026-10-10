"""
host_server/client_manager.py

Owner: Member 2 (Python host protocol and dropout recovery).

Factored out of protocol_bridge.py: the per-round data model (ClientState,
RoundState), the explicit round-stage state machine, and the protocol
exception hierarchy protocol_bridge.py's validation layer raises.

RoundStage's ordering deliberately mirrors round_state_t in
src/core_rtos/protocol_types.h (ROUND_STATE_INIT=0 .. ROUND_STATE_ABORTED=8)
so the two sides of the project describe the same state machine, even
though Member 1/3's C code and this Python reference don't share a build --
this is the kind of thing Section 3 of the capstone plan asks to be an
explicit, agreed, version-controlled contract rather than two
independently-invented numberings that happen to drift apart.

Assumed library versions:
    Python >= 3.9
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Set, Tuple


class RoundStage(IntEnum):
    """Mirrors round_state_t in protocol_types.h."""
    INIT = 0
    KEY_SETUP = 1
    MASK_SETUP = 2
    MASKED_UPDATE_STREAM = 3
    DROPOUT_DETECTION = 4
    MASK_RECOVERY = 5
    UNMASK = 6
    COMPLETE = 7
    ABORTED = 8


# Explicit allowed transitions -- any transition not listed here is
# rejected by transition_round_stage() below, rather than allowed
# implicitly by just assigning a new stage value.
_ALLOWED_TRANSITIONS: Dict[RoundStage, Set[RoundStage]] = {
    RoundStage.INIT: {RoundStage.KEY_SETUP, RoundStage.ABORTED},
    # KEY_SETUP -> MASKED_UPDATE_STREAM (skipping MASK_SETUP) is included
    # deliberately: a fast client can finish its OWN pairwise setup (via
    # direct peer-to-peer relay) and start streaming before the round-wide
    # stage has caught up to MASK_SETUP, which only flips once the LAST
    # client's registration handler happens to reach that check --
    # concurrent per-connection handlers racing on shared round_state is
    # expected here, not a protocol violation. Rejecting that chunk
    # outright (as an earlier revision did) silently drops valid data,
    # since mock_client.py sends chunks fire-and-forget without checking
    # for an error reply.
    RoundStage.KEY_SETUP: {RoundStage.MASK_SETUP, RoundStage.MASKED_UPDATE_STREAM, RoundStage.ABORTED},
    RoundStage.MASK_SETUP: {RoundStage.MASKED_UPDATE_STREAM, RoundStage.ABORTED},
    RoundStage.MASKED_UPDATE_STREAM: {RoundStage.DROPOUT_DETECTION, RoundStage.UNMASK, RoundStage.ABORTED},
    RoundStage.DROPOUT_DETECTION: {RoundStage.MASK_RECOVERY, RoundStage.UNMASK, RoundStage.ABORTED},
    RoundStage.MASK_RECOVERY: {RoundStage.UNMASK, RoundStage.ABORTED},
    RoundStage.UNMASK: {RoundStage.COMPLETE, RoundStage.ABORTED},
    RoundStage.COMPLETE: set(),   # Terminal.
    RoundStage.ABORTED: set(),    # Terminal.
}


# ---------------------------------------------------------------------------
# Protocol exception hierarchy
# ---------------------------------------------------------------------------

class ProtocolError(Exception):
    """Base class for all rejectable-message conditions. protocol_bridge.py
    catches this (not bare Exception) around dispatch, so a malformed
    message from one client degrades to an error reply rather than an
    unhandled exception killing that connection's handler task."""


class MalformedMessageError(ProtocolError):
    """Payload length, structure, or field values don't match what the
    message_type requires (e.g. a chunk of the wrong byte length, a
    truncated Shamir-share payload)."""


class ProtocolVersionError(ProtocolError):
    """header.protocol_version != PROTOCOL_VERSION."""


class ReplayError(ProtocolError):
    """header.sequence_number <= the last accepted sequence number for
    this (round_id, client_id) pair."""


class UnknownRoundError(ProtocolError):
    """header.round_id does not correspond to an active round (and the
    message isn't itself a ROUND_INIT, which is exempt from this check
    since it's what CREATES the round)."""


class UnknownClientError(ProtocolError):
    """header.client_id is not registered in the target round."""


class InvalidStateError(ProtocolError):
    """An operation was attempted while the round was in an incompatible
    RoundStage, or an illegal stage transition was requested."""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class ClientState:
    client_id: int
    round_id: int
    public_key: bytes = None
    shared_secret: bytes = None          # Server-client secret ONLY (0x01/0x02 path), never a pairwise secret.
    expected_chunks: int = 0
    received_chunks: Dict[int, bytes] = field(default_factory=dict)
    completed: bool = False
    sample_count: int = 0
    last_sequence_number: int = 0        # Replay guard high-water mark.
    dropped: bool = False


@dataclass
class RoundState:
    round_id: int
    expected_clients: int
    threshold: int
    chunk_size: int
    model_size: int
    clients: Dict[int, ClientState] = field(default_factory=dict)
    stage: RoundStage = RoundStage.INIT
    dropout_clients: List[int] = field(default_factory=list)
    unmasked_chunks: Dict[int, List[int]] = field(default_factory=dict)

    # (owner_client_id, peer_client_id) -> set of client_ids known to be
    # holding a Shamir share of that pair's secret (metadata only; the
    # server never stores the share VALUE here, only who was sent one).
    share_holders: Dict[Tuple[int, int], Set[int]] = field(default_factory=dict)

    # (owner_client_id, peer_client_id) -> list of (x, y) shares collected
    # during active post-dropout recovery.
    recovery_shares: Dict[Tuple[int, int], List[Tuple[int, bytes]]] = field(default_factory=dict)

    # Pairs for which a RECOVERY_SHARE_REQUEST has already been sent.
    recovery_requested: Set[Tuple[int, int]] = field(default_factory=set)

    # Pairwise secrets successfully reconstructed for a dropout so far.
    recovered_pairwise_secrets: Dict[Tuple[int, int], bytes] = field(default_factory=dict)


def pair_key(a: int, b: int) -> Tuple[int, int]:
    return (a, b) if a < b else (b, a)


def get_or_create_client(round_state: RoundState, client_id: int) -> ClientState:
    client_state = round_state.clients.get(client_id)
    if not client_state:
        client_state = ClientState(client_id=client_id, round_id=round_state.round_id)
        round_state.clients[client_id] = client_state
    return client_state


def transition_round_stage(round_state: RoundState, new_stage: RoundStage) -> None:
    """Validates and applies a RoundStage transition. Raises
    InvalidStateError for any transition not present in
    _ALLOWED_TRANSITIONS, rather than allowing an implicit/unchecked
    stage change (this was a gap in the prior version of this file, which
    just assigned free-form strings to `stage` with no enforcement)."""
    allowed = _ALLOWED_TRANSITIONS.get(round_state.stage, set())
    if new_stage not in allowed:
        raise InvalidStateError(
            f"illegal round stage transition: {round_state.stage.name} -> {new_stage.name}"
        )
    round_state.stage = new_stage


def detect_dropouts(round_state: RoundState) -> Set[int]:
    """Returns client_ids that registered but are neither already marked
    dropped nor completed. Pure function: does not itself decide WHEN to
    call this (that's a timeout/explicit-notify policy decision made by
    the caller), only WHO qualifies once called."""
    return {
        cid for cid, state in round_state.clients.items()
        if not state.dropped and not state.completed
    }
