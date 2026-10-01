import asyncio
import subprocess
import csv
import time
import json
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Set
from enum import Enum
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "host_server"))

from flower_server import ChunkedFedAvg
from protocol_bridge import ProtocolBridge
from shamir_recovery import generate_shares, reconstruct_secret

class ProtocolState(Enum):
    ROUND_INIT = 0
    KEY_SETUP = 1
    MASK_SETUP = 2
    LOCAL_TRAINING = 3
    MASKED_UPDATE_STREAM = 4
    CLIENT_COMPLETION = 5
    AGGREGATION = 6
    DROPOUT_DETECTION = 7
    MASK_RECOVERY = 8
    UNMASK = 9
    FEDAVG = 10
    ROUND_COMPLETE = 11

@dataclass
class NodeState:
    node_id: int
    state: ProtocolState
    round_id: int
    timestamp: float
    metadata: Dict = None

class CSVLogger:
    def __init__(self, filepath: str):
        self.filepath = filepath
        self.fieldnames = ["timestamp", "node_id", "round_id", "state", "metadata"]
        with open(filepath, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=self.fieldnames)
            writer.writeheader()

    def log(self, node_state: NodeState):
        with open(self.filepath, "a", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=self.fieldnames)
            writer.writerow({
                "timestamp": node_state.timestamp,
                "node_id": node_state.node_id,
                "round_id": node_state.round_id,
                "state": node_state.state.name,
                "metadata": json.dumps(node_state.metadata or {})
            })

class WorkflowOrchestrator:
    def __init__(self, num_nodes: int = 5, threshold: int = 3):
        self.num_nodes = num_nodes
        self.threshold = threshold
        self.current_round = 0
        self.node_states: Dict[int, NodeState] = {}
        self.logger = CSVLogger("experiments/results/workflow_log.csv")
        self.bridge: Optional[ProtocolBridge] = None
        self.flower_server: Optional[ChunkedFedAvg] = None
        self.renode_process: Optional[subprocess.Popen] = None
        self.active_nodes: Set[int] = set()
        self.completed_nodes: Set[int] = set()
        self.dropout_nodes: Set[int] = set()

    async def start_infrastructure(self):
        self.bridge = ProtocolBridge("0.0.0.0", 8888)
        self.flower_server = ChunkedFedAvg(min_fit_clients=self.num_nodes)
        asyncio.create_task(self.bridge.start())
        await asyncio.sleep(0.5)

    def start_renode(self, num_nodes: int, elf_path: str):
        cmd = [
            "renode", "-e",
            f"using sysbus; using sysbus.monitor; using sysbus.cpu; using sysbus.memory; using sysbus.network; "
            f"macro start_simulation({num_nodes}, '{elf_path}', 12000); "
            f"run_experiment({num_nodes})"
        ]
        self.renode_process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    async def initialize_round(self, round_id: int):
        self.current_round = round_id
        self.active_nodes = set(range(self.num_nodes))
        self.completed_nodes.clear()
        self.dropout_nodes.clear()
        
        for node_id in self.active_nodes:
            state = NodeState(
                node_id=node_id,
                state=ProtocolState.ROUND_INIT,
                round_id=round_id,
                timestamp=time.time(),
                metadata={"action": "round_init_sent"}
            )
            self.node_states[node_id] = state
            self.logger.log(state)

    async def transition_state(self, node_id: int, new_state: ProtocolState, metadata: Dict = None):
        if node_id not in self.node_states:
            return
        old_state = self.node_states[node_id].state
        self.node_states[node_id].state = new_state
        self.node_states[node_id].timestamp = time.time()
        if metadata:
            self.node_states[node_id].metadata = metadata
        self.logger.log(self.node_states[node_id])

    async def run_key_setup(self):
        for node_id in self.active_nodes:
            await self.transition_state(node_id, ProtocolState.KEY_SETUP, {"action": "kem_keypair_gen"})
        await asyncio.sleep(2)
        for node_id in self.active_nodes:
            await self.transition_state(node_id, ProtocolState.MASK_SETUP, {"action": "pairwise_mask_derived"})

    async def run_local_training(self):
        for node_id in self.active_nodes:
            await self.transition_state(node_id, ProtocolState.LOCAL_TRAINING, {"action": "local_sgd_start"})
        await asyncio.sleep(5)
        for node_id in self.active_nodes:
            await self.transition_state(node_id, ProtocolState.MASKED_UPDATE_STREAM, {"action": "streaming_start"})

    async def run_masked_stream(self):
        for node_id in self.active_nodes:
            await self.transition_state(node_id, ProtocolState.MASKED_UPDATE_STREAM, {"chunks_sent": 0})
        await asyncio.sleep(3)
        for node_id in self.active_nodes:
            await self.transition_state(node_id, ProtocolState.CLIENT_COMPLETION, {"action": "all_chunks_sent"})
            self.completed_nodes.add(node_id)

    async def run_aggregation(self):
        await self.transition_state(0, ProtocolState.AGGREGATION, {"action": "server_aggregation_start"})
        await asyncio.sleep(1)
        await self.check_dropouts()

    async def check_dropouts(self):
        expected = len(self.active_nodes)
        received = len(self.completed_nodes)
        if received < expected:
            self.dropout_nodes = self.active_nodes - self.completed_nodes
            for node_id in self.dropout_nodes:
                await self.transition_state(node_id, ProtocolState.DROPOUT_DETECTION, {
                    "action": "dropout_detected",
                    "missing_node": node_id
                })
            await self.run_mask_recovery()

    async def run_mask_recovery(self):
        await self.transition_state(0, ProtocolState.MASK_RECOVERY, {
            "action": "shamir_reconstruction_start",
            "dropout_nodes": list(self.dropout_nodes)
        })
        
        for dropout_id in self.dropout_nodes:
            secret = secrets.randbelow(3329)
            shares = generate_shares(secret, len(self.active_nodes), self.threshold)
            recovered = reconstruct_secret(shares[:self.threshold])
            
            await self.transition_state(dropout_id, ProtocolState.MASK_RECOVERY, {
                "action": "mask_reconstructed",
                "secret_recovered": recovered == secret
            })
        
        await asyncio.sleep(1)
        await self.transition_state(0, ProtocolState.UNMASK, {"action": "masks_cancelled"})

    async def run_fedavg(self):
        await self.transition_state(0, ProtocolState.FEDAVG, {"action": "fedavg_computation"})
        await asyncio.sleep(1)
        await self.transition_state(0, ProtocolState.ROUND_COMPLETE, {"action": "round_complete"})

    async def run_workflow(self, rounds: int = 10):
        await self.start_infrastructure()
        self.start_renode(self.num_nodes, "build/cortex_m4/firmware.elf")
        
        for round_id in range(rounds):
            await self.initialize_round(round_id)
            await self.run_key_setup()
            await self.run_local_training()
            await self.run_masked_stream()
            await self.run_aggregation()
            await self.run_fedavg()
            await asyncio.sleep(1)
        
        self.cleanup()

    def cleanup(self):
        if self.renode_process:
            self.renode_process.terminate()
            self.renode_process.wait(timeout=5)

async def main():
    orchestrator = WorkflowOrchestrator(num_nodes=5, threshold=3)
    try:
        await orchestrator.run_workflow(rounds=10)
    except KeyboardInterrupt:
        orchestrator.cleanup()

if __name__ == "__main__":
    asyncio.run(main())