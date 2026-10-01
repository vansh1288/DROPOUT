def fix_baseline_server_py():
    with open(r'C:\DROP\host_server\baseline_server.py', 'r') as f:
        content = f.read()

    content = content.replace(
        'MSG_TYPE_RECOVERY_COMPLETE = 0x33',
        'MSG_TYPE_RECOVERY_COMPLETE = 0x33\nMSG_TYPE_PAIRWISE_KEM_PUBKEY = 0x10\nMSG_TYPE_PAIRWISE_KEM_CIPHERTEXT = 0x11'
    )

    content = content.replace(
        '        elif header.message_type == MSG_TYPE_ROUND_INIT:\n            await self._handle_round_init(header, payload)',
        '        elif header.message_type == MSG_TYPE_ROUND_INIT:\n            await self._handle_round_init(header, payload)\n        elif header.message_type == MSG_TYPE_PAIRWISE_KEM_PUBKEY:\n            await self._handle_pairwise_pubkey(header, payload, writer)\n        elif header.message_type == MSG_TYPE_PAIRWISE_KEM_CIPHERTEXT:\n            await self._handle_pairwise_ciphertext(header, payload)'
    )

    old_setup = '''    async def _setup_keys_and_masks(self, round_state: RoundState):
        for client_id, client_state in round_state.clients.items():
            if client_state.public_key and not client_state.shared_secret:
                ct, ss = self._encapsulate(client_state.public_key)
                client_state.shared_secret = ss
                header = self._build_header(
                    MSG_TYPE_KEM_CIPHERTEXT,
                    round_state.round_id,
                    0,
                    0,
                    len(ct),
                )
                writer = self.client_writers.get(client_id)
                if writer:
                    writer.write(header + ct)
                    await writer.drain()
        for client_id, client_state in round_state.clients.items():
            if client_state.shared_secret:
                for peer_id, peer_state in round_state.clients.items():
                    if peer_id != client_id and peer_state.shared_secret:
                        seed = self._derive_pairwise_seed(client_state.shared_secret, min(client_id, peer_id), max(client_id, peer_id), round_state.round_id)
                        client_state.pairwise_seeds[peer_id] = seed
        round_state.stage = "MASK_SETUP"'''

    new_setup = '''    async def _setup_keys_and_masks(self, round_state: RoundState):
        for client_id, client_state in round_state.clients.items():
            if client_state.public_key and not client_state.shared_secret:
                ct, ss = self._encapsulate(client_state.public_key)
                client_state.shared_secret = ss
                header = self._build_header(
                    MSG_TYPE_KEM_CIPHERTEXT,
                    round_state.round_id,
                    0,
                    0,
                    len(ct),
                )
                writer = self.client_writers.get(client_id)
                if writer:
                    writer.write(header + ct)
                    await writer.drain()
        
        client_ids = list(round_state.clients.keys())
        for i, client_a_id in enumerate(client_ids):
            client_a_state = round_state.clients[client_a_id]
            for client_b_id in client_ids[i+1:]:
                client_b_state = round_state.clients[client_b_id]
                if client_a_state.shared_secret and client_b_state.shared_secret:
                    continue
                
                if client_a_state.public_key and client_b_state.public_key:
                    if client_a_id < client_b_id:
                        initiator, responder = client_a_id, client_b_id
                        initiator_state, responder_state = client_a_state, client_b_state
                    else:
                        initiator, responder = client_b_id, client_a_id
                        initiator_state, responder_state = client_b_state, client_a_state
                    
                    if initiator_state.shared_secret and responder_state.shared_secret:
                        continue
                    
                    if not initiator_state.shared_secret:
                        ct, ss = self._encapsulate(initiator_state.public_key)
                        initiator_state.shared_secret = ss
                        header = self._build_header(
                            MSG_TYPE_KEM_CIPHERTEXT,
                            round_state.round_id,
                            0,
                            0,
                            len(ct),
                        )
                        writer = self.client_writers.get(initiator)
                        if writer:
                            writer.write(header + ct)
                            await writer.drain()
                    
                    if not responder_state.shared_secret:
                        ct, ss = self._encapsulate(responder_state.public_key)
                        responder_state.shared_secret = ss
                        header = self._build_header(
                            MSG_TYPE_KEM_CIPHERTEXT,
                            round_state.round_id,
                            0,
                            0,
                            len(ct),
                        )
                        writer = self.client_writers.get(responder)
                        if writer:
                            writer.write(header + ct)
                            await writer.drain()
        
        await self._orchestrate_pairwise_kem(round_state)
        
        for client_id, client_state in round_state.clients.items():
            if client_state.shared_secret:
                for peer_id, peer_state in round_state.clients.items():
                    if peer_id != client_id and peer_state.shared_secret:
                        seed = self._derive_pairwise_seed(client_state.shared_secret, min(client_id, peer_id), max(client_id, peer_id), round_state.round_id)
                        client_state.pairwise_seeds[peer_id] = seed
        round_state.stage = "MASK_SETUP"'''

    content = content.replace(old_setup, new_setup)

    pairwise_method = '''
    async def _orchestrate_pairwise_kem(self, round_state: RoundState):
        client_ids = list(round_state.clients.keys())
        for i, client_a_id in enumerate(client_ids):
            client_a_state = round_state.clients[client_a_id]
            for client_b_id in client_ids[i+1:]:
                client_b_state = round_state.clients[client_b_id]
                if not client_a_state.public_key or not client_b_state.public_key:
                    continue
                
                if client_a_state.shared_secret and client_b_state.shared_secret:
                    continue
                
                initiator = client_a_id if client_a_id < client_b_id else client_b_id
                responder = client_b_id if client_a_id < client_b_id else client_a_id
                initiator_state = round_state.clients[initiator]
                responder_state = round_state.clients[responder]
                
                if not initiator_state.shared_secret:
                    ct, ss = self._encapsulate(initiator_state.public_key)
                    initiator_state.shared_secret = ss
                    header = self._build_header(
                        MSG_TYPE_KEM_CIPHERTEXT,
                        round_state.round_id,
                        0,
                        0,
                        len(ct),
                    )
                    writer = self.client_writers.get(initiator)
                    if writer:
                        writer.write(header + ct)
                        await writer.drain()
                
                if not responder_state.shared_secret:
                    ct, ss = self._encapsulate(responder_state.public_key)
                    responder_state.shared_secret = ss
                    header = self._build_header(
                        MSG_TYPE_KEM_CIPHERTEXT,
                        round_state.round_id,
                        0,
                        0,
                        len(ct),
                    )
                    writer = self.client_writers.get(responder)
                    if writer:
                        writer.write(header + ct)
                        await writer.drain()
                
                if initiator_state.shared_secret and responder_state.shared_secret:
                    seed = self._derive_pairwise_seed(initiator_state.shared_secret, initiator, responder, round_state.round_id)
                    round_state.clients[initiator].pairwise_seeds[responder] = seed
                    round_state.clients[responder].pairwise_seeds[initiator] = seed

'''

    content = content.replace(
        '    def _compute_fedavg(self, round_state: RoundState, client_unmasked: Dict[int, Dict[int, List[int]]]) -> Dict[int, List[int]]:',
        pairwise_method + '\n    def _compute_fedavg(self, round_state: RoundState, client_unmasked: Dict[int, Dict[int, List[int]]]) -> Dict[int, List[int]]:'
    )

    pairwise_handlers = '''
    async def _handle_pairwise_pubkey(self, header: MessageHeader, payload: bytes, writer: asyncio.StreamWriter):
        round_state = self.rounds.get(header.round_id)
        if not round_state:
            return
        client_state = round_state.clients.get(header.client_id)
        if not client_state:
            return
        client_state.public_key = payload
        self.client_writers[header.client_id] = writer

    async def _handle_pairwise_ciphertext(self, header: MessageHeader, payload: bytes):
        round_state = self.rounds.get(header.round_id)
        if not round_state:
            return
        client_state = round_state.clients.get(header.client_id)
        if not client_state:
            return
        if len(payload) >= 32:
            client_state.shared_secret = payload[:32]

'''

    content = content.replace(
        '    async def _handle_round_init(',
        pairwise_handlers + '\n    async def _handle_round_init('
    )

    content = content.replace(
        'MSG_TYPE_RECOVERY_COMPLETE = 0x33',
        'MSG_TYPE_RECOVERY_COMPLETE = 0x33\nMSG_TYPE_PAIRWISE_KEM_PUBKEY = 0x10\nMSG_TYPE_PAIRWISE_KEM_CIPHERTEXT = 0x11'
    )

    with open(r'C:\DROP\host_server\baseline_server.py', 'w') as f:
        f.write(content)
    print("Fixed baseline_server.py")


def create_run_all_experiments_py():
    import os
    os.makedirs(r'C:\DROP\experiments\scripts', exist_ok=True)
    
    content = '''import subprocess
import sys
import os
import csv

SCRIPTS = [
    "run_variant_comparison.py",
    "run_model_scaling.py",
    "run_chunk_optimization.py",
    "run_dropout_sweep.py"
]

REQUIRED_KEYS = [
    "run_id", "round_id", "mlkem_variant", 
    "peak_sram_bytes", "recovery_latency_ms", "round_latency_ms"
]

def validate_csv(csv_path: str) -> bool:
    try:
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            headers = reader.fieldnames
            if not headers:
                return False
            for key in REQUIRED_KEYS:
                if key not in headers:
                    return False
            return True
    except Exception:
        return False

def run_script(script_name: str) -> bool:
    script_path = os.path.join(r"C:\\DROP\\experiments\\scripts", script_name)
    if not os.path.exists(script_path):
        return False
    try:
        result = subprocess.run(
            [sys.executable, script_path],
            capture_output=True,
            text=True,
            timeout=3600
        )
        if result.returncode != 0:
            return False
        return True
    except Exception:
        return False

def main():
    for script in SCRIPTS:
        sys.stdout.write(f"Running {script}...\n")
        sys.stdout.flush()
        success = run_script(script)
        if not success:
            sys.stdout.write(f"FAILED: {script}\n")
            sys.stdout.flush()
            return 1
        csv_name = f"experiment_{script.split('_')[1][0]}.csv"
        csv_path = os.path.join(r"C:\\DROP\\experiments\\results", csv_name)
        if not validate_csv(csv_path):
            sys.stdout.write(f"VALIDATION FAILED: {csv_path} missing required keys\n")
            sys.stdout.flush()
            return 1
        sys.stdout.write(f"SUCCESS: {script}\n")
        sys.stdout.flush()
    sys.stdout.write("All experiments completed and validated\n")
    sys.stdout.flush()
    return 0

if __name__ == "__main__":
    sys.exit(main())
'''

    with open(r'C:\DROP\experiments\scripts\run_all_experiments.py', 'w') as f:
        f.write(content)
    print("Created run_all_experiments.py")


if __name__ == '__main__':
    fix_baseline_server_py()
    create_run_all_experiments_py()
    print("All baseline and experiment orchestration fixes applied successfully")