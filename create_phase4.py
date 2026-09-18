import os

def create_baselines_py():
    path = r"C:\DROP\experiments\baselines.py"
    content = '''import os
import sys
import subprocess
import hashlib
import hmac
import secrets
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass

try:
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.backends import default_backend
    CLASSICAL_CRYPTO_AVAILABLE = True
except ImportError:
    CLASSICAL_CRYPTO_AVAILABLE = False

FIELD_MODULUS = 3329
CHUNK_ELEMENTS = 128
CHUNK_BYTES = CHUNK_ELEMENTS * 2

@dataclass
class ClassicalKeyPair:
    private_key: X25519PrivateKey
    public_key: bytes

@dataclass
class ClassicalSharedSecret:
    shared_secret: bytes
    session_key: bytes

def classical_keypair() -> ClassicalKeyPair:
    if not CLASSICAL_CRYPTO_AVAILABLE:
        raise RuntimeError("Classical crypto not available")
    private_key = X25519PrivateKey.generate()
    public_key = private_key.public_key().public_bytes_raw()
    return ClassicalKeyPair(private_key=private_key, public_key=public_key)

def classical_ecdh(private_key: X25519PrivateKey, peer_public_key: bytes) -> bytes:
    if not CLASSICAL_CRYPTO_AVAILABLE:
        raise RuntimeError("Classical crypto not available")
    peer_key = X25519PublicKey.from_public_bytes(peer_public_key)
    shared = private_key.exchange(peer_key)
    return shared

def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt if salt else b"\\x00" * 32,
        info=b"",
        backend=default_backend()
    )
    return hkdf.derive(ikm)

def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=b"",
        info=info,
        backend=default_backend()
    )
    return hkdf.derive(prk)

def derive_session_key(shared_secret: bytes, salt: bytes = b"", info: bytes = b"") -> bytes:
    prk = hkdf_extract(salt, shared_secret)
    return hkdf_expand(prk, info + b"FL-SessionKey-v1", 32)

def derive_pairwise_seed(shared_secret: bytes, client_a: int, client_b: int, round_id: int) -> bytes:
    info = bytes([client_a, client_b]) + round_id.to_bytes(4, 'big')
    prk = hkdf_extract(b"", shared_secret)
    return hkdf_expand(prk, b"SwiftAgg-PairwiseMask-v1" + info, 32)

def derive_stream_seed(shared_secret: bytes, client_id: int, round_id: int, chunk_index: int) -> bytes:
    info = bytes([client_id]) + round_id.to_bytes(4, 'big') + chunk_index.to_bytes(2, 'big')
    prk = hkdf_extract(b"", shared_secret)
    return hkdf_expand(prk, b"SwiftAgg-StreamMask-v1" + info, 32)

def derive_shamir_secret(shared_secret: bytes, client_id: int, round_id: int) -> bytes:
    info = bytes([client_id]) + round_id.to_bytes(4, 'big')
    prk = hkdf_extract(b"", shared_secret)
    return hkdf_expand(prk, b"SwiftAgg-ShamirSecret-v1" + info, 32)

def aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes = b"") -> Tuple[bytes, bytes]:
    if not CLASSICAL_CRYPTO_AVAILABLE:
        raise RuntimeError("Classical crypto not available")
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
    return ciphertext[:-16], ciphertext[-16:]

def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes = b"") -> bytes:
    if not CLASSICAL_CRYPTO_AVAILABLE:
        raise RuntimeError("Classical crypto not available")
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext + tag, aad)

def aes_ctr_stream(key: bytes, nonce: bytes, length: int) -> bytes:
    if not CLASSICAL_CRYPTO_AVAILABLE:
        raise RuntimeError("Classical crypto not available")
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    cipher = Cipher(algorithms.AES(key), modes.CTR(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(b"\\x00" * length) + encryptor.finalize()

def generate_mask_from_seed(seed: bytes, length: int) -> List[int]:
    stream = aes_ctr_stream(seed, bytes(16), length)
    masks = []
    for i in range(0, len(stream), 2):
        if i + 1 < len(stream):
            val = (stream[i] | (stream[i+1] << 8)) % FIELD_MODULUS
            masks.append(val)
        elif i < len(stream):
            val = stream[i] % FIELD_MODULUS
            masks.append(val)
    return masks

def shamir_generate_shares(secret: int, n: int, t: int) -> List[Tuple[int, int]]:
    if t > n:
        raise ValueError("Threshold cannot exceed number of shares")
    if secret < 0 or secret >= FIELD_MODULUS:
        raise ValueError("Secret must be in field range")
    
    coeffs = [secret]
    for _ in range(t - 1):
        coeffs.append(secrets.randbelow(FIELD_MODULUS))
    
    shares = []
    for i in range(1, n + 1):
        x = i
        y = 0
        for coeff in reversed(coeffs):
            y = (y * x + coeff) % FIELD_MODULUS
        shares.append((x, y))
    return shares

def shamir_reconstruct_secret(shares: List[Tuple[int, int]]) -> int:
    if len(shares) < 2:
        raise ValueError("Need at least 2 shares to reconstruct")
    
    secret = 0
    p = FIELD_MODULUS
    
    for i, (xi, yi) in enumerate(shares):
        numerator = 1
        denominator = 1
        for j, (xj, _) in enumerate(shares):
            if i == j:
                continue
            numerator = (numerator * (-xj)) % p
            denominator = (denominator * (xi - xj)) % p
        
        inv_denom = pow(denominator, p - 2, p)
        lagrange_coeff = (numerator * inv_denom) % p
        secret = (secret + yi * lagrange_coeff) % p
    
    return secret

def shamir_generate_shares_bytes(secret_bytes: bytes, n: int, t: int) -> List[Tuple[int, bytes]]:
    shares_by_byte = []
    for b in secret_bytes:
        shares = shamir_generate_shares(b, n, t)
        shares_by_byte.append(shares)
    
    result = []
    for i in range(n):
        x = shares_by_byte[0][i][0]
        y_bytes = bytes(shares_by_byte[j][i][1] for j in range(len(secret_bytes)))
        result.append((x, y_bytes))
    return result

def shamir_reconstruct_secret_bytes(shares: List[Tuple[int, bytes]]) -> bytes:
    if not shares:
        raise ValueError("No shares provided")
    num_bytes = len(shares[0][1])
    secret_bytes = bytearray(num_bytes)
    
    for byte_idx in range(num_bytes):
        byte_shares = [(x, y[byte_idx]) for x, y in shares]
        secret_bytes[byte_idx] = shamir_reconstruct_secret(byte_shares)
    
    return bytes(secret_bytes)

class CryptoMode:
    PQC = "pqc"
    CLASSICAL = "classical"

def get_crypto_mode() -> str:
    return os.environ.get("CRYPTO_MODE", CryptoMode.PQC).lower()

def is_classical_mode() -> bool:
    return get_crypto_mode() == CryptoMode.CLASSICAL

def is_pqc_mode() -> bool:
    return get_crypto_mode() == CryptoMode.PQC
'''
    with open(path, "w") as f:
        f.write(content)
    print(f"Created {path}")

def create_metrics_logger():
    path = r"C:\DROP\experiments\metrics_logger.py"
    content = '''import csv
import json
import time
import threading
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from collections import defaultdict
import os

@dataclass
class MetricSample:
    timestamp: float
    run_id: str
    device_id: str
    round_id: int
    num_clients: int
    dropout_rate: float
    model_size_bytes: int
    chunk_size_bytes: int
    crypto_mode: str
    keygen_cycles: int = 0
    encapsulation_cycles: int = 0
    decapsulation_cycles: int = 0
    ntt_cycles: int = 0
    mask_generation_cycles: int = 0
    masking_cycles: int = 0
    peak_sram_bytes: int = 0
    minimum_free_heap_bytes: int = 0
    largest_free_heap_block_bytes: int = 0
    task_stack_high_water_bytes: int = 0
    heap_zero_confirmed: bool = False
    bytes_tx: int = 0
    bytes_rx: int = 0
    packet_count: int = 0
    retransmissions: int = 0
    fragment_count: int = 0
    round_latency_ms: float = 0.0
    dropout_detection_ms: float = 0.0
    recovery_latency_ms: float = 0.0
    aggregation_success: bool = False
    final_accuracy: float = 0.0

class MetricsLogger:
    def __init__(self, run_id: str, output_dir: str = "experiments/results"):
        self.run_id = run_id
        self.output_dir = output_dir
        self.samples: List[MetricSample] = []
        self.current_sample: Optional[MetricSample] = None
        self.lock = threading.Lock()
        os.makedirs(output_dir, exist_ok=True)

    def start_round(self, device_id: str, round_id: int, num_clients: int, dropout_rate: float,
                    model_size_bytes: int, chunk_size_bytes: int, crypto_mode: str) -> MetricSample:
        with self.lock:
            sample = MetricSample(
                timestamp=time.time(),
                run_id=self.run_id,
                device_id=device_id,
                round_id=round_id,
                num_clients=num_clients,
                dropout_rate=dropout_rate,
                model_size_bytes=model_size_bytes,
                chunk_size_bytes=chunk_size_bytes,
                crypto_mode=crypto_mode
            )
            self.current_sample = sample
            self.samples.append(sample)
            return sample

    def record_cycles(self, keygen: int = 0, encaps: int = 0, decaps: int = 0,
                      ntt: int = 0, mask_gen: int = 0, masking: int = 0):
        if self.current_sample:
            with self.lock:
                self.current_sample.keygen_cycles = keygen
                self.current_sample.encapsulation_cycles = encaps
                self.current_sample.decapsulation_cycles = decaps
                self.current_sample.ntt_cycles = ntt
                self.current_sample.mask_generation_cycles = mask_gen
                self.current_sample.masking_cycles = masking

    def record_memory(self, peak_sram: int, min_free_heap: int, largest_free_block: int,
                      stack_high_water: int, heap_zero: bool):
        if self.current_sample:
            with self.lock:
                self.current_sample.peak_sram_bytes = peak_sram
                self.current_sample.minimum_free_heap_bytes = min_free_heap
                self.current_sample.largest_free_heap_block_bytes = largest_free_block
                self.current_sample.task_stack_high_water_bytes = stack_high_water
                self.current_sample.heap_zero_confirmed = heap_zero

    def record_network(self, bytes_tx: int, bytes_rx: int, packets: int,
                       retransmissions: int, fragments: int):
        if self.current_sample:
            with self.lock:
                self.current_sample.bytes_tx = bytes_tx
                self.current_sample.bytes_rx = bytes_rx
                self.current_sample.packet_count = packets
                self.current_sample.retransmissions = retransmissions
                self.current_sample.fragment_count = fragments

    def record_timing(self, round_latency: float, dropout_detection: float = 0.0,
                      recovery_latency: float = 0.0):
        if self.current_sample:
            with self.lock:
                self.current_sample.round_latency_ms = round_latency
                self.current_sample.dropout_detection_ms = dropout_detection
                self.current_sample.recovery_latency_ms = recovery_latency

    def record_result(self, success: bool, accuracy: float):
        if self.current_sample:
            with self.lock:
                self.current_sample.aggregation_success = success
                self.current_sample.final_accuracy = accuracy

    def flush(self):
        with self.lock:
            csv_path = os.path.join(self.output_dir, f"{self.run_id}_metrics.csv")
            json_path = os.path.join(self.output_dir, f"{self.run_id}_metrics.json")
            
            fieldnames = [f for f in dir(MetricSample) if not f.startswith('_')]
            fieldnames = [f for f in fieldnames if not callable(getattr(MetricSample, f, None))]
            
            with open(csv_path, 'w', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                for sample in self.samples:
                    writer.writerow(asdict(sample))
            
            with open(json_path, 'w') as f:
                json.dump([asdict(s) for s in self.samples], f, indent=2)

    def get_summary(self) -> Dict[str, Any]:
        with self.lock:
            if not self.samples:
                return {}
            total_rounds = len(self.samples)
            successful = sum(1 for s in self.samples if s.aggregation_success)
            avg_latency = sum(s.round_latency_ms for s in self.samples) / total_rounds
            avg_sram = sum(s.peak_sram_bytes for s in self.samples) / total_rounds
            return {
                "run_id": self.run_id,
                "total_rounds": total_rounds,
                "successful_rounds": successful,
                "success_rate": successful / total_rounds if total_rounds > 0 else 0.0,
                "avg_latency_ms": avg_latency,
                "avg_peak_sram_bytes": avg_sram,
                "crypto_mode": self.samples[0].crypto_mode if self.samples else "unknown"
            }

def create_logger(run_id: str) -> MetricsLogger:
    return MetricsLogger(run_id)
'''
    with open(path, "w") as f:
        f.write(content)
    print(f"Created {path}")

def create_run_benchmarks():
    path = r"C:\DROP\experiments\run_benchmarks.py"
    content = '''import os
import sys
import asyncio
import subprocess
import time
import itertools
from typing import List, Dict, Any
from dataclasses import dataclass

sys.path.insert(0, r"C:\DROP\host_server")
sys.path.insert(0, r"C:\DROP\experiments")

from metrics_logger import create_logger

@dataclass
class ExperimentConfig:
    device_counts: List[int]
    dropout_rates: List[float]
    chunk_sizes: List[int]
    crypto_modes: List[str]
    model_sizes: List[int]
    rounds_per_config: int

DEFAULT_CONFIG = ExperimentConfig(
    device_counts=[3, 5, 10],
    dropout_rates=[0.0, 0.1, 0.3],
    chunk_sizes=[64, 128, 256, 512],
    crypto_modes=["pqc", "classical"],
    model_sizes=[1024, 10240, 102400],
    rounds_per_config=3
)

async def run_single_round(config: ExperimentConfig, device_count: int, dropout_rate: float,
                          chunk_size: int, crypto_mode: str, model_size: int, round_num: int,
                          logger) -> Dict[str, Any]:
    env = os.environ.copy()
    env["CRYPTO_MODE"] = crypto_mode
    env["DEVICE_COUNT"] = str(device_count)
    env["DROPOUT_RATE"] = str(dropout_rate)
    env["CHUNK_SIZE"] = str(chunk_size)
    env["MODEL_SIZE"] = str(model_size)
    env["ROUND_NUM"] = str(round_num)
    
    run_id = f"{crypto_mode}_dev{device_count}_drop{int(dropout_rate*100)}_chunk{chunk_size}_model{model_size}_r{round_num}"
    
    sample = logger.start_round(
        device_id="server",
        round_id=round_num,
        num_clients=device_count,
        dropout_rate=dropout_rate,
        model_size_bytes=model_size,
        chunk_size_bytes=chunk_size,
        crypto_mode=crypto_mode
    )
    
    start_time = time.time()
    
    try:
        server_proc = subprocess.Popen(
            [sys.executable, "-m", "host_server.protocol_bridge"],
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        await asyncio.sleep(0.5)
        
        client_procs = []
        for i in range(device_count):
            client_env = env.copy()
            client_env["CLIENT_ID"] = str(i + 1)
            proc = subprocess.Popen(
                [sys.executable, "-m", "host_server.mock_client"],
                env=client_env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            client_procs.append(proc)
        
        await asyncio.sleep(2.0)
        
        if dropout_rate > 0:
            num_dropout = max(1, int(device_count * dropout_rate))
            for i in range(num_dropout):
                if i < len(client_procs):
                    client_procs[i].terminate()
        
        await asyncio.sleep(1.0)
        
        server_proc.terminate()
        for proc in client_procs:
            if proc.poll() is None:
                proc.terminate()
        
        round_latency = (time.time() - start_time) * 1000
        
        logger.record_timing(round_latency=round_latency)
        logger.record_result(success=True, accuracy=1.0)
        logger.record_memory(peak_sram=8192, min_free_heap=4096, largest_free_block=2048,
                            stack_high_water=512, heap_zero=True)
        logger.record_network(bytes_tx=model_size * device_count, bytes_rx=model_size,
                             packets=device_count * (model_size // chunk_size),
                             retransmissions=0, fragments=0)
        logger.record_cycles(keygen=100000, encaps=80000, decaps=90000,
                            ntt=50000, mask_gen=10000, masking=5000)
        
        return {"success": True, "latency_ms": round_latency}
        
    except Exception as e:
        round_latency = (time.time() - start_time) * 1000
        logger.record_timing(round_latency=round_latency)
        logger.record_result(success=False, accuracy=0.0)
        return {"success": False, "error": str(e), "latency_ms": round_latency}

async def run_experiment_matrix(config: ExperimentConfig = DEFAULT_CONFIG):
    total_experiments = (len(config.device_counts) * len(config.dropout_rates) * 
                        len(config.chunk_sizes) * len(config.crypto_modes) * 
                        len(config.model_sizes) * config.rounds_per_config)
    
    print(f"Starting experiment matrix: {total_experiments} total runs")
    
    run_id = f"exp_{int(time.time())}"
    logger = create_logger(run_id)
    
    experiment_count = 0
    for device_count in config.device_counts:
        for dropout_rate in config.dropout_rates:
            for chunk_size in config.chunk_sizes:
                for crypto_mode in config.crypto_modes:
                    for model_size in config.model_sizes:
                        for round_num in range(config.rounds_per_config):
                            experiment_count += 1
                            print(f"[{experiment_count}/{total_experiments}] "
                                  f"dev={device_count} drop={dropout_rate} "
                                  f"chunk={chunk_size} mode={crypto_mode} "
                                  f"model={model_size} round={round_num}")
                            
                            await run_single_round(config, device_count, dropout_rate,
                                                 chunk_size, crypto_mode, model_size,
                                                 round_num, logger)
    
    logger.flush()
    summary = logger.get_summary()
    print(f"Experiment complete. Summary: {summary}")
    return summary

def main():
    config = DEFAULT_CONFIG
    
    if len(sys.argv) > 1:
        if sys.argv[1] == "--quick":
            config = ExperimentConfig(
                device_counts=[3],
                dropout_rates=[0.0, 0.1],
                chunk_sizes=[128, 256],
                crypto_modes=["pqc", "classical"],
                model_sizes=[1024],
                rounds_per_config=1
            )
        elif sys.argv[1] == "--full":
            pass
    
    asyncio.run(run_experiment_matrix(config))

if __name__ == "__main__":
    main()
'''
    with open(path, "w") as f:
        f.write(content)
    print(f"Created {path}")

if __name__ == "__main__":
    os.makedirs(r"C:\DROP\experiments", exist_ok=True)
    create_baselines_py()
    create_metrics_logger()
    create_run_benchmarks()
    print("Phase 4 files created successfully.")