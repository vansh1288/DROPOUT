import csv
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
