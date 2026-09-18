import flwr as flower
from flwr.server.strategy import FedAvg
from flwr.common import Parameters, Scalar, ndarrays_to_parameters, parameters_to_ndarrays
from typing import List, Tuple, Dict, Optional, Union
import numpy as np

FIELD_MODULUS = 3329

def mod_inv(a: int, p: int = FIELD_MODULUS) -> int:
    return pow(a, p - 2, p)
import csv
import time
import os

class ClassicalFedAvg(FedAvg):
    def __init__(
        self,
        fraction_fit: float = 1.0,
        fraction_evaluate: float = 1.0,
        min_fit_clients: int = 2,
        min_evaluate_clients: int = 2,
        min_available_clients: int = 2,
    ):
        super().__init__(
            fraction_fit=fraction_fit,
            fraction_evaluate=fraction_evaluate,
            min_fit_clients=min_fit_clients,
            min_evaluate_clients=min_evaluate_clients,
            min_available_clients=min_available_clients,
        )
        self.metrics_file = "experiments/results/metrics.csv"
        self._init_metrics_file()

    def _init_metrics_file(self):
        os.makedirs(os.path.dirname(self.metrics_file), exist_ok=True)
        with open(self.metrics_file, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "run_id", "timestamp", "device_id", "round_id", "num_clients", "dropout_rate",
                "model_size_bytes", "chunk_size_bytes", "mlkem_variant",
                "keygen_cycles", "encapsulation_cycles", "decapsulation_cycles",
                "ntt_cycles", "mask_generation_cycles", "masking_cycles",
                "peak_sram_bytes", "minimum_free_heap_bytes", "largest_free_heap_block_bytes",
                "task_stack_high_water_bytes", "bytes_tx", "bytes_rx", "packet_count",
                "retransmissions", "fragment_count", "round_latency_ms",
                "dropout_detection_ms", "recovery_latency_ms",
                "aggregation_success", "final_accuracy"
            ])

    def log_metrics(self, round_id: int, num_clients: int, latency_ms: float, accuracy: float):
        with open(self.metrics_file, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                f"classical_{round_id}", time.time(), "server", round_id, num_clients, 0.0,
                0, 0, "CLASSICAL_BASELINE",
                0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0,
                latency_ms, 0.0, 0.0, 1, accuracy
            ])

    def aggregate_fit(
        self,
        server_round: int,
        results: List[Tuple],
        failures: List[Union[Tuple, BaseException]],
    ) -> Tuple[Optional[Parameters], Dict[str, Scalar]]:
        if not results:
            return None, {}
        
        start = time.perf_counter()
        aggregated_ndarrays: List[np.ndarray] = []
        first_result = results[0][1]
        reference_ndarrays = parameters_to_ndarrays(first_result.parameters)
        
        for i, ref_array in enumerate(reference_ndarrays):
            aggregated = np.zeros_like(ref_array, dtype=np.int64)
            total_weight = 0
            
            for client_proxy, fit_res in results:
                ndarrays = parameters_to_ndarrays(fit_res.parameters)
                if i < len(ndarrays):
                    weight = fit_res.num_examples
                    aggregated += ndarrays[i].astype(np.int64) * weight
                    total_weight += weight
            
            if total_weight > 0:
                inv_weight = mod_inv(total_weight % FIELD_MODULUS)
                aggregated = (aggregated * inv_weight) % FIELD_MODULUS
            aggregated_ndarrays.append(aggregated.astype(ref_array.dtype))
        
        latency_ms = (time.perf_counter() - start) * 1000
        aggregated_parameters = ndarrays_to_parameters(aggregated_ndarrays)
        metrics_aggregated = {"num_clients": len(results)}
        return aggregated_parameters, metrics_aggregated

def main():
    strategy = ClassicalFedAvg(min_fit_clients=5, min_available_clients=5)
    flower.server.start_server(
        server_address="0.0.0.0:8080",
        config=flower.server.ServerConfig(num_rounds=10),
        strategy=strategy,
    )

if __name__ == "__main__":
    main()