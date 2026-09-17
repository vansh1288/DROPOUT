import flwr as flower
from flwr.server.strategy import FedAvg
from flwr.common import Parameters, Scalar, ndarrays_to_parameters, parameters_to_ndarrays
from typing import List, Tuple, Dict, Optional, Union
import numpy as np
from dataclasses import dataclass

@dataclass
class ChunkedModelUpdate:
    round_id: int
    client_id: int
    chunks: Dict[int, np.ndarray]
    total_chunks: int
    completed: bool = False

class ChunkedFedAvg(FedAvg):
    def __init__(
        self,
        fraction_fit: float = 1.0,
        fraction_evaluate: float = 1.0,
        min_fit_clients: int = 2,
        min_evaluate_clients: int = 2,
        min_available_clients: int = 2,
        chunk_size: int = 128,
        modulus: int = 3329,
    ):
        super().__init__(
            fraction_fit=fraction_fit,
            fraction_evaluate=fraction_evaluate,
            min_fit_clients=min_fit_clients,
            min_evaluate_clients=min_evaluate_clients,
            min_available_clients=min_available_clients,
        )
        self.chunk_size = chunk_size
        self.modulus = modulus
        self.pending_updates: Dict[int, ChunkedModelUpdate] = {}
        self.current_round = 0

    def configure_fit(
        self,
        server_round: int,
        parameters: Parameters,
        client_manager: flower.server.client_manager.ClientManager,
    ) -> List[Tuple[flower.server.client_proxy.ClientProxy, flower.common.FitIns]]:
        self.current_round = server_round
        self.pending_updates.clear()
        return super().configure_fit(server_round, parameters, client_manager)

    def aggregate_fit(
        self,
        server_round: int,
        results: List[
            Tuple[flower.server.client_proxy.ClientProxy, flower.common.FitRes]
        ],
        failures: List[Union[Tuple[flower.server.client_proxy.ClientProxy, flower.common.FitRes], BaseException]],
    ) -> Tuple[Optional[Parameters], Dict[str, Scalar]]:
        if not results:
            return None, {}
        
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
                aggregated = (aggregated // total_weight) % self.modulus
            aggregated_ndarrays.append(aggregated.astype(ref_array.dtype))
        
        aggregated_parameters = ndarrays_to_parameters(aggregated_ndarrays)
        metrics_aggregated = {"num_clients": len(results)}
        return aggregated_parameters, metrics_aggregated

    def process_chunked_update(
        self, round_id: int, client_id: int, chunk_index: int, chunk_data: np.ndarray
    ) -> bool:
        if round_id not in self.pending_updates:
            self.pending_updates[round_id] = ChunkedModelUpdate(
                round_id=round_id,
                client_id=client_id,
                chunks={},
                total_chunks=0,
            )
        update = self.pending_updates[round_id]
        update.chunks[chunk_index] = chunk_data
        return len(update.chunks) == update.total_chunks

    def get_aggregated_model(self, round_id: int) -> Optional[Parameters]:
        if round_id not in self.pending_updates:
            return None
        update = self.pending_updates[round_id]
        if not update.completed:
            return None
        return None