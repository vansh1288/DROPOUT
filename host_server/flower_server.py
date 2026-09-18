import flwr as flower
from flwr.server.strategy import FedAvg
from flwr.common import Parameters, Scalar, ndarrays_to_parameters, parameters_to_ndarrays
from typing import List, Tuple, Dict, Optional, Union
import numpy as np
import asyncio
import struct
from protocol_bridge import ProtocolBridge, MSG_TYPE_ROUND_INIT, MSG_TYPE_MASK_CHUNK, MSG_TYPE_ROUND_COMPLETE, HEADER_FORMAT, PROTOCOL_VERSION, FIELD_MODULUS

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
        bridge_host: str = "0.0.0.0",
        bridge_port: int = 8888,
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
        self.bridge = ProtocolBridge(bridge_host, bridge_port)
        self.current_round = 0
        self.client_samples: Dict[int, int] = {}
        self.client_chunks: Dict[int, Dict[int, np.ndarray]] = {}
        self.expected_chunks: Dict[int, int] = {}

    def configure_fit(
        self,
        server_round: int,
        parameters: Parameters,
        client_manager: flower.server.client_manager.ClientManager,
    ) -> List[Tuple[flower.server.client_proxy.ClientProxy, flower.common.FitIns]]:
        self.current_round = server_round
        self.client_samples.clear()
        self.client_chunks.clear()
        self.expected_chunks.clear()
        return super().configure_fit(server_round, parameters, client_manager)

    def _model_to_chunks(self, ndarrays: List[np.ndarray]) -> Dict[int, bytes]:
        flat = np.concatenate([arr.flatten() for arr in ndarrays]).astype(np.int16)
        total_elements = len(flat)
        chunk_elements = self.chunk_size
        num_chunks = (total_elements + chunk_elements - 1) // chunk_elements
        chunks = {}
        for i in range(num_chunks):
            start = i * chunk_elements
            end = min(start + chunk_elements, total_elements)
            chunk_data = flat[start:end]
            if len(chunk_data) < chunk_elements:
                chunk_data = np.pad(chunk_data, (0, chunk_elements - len(chunk_data)), mode='constant')
            chunk_bytes = struct.pack(f">{chunk_elements}h", *chunk_data)
            chunks[i] = chunk_bytes
        return chunks

    def _chunks_to_model(self, chunks: Dict[int, bytes], reference_ndarrays: List[np.ndarray]) -> List[np.ndarray]:
        chunk_elements = self.chunk_size
        all_elements = []
        for i in range(len(chunks)):
            if i in chunks:
                values = struct.unpack(f">{chunk_elements}h", chunks[i])
                all_elements.extend(values)
        flat = np.array(all_elements, dtype=np.int16)
        result = []
        offset = 0
        for ref in reference_ndarrays:
            size = ref.size
            arr = flat[offset:offset + size].reshape(ref.shape).astype(ref.dtype)
            result.append(arr)
            offset += size
        return result

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

        for client_proxy, fit_res in results:
            self.client_samples[fit_res.num_examples] = fit_res.num_examples

        first_result = results[0][1]
        reference_ndarrays = parameters_to_ndarrays(first_result.parameters)
        model_chunks = self._model_to_chunks(reference_ndarrays)
        self.expected_chunks = {cid: len(model_chunks) for cid in self.client_samples}

        asyncio.run(self._send_round_init(len(results), len(model_chunks)))

        aggregated_chunks: Dict[int, List[int]] = {}
        for i in range(len(model_chunks)):
            aggregated_chunks[i] = [0] * self.chunk_size

        for client_proxy, fit_res in results:
            ndarrays = parameters_to_ndarrays(fit_res.parameters)
            client_chunks = self._model_to_chunks(ndarrays)
            weight = fit_res.num_examples
            for chunk_idx, chunk_bytes in client_chunks.items():
                values = struct.unpack(f">{self.chunk_size}h", chunk_bytes)
                for j, val in enumerate(values):
                    aggregated_chunks[chunk_idx][j] = (aggregated_chunks[chunk_idx][j] + val * weight) % self.modulus

        total_weight = sum(self.client_samples.values())
        if total_weight > 0:
            inv_total = pow(total_weight, self.modulus - 2, self.modulus)
            for chunk_idx in range(len(model_chunks)):
                for j in range(self.chunk_size):
                    aggregated_chunks[chunk_idx][j] = (aggregated_chunks[chunk_idx][j] * inv_total) % self.modulus

        aggregated_ndarrays = self._chunks_to_model(
            {k: struct.pack(f">{self.chunk_size}h", *v) for k, v in aggregated_chunks.items()},
            reference_ndarrays
        )

        aggregated_parameters = ndarrays_to_parameters(aggregated_ndarrays)
        metrics_aggregated = {"num_clients": len(results)}
        return aggregated_parameters, metrics_aggregated

    async def _send_round_init(self, num_clients: int, num_chunks: int):
        payload = bytes([num_clients, 2]) + struct.pack(">H", self.chunk_size) + struct.pack(">I", num_chunks * self.chunk_size * 2)
        header = struct.pack(HEADER_FORMAT, PROTOCOL_VERSION, self.current_round, 0, MSG_TYPE_ROUND_INIT, 0, len(payload), 0)
        for writer in self.bridge.client_writers.values():
            writer.write(header + payload)
            await writer.drain()

    def process_chunked_update(
        self, round_id: int, client_id: int, chunk_index: int, chunk_data: np.ndarray
    ) -> bool:
        if round_id not in self.client_chunks:
            self.client_chunks[round_id] = {}
        if client_id not in self.client_chunks[round_id]:
            self.client_chunks[round_id][client_id] = {}
        self.client_chunks[round_id][client_id][chunk_index] = chunk_data
        expected = self.expected_chunks.get(client_id, 0)
        return len(self.client_chunks[round_id][client_id]) == expected

    def get_aggregated_model(self, round_id: int) -> Optional[Parameters]:
        if round_id not in self.client_chunks:
            return None
        return None

def main():
    strategy = ChunkedFedAvg(min_fit_clients=2, min_available_clients=2)
    flower.server.start_server(
        server_address="0.0.0.0:8080",
        config=flower.server.ServerConfig(num_rounds=10),
        strategy=strategy,
    )

if __name__ == "__main__":
    main()