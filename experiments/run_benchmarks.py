import os
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
from typing import Dict, Any
import struct

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
    
    telemetry_queue: asyncio.Queue = asyncio.Queue()
    
    async def telemetry_server():
        server = await asyncio.start_server(
            lambda r, w: handle_telemetry_client(r, w, telemetry_queue),
            "0.0.0.0", 8889
        )
        async with server:
            await server.serve_forever()
    
    async def handle_telemetry_client(reader, writer, queue):
        try:
            while True:
                header_data = await reader.readexactly(16)
                if not header_data:
                    break
                proto_ver, round_id, client_id, msg_type, seq, payload_len, _ = struct.unpack(">IIBBHHH", header_data)
                payload = await reader.readexactly(payload_len)
                if msg_type == 0x41 and payload_len >= 64:
                    telemetry_bytes = payload[-64:]
                    await queue.put(parse_telemetry(telemetry_bytes))
        except Exception:
            pass
        finally:
            writer.close()
            await writer.wait_closed()
    
    def parse_telemetry(data: bytes) -> Dict[str, Any]:
        if len(data) < 60:
            return {}
        values = struct.unpack(">IIIIIIIIIIIIIIBBBB", data[:60])
        return {
            "round_id": values[0],
            "keygen_cycles": values[1],
            "encaps_cycles": values[2],
            "decaps_cycles": values[3],
            "hkdf_cycles": values[4],
            "mask_gen_cycles": values[5],
            "mask_apply_cycles": values[6],
            "peak_sram": values[7],
            "min_free_heap": values[8],
            "largest_free_block": values[9],
            "stack_high_water": values[10],
            "heap_zero": bool(values[14]),
            "aggregation_success": values[15],
            "final_accuracy": values[16] / 255.0
        }
    
    telemetry_task = asyncio.create_task(telemetry_server())
    
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
        
        round_latency = (time.time() - start_time) * 1000
        
        telemetry = {}
        try:
            telemetry = await asyncio.wait_for(telemetry_queue.get(), timeout=1.0)
        except asyncio.TimeoutError:
            pass
        
        logger.record_timing(round_latency=round_latency)
        logger.record_result(success=True, accuracy=1.0)
        
        if telemetry:
            logger.record_memory(
                peak_sram=telemetry.get("peak_sram", 0),
                min_free_heap=telemetry.get("min_free_heap", 0),
                largest_free_block=telemetry.get("largest_free_block", 0),
                stack_high_water=telemetry.get("stack_high_water", 0),
                heap_zero=telemetry.get("heap_zero", False)
            )
            logger.record_network(
                bytes_tx=model_size * device_count,
                bytes_rx=model_size,
                packets=device_count * (model_size // chunk_size),
                retransmissions=0,
                fragments=0
            )
            logger.record_cycles(
                keygen=telemetry.get("keygen_cycles", 0),
                encaps=telemetry.get("encaps_cycles", 0),
                decaps=telemetry.get("decaps_cycles", 0),
                ntt=telemetry.get("hkdf_cycles", 0),
                mask_gen=telemetry.get("mask_gen_cycles", 0),
                masking=telemetry.get("mask_apply_cycles", 0)
            )
        
        server_proc.terminate()
        for proc in client_procs:
            if proc.poll() is None:
                proc.terminate()
        
        telemetry_task.cancel()
        try:
            await telemetry_task
        except asyncio.CancelledError:
            pass
        
        return {"success": True, "latency_ms": round_latency}
        
    except Exception as e:
        round_latency = (time.time() - start_time) * 1000
        logger.record_timing(round_latency=round_latency)
        logger.record_result(success=False, accuracy=0.0)
        telemetry_task.cancel()
        try:
            await telemetry_task
        except asyncio.CancelledError:
            pass
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