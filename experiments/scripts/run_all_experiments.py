import subprocess
import sys
import os
import csv
import time
import json
from pathlib import Path

EXPERIMENTS_DIR = Path(__file__).parent.parent
RESULTS_DIR = EXPERIMENTS_DIR / "results"
PLOTS_DIR = RESULTS_DIR / "plots"
METRICS_CSV = RESULTS_DIR / "metrics.csv"

MODEL_SIZES = [10240, 51200, 102400, 256000, 512000, 1048576]
DROPOUT_RATES = [0.0, 0.1, 0.2, 0.3, 0.4, 0.5]
CHUNK_SIZES = [64, 128, 256, 512, 1024]

def init_csv():
    RESULTS_DIR.mkdir(exist_ok=True)
    PLOTS_DIR.mkdir(exist_ok=True)
    with open(METRICS_CSV, "w", newline="") as f:
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

def run_cmd(cmd, cwd=None, timeout=300):
    result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True, timeout=timeout)
    return result.returncode == 0, result.stdout, result.stderr

def log_failure(phase, model_size, error):
    with open(METRICS_CSV, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            f"{phase}_fail_{model_size}", time.time(), "host", 0, 0, 0.0,
            model_size, 0, "FAILURE", 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0.0
        ])

def sequence1_classical_baseline():
    print("Sequence 1: Classical Baseline")
    ok, out, err = run_cmd(f"cd {EXPERIMENTS_DIR.parent} && python -m host_server.baseline_server", timeout=600)
    if not ok:
        log_failure("CLASSICAL_BASELINE", 0, err)

def sequence2_baseline_buffered():
    print("Sequence 2: Baseline Buffered (PQC no streaming)")
    for size in MODEL_SIZES:
        print(f"  Testing model size: {size} bytes")
        build_cmd = f"cd {EXPERIMENTS_DIR.parent} && pio run -e cortex_m4 -D MODEL_SIZE={size} 2>&1"
        ok, out, err = run_cmd(build_cmd, timeout=300)
        if not ok:
            if "RAM overflow" in err or "HEAP USAGE" in err or "memory" in err.lower():
                with open(METRICS_CSV, "a", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        f"BASELINE_BUFFERED_LINKER_FAIL_{size}", time.time(), "mcu", 0, 0, 0.0,
                        size, 0, "BASELINE_BUFFERED", 0, 0, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                        0, 0.0
                    ])
            else:
                log_failure("BASELINE_BUFFERED", size, err)
        else:
            with open(METRICS_CSV, "a", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    f"BASELINE_BUFFERED_SUCCESS_{size}", time.time(), "mcu", 0, 0, 0.0,
                    size, 0, "BASELINE_BUFFERED", 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                    1, 0.0
                ])

def sequence3_proposed_streaming():
    print("Sequence 3: Proposed PQC Streaming")
    ok, out, err = run_cmd(f"cd {EXPERIMENTS_DIR.parent} && python -m experiments.scripts.run_workflow", timeout=1200)
    if not ok:
        log_failure("PROPOSED_STREAMING", 0, err)

def sequence4_generate_plots():
    print("Sequence 4: Generate Plots")
    ok, out, err = run_cmd(f"cd {EXPERIMENTS_DIR.parent} && python -m experiments.analysis.plot_metrics", timeout=60)
    if not ok:
        print(f"Plot generation failed: {err}")

def main():
    init_csv()
    sequence1_classical_baseline()
    sequence2_baseline_buffered()
    sequence3_proposed_streaming()
    sequence4_generate_plots()
    print("All experiment sequences completed")

if __name__ == "__main__":
    main()