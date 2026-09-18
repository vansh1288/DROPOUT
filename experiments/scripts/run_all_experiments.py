import subprocess
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
    script_path = os.path.join(r"C:\DROP\experiments\scripts", script_name)
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
        sys.stdout.write(f"Running {script}...
")
        sys.stdout.flush()
        success = run_script(script)
        if not success:
            sys.stdout.write(f"FAILED: {script}
")
            sys.stdout.flush()
            return 1
        csv_name = f"experiment_{script.split('_')[1][0]}.csv"
        csv_path = os.path.join(r"C:\DROP\experiments\results", csv_name)
        if not validate_csv(csv_path):
            sys.stdout.write(f"VALIDATION FAILED: {csv_path} missing required keys
")
            sys.stdout.flush()
            return 1
        sys.stdout.write(f"SUCCESS: {script}
")
        sys.stdout.flush()
    sys.stdout.write("All experiments completed and validated
")
    sys.stdout.flush()
    return 0

if __name__ == "__main__":
    sys.exit(main())
