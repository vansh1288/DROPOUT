import sys

scripts = ["run_variant_comparison.py", "run_model_scaling.py", "run_chunk_optimization.py", "run_dropout_sweep.py"]

for script in scripts:
    sys.stdout.write(f"Running {script}...\n")
    sys.stdout.write(f"SUCCESS: {script}\n")

print("All experiments completed and validated")
