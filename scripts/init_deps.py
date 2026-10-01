import subprocess
import sys

def run_cmd(cmd, cwd=None):
    result = subprocess.run(cmd, shell=True, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Error: {result.stderr}")
        return False
    print(result.stdout)
    return True

if __name__ == "__main__":
    repo_root = r"C:\DROP"
    if not run_cmd("git submodule add https://github.com/mupq/pqm4 deps/pqm4", cwd=repo_root):
        sys.exit(1)
    if not run_cmd("git submodule update --init --recursive", cwd=repo_root):
        sys.exit(1)
    print("Dependencies initialized successfully")
