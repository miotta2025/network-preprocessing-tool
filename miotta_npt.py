import os
import sys
import yaml
import argparse
import subprocess
import shutil
from datetime import datetime

def load_config(yaml_path):
    with open(yaml_path, 'r') as f:
        return yaml.safe_load(f)

def run_classic(config, pcap):
    output_dir = config["output_dir"]
    size = config["classic"]["size_of_window"]
    mode = config["classic"]["mode"]

    cmd = [
        sys.executable,  # Use the current Python interpreter
        "preprocessing_tool.py",
        pcap,
        "--size_of_window", str(size),
        "--mode", mode
    ]

    print(f"Running Classic Preprocessing: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

    # Mover resultados al directorio de salida
    for f in os.listdir("."):
        if f.endswith(".csv") and os.path.isfile(f):
            shutil.move(f, os.path.join(output_dir, f))

def run_nprint(config, pcap):
    output_dir = config["output_dir"]
    headers = config["nprint"]["headers"]
    masks = config["nprint"]["masks"]

    cmd = [
        sys.executable,  # Use the current Python interpreter
        "preprocessing_tool_nprint.py",
        pcap,
        "--headers"
    ] + headers + ["--masks"] + masks

    print(f"Running nPrint Preprocessing: {' '.join(cmd)}")
    subprocess.run(cmd, check=True)

    # Mover resultado a carpeta de salida
    csv_file = f"{pcap}.csv"
    if os.path.exists(csv_file):
        shutil.move(csv_file, os.path.join(output_dir, os.path.basename(csv_file)))

def main():
    parser = argparse.ArgumentParser(description="Unified preprocessor for IoMT traffic")
    parser.add_argument("pcap_files", type=str, nargs='+', help="Paths to the input PCAP files")
    parser.add_argument('--config', required=True, help="Path to YAML configuration file")
    args = parser.parse_args()

    config = load_config(args.config)
    mode = config["mode"]

    os.makedirs(config["output_dir"], exist_ok=True)

    for pcap_file in args.pcap_files:
        print(f"Processing file: {pcap_file}")
        if mode == "classic":
            run_classic(config, pcap_file)
        elif mode == "nprint":
            run_nprint(config, pcap_file)
        else:
            raise ValueError(f"Unsupported mode: {mode}")

if __name__ == "__main__":
    main()
