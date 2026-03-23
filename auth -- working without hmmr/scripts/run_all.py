#!/usr/bin/env python3
import subprocess
import sys


STEPS = [
    ("Generate off-chain voter devices (iot_devices.json)", ["go", "run", "./cmd/generate-devices"]),
    ("Generate registered devices (sc_devices.json)", ["go", "run", "./cmd/reg"]),
    ("Authenticate devices and write blocks", ["go", "run", "./cmd/auth"]),
    ("Show device summary", ["go", "run", "./cmd/detail-dev"]),
]


def run_step(description, command):
    print("\n=== " + description + " ===")
    print("Running: " + " ".join(command))
    subprocess.run(command, check=True)


def main():
    print("AuthHMMR runner: executes each step in order.")
    for description, command in STEPS:
        try:
            run_step(description, command)
        except subprocess.CalledProcessError as exc:
            print(f"Step failed with exit code {exc.returncode}: {description}")
            sys.exit(exc.returncode)
    print("\nAll steps completed.")


if __name__ == "__main__":
    main()
