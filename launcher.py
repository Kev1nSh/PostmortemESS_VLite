#!/usr/bin/env python3

import os
import shutil
import subprocess
import sys
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parent
ENV_FILE = ROOT / ".env"

NETWORK = "postmortemess-net"
DATA_VOLUME = "postmortemess-data"

API_CONTAINER = "postmortem-api"
FRONTEND_CONTAINER = "postmortem-frontend"

API_IMAGE = "postmortemess-vlite-api:local"
FRONTEND_IMAGE = "postmortemess-vlite-frontend:local"

API_PORT = 8000
FRONTEND_PORT = 8080

# Runtime

def find_runtime():
    for runtime in ("podman", "docker"):
        if shutil.which(runtime):
            return runtime

    print("[ERROR] Neither Podman nor Docker was found.")
    print()
    print("Install one of:")
    print("  Podman: https://podman.io/")
    print("  Docker: https://www.docker.com/")
    sys.exit(1)


def run(runtime, args, check=True):
    command = [runtime, *args]

    print("$", " ".join(command))

    return subprocess.run(
        command,
        cwd=ROOT,
        check=check
    )

# Environment

def create_env():
    if ENV_FILE.exists():
        print("[OK] .env already exists")
        return

    hash_key = os.urandom(32).hex()

    ENV_FILE.write_text(
        f"""# PostmortemESS VLite local configuration

VIRUSTOTAL_API_KEY=
GOOGLE_SAFE_BROWSING_KEY=
ABUSEIPDB_API_KEY=
ABUSE_CH_API_KEY=
OPENLOOKUP_API_KEY=

# Random secret used for HMAC hashing
HASH_KEY={hash_key}
"""
    )

    if os.name != "nt":
        ENV_FILE.chmod(0o600)

    print("[OK] Created .env")
    print()
    print("Add your API keys to:")
    print(f"  {ENV_FILE}")

# Containers

def stop_containers(runtime):
    print("[*] Stopping existing containers...")

    for container in (FRONTEND_CONTAINER, API_CONTAINER):
        subprocess.run(
            [runtime, "rm", "-f", container],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )


def create_network(runtime):
    result = subprocess.run(
        [runtime, "network", "inspect", NETWORK],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    if result.returncode != 0:
        print(f"[*] Creating network: {NETWORK}")
        run(runtime, ["network", "create", NETWORK])


def create_data_volume(runtime):
    result = subprocess.run(
        [runtime, "volume", "inspect", DATA_VOLUME],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    if result.returncode != 0:
        print(f"[*] Creating volume: {DATA_VOLUME}")
        run(runtime, ["volume", "create", DATA_VOLUME])


def build_api(runtime):
    print()
    print("=== Building API ===")

    run(
        runtime,
        [
            "build",
            "-t",
            API_IMAGE,
            "-f",
            "api/Dockerfile",
            ".",
        ],
    )


def build_frontend(runtime):
    print()
    print("=== Building frontend ===")

    run(
        runtime,
        [
            "build",
            "-t",
            FRONTEND_IMAGE,
            "-f",
            "frontend/Dockerfile",
            "frontend",
        ],
    )


def start_api(runtime):
    print()
    print("=== Starting API ===")

    run(
        runtime,
        [
            "run",
            "-d",
            "--name",
            API_CONTAINER,
            "--network",
            NETWORK,
            "--env-file",
            str(ENV_FILE),
            "-p",
            f"{API_PORT}:8000",
            "-v",
            f"{DATA_VOLUME}:/data",
            API_IMAGE,
        ],
    )


def start_frontend(runtime):
    print()
    print("=== Starting frontend ===")

    run(
        runtime,
        [
            "run",
            "-d",
            "--name",
            FRONTEND_CONTAINER,
            "--network",
            NETWORK,
            "-p",
            f"{FRONTEND_PORT}:80",
            FRONTEND_IMAGE,
        ],
    )

# Status

def status(runtime):
    print()
    print("=== PostmortemESS VLite ===")
    print()

    result = subprocess.run(
        [
            runtime,
            "ps",
            "--filter",
            f"name={API_CONTAINER}",
            "--filter",
            f"name={FRONTEND_CONTAINER}",
        ],
        cwd=ROOT,
    )

    print()
    print(f"Frontend: http://localhost:{FRONTEND_PORT}")
    print(f"API:      http://localhost:{API_PORT}")
    print(f"API docs: http://localhost:{API_PORT}/docs")

# Commands

def cmd_setup(runtime):
    create_env()

    print()
    print("Setup complete.")
    print()
    print("Next step:")
    print("  python3 launcher.py build")
    print()


def cmd_build(runtime):
    create_env()
    create_network(runtime)
    create_data_volume(runtime)

    build_api(runtime)
    build_frontend(runtime)

    print()
    print("Build complete.")


def cmd_start(runtime):
    create_env()
    create_network(runtime)
    create_data_volume(runtime)

    stop_containers(runtime)

    start_api(runtime)

    # Give API a moment to initialise before frontend starts.
    time.sleep(2)

    start_frontend(runtime)

    print()
    print("======================================")
    print(" PostmortemESS VLite is running")
    print("======================================")
    print()
    print(f" Web UI:   http://localhost:{FRONTEND_PORT}")
    print(f" API:      http://localhost:{API_PORT}")
    print(f" Swagger:  http://localhost:{API_PORT}/docs")
    print()


def cmd_stop(runtime):
    stop_containers(runtime)

    print()
    print("PostmortemESS VLite stopped.")


def cmd_logs(runtime, container):
    name = {
        "api": API_CONTAINER,
        "frontend": FRONTEND_CONTAINER,
    }.get(container)

    if not name:
        print("[ERROR] Choose 'api' or 'frontend'.")
        sys.exit(1)

    run(runtime, ["logs", "-f", name])


def cmd_restart(runtime):
    cmd_stop(runtime)
    cmd_start(runtime)

# Main

def main():
    runtime = find_runtime()

    print()
    print("PostmortemESS VLite")
    print("===================")
    print(f"Container runtime: {runtime}")
    print()

    command = sys.argv[1] if len(sys.argv) > 1 else "help"

    if command == "setup":
        cmd_setup(runtime)

    elif command == "build":
        cmd_build(runtime)

    elif command == "start":
        cmd_start(runtime)

    elif command == "stop":
        cmd_stop(runtime)

    elif command == "restart":
        cmd_restart(runtime)

    elif command == "status":
        status(runtime)

    elif command == "logs":
        container = sys.argv[2] if len(sys.argv) > 2 else "api"
        cmd_logs(runtime, container)

    elif command == "help":
        print("Usage:")
        print()
        print("  python3 launcher.py setup")
        print("  python3 launcher.py build")
        print("  python3 launcher.py start")
        print("  python3 launcher.py stop")
        print("  python3 launcher.py restart")
        print("  python3 launcher.py status")
        print("  python3 launcher.py logs api")
        print("  python3 launcher.py logs frontend")

    else:
        print(f"[ERROR] Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()