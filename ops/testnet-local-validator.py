#!/usr/bin/env python3
"""Run two validator seats in one rehearsal container without sharing durable state."""

from __future__ import annotations

import signal
import subprocess
import sys
import time
from pathlib import Path

CEREMONY_DIR = Path("/home/budlum/ceremony")
DATA_DIR = Path("/home/budlum/data")


def seat_bootnodes(seat: str, fallback_bootstrap: str) -> list[str]:
    try:
        idx = int(seat) - 1
    except ValueError:
        return [fallback_bootstrap]
    if not 0 <= idx < 8:
        return [fallback_bootstrap]
    peers = (((idx + 1) % 8) + 1, ((idx + 7) % 8) + 1, ((idx + 4) % 8) + 1)
    addrs: list[str] = []
    for n in peers:
        p = CEREMONY_DIR / f"validator{n}.bootnode"
        if p.exists():
            addr = p.read_text(encoding="utf-8").strip()
            if addr and addr not in addrs:
                addrs.append(addr)
    return addrs or [fallback_bootstrap]


def write_seat_config(seat: str, bootnodes: list[str]) -> Path:
    seat_dir = DATA_DIR / f"validator{seat}"
    seat_dir.mkdir(parents=True, exist_ok=True)
    vote_db = (seat_dir / "vote-history.json").as_posix()
    ban_db = (seat_dir / "banned-peers.json").as_posix()
    bootnodes_toml = ", ".join(f'"{b}"' for b in bootnodes)
    node_toml = seat_dir / "node.toml"
    node_toml.write_text(
        f'[p2p]\nbootnodes = [{bootnodes_toml}]\nvote_history_db = "{vote_db}"\nbanned_peer_db = "{ban_db}"\n',
        encoding="utf-8",
    )
    return node_toml


def start_seat(
    seat: str,
    bootstrap: str,
    p2p_port: int,
    rpc_port: int,
    operator_port: int,
    metrics_port: int,
) -> subprocess.Popen[bytes]:
    bootnodes = seat_bootnodes(seat, bootstrap)
    node_file = write_seat_config(seat, bootnodes)
    seat_db = DATA_DIR / f"validator{seat}/db"
    return subprocess.Popen(
        [
            "budlum-core",
            f"--config={node_file}",
            "--network=testnet",
            f"--genesis-file={CEREMONY_DIR / 'genesis.json'}",
            "--consensus=pos",
            "--role=validator",
            f"--validator-key-file={CEREMONY_DIR / f'validator{seat}.key'}",
            f"--p2p-identity-file={CEREMONY_DIR / f'validator{seat}.p2p'}",
            f"--port={p2p_port}",
            f"--db-path={seat_db}",
            f"--rpc-public-listener=127.0.0.1:{rpc_port}",
            f"--rpc-operator-listener=127.0.0.1:{operator_port}",
            f"--metrics-listener=0.0.0.0:{metrics_port}",
            f"--bootstrap={bootnodes[0]}",
        ]
    )


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(f"usage: {argv[0]} FIRST_SEAT SECOND_SEAT BOOTSTRAP_HOST", file=sys.stderr)
        return 2

    legacy_vote = DATA_DIR / "testnet/vote-history.json"
    if legacy_vote.exists():
        print(
            f"refusing to start: shared legacy vote history found at {legacy_vote}",
            file=sys.stderr,
        )
        return 1

    first, second, bootstrap_host = argv[1], argv[2], argv[3]
    bootstrap = (CEREMONY_DIR / f"{bootstrap_host}.bootnode").read_text(encoding="utf-8").strip()

    procs = [
        start_seat(first, bootstrap, 5001, 8545, 8546, 9090),
        start_seat(second, bootstrap, 5002, 8555, 8556, 9091),
    ]
    stopping = False

    def handle_signal(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True
        for proc in procs:
            if proc.poll() is None:
                proc.terminate()

    signal.signal(signal.SIGTERM, handle_signal)
    signal.signal(signal.SIGINT, handle_signal)

    while all(proc.poll() is None for proc in procs):
        time.sleep(0.2)

    if not stopping:
        # Let sibling seats complete startup/early-exit before sending SIGTERM.
        deadline = time.monotonic() + 1.0
        while (
            any(proc.poll() is None for proc in procs)
            and time.monotonic() < deadline
            and not stopping
        ):
            time.sleep(0.05)

    for proc in procs:
        if proc.poll() is None:
            proc.terminate()
    for proc in procs:
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    return 0 if stopping else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
