"""Local two-seat validators must never share vote high-water marks."""

import os
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[2] / "testnet-local-validator.py"


class ValidatorSeatStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.ceremony = self.root / "ceremony"
        self.ceremony.mkdir()
        self.data = self.root / "data"
        self.data.mkdir()
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.calls = self.root / "calls"
        (self.bin / "budlum-core").write_text(
            '#!/bin/sh\nprintf "%s\\n" "$@" >> "$CALLS"\nexit 1\n', encoding="utf-8"
        )
        (self.bin / "budlum-core").chmod(0o755)
        script = SCRIPT.read_text(encoding="utf-8")
        script = script.replace('CEREMONY_DIR = Path("/home/budlum/ceremony")', f'CEREMONY_DIR = Path("{self.ceremony}")')
        script = script.replace('DATA_DIR = Path("/home/budlum/data")', f'DATA_DIR = Path("{self.data}")')
        self.script = self.root / "validator.py"
        self.script.write_text(script, encoding="utf-8")
        (self.ceremony / "genesis.json").write_text("genesis", encoding="utf-8")
        (self.ceremony / "validator2.bootnode").write_text("/dns4/validator2/tcp/5001/p2p/peer", encoding="utf-8")
        for seat in (1, 5):
            (self.ceremony / f"validator{seat}.key").write_text("key", encoding="utf-8")
            (self.ceremony / f"validator{seat}.p2p").write_text("p2p", encoding="utf-8")

    def run_seats(self):
        env = os.environ.copy()
        env["PATH"] = f"{self.bin}{os.pathsep}{env['PATH']}"
        env["CALLS"] = str(self.calls)
        return subprocess.run(
            [sys.executable, str(self.script), "1", "5", "validator2"],
            env=env,
            capture_output=True,
            text=True,
            timeout=10,
        )

    def test_two_seats_keep_separate_durable_vote_and_ban_files(self):
        result = self.run_seats()
        # The fake budlum-core exits nonzero; the supervisor must notice.
        self.assertEqual(result.returncode, 1, result.stderr)
        calls = self.calls.read_text(encoding="utf-8")
        for seat in (1, 5):
            node_file = self.data / f"validator{seat}/node.toml"
            config = tomllib.loads(node_file.read_text(encoding="utf-8"))
            self.assertEqual(
                config["p2p"]["vote_history_db"],
                str(self.data / f"validator{seat}/vote-history.json"),
            )
            self.assertEqual(
                config["p2p"]["banned_peer_db"],
                str(self.data / f"validator{seat}/banned-peers.json"),
            )
            self.assertIn(f"--config={node_file}", calls)
        self.assertNotEqual(
            (self.data / "validator1/node.toml").read_bytes(),
            (self.data / "validator5/node.toml").read_bytes(),
        )

    def test_legacy_shared_vote_history_fails_closed_before_starting(self):
        legacy = self.data / "testnet/vote-history.json"
        legacy.parent.mkdir()
        legacy.write_text('{"last_prevote_height":10}', encoding="utf-8")
        result = self.run_seats()
        self.assertEqual(result.returncode, 1)
        self.assertIn("shared legacy vote history", result.stderr)
        self.assertFalse(self.calls.exists(), "node started with a shared vote history")


if __name__ == "__main__":
    unittest.main()
