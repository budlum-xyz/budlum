"""The documented two-seat restore keeps vote marks bound to their seat."""

import re
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
BACKUP = ROOT / "ops/BACKUP_AND_RESTORE.md"
RUNBOOK = ROOT / "docs/OPERATIONS.md"


class TestnetRestoreTests(unittest.TestCase):
    def test_documented_sidecar_restore_keeps_both_seats(self):
        text = BACKUP.read_text(encoding="utf-8")
        command = re.search(r"^for seat in 1 5; do.*?^done", text, flags=re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(command, "the two-seat restore command is missing")
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / "saved"
            target = Path(tmp) / "restored"
            for seat in (1, 5):
                seat_dir = source / f"validator{seat}"
                seat_dir.mkdir(parents=True)
                (seat_dir / "vote-history.json").write_text(f"seat-{seat}", encoding="utf-8")
            (source / "validator1/banned-peers.json").write_text("peers-1", encoding="utf-8")
            script = command.group().replace("<saved-volume>", str(source))
            script = script.replace("<restored-volume>", str(target))
            subprocess.run(["sh", "-eu", "-c", script], check=True, timeout=10)
            for seat in (1, 5):
                restored = target / f"validator{seat}/vote-history.json"
                self.assertEqual(restored.read_text(encoding="utf-8"), f"seat-{seat}")
                self.assertEqual(stat.S_IMODE(restored.stat().st_mode), 0o600)
            self.assertEqual(
                (target / "validator1/banned-peers.json").read_text(encoding="utf-8"),
                "peers-1",
            )
            self.assertFalse((target / "validator5/banned-peers.json").exists())
        runbook = RUNBOOK.read_text(encoding="utf-8")
        self.assertIn("Restore the backed-up vote high-water marks", runbook)
        self.assertIn("before restarting either process", runbook)


if __name__ == "__main__":
    unittest.main()
