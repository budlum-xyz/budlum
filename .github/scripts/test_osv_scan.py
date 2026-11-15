"""Regression tests for the OSV lockfile coverage and failure handling."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name("osv_scan.py")


class OsvScanTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        scanner = self.bin / "osv-scanner"
        scanner.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "pathlib.Path('arguments.json').write_text(json.dumps(sys.argv[1:]))\n"
            "if os.environ.get('WRITE_REPORT') == '1':\n"
            "    pathlib.Path('osv-scanner.sarif').write_text('{}')\n"
            "sys.exit(int(os.environ.get('EXIT_CODE', '0')))\n"
        )
        scanner.chmod(0o755)
        self.env = dict(os.environ, PATH=f"{self.bin}{os.pathsep}{os.environ['PATH']}")

    def lock(self, name):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("version = 3\n")

    def run_scan(self, mode, **env):
        return subprocess.run([sys.executable, str(SCRIPT), mode], cwd=self.root,
                              env=dict(self.env, **env), capture_output=True, text=True)

    def test_discovers_new_and_space_containing_lockfiles_in_both_modes(self):
        self.lock("Cargo.lock")
        self.lock("crates/new crate/Cargo.lock")
        self.lock("target/debug/Cargo.lock")
        self.lock("crates/x/target/Cargo.lock")
        for mode in ("report", "gate"):
            result = self.run_scan(mode, WRITE_REPORT="1")
            self.assertEqual(result.returncode, 0, result.stderr)
            args = json.loads((self.root / "arguments.json").read_text())
            self.assertEqual([x for x in args if x.startswith("--lockfile=")],
                             ["--lockfile=Cargo.lock", "--lockfile=crates/new crate/Cargo.lock"])

    def test_empty_tree_fails_closed(self):
        result = self.run_scan("gate")
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.root / "arguments.json").exists())

    def test_findings_fail_gate_but_report_can_be_uploaded(self):
        self.lock("Cargo.lock")
        self.assertEqual(self.run_scan("gate", EXIT_CODE="1").returncode, 1)
        self.assertEqual(self.run_scan("report", EXIT_CODE="1", WRITE_REPORT="1").returncode, 0)

    def test_report_requires_new_nonempty_output_and_valid_status(self):
        self.lock("Cargo.lock")
        (self.root / "osv-scanner.sarif").write_text("stale")
        self.assertNotEqual(self.run_scan("report", EXIT_CODE="1").returncode, 0)
        self.assertNotEqual(self.run_scan("report", EXIT_CODE="2", WRITE_REPORT="1").returncode, 0)

    def test_symlink_lock_is_rejected(self):
        self.lock("real")
        (self.root / "Cargo.lock").symlink_to(self.root / "real")
        self.assertNotEqual(self.run_scan("gate").returncode, 0)
        self.assertFalse((self.root / "arguments.json").exists())


if __name__ == "__main__":
    unittest.main()
