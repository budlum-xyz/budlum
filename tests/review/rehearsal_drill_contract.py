#!/usr/bin/env python3
"""Contract checks for the WP-46 drills.

Run:
    python3 tests/review/rehearsal_drill_contract.py

A drill may pass only when its measurement file satisfies the card. It must
never write evidence or report success when the measurement is absent, and
`run_all.sh` must report such a drill as not run and fail the run.
"""

import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DRILLS = ROOT / "ops/rehearsal/drills"
T1 = DRILLS / "t1_mobile_mass_departure.sh"
GOOD = {
    "finality_delay_before_ms": 900,
    "finality_delay_after_ms": 900,
    "objects_lost": 0,
    "full_class_reads_ok": True,
}


class DrillContract(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.out = self.dir / "out"

    def run_drill(self, evidence=None, script=T1):
        env = {k: v for k, v in os.environ.items() if k != "REHEARSAL_EVIDENCE"}
        env["REHEARSAL_OUT"] = str(self.out)
        if evidence is not None:
            path = self.dir / "measurement.json"
            path.write_text(json.dumps(evidence))
            env["REHEARSAL_EVIDENCE"] = str(path)
        return subprocess.run(
            ["bash", str(script)], env=env, text=True, capture_output=True, timeout=60
        )

    def test_absent_measurement_is_not_a_pass(self):
        result = self.run_drill()
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertFalse((self.out / "T-1.md").exists(), "a drill wrote evidence without a measurement")

    def test_measurement_missing_a_field_fails(self):
        result = self.run_drill({"objects_lost": 0})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("FAIL", (self.out / "T-1.md").read_text())

    def test_measurement_over_the_limit_fails(self):
        result = self.run_drill({**GOOD, "objects_lost": 1})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_measurement_within_the_card_passes_and_records_evidence(self):
        result = self.run_drill(GOOD)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("Verdict: PASS", (self.out / "T-1.md").read_text())

    def test_run_all_never_reports_an_unevidenced_rehearsal_as_complete(self):
        sandbox = self.dir / "drills"
        shutil.copytree(DRILLS, sandbox)
        result = subprocess.run(
            ["bash", str(sandbox / "run_all.sh")],
            env={**{k: v for k, v in os.environ.items() if k != "REHEARSAL_EVIDENCE"},
                 "REHEARSAL_OUT": str(self.out)},
            text=True, capture_output=True, timeout=120,
        )
        self.assertNotEqual(result.returncode, 0, "run_all accepted drills with no measurements")
        self.assertIn("NOT RUN", result.stdout)
        self.assertNotIn("all seven drills passed", result.stdout)


if __name__ == "__main__":
    unittest.main(verbosity=2)
