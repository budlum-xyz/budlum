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


MEASUREMENTS = {
    "t1": {"finality_delay_before_ms": 900, "finality_delay_after_ms": 900,
           "objects_lost": 0, "full_class_reads_ok": True},
    "t2": {"finality_delay_checkpoints": 2, "seat_handover_checkpoints": 3},
    "t3": {"blocks_halted": 50, "alert_fired": True, "finality_resumed": True},
    "t4": {"resume_effective_epochs": 1, "repair_completed": True},
    "t5": {"total_gib": 100, "object_count": 10000,
           "upload_success_ratio": 1.0, "view_success_ratio": 1.0},
    "t6": {"tool_scenarios_passed": 6, "tool_scenarios_total": 6,
           "atomic_evm_call": True},
    "t7": {"rate_limited": True, "ratio_429": 0.42},
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

    def run_all(self, evidence: dict[str, dict]):
        sandbox = self.dir / "drills"
        shutil.copytree(DRILLS, sandbox)
        evidence_dir = self.dir / "evidence"
        evidence_dir.mkdir(exist_ok=True)
        for drill, measurement in evidence.items():
            (evidence_dir / f"{drill}.json").write_text(json.dumps(measurement))
        env = {k: v for k, v in os.environ.items()
               if k not in {"REHEARSAL_EVIDENCE", "REHEARSAL_EVIDENCE_DIR"}}
        env.update({"REHEARSAL_OUT": str(self.out),
                    "REHEARSAL_EVIDENCE_DIR": str(evidence_dir)})
        return subprocess.run(
            ["bash", str(sandbox / "run_all.sh")],
            env=env, text=True, capture_output=True, timeout=120,
        )

    def test_run_all_reports_missing_drill_measurement_as_not_run(self):
        result = self.run_all({"t1": MEASUREMENTS["t1"]})
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("t1_mobile_mass_departure PASS", result.stdout)
        for drill in ("t2_full_departure", "t7_rpc_load"):
            self.assertIn(f"{drill} NOT RUN", result.stdout)

    def test_run_all_passes_only_with_one_measurement_per_drill(self):
        result = self.run_all(MEASUREMENTS)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("7 passed, 0 failed, 0 not run", result.stdout)

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
