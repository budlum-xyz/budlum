#!/usr/bin/env python3
"""Exercise the actual benchmark workflow validation body with finite fixtures.

The red phase selects one valid control and three incomplete proof reports.
The green phase checks the registered native gate through the same Bash body.
Only artifact paths and the executable path are relocated into the test fixture.
This is report-schema evidence, not a fresh performance measurement.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest

STEP = "Fail on a vacuous benchmark run"
EXECUTABLE = "./xtask/gates/target/release/budlum-gates"
CANONICAL = "bench-budzero-canonical.txt"
BASELINE = "bench-budzero-baseline.txt"
NAMES = (
    "budzero-canonical-storage-challenge-v1",
    "budzero-canonical-private-transfer-v1",
    "budzero-canonical-matmul-2-3-2-v1",
)
BASELINE_NAME = "budzero-proof-baseline-v1"


def validation_body(workflow: str) -> str:
    marker = f"      - name: {STEP}\n        run: |\n"
    if workflow.count(marker) != 1:
        raise ValueError("expected exactly one unchanged validation step")
    tail = workflow.split(marker, 1)[1]
    body = []
    for line in tail.splitlines():
        if not line.strip():
            body.append("")
        elif line.startswith("          "):
            body.append(line[10:])
        else:
            break
    result = "\n".join(body).rstrip() + "\n"
    if not result.startswith("set -euo pipefail\n"):
        raise ValueError("validation must retain strict Bash error propagation")
    return result


def sample(name: str, **changes: object) -> str:
    record = {
        "benchmark": name,
        "samples": 1,
        "trace_rows": 1,
        "proof_bytes": 1,
        "prove_seconds_mean": 1.0,
        "verify_seconds_mean": 1.0,
    }
    record.update(changes)
    return json.dumps(record, separators=(",", ":")) + "\n"


def fixtures() -> list[tuple[str, dict[str, str | None], int]]:
    valid = {
        "bench-micro.txt": "Throughput: 1 fixture/s\n",
        "bench-single.txt": "Avg per transaction: 1 fixture unit\n",
        CANONICAL: "".join(sample(name) for name in NAMES),
        BASELINE: sample(BASELINE_NAME),
    }
    cases = [("valid_control", valid, 0)]
    for name, path, value in [
        ("compiler_only_canonical", CANONICAL, "Compiling fixture\nFinished build\n"),
        ("compiler_only_baseline", BASELINE, "Compiling fixture\nFinished build\n"),
        ("malformed_canonical", CANONICAL, "{broken}\n"),
        ("missing_program", CANONICAL, "".join(sample(name) for name in NAMES[:2])),
        ("duplicate_program", CANONICAL, valid[CANONICAL] + sample(NAMES[0])),
        ("unknown_program", CANONICAL, valid[CANONICAL] + sample("unknown-proof-report")),
        ("wrong_file", CANONICAL, valid[BASELINE]),
        ("zero_samples", BASELINE, sample(BASELINE_NAME, samples=0)),
        ("fractional_samples", BASELINE, sample(BASELINE_NAME, samples=1.5)),
        ("negative_rows", BASELINE, sample(BASELINE_NAME, trace_rows=-1)),
        ("text_proof_bytes", BASELINE, sample(BASELINE_NAME, proof_bytes="one")),
        ("zero_prove_time", BASELINE, sample(BASELINE_NAME, prove_seconds_mean=0.0)),
        ("text_verify_time", BASELINE, sample(BASELINE_NAME, verify_seconds_mean="NaN")),
        ("null_verify_time", BASELINE, sample(BASELINE_NAME, verify_seconds_mean=None)),
        ("trailing_malformed", CANONICAL, valid[CANONICAL] + "{broken}\n"),
        ("missing_baseline", BASELINE, None),
        ("empty_canonical", CANONICAL, ""),
        ("missing_micro_metric", "bench-micro.txt", "Finished build\n"),
        ("missing_single_metric", "bench-single.txt", "Finished build\n"),
    ]:
        cases.append((name, {**valid, path: value}, 1))
    return cases


def invoke(body: str, files: dict[str, str | None], gate: str | None) -> dict:
    with tempfile.TemporaryDirectory(prefix="proof-metric-fixture-") as temporary:
        directory = Path(temporary)
        for name, value in files.items():
            if value is not None:
                (directory / name).write_text(value, encoding="utf-8")
        command = body.replace("/tmp", shlex.quote(str(directory)))
        if gate is not None:
            command = command.replace(EXECUTABLE, shlex.quote(str(Path(gate).resolve())))
        result = subprocess.run(
            ["bash", "-c", command],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        return {
            "exit": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "input_sha256": {
                name: hashlib.sha256(value.encode()).hexdigest() if value is not None else None
                for name, value in files.items()
            },
        }


def run_suite(workflow: str, phase: str, gate: str | None = None) -> dict:
    body = validation_body(workflow)
    selected = fixtures()[:4] if phase == "red" else fixtures()
    observations = []
    attributes = {}
    for name, files, expected in selected:
        def build_case(case_name: str, inputs: dict, expected_exit: int):
            def check(self):
                observation = invoke(body, inputs, gate)
                observations.append({"case": case_name, "expected_exit": expected_exit, **observation})
                self.assertEqual(observation["exit"], expected_exit, observation)
                if phase == "green" and expected_exit == 0:
                    self.assertIn("4 required proof measurements contain numeric fields", observation["stdout"])
                    self.assertIn("25 invalid observations refused", observation["stdout"])
                if expected_exit != 0:
                    self.assertNotIn("all benchmark runs produced metrics", observation["stdout"])
            return check
        attributes["test_" + name] = build_case(name, files, expected)
    case_class = type("WorkflowMetrics", (unittest.TestCase,), attributes)
    output = io.StringIO()
    result = unittest.TextTestRunner(stream=output, verbosity=2).run(
        unittest.defaultTestLoader.loadTestsFromTestCase(case_class)
    )
    return {
        "scope": "Actual workflow validation shell with synthetic, finite metric fixtures; not a benchmark run.",
        "phase": phase,
        "workflow_sha256": hashlib.sha256(workflow.encode()).hexdigest(),
        "body_sha256": hashlib.sha256(body.encode()).hexdigest(),
        "body": body,
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "successful": result.wasSuccessful(),
        "unittest_output": output.getvalue(),
        "cases": observations,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workflow", required=True, type=Path)
    parser.add_argument("--phase", choices=("red", "green"), required=True)
    parser.add_argument("--gate")
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args()
    result = run_suite(args.workflow.read_text(encoding="utf-8"), args.phase, args.gate)
    args.report.write_text(json.dumps(result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(result["unittest_output"], end="")
    return 0 if result["successful"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
