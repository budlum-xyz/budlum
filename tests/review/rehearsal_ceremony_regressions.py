#!/usr/bin/env python3
"""Black-box safety checks for a WP-46 rehearsal checkout.

Run explicitly, not as part of main's test suite:
    python3 tests/review/rehearsal_ceremony_regressions.py /path/to/checkout

To check the reviewed variant in this repository instead of another PR:
    PATH="$PWD/tests/review/fixtures/bin:$PATH" \
        python3 tests/review/rehearsal_ceremony_regressions.py tests/review/fixtures

The checkout must contain ops/rehearsal/genesis_rehearsal.sh and its template.
Inputs are deliberately invalid public records. A successful ceremony must never
be produced from them, even when eight files claim to be Full validators.
"""

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

if len(sys.argv) != 2:
    raise SystemExit(f"usage: {sys.argv[0]} CHECKOUT")
CHECKOUT = Path(sys.argv.pop()).resolve()
# A review fixture may place the script elsewhere; `config/rehearsal-genesis.json`
# is only used when the script under test reads it.
SCRIPT = (
    CHECKOUT / "ops/rehearsal/genesis_rehearsal.sh"
    if (CHECKOUT / "ops/rehearsal/genesis_rehearsal.sh").is_file()
    else CHECKOUT / "genesis_rehearsal.reviewed.sh"
)
TEMPLATE = CHECKOUT / "config/rehearsal-genesis.json"
if not SCRIPT.is_file():
    raise SystemExit(f"{CHECKOUT} lacks a WP-46 ceremony script")


class RehearsalCeremonySafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "config").mkdir()
        if TEMPLATE.is_file():
            shutil.copyfile(TEMPLATE, self.root / "config/rehearsal-genesis.json")
        self.records = self.root / "records"
        self.records.mkdir()
        self.output = self.root / "output"

    def run_ceremony(self, records):
        for i, record in enumerate(records):
            (self.records / f"operator-{i}.json").write_text(json.dumps(record))
        return subprocess.run(
            ["bash", str(SCRIPT), str(self.records), str(self.output)],
            cwd=self.root, text=True, capture_output=True, timeout=30,
        )

    def assert_refused(self, result):
        self.assertNotEqual(result.returncode, 0, f"invalid ceremony accepted: {result.stdout}")
        self.assertFalse((self.output / "rehearsal-genesis.json").exists(),
                         "invalid ceremony published a genesis")
        self.assertFalse((self.output / "rehearsal-genesis.sha256").exists(),
                         "invalid ceremony published a digest")

    def test_empty_full_claims_are_not_validator_records(self):
        self.assert_refused(self.run_ceremony([{"class": "Full"}] * 8))

    def test_duplicate_validator_records_do_not_form_a_committee(self):
        record = {"class": "Full", "validator": "duplicate", "registration": {}}
        self.assert_refused(self.run_ceremony([record] * 8))

    def test_record_filename_is_not_executed_as_python(self):
        # The sentinel is created only if the filename is interpolated into
        # Python source and executed. It contains no shell metacharacter call.
        name = "record', (__import__('pathlib').Path('sentinel').touch() or 'r')) or open('ignored.json"
        (self.records / name).write_text(json.dumps({"class": "Full"}))
        result = subprocess.run(
            ["bash", str(SCRIPT), str(self.records), str(self.output)],
            cwd=self.root, text=True, capture_output=True, timeout=30,
        )
        self.assertFalse((self.root / "sentinel").exists(),
                         "a record filename was executed as Python code")
        self.assert_refused(result)

    def test_private_key_material_is_not_published(self):
        records = [{"class": "Full", "validator": str(i), "registration": {},
                    "private_key": "SENTINEL-PRIVATE-KEY"} for i in range(8)]
        result = self.run_ceremony(records)
        genesis = self.output / "rehearsal-genesis.json"
        if genesis.exists():
            self.assertNotIn("SENTINEL-PRIVATE-KEY", genesis.read_text(),
                             "ceremony copied private material into a public file")
        self.assert_refused(result)


if __name__ == "__main__":
    unittest.main(verbosity=2)
