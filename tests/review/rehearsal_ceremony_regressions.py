#!/usr/bin/env python3
"""Black-box safety checks for a WP-46 rehearsal checkout.

Run explicitly, not as part of main's test suite:
    python3 tests/review/rehearsal_ceremony_regressions.py /path/to/checkout

The checkout must contain ops/rehearsal/genesis_rehearsal.sh and its template.
Inputs are deliberately invalid public records. A successful ceremony must never
be produced from them, even when eight files claim to be Full validators.
"""

import hashlib
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
SCRIPT = CHECKOUT / "ops/rehearsal/genesis_rehearsal.sh"
TEMPLATE = CHECKOUT / "config/rehearsal-genesis.json"
if not SCRIPT.is_file() or not TEMPLATE.is_file():
    raise SystemExit("checkout lacks the WP-46 ceremony script or template")


class RehearsalCeremonySafety(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "config").mkdir()
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


    @staticmethod
    def valid_record(index):
        """A Full public registration record, directive 7.3, public fields only."""
        return {
            "class": "Full",
            "owner": f"owner-{index}",
            "operator_key": f"ml-dsa-65-operator-{index}",
            "bls_key": f"bls-{index}",
            "bls_pop": f"pop-{index}",
            "pq_vote_key": f"ml-dsa-65-vote-{index}",
            "leader_commitment": f"commitment-{index}",
            "custody_quota_bytes": 4 * 1024 * 1024 * 1024,
            "peer_id": f"peer-{index}",
            "relay_offer": {"multiaddrs": [f"/ip4/127.0.0.1/tcp/{4000 + index}"]},
        }

    def test_valid_ceremony_publishes_only_public_fields(self):
        result = self.run_ceremony([self.valid_record(i) for i in range(8)])
        self.assertEqual(result.returncode, 0, result.stderr)
        genesis = self.output / "rehearsal-genesis.json"
        self.assertTrue(genesis.is_file(), "a valid ceremony published no genesis")
        body = json.loads(genesis.read_text())
        self.assertEqual(len(body["validators"]), 8)
        self.assertEqual(body["validators"][0]["class"], "Full")
        self.assertNotIn("private_key", genesis.read_text())
        self.assertNotIn("SENTINEL-PRIVATE-KEY", genesis.read_text())
        digest_file = self.output / "rehearsal-genesis.sha256"
        self.assertTrue(digest_file.is_file(), "no digest was published")
        expected = hashlib.sha256(genesis.read_bytes()).hexdigest()
        self.assertIn(expected, digest_file.read_text())
        audit = json.loads((self.output / "rehearsal-ceremony-audit.json").read_text())
        self.assertEqual(audit["validator_count"], 8)
        self.assertEqual(len(set(audit["validator_public_digests"])), 8)

    def test_fewer_than_eight_full_validators_is_refused(self):
        self.assert_refused(self.run_ceremony([self.valid_record(i) for i in range(7)]))

    def test_non_full_records_do_not_count(self):
        records = [self.valid_record(i) for i in range(7)]
        records.append({"class": "Mobile", "owner": "mobile-owner"})
        self.assert_refused(self.run_ceremony(records))

    def test_private_field_on_a_valid_record_is_still_refused(self):
        records = [self.valid_record(i) for i in range(8)]
        records[3]["operator_secret_key"] = "SENTINEL-PRIVATE-KEY"
        self.assert_refused(self.run_ceremony(records))

    def test_malformed_json_does_not_publish_a_genesis(self):
        (self.records / "broken.json").write_text("{not json")
        self.assert_refused(self.run_ceremony([self.valid_record(i) for i in range(8)]))

    def test_duplicate_peer_id_on_otherwise_valid_records_is_refused(self):
        records = [self.valid_record(i) for i in range(8)]
        records[5]["peer_id"] = records[2]["peer_id"]
        self.assert_refused(self.run_ceremony(records))


if __name__ == "__main__":
    unittest.main(verbosity=2)
