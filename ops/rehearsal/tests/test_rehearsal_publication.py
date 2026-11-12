"""A live rehearsal starts at wall time and keeps its original genesis on retry."""

import hashlib
import importlib.util
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[3]
SCRIPT = ROOT / "ops/rehearsal/genesis_rehearsal.py"


class RehearsalPublicationTests(unittest.TestCase):
    def setUp(self):
        spec = importlib.util.spec_from_file_location("rehearsal_publication", SCRIPT)
        self.ceremony = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.ceremony)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.registrations = Path(self.temp.name) / "operators"
        self.registrations.mkdir()
        self.output = Path(self.temp.name) / "published"
        self.old_cwd = Path.cwd()
        os.chdir(ROOT)
        self.addCleanup(os.chdir, self.old_cwd)
        self.records = {}
        for index in range(1, 9):
            address = f"{index:064x}"
            self.records[address] = {
                "scheme_id": self.ceremony.BLS_SCHEME,
                "vrf_public_key": [index] * 32,
                "bls_public_key": [index] * 96,
                "pop_signature": [index] * 48,
                "pq_public_key": [index] * 1952,
            }

    def assemble(self, _staging, output_path, timestamp_ms):
        template = json.loads((ROOT / "config/ceremony-rehearsal-template.json").read_text())
        genesis = {name: template[name] for name in self.ceremony.TEMPLATE_FIELDS}
        genesis["timestamp"] = timestamp_ms
        genesis["validators"] = list(self.records)
        genesis["validator_consensus_keys"] = [
            {"validator": address, "registration": registration}
            for address, registration in self.records.items()
        ]
        genesis["tokenomics_addresses"] = {
            name: self.ceremony.reserved_address(tag)
            for name, tag in (("community", 1), ("liquidity", 2), ("ecosystem", 3),
                              ("team", 4), ("burn_reserve", 5))
        }
        genesis["reward_pool"] = {"enabled": True}
        output_path.write_text(json.dumps(genesis), encoding="utf-8")
        return 0

    def test_live_stamp_is_not_the_future_template_and_retry_is_immutable(self):
        stamp_ms = 1_750_000_000_000
        with mock.patch.object(self.ceremony, "stage_public_records", return_value=self.records), \
             mock.patch.object(self.ceremony, "run_genesis_assembler", side_effect=self.assemble) as assembler, \
             mock.patch.object(self.ceremony.time, "time_ns", return_value=stamp_ms * 1_000_000):
            self.assertEqual(self.ceremony.main([str(self.registrations), str(self.output)]), 0)
            genesis_path = self.output / "rehearsal-genesis.json"
            original = genesis_path.read_bytes()
            self.assertEqual(json.loads(original)["timestamp"], stamp_ms)
            self.assertNotEqual(stamp_ms, json.loads((ROOT / "config/ceremony-rehearsal-template.json").read_text())["timestamp"])
            self.assertEqual(assembler.call_count, 1)
            self.assertEqual(self.ceremony.main([str(self.registrations), str(self.output)]), 0)
            self.assertEqual(assembler.call_count, 1, "a retry must not replace a live genesis")
            self.assertEqual(genesis_path.read_bytes(), original)
            self.assertEqual(
                (self.output / "rehearsal-genesis.sha256").read_text(),
                f"{hashlib.sha256(original).hexdigest()}  rehearsal-genesis.json\n",
            )

    def test_incomplete_or_changed_published_ceremony_refuses_retry(self):
        stamp_ms = 1_750_000_000_000
        with mock.patch.object(self.ceremony, "stage_public_records", return_value=self.records), \
             mock.patch.object(self.ceremony, "run_genesis_assembler", side_effect=self.assemble), \
             mock.patch.object(self.ceremony.time, "time_ns", return_value=stamp_ms * 1_000_000):
            self.assertEqual(self.ceremony.main([str(self.registrations), str(self.output)]), 0)
            genesis_path = self.output / "rehearsal-genesis.json"
            original = genesis_path.read_bytes()
            changed = dict(self.records)
            changed.pop(next(iter(changed)))
            with mock.patch.object(self.ceremony, "stage_public_records", return_value=changed):
                self.assertNotEqual(self.ceremony.main([str(self.registrations), str(self.output)]), 0)
            self.assertEqual(genesis_path.read_bytes(), original)
            (self.output / "rehearsal-genesis.sha256").unlink()
            self.assertNotEqual(self.ceremony.main([str(self.registrations), str(self.output)]), 0)
            self.assertEqual(genesis_path.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
