"""Regression tests for the WP-46 public-operator-record ceremony."""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import unittest
from pathlib import Path


REPOSITORY = Path(__file__).resolve().parents[3]
SCRIPT = REPOSITORY / "ops/rehearsal/genesis_rehearsal.sh"
TEMPLATE = REPOSITORY / "config/rehearsal-genesis.json"
BLS_SCHEME = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"


FAKE_BUD = textwrap.dedent(
    """\
    #!/usr/bin/env python3
    import json
    import os
    import sys
    from pathlib import Path

    args = sys.argv[1:]
    if args[:2] != ["genesis", "assemble"]:
        raise SystemExit("wrong bud subcommand")
    if os.environ.get("BUD_TEST_FAIL") == "1":
        raise SystemExit(9)

    def option(name):
        try:
            return args[args.index(name) + 1]
        except (ValueError, IndexError):
            raise SystemExit(f"missing {name}")

    if option("--network") != "testnet":
        raise SystemExit("wrong network")
    operators = Path(option("--operators"))
    out = Path(option("--out"))
    template = json.loads(Path("config/rehearsal-genesis.json").read_text(encoding="utf-8"))
    paths = sorted(operators.glob("*.json"))
    records = [json.loads(path.read_text(encoding="utf-8")) for path in paths]
    Path(os.environ["BUD_TEST_CALLS"]).write_text(
        json.dumps({"args": args, "staged_names": [path.name for path in paths]}),
        encoding="utf-8",
    )
    for record in records:
        if set(record) != {"validator", "registration"}:
            raise SystemExit("staged record contains non-public metadata")

    genesis = {
        field: template[field]
        for field in (
            "chain_id", "allocations", "block_reward", "base_fee", "gas_schedule",
            "timestamp", "bud_tokenomics", "pq_scheme",
        )
    }
    genesis["timestamp"] = int(option("--timestamp-ms"))
    genesis["validators"] = [record["validator"] for record in records]
    genesis["validator_consensus_keys"] = [
        {"validator": record["validator"], "registration": record["registration"]}
        for record in records
    ]
    genesis["tokenomics_addresses"] = {
        name: "b0d0" + f"{tag:02x}" + "0" * 58
        for name, tag in (
            ("community", 1), ("liquidity", 2), ("ecosystem", 3),
            ("team", 4), ("burn_reserve", 5),
        )
    }
    genesis["reward_pool"] = {"enabled": True}
    out.write_text(json.dumps(genesis), encoding="utf-8")
    print(f"assembled {len(records)} records")
    """
)


def public_record(index):
    byte = index + 1
    return {
        "validator": f"{index + 1:064x}",
        "registration": {
            "scheme_id": BLS_SCHEME,
            "vrf_public_key": [byte] * 32,
            "bls_public_key": [byte] * 96,
            "pop_signature": [byte] * 48,
            "pq_public_key": [byte] * 1952,
        },
        "moniker": f"operator-{index}",
    }


class GenesisRehearsalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "config").mkdir()
        shutil.copyfile(TEMPLATE, self.root / "config/rehearsal-genesis.json")
        self.records = self.root / "records"
        self.records.mkdir()
        self.output = self.root / "output"
        self.fake_bud = self.root / "fake-bud"
        self.fake_bud.write_text(FAKE_BUD, encoding="utf-8")
        self.fake_bud.chmod(0o755)
        self.call_log = self.root / "bud-calls.json"

    def run_ceremony(self, records, fail_assembly=False):
        for filename, record in records:
            (self.records / filename).write_text(json.dumps(record), encoding="utf-8")
        env = os.environ.copy()
        env["BUD_BIN"] = str(self.fake_bud)
        env["BUD_TEST_CALLS"] = str(self.call_log)
        if fail_assembly:
            env["BUD_TEST_FAIL"] = "1"
        return subprocess.run(
            ["bash", str(SCRIPT), str(self.records), str(self.output)],
            cwd=self.root,
            env=env,
            text=True,
            capture_output=True,
            timeout=30,
        )

    def assert_refused_before_assembly(self, result):
        self.assertNotEqual(result.returncode, 0, result.stdout)
        self.assertFalse(self.call_log.exists(), "invalid records reached the genesis assembler")
        self.assertFalse((self.output / "rehearsal-genesis.json").exists())
        self.assertFalse((self.output / "rehearsal-genesis.sha256").exists())

    def test_full_class_label_without_operator_record_is_refused(self):
        result = self.run_ceremony(
            [(f"operator-{index}.json", {"class": "Full"}) for index in range(8)]
        )
        self.assert_refused_before_assembly(result)

    def test_duplicate_validator_addresses_are_refused(self):
        record = public_record(0)
        result = self.run_ceremony(
            [(f"operator-{index}.json", record) for index in range(8)]
        )
        self.assert_refused_before_assembly(result)
        self.assertIn("duplicate validator address", result.stderr)

    def test_duplicate_consensus_keys_are_refused(self):
        records = [public_record(index) for index in range(8)]
        records[1]["registration"]["bls_public_key"] = list(
            bytes(records[0]["registration"]["bls_public_key"])
        )
        result = self.run_ceremony(
            [(f"operator-{index}.json", record) for index, record in enumerate(records)]
        )
        self.assert_refused_before_assembly(result)
        self.assertIn("duplicate bls_public_key", result.stderr)

    def test_private_material_is_refused_instead_of_published(self):
        records = [public_record(index) for index in range(8)]
        records[0]["private_key"] = "SENTINEL-PRIVATE-KEY"
        result = self.run_ceremony(
            [(f"operator-{index}.json", record) for index, record in enumerate(records)]
        )
        self.assert_refused_before_assembly(result)
        self.assertNotIn("SENTINEL-PRIVATE-KEY", result.stdout + result.stderr)

    def test_fewer_than_eight_complete_records_are_refused(self):
        result = self.run_ceremony(
            [(f"operator-{index}.json", public_record(index)) for index in range(7)]
        )
        self.assert_refused_before_assembly(result)
        self.assertIn("at least 8", result.stderr)

    def test_filename_is_data_and_not_executable_code(self):
        malicious_name = (
            "record', (__import__('pathlib').Path('sentinel').touch() or 'r')) "
            "or open('ignored.json"
        )
        records = [(f"operator-{index}.json", public_record(index)) for index in range(8)]
        records[0] = (malicious_name, public_record(0))

        result = self.run_ceremony(records)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.root / "sentinel").exists())
        call = json.loads(self.call_log.read_text(encoding="utf-8"))
        self.assertEqual(
            call["staged_names"],
            [f"operator-{index:04d}.json" for index in range(8)],
        )

    def test_assembled_genesis_uses_address_and_public_key_records(self):
        records = [(f"operator-{index}.json", public_record(index)) for index in range(8)]
        result = self.run_ceremony(records)

        self.assertEqual(result.returncode, 0, result.stderr)
        genesis_path = self.output / "rehearsal-genesis.json"
        genesis_text = genesis_path.read_text(encoding="utf-8")
        genesis = json.loads(genesis_text)
        self.assertEqual(stat.S_IMODE(genesis_path.stat().st_mode), 0o644)
        self.assertEqual(len(genesis["validators"]), 8)
        self.assertTrue(all(isinstance(address, str) for address in genesis["validators"]))
        self.assertEqual(len(genesis["validator_consensus_keys"]), 8)
        self.assertEqual(
            {entry["validator"] for entry in genesis["validator_consensus_keys"]},
            set(genesis["validators"]),
        )
        self.assertNotIn("moniker", genesis_text)
        self.assertNotIn("class", genesis_text)
        self.assertEqual(genesis["ceremony_status"], "rehearsal")
        digest = (self.output / "rehearsal-genesis.sha256").read_text(encoding="utf-8").split()
        self.assertEqual(digest[0], hashlib.sha256(genesis_path.read_bytes()).hexdigest())
        self.assertEqual(digest[1], "rehearsal-genesis.json")

    def test_assembler_refusal_does_not_publish_partial_files(self):
        result = self.run_ceremony(
            [(f"operator-{index}.json", public_record(index)) for index in range(8)],
            fail_assembly=True,
        )
        self.assertEqual(result.returncode, 9, result.stderr)
        self.assertFalse((self.output / "rehearsal-genesis.json").exists())
        self.assertFalse((self.output / "rehearsal-genesis.sha256").exists())

    def test_invalid_public_key_shape_is_refused(self):
        records = [public_record(index) for index in range(8)]
        records[3]["registration"]["pq_public_key"] = [1, 2, 3]
        result = self.run_ceremony(
            [(f"operator-{index}.json", record) for index, record in enumerate(records)]
        )
        self.assert_refused_before_assembly(result)
        self.assertIn("1952-byte", result.stderr)


if __name__ == "__main__":
    unittest.main(verbosity=2)
