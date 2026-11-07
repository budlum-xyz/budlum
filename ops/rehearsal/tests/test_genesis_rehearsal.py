import json
import tempfile
import unittest
from pathlib import Path

from ops.rehearsal.genesis_rehearsal import (
    CeremonyValidationError,
    assemble_rehearsal_genesis,
    validate_operator_record,
)


def _valid_record(idx: int) -> dict:
    b = f"{idx:02x}"
    return {
        "validator": b * 32,
        "registration": {
            "vrf_public_key": f"{idx + 16:02x}" * 32,
            "bls_public_key": f"{idx + 32:02x}" * 48,
            "bls_proof_of_possession": f"{idx + 48:02x}" * 96,
            "pq_public_key": f"{idx + 64:02x}" * 1952,
        },
        "moniker": f"rehearsal-{idx}",
    }


def _template_doc() -> dict:
    return {
        "chain_id": 45261,
        "pq_scheme": "ml-dsa-65",
        "allocations": [],
        "validators": [],
        "block_reward": 0,
        "base_fee": 1,
        "gas_schedule": {
            "base_fee": 1,
            "gas_per_byte": 1,
            "gas_per_signature": 500,
            "transfer_gas": 21000,
            "stake_gas": 35000,
            "vote_gas": 25000,
            "contract_call_gas": 35000,
        },
        "timestamp": 1800000000000,
        "bud_tokenomics": {
            "community": 10000000000000,
            "liquidity": 10000000000000,
            "ecosystem": 20000000000000,
            "team": 20000000000000,
            "burn_reserve": 40000000000000,
            "epochs_per_year": 210240,
            "annual_burn_ratio_fixed": 100000,
            "team_cliff_epochs": 210240,
            "team_vesting_epochs": 840960,
            "tx_fee_burn_ratio_fixed": 10000,
            "block_reward": 0,
            "validator_annual_yield_ratio_fixed": 50000,
            "slot_duration_secs": 3,
            "epoch_length_slots": 50,
        },
        "ceremony_status": "template_ready",
    }


class RehearsalCeremonyTests(unittest.TestCase):
    def test_empty_full_claims_are_rejected(self) -> None:
        with self.assertRaises(CeremonyValidationError):
            validate_operator_record({"class": "Full"})

    def test_private_key_material_is_rejected(self) -> None:
        rec = _valid_record(1)
        rec["private_key"] = "SENTINEL-PRIVATE-KEY"
        with self.assertRaises(CeremonyValidationError):
            validate_operator_record(rec)

    def test_duplicate_validator_records_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ops = root / "ops"
            ops.mkdir()
            tmpl = root / "template.json"
            tmpl.write_text(json.dumps(_template_doc()), encoding="utf-8")
            for i in range(8):
                (ops / f"op-{i}.json").write_text(
                    json.dumps(_valid_record(1)), encoding="utf-8"
                )
            with self.assertRaises(CeremonyValidationError):
                assemble_rehearsal_genesis(ops, tmpl)

    def test_crafted_filename_is_not_executed_and_assembly_is_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ops = root / "ops"
            ops.mkdir()
            sentinel = root / "sentinel"
            tmpl = root / "template.json"
            tmpl.write_text(json.dumps(_template_doc()), encoding="utf-8")
            for i in range(1, 9):
                weird_name = f"';__import__('pathlib').Path('sentinel').touch();op-{i}.json"
                (ops / weird_name).write_text(
                    json.dumps(_valid_record(i)), encoding="utf-8"
                )
            doc, digest = assemble_rehearsal_genesis(ops, tmpl)
            self.assertFalse(sentinel.exists())
            self.assertEqual(len(doc["validators"]), 8)
            self.assertEqual(len(digest), 64)


if __name__ == "__main__":
    unittest.main()
