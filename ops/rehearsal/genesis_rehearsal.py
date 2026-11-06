#!/usr/bin/env python3
"""Deterministic WP-46 rehearsal genesis validator and assembler.

Validates public `OperatorRecord` JSON files (as produced by `bud validator init`)
without invoking a shell or evaluating untrusted paths, rejects secret-key fields,
enforces >= 8 unique Full validator records, and emits a `genesis_schema`-compliant
rehearsal genesis JSON together with its canonical SHA-256 digest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

BUD_MAX_SUPPLY = 100_000_000_000_000
MIN_REHEARSAL_VALIDATORS = 8
FORBIDDEN_SECRET_KEYS = frozenset(
    {
        "private_key",
        "secret_key",
        "signing_key",
        "seed",
        "mnemonic",
        "vrf_secret_key",
        "bls_secret_key",
        "pq_secret_key",
        "operator_secret_key",
    }
)
REQUIRED_REGISTRATION_KEYS = (
    "vrf_public_key",
    "bls_public_key",
    "bls_proof_of_possession",
    "pq_public_key",
)


class CeremonyValidationError(ValueError):
    """Raised when an operator record or genesis input violates R-09 checks."""


def _contains_forbidden_key(obj: Any) -> str | None:
    if isinstance(obj, dict):
        for k, v in obj.items():
            lowered = str(k).lower()
            if lowered in FORBIDDEN_SECRET_KEYS or "private" in lowered or "secret" in lowered:
                return str(k)
            nested = _contains_forbidden_key(v)
            if nested is not None:
                return nested
    elif isinstance(obj, list):
        for item in obj:
            nested = _contains_forbidden_key(item)
            if nested is not None:
                return nested
    return None


def _normalize_hex(value: Any, label: str, expected_bytes: int | None = None) -> str:
    if not isinstance(value, str):
        raise CeremonyValidationError(f"{label} must be a hex string")
    clean = value[2:] if value.startswith("0x") else value
    if not clean or len(clean) % 2 != 0:
        raise CeremonyValidationError(f"{label} must have non-empty even hex length")
    try:
        raw = bytes.fromhex(clean)
    except ValueError as exc:
        raise CeremonyValidationError(f"{label} is not valid hex") from exc
    if expected_bytes is not None and len(raw) != expected_bytes:
        raise CeremonyValidationError(f"{label} must be {expected_bytes} bytes")
    if all(b == 0 for b in raw):
        raise CeremonyValidationError(f"{label} must not be all-zero")
    return clean.lower()


def validate_operator_record(record: Any) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise CeremonyValidationError("operator record must be a JSON object")
    leaked = _contains_forbidden_key(record)
    if leaked is not None:
        raise CeremonyValidationError(f"secret material field `{leaked}` refused")

    validator_hex = _normalize_hex(record.get("validator"), "validator", expected_bytes=32)
    reg = record.get("registration")
    if not isinstance(reg, dict):
        raise CeremonyValidationError("missing `registration` consensus key bundle")
    vrf_hex = _normalize_hex(reg.get("vrf_public_key"), "vrf_public_key", expected_bytes=32)
    bls_hex = _normalize_hex(reg.get("bls_public_key"), "bls_public_key", expected_bytes=48)
    pop_hex = _normalize_hex(
        reg.get("bls_proof_of_possession"), "bls_proof_of_possession", expected_bytes=96
    )
    pq_hex = _normalize_hex(reg.get("pq_public_key"), "pq_public_key")
    if len(bytes.fromhex(pq_hex)) < 1952:
        raise CeremonyValidationError("pq_public_key is shorter than ML-DSA-65 public key")

    return {
        "validator": validator_hex,
        "registration": {
            "vrf_public_key": vrf_hex,
            "bls_public_key": bls_hex,
            "bls_proof_of_possession": pop_hex,
            "pq_public_key": pq_hex,
        },
    }


def assemble_rehearsal_genesis(
    records_dir: Path,
    template_path: Path,
    min_validators: int = MIN_REHEARSAL_VALIDATORS,
) -> tuple[dict[str, Any], str]:
    if not records_dir.is_dir():
        raise CeremonyValidationError(f"records directory does not exist: {records_dir}")
    files = sorted(p for p in records_dir.iterdir() if p.is_file() and p.suffix == ".json")
    if len(files) < min_validators:
        raise CeremonyValidationError(
            f"need at least {min_validators} operator records, found {len(files)}"
        )

    validated: list[dict[str, Any]] = []
    seen_validators: set[str] = set()
    seen_vrf: set[str] = set()
    for file_path in files:
        raw = json.loads(file_path.read_text(encoding="utf-8"))
        cleaned = validate_operator_record(raw)
        val = cleaned["validator"]
        vrf = cleaned["registration"]["vrf_public_key"]
        if val in seen_validators:
            raise CeremonyValidationError(f"duplicate validator address: {val}")
        if vrf in seen_vrf:
            raise CeremonyValidationError(f"duplicate VRF key: {vrf}")
        seen_validators.add(val)
        seen_vrf.add(vrf)
        validated.append(cleaned)

    validated.sort(key=lambda item: item["validator"])
    template = json.loads(template_path.read_text(encoding="utf-8"))
    tok = template["bud_tokenomics"]
    buckets = [
        ("51" * 32, int(tok["community"])),
        ("52" * 32, int(tok["liquidity"])),
        ("53" * 32, int(tok["ecosystem"])),
        ("54" * 32, int(tok["team"])),
        ("55" * 32, int(tok["burn_reserve"])),
    ]
    if sum(amount for _, amount in buckets) != BUD_MAX_SUPPLY:
        raise CeremonyValidationError("tokenomics buckets do not sum to 100,000,000 BUD")

    out = dict(template)
    out["allocations"] = [[addr, amount] for addr, amount in buckets]
    out["validators"] = [item["validator"] for item in validated]
    out["ceremony_status"] = "rehearsal_verified"

    canonical_bytes = json.dumps(out, indent=2, sort_keys=False).encode("utf-8") + b"\n"
    digest = hashlib.sha256(canonical_bytes).hexdigest()
    return out, digest


def main() -> int:
    parser = argparse.ArgumentParser(description="Assemble WP-46 rehearsal genesis")
    parser.add_argument("--operators", type=Path, required=True)
    parser.add_argument(
        "--template", type=Path, default=Path("config/testnet-genesis.json")
    )
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()

    genesis_doc, digest = assemble_rehearsal_genesis(args.operators, args.template)
    rendered = json.dumps(genesis_doc, indent=2) + "\n"
    args.out.write_text(rendered, encoding="utf-8")
    print(f"rehearsal_genesis_sha256={digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
