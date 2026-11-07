#!/usr/bin/env python3
"""Validate public validator records and assemble the WP-46 rehearsal genesis."""

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


BLS_SCHEME = "BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_POP_"
PUBLIC_KEY_LENGTHS = {
    "vrf_public_key": 32,
    "bls_public_key": 96,
    "pop_signature": 48,
    "pq_public_key": 1952,
}
TEMPLATE_FIELDS = (
    "chain_id",
    "allocations",
    "block_reward",
    "base_fee",
    "gas_schedule",
    "timestamp",
    "bud_tokenomics",
    "pq_scheme",
)
MIN_FULL_VALIDATORS = 8
MAX_RECORD_BYTES = 64 * 1024


class Refusal(Exception):
    """An invalid rehearsal input or output that must not be published."""


def refuse(message):
    raise Refusal(message)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field {key!r}")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError(f"non-JSON numeric constant {value!r}")


def load_json(path, label, max_bytes=None):
    try:
        if max_bytes is not None and path.stat().st_size > max_bytes:
            refuse(f"{label} exceeds {max_bytes} bytes")
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except Refusal:
        raise
    except (OSError, UnicodeError, ValueError) as error:
        refuse(f"cannot read {label} as strict JSON: {error}")


def is_sensitive_field(name):
    normalized = "".join(character.lower() for character in name if character.isalnum())
    return any(token in normalized for token in ("private", "secret", "mnemonic", "seed"))


def check_fields(value, required, optional, label):
    if not isinstance(value, dict):
        refuse(f"{label} must be a JSON object")
    missing = required - value.keys()
    if missing:
        refuse(f"{label} is missing required public fields: {', '.join(sorted(missing))}")
    unexpected = value.keys() - required - optional
    if unexpected:
        if any(is_sensitive_field(name) for name in unexpected):
            refuse(f"{label} contains a private or secret field")
        if "class" in unexpected:
            refuse(
                f"{label} is not a `bud validator init` record; Full is derived from "
                "complete consensus keys, not a class label"
            )
        refuse(f"{label} has unsupported fields: {', '.join(sorted(unexpected))}")


def normalize_address(value, label):
    if not isinstance(value, str):
        refuse(f"{label}.validator must be a 32-byte hexadecimal address")
    address = value[2:] if value.startswith(("0x", "0X")) else value
    if re.fullmatch(r"[0-9a-fA-F]{64}", address) is None:
        refuse(f"{label}.validator must be a 32-byte hexadecimal address")
    address = address.lower()
    if address == "0" * 64:
        refuse(f"{label}.validator must not be the zero address")
    return address


def public_bytes(value, field, label):
    expected = PUBLIC_KEY_LENGTHS[field]
    if (
        not isinstance(value, list)
        or len(value) != expected
        or any(type(byte) is not int or byte < 0 or byte > 255 for byte in value)
    ):
        refuse(f"{label}.{field} must be a {expected}-byte public value")
    return bytes(value)


def validate_template(path):
    template = load_json(path, "rehearsal template", MAX_RECORD_BYTES)
    if not isinstance(template, dict):
        refuse("rehearsal template must be a JSON object")
    if template.get("chain_id") != 45261:
        refuse("rehearsal template must use testnet chain id 45261")
    if template.get("validators") != [] or template.get("validator_consensus_keys", []) != []:
        refuse("rehearsal template must not contain validators or consensus keys")
    if template.get("allocations") != []:
        refuse("rehearsal template must not contain extra allocations")
    timestamp = template.get("timestamp")
    if type(timestamp) is not int or timestamp < 0:
        refuse("rehearsal template must contain a non-negative integer timestamp")
    if template.get("pq_scheme") != "ml-dsa-65":
        refuse("rehearsal template must pin the testnet PQ scheme to ml-dsa-65")
    for field in ("gas_schedule", "bud_tokenomics"):
        if not isinstance(template.get(field), dict):
            refuse(f"rehearsal template must contain {field}")
    return template


def stage_public_records(registrations_dir, staging_dir):
    try:
        paths = sorted(registrations_dir.glob("*.json"), key=lambda path: path.name)
    except OSError as error:
        refuse(f"cannot list registration directory: {error}")
    if not paths:
        refuse(f"no registration files in {registrations_dir}")

    records = []
    seen_addresses = set()
    seen_keys = {field: set() for field in ("vrf_public_key", "bls_public_key", "pq_public_key")}
    for path in paths:
        if path.is_symlink() or not path.is_file():
            refuse(f"registration entry {path.name!r} is not a regular file")
        label = f"registration {path.name!r}"
        record = load_json(path, label, MAX_RECORD_BYTES)
        check_fields(record, {"validator", "registration"}, {"moniker"}, label)
        if "moniker" in record and not isinstance(record["moniker"], str):
            refuse(f"{label}.moniker must be a string")

        address = normalize_address(record["validator"], label)
        if address in seen_addresses:
            refuse(f"duplicate validator address {address}")
        seen_addresses.add(address)

        registration = record["registration"]
        registration_fields = set(PUBLIC_KEY_LENGTHS) | {"scheme_id"}
        check_fields(registration, registration_fields, set(), f"{label}.registration")
        if registration["scheme_id"] != BLS_SCHEME:
            refuse(f"{label}.registration.scheme_id is not the pinned testnet BLS suite")

        public_registration = {"scheme_id": BLS_SCHEME}
        for field in PUBLIC_KEY_LENGTHS:
            key_bytes = public_bytes(registration[field], field, f"{label}.registration")
            if field in seen_keys:
                if key_bytes in seen_keys[field]:
                    refuse(f"duplicate {field} across validator records")
                seen_keys[field].add(key_bytes)
            public_registration[field] = list(key_bytes)

        # OperatorRecord's moniker is display-only and is not part of genesis.
        # Omitting it ensures arbitrary operator metadata is never published.
        records.append({"validator": address, "registration": public_registration})

    if len(records) < MIN_FULL_VALIDATORS:
        refuse(
            f"needs at least {MIN_FULL_VALIDATORS} complete Full validator public records, "
            f"got {len(records)}"
        )

    staging_dir.mkdir(mode=0o700, parents=True, exist_ok=False)
    for index, record in enumerate(records):
        destination = staging_dir / f"operator-{index:04d}.json"
        with destination.open("x", encoding="utf-8") as output:
            json.dump(record, output, sort_keys=True, separators=(",", ":"))
            output.write("\n")
    return {record["validator"]: record["registration"] for record in records}


def reserved_address(tag):
    return f"b0d0{tag:02x}" + "0" * 58


def run_genesis_assembler(staging_dir, output_path, timestamp):
    binary = os.environ.get("BUD_BIN", "bud")
    if "/" in binary:
        if not Path(binary).is_file() or not os.access(binary, os.X_OK):
            refuse(f"bud genesis assembler is not executable: {binary}")
    else:
        resolved = shutil.which(binary)
        if resolved is None:
            refuse("bud genesis assembler not found; build it or set BUD_BIN")
        binary = resolved

    arguments = [
        binary,
        "genesis",
        "assemble",
        "--network",
        "testnet",
        "--operators",
        str(staging_dir),
        "--community",
        reserved_address(1),
        "--liquidity",
        reserved_address(2),
        "--ecosystem",
        reserved_address(3),
        "--team",
        reserved_address(4),
        "--burn-reserve",
        reserved_address(5),
        "--timestamp-ms",
        str(timestamp),
        "--out",
        str(output_path),
    ]
    try:
        result = subprocess.run(arguments, check=False)
    except OSError as error:
        refuse(f"cannot start the bud genesis assembler: {error}")
    return result.returncode


def reject_secret_fields(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if is_sensitive_field(key):
                refuse("assembled genesis contains a private or secret field")
            reject_secret_fields(child)
    elif isinstance(value, list):
        for child in value:
            reject_secret_fields(child)


def finalize_genesis(template, assembled_path, expected_records):
    expected_count = len(expected_records)
    genesis = load_json(assembled_path, "assembled genesis")
    if not isinstance(genesis, dict):
        refuse("assembled genesis must be a JSON object")
    for field in TEMPLATE_FIELDS:
        if field not in template or genesis.get(field) != template[field]:
            refuse(f"assembled testnet genesis differs from rehearsal template field {field!r}")

    validators = genesis.get("validators")
    keys = genesis.get("validator_consensus_keys")
    if not isinstance(validators, list) or len(validators) != expected_count:
        refuse("assembled genesis validator count differs from the validated records")
    if not isinstance(keys, list) or len(keys) != expected_count:
        refuse("assembled genesis must include one public consensus-key record per validator")
    validators = [normalize_address(address, "assembled genesis") for address in validators]
    if len(set(validators)) != len(validators):
        refuse("assembled genesis contains duplicate validators")

    keys_by_validator = {}
    for entry in keys:
        if not isinstance(entry, dict) or set(entry) != {"validator", "registration"}:
            refuse("assembled genesis contains a malformed consensus-key record")
        address = normalize_address(entry["validator"], "assembled consensus-key record")
        registration = entry["registration"]
        if address in keys_by_validator:
            refuse("assembled genesis contains duplicate consensus-key registrations")
        if not isinstance(registration, dict) or set(registration) != {
            "scheme_id",
            "vrf_public_key",
            "bls_public_key",
            "pop_signature",
            "pq_public_key",
        }:
            refuse("assembled genesis contains an incomplete consensus-key registration")
        if registration["scheme_id"] != BLS_SCHEME:
            refuse("assembled genesis contains an unexpected BLS scheme")
        for field in PUBLIC_KEY_LENGTHS:
            public_bytes(registration[field], field, "assembled consensus-key record")
        keys_by_validator[address] = registration
    if set(keys_by_validator) != set(validators):
        refuse("assembled genesis validator addresses and consensus-key records disagree")
    if keys_by_validator != expected_records:
        refuse("assembled genesis does not match the validated public operator records")

    expected_addresses = {
        name: reserved_address(tag)
        for name, tag in (
            ("community", 1),
            ("liquidity", 2),
            ("ecosystem", 3),
            ("team", 4),
            ("burn_reserve", 5),
        )
    }
    if genesis.get("tokenomics_addresses") != expected_addresses:
        refuse("assembled genesis does not use the reserved rehearsal tokenomics destinations")
    if genesis.get("reward_pool") != {"enabled": True}:
        refuse("assembled testnet genesis does not enable the testnet reward pool")

    reject_secret_fields(genesis)
    genesis["ceremony_status"] = "rehearsal"
    genesis["ceremony_note"] = (
        "Rehearsal genesis produced by ops/rehearsal/genesis_rehearsal.sh from "
        f"{expected_count} complete Full validator public records. Throwaway network; "
        "chain id 45261 (KR-34)."
    )
    return (json.dumps(genesis, indent=2, sort_keys=True) + "\n").encode("utf-8")


def publish(output_dir, genesis_bytes):
    digest = hashlib.sha256(genesis_bytes).hexdigest()
    digest_bytes = f"{digest}  rehearsal-genesis.json\n".encode("ascii")
    output_dir.mkdir(parents=True, exist_ok=True)
    temporary_paths = []
    try:
        for prefix, content in (
            (".rehearsal-genesis.", genesis_bytes),
            (".rehearsal-digest.", digest_bytes),
        ):
            with tempfile.NamedTemporaryFile(
                mode="wb", prefix=prefix, dir=output_dir, delete=False
            ) as output:
                temporary_paths.append(Path(output.name))
                output.write(content)
                output.flush()
                os.fchmod(output.fileno(), 0o644)
                os.fsync(output.fileno())
        # A pair of independent renames is not atomic. Remove any old digest
        # before replacing the genesis so an interrupted publish cannot leave
        # a stale digest next to the new file. Readers must verify the digest.
        (output_dir / "rehearsal-genesis.sha256").unlink(missing_ok=True)
        os.replace(temporary_paths[0], output_dir / "rehearsal-genesis.json")
        os.replace(temporary_paths[1], output_dir / "rehearsal-genesis.sha256")
    finally:
        for path in temporary_paths:
            path.unlink(missing_ok=True)
    return digest


def main(argv):
    if len(argv) not in (1, 2):
        print("usage: genesis_rehearsal.sh <registrations-dir> [out-dir]", file=sys.stderr)
        return 2
    registrations_dir = Path(argv[0]).resolve()
    output_dir = Path(argv[1] if len(argv) == 2 else "docs/rehearsal").resolve()
    template_path = Path("config/rehearsal-genesis.json")

    if not registrations_dir.is_dir():
        print(f"registration directory does not exist: {registrations_dir}", file=sys.stderr)
        return 2
    if not template_path.is_file():
        print(f"rehearsal genesis template is missing: {template_path}", file=sys.stderr)
        return 2
    if output_dir == registrations_dir or registrations_dir in output_dir.parents:
        print("genesis rehearsal refused: the output directory must not be inside the registrations directory", file=sys.stderr)
        return 1

    try:
        template = validate_template(template_path)
        with tempfile.TemporaryDirectory(prefix="budlum-rehearsal-") as temporary:
            temporary_dir = Path(temporary)
            staging_dir = temporary_dir / "operators"
            assembled_path = temporary_dir / "assembled-genesis.json"
            records = stage_public_records(registrations_dir, staging_dir)
            record_count = len(records)
            print(
                f"preflight accepted {record_count} complete public operator records; "
                "the node CLI will validate their proofs",
                file=sys.stderr,
            )
            assembler_status = run_genesis_assembler(
                staging_dir, assembled_path, template["timestamp"]
            )
            if assembler_status != 0:
                return assembler_status
            genesis_bytes = finalize_genesis(template, assembled_path, records)
        digest = publish(output_dir, genesis_bytes)
    except Refusal as error:
        print(f"genesis rehearsal refused: {error}", file=sys.stderr)
        return 1
    except OSError as error:
        print(f"genesis rehearsal failed: {error}", file=sys.stderr)
        return 1

    print(
        f"rehearsal genesis written to {output_dir / 'rehearsal-genesis.json'} "
        f"({record_count} Full validators; SHA-256 {digest})"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
