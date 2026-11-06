#!/usr/bin/env bash
# WP-46 ceremony rehearsal (directive 12.5, 17.2.2, 15.8 WP-16).
#
# Build a rehearsal genesis from at least 8 distinct Full validator public
# registration records and publish the genesis, its digest and an audit report.
#
#   genesis_rehearsal.sh <registrations-dir> [out-dir]
#
# The private keys stay on the operator's machine. This script is fail-closed:
# an empty Full claim, a repeated record, a private field or an unparsable
# record refuses the ceremony and writes nothing. Record filenames are read
# through pathlib; they are never interpolated into Python source.
set -euo pipefail

REG_DIR="${1:?usage: genesis_rehearsal.sh <registrations-dir> [out-dir]}"
OUT_DIR="${2:-docs/rehearsal}"
MIN_FULL=8

python3 - "$REG_DIR" "$OUT_DIR" "$MIN_FULL" <<'PY'
"""One process decides everything, so no partial state can be published."""
import hashlib
import json
import pathlib
import sys

reg_dir = pathlib.Path(sys.argv[1])
out_dir = pathlib.Path(sys.argv[2])
min_full = int(sys.argv[3])

# Directive 7.3: the Full-class public registration record. Only these fields
# may be published. Every other key is private material or untrusted data.
PUBLIC_FIELDS = frozenset(
    {
        "class",
        "owner",
        "operator_key",
        "bls_key",
        "bls_pop",
        "pq_vote_key",
        "leader_commitment",
        "custody_quota_bytes",
        "peer_id",
        "relay_offer",
        "gateway_offer",
    }
)
REQUIRED_FIELDS = (
    "owner",
    "operator_key",
    "bls_key",
    "bls_pop",
    "pq_vote_key",
    "leader_commitment",
    "custody_quota_bytes",
    "peer_id",
)
PRIVATE_WORDS = (
    "private",
    "secret",
    "seed",
    "mnemonic",
    "passphrase",
    "password",
)


def refuse(reason):
    print(f"ceremony rehearsal refused: {reason}", file=sys.stderr)
    raise SystemExit(1)


if not reg_dir.is_dir():
    refuse(f"{reg_dir} is not a registrations directory")

records = []
for path in sorted(reg_dir.glob("*.json")):
    try:
        payload = json.loads(path.read_text())
    except (OSError, ValueError) as exc:
        refuse(f"{path.name} is not a readable JSON record: {exc}")
    if not isinstance(payload, dict):
        refuse(f"{path.name} is not a JSON object")
    if payload.get("class") != "Full":
        continue
    unknown = sorted(set(payload) - PUBLIC_FIELDS)
    if unknown:
        refuse(f"{path.name} carries non-public field(s): {', '.join(unknown)}")
    for key in payload:
        if any(word in key.lower() for word in PRIVATE_WORDS):
            refuse(f"{path.name} carries a private field: {key}")
    missing = [k for k in REQUIRED_FIELDS if k not in payload]
    if missing:
        refuse(f"{path.name} is an empty Full claim; missing: {', '.join(missing)}")
    for key in REQUIRED_FIELDS:
        if key == "custody_quota_bytes":
            if not isinstance(payload[key], int) or isinstance(payload[key], bool) or payload[key] <= 0:
                refuse(f"{path.name} has no positive custody_quota_bytes")
        elif not isinstance(payload[key], str) or not payload[key].strip():
            refuse(f"{path.name} has an empty {key}")
    records.append(payload)

if len(records) < min_full:
    refuse(f"at least {min_full} Full validators are needed, got {len(records)}")

# A committee is a set of distinct operators. Three identities are checked:
# owner, peer_id and the canonical public record itself.
def public_digest(record):
    canonical = json.dumps(record, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


for label, key in (
    ("owner", lambda r: r["owner"]),
    ("peer_id", lambda r: r["peer_id"]),
    ("public record", public_digest),
):
    values = [key(r) for r in records]
    if len(set(values)) != len(values):
        refuse(f"duplicate {label} among the Full validator records")

public = [
    {k: r[k] for k in sorted(PUBLIC_FIELDS) if k in r} for r in records
]
public.sort(key=public_digest)

try:
    template = json.loads(pathlib.Path("config/rehearsal-genesis.json").read_text())
except (OSError, ValueError) as exc:
    refuse(f"cannot read the rehearsal template: {exc}")
if not isinstance(template, dict):
    refuse("the rehearsal template is not a JSON object")
for key in template:
    if any(word in key.lower() for word in PRIVATE_WORDS):
        refuse(f"the template carries a private field: {key}")

template["validators"] = public
template["ceremony_status"] = "rehearsal"
template["ceremony_note"] = (
    "Rehearsal genesis produced by ops/rehearsal/genesis_rehearsal.sh from "
    f"{len(public)} distinct Full validator public records. Throwaway network; "
    "chain id 45261 (KR-34). No private material is published."
)
genesis_bytes = (
    json.dumps(template, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
).encode()
digest = hashlib.sha256(genesis_bytes).hexdigest()
audit = {
    "ceremony": "rehearsal",
    "validator_count": len(public),
    "validator_public_digests": [public_digest(r) for r in public],
    "genesis_sha256": digest,
    "published_fields": sorted(PUBLIC_FIELDS),
    "refused_private_material": True,
}
audit_bytes = (
    json.dumps(audit, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
).encode()

# Publish only after every check passed, and never leave a half-written pair.
out_dir.mkdir(parents=True, exist_ok=True)
for name, body in (
    ("rehearsal-genesis.json", genesis_bytes),
    ("rehearsal-genesis.sha256", f"{digest}  rehearsal-genesis.json\n".encode()),
    ("rehearsal-ceremony-audit.json", audit_bytes),
):
    target = out_dir / name
    staged = out_dir / (name + ".tmp")
    staged.write_bytes(body)
    staged.replace(target)

print(
    f"rehearsal genesis written to {out_dir}/rehearsal-genesis.json "
    f"({len(public)} distinct Full validators, sha256 {digest})"
)
PY
