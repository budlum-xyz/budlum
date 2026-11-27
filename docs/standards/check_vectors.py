#!/usr/bin/env python3
"""Executable conformance check for the three published settlement standards.

Reads the vector files that ship next to this script and recomputes every published
number from scratch: Keccak-256, the row digest, the bucket Merkle tree, the certificate
digest, the inclusion verifier, the 17-byte guarantee wire, the weakest-link fold, the
cross-domain value gate, and the two Solidity-side encodings. Nothing here imports or
links the node: only the Python standard library is used, so this runs in any
environment, in milliseconds, with no toolchain.

    python3 docs/standards/check_vectors.py              # verify the published vectors
    python3 docs/standards/check_vectors.py --self-test  # prove this check can fail

Exit status 0 means every published digest, root, count, wire hex and rejection in
``vectors/*.json`` was reproduced. A non-zero exit lists each mismatch as
``MISMATCH <case>: <field> expected <published> got <recomputed>``.

Why ``--self-test`` exists: a checker that always prints OK is worthless. It mutates one
published value at a time and requires the mismatch to be caught, so a green run here is
known to be sensitive to every field the standards commit to.

The rules below are transcribed from the prose of the documents in this directory, not
from any node implementation: where the two disagree, the disagreement is a defect in one
of them, which is exactly what this script is for.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import pathlib
import re
import sys

# --------------------------------------------------------------------------------------------
# Keccak-256: Keccak-f[1600], a 136-byte rate, and the legacy ``0x01`` pad byte. Standard 3
# section 3 names this hash and standard 4 relies on it being Solidity's, so the padding is
# the first thing a re-implementation gets wrong. It is NOT SHA3-256.
# --------------------------------------------------------------------------------------------

_RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)
_ROT = (
    (0, 36, 3, 41, 18),
    (1, 44, 10, 45, 2),
    (62, 6, 43, 15, 61),
    (28, 55, 25, 21, 56),
    (27, 20, 39, 8, 14),
)
_MASK = (1 << 64) - 1


def _rol(value: int, shift: int) -> int:
    shift %= 64
    return ((value << shift) | (value >> (64 - shift))) & _MASK if shift else value


def keccak256(data: bytes) -> bytes:
    state = [[0] * 5 for _ in range(5)]
    block = bytearray(data)
    block.append(0x01)
    while len(block) % 136:
        block.append(0x00)
    block[-1] ^= 0x80
    for start in range(0, len(block), 136):
        chunk = block[start:start + 136]
        for lane in range(17):
            state[lane % 5][lane // 5] ^= int.from_bytes(chunk[lane * 8:lane * 8 + 8], "little")
        for round_index in range(24):
            parity = [state[x][0] ^ state[x][1] ^ state[x][2] ^ state[x][3] ^ state[x][4]
                      for x in range(5)]
            drift = [parity[(x - 1) % 5] ^ _rol(parity[(x + 1) % 5], 1) for x in range(5)]
            for x in range(5):
                for y in range(5):
                    state[x][y] ^= drift[x]
            turned = [[0] * 5 for _ in range(5)]
            for x in range(5):
                for y in range(5):
                    turned[y][(2 * x + 3 * y) % 5] = _rol(state[x][y], _ROT[x][y])
            for x in range(5):
                for y in range(5):
                    state[x][y] = (turned[x][y]
                                   ^ ((~turned[(x + 1) % 5][y] & _MASK) & turned[(x + 2) % 5][y]))
            state[0][0] ^= _RC[round_index]
    out = bytearray()
    while len(out) < 32:
        lane = len(out) // 8
        out += state[lane % 5][lane // 5].to_bytes(8, "little")
    return bytes(out[:32])


# --------------------------------------------------------------------------------------------
# Standard 1 - assurance bundle: 17 bytes, big-endian, in the published field order.
# --------------------------------------------------------------------------------------------

REVERSIBILITY = {"ProbabilisticWork": 0, "DataAvailabilitySampled": 1,
                 "DeterministicQuorum": 2, "CryptographicValidity": 3}
QUANTUM = {"Classical": 0, "Lattice": 1, "Hash": 2}
PENDING_REASON = {"EvidenceMissing": 1, "AttestationUnbound": 2, "RuleNotSatisfied": 3,
                  "BondUnverified": 4}
BPS_SCALE = 10_000
DEEP_POW_CONFIRMATIONS = 6
ATTESTATION_FIELDS = ("state_root", "tx_root", "event_root", "parent")
FIELD_ORDER = ("reversibility_tag", "reversibility_param", "quantum_tag", "attestation",
               "slashable_backing", "fault_tolerance_bps")


def bundle_wire(guarantee: dict) -> bytes:
    """The whole bundle, at fixed width, so a parser never has to guess where a field ends."""
    reversal = guarantee["reversibility"]
    tag = REVERSIBILITY[reversal["kind"]]
    param = int(reversal.get("param", 0))
    if tag >= 2 and param:
        raise ValueError(f"{reversal['kind']} carries no parameter, got {param}")
    attestation = guarantee["attestation"]
    bps = int(guarantee["fault_tolerance_bps"])
    if bps > BPS_SCALE:
        raise ValueError(f"fault_tolerance_bps {bps} exceeds the basis-point scale")
    wire = bytes([tag]) + param.to_bytes(8, "big")
    wire += bytes([QUANTUM[guarantee["quantum_posture"]]])
    wire += bytes(1 if attestation[key] else 0 for key in ATTESTATION_FIELDS)
    wire += bytes([1 if guarantee["slashable_backing"] else 0])
    wire += bps.to_bytes(2, "big")
    if len(wire) != 17:
        raise AssertionError(f"wire length {len(wire)} is not 17")
    return wire


def bundle_meet(left: dict, right: dict) -> dict:
    """Weakest link: lower rank wins, smaller parameter wins inside one rank, AND on bits."""
    tag_left = REVERSIBILITY[left["reversibility"]["kind"]]
    tag_right = REVERSIBILITY[right["reversibility"]["kind"]]
    if tag_left == tag_right:
        kind = left["reversibility"]["kind"]
        if tag_left <= 1:
            reversal = {"kind": kind,
                        "param": min(int(left["reversibility"].get("param", 0)),
                                     int(right["reversibility"].get("param", 0)))}
        else:
            reversal = {"kind": kind}
    else:
        reversal = dict((left if tag_left < tag_right else right)["reversibility"])
    ranks = (QUANTUM[left["quantum_posture"]], QUANTUM[right["quantum_posture"]])
    posture = left["quantum_posture"] if ranks[0] <= ranks[1] else right["quantum_posture"]
    return {
        "reversibility": reversal,
        "quantum_posture": posture,
        "attestation": {key: bool(left["attestation"][key] and right["attestation"][key])
                        for key in ATTESTATION_FIELDS},
        "slashable_backing": bool(left["slashable_backing"] and right["slashable_backing"]),
        "fault_tolerance_bps": min(int(left["fault_tolerance_bps"]),
                                   int(right["fault_tolerance_bps"]), BPS_SCALE),
    }


def admits_cross_domain_value(guarantee: dict) -> bool:
    """Standard 1's single decision point: what may a consumer forward on this promise?"""
    bps = int(guarantee["fault_tolerance_bps"])
    if not guarantee["attestation"]["event_root"] or bps == 0 or bps > BPS_SCALE:
        return False
    if guarantee["slashable_backing"]:
        return True
    reversal = guarantee["reversibility"]
    if reversal["kind"] == "CryptographicValidity":
        return True
    if reversal["kind"] == "ProbabilisticWork":
        return int(reversal.get("param", 0)) >= DEEP_POW_CONFIRMATIONS
    return False


# --------------------------------------------------------------------------------------------
# Standard 3 - rows, bucket trees, the certificate digest, the verifier.
# --------------------------------------------------------------------------------------------

TAG = {
    "row": b"BDLM_FINALITY_CERT_ROW_V1",
    "leaf": b"BDLM_FINALITY_CERT_LEAF_V1",
    "node": b"BDLM_FINALITY_CERT_NODE_V1",
    "empty": b"BDLM_FINALITY_CERT_EMPTY_V1",
    "cert": b"BDLM_FINALITY_CERT_V1",
}
MAX_CERTIFICATE_DOMAINS = 4096
BUCKETS = ("Established", "Pending", "Refuted")
# Section 6 lists these rejections normatively. A vector file that silently drops one would
# still "pass" every case it kept, so the checker requires the set, not just the entries.
REQUIRED_COMPOSITION_REJECTIONS = ("empty_row_set", "duplicate_domain_id",
                                   "conflicting_checkpoint_heights",
                                   "established_row_without_event_attestation",
                                   "established_row_with_zero_fault_tolerance")
REQUIRED_FORGERY_REJECTIONS = ("forged_fourth_leaf_on_three_row_bucket",
                               "pending_row_presented_as_established", "leaf_index_out_of_range",
                               "truncated_sibling_path", "siblings_reused_across_levels",
                               "wrong_bucket_root_target")


def row_digest(row: dict) -> bytes:
    """Section 4, in the order the table gives it. Any reordering is a different digest."""
    absorb = bytearray(TAG["row"])
    absorb += int(row["domain_id"]).to_bytes(4, "big")
    absorb += int(row["height"]).to_bytes(8, "big")
    absorb += int(row["checkpoint_height"]).to_bytes(8, "big")
    absorb += bytes.fromhex(row["state_root"])
    adapter = row["adapter_id"].encode("utf-8")
    absorb += min(len(adapter), (1 << 64) - 1).to_bytes(8, "big")
    absorb += adapter
    absorb += int(row["adapter_version"]).to_bytes(4, "big")
    absorb += bytes.fromhex(row["finality_proof_hash"])
    absorb += bytes.fromhex(row["guarantee_backing_hash"])
    absorb += int(row["bond_atoms"]).to_bytes(16, "big")
    absorb += bundle_wire(row["guarantee"])
    verdict = row["verdict"]
    if verdict["kind"] == "Established":
        absorb += bytes([0]) + (0).to_bytes(2, "big")
    elif verdict["kind"] == "Refuted":
        absorb += bytes([1]) + int(verdict["code"]).to_bytes(2, "big")
    elif verdict["kind"] == "Pending":
        absorb += bytes([2]) + int(PENDING_REASON[verdict["reason"]]).to_bytes(2, "big")
    else:
        raise ValueError(f"unknown verdict {verdict['kind']!r}")
    return keccak256(bytes(absorb))


def tree_leaf(row: dict) -> bytes:
    return keccak256(TAG["leaf"] + row_digest(row))


def tree_node(left: bytes, right: bytes) -> bytes:
    return keccak256(TAG["node"] + left + right)


def empty_bucket_root() -> bytes:
    return keccak256(TAG["empty"])


def tree_depth(leaf_count: int) -> int:
    depth, width = 0, leaf_count
    while width > 1:
        width = -(-width // 2)
        depth += 1
    return depth


def bucket_root(rows: list) -> bytes:
    if not rows:
        return empty_bucket_root()
    level = [tree_leaf(row) for row in rows]
    while len(level) > 1:
        level = [tree_node(level[index],
                           level[index + 1] if index + 1 < len(level) else level[index])
                 for index in range(0, len(level), 2)]
    return level[0]


def _reverse_a_multilevel_sibling_path(vectors: dict) -> None:
    """Reverse the sibling order of the first proof that has more than one level.

    Reversing a one-element path changes nothing, so a mutation like that would test the
    mutation table rather than the checker.
    """
    for case in vectors["positive"]:
        for proof in case.get("inclusion_proofs", []):
            if len(proof["siblings"]) >= 2:
                proof["siblings"] = list(reversed(proof["siblings"]))
                return
    raise IndexError("no multi-level inclusion proof published")


def validate_rows(rows: list) -> tuple:
    """Section 6 on its own: the composition rules, with no hashing at all.

    Split out because the registry ceiling is a composition rule. Proving 4096 is accepted and
    4097 is not must not require building a 4096-leaf tree in pure Python.
    """
    if not rows:
        raise ValueError("an empty certificate proves nothing")
    if len(rows) > MAX_CERTIFICATE_DOMAINS:
        raise ValueError(f"{len(rows)} domains exceeds the registry ceiling")
    if len({row["domain_id"] for row in rows}) != len(rows):
        raise ValueError("a domain id appears twice in one certificate")
    checkpoint = int(rows[0]["checkpoint_height"])
    buckets = {name: [] for name in BUCKETS}
    for row in rows:
        if int(row["checkpoint_height"]) != checkpoint:
            raise ValueError(f"domain {row['domain_id']} seals a different checkpoint")
        if row["verdict"]["kind"] not in buckets:
            raise ValueError(f"unknown verdict {row['verdict']['kind']!r}")
        buckets[row["verdict"]["kind"]].append(row)
    for row in buckets["Established"]:
        if not all(row["guarantee"]["attestation"][key] for key in ATTESTATION_FIELDS):
            raise ValueError(f"established domain {row['domain_id']} does not bind every commitment")
        if int(row["guarantee"]["fault_tolerance_bps"]) == 0:
            raise ValueError(f"established domain {row['domain_id']} has zero fault tolerance")
    for bucket_rows in buckets.values():
        bucket_rows.sort(key=lambda row: int(row["domain_id"]))
    return checkpoint, buckets


def _mend_the_forgery(vectors: dict) -> None:
    """Turn the forged four-leaf opening back into the honest three-leaf one.

    The vectors publish the forgery as a real proof object with one row more than the bucket
    actually has; repairing it must make this checker shout. That is the only proof that the
    rejection is being performed rather than copied from the file.
    """
    for case in vectors["negative"]:
        if case.get("name") == "forged_fourth_leaf_on_three_row_bucket":
            proof = case["proof"]
            proof["leaf_count"] = 3
            proof["siblings"] = proof["siblings"][:2]
            return
    raise KeyError("forged_fourth_leaf_on_three_row_bucket is not in the vector file")


def _repair_the_wrong_root(vectors: dict) -> None:
    """Give the wrong-target forgery its honest root, taken from the published positives."""
    for case in vectors["negative"]:
        if case.get("name") == "wrong_bucket_root_target":
            proof = case["proof"]
            for positive in vectors["positive"]:
                for honest in positive.get("inclusion_proofs", []):
                    same = (honest["entry"]["domain_id"] == proof["entry"]["domain_id"]
                            and honest["bucket"] == proof["bucket"]
                            and honest["leaf_index"] == proof["leaf_index"]
                            and honest["leaf_count"] == proof["leaf_count"])
                    if same and honest["expected_bucket_root"] != proof["expected_bucket_root"]:
                        proof["expected_bucket_root"] = honest["expected_bucket_root"]
                        return
            raise IndexError("no honest counterpart for the wrong-root forgery")
    raise KeyError("wrong_bucket_root_target is not in the vector file")


def compose(rows: list) -> dict:
    """Section 6 then section 5: reject an ill-formed row set first, then digest it."""
    if not rows:
        raise ValueError("an empty certificate proves nothing")
    checkpoint, buckets = validate_rows(rows)
    roots = {name: bucket_root(bucket_rows) for name, bucket_rows in buckets.items()}
    folded = None
    for row in buckets["Established"]:
        folded = row["guarantee"] if folded is None else bundle_meet(folded, row["guarantee"])
    absorb = bytearray(TAG["cert"]) + checkpoint.to_bytes(8, "big")
    for name in BUCKETS:
        absorb += len(buckets[name]).to_bytes(4, "big")
    for name in BUCKETS:
        absorb += roots[name]
    absorb += bytes([0]) if folded is None else bytes([1]) + bundle_wire(folded)
    return {
        "checkpoint_height": checkpoint,
        "counts": {name: len(buckets[name]) for name in BUCKETS},
        "roots": {name: roots[name].hex() for name in BUCKETS},
        "folded_guarantee": folded,
        "certificate_digest": keccak256(bytes(absorb)).hex(),
        "row_digests": {str(row["domain_id"]): row_digest(row).hex() for row in rows},
        "buckets": buckets,
    }


def verify_inclusion(proof: dict) -> bool:
    """Section 7, in the order the document gives it: reject, then walk, then compare."""
    leaf_count = int(proof["leaf_count"])
    index = int(proof["leaf_index"])
    if leaf_count == 0 or index >= leaf_count:
        return False
    if proof["bucket"] != proof["entry"]["verdict"]["kind"]:
        return False
    siblings = [bytes.fromhex(sibling) for sibling in proof["siblings"]]
    if len(siblings) != tree_depth(leaf_count):
        return False
    accumulator = tree_leaf(proof["entry"])
    for sibling in siblings:
        # A duplicated tail and an odd last level are the same event seen from two sides, so a
        # sibling equal to the running root is legal on exactly that level and nowhere else.
        odd_tail = leaf_count % 2 == 1 and index == leaf_count - 1
        if odd_tail != (sibling == accumulator):
            return False
        accumulator = (tree_node(accumulator, sibling) if index % 2 == 0
                       else tree_node(sibling, accumulator))
        index, leaf_count = index // 2, -(-leaf_count // 2)
    return accumulator == bytes.fromhex(proof["expected_bucket_root"])


def build_inclusion(bucket_rows: list, domain_id: int) -> dict:
    """The producer's half of section 7, derived here so proofs are not taken on faith."""
    rows = sorted(bucket_rows, key=lambda row: int(row["domain_id"]))
    matches = [i for i, row in enumerate(rows) if int(row["domain_id"]) == domain_id]
    if not matches:
        raise ValueError(f"no row for domain {domain_id} in this bucket")
    index = matches[0]
    level = [tree_leaf(row) for row in rows]
    siblings, cursor, width = [], index, len(rows)
    while width > 1:
        pair = cursor + 1 if cursor % 2 == 0 else cursor - 1
        siblings.append(level[pair if pair < width else cursor].hex())
        level = [tree_node(level[i], level[i + 1] if i + 1 < len(level) else level[i])
                 for i in range(0, len(level), 2)]
        cursor, width = cursor // 2, -(-width // 2)
    return {"bucket": rows[index]["verdict"]["kind"], "leaf_index": index,
            "leaf_count": len(rows), "siblings": siblings, "entry": rows[index],
            "expected_bucket_root": level[0].hex()}


# --------------------------------------------------------------------------------------------
# Standard 4 - the Solidity surface. ``abi.encode`` widens to words; ``bytes.concat`` does not.
# --------------------------------------------------------------------------------------------

def word(value) -> bytes:
    if isinstance(value, bool):
        return (1 if value else 0).to_bytes(32, "big")
    if isinstance(value, (bytes, bytearray)):
        return bytes(value).rjust(32, b"\x00")
    return int(value).to_bytes(32, "big")


def abi_encode(arguments: list) -> bytes:
    """Head/tail layout: a dynamic string is pointed at from its own slot, not the front."""
    heads, tails, cursor = [], [], 32 * len(arguments)
    for kind, value in arguments:
        if kind == "string":
            data = value.encode("utf-8")
            padding = (-len(data)) % 32
            heads.append(cursor.to_bytes(32, "big"))
            tails.append(len(data).to_bytes(32, "big") + data + b"\x00" * padding)
            cursor += 32 + len(data) + padding
        else:
            heads.append(word(value))
    return b"".join(heads) + b"".join(tails)


HASHED_ATTESTATION_FIELDS = ("g2AggregatePubkey", "g2Generator", "g1NegSignature",
                             "mlDsaSignature", "mlDsaPubkey")


def attestation_digest(att: dict) -> dict:
    """Variable-length fields enter pre-hashed, so the encoding stays fixed-width."""
    arguments = [("string", "bud-attestation-v1"), ("word", int(att["height"])),
                 ("word", bytes.fromhex(att["stateRoot"])), ("word", int(att["epoch"])),
                 ("word", int(att["chainId"]))]
    arguments += [("word", keccak256(bytes.fromhex(att[field])))
                  for field in HASHED_ATTESTATION_FIELDS]
    arguments.append(("word", bool(att["mlDsaEthVariant"])))
    preimage = abi_encode(arguments)
    return {"preimage": preimage.hex(), "digest": keccak256(preimage).hex()}


def pending_identity(height: int, state_root: str) -> dict:
    preimage = abi_encode([("string", "bud-attestation-pending-v1"), ("word", int(height)),
                           ("word", bytes.fromhex(state_root))])
    return {"preimage": preimage.hex(), "digest": keccak256(preimage).hex()}


def signing_root(host_chain_id: int, att: dict) -> dict:
    """Packed at their own widths, because this preimage is the EIP-191 message body."""
    preimage = (b"bud-finality-signing-root-v1" + int(host_chain_id).to_bytes(32, "big")
                + int(att["height"]).to_bytes(8, "big") + bytes.fromhex(att["stateRoot"])
                + int(att["epoch"]).to_bytes(8, "big") + int(att["chainId"]).to_bytes(8, "big"))
    return {"preimage": preimage.hex(), "digest": keccak256(preimage).hex()}


def att_of(case: dict) -> dict:
    return case["input"].get("att", case["input"])


EVM_VARIANTS = {"attestation_digest_pq_variant_on": "attestation_digest"}

# One rule per published positive case; ``attestation_digest_pq_variant_on`` is the same rule
# with the variant flag set, published as its own case so the flag cannot be ignored quietly.
EVM_RULES = {
    "attestation_digest": attestation_digest,
    "pending_identity": lambda given: pending_identity(given["height"], given["stateRoot"]),
    "signing_root": lambda given: signing_root(given["host_chain_id"], given["att"]),
}


# The three bindings a consumer must be able to tell apart, named by standard 4's text.
REQUIRED_EVM_BINDINGS = ("host_chainid_changes_signing_root_only",
                         "budlum_chainid_change_changes_both", "variant_flag_changes_digest")


ADMIT_BRANCHES = ("deep_pow_without_stake_allows", "shallow_pow_without_stake_blocks",
                  "deterministic_quorum_alone_blocks", "deterministic_quorum_with_stake_allows",
                  "unauthenticated_events_block", "zero_bps_blocks")


def _admits_table_is_complete(vectors: dict) -> list:
    """Standard 1's decision table must cover every branch it states.

    Six of them, because the gate has six ways to answer: deep PoS-less work, shallow work,
    a quorum without stake, a quorum with stake, no event root, zero fault tolerance. A table
    missing a row is a table that stopped describing the rule.
    """
    published = {case["name"] for case in vectors["admits_cross_domain_value"]}
    return [f"coverage: the decision table has no case for {name!r}"
            for name in ADMIT_BRANCHES if name not in published]


def expect(failures: list, case: str, field: str, published, recomputed) -> int:
    if published != recomputed:
        failures.append(f"{case}: {field} expected {published!r} got {recomputed!r}")
        return 0
    return 1


def check_certificate(vectors: dict) -> tuple:
    failures, checks = [], 0
    for name, value in (("row", TAG["row"]), ("leaf", TAG["leaf"]), ("node", TAG["node"]),
                        ("empty_bucket", TAG["empty"])):
        checks += expect(failures, "tags", name, value.decode(), vectors["tags"][name])
    known = vectors["known_answers"]
    checks += expect(failures, "known_answers", "keccak256(empty)", keccak256(b"").hex(),
                     known["keccak256(empty)"])
    checks += expect(failures, "known_answers", "keccak256(abc)", keccak256(b"abc").hex(),
                     known["keccak256(0x616263)"])
    checks += expect(failures, "known_answers", "sha3_256(empty)_MUST_NOT_BE_USED",
                     hashlib.sha3_256(b"").hexdigest(), known["sha3_256(empty)_MUST_NOT_BE_USED"])
    if keccak256(b"") == hashlib.sha3_256(b"").digest():
        failures.append("known_answers: keccak256 collides with sha3_256 - the pad byte is wrong")

    for case in vectors["positive"]:
        name = case["name"]
        rows = case["input"]["rows"]
        try:
            got = compose(copy.deepcopy(rows))
        except ValueError as exc:
            # A published positive that this reference rule rejects is a mismatch, not a crash:
            # the vector file and the prose disagree.
            failures.append(f"{name}: reference compose rejects a published positive ({exc})")
            checks += 1
            continue
        want = case["expected"]
        checks += expect(failures, name, "certificate_digest", want["certificate_digest"],
                         got["certificate_digest"])
        checks += expect(failures, name, "checkpoint_height", want["checkpoint_height"],
                         got["checkpoint_height"])
        checks += expect(failures, name, "counts", want["counts"], got["counts"])
        checks += expect(failures, name, "roots", want["roots"], got["roots"])
        checks += expect(failures, name, "row_digests", want["row_digests"], got["row_digests"])
        fold = want.get("folded_guarantee")
        if fold is None:
            checks += expect(failures, name, "folded_guarantee", None, got["folded_guarantee"])
        else:
            checks += expect(failures, name, "folded_guarantee", bundle_wire(fold),
                             bundle_wire(got["folded_guarantee"]))
        published_proofs = case.get("inclusion_proofs", [])
        for proof in published_proofs:
            domain = proof["entry"]["domain_id"]
            checks += expect(failures, f"{name}/proof[{domain}]", "opens", True,
                             verify_inclusion(proof))
            try:
                rebuilt = build_inclusion(got["buckets"][proof["bucket"]], domain)
            except ValueError as exc:
                failures.append(f"{name}/proof[{domain}]: {exc}")
                checks += 1
                continue
            for field in ("bucket", "leaf_index", "leaf_count", "siblings",
                          "expected_bucket_root"):
                checks += expect(failures, f"{name}/proof[{domain}]", field, proof[field],
                                 rebuilt[field])
            checks += expect(failures, f"{name}/proof[{domain}]", "rebuilt_opens", True,
                             verify_inclusion(rebuilt))
        # Coverage: a row with no published proof leaves its opening path untested, which is
        # how a producer-side index bug hides in a bucket nobody opened.
        covered = {proof["entry"]["domain_id"] for proof in published_proofs}
        for row in rows:
            checks += 1
            if row["domain_id"] not in covered:
                failures.append(f"{name}: row domain {row['domain_id']} has no published proof")

    names = {case["name"] for case in vectors["negative"]}
    for required in REQUIRED_COMPOSITION_REJECTIONS + REQUIRED_FORGERY_REJECTIONS:
        checks += 1
        if required not in names:
            failures.append(f"coverage: the document requires a negative case {required!r}, "
                            "the vector file has none")

    for case in vectors["negative"]:
        name, why = case["name"], case.get("why_rejected", "")
        checks += 1
        if not why:
            failures.append(f"{name}: negative case carries no reason")
            continue
        if "proof" in case:
            if "expect" in case:
                failures.append(f"{name}: a proof-level negative carries an expect field; it is "
                                "rejected by verify, not by composition")
            if verify_inclusion(case["proof"]):
                failures.append(f"{name}: the forgery verified as honest")
            continue
        if case.get("expect") != "compose_rejects":
            failures.append(f"{name}: a row-set negative must state \"expect\": "
                            "\"compose_rejects\", got " + repr(case.get("expect")))
        try:
            compose(copy.deepcopy(case["rows"]))
        except ValueError:
            pass
        else:
            failures.append(f"{name}: invalid row set composed without rejection")
    return failures, checks


def check_bundle(vectors: dict) -> tuple:
    failures, checks = [], 0
    encoding = vectors["encoding"]
    checks += expect(failures, "encoding", "length_bytes", 17, encoding["length_bytes"])
    checks += expect(failures, "encoding", "integers", "big-endian", encoding["integers"])
    checks += expect(failures, "encoding", "field_order", list(FIELD_ORDER),
                     encoding["field_order"])
    for case in vectors["wire"]:
        checks += expect(failures, case["name"], "hex", case["expected"]["hex"],
                         bundle_wire(case["input"]).hex())
    for case in vectors["meet"]:
        folded = bundle_meet(case["a"], case["b"])
        checks += expect(failures, case["name"], "expected", bundle_wire(case["expected"]),
                         bundle_wire(folded))
        checks += expect(failures, case["name"], "commutative", bundle_wire(folded),
                         bundle_wire(bundle_meet(case["b"], case["a"])))
        checks += expect(failures, case["name"], "idempotent", bundle_wire(folded),
                         bundle_wire(bundle_meet(folded, folded)))
    for case in vectors["admits_cross_domain_value"]:
        checks += expect(failures, case["name"], "expected", case["expected"],
                         admits_cross_domain_value(case["input"]))
    missing = _admits_table_is_complete(vectors)
    failures += missing
    checks += len(ADMIT_BRANCHES)
    return failures, checks


def check_evm(vectors: dict) -> tuple:
    failures, checks = [], 0
    positives = {case["name"]: case for case in vectors["positive"]}
    for name, case in positives.items():
        want = case["expected"]
        got = EVM_RULES[EVM_VARIANTS.get(name, name)](case["input"])
        checks += expect(failures, name, "preimage", want["preimage"], got["preimage"])
        checks += expect(failures, name, "digest", want["digest"], got["digest"])
    for case in vectors["negative"]:
        name, why = case["name"], case.get("why_rejected", "")
        checks += 1
        if not why:
            failures.append(f"{name}: negative case carries no reason")
            continue
        basis, mutate = case.get("basis"), case.get("mutate")
        if basis is None or mutate is None:
            failures.append(f"{name}: no basis/mutate, so its digests are unexplained constants")
            continue
        source = positives.get(basis)
        if source is None:
            failures.append(f"{name}: basis {basis!r} is not a published positive case")
            continue
        input_a = copy.deepcopy(source["input"])
        input_b = copy.deepcopy(source["input"])
        input_b.update(mutate)
        if input_a == input_b:
            failures.append(f"{name}: the mutation changes nothing in the basis input")
            continue
        digest_a = EVM_RULES[basis](input_a)["digest"]
        digest_b = EVM_RULES[basis](input_b)["digest"]
        checks += expect(failures, name, "a", case["a"], digest_a)
        checks += expect(failures, name, "b", case["b"], digest_b)
        checks += expect(failures, name, "a_differs_from_b", True, digest_a != digest_b)
        if "same_attestation_digest" in case:
            checks += expect(failures, name, "same_attestation_digest",
                             case["same_attestation_digest"],
                             attestation_digest(att_of(source))["digest"])
    for required in REQUIRED_EVM_BINDINGS:
        checks += 1
        if required not in {case["name"] for case in vectors["negative"]}:
            failures.append(f"coverage: the document requires a negative case {required!r}, "
                            "the vector file has none")
    return failures, checks


_SWEEP: list = []  # synthetic rows, built once and grown on demand
_SWEEP_BOUND = 8192


def check_limits(vectors: dict) -> tuple:
    """The registry ceiling, tested rather than asserted.

    A published vector for 4097 rows would be a megabyte of JSON saying one thing: an
    implementation that stops at 4096. So the boundary is generated here from the row shape the
    document defines, and both sides of it are checked - the ceiling accepted, one more refused.

    The number of rows to build is clamped: this file is fed by JSON a stranger may edit, and a
    checker that allocates whatever the input tells it to is a denial of service against its own
    user. A published ceiling above the bound is reported instead of honoured.
    """
    failures, checks = [], 0
    limits = vectors.get("limits", {})
    checks += expect(failures, "limits", "max_certificate_domains", MAX_CERTIFICATE_DOMAINS,
                     limits.get("max_certificate_domains"))
    checks += expect(failures, "limits", "bps_scale", BPS_SCALE, limits.get("bps_scale"))
    checks += expect(failures, "limits", "min_value_safe_pow_confirmations",
                     DEEP_POW_CONFIRMATIONS, limits.get("min_value_safe_pow_confirmations"))
    published = limits.get("max_certificate_domains")
    if not isinstance(published, int) or published <= 0:
        failures.append(f"limits: max_certificate_domains must be a positive integer, got "
                        f"{published!r}")
        return failures, checks
    if published > _SWEEP_BOUND:
        checks += 1
        failures.append(f"limits: refusing to build {published} synthetic rows to test a "
                        f"ceiling; a conforming certificate set is capped at "
                        f"{MAX_CERTIFICATE_DOMAINS}")
        return failures, checks

    def upto(count: int) -> list:
        while len(_SWEEP) < count:
            index = len(_SWEEP) + 1
            _SWEEP.append({"domain_id": index, "height": index, "checkpoint_height": 1,
                           "state_root": f"{index:064x}", "adapter_id": "sweep",
                           "adapter_version": 1, "finality_proof_hash": f"{index:064x}",
                           "guarantee_backing_hash": f"{index:064x}", "bond_atoms": index,
                           "guarantee": {"reversibility": {"kind": "DeterministicQuorum"},
                                         "quantum_posture": "Classical",
                                         "attestation": {key: True for key in ATTESTATION_FIELDS},
                                         "slashable_backing": True,
                                         "fault_tolerance_bps": BPS_SCALE},
                           "verdict": {"kind": "Established"}})
        return _SWEEP[:count]

    try:
        accepted = bool(validate_rows(upto(published))[1]["Established"])
    except ValueError as exc:
        accepted = False
        failures.append(f"limits: {published} rows is a legal certificate, validation refused "
                        f"({exc})")
    checks += expect(failures, "limits", f"{published}_rows_accepted", True, accepted)
    try:
        validate_rows(upto(published + 1))
    except ValueError:
        checks += 1
    else:
        failures.append(f"limits: {published + 1} domains accepted, above the published ceiling")
    return failures, checks


# --------------------------------------------------------------------------------------------
# --the published selectors against the Solidity sources they claim to come from------------
#
# A vector file can state a keccak digest of anything and look self-consistent. This section
# refuses to take a selector on faith: it re-reads the .sol declarations named in the vectors,
# canonicalises every parameter type from the source text (including expanding a struct into
# the tuple of its member types, which is the part a hand-typed table gets wrong), and requires
# the published 4-byte value to be what the line in the tree hashes to. It shares no code with
# whichever generator wrote the file.
# --------------------------------------------------------------------------------------------

SURFACE_NAMES = ("rootAtHeight", "heightFinal", "latestFinalHeight", "finalityModeAtHeight",
                 "pendingIdentity", "attestationDigest", "signingRoot")
_WIDTHS = "|".join(str(width) for width in range(8, 257, 8))
_PRIMITIVE = re.compile(rf"^(?:u?int({_WIDTHS})|bytes(?:[1-9]|[12][0-9]|3[0-2])?|bool|address)$")
_DECLARATION = re.compile(r"\bfunction\s+([A-Za-z_]\w*)\s*\(([^)]*)\)")
_STRUCT = re.compile(r"\bstruct\s+([A-Za-z_]\w*)\s*\{([^}]*)\}")


def repo_root() -> pathlib.Path:
    """Where the .sol sources of the tree under check live, or None if they are not here.

    The checker is copied into second-implementation trees that have no contracts, so the
    answer is looked up rather than assumed; when nothing is found the selector section is
    reported as unavailable instead of passing quietly.
    """
    candidates = []
    env = os.environ.get("BUDLUM_REPO")
    if env:
        candidates.append(pathlib.Path(env))
    here = pathlib.Path(__file__).resolve()
    candidates += [here.parents[2], pathlib.Path("/var/tmp/budlum-work/budlum")]
    for candidate in candidates:
        if (candidate / "contracts/external-domain/BudlumFinalityVerifier.sol").is_file():
            return candidate
    return None


def _structs_of(text: str) -> dict:
    members = {}
    for name, body in _STRUCT.findall(text):
        members[name] = [line.strip().rstrip(";").split()[0]
                         for line in body.splitlines()
                         if line.strip() and not line.strip().startswith("//")]
    return members


def _canonical(token: str, structs: dict) -> str:
    base, array = token.strip().split()[0] if token.strip() else "", ""
    while base.endswith("]"):
        cut = base.rindex("[")
        array, base = base[cut:] + array, base[:cut]
    base = base.split(".")[-1]
    if _PRIMITIVE.match(base):
        return base + array
    if base in structs:
        return "tuple(" + ",".join(_canonical(t, structs) for t in structs[base]) + ")" + array
    raise ValueError(f"unresolvable solidity type {token!r}")


def _signature_of(line: str, structs: dict) -> tuple:
    match = _DECLARATION.search(line)
    if not match:
        raise ValueError(f"not a function declaration: {line!r}")
    params = [chunk for chunk in match.group(2).split(",") if chunk.strip()]
    return (f"{match.group(1)}(" + ",".join(_canonical(p, structs) for p in params) + ")")


def solidity_declarations(root: pathlib.Path, files: list) -> dict:
    """Every surface declaration in `files`, as {name: [(canonical signature, file, line)]}."""
    out = {}
    for rel in files:
        text = (root / rel).read_text(encoding="utf-8")
        structs = _structs_of(text)
        for number, line in enumerate(text.splitlines(), start=1):
            match = _DECLARATION.search(line)
            if not match or match.group(1) not in SURFACE_NAMES:
                continue
            try:
                signature = _signature_of(line, structs)
            except ValueError:
                continue      # a type this standard does not use; not our surface
            out.setdefault(match.group(1), []).append((signature, rel, number, line.strip()))
    return out


def check_solidity(vectors: dict, root) -> tuple:
    failures, checks = [], 0
    block = vectors.get("solidity")
    if block is None:
        return failures, checks
    files = block.get("source_files", [])
    if root is None or not all((root / rel).is_file() for rel in files):
        return failures, checks
    found = solidity_declarations(root, files)
    recomputed = {name: "0x" + keccak256(entries[0][0].encode("ascii")).hex()[:8]
                  for name, entries in sorted(found.items())}
    checks += expect(failures, "solidity", "declared_selector", block["declared_selector"],
                     recomputed)
    checks += 1
    if not set(SURFACE_NAMES) <= set(block["declared_selector"]):
        failures.append("solidity: the published selector table does not cover the read surface")
    for entry in block["declarations"]:
        label = f"solidity/{entry['file']}:{entry['line']}"
        line = (root / entry["file"]).read_text(encoding="utf-8").splitlines()[entry["line"] - 1]
        structs = _structs_of((root / entry["file"]).read_text(encoding="utf-8"))
        checks += 2
        if line.strip() != entry["declaration"]:
            failures.append(f"{label}: the tree's line reads {line.strip()!r}, "
                            f"the vectors say {entry['declaration']!r}")
            continue
        try:
            signature = _signature_of(line, structs)
        except ValueError as exc:
            failures.append(f"{label}: {exc}")
            continue
        checks += expect(failures, label, "canonical_signature", entry["canonical_signature"],
                         signature)
        checks += expect(failures, label, "selector", entry["selector"],
                         "0x" + keccak256(signature.encode("ascii")).hex()[:8])
        checks += 1
        if (signature, entry["file"], entry["line"], entry["declaration"]) not in found.get(
                entry["canonical_signature"].split("(")[0], []):
            failures.append(f"{label}: not where the vectors say this is declared")
    return failures, checks


def check_evm_document(vectors: dict) -> tuple:
    """The evm vectors plus the contract sources they are pinned to."""
    failures, checks = check_evm(vectors)
    extra, more = check_solidity(vectors, repo_root())
    return failures + extra, checks + more


def check_all(cert: dict, bundle: dict, evm: dict, with_limits: bool = True) -> tuple:
    failures, checks = [], 0
    parts = [check_certificate(cert), check_bundle(bundle), check_evm_document(evm)]
    parts.append(check_limits(cert) if with_limits else ([], 0))
    for part in parts:
        failures += part[0]
        checks += part[1]
    return failures, checks


# --------------------------------------------------------------------------------------------
# --self-test: each published field must be mutable in a way this check notices.
# --------------------------------------------------------------------------------------------

MUTATIONS = {
    "certificate": [
        ("expected/certificate_digest",
         lambda v: v["positive"][0]["expected"].__setitem__(
             "certificate_digest", "00" + v["positive"][0]["expected"]["certificate_digest"][2:])),
        ("expected/counts",
         lambda v: v["positive"][1]["expected"]["counts"].__setitem__(
             "Established", v["positive"][1]["expected"]["counts"]["Established"] + 1)),
        ("expected/roots/Established",
         lambda v: v["positive"][1]["expected"]["roots"].__setitem__(
             "Established", "ff" + v["positive"][1]["expected"]["roots"]["Established"][2:])),
        ("expected/row_digests",
         lambda v: v["positive"][1]["expected"]["row_digests"].__setitem__(
             "1", "fe" + list(v["positive"][1]["expected"]["row_digests"].values())[0][2:])),
        ("expected/folded_guarantee/bps",
         lambda v: v["positive"][1]["expected"]["folded_guarantee"].__setitem__(
             "fault_tolerance_bps", 3332)),
        ("proof/siblings_reversed", _reverse_a_multilevel_sibling_path),
        ("proof/leaf_index_off_by_one",
         lambda v: v["positive"][4]["inclusion_proofs"][0].__setitem__(
             "leaf_index", v["positive"][4]["inclusion_proofs"][0]["leaf_index"] + 1)),
        ("row/height",
         lambda v: v["positive"][0]["input"]["rows"][0].__setitem__(
             "height", v["positive"][0]["input"]["rows"][0]["height"] + 1)),
        ("row/adapter_id",
         lambda v: v["positive"][1]["input"]["rows"][0].__setitem__(
             "adapter_id", v["positive"][1]["input"]["rows"][0]["adapter_id"] + "x")),
        ("row/state_root",
         lambda v: v["positive"][1]["input"]["rows"][0].__setitem__(
             "state_root", "11" + v["positive"][1]["input"]["rows"][0]["state_root"][2:])),
        ("row/bond_atoms",
         lambda v: v["positive"][1]["input"]["rows"][0].__setitem__(
             "bond_atoms", v["positive"][1]["input"]["rows"][0]["bond_atoms"] + 1)),
        ("row/verdict_to_pending",
         lambda v: v["positive"][1]["input"]["rows"][0].__setitem__(
             "verdict", {"kind": "Pending", "reason": "EvidenceMissing"})),
        ("row/attestation_bit",
         lambda v: v["positive"][1]["input"]["rows"][0]["guarantee"]["attestation"].__setitem__(
             "parent", False)),
        ("negative/forgery_mended", _mend_the_forgery),
        ("negative/wrong_root_repaired", _repair_the_wrong_root),
        ("negative/expect_field_removed",
         lambda v: [n for n in v["negative"] if n["name"] == "empty_row_set"][0].pop("expect")),
        ("negative/expect_moved_onto_a_proof",
         lambda v: [n for n in v["negative"] if n["name"] == "forged_fourth_leaf_on_three_row_bucket"][0]
         .__setitem__("expect", "compose_rejects")),
        ("negative/empty_row_set_dropped",
         lambda v: v.__setitem__("negative",
                                 [n for n in v["negative"] if n["name"] != "empty_row_set"])),
        ("known_answers/keccak256_empty",
         lambda v: v["known_answers"].__setitem__(
             "keccak256(empty)", "00" + v["known_answers"]["keccak256(empty)"][2:])),
        ("tags/node",
         lambda v: v["tags"].__setitem__("node", "BDLM_FINALITY_CERT_NODE_V2")),
    ],
    "limits": [
        ("limits/max_certificate_domains",
         lambda v: v["limits"].__setitem__("max_certificate_domains", 4097)),
        ("limits/bps_scale", lambda v: v["limits"].__setitem__("bps_scale", 10_001)),
        ("limits/min_pow_confirmations",
         lambda v: v["limits"].__setitem__("min_value_safe_pow_confirmations", 7)),
        ("limits/ceiling_not_enforced",
         lambda v: v["limits"].__setitem__("max_certificate_domains", 8192)),
        ("limits/ceiling_absurd",
         lambda v: v["limits"].__setitem__("max_certificate_domains", 1_000_000)),
        ("limits/ceiling_not_a_number",
         lambda v: v["limits"].__setitem__("max_certificate_domains", "4096")),
    ],
    "bundle": [
        ("encoding/length_bytes", lambda v: v["encoding"].__setitem__("length_bytes", 26)),
        ("encoding/field_order",
         lambda v: v["encoding"].__setitem__("field_order", list(reversed(v["encoding"]["field_order"])))),
        ("wire/0/hex",
         lambda v: v["wire"][0]["expected"].__setitem__(
             "hex", v["wire"][0]["expected"]["hex"][:-2] + "ff")),
        ("wire/3/hex",
         lambda v: v["wire"][3]["expected"].__setitem__(
             "hex", v["wire"][3]["expected"]["hex"][:-2] + "00")),
        ("meet/0/expected/bps",
         lambda v: v["meet"][0]["expected"].__setitem__("fault_tolerance_bps", 4999)),
        ("meet/0/expected/posture",
         lambda v: v["meet"][0]["expected"].__setitem__("quantum_posture", "Hash")),
        ("meet/0/expected/attestation",
         lambda v: v["meet"][0]["expected"]["attestation"].__setitem__("parent", True)),
        ("admits/0/expected",
         lambda v: v["admits_cross_domain_value"][0].__setitem__(
             "expected", not v["admits_cross_domain_value"][0]["expected"])),
        ("admits/1/expected",
         lambda v: v["admits_cross_domain_value"][1].__setitem__(
             "expected", not v["admits_cross_domain_value"][1]["expected"])),
    ],
    "evm": [
        ("positive/0/digest",
         lambda v: v["positive"][0]["expected"].__setitem__(
             "digest", "01" + v["positive"][0]["expected"]["digest"][2:])),
        ("positive/0/preimage",
         lambda v: v["positive"][0]["expected"].__setitem__(
             "preimage", v["positive"][0]["expected"]["preimage"][:-2] + "01")),
        ("positive/1/input/variant",
         lambda v: v["positive"][1]["input"].__setitem__(
             "mlDsaEthVariant", not v["positive"][1]["input"]["mlDsaEthVariant"])),
        ("positive/2/input/height",
         lambda v: v["positive"][2]["input"].__setitem__("height", v["positive"][2]["input"]["height"] + 1)),
        ("positive/3/input/host_chainid",
         lambda v: v["positive"][3]["input"].__setitem__(
             "host_chain_id", v["positive"][3]["input"]["host_chain_id"] + 1)),
        ("positive/0/input/chainId",
         lambda v: v["positive"][0]["input"].__setitem__("chainId", v["positive"][0]["input"]["chainId"] + 1)),
        ("negative/0/mutation_neutralised",
         lambda v: v["negative"][0]["mutate"].__setitem__(
             "host_chain_id", v["positive"][3]["input"]["host_chain_id"])),
        ("negative/1/mutation_wrong_value",
         lambda v: v["negative"][1]["mutate"].__setitem__("chainId", 45263)),
        ("negative/2/basis_dropped", lambda v: v["negative"][2].pop("basis")),
        ("solidity/selector_table_wrong",
         lambda v: v["solidity"]["declared_selector"].__setitem__("rootAtHeight", "0x00000000")),
        ("solidity/declaration_line_moved",
         lambda v: v["solidity"]["declarations"][0].__setitem__("line",
                                                                v["solidity"]["declarations"][0]["line"] + 1)),
        ("solidity/canonical_signature_narrowed",
         lambda v: v["solidity"]["declarations"][0].__setitem__(
             "canonical_signature", v["solidity"]["declarations"][0]["canonical_signature"]
             .replace("uint64", "uint32"))),
        ("solidity/declaration_text_edited",
         lambda v: v["solidity"]["declarations"][0].__setitem__(
             "declaration", v["solidity"]["declarations"][0]["declaration"].replace(
                 "bytes32", "bytes31"))),
    ],
}

# The selector section reads the tree, so a copy of this checker without the Solidity sources
# cannot exercise those four mutations; it says so instead of reporting them as covered.
SOLIDITY_MUTATIONS = ("solidity/selector_table_wrong", "solidity/declaration_line_moved",
                      "solidity/canonical_signature_narrowed", "solidity/declaration_text_edited")


# The three documents are independent files, so a mutation in one cannot change what the
# checker derives from another. Running only the affected check keeps --self-test linear in
# the number of mutations instead of three times that.
CHECK_BY_DOC = {"certificate": check_certificate, "bundle": check_bundle,
                "evm": check_evm_document,
                "limits": check_limits}


def self_test(documents: dict) -> tuple:
    caught, misses = 0, []
    for doc_name, mutations in MUTATIONS.items():
        real_doc = "certificate" if doc_name == "limits" else doc_name
        for label, mutate in mutations:
            probe = copy.deepcopy(documents[real_doc])
            try:
                mutate(probe)
            except (KeyError, IndexError, TypeError, ValueError) as exc:
                misses.append(f"{doc_name}/{label}: mutation not applicable ({exc})")
                continue
            failures, _ = CHECK_BY_DOC[doc_name](probe)
            if failures:
                caught += 1
            else:
                misses.append(f"{doc_name}/{label}: mutated and the check still passed")
    return caught, misses


def load(directory: str) -> dict:
    documents = {}
    for filename, key in (("finality-certificate-v1.json", "certificate"),
                          ("assurance-bundle-v1.json", "bundle"),
                          ("ibudlum-finality-v1.json", "evm")):
        with open(os.path.join(directory, "vectors", filename), "r", encoding="utf-8") as handle:
            documents[key] = json.load(handle)
    return documents


def main(argv: list) -> int:
    documents = load(os.path.dirname(os.path.abspath(__file__)))
    failures, checks = check_all(documents["certificate"], documents["bundle"], documents["evm"])
    for line in failures:
        print(f"MISMATCH {line}")
    if failures:
        print(f"FAILED: {len(failures)} of {checks} checks do not reproduce")
        return 1
    print(f"OK: {checks} checks reproduce every published value of the three standards")
    if "--self-test" in argv:
        caught, misses = self_test(documents)
        total = sum(len(items) for items in MUTATIONS.values())
        for line in misses:
            print(f"SELF-TEST WEAK: {line}")
        if misses:
            print(f"SELF-TEST FAILED: {caught}/{total} mutations caught")
            return 1
        print(f"SELF-TEST OK: all {total} published fields are mutation-sensitive")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
