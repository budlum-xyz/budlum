#!/usr/bin/env bash
# ============================================================================
# check-wire-fields-are-signed.sh
#
# A field a peer can put on the wire must be inside the signing preimage.
#
# Why this gate exists.
#
# `Transaction::signing_hash` builds a byte string by hand, field by field,
# and `encode_transaction_type_payload` appends the variant's own payload. The
# comment above it says "every execution-relevant variant field is committed
# explicitly", and for most variants that was true. Three had drifted:
#
#   * `AiModelSpec.execution_weights_digest` and `.execution_dims`. The guest
#     program for a fixed-point MLP is a function of the layer shape alone, so
#     `execution_program_hash` cannot separate two models with the same
#     architecture; the digest is what does, and `guest_program_for_model`
#     rebuilds the verified instruction words from the dims. Both crossed the
#     wire in `ProtoAiModelRegister` and neither reached the preimage, so a
#     relaying node could aim a signed registration at different weights or a
#     different program and the signature still verified.
#
#   * `AiInferenceRequest.effort`. Hashed into `calculate_id`, which
#     `submit_request` re-derives, so the id was a second door. The signature
#     is the first one, and it did not name the tier.
#
#   * `AiExecutionProof.weights_digest` and `.public_inputs`. These are the two
#     values `verify_execution_proof_stark` and
#     `verify_execution_proof_structural_with_model` check the proof against.
#
# The shape is the same each time and it is not a shape a reviewer catches by
# eye: a field is added to a struct, to the protobuf, and to the conversions,
# and the hand-written preimage 700 lines away is the one place that does not
# get the edit. Every test stays green, because a test that builds a
# transaction and verifies it never varies the field the preimage forgot.
#
# What the gate checks.
#
# For every `TransactionType` variant, take the struct types it carries, take
# every `pub` field of those structs, and require that
# `encode_transaction_type_payload` (following the `encode_*` helpers it calls)
# mentions each one, or that the field carries
# `SIGNING: excluded - <reason>` in its own doc comment.
#
# Known limits, stated so a pass is not read for more than it carries.
# Coverage is by name: a preimage that mentions `spec.foo` counts `foo` as
# committed, and this gate cannot tell whether the bytes were appended or the
# field was read for a length check. It measures that the field reached the
# encoder, not that it reached the digest. The per-variant tampering tests in
# `mod v29_signing_tests` are what measure the rest.
#
# Usage:
#   bash scripts/check-wire-fields-are-signed.sh              # gate
#   bash scripts/check-wire-fields-are-signed.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

scan() {
  python3 - "$1" <<'PY'
import os
import re
import sys

root = sys.argv[1]
TX = os.path.join(root, "src", "core", "transaction.rs")

MARKER = re.compile(r"SIGNING:\s*excluded\b(.*)")


def balanced(src, open_at):
    """Text from `open_at` (an opening brace) through its match."""
    depth, j = 0, open_at
    while j < len(src):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[open_at:j + 1]
        j += 1
    return src[open_at:]


def fn_body(src, name):
    """The body of `fn name`, walking the signature rather than guessing.

    A regex that stops at the first brace or semicolon after the arguments
    misses any function returning `[u8; 32]`, because the return type holds a
    semicolon. `encode_*` helpers return `()`, but the same walk is what makes
    this robust when one of them starts returning a `Result<_, _>`.
    """
    m = re.search(r"\bfn\s+" + re.escape(name) + r"\s*\(", src)
    if not m:
        return ""
    depth, j = 0, m.end() - 1
    while j < len(src):
        if src[j] == "(":
            depth += 1
        elif src[j] == ")":
            depth -= 1
            if depth == 0:
                break
        j += 1
    brackets, j = 0, j + 1
    while j < len(src):
        c = src[j]
        if c == ">" and j > 0 and src[j - 1] == "-":
            j += 1
            continue
        if c in "[<(":
            brackets += 1
        elif c in "]>)":
            brackets = max(0, brackets - 1)
        elif brackets == 0 and c == "{":
            return balanced(src, j)
        elif brackets == 0 and c == ";":
            return ""
        j += 1
    return ""


def struct_fields(body):
    """`[(name, doc)]` for each `pub` field, doc being the comment above it."""
    fields, doc = [], []
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("//"):
            doc.append(stripped)
            continue
        m = re.match(r"pub\s+(\w+)\s*:", stripped)
        if m:
            fields.append((m.group(1), "\n".join(doc)))
            doc = []
            continue
        if stripped.startswith("#["):
            continue
        if stripped:
            doc = []
    return fields


def is_test_path(path):
    return (
        f"{os.sep}tests{os.sep}" in path
        or path.endswith("_tests.rs")
        or path.endswith(f"{os.sep}tests.rs")
    )


try:
    tx_src = open(TX, encoding="utf-8", errors="ignore").read()
except OSError as exc:
    print(f"FAIL: cannot read {TX}: {exc}", file=sys.stderr)
    sys.exit(2)

enum_at = tx_src.find("pub enum TransactionType")
if enum_at < 0:
    print("FAIL: no `pub enum TransactionType` found - wrong root?", file=sys.stderr)
    sys.exit(2)
enum_body = balanced(tx_src, tx_src.find("{", enum_at))

preimage = fn_body(tx_src, "encode_transaction_type_payload")
if not preimage:
    print(
        "FAIL: `encode_transaction_type_payload` has no body the gate can read.",
        file=sys.stderr,
    )
    sys.exit(2)

# The helpers it delegates to are part of the preimage.
helpers = {
    m.group(1): fn_body(tx_src, m.group(1))
    for m in re.finditer(r"\bfn (encode_\w+)\s*\(", tx_src)
}
committed = preimage
for name, body in helpers.items():
    if re.search(r"\b" + re.escape(name) + r"\s*\(", preimage):
        committed += body
# One more level: a helper that calls a helper.
for name, body in helpers.items():
    if re.search(r"\b" + re.escape(name) + r"\s*\(", committed):
        committed += body

# Every struct in the tree, so a variant carrying `AiModelSpec` can be resolved.
structs = {}
for scan_root in ("src", "wallet-core"):
    base = os.path.join(root, scan_root)
    if not os.path.isdir(base):
        continue
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in (".git", "target", "node_modules")]
        for name in filenames:
            if not name.endswith(".rs"):
                continue
            path = os.path.join(dirpath, name)
            if is_test_path(path):
                continue
            src = open(path, encoding="utf-8", errors="ignore").read()
            for m in re.finditer(r"pub struct (\w+)\s*\{", src):
                structs.setdefault(
                    m.group(1),
                    (os.path.relpath(path, root), struct_fields(balanced(src, m.end() - 1))),
                )

carried = sorted(set(re.findall(r"\b([A-Z]\w+)\b", enum_body)))
if not carried:
    print("FAIL: TransactionType carries no named types - wrong parse?", file=sys.stderr)
    sys.exit(2)

problems = []
checked_structs = 0
checked_fields = 0

for type_name in carried:
    if type_name not in structs:
        continue
    rel, fields = structs[type_name]
    if not fields:
        continue
    checked_structs += 1
    for field, doc in fields:
        checked_fields += 1
        bound = re.search(r"\.%s\b" % re.escape(field), committed) is not None
        declared = MARKER.search(doc)
        if not bound and not declared:
            problems.append(
                f"{rel}: {type_name}.{field} rides inside a signed transaction and is "
                "not in the signing preimage. A relaying node can rewrite it and the "
                "signature still verifies. Append it in "
                "`encode_transaction_type_payload` (or the `encode_*` helper for this "
                "type), or write `SIGNING: excluded - <reason>` in the field's doc."
            )
        elif bound and declared:
            reason = declared.group(1).strip(" -\t")
            problems.append(
                f"{rel}: {type_name}.{field} is marked `SIGNING: excluded` "
                f"({reason or 'no reason given'}) and the preimage does commit it. "
                "The marker is stale and now describes a hole that is closed."
            )

if not checked_structs:
    print(
        "FAIL: gate resolved no struct carried by TransactionType - wrong root?",
        file=sys.stderr,
    )
    sys.exit(2)

if problems:
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    sys.exit(1)

print(
    f"wire-field signing gate OK: {checked_structs} structs carried by a "
    f"transaction, {checked_fields} fields each in the preimage or declaring "
    "why they are not"
)
PY
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  # Exit 1 is a finding. Exit 2 means the gate measured nothing, which is a
  # broken gate and must never be read as a pass.
  expect_finding() {
    local dir="$1" what="$2" rc=0
    ( scan "$dir" ) >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then
      echo "GATE IS VACUOUS: $what passed!" >&2
      return 1
    fi
    if [ "$rc" -ne 1 ]; then
      echo "GATE IS BROKEN: $what exited $rc, which is not a finding." >&2
      echo "Exit 2 means the gate measured nothing; that is not a pass." >&2
      return 1
    fi
  }

  expect_pass() {
    local dir="$1" what="$2"
    if ! ( scan "$dir" ) >/dev/null 2>&1; then
      echo "GATE IS WRONG: $what was rejected!" >&2
      return 1
    fi
  }

  expect_broken() {
    local dir="$1" what="$2" rc=0
    ( scan "$dir" ) >/dev/null 2>&1 || rc=$?
    if [ "$rc" -ne 2 ]; then
      echo "GATE MISREPORTS: $what exited $rc, expected 2 (measured nothing)." >&2
      return 1
    fi
  }

  mk() {
    local dir="$1" body="$2"
    rm -rf "$dir"
    mkdir -p "$dir/src/core"
    printf '%s\n' "$body" >"$dir/src/core/transaction.rs"
  }

  # 1. Every carried field committed: the healthy shape.
  mk "$tmp/covered" 'pub struct Spec {
    pub model_id: [u8; 32],
    pub weights_digest: Option<[u8; 32]>,
}
pub enum TransactionType {
    Register(Spec),
}
fn encode_transaction_type_payload(tx_type: &TransactionType, out: &mut Vec<u8>) {
    match tx_type {
        TransactionType::Register(spec) => encode_spec(spec, out),
    }
}
fn encode_spec(spec: &Spec, out: &mut Vec<u8>) {
    put_fixed(out, &spec.model_id);
    put_option_fixed32(out, spec.weights_digest);
}'
  expect_pass "$tmp/covered" "a variant whose preimage commits every field" || return 1

  # 2. The bug this gate exists for: a field on the struct, absent from the
  #    preimage. Exactly the shape `execution_weights_digest` had.
  mk "$tmp/silent" 'pub struct Spec {
    pub model_id: [u8; 32],
    pub weights_digest: Option<[u8; 32]>,
}
pub enum TransactionType {
    Register(Spec),
}
fn encode_transaction_type_payload(tx_type: &TransactionType, out: &mut Vec<u8>) {
    match tx_type {
        TransactionType::Register(spec) => encode_spec(spec, out),
    }
}
fn encode_spec(spec: &Spec, out: &mut Vec<u8>) {
    put_fixed(out, &spec.model_id);
}'
  expect_finding "$tmp/silent" "a carried field outside the signing preimage" || return 1

  # 3. Declared exclusion: honest, must pass.
  mk "$tmp/declared" 'pub struct Spec {
    pub model_id: [u8; 32],
    /// SIGNING: excluded - server-assigned after the signature is checked.
    pub received_at: u64,
}
pub enum TransactionType {
    Register(Spec),
}
fn encode_transaction_type_payload(tx_type: &TransactionType, out: &mut Vec<u8>) {
    match tx_type {
        TransactionType::Register(spec) => encode_spec(spec, out),
    }
}
fn encode_spec(spec: &Spec, out: &mut Vec<u8>) {
    put_fixed(out, &spec.model_id);
}'
  expect_pass "$tmp/declared" "a declared exclusion with a reason" || return 1

  # 4. Stale marker on a field the preimage does commit.
  mk "$tmp/stale" 'pub struct Spec {
    pub model_id: [u8; 32],
    /// SIGNING: excluded - left over from before it was committed.
    pub weights_digest: Option<[u8; 32]>,
}
pub enum TransactionType {
    Register(Spec),
}
fn encode_transaction_type_payload(tx_type: &TransactionType, out: &mut Vec<u8>) {
    match tx_type {
        TransactionType::Register(spec) => encode_spec(spec, out),
    }
}
fn encode_spec(spec: &Spec, out: &mut Vec<u8>) {
    put_fixed(out, &spec.model_id);
    put_option_fixed32(out, spec.weights_digest);
}'
  expect_finding "$tmp/stale" "a stale SIGNING: excluded marker" || return 1

  # 5. The helper chain has to be followed, or a preimage that delegates twice
  #    looks empty and the gate accuses fields that are committed.
  mk "$tmp/nested" 'pub struct Inner {
    pub value: u64,
}
pub struct Spec {
    pub model_id: [u8; 32],
    pub inner: Inner,
}
pub enum TransactionType {
    Register(Spec),
}
fn encode_transaction_type_payload(tx_type: &TransactionType, out: &mut Vec<u8>) {
    match tx_type {
        TransactionType::Register(spec) => encode_spec(spec, out),
    }
}
fn encode_spec(spec: &Spec, out: &mut Vec<u8>) {
    put_fixed(out, &spec.model_id);
    encode_inner(&spec.inner, out);
}
fn encode_inner(inner: &Inner, out: &mut Vec<u8>) {
    put_u64(out, inner.value);
}'
  expect_pass "$tmp/nested" "a preimage that delegates through two helpers" || return 1

  # 6. A return type holding a semicolon must not truncate the body scan.
  #    `[u8; 32]` is why `fn_body` walks the signature instead of regexing it.
  mk "$tmp/array_return" 'pub struct Spec {
    pub model_id: [u8; 32],
    pub weights_digest: Option<[u8; 32]>,
}
pub enum TransactionType {
    Register(Spec),
}
fn encode_transaction_type_payload(tx_type: &TransactionType, out: &mut Vec<u8>) {
    match tx_type {
        TransactionType::Register(spec) => encode_spec(spec, out),
    }
}
fn encode_spec(spec: &Spec, out: &mut Vec<u8>) -> [u8; 32] {
    put_fixed(out, &spec.model_id);
    put_option_fixed32(out, spec.weights_digest);
    [0u8; 32]
}'
  expect_pass "$tmp/array_return" "a helper returning a fixed-size array" || return 1

  # 7. No transaction module at all: the gate measured nothing and says so
  #    with exit 2, never a pass.
  rm -rf "$tmp/empty"
  mkdir -p "$tmp/empty/src"
  expect_broken "$tmp/empty" "a tree with no transaction module" || return 1

  # 8. An enum with no carried struct is also nothing measured.
  mk "$tmp/bare" 'pub enum TransactionType {
    Transfer,
}
fn encode_transaction_type_payload(tx_type: &TransactionType, out: &mut Vec<u8>) {
    match tx_type {
        TransactionType::Transfer => {}
    }
}'
  expect_broken "$tmp/bare" "an enum carrying no struct" || return 1

  echo "wire-field signing gate self-test OK: a missing field, a stale marker, \
an unreadable tree and an enum with nothing to measure are all rejected; a \
covered variant, a declared exclusion, a two-level helper chain and an array \
return all pass."
}

case "${1:-}" in
  --self-test)
    self_test
    ;;
  "")
    scan "$ROOT"
    ;;
  *)
    echo "usage: $0 [--self-test]" >&2
    exit 2
    ;;
esac
