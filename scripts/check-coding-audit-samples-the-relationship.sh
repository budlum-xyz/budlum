#!/usr/bin/env bash
# ============================================================================
# check-coding-audit-samples-the-relationship.sh
#
# The coding audit must check the Reed-Solomon relationship, on a column the
# operator did not choose, and must refuse the objects it cannot audit.
#
# Why this gate exists.
#
# A retrieval challenge asks whether the operator still has the bytes. It
# cannot ask whether those bytes are correct parity, because the chain never
# sees shard contents. So an operator could pass every retrieval challenge it
# was ever given while storing garbage under the parity shard's `ContentId`,
# and nobody would find out until the repair that needed that parity, which
# is the one moment the object cannot afford it.
#
# The audit closes that by sampling the relationship itself. Reed-Solomon
# works symbol-wise, so one byte column is a complete instance of it: parity
# byte `c` of shard `i` is `XOR_j coeff(i, j) * data_j[c]`. That makes the
# audit cost `k` data bytes plus one parity byte no matter how large the
# object is.
#
# The four ways this can be built so it looks right and proves nothing:
#
#   1. The verifier compares hashes, or compares the parity byte against
#      something other than the generator product. Then it is a checksum over
#      bytes the operator supplied, and the operator supplies both sides.
#   2. The column is chosen by the caller rather than derived from entropy.
#      An opener who picks the column picks one the operator has, and an
#      operator who knows the column in advance stores only that column.
#   3. A replicated object reports a passing audit. There is no parity, so
#      there is no relationship, and "pass" there is a report about an audit
#      that did not happen, on exactly the objects with no redundancy to
#      spare.
#   4. An out-of-range parity index or a short data column is treated as
#      zero-padded rather than refused. Zero is a valid byte, so the
#      relationship stays checkable and an operator answers an audit it
#      cannot answer.
#
# What this gate does not check: that the operator stores anything. That is
# the retrieval challenge's question, and a passing audit says nothing about
# it, because parity can be computed on demand by someone holding nothing.
# Nor does it check the whole shard: the audit is probabilistic by
# construction and the docs say so.
#
# Usage:
#   bash scripts/check-coding-audit-samples-the-relationship.sh
#   bash scripts/check-coding-audit-samples-the-relationship.sh --self-test
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

scan() {
  python3 - "$1" <<'PY'
import os
import re
import sys

root = sys.argv[1]
erasure = os.path.join(root, "src", "storage", "erasure.rs")
deal = os.path.join(root, "src", "domain", "storage_deal.rs")
locks = os.path.join(root, "src", "tests", "manifest_commitment_locks.rs")

for path in (erasure, deal, locks):
    if not os.path.isfile(path):
        print(f"FAIL: expected source file missing: {path}", file=sys.stderr)
        sys.exit(2)


def strip_comments(src):
    return re.sub(r"//[^\n]*", "", src)


def body_of(src, header):
    """Brace-matched body of the item whose signature matches `header`.

    Cutting at the first `#[cfg(test)]` drops the production half of a file
    that puts tests at the bottom; cutting at the next `}` stops at the first
    nested block. Matching braces is the only reading that survives both.
    """
    m = re.search(header, src)
    if not m:
        return None
    i = src.index("{", m.end() - 1) if "{" not in m.group(0) else m.end() - 1
    depth, j = 0, i
    while j < len(src):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[i : j + 1]
        j += 1
    return None


erasure_code = strip_comments(open(erasure, encoding="utf-8").read())
deal_code = strip_comments(open(deal, encoding="utf-8").read())
locks_src = open(locks, encoding="utf-8").read()

problems = []
checked = 0

# 1. The column check must exist and must actually multiply through the
#    generator. A version comparing hashes would pass every name-based check.
checked += 1
col = body_of(
    erasure_code, r"pub fn column_is_correctly_encoded\s*\("
)
if col is None:
    problems.append(
        "`ReedSolomon::column_is_correctly_encoded` is gone. It is the only "
        "thing that checks parity against the generator rather than against "
        "bytes the operator supplied."
    )
else:
    checked += 1
    if "gf_mul" not in col:
        problems.append(
            "`column_is_correctly_encoded` no longer multiplies through the "
            "field. Without `gf_mul` it is not checking the Reed-Solomon "
            "relationship, whatever else it compares."
        )
    checked += 1
    if "^=" not in col and "^" not in col:
        problems.append(
            "`column_is_correctly_encoded` no longer accumulates with XOR. "
            "GF(2^8) addition is XOR; any other combiner computes a different "
            "code."
        )
    checked += 1
    if "generator" not in col:
        problems.append(
            "`column_is_correctly_encoded` does not read the generator "
            "matrix, so it is not comparing against the coefficients the "
            "encoder used."
        )
    # 4. Width and range must be refused, not padded.
    checked += 1
    if "self.k" not in col or "self.m" not in col:
        problems.append(
            "`column_is_correctly_encoded` does not bound the column width "
            "against `k` and the parity index against `m`. A short column "
            "treated as zero-padded still satisfies the relationship, because "
            "zero is a valid byte, so an operator answers an audit it cannot "
            "answer."
        )

# 2. Selection must be derived from entropy, inside the chain, not taken as a
#    caller-chosen argument.
checked += 1
sel = body_of(deal_code, r"pub fn derive_coding_audit\s*\(")
sig = re.search(r"pub fn derive_coding_audit\s*\((.*?)\)\s*->", deal_code, re.S)
if sel is None or sig is None:
    problems.append(
        "`derive_coding_audit` is gone; nothing derives which column to "
        "sample, so the choice falls to whoever opens the challenge."
    )
else:
    checked += 1
    if "entropy" not in sig.group(1):
        problems.append(
            "`derive_coding_audit` does not take entropy. An opener who picks "
            "the column picks one the operator has, and an operator who knows "
            "the column in advance stores only that column."
        )
    checked += 1
    if "hash_fields_bytes" not in sel:
        problems.append(
            "`derive_coding_audit` no longer hashes its inputs, so the "
            "selection is not a function of unpredictable entropy."
        )
    checked += 1
    if "%" not in sel:
        problems.append(
            "`derive_coding_audit` never reduces the digest into range, so "
            "the selection can land outside the object and no honest operator "
            "can answer it."
        )
    # 3. Replication must be refused.
    checked += 1
    if "NoParityToAudit" not in sel:
        problems.append(
            "`derive_coding_audit` does not refuse an object with no parity. "
            "Reporting a pass there reports an audit that never happened, on "
            "the objects that have no redundancy to lose."
        )

# 5. The verifier must go through the coder rather than reimplementing it.
checked += 1
ver = body_of(deal_code, r"pub fn verify_coding_audit\s*\(")
if ver is None:
    problems.append("`verify_coding_audit` is gone; nothing checks an answer.")
else:
    checked += 1
    if "column_is_correctly_encoded" not in ver:
        problems.append(
            "`verify_coding_audit` does not call "
            "`column_is_correctly_encoded`. A second implementation of the "
            "relationship can disagree with the encoder, and the encoder is "
            "what a repair will use."
        )
    checked += 1
    if "ParityColumnMismatch" not in ver:
        problems.append(
            "`verify_coding_audit` has no distinct failure for a wrong "
            "column, so a mismatch is indistinguishable from a lookup error."
        )

# 6. The regressions must exist as real tests.
checked += 1
for test in (
    "an_honest_operator_passes_the_audit",
    "an_operator_serving_garbage_parity_fails",
    "a_single_flipped_bit_is_caught",
    "a_replicated_object_has_nothing_to_audit",
    "the_selection_is_not_the_openers_to_make",
    "the_selection_lands_inside_the_object",
):
    if not re.search(
        r"#\[test\]\s*(?:#\[[^\]]*\]\s*)*fn\s+" + test + r"\s*\(", locks_src
    ):
        problems.append(
            f"required regression test `{test}` is missing or is not a `#[test]`."
        )

if not checked:
    print("FAIL: gate checked nothing", file=sys.stderr)
    sys.exit(2)

if problems:
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    sys.exit(1)

print(
    f"coding audit gate OK: {checked} checks, the relationship is sampled at "
    "an entropy-chosen column and replication is refused"
)
PY
}

self_test() {
  local tmp
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  expect_finding() {
    local dir="$1" what="$2" rc=0
    ( scan "$dir" ) >/dev/null 2>&1 || rc=$?
    if [ "$rc" -eq 0 ]; then
      echo "GATE IS VACUOUS: $what passed!" >&2
      return 1
    fi
    if [ "$rc" -ne 1 ]; then
      echo "GATE IS BROKEN: $what exited $rc, which is not a finding." >&2
      return 1
    fi
  }

  # Fixtures are written by python: the bodies contain `#[test]`, and bash
  # treats `[` as a glob inside `${var//pattern/...}`, so a substitution would
  # silently do nothing and leave the canary asserting against an unmodified
  # tree.
  build() {
    python3 - "$@" <<'PYB'
import os
import sys

root, col_mode, sel_mode, ver_mode, tests_mode = sys.argv[1:6]
for sub in ("src/storage", "src/domain", "src/tests"):
    os.makedirs(os.path.join(root, sub), exist_ok=True)

if col_mode == "gone":
    col = ""
elif col_mode == "hash":
    # Compares a hash of what the operator sent against what the operator
    # sent. Reads like a check and is one side of an equation.
    col = """    pub fn column_is_correctly_encoded(&self, i: usize, c: &[u8], p: u8) -> bool {
        hash(c) == hash(&[p])
    }
"""
elif col_mode == "nobound":
    # Multiplies correctly but pads a short column with zeroes.
    col = """    pub fn column_is_correctly_encoded(&self, i: usize, c: &[u8], p: u8) -> bool {
        let mut acc = 0u8;
        for (j, b) in c.iter().enumerate() {
            acc ^= gf_mul(self.generator.get(j), *b);
        }
        acc == p
    }
"""
elif col_mode == "nogf":
    # Bounds correctly, combines with plain addition instead of the field.
    col = """    pub fn column_is_correctly_encoded(&self, i: usize, c: &[u8], p: u8) -> bool {
        if c.len() != self.k || i >= self.m { return false; }
        let mut acc = 0u8;
        for b in c.iter() { acc = acc.wrapping_add(*b); }
        acc == p
    }
"""
else:
    col = """    pub fn column_is_correctly_encoded(&self, i: usize, c: &[u8], p: u8) -> bool {
        if c.len() != self.k || i >= self.m { return false; }
        let mut acc = 0u8;
        for (j, b) in c.iter().enumerate() {
            acc ^= gf_mul(self.generator.get(self.k + i, j), *b);
        }
        acc == p
    }
"""
open(os.path.join(root, "src/storage/erasure.rs"), "w").write(
    "impl ReedSolomon {\n%s}\n" % col
)

if sel_mode == "gone":
    sel = ""
elif sel_mode == "caller":
    # Takes the column from the caller. Every other check still passes.
    sel = """    pub fn derive_coding_audit(
        column: u64,
        manifest: &ContentManifest,
        challenge_id: u64,
    ) -> Result<CodingAudit, StorageError> {
        if manifest.erasure.parity_count() == 0 {
            return Err(StorageError::NoParityToAudit { manifest_id: manifest.manifest_id });
        }
        Ok(CodingAudit { manifest_id: manifest.manifest_id, parity_index: 0, column })
    }
"""
elif sel_mode == "norange":
    # Hashes entropy but never reduces into range.
    sel = """    pub fn derive_coding_audit(
        entropy: &Hash32,
        manifest: &ContentManifest,
        challenge_id: u64,
    ) -> Result<CodingAudit, StorageError> {
        if manifest.erasure.parity_count() == 0 {
            return Err(StorageError::NoParityToAudit { manifest_id: manifest.manifest_id });
        }
        let d = hash_fields_bytes(&[b"X", entropy]);
        Ok(CodingAudit {
            manifest_id: manifest.manifest_id,
            parity_index: 0,
            column: u64::from_le_bytes(d[..8].try_into().unwrap()),
        })
    }
"""
elif sel_mode == "noparity":
    # Happily audits a replicated object.
    sel = """    pub fn derive_coding_audit(
        entropy: &Hash32,
        manifest: &ContentManifest,
        challenge_id: u64,
    ) -> Result<CodingAudit, StorageError> {
        let d = hash_fields_bytes(&[b"X", entropy]);
        Ok(CodingAudit {
            manifest_id: manifest.manifest_id,
            parity_index: 0,
            column: u64::from_le_bytes(d[..8].try_into().unwrap()) % 16,
        })
    }
"""
else:
    sel = """    pub fn derive_coding_audit(
        entropy: &Hash32,
        manifest: &ContentManifest,
        challenge_id: u64,
    ) -> Result<CodingAudit, StorageError> {
        if manifest.erasure.parity_count() == 0 {
            return Err(StorageError::NoParityToAudit { manifest_id: manifest.manifest_id });
        }
        let d = hash_fields_bytes(&[b"X", entropy, &challenge_id.to_le_bytes()]);
        Ok(CodingAudit {
            manifest_id: manifest.manifest_id,
            parity_index: 0,
            column: u64::from_le_bytes(d[..8].try_into().unwrap()) % 16,
        })
    }
"""

if ver_mode == "gone":
    ver = ""
elif ver_mode == "reimpl":
    # Reimplements the relationship instead of calling the coder, so the two
    # can drift and the repair path uses the other one.
    ver = """    pub fn verify_coding_audit(&self, a: &CodingAudit, c: &[u8], p: u8) -> Result<(), StorageError> {
        let mut acc = 0u8;
        for b in c.iter() { acc ^= *b; }
        if acc == p { Ok(()) } else {
            Err(StorageError::ParityColumnMismatch {
                manifest_id: a.manifest_id, parity_index: a.parity_index, column: a.column,
            })
        }
    }
"""
elif ver_mode == "noerror":
    ver = """    pub fn verify_coding_audit(&self, a: &CodingAudit, c: &[u8], p: u8) -> Result<(), StorageError> {
        let coder = ReedSolomon::for_scheme(&self.scheme).unwrap();
        if coder.column_is_correctly_encoded(a.parity_index as usize, c, p) {
            Ok(())
        } else {
            Err(StorageError::UnknownManifest(a.manifest_id))
        }
    }
"""
else:
    ver = """    pub fn verify_coding_audit(&self, a: &CodingAudit, c: &[u8], p: u8) -> Result<(), StorageError> {
        let coder = ReedSolomon::for_scheme(&self.scheme).unwrap();
        if coder.column_is_correctly_encoded(a.parity_index as usize, c, p) {
            Ok(())
        } else {
            Err(StorageError::ParityColumnMismatch {
                manifest_id: a.manifest_id, parity_index: a.parity_index, column: a.column,
            })
        }
    }
"""
open(os.path.join(root, "src/domain/storage_deal.rs"), "w").write(
    "impl StorageRegistry {\n%s\n%s}\n" % (sel, ver)
)

names = [
    "an_honest_operator_passes_the_audit",
    "an_operator_serving_garbage_parity_fails",
    "a_single_flipped_bit_is_caught",
    "a_replicated_object_has_nothing_to_audit",
    "the_selection_is_not_the_openers_to_make",
    "the_selection_lands_inside_the_object",
]
if tests_mode == "absent":
    names = names[:-1]
open(os.path.join(root, "src/tests/manifest_commitment_locks.rs"), "w").write(
    "".join("#[test]\nfn %s() {}\n" % n for n in names)
)
PYB
  }

  # 1. The corrected shape must pass, or every canary below proves nothing.
  build "$tmp/good" ok ok ok present
  if ! ( scan "$tmp/good" ) >/dev/null 2>&1; then
    echo "GATE IS WRONG: the corrected tree was rejected!" >&2
    ( scan "$tmp/good" ) >&2 || true
    return 1
  fi

  # 2. The column check disappears.
  build "$tmp/nocol" gone ok ok present
  expect_finding "$tmp/nocol" "a missing column check" || return 1

  # 3. It compares hashes of what the operator sent, both sides.
  build "$tmp/hash" hash ok ok present
  expect_finding "$tmp/hash" "a checksum standing in for the relationship" || return 1

  # 4. It multiplies but pads a short column with zeroes.
  build "$tmp/nobound" nobound ok ok present
  expect_finding "$tmp/nobound" "a column width nobody bounds" || return 1

  # 5. It bounds correctly but combines outside the field.
  build "$tmp/nogf" nogf ok ok present
  expect_finding "$tmp/nogf" "an accumulator that is not GF(2^8)" || return 1

  # 6. Selection disappears.
  build "$tmp/nosel" ok gone ok present
  expect_finding "$tmp/nosel" "a missing selection" || return 1

  # 7. The caller chooses the column.
  build "$tmp/caller" ok caller ok present
  expect_finding "$tmp/caller" "a column the opener picks" || return 1

  # 8. Entropy is hashed but never reduced into range.
  build "$tmp/norange" ok norange ok present
  expect_finding "$tmp/norange" "a selection that lands past the shard" || return 1

  # 9. A replicated object reports an audit.
  build "$tmp/noparity" ok noparity ok present
  expect_finding "$tmp/noparity" "an audit of an object with no parity" || return 1

  # 10. The verifier disappears.
  build "$tmp/nover" ok ok gone present
  expect_finding "$tmp/nover" "a missing verifier" || return 1

  # 11. The verifier reimplements the relationship instead of calling the
  #     coder, so the audit and the repair can disagree about the same object.
  build "$tmp/reimpl" ok ok reimpl present
  expect_finding "$tmp/reimpl" "a second implementation of the relationship" || return 1

  # 12. A mismatch is reported as a lookup error, so the two are
  #     indistinguishable to anything acting on the result.
  build "$tmp/noerror" ok ok noerror present
  expect_finding "$tmp/noerror" "a mismatch with no distinct failure" || return 1

  # 13. A regression test is dropped.
  build "$tmp/notest" ok ok ok absent
  expect_finding "$tmp/notest" "a missing regression test" || return 1

  echo "coding audit gate self-test OK: 13 canaries"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  scan "$ROOT"
fi
