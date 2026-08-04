#!/usr/bin/env bash
# ============================================================================
# check-self-derived-ids-cover-every-field.sh
#
# A field outside a self-derived id must say so next to itself.
#
# Why this gate exists.
#
# `AiInferenceRequest` carries a `request_id` that the requester computes from
# the request's own fields, signs inside the transaction, and the registry
# re-derives before it will accept anything: `submit_request` refuses when
# `verify_id` fails. That makes the id the thing the requester is bound to.
#
# The `effort` tier was added to the struct and, in the same change, to
# `calculate_id`. Had it been added to the struct alone, the shape would have
# looked finished and behaved as a hole: an operator could take a `5.0x`
# request, rewrite the tier to `0.5x`, keep the id it was handed, do the cheap
# work, and claim the deep fee, because nothing the requester signed named the
# depth. Every test would still pass, because every test that exists asserts a
# tier round-trips, not that changing it changes the id.
#
# That failure is not specific to one field. Any struct with a self-derived id
# has the same shape: the id is only a commitment to the fields it hashes, and
# a field left outside can be rewritten under a stable id. `ContentManifest`
# already carried the scar: its own doc records that `k` and `n` were outside
# the commitment until someone noticed that two manifests could disagree about
# redundancy at the same id, and whichever registered first would win, because
# registration is first-writer-wins.
#
# What the gate checks.
#
# For every production struct whose impl defines `verify_id`, every field other
# than the id itself must either
#
#   * be named in the derivation the id comes from, or
#   * carry `IDENTITY: excluded - <reason>` in its own doc comment.
#
# The marker sits on the field rather than in a central list for the same
# reason the wiring marker does: a central list is edited by whoever is adding
# an entry, and a doc comment is read by whoever next touches the field.
#
# The gate does not require full coverage. Leaving a field outside an id is
# sometimes right, `status` is mutable and cannot be inside an id that has to
# stay stable across a lifecycle. Leaving it outside silently is not.
#
# It also refuses the reverse: a field that is both marked excluded and named
# in the derivation. That marker is stale and now describes a binding that
# exists, which is the more dangerous direction to be wrong in, because the
# reader concludes there is a hole where there is none and may "fix" it by
# changing a consensus preimage.
#
# Known limits, stated so a pass is not read for more than it carries.
# Coverage is measured by name: a derivation that mentions `self.foo` counts
# `foo` as bound, and this gate cannot tell whether it was hashed, printed, or
# used in a length check. It measures that the field reached the function, not
# that it reached the digest. The narrower check is what the domain-tag
# inventory and the per-struct tests are for.
#
# Usage:
#   bash scripts/check-self-derived-ids-cover-every-field.sh              # gate
#   bash scripts/check-self-derived-ids-cover-every-field.sh --self-test  # canary
# ============================================================================
set -euo pipefail

ROOT="${BUDLUM_ROOT:-$(cd "$(dirname "$0")/.." && pwd)}"

scan() {
  python3 - "$1" <<'PY'
import os
import re
import sys

root = sys.argv[1]

SCAN_ROOTS = ("src", "budzero", "wallet-core")

MARKER = re.compile(r"IDENTITY:\s*excluded\b(.*)")


def strip_test_mods(src):
    """Remove `#[cfg(test)] mod ... { ... }` blocks, brace-matched.

    Test fixtures build these structs by hand all the time, and a fixture
    naming a field is not a derivation binding it.
    """
    out, i = [], 0
    while True:
        m = re.search(r"#\[cfg\(test\)\]\s*(?:pub\s+)?mod\s+\w+\s*\{", src[i:])
        if not m:
            out.append(src[i:])
            return "".join(out)
        start, brace = i + m.start(), i + m.end() - 1
        out.append(src[i:start])
        depth, j = 0, brace
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        i = j + 1


def balanced(src, open_at):
    """Return the text from `open_at` (an opening brace) to its match."""
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


def fn_bodies(src):
    """`{name: body}` for every function with a body in `src`.

    A regex that stops at the first brace-or-semicolon after the argument list
    looks like it would do this and does not: `-> [u8; 32]` contains a
    semicolon, so every function returning a
    fixed-size array is skipped. `calculate_id` returns exactly that, so the
    derivation came back empty and the gate accused every field of a struct
    whose id hashes all of them. Walk the signature instead of guessing at it.
    """
    bodies = {}
    for m in re.finditer(r"\bfn\s+(\w+)\s*\(", src):
        # Balance the argument list; a default value or a closure argument can
        # contain further parentheses.
        depth, j = 0, m.end() - 1
        while j < len(src):
            if src[j] == "(":
                depth += 1
            elif src[j] == ")":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        # Then the return type. `[u8; 32]` holds a semicolon and `Result<T, E>`
        # holds angle brackets, so the scan has to nest rather than stop at the
        # first delimiter it meets. The `>` of `->` is not a closing bracket
        # and must not be counted as one.
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
                bodies[m.group(1)] = balanced(src, j)
                break
            elif brackets == 0 and c == ";":
                break  # a signature with no body
            j += 1
    return bodies


def is_test_path(path):
    return (
        f"{os.sep}tests{os.sep}" in path
        or path.endswith("_tests.rs")
        or path.endswith(f"{os.sep}tests.rs")
    )


def struct_fields(body):
    """`[(name, doc)]` for each `pub` field, doc being the comment above it."""
    fields, doc = [], []
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith("///") or stripped.startswith("//"):
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


files = []
for scan_root in SCAN_ROOTS:
    base = os.path.join(root, scan_root)
    if not os.path.isdir(base):
        continue
    for dirpath, dirnames, filenames in os.walk(base):
        dirnames[:] = [d for d in dirnames if d not in (".git", "target", "node_modules")]
        for name in filenames:
            if name.endswith(".rs") and not is_test_path(os.path.join(dirpath, name)):
                files.append(os.path.join(dirpath, name))

if not files:
    print(f"FAIL: no production .rs files found under {root}", file=sys.stderr)
    sys.exit(2)

problems = []
checked_structs = 0
checked_fields = 0

for path in files:
    try:
        raw = open(path, encoding="utf-8", errors="ignore").read()
    except OSError as exc:
        print(f"FAIL: cannot read {path}: {exc}", file=sys.stderr)
        sys.exit(2)
    src = strip_test_mods(raw)
    if "fn verify_id" not in src:
        continue

    structs = {}
    for m in re.finditer(r"pub struct (\w+)\s*\{", src):
        structs[m.group(1)] = struct_fields(balanced(src, m.end() - 1))

    # Free functions in this file, so a derivation that delegates to one
    # (`manifest_id_from_parts`) is followed rather than counted as empty.
    helpers = fn_bodies(src)

    for m in re.finditer(r"impl\s+(\w+)\s*\{", src):
        name = m.group(1)
        if name not in structs:
            continue
        impl_body = balanced(src, m.end() - 1)
        vm = re.search(r"fn verify_id\s*\([^)]*\)[^{]*\{", impl_body)
        if not vm:
            continue

        # Every method of this impl plus every free function in the file that
        # `verify_id` reaches, transitively one level, which is as deep as any
        # derivation in this tree goes.
        methods = fn_bodies(impl_body)

        derivation = methods.get("verify_id", balanced(impl_body, vm.end() - 1))
        frontier = [derivation]
        seen = {"verify_id"}
        while frontier:
            text = frontier.pop()
            for called in set(re.findall(r"\b(\w+)\s*\(", text)):
                if called in seen:
                    continue
                if called in methods:
                    seen.add(called)
                    derivation += methods[called]
                    frontier.append(methods[called])
                elif called in helpers:
                    seen.add(called)
                    derivation += helpers[called]
                    frontier.append(helpers[called])

        fields = structs[name]
        if not fields:
            continue

        # The id field is whatever `verify_id` compares against, falling back
        # to the first field, which is the shape every one of these uses.
        idm = re.search(r"self\.(\w+)\s*(?:==|!=)", derivation)
        id_field = idm.group(1) if idm else fields[0][0]

        checked_structs += 1
        rel = os.path.relpath(path, root)

        for field, doc in fields:
            if field == id_field:
                continue
            checked_fields += 1
            bound = re.search(r"\bself\.%s\b" % re.escape(field), derivation) is not None
            declared = MARKER.search(doc)
            if not bound and not declared:
                problems.append(
                    f"{rel}: {name}.{field} is outside the id that {name}.{id_field} "
                    "commits to, and the field does not say so. Two values of this "
                    "struct can disagree about it under one id, and whichever is "
                    "stored first defines the entry. Hash it in the derivation, or "
                    "write `IDENTITY: excluded - <reason>` in the field's doc."
                )
            elif bound and declared:
                reason = declared.group(1).strip(" -\t")
                problems.append(
                    f"{rel}: {name}.{field} is marked `IDENTITY: excluded` "
                    f"({reason or 'no reason given'}) and the derivation does read "
                    "it. The marker is stale and now describes a hole that is "
                    "closed. Remove it in the commit that closed it."
                )

if not checked_structs:
    print(
        "FAIL: gate found no struct with a verify_id to measure - wrong root?",
        file=sys.stderr,
    )
    sys.exit(2)

if problems:
    for problem in problems:
        print(f"FAIL: {problem}", file=sys.stderr)
    sys.exit(1)

print(
    f"self-derived id gate OK: {checked_structs} structs with a verify_id, "
    f"{checked_fields} non-id fields each hashed into the id or declaring that "
    "they are not"
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

  mk() {
    local dir="$1" body="$2"
    rm -rf "$dir"
    mkdir -p "$dir/src"
    printf '%s\n' "$body" >"$dir/src/lib.rs"
  }

  # 1. Every field hashed: the healthy shape.
  mk "$tmp/covered" 'pub struct Req {
    pub id: [u8; 32],
    pub amount: u64,
    pub effort: u16,
}
impl Req {
    pub fn calculate_id(&self) -> [u8; 32] {
        let mut h = Vec::new();
        h.extend_from_slice(&self.amount.to_le_bytes());
        h.extend_from_slice(&self.effort.to_le_bytes());
        [h.len() as u8; 32]
    }
    pub fn verify_id(&self) -> bool {
        self.id == self.calculate_id()
    }
}'
  expect_pass "$tmp/covered" "a struct whose id hashes every field" || return 1

  # 2. The bug this gate exists for: a field added to the struct and not to
  #    the derivation, exactly the shape `effort` would have had.
  mk "$tmp/silent" 'pub struct Req {
    pub id: [u8; 32],
    pub amount: u64,
    pub effort: u16,
}
impl Req {
    pub fn calculate_id(&self) -> [u8; 32] {
        let mut h = Vec::new();
        h.extend_from_slice(&self.amount.to_le_bytes());
        [h.len() as u8; 32]
    }
    pub fn verify_id(&self) -> bool {
        self.id == self.calculate_id()
    }
}'
  expect_finding "$tmp/silent" "a field silently outside a self-derived id" || return 1

  # 3. Declared exclusion: honest, must pass.
  mk "$tmp/declared" 'pub struct Req {
    pub id: [u8; 32],
    pub amount: u64,
    /// IDENTITY: excluded - mutable across the lifecycle, cannot sit in a
    /// stable id.
    pub status: u8,
}
impl Req {
    pub fn calculate_id(&self) -> [u8; 32] {
        let mut h = Vec::new();
        h.extend_from_slice(&self.amount.to_le_bytes());
        [h.len() as u8; 32]
    }
    pub fn verify_id(&self) -> bool {
        self.id == self.calculate_id()
    }
}'
  expect_pass "$tmp/declared" "a declared exclusion with a reason" || return 1

  # 4. Stale marker on a field the derivation does read.
  mk "$tmp/stale" 'pub struct Req {
    pub id: [u8; 32],
    pub amount: u64,
    /// IDENTITY: excluded - left over from before it was bound.
    pub effort: u16,
}
impl Req {
    pub fn calculate_id(&self) -> [u8; 32] {
        let mut h = Vec::new();
        h.extend_from_slice(&self.amount.to_le_bytes());
        h.extend_from_slice(&self.effort.to_le_bytes());
        [h.len() as u8; 32]
    }
    pub fn verify_id(&self) -> bool {
        self.id == self.calculate_id()
    }
}'
  expect_finding "$tmp/stale" "a stale exclusion marker on a bound field" || return 1

  # 5. A derivation that delegates to a free function must be followed. This
  #    is `ContentManifest` calling `manifest_id_from_parts`; measuring only
  #    the method body would report every field missing and the only way to
  #    quiet it would be markers that say nothing true.
  mk "$tmp/delegated" 'pub struct Req {
    pub id: [u8; 32],
    pub amount: u64,
    pub effort: u16,
}
fn derive(amount: u64, effort: u16) -> [u8; 32] {
    [(amount as u8).wrapping_add(effort as u8); 32]
}
impl Req {
    pub fn verify_id(&self) -> bool {
        self.id == derive(self.amount, self.effort)
    }
}'
  expect_pass "$tmp/delegated" "a derivation delegating to a free function" || return 1

  # 6. A test fixture naming the field is not a derivation binding it. This is
  #    the shape that makes a hole look closed: every test constructs the
  #    struct with all its fields.
  rm -rf "$tmp/fixture"
  mkdir -p "$tmp/fixture/src"
  printf '%s\n' 'pub struct Req {
    pub id: [u8; 32],
    pub amount: u64,
    pub effort: u16,
}
impl Req {
    pub fn calculate_id(&self) -> [u8; 32] {
        [self.amount as u8; 32]
    }
    pub fn verify_id(&self) -> bool {
        self.id == self.calculate_id()
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn builds() {
        let r = Req { id: [0; 32], amount: 1, effort: 2 };
        assert_eq!(r.effort, 2);
        assert!(!r.verify_id());
    }
}' >"$tmp/fixture/src/lib.rs"
  expect_finding "$tmp/fixture" "a test fixture counted as an identity binding" || return 1

  # 7. A struct with no verify_id is not this gate's business. Reporting it
  #    would push markers onto every struct in the tree, and a marker written
  #    to silence a gate is worth nothing. One measurable struct keeps the run
  #    non-empty, so a pass here means "skipped politely" and not "measured
  #    nothing".
  mk "$tmp/no_verify" 'pub struct Plain {
    pub a: u64,
    pub b: u64,
}
pub struct Req {
    pub id: [u8; 32],
    pub amount: u64,
}
impl Req {
    pub fn calculate_id(&self) -> [u8; 32] {
        [self.amount as u8; 32]
    }
    pub fn verify_id(&self) -> bool {
        self.id == self.calculate_id()
    }
}'
  expect_pass "$tmp/no_verify" "a struct with no self-derived id" || return 1

  # 8. An empty tree must exit 2, not 0. A gate that passes when it measured
  #    nothing is the failure mode every canary here is guarding against.
  rm -rf "$tmp/empty"
  mkdir -p "$tmp/empty/src"
  printf '%s\n' 'pub fn nothing() {}' >"$tmp/empty/src/lib.rs"
  local rc=0
  ( scan "$tmp/empty" ) >/dev/null 2>&1 || rc=$?
  if [ "$rc" -ne 2 ]; then
    echo "GATE IS BROKEN: a tree with no verify_id exited $rc, expected 2." >&2
    return 1
  fi

  echo "self-derived id gate self-test OK: 8 canaries"
}

if [[ "${1:-}" == "--self-test" ]]; then
  self_test
else
  scan "$ROOT"
fi
