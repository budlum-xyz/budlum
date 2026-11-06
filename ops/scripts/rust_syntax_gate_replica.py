#!/usr/bin/env python3
"""Local replica of the `rust-syntax-is-parseable` gate.

This workspace has no Rust toolchain, so the wired Rust gate cannot be executed
here. The replica is a line-for-line transcription of
`xtask/gates/src/gates/rust_syntax_is_parseable.rs`. It exists to show that the
gate's heuristics do not reject the live tree and do reject each defect class
found on the open PR heads. It is a verification aid, not a second gate and not
a CI authority: CI runs the Rust version through `--all`.

Usage:
    python3 ops/scripts/rust_syntax_gate_replica.py [ROOT ...]
    python3 ops/scripts/rust_syntax_gate_replica.py --self-test

With no ROOT, the repository's Rust roots are scanned. Exit status is 1 when a
finding exists, 0 otherwise.
"""

from __future__ import annotations

import pathlib
import sys

ROOTS = [
    "src", "crates", "budzero", "bud", "xtask", "tests", "examples",
    "benches", "fuzz", "mobile", "execution", "contracts", "ops",
]
SKIP = {".git", "target", "node_modules", "Unselected files", "build", "dist"}
ITEM_PREFIXES = (
    "fn ", "pub ", "async ", "const ", "unsafe ", "extern ", "mod ",
    "struct ", "enum ", "impl", "trait ", "type ", "static ", "use ",
    "macro_rules!", "#[", "fn", "///", "//!",
)


def strip_literals(text: str) -> list[str]:
    """Replace string, char and comment bytes with spaces, keeping lines.

    The scanner is stateful: raw strings and block comments can span lines,
    and a per-line reset reads their braces as code (315 false positives on
    the first version of this gate).
    """
    b = text.encode("utf-8", "surrogateescape")
    out = bytearray()
    i, n = 0, len(b)
    state = "code"
    hashes = 0
    depth = 0
    while i < n:
        if state == "code":
            if b[i] == 10:
                out.append(10)
                i += 1
            elif i + 1 < n and b[i:i + 2] == b"//":
                out += b"  "
                i += 2
                while i < n and b[i] != 10:
                    out.append(32)
                    i += 1
            elif i + 1 < n and b[i:i + 2] == b"/*":
                out += b"  "
                i += 2
                state, depth = "block", 1
            else:
                j = i
                if b[j] == ord("b") and j + 1 < n and b[j + 1] == ord("r"):
                    j += 1
                if b[j] == ord("r"):
                    k = j + 1
                    while k < n and b[k] == ord("#"):
                        k += 1
                    if k < n and b[k] == ord('"'):
                        hashes = k - (j + 1)
                        out += b" " * (k + 1 - i)
                        i = k + 1
                        state = "raw"
                        continue
                if b[i] == ord('"'):
                    out.append(32)
                    i += 1
                    state = "str"
                elif b[i] == ord("'"):
                    closes = (i + 2 < n and b[i + 2] == ord("'")) or (
                        i + 3 < n and b[i + 1] == ord("\\") and b[i + 3] == ord("'")
                    )
                    if closes:
                        end = i + 4 if b[i + 1] == ord("\\") else i + 3
                        out += b" " * (min(end, n) - i)
                        i = min(end, n)
                    else:
                        out.append(b[i])
                        i += 1
                else:
                    out.append(b[i])
                    i += 1
        elif state == "block":
            if i + 1 < n and b[i:i + 2] == b"/*":
                out += b"  "
                i += 2
                depth += 1
            elif i + 1 < n and b[i:i + 2] == b"*/":
                out += b"  "
                i += 2
                depth -= 1
                if depth == 0:
                    state = "code"
            else:
                out.append(10 if b[i] == 10 else 32)
                i += 1
        elif state == "str":
            if b[i] == ord("\\"):
                out.append(32)
                i += 1
                if i < n:
                    out.append(10 if b[i] == 10 else 32)
                    i += 1
            elif b[i] == 10:
                # Rust string literals may span lines; stay in the string.
                out.append(10)
                i += 1
            else:
                out.append(32)
                closing = b[i] == ord('"')
                i += 1
                if closing:
                    state = "code"
        else:  # raw
            if b[i] == ord('"') and i + 1 + hashes <= n and all(
                b[i + 1 + h] == ord("#") for h in range(hashes)
            ):
                out += b" " * (1 + hashes)
                i += 1 + hashes
                state = "code"
            else:
                out.append(10 if b[i] == 10 else 32)
                i += 1
    return out.decode("utf-8", "replace").splitlines()

def is_test_attr(t: str) -> bool:
    if not (t.startswith("#[") and t.endswith("]")):
        return False
    inner = t[2:-1]
    name = inner.split("(")[0].split(",")[0].split(" ")[0]
    return name == "test" or name.endswith("::test") or name.startswith("test_case")


def is_item_start(t: str) -> bool:
    return t.startswith(ITEM_PREFIXES)


def findings(text: str) -> list[str]:
    code = strip_literals(text)
    raw = text.splitlines()
    out: list[str] = []
    stack: list[tuple[str, int]] = []
    depth = 0
    pending_test_attr: int | None = None
    previous_self_dot = False
    for idx, line in enumerate(code):
        lineno = idx + 1
        t = line.strip()
        start_depth = depth
        if pending_test_attr is not None and t:
            if not is_item_start(t):
                out.append(f"{pending_test_attr}: test attribute is followed by `{t[:24]}`, not a function")
            pending_test_attr = None
        if is_test_attr(t):
            pending_test_attr = lineno
        if previous_self_dot and (t.startswith(".") or not t):
            out.append(f"{lineno}: method name after `self.` is missing")
        previous_self_dot = t.endswith("self.")
        raw_t = raw[idx].lstrip() if idx < len(raw) else ""
        if raw_t.startswith("f//"):
            out.append(f"{lineno}: stray `f` prefix on a comment line")
        if start_depth == 0:
            if len(t) == 1 and t.isascii() and t.isalpha():
                out.append(f"{lineno}: lone identifier `{t}` at module level")
            candidate = t[:-1].strip() if t.endswith(",") else ""
            previous = next((l.strip() for l in reversed(code[:idx]) if l.strip()), "")
            after_item_close = previous.endswith("}") or previous.endswith("};")
            if (
                candidate
                and after_item_close
                and candidate.replace("_", "").isalnum()
                and candidate[0].isupper()
            ):
                out.append(f"{lineno}: enum variant `{candidate}` outside an enum")
        for c in line:
            if c in "([{":
                stack.append((c, lineno))
                depth += 1
            elif c in ")]}":
                expected = {")": "(", "]": "[", "}": "{"}[c]
                if stack:
                    open_c, at = stack.pop()
                    depth -= 1
                    if open_c != expected:
                        out.append(f"{lineno}: closing `{c}` does not match `{open_c}` opened at line {at}")
                else:
                    out.append(f"{lineno}: unmatched closing `{c}`")
    if pending_test_attr is not None:
        out.append(f"{pending_test_attr}: test attribute at end of file has no function")
    for open_c, at in stack:
        out.append(f"{at}: `{open_c}` is never closed")
    return sorted(set(out))


def rust_files(roots: list[pathlib.Path]) -> list[pathlib.Path]:
    out = []
    for root in roots:
        if not root.exists():
            continue
        for path in root.rglob("*.rs"):
            if not SKIP.intersection(path.parts):
                out.append(path)
    return sorted(set(out))


def self_test() -> int:
    clean = (
        "//! A string with { and ( and a comment // }\n"
        "pub fn answer() -> u64 {\n    let x = vec![1, 2, 3];\n    x.iter().sum()\n}\n\n"
        "#[test]\nfn answer_is_42() {\n    assert_eq!(answer(), 6);\n}\n"
    )
    bad = {
        "lone f after test attribute": "#[test]\nf\nfn orphan() {}\n",
        "unclosed brace": "pub fn f() { let _ = 1; \n",
        "deleted method name": "pub struct S;\nimpl Clone for S {\n fn clone(&self) -> Self {\n  self.\n   .clone()\n }\n}\n",
        "stray f doc prefix": "f/// a mangled doc line\npub fn g() {}\n",
        "orphan enum variant": "pub enum E { A }\nBud3NotReady,\npub fn g() -> u8 { 0 }\n",
    }
    assert not findings(clean), f"clean source refused: {findings(clean)}"
    for name, source in bad.items():
        assert findings(source), f"canary accepted: {name}"
    comments = (
        "/// { [ ( unmatched on purpose\n"
        "pub fn g() -> &'static str { \"}}} {{{ \" }\n"
    )
    assert not findings(comments), f"literals scanned as code: {findings(comments)}"
    print("rust-syntax gate replica self-test OK: 5 defect classes refused, clean tree accepted")
    return 0


def main() -> int:
    if "--self-test" in sys.argv:
        return self_test()
    repo = pathlib.Path(__file__).resolve().parents[2]
    roots = [pathlib.Path(a) for a in sys.argv[1:]] or [repo / r for r in ROOTS]
    files = rust_files(roots)
    hits = []
    for path in files:
        if path.stat().st_size > 4 * 1024 * 1024:
            continue
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            continue
        for f in findings(text):
            hits.append(f"{path.relative_to(repo) if path.is_relative_to(repo) else path}:{f}")
    print(f"scanned {len(files)} Rust files, {len(hits)} structural findings")
    for h in hits[:40]:
        print("  " + h)
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
