#!/usr/bin/env python3
"""Check that the iOS class parameters equal the Rust ones.

`crates/budlum-types/src/class.rs` (WP-11) is the single definition of the
validator class and its per-class numbers: the node, the Android app and this
app all read it. `Sources/BudlumValidatorKit/ValidatorClass.swift` carries a
reference copy so the app runs before that crate is in the same branch, and a
copy left unchecked is how a phone and a node come to disagree about a
suspension threshold.

This script parses both sides and compares them. It never prints a number it
did not read from one of the two files.

Exit status
    0   the two agree, or the Rust crate is not in this tree (reported, not
        failed: this branch must not be blocked on WP-11)
    1   the two disagree; every difference is printed
    2   a file is missing or unparsable

Usage
    python3 mobile/ios/Scripts/check_class_parity.py [--repo ROOT]
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

RUST_REL = Path("crates/budlum-types/src/class.rs")
SWIFT_REL = Path("mobile/ios/Sources/BudlumValidatorKit/ValidatorClass.swift")

# The three classes, in the order the Rust enum declares them.
CLASSES = ("full", "mobile", "mobileOpportunistic")

# A match arm inside a Rust `fn`. The left side may be an alternation, e.g.
# `Self::Mobile | Self::MobileOpportunistic => 4,`, and then the value belongs
# to every class named on it.
RUST_ARM = re.compile(
    r"^\s*(?P<arms>Self::\w+(?:\s*\|\s*Self::\w+)*)\s*=>\s*(?P<value>.+?),?\s*$"
)
# The Swift reference table entry, e.g. `.full: ClassParameters(` ... `),`.
SWIFT_ENTRY = re.compile(
    r"\.(?P<class>full|mobile|mobileOpportunistic):\s*ClassParameters\((?P<body>.*?)\n\s*\)",
    re.DOTALL,
)
SWIFT_FIELD = re.compile(r"(?P<key>\w+):\s*(?P<value>[^\n,]+),?")
SWIFT_CONST = re.compile(
    r"public static let (?P<name>\w+):\s*UInt64\s*=\s*(?P<value>[^\n]+?)\s*$", re.MULTILINE
)
SWIFT_TAG = re.compile(r"case \.(?P<class>full|mobile|mobileOpportunistic): return (?P<value>\d+)")
RUST_CONST = re.compile(
    r"pub const (?P<name>[A-Z_]+):\s*u64\s*=\s*(?P<value>[^;]+);"
)


class ParseError(Exception):
    """A file does not look like the file it is supposed to be."""


def eval_int(expression: str) -> int:
    """Evaluate an integer literal built from digits, spaces, `*`, `+` and parens.

    `eval` is not used: this reads two source files that a pull request can
    change, and the only arithmetic either of them needs is the byte-count
    product that writes a size constant.
    """
    text = expression.strip().replace("_", "")
    if not text:
        raise ParseError(f"empty integer expression")
    pos = 0

    def parse_atom() -> int:
        nonlocal pos
        while pos < len(text) and text[pos] == " ":
            pos += 1
        if pos < len(text) and text[pos] == "(":
            pos += 1
            value = parse_sum()
            while pos < len(text) and text[pos] == " ":
                pos += 1
            if pos >= len(text) or text[pos] != ")":
                raise ParseError(f"unbalanced parenthesis in {expression!r}")
            pos += 1
            return value
        start = pos
        while pos < len(text) and text[pos].isdigit():
            pos += 1
        if start == pos:
            raise ParseError(f"not an integer literal: {expression!r}")
        return int(text[start:pos])

    def parse_product() -> int:
        nonlocal pos
        value = parse_atom()
        while True:
            saved = pos
            while pos < len(text) and text[pos] == " ":
                pos += 1
            if pos < len(text) and text[pos] == "*":
                pos += 1
                value *= parse_atom()
            else:
                pos = saved
                return value

    def parse_sum() -> int:
        nonlocal pos
        value = parse_product()
        while True:
            saved = pos
            while pos < len(text) and text[pos] == " ":
                pos += 1
            if pos < len(text) and text[pos] == "+":
                pos += 1
                value += parse_product()
            else:
                pos = saved
                return value

    result = parse_sum()
    while pos < len(text) and text[pos] == " ":
        pos += 1
    if pos != len(text):
        raise ParseError(f"trailing text in {expression!r}: {text[pos:]!r}")
    return result


def rust_function_body(source: str, name: str) -> str:
    """Return the body of `fn <name>(self)`."""
    marker = f"fn {name}("
    start = source.find(marker)
    if start < 0:
        raise ParseError(f"no `fn {name}` in the Rust class module")
    open_brace = source.find("{", start)
    if open_brace < 0:
        raise ParseError(f"`fn {name}` has no body")
    depth = 0
    for index in range(open_brace, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[open_brace + 1 : index]
    raise ParseError(f"`fn {name}` is not closed")


def swift_name(rust_variant: str) -> str:
    """`MobileOpportunistic` -> `mobileOpportunistic`: the Swift enum cases are
    the Rust variants with the first letter lowered."""
    if not rust_variant:
        raise ParseError("empty Rust variant name")
    return rust_variant[0].lower() + rust_variant[1:]


def rust_arms(source: str, function: str) -> dict[str, str]:
    """The match arms of one Rust function, as `{swift class name: raw value}`.

    An arm naming several variants at once (`Self::Mobile |
    Self::MobileOpportunistic => 4`) is recorded against each of them, because
    that is what the Rust means.
    """
    body = rust_function_body(source, function)
    arms: dict[str, str] = {}
    for line in body.splitlines():
        match = RUST_ARM.match(line)
        if not match:
            continue
        value = match.group("value").strip()
        for variant in match.group("arms").split("|"):
            variant = variant.strip()
            if variant.startswith("Self::"):
                arms[swift_name(variant[len("Self::") :])] = value
    if not arms:
        raise ParseError(f"`fn {function}` has no readable match arm")
    return arms


def rust_constants(source: str) -> dict[str, int]:
    consts: dict[str, int] = {}
    for match in RUST_CONST.finditer(source):
        consts[match.group("name")] = eval_int(match.group("value"))
    return consts


def parse_rust(path: Path) -> dict[str, object]:
    source = path.read_text(encoding="utf-8")
    consts = rust_constants(source)
    tags = {k: int(v) for k, v in rust_arms(source, "tag").items()}
    presence = {k: eval_int(v) for k, v in rust_arms(source, "presence_window_epochs").items()}
    suspension = {k: eval_int(v) for k, v in rust_arms(source, "suspension_hours").items()}
    audit = {k: v for k, v in rust_arms(source, "audit_window").items()}
    return {
        "quota_ceiling": consts.get("MOBILE_OPPORTUNISTIC_MAX_QUOTA_BYTES"),
        "tag": tags,
        "presence_window_epochs": presence,
        "suspension_hours": suspension,
        "audit_window": audit,
    }


def swift_reference_table(source: str) -> dict[str, dict[str, str]]:
    table: dict[str, dict[str, str]] = {}
    for match in SWIFT_ENTRY.finditer(source):
        fields: dict[str, str] = {}
        for field in SWIFT_FIELD.finditer(match.group("body")):
            fields[field.group("key")] = field.group("value").strip()
        table[match.group("class")] = fields
    if len(table) != len(CLASSES):
        raise ParseError(
            f"the Swift reference table holds {len(table)} entries, expected {len(CLASSES)}"
        )
    return table


def parse_swift(path: Path) -> dict[str, object]:
    source = path.read_text(encoding="utf-8")
    table = swift_reference_table(source)
    consts: dict[str, int] = {}
    for match in SWIFT_CONST.finditer(source):
        consts[match.group("name")] = eval_int(match.group("value"))

    tags: dict[str, int] = {}
    for match in SWIFT_TAG.finditer(source):
        tags[match.group("class")] = int(match.group("value"))

    presence: dict[str, int] = {}
    suspension: dict[str, int] = {}
    audit: dict[str, str] = {}
    for name, entry in table.items():
        presence[name] = eval_int(entry.get("presenceWindowEpochs", ""))
        suspension[name] = eval_int(entry.get("suspensionHours", ""))
        raw = entry.get("auditWindow", "").strip()
        if raw.startswith(".epochs("):
            audit[name] = f"AuditWindow::Epochs({eval_int(raw[len('.epochs('):-1])})"
        elif raw.startswith(".hours("):
            audit[name] = f"AuditWindow::Hours({eval_int(raw[len('.hours('):-1])})"
        else:
            raise ParseError(f"unreadable auditWindow for {name}: {raw!r}")

    ceilings: dict[str, int | None] = {}
    for name, entry in table.items():
        raw = entry.get("maxCustodyQuotaBytes", "nil").strip()
        if raw == "nil":
            ceilings[name] = None
        elif raw == "ClassParameters.iosQuotaCeilingBytes":
            ceilings[name] = consts.get("iosQuotaCeilingBytes")
        else:
            ceilings[name] = eval_int(raw)

    return {
        "quota_ceiling": consts.get("iosQuotaCeilingBytes"),
        "tag": tags,
        "presence_window_epochs": presence,
        "suspension_hours": suspension,
        "audit_window": audit,
        "ceilings": ceilings,
    }


def compare(rust: dict[str, object], swift: dict[str, object]) -> list[str]:
    differences: list[str] = []
    if rust["quota_ceiling"] != swift["quota_ceiling"]:
        differences.append(
            f"MOBILE_OPPORTUNISTIC_MAX_QUOTA_BYTES: Rust {rust['quota_ceiling']} "
            f"!= Swift iosQuotaCeilingBytes {swift['quota_ceiling']}"
        )

    for key, label in (
        ("tag", "tag"),
        ("presence_window_epochs", "presenceWindowEpochs"),
        ("suspension_hours", "suspensionHours"),
        ("audit_window", "auditWindow"),
    ):
        for name in CLASSES:
            rust_value = rust[key].get(name)  # type: ignore[union-attr]
            swift_value = swift[key].get(name)  # type: ignore[union-attr]
            if rust_value != swift_value:
                differences.append(f"{name}.{label}: Rust {rust_value} != Swift {swift_value}")

    ceilings = swift["ceilings"]  # type: ignore[assignment]
    for name in CLASSES:
        expected = rust["quota_ceiling"] if name == "mobileOpportunistic" else None
        if ceilings.get(name) != expected:
            differences.append(
                f"{name}.maxCustodyQuotaBytes: Swift {ceilings.get(name)} "
                f"!= expected {expected}"
            )
    return differences


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="repository root")
    args = parser.parse_args()

    root = Path(args.repo).resolve()
    rust_path = root / RUST_REL
    swift_path = root / SWIFT_REL

    if not swift_path.is_file():
        print(f"FAIL: the Swift class module is missing: {SWIFT_REL}", file=sys.stderr)
        return 2

    if not rust_path.is_file():
        print(
            f"SKIP: {RUST_REL} is not in this tree, so there is nothing to compare "
            f"against yet. WP-11 lands that crate; until then "
            f"`ValidatorClass.swift` is the only copy and this check reports "
            f"green without checking anything. That is the honest result, not a "
            f"pass: it is recorded in the PR body rather than hidden."
        )
        return 0

    try:
        rust = parse_rust(rust_path)
        swift = parse_swift(swift_path)
    except ParseError as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 2

    differences = compare(rust, swift)
    if differences:
        print(
            "FAIL: the iOS class parameters disagree with "
            f"{RUST_REL}. The Rust crate is the definition; fix the Swift side."
        )
        for difference in differences:
            print(f"  - {difference}")
        return 1

    print(
        f"OK: {SWIFT_REL} matches {RUST_REL} on every class parameter "
        f"({len(CLASSES)} classes, 4 fields each, plus the quota ceiling)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
