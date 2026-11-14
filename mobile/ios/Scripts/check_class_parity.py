#!/usr/bin/env python3
"""Fail when the current iOS custody constants drift from budlum-types."""

from __future__ import annotations

import argparse
import ast
import re
import sys
from pathlib import Path

RUST_REL = Path("crates/budlum-types/src/class.rs")
SWIFT_REL = Path("mobile/ios/Sources/BudlumValidator/OpportunisticValidatorEngine.swift")


class ParityError(Exception):
    """A required source declaration is absent or not an integer expression."""


def integer(expression: str, constants: dict[str, int] | None = None) -> int:
    """Evaluate only integer literals, names, addition, multiplication and shifts."""

    constants = constants or {}
    try:
        tree = ast.parse(expression.replace("_", "").strip(), mode="eval")
    except SyntaxError as error:
        raise ParityError(f"invalid integer expression: {expression!r}") from error

    def evaluate(node: ast.AST) -> int:
        if isinstance(node, ast.Expression):
            return evaluate(node.body)
        if isinstance(node, ast.Constant) and type(node.value) is int:
            return node.value
        if isinstance(node, ast.Name) and node.id in constants:
            return constants[node.id]
        if isinstance(node, ast.BinOp) and isinstance(
            node.op, (ast.Add, ast.Mult, ast.LShift, ast.RShift)
        ):
            left, right = evaluate(node.left), evaluate(node.right)
            if isinstance(node.op, ast.Add):
                return left + right
            if isinstance(node.op, ast.Mult):
                return left * right
            if right < 0:
                raise ParityError("negative shift")
            return left << right if isinstance(node.op, ast.LShift) else left >> right
        raise ParityError(f"unsupported integer expression: {expression!r}")

    return evaluate(tree)


def function_body(source: str, name: str) -> str:
    match = re.search(rf"\bfn\s+{re.escape(name)}\s*\(", source)
    if not match:
        raise ParityError(f"missing Rust function {name}")
    opening = source.find("{", match.end())
    if opening < 0:
        raise ParityError(f"Rust function {name} has no body")
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : index]
    raise ParityError(f"Rust function {name} is not closed")


def parse_rust(path: Path) -> dict[str, object]:
    source = path.read_text(encoding="utf-8")
    quota = re.search(
        r"pub const MOBILE_OPPORTUNISTIC_MAX_QUOTA_BYTES:\s*u64\s*=\s*([^;]+);", source
    )
    if not quota:
        raise ParityError("missing Rust opportunistic quota ceiling")
    tag = re.search(
        r"Self::MobileOpportunistic\s*=>\s*(\d+)", function_body(source, "tag")
    )
    suspension = re.search(
        r"Self::MobileOpportunistic\s*=>\s*(\d+)",
        function_body(source, "suspension_hours"),
    )
    audit = re.search(
        r"Self::MobileOpportunistic\s*=>\s*AuditWindow::Hours\((\d+)\)",
        function_body(source, "audit_window"),
    )
    if not all((tag, suspension, audit)):
        raise ParityError("incomplete Rust MobileOpportunistic parameters")
    if not re.search(r"\bMobileOpportunistic\b", source):
        raise ParityError("Rust MobileOpportunistic variant is missing")
    return {
        "class_name": "MobileOpportunistic",
        "tag": int(tag.group(1)),
        "quota": integer(quota.group(1)),
        "audit_hours": int(audit.group(1)),
        "suspension_hours": int(suspension.group(1)),
    }


def parse_swift(path: Path) -> dict[str, object]:
    source = path.read_text(encoding="utf-8")
    declarations = re.findall(
        r"public static let (\w+):\s*UInt(?:32|64)\s*=\s*([^\n]+)", source
    )
    constants: dict[str, int] = {}
    for name, expression in declarations:
        constants[name] = integer(expression, constants)
    required = (
        "registrationTag",
        "maxQuotaBytes",
        "auditWindowHours",
        "suspensionOfflineHours",
    )
    missing = [name for name in required if name not in constants]
    if missing:
        raise ParityError(f"missing Swift constants: {', '.join(missing)}")
    registration = re.search(
        r'case mobileOpportunistic\s*=\s*"(MobileOpportunistic)"', source
    )
    if not registration:
        raise ParityError("Swift MobileOpportunistic registration is missing")
    return {
        "class_name": registration.group(1),
        "tag": constants["registrationTag"],
        "quota": constants["maxQuotaBytes"],
        "audit_hours": constants["auditWindowHours"],
        "suspension_hours": constants["suspensionOfflineHours"],
    }


def compare(rust: dict[str, object], swift: dict[str, object]) -> list[str]:
    return [
        f"{key}: Rust {rust[key]!r} != Swift {swift[key]!r}"
        for key in ("class_name", "tag", "quota", "audit_hours", "suspension_hours")
        if rust[key] != swift[key]
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo", default=".", help="repository root")
    args = parser.parse_args()
    root = Path(args.repo).resolve()
    try:
        rust = parse_rust(root / RUST_REL)
        swift = parse_swift(root / SWIFT_REL)
    except (OSError, UnicodeError, ParityError, SyntaxError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 2
    differences = compare(rust, swift)
    if differences:
        print("FAIL: iOS/Rust class parity drift", file=sys.stderr)
        for difference in differences:
            print(f"  - {difference}", file=sys.stderr)
        return 1
    print("OK: iOS class name, tag, quota, audit and suspension match budlum-types")
    return 0


if __name__ == "__main__":
    sys.exit(main())
