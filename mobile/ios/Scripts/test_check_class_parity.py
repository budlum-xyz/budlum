#!/usr/bin/env python3

import tempfile
import unittest
from pathlib import Path

import check_class_parity as parity


class ClassParityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = Path(__file__).resolve().parents[3]
        cls.rust = parity.parse_rust(cls.root / parity.RUST_REL)
        cls.swift_source = (cls.root / parity.SWIFT_REL).read_text(encoding="utf-8")
        cls.swift = parity.parse_swift(cls.root / parity.SWIFT_REL)

    def test_current_tree_agrees(self):
        self.assertEqual(parity.compare(self.rust, self.swift), [])

    def test_quota_mutation_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            mutated = Path(directory) / "engine.swift"
            mutated.write_text(self.swift_source.replace("8 * gib", "9 * gib", 1))
            differences = parity.compare(self.rust, parity.parse_swift(mutated))
        self.assertTrue(any("quota" in difference for difference in differences))

    def test_missing_audit_constant_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            mutated = Path(directory) / "engine.swift"
            lines = self.swift_source.splitlines()
            lines = [line for line in lines if "public static let auditWindowHours" not in line]
            mutated.write_text("\n".join(lines))
            with self.assertRaises(parity.ParityError):
                parity.parse_swift(mutated)

    def test_integer_parser_rejects_code_execution(self):
        with self.assertRaises(parity.ParityError):
            parity.integer("__import__('os').system('false')")


if __name__ == "__main__":
    unittest.main()
