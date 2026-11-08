"""Regression tests for the inventory scanner's accounting."""
import tempfile
import unittest
from pathlib import Path

from storage_inventory import count_mentions


class StorageInventoryTest(unittest.TestCase):
    def test_counts_files_and_whole_tokens(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.rs").write_text("OpenDeal OpenDeal OpenDealExtra\n", encoding="utf-8")
            (root / "b.md").write_text("OpenDeal\n", encoding="utf-8")
            (root / "binary").write_bytes(b"\xff")
            result = count_mentions(root, [Path("a.rs"), Path("b.md"), Path("binary")], ["OpenDeal", "Missing"])
            self.assertEqual(result["OpenDeal"], [2, 3])
            self.assertEqual(result["Missing"], [0, 0])


if __name__ == "__main__":
    unittest.main()
