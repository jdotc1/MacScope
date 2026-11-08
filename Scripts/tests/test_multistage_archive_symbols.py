from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "native-decompiler-direct"))
import sleigh_package as package


class MultistageArchiveSymbolTests(unittest.TestCase):
    def test_requires_defined_text_symbol_in_nm_output(self):
        symbol = package.FIRST_PARTY_MULTISTAGE_GETTER_SYMBOL
        for text in (f"                 U {symbol}\n", f"0000000000000000 D {symbol}\n", "archive.o:\n"):
            with self.subTest(text=text):
                self.assertNotIn(symbol, package.defined_archive_text_symbols(text))
        output = f"libdecomp.a(architecture.o):\n0000000000000040 T {symbol}\n"
        self.assertIn(symbol, package.defined_archive_text_symbols(output))


if __name__ == "__main__":
    unittest.main()
