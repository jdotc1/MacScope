from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "native-decompiler-direct"))
import sleigh_package as package


class MultistageMaterializationFactsTests(unittest.TestCase):
    def test_record_creation_requires_derived_header_and_defined_accessor(self):
        toolchain = {
            "compiler": {"path": "/tool/clang", "sha256": "a" * 64, "version": "Apple clang version 21.0"},
            "cmake": {"path": "/tool/cmake", "sha256": "b" * 64, "version": "cmake version 4.4.3"},
            "ninja": {"path": "/tool/ninja", "sha256": "c" * 64, "version": "1.13.2"},
        }
        analysis = {"criticalFileSha256": {
            package.FIRST_PARTY_MULTISTAGE_HEADER: package.FIRST_PARTY_MULTISTAGE_HEADER_SHA256,
        }}
        with self.assertRaises(package.PackageContractError):
            package.source_materialization_value(analysis, toolchain, first_party=True)
        result = package.source_materialization_value(
            analysis, toolchain, first_party=True,
            defined_symbols={package.FIRST_PARTY_MULTISTAGE_GETTER_SYMBOL},
        )
        package.require_first_party_multistage_patch(result)


if __name__ == "__main__":
    unittest.main()
