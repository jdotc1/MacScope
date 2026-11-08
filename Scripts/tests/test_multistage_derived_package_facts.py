from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "native-decompiler-direct"))
import sleigh_package as package


class MultistageDerivedPackageFactsTests(unittest.TestCase):
    def test_refuses_falsely_relabeled_old_or_partial_package(self):
        actual_header = {"criticalFileSha256": {
            package.FIRST_PARTY_MULTISTAGE_HEADER: package.FIRST_PARTY_MULTISTAGE_HEADER_SHA256,
        }}
        symbol = package.FIRST_PARTY_MULTISTAGE_GETTER_SYMBOL
        package.require_multistage_package_facts(actual_header, {symbol})
        for header, symbols in (
            ({"criticalFileSha256": {}}, {symbol}),
            ({"criticalFileSha256": {package.FIRST_PARTY_MULTISTAGE_HEADER: "a" * 64}}, {symbol}),
            (actual_header, set()),
        ):
            with self.subTest(header=header, symbols=symbols):
                with self.assertRaises(package.PackageContractError):
                    package.require_multistage_package_facts(header, symbols)
        record = {"sourceBuild": {"patches": [{"path": package.FIRST_PARTY_MULTISTAGE_PATCH[0],
                                                  "sha256": package.FIRST_PARTY_MULTISTAGE_PATCH[1]}]},
                  "package": actual_header}
        package.require_first_party_multistage_patch(record)
        record["package"] = {"criticalFileSha256": {}}
        with self.assertRaises(package.PackageContractError):
            package.require_first_party_multistage_patch(record)


if __name__ == "__main__":
    unittest.main()
