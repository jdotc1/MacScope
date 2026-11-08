from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "native-decompiler-direct"))
import sleigh_package as package


class MultistagePatchAdmissionTests(unittest.TestCase):
    def test_exact_overlay_is_distinct_from_legacy_and_tampered_records(self):
        toolchain = {
            "compiler": {"path": "/tool/clang", "sha256": "a" * 64, "version": "Apple clang version 21.0"},
            "cmake": {"path": "/tool/cmake", "sha256": "b" * 64, "version": "cmake version 4.4.3"},
            "ninja": {"path": "/tool/ninja", "sha256": "c" * 64, "version": "1.13.2"},
        }
        patched = {**package._source_static_evidence(first_party=True), "toolchain": toolchain}
        package._validate_source_build(patched)
        derived = {"criticalFileSha256": {package.FIRST_PARTY_MULTISTAGE_HEADER:
                                          package.FIRST_PARTY_MULTISTAGE_HEADER_SHA256}}
        package.require_first_party_multistage_patch({"sourceBuild": patched, "package": derived})
        legacy = {**package._source_static_evidence(), "toolchain": toolchain}
        package._validate_source_build(legacy)
        with self.assertRaises(package.PackageContractError):
            package.require_first_party_multistage_patch({"sourceBuild": legacy})
        altered = copy.deepcopy(patched)
        altered["patches"][-1]["sha256"] = "f" * 64
        with self.assertRaises(package.PackageContractError):
            package._validate_source_build(altered)
        with self.assertRaises(package.PackageContractError):
            package.require_first_party_multistage_patch({"sourceBuild": altered})
        with self.assertRaises(package.PackageContractError):
            package.require_first_party_multistage_patch({})


if __name__ == "__main__":
    unittest.main()
