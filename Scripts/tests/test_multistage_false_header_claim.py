from __future__ import annotations

import copy
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "native-decompiler-direct"))
import sleigh_package as package


class MultistageFalseHeaderClaimTests(unittest.TestCase):
    def test_strict_verifier_rejects_claimed_pin_when_analyzed_header_differs(self):
        toolchain = {
            "compiler": {"path": "/tool/clang", "sha256": "a" * 64, "version": "Apple clang version 21.0"},
            "cmake": {"path": "/tool/cmake", "sha256": "b" * 64, "version": "cmake version 4.4.3"},
            "ninja": {"path": "/tool/ninja", "sha256": "c" * 64, "version": "1.13.2"},
        }
        claimed_package = {
            "relativeRoot": "package",
            "cmakeConfigRelativePath": "lib/cmake/sleigh/sleighConfig.cmake",
            "processorSpecRelativeRoot": "share/sleigh/specfiles",
            "decompilerLibraryRelativePath": "lib/libdecomp.a",
            "sleighLibraryRelativePath": "lib/libsla.a",
            "fileCount": 10, "totalBytes": 100, "treeSha256": "d" * 64,
            "criticalFileSha256": {package.FIRST_PARTY_MULTISTAGE_HEADER:
                                   package.FIRST_PARTY_MULTISTAGE_HEADER_SHA256},
        }
        manifest = {
            "schemaVersion": package.SOURCE_SCHEMA_VERSION,
            "componentId": package.SOURCE_COMPONENT_ID,
            "sleighVersion": package.SLEIGH_VERSION,
            "sleighGitRevision": package.SLEIGH_GIT_REVISION,
            "ghidraVersion": package.GHIDRA_VERSION,
            "ghidraGitRevision": package.GHIDRA_GIT_REVISION,
            "sourceBuild": {**package._source_static_evidence(first_party=True), "toolchain": toolchain},
            "package": claimed_package,
        }
        analyzed = copy.deepcopy(claimed_package)
        del analyzed["relativeRoot"]
        analyzed["criticalFileSha256"][package.FIRST_PARTY_MULTISTAGE_HEADER] = "e" * 64
        root = Path("/synthetic")
        with patch.object(package, "_ordinary_directory", return_value=root), \
             patch.object(Path, "iterdir", return_value=iter([root / "package", root / "MATERIALIZATION.json"])), \
             patch.object(Path, "resolve", lambda path, strict=False: path), \
             patch.object(package, "_load_manifest", return_value=manifest), \
             patch.object(package, "analyze_package", return_value=analyzed) as analyze:
            with self.assertRaisesRegex(package.PackageContractError, "materialized multistage header"):
                package.verify_materialization(root)
            self.assertEqual(analyze.call_count, 1)


if __name__ == "__main__":
    unittest.main()
