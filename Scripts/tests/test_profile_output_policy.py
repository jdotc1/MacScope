"""Item 1247 static-source regression controls. All cases authored, NOT RUN."""
from __future__ import annotations

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[2]


class ProfileOutputPolicyTests(unittest.TestCase):
    def read(self, relative: str) -> str:
        return (ROOT / relative).read_text(encoding="utf-8")

    def test_both_client_debug_builds_explicitly_disable_coverage(self) -> None:
        for relative in ("MacScope/script/build_and_run.sh", "Scripts/build_unsigned_development.sh"):
            with self.subTest(script=relative):
                script = self.read(relative)
                self.assertEqual(script.count("ENABLE_CODE_COVERAGE=NO"), 1)
                self.assertNotIn("-enableCodeCoverage", script)
                self.assertRegex(script, r"xcodebuild build \\\n(?:[^\n]*\\\n)*?"
                                 r"\s+ENABLE_CODE_COVERAGE=NO \\\n")
                self.assertNotIn("ENABLE_CODE_COVERAGE=YES", script)
        self.assertIn('CONFIGURATION="${MACSCOPE_CONFIGURATION:-Debug}"',
                      self.read("MacScope/script/build_and_run.sh"))
        self.assertIn("-configuration Debug", self.read("Scripts/build_unsigned_development.sh"))

    def test_full_test_sets_the_same_build_setting_to_yes_on_all_three_actions(self) -> None:
        script = self.read("Scripts/qualify_local_private_build.sh")
        start = script.index("  full-test)")
        full = script[start:script.index("    ;;", start)]
        self.assertEqual(script.count("ENABLE_CODE_COVERAGE=YES"), 3)
        self.assertEqual(full.count("ENABLE_CODE_COVERAGE=YES"), 3)
        self.assertRegex(full, r"-configuration Debug -enableCodeCoverage YES\s*\\\n\s*ENABLE_CODE_COVERAGE=YES build-for-testing")
        self.assertIn("-enableCodeCoverage YES ENABLE_CODE_COVERAGE=YES", full)
        self.assertRegex(full, r"CORE_TESTS_OPTIONS=\(-scheme MacScopeApp -configuration Debug -enableCodeCoverage YES\n\s*ENABLE_CODE_COVERAGE=YES")
        self.assertEqual(script.count("-enableCodeCoverage YES"), 3)
        self.assertEqual(script.count("CLANG_COVERAGE_MAPPING=NO"), 2)
        self.assertIn('COVERAGE_JSON="${RUN_ROOT}/COVERAGE.json"', full)
        self.assertIn('LLVM_PROFILE_FILE=${COVERAGE_PROFILE_ROOT}/%p-%m.profraw', full)

    def test_installer_stays_release_only_and_release_build_paths_stay_uninstrumented(self) -> None:
        install = self.read("Scripts/install_local_private_build.sh")
        self.assertIn('[[ "$CONFIGURATION" == Release ]]', install)
        script = self.read("Scripts/qualify_local_private_build.sh")
        self.assertEqual(len(re.findall(
            r"-configuration Release\s*\\\n\s*CLANG_COVERAGE_MAPPING=NO build", script)), 2)
        project = self.read("MacScope/project.yml")
        configs = project[project.index("  configs:\n"):project.index("targets:\n")]
        debug, release = configs.split("    Release:\n", 1)
        self.assertIn("ENABLE_CODE_COVERAGE: NO", debug)
        self.assertIn("ENABLE_CODE_COVERAGE: NO", release)
        self.assertEqual(project.count("ENABLE_CODE_COVERAGE: NO"), 2)
        self.assertIn("      gatherCoverageData: true\n      coverageTargets:\n        - MacScopeApp", project)


if __name__ == "__main__":
    unittest.main()
