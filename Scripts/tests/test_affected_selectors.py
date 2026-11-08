#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
import os
import re
import subprocess
import tempfile
import unittest
from unittest import mock

from Scripts.ci import affected_selectors as subject

CLASSES = {
    "MacScope/Tests/CoreTests/MacIRBuilderTests.swift": ["CoreTests/MacIRBuilderTests"],
    "MacScope/Tests/CoreTests/MacIRUnknownDestinationTests.swift": ["CoreTests/MacIRUnknownDestinationTests"],
    "MacScope/Tests/CoreTests/ARM64DecoderTests.swift": ["CoreTests/ARM64DecoderTests"],
    "MacScope/Tests/Phase2Tests/REAInspectionProviderTests.swift": ["Phase2Tests/REAInspectionProviderTests"],
    "MacScope/Tests/CoreTests/WorkspaceScriptingAPITests.swift": ["CoreTests/WorkspaceScriptingAPITests"],
    "MacScope/Tests/CoreTests/ImageLayoutTests.swift": ["CoreTests/ImageLayoutTests"],
    "MacScope/Tests/CoreTests/TwoClassTests.swift": ["CoreTests/TwoClassTests", "CoreTests/TwoClassExtraTests"],
}


class AffectedSelectorTests(unittest.TestCase):
    def select(self, *paths: str, event: str = "pull_request") -> subject.Selection:
        return subject.select(event, list(paths), CLASSES)

    def test_push_is_a_smoke_build_and_dispatch_is_the_full_suite(self) -> None:
        self.assertEqual(self.select("MacScope/Services/REA/A.swift", event="push").qualify_arguments(), "--mode smoke")
        dispatch = self.select(event="workflow_dispatch")
        self.assertEqual(dispatch.qualify_arguments(), "--mode full-test")
        self.assertTrue(dispatch.governance and dispatch.sanitizers)
        # D11/D12: the nightly schedule is the full regression net.
        nightly = self.select(event="schedule")
        self.assertEqual(nightly.qualify_arguments(), "--mode full-test")
        self.assertTrue(nightly.governance and nightly.sanitizers)

    def test_docs_and_scripts_only_changes_get_a_smoke_build(self) -> None:
        docs = self.select("docs/ROADMAP.md", "AGENTS.md")
        self.assertEqual(docs.qualify_arguments(), "--mode smoke")
        self.assertFalse(docs.governance)
        scripts = self.select("Scripts/ci/affected_selectors.py", ".github/workflows/ci.yml")
        self.assertEqual(scripts.qualify_arguments(), "--mode smoke")
        self.assertTrue(scripts.governance)

    def test_source_stem_and_area_select_test_classes(self) -> None:
        selection = self.select("MacScope/Services/Decompiler/MacIRBuilder+RegisterEffects.swift")
        self.assertEqual(selection.mode, "focused-test")
        self.assertEqual(
            selection.selectors,
            ["CoreTests/MacIRBuilderTests", "CoreTests/MacIRUnknownDestinationTests"],
        )
        self.assertIn("--only-testing CoreTests/MacIRBuilderTests", selection.qualify_arguments())

    def test_changed_test_file_selects_every_class_it_declares(self) -> None:
        selection = self.select("MacScope/Tests/CoreTests/TwoClassTests.swift")
        self.assertEqual(selection.selectors, ["CoreTests/TwoClassExtraTests", "CoreTests/TwoClassTests"])

    def test_same_line_main_actor_test_class_is_selected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "MacScope/Tests/CoreTests").mkdir(parents=True)
            path = root / "MacScope/Tests/Phase2Tests/REAScenarioCaptureProviderTests.swift"
            path.parent.mkdir(parents=True)
            path.write_text(
                "@MainActor final class REAScenarioCaptureProviderTests: XCTestCase {}\n"
                "final class OtherTests: XCTestCase {}\n"
                "// @MainActor final class CommentTests: XCTestCase {}\n",
                encoding="utf-8",
            )
            classes = subject.test_classes(root)
            selection = subject.select("pull_request", [path.relative_to(root).as_posix()], classes, root=root)
            self.assertEqual(selection.selectors, ["Phase2Tests/OtherTests", "Phase2Tests/REAScenarioCaptureProviderTests"])

    def test_same_named_files_in_different_bundles_keep_both_classes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for folder, class_name in (("CoreTests", "FooCoreTests"), ("Phase2Tests", "FooPhaseTests")):
                test_file = root / "MacScope" / "Tests" / folder / "FooTests.swift"
                test_file.parent.mkdir(parents=True)
                test_file.write_text(f"final class {class_name}: XCTestCase {{}}\n", encoding="utf-8")
            classes = subject.test_classes(root)
            core = subject.select("pull_request", ["MacScope/Tests/CoreTests/FooTests.swift"], classes, root=root)
            phase = subject.select("pull_request", ["MacScope/Tests/Phase2Tests/FooTests.swift"], classes, root=root)
            source = subject.select("pull_request", ["MacScope/Services/Foo.swift"], classes, root=root)
            self.assertEqual(core.selectors, ["CoreTests/FooCoreTests"])
            self.assertEqual(phase.selectors, ["Phase2Tests/FooPhaseTests"])
            self.assertEqual(source.selectors, ["CoreTests/FooCoreTests", "Phase2Tests/FooPhaseTests"])

    def test_changed_paths_preserve_unusual_git_path_bytes(self) -> None:
        raw_paths = [
            "MacScope/Tests/CoreTests/Foo 名.swift".encode("utf-8"),
            b"MacScope/Tests/CoreTests/Line\nBreak.swift",
            b"Scripts/odd-\xff.py",
        ]
        output = b"\0".join(raw_paths) + b"\0"
        completed = subprocess.CompletedProcess([], 0, stdout=output, stderr=b"")
        with mock.patch.object(subject.subprocess, "run", return_value=completed) as run:
            paths = subject.changed_paths("base", "head")
        self.assertEqual(paths, [os.fsdecode(path) for path in raw_paths])
        run.assert_called_once_with(
            ["git", "-C", str(subject.ROOT), "diff", "--name-only", "--no-renames", "-z", "base", "head"],
            check=True, capture_output=True,
        )
        classes = {
            paths[0]: ["CoreTests/FooTests"],
            paths[1]: ["CoreTests/LineBreakTests"],
        }
        selection = subject.select("pull_request", paths, classes)
        self.assertEqual(selection.selectors, ["CoreTests/FooTests", "CoreTests/LineBreakTests"])
        self.assertTrue(selection.governance)

    def test_nested_and_shared_sources_select_their_hosted_bundles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sources = {
                "MacScope/Tests/CoreTests/Support/ModeIsolatedTestCase.swift": "SharedFixtureTests",
                "MacScope/Tests/Phase2Tests/Nested/ExtraTests.swift": "ExtraTests",
                "MacScope/Tests/CoreTests/GoldenFixtures/corpus/Excluded.swift": "GoldenExcludedTests",
                "MacScope/Tests/CoreTests/Support/A64Oracle/Fixtures/Excluded.swift": "OracleExcludedTests",
                "MacScope/Tests/CoreTests/Fixtures/libjpeg-turbo-3.2.0/Excluded.swift": "JPEGExcludedTests",
                "MacScope/Tests/CoreTests/NativeDecompilerObjCBridgeCrossLanguageTests.swift": "BridgeExcludedTests",
            }
            for relative, name in sources.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(f"final class {name}: XCTestCase {{}}\n", encoding="utf-8")
            classes = subject.test_classes(root)
            shared = "MacScope/Tests/CoreTests/Support/ModeIsolatedTestCase.swift"
            self.assertEqual(classes[shared], ["CoreTests/SharedFixtureTests", "Phase2Tests/SharedFixtureTests"])
            self.assertEqual(subject.select("pull_request", [shared], classes, root=root).selectors,
                             ["CoreTests/SharedFixtureTests", "Phase2Tests/SharedFixtureTests"])
            self.assertEqual(subject.select("pull_request", ["MacScope/Services/SharedFixture.swift"], classes, root=root).selectors,
                             ["CoreTests/SharedFixtureTests", "Phase2Tests/SharedFixtureTests"])
            self.assertEqual(subject.select("pull_request", ["MacScope/Tests/Phase2Tests/Nested/ExtraTests.swift"], classes, root=root).selectors,
                             ["Phase2Tests/ExtraTests"])
            discovered = {selector for values in classes.values() for selector in values}
            self.assertFalse(any("ExcludedTests" in selector for selector in discovered))

    def test_nested_test_directory_symlink_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            external = root / "outside"
            external.mkdir()
            (external / "Linked.swift").write_text("final class LinkedTests: XCTestCase {}\n", encoding="utf-8")
            link = root / "MacScope/Tests/CoreTests/Linked"
            link.parent.mkdir(parents=True)
            (root / "MacScope/Tests/Phase2Tests").mkdir(parents=True)
            link.symlink_to(external, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "test source directory must not be a symlink"):
                subject.test_classes(root)

    def test_nested_test_file_symlink_is_refused(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            external = root / "external.swift"
            external.write_text("final class ExternalTests: XCTestCase {}\n", encoding="utf-8")
            link = root / "MacScope/Tests/CoreTests/Support/Linked.swift"
            link.parent.mkdir(parents=True)
            link.symlink_to(external)
            with self.assertRaisesRegex(ValueError, "test source must be an ordinary file"):
                subject.test_classes(root)

    def test_missing_test_bundle_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "MacScope/Tests/CoreTests").mkdir(parents=True)
            with self.assertRaises(FileNotFoundError):
                subject.test_classes(root)

    def test_unmapped_product_change_still_compiles_tests_through_the_canary(self) -> None:
        selection = self.select("MacScope/App/Unmapped.swift")
        self.assertEqual(selection.selectors, ["CoreTests/ImageLayoutTests"])
        helper = self.select("MacScope/Tests/CoreTests/SharedFixtureSupport.swift")
        self.assertEqual(helper.selectors, ["CoreTests/ImageLayoutTests"])

    def test_bridge_changes_add_sanitizers(self) -> None:
        self.assertTrue(self.select("Tools/NativeDecompilerBridge/bridge.cpp").sanitizers)
        self.assertTrue(self.select("ThirdParty/SleighNative/patches/0004.patch").sanitizers)
        self.assertFalse(self.select("MacScope/Services/REA/A.swift").sanitizers)

    def test_large_selection_falls_back_to_the_full_suite(self) -> None:
        many = {f"Area{index}Tests": [f"CoreTests/Area{index}Tests"] for index in range(subject.FULL_SUITE_THRESHOLD + 1)}
        selection = subject.select("pull_request", ["MacScope/Services/Area.swift"], many)
        self.assertEqual(selection.qualify_arguments(), "--mode full-test")

    def test_repository_test_classes_are_discovered(self) -> None:
        classes = subject.test_classes(subject.ROOT)
        canary_path = f"MacScope/Tests/CoreTests/{subject.CANARY_CLASS}.swift"
        self.assertIn(canary_path, classes)
        self.assertIn(f"CoreTests/{subject.CANARY_CLASS}", classes[canary_path])
        phase2 = [selector for selectors in classes.values() for selector in selectors if selector.startswith("Phase2Tests/")]
        self.assertTrue(phase2, "no Phase2Tests classes discovered")

    def test_decompiler_source_references_select_every_requested_family(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / subject.DECOMPILER_AREA / "Nested.swift"
            source.parent.mkdir(parents=True)
            source.write_text("struct FreshDecompilerType {}\n", encoding="utf-8")
            tests = root / subject.TESTS
            tests.mkdir(parents=True)
            (root / "MacScope/Tests/Phase2Tests").mkdir(parents=True)
            names = [f"{prefix}CoverageTests" for prefix in
                     ("G2", "Callee", "F1b", "S1Vector", "D06", "Golden")]
            (tests / "Coverage.swift").write_text(
                "\n".join(f"final class {name}: XCTestCase {{}}" for name in names)
                + "\nlet value: FreshDecompilerType?\n", encoding="utf-8")
            (tests / "Unrelated.swift").write_text(
                "final class UnrelatedTests: XCTestCase {}\n"
                "let value: FreshDecompilerTypeSuffix?\n", encoding="utf-8")
            selection = subject.select(
                "pull_request", ["MacScope/Services/Decompiler/MacIRBuilder+State.swift"],
                subject.test_classes(root), root=root)
            self.assertEqual(selection.selectors, sorted(f"CoreTests/{name}" for name in names))
            self.assertEqual(selection.mode, "focused-test")

    def test_repository_decompiler_families_and_threshold(self) -> None:
        classes = subject.test_classes(subject.ROOT)
        discovered = subject.decompiler_classes(subject.ROOT)
        for prefix in ("Callee", "F1b", "S1Vector", "D06", "Golden"):
            expected = {name for names in classes.values() for name in names
                        if name.startswith(f"CoreTests/{prefix}")}
            self.assertTrue(expected, prefix)
            self.assertTrue(expected <= discovered, sorted(expected - discovered))
        selection = subject.select(
            "pull_request", ["MacScope/Services/Decompiler/MacIRBuilder+State.swift"], classes)
        if len(discovered) > subject.FULL_SUITE_THRESHOLD:
            self.assertEqual(selection.mode, "full-test")
        else:
            self.assertTrue(discovered <= set(selection.selectors))

    def test_shared_fixture_directories_select_readers_without_type_references(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / subject.DECOMPILER_AREA / "Engine.swift"
            source.parent.mkdir(parents=True)
            source.write_text("struct FixtureEngine {}\n", encoding="utf-8")
            tests = root / subject.TESTS
            tests.mkdir(parents=True)
            (root / "MacScope/Tests/Phase2Tests").mkdir(parents=True)
            # A helper without a test class establishes the fixture directory.
            (tests / "Helper.swift").write_text(
                'let engine: FixtureEngine?\n'
                'let url = base.appendingPathComponent("FreshFixtures/decompiler")\n',
                encoding="utf-8")
            (tests / "Reader.swift").write_text(
                'final class FixtureReaderTests: XCTestCase {}\n'
                'let url = base.appendingPathComponent("FreshFixtures/snapshot.json")\n',
                encoding="utf-8")
            (tests / "Other.swift").write_text(
                'final class OtherReaderTests: XCTestCase {}\n'
                'let a = base.appendingPathComponent("OtherFixtures/snapshot.json")\n'
                'let b = base.appendingPathComponent("FreshFixturesSuffix/snapshot.json")\n',
                encoding="utf-8")
            selection = subject.select(
                "pull_request", ["MacScope/Services/Decompiler/MacIRBuilder+State.swift"],
                subject.test_classes(root), root=root)
            self.assertEqual(selection.selectors, ["CoreTests/FixtureReaderTests"])
            self.assertEqual(selection.mode, "focused-test")

    def test_repository_fixture_readers_and_fixture_free_gate_are_covered(self) -> None:
        # Independently inventory literal fixture paths used by type-referencing
        # sources, then require every reader of those roots in the coverage set.
        sources = [path.read_text(encoding="utf-8")
                   for path in (subject.ROOT / subject.TESTS).rglob("*.swift")]
        types = {name for path in (subject.ROOT / subject.DECOMPILER_AREA).rglob("*.swift")
                 for name in subject.TYPE_PATTERN.findall(path.read_text(encoding="utf-8"))}
        roots = {part for source in sources
                 if types.intersection(subject.IDENTIFIER_PATTERN.findall(source))
                 for literal in re.findall(r'"([^"\n]*)"', source)
                 for part in literal.split("/")
                 if re.fullmatch(r"[A-Za-z_-]*(?:fixtures?|goldens?)", part, re.I)}
        self.assertTrue(roots)
        expected = {f"CoreTests/{name}" for source in sources
                    if any(roots.intersection(literal.split("/"))
                           for literal in re.findall(r'"([^"\n]*)"', source))
                    for name in subject.CLASS_PATTERN.findall(source)}
        self.assertIn("CoreTests/PreRefactorByteIdentityTests", expected)
        expected.add("CoreTests/GoldenGateTests")
        discovered = subject.decompiler_classes(subject.ROOT)
        self.assertTrue(expected <= discovered, sorted(expected - discovered))

    def test_non_decompiler_area_keeps_its_exact_selection(self) -> None:
        selection = self.select("MacScope/Services/Disassembly/InstructionDecoder.swift")
        self.assertEqual(selection.selectors, ["CoreTests/ARM64DecoderTests"])
        self.assertEqual(selection.mode, "focused-test")
        self.assertFalse(selection.governance or selection.sanitizers)

    def test_phase2_bundle_classes_keep_their_bundle(self) -> None:
        self.assertIn("Phase2Tests/REAInspectionProviderTests",
                      self.select("MacScope/Services/REA/A.swift").selectors)
        changed = self.select("MacScope/Tests/Phase2Tests/REAInspectionProviderTests.swift")
        self.assertEqual(changed.selectors, ["Phase2Tests/REAInspectionProviderTests"])


if __name__ == "__main__":
    unittest.main()
