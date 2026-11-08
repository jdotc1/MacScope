#!/usr/bin/env python3
"""Select the native CI validation for a change from the paths it touches.

Tier 1 (pull requests): a Debug build plus the CoreTests classes that the
changed paths map to. Changed test files select themselves; a changed source
file `Foo.swift` or `Foo+Bar.swift` selects every test class whose name starts
with `Foo`; a changed directory in AREA_PREFIXES selects the listed test-name
prefixes. The decompiler area instead selects CoreTests classes whose source
references a type declared in that area or shares its fixture directories.
Script/workflow changes add the macOS Python governance suite;
native-bridge or SLEIGH changes add the sanitizer builds. Docs-only changes get
a smoke build.

Main pushes get a smoke build: branch protection keeps PR heads up to date
with main, so the PR run already tested the merge result. Manual dispatch runs
full CoreTests, governance and sanitizers (Tier 2).

Prints a summary and, with --github-output, writes `qualify-arguments`,
`governance` and `sanitizers` for the workflow.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
# Hosted test bundles (D12 layer 3): folder -> bundle name used in selectors.
TEST_BUNDLES = {"MacScope/Tests/CoreTests": "CoreTests", "MacScope/Tests/Phase2Tests": "Phase2Tests"}
TESTS = "MacScope/Tests/CoreTests"
# These CoreTests sources are also explicitly compiled into Phase2Tests in
# project.yml. Keep this list aligned with that target's shared sources.
SHARED_PHASE2_SOURCES = frozenset(f"MacScope/Tests/CoreTests/{path}" for path in (
    "Support/CoreTestPipeDrain.swift", "DyldCacheAnalysisTestFixtures.swift",
    "Support/Golden/GoldenOutput.swift", "Support/MachOFixture.swift",
    "Support/ReconstructionHeadlessFixture.swift", "Support/ReconstructionSourceRepairFixture.swift",
    "Task10InstalledScenarioFixtureSupport.swift", "Support/TestSourceRoot.swift",
    "Support/TestWorkRoot.swift", "Support/ModeIsolatedTestCase.swift",
    "UncachedDisassemblyListingOracle.swift", "ReconstructionJoinedWorkflowTestFixture.swift",
    "Support/ReconstructionDatabaseTestFixtures.swift",
))
# The project excludes these fixture trees and the cross-language test source
# from CoreTests. Prune trees before walking; they are not test sources.
EXCLUDED_TEST_TREES = frozenset((
    "MacScope/Tests/CoreTests/GoldenFixtures",
    "MacScope/Tests/CoreTests/Support/A64Oracle/Fixtures",
    "MacScope/Tests/CoreTests/Fixtures/libjpeg-turbo-3.2.0",
))
EXCLUDED_TEST_FILES = frozenset((
    "MacScope/Tests/CoreTests/NativeDecompilerObjCBridgeCrossLanguageTests.swift",
))

# Directory → test-class name prefixes. Longest matching directory wins; the
# stem rule below still applies to every changed Swift file.
AREA_PREFIXES: dict[str, tuple[str, ...]] = {
    "MacScope/Services/Disassembly/": ("ARM64", "Disassembl"),
    "MacScope/Services/Assembler/": ("ARM64Assembl", "Assembler"),
    "MacScope/Services/REA/": ("REA",),
    "MacScope/Services/Phase2/": ("Phase2",),
    "MacScope/ShellBrokerService/": ("Phase2Shell", "WorkspaceStorePhase2Shell"),
    "MacScope/Stores/": ("WorkspaceStore",),
    "MacScope/Services/Scripting/": ("Scripting", "WorkspaceScripting", "MCP"),
    "MacScope/Services/Loader/": ("Loader", "LoadedBinary", "ImageLayout"),
    "MacScope/Services/MachO/": ("MachO", "LoadedBinary"),
    "MacScope/Services/NativeDecompilerXPC/": ("NativeDecompiler",),
    "MacScope/NativeDecompilerXPCService/": ("NativeDecompiler",),
    "MacScope/Services/VersionMatching/": ("FunctionVersion", "VersionMatch", "AnnotationTransfer"),
    "MacScope/Services/Debugger/": ("Debugger",),
    "MacScope/Services/ObjectiveC/": ("ObjC", "ObjectiveC"),
    "MacScope/Services/SwiftMetadata/": ("SwiftMetadata",),
    "MacScope/Services/Export/": ("Export", "BinExport"),
    "MacScope/AnalysisWorkerService/": ("AnalysisWorker", "WorkerRehydrate"),
    "MacScope/AIAgentWorkerCore/": ("AIAgent",),
    "MacScope/AIAgentWorkerService/": ("AIAgent",),
}
# Paths that build but select no tests by themselves.
BUILD_INPUT_PREFIXES = ("MacScope/", "Tools/", "ThirdParty/", "script/")
GOVERNANCE_PREFIXES = ("Scripts/", ".github/", "THIRD_PARTY_", "FIRST_PARTY_", "MacScope/project.yml")
SANITIZER_PREFIXES = ("Tools/NativeDecompilerBridge/", "ThirdParty/SleighNative/")
DOC_SUFFIXES = (".md", ".txt")
# Above this many classes a filtered run costs about as much as the full suite.
FULL_SUITE_THRESHOLD = 150
# A product change that maps to no test still compiles CoreTests through one
# small, fast class, so a broken test target cannot pass as a smoke build.
CANARY_CLASS = "ImageLayoutTests"
CLASS_PATTERN = re.compile(r"^\s*(?:@MainActor[ \t]+)?(?:final\s+)?class\s+(\w+)\s*:\s*XCTestCase\b", re.M)


@dataclass
class Selection:
    mode: str
    selectors: list[str] = field(default_factory=list)
    governance: bool = False
    sanitizers: bool = False
    reasons: list[str] = field(default_factory=list)

    def qualify_arguments(self) -> str:
        return " ".join(["--mode", self.mode, *(f"--only-testing {item}" for item in self.selectors)])


def test_classes(root: Path) -> dict[str, list[str]]:
    """Map each repository-relative test path to its `<Bundle>/<Class>` selectors."""
    classes: dict[str, list[str]] = {}
    def fail_walk(error: OSError) -> None:
        raise error
    for folder, bundle in TEST_BUNDLES.items():
        bundle_root = root / folder
        if not stat.S_ISDIR(bundle_root.lstat().st_mode):
            raise ValueError(f"test bundle must be an ordinary directory: {folder}")
        for current, directories, filenames in os.walk(bundle_root, followlinks=False, onerror=fail_walk):
            parent = Path(current)
            retained_directories = []
            for name in sorted(directories):
                directory = parent / name
                relative_directory = directory.relative_to(root).as_posix()
                if relative_directory in EXCLUDED_TEST_TREES:
                    continue
                if directory.is_symlink():
                    raise ValueError(f"test source directory must not be a symlink: {relative_directory}")
                retained_directories.append(name)
            directories[:] = retained_directories
            for filename in sorted(filenames):
                path = parent / filename
                relative = path.relative_to(root).as_posix()
                if path.suffix != ".swift" or relative in EXCLUDED_TEST_FILES:
                    continue
                if not stat.S_ISREG(path.lstat().st_mode):
                    raise ValueError(f"test source must be an ordinary file: {relative}")
                declared = CLASS_PATTERN.findall(path.read_text(encoding="utf-8", errors="replace"))
                if declared:
                    bundles = (bundle, "Phase2Tests") if relative in SHARED_PHASE2_SOURCES else (bundle,)
                    classes[relative] = [f"{host}/{name}" for host in bundles for name in declared]
    return classes


DECOMPILER_AREA = "MacScope/Services/Decompiler/"
TYPE_PATTERN = re.compile(
    r"^\s*(?:(?:public|internal|private|fileprivate|package|final|indirect|nonisolated)\s+)*"
    r"(?:class|struct|enum|protocol|actor|typealias)\s+([A-Za-z_]\w*)", re.M
)
IDENTIFIER_PATTERN = re.compile(r"[A-Za-z_]\w*")
STRING_PATTERN = re.compile(r'"([^"\n]*)"')
FIXTURE_DIRECTORY_PATTERN = re.compile(r"[A-Za-z_-]*(?:fixtures?|goldens?)", re.I)
# This fixture-free gate tests synthetic golden outputs, so neither decompiler
# type references nor fixture paths connect it to the decompiler area.
DECOMPILER_EXTRA_CLASSES = {"CoreTests/GoldenGateTests"}


def fixture_directories(source: str) -> set[str]:
    """Extract fixture directory components from source literals, without I/O.

    Match directory components, not substrings, and retain their spelling. A
    shared fixture root is deliberately conservative: its other readers belong
    to the coverage set even when they read different children of that root.
    """
    return {part for literal in STRING_PATTERN.findall(source)
            for part in literal.split("/")
            if FIXTURE_DIRECTORY_PATTERN.fullmatch(part)}


def decompiler_classes(root: Path) -> set[str]:
    """Discover CoreTests references to decompiler types and shared fixture roots.

    This deliberately conservative lexical scan includes nested types, aliases,
    comments and literals: false positives cost coverage, not missed tests.
    No compiler or product-code imports are needed; the fixture-free golden
    gate is the sole explicit addition.
    """
    types: set[str] = set()
    for path in sorted((root / DECOMPILER_AREA).rglob("*.swift")):
        types.update(TYPE_PATTERN.findall(path.read_text(encoding="utf-8", errors="replace")))
    sources = [path.read_text(encoding="utf-8", errors="replace")
               for path in sorted((root / TESTS).rglob("*.swift"))]
    direct = [source for source in sources
              if types.intersection(IDENTIFIER_PATTERN.findall(source))]
    # Include helper sources without XCTestCase declarations when deriving the
    # fixture roots. Do not open fixture data or require local oracle captures.
    directories = {directory for source in direct
                   for directory in fixture_directories(source)}
    selected = set(DECOMPILER_EXTRA_CLASSES)
    for source in sources:
        if (types.intersection(IDENTIFIER_PATTERN.findall(source))
                or directories.intersection(fixture_directories(source))):
            selected.update(f"CoreTests/{name}" for name in CLASS_PATTERN.findall(source))
    return selected


def _source_stem(path: PurePosixPath) -> str:
    return path.stem.split("+", 1)[0]


def select(event: str, changed: list[str], classes: dict[str, list[str]], *, root: Path = ROOT) -> Selection:
    if event in {"workflow_dispatch", "schedule"}:
        reason = "nightly schedule" if event == "schedule" else "manual dispatch"
        return Selection("full-test", governance=True, sanitizers=True, reasons=[f"{reason}: full CoreTests"])
    if event == "push":
        return Selection("smoke", reasons=["main push: smoke build; the up-to-date PR run is the merge authority"])

    all_classes = sorted({name for names in classes.values() for name in names})
    class_name = lambda selector: selector.split("/", 1)[-1]
    chosen: set[str] = set()
    builds = False
    selection = Selection("smoke")
    decompiler = None
    for raw in changed:
        path = PurePosixPath(raw)
        if raw.startswith(GOVERNANCE_PREFIXES):
            selection.governance = True
        if raw.startswith(SANITIZER_PREFIXES):
            selection.sanitizers = True
        if raw.endswith(DOC_SUFFIXES) or not raw.startswith(BUILD_INPUT_PREFIXES):
            continue
        builds = True
        if raw.startswith(tuple(folder + "/" for folder in TEST_BUNDLES)) and path.suffix == ".swift":
            chosen.update(classes.get(path.as_posix(), []))
            continue
        if path.suffix == ".swift":
            stem = _source_stem(path)
            chosen.update(name for name in all_classes if class_name(name).startswith(stem))
        if raw.startswith(DECOMPILER_AREA):
            if decompiler is None:
                decompiler = decompiler_classes(root)
            chosen.update(decompiler.intersection(all_classes))
        areas = [prefix for prefix in AREA_PREFIXES if raw.startswith(prefix)]
        if areas:
            prefixes = AREA_PREFIXES[max(areas, key=len)]
            chosen.update(name for name in all_classes if class_name(name).startswith(prefixes))

    if not builds:
        selection.reasons.append("no product inputs changed: smoke build")
        return selection
    if len(chosen) > FULL_SUITE_THRESHOLD:
        selection.mode = "full-test"
        selection.reasons.append(f"{len(chosen)} classes selected: full CoreTests")
        return selection
    if not chosen:
        chosen.add(f"CoreTests/{CANARY_CLASS}")
        selection.reasons.append(f"no test maps to the changed product inputs: canary {CANARY_CLASS}")
    else:
        selection.reasons.append(f"{len(chosen)} CoreTests classes selected from changed paths")
    selection.mode = "focused-test"
    selection.selectors = sorted(chosen)
    return selection


def changed_paths(base: str, head: str) -> list[str]:
    output = subprocess.run(
        ["git", "-C", str(ROOT), "diff", "--name-only", "--no-renames", "-z", base, head],
        check=True, capture_output=True,
    ).stdout
    return [os.fsdecode(path) for path in output.split(b"\0") if path]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--event", required=True)
    parser.add_argument("--base", default="")
    parser.add_argument("--head", default="HEAD")
    parser.add_argument("--github-output", type=Path)
    arguments = parser.parse_args(argv)

    changed: list[str] = []
    if arguments.event == "pull_request":
        if not re.fullmatch(r"[0-9a-f]{40}", arguments.base):
            print("ERROR: pull_request selection needs the 40-hex base commit", file=sys.stderr)
            return 2
        changed = changed_paths(arguments.base, arguments.head)
    selection = select(arguments.event, changed, test_classes(ROOT))

    print(f"affected selection: {len(changed)} changed paths; " + "; ".join(selection.reasons))
    print(f"  qualify arguments: {selection.qualify_arguments()}")
    print(f"  governance={str(selection.governance).lower()} sanitizers={str(selection.sanitizers).lower()}")
    if arguments.github_output is not None:
        with arguments.github_output.open("a", encoding="utf-8") as stream:
            stream.write(f"qualify-arguments={selection.qualify_arguments()}\n")
            stream.write(f"governance={str(selection.governance).lower()}\n")
            stream.write(f"sanitizers={str(selection.sanitizers).lower()}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
