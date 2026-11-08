#!/usr/bin/env python3
"""Deterministic tool-contract tests. Synthetic numbers are never performance evidence."""
import hashlib
import json
from pathlib import Path
import plistlib
import tempfile
import unittest

import compare_results as comparison
import make_manifest
import run_benchmark


class PerformanceToolTests(unittest.TestCase):
    def fixture(self, root, multiplier=1.0):
        root.mkdir()
        manifest = {"schemaVersion": 1, "warmupIterations": 1, "measuredIterations": 20,
                    "inputs": [{"id": "fixture", "mode": "inProcess", "sha256": "a" * 64}]}
        payload = json.dumps(manifest, sort_keys=True).encode()
        (root / "corpus.json").write_bytes(payload)
        context = {"schemaVersion": 1, "status": "complete", "runID": "fixture",
                   "manifestSHA256": hashlib.sha256(payload).hexdigest(),
                   "identity": {"xcode": "fixture", "swift": "fixture", "sdk": "fixture",
                                "configuration": "Release", "coverage": False, "testability": True,
                                "sourceCommit": "fixture"},
                   "buildSettings": {"MacScopeApp": {"SWIFT_OPTIMIZATION_LEVEL": "-O", "ARCHS": "arm64"}},
                   "hardware": {key: "fixture" for key in ("hw.model", "machdep.cpu.brand_string", "hw.memsize", "hw.logicalcpu", "macOSBuild")}}
        (root / "context.json").write_text(json.dumps(context))
        rows = []
        for index in range(21):
            row = {"schemaVersion": 1, "runID": "fixture", "inputID": "fixture",
                   "inputSHA256": "a" * 64, "mode": "inProcess", "iteration": index,
                   "warmup": index == 0, "thermalState": 0, "lowPowerMode": False,
                   "facetSHA256": "b" * 64, "instructionCount": 100, "procedureCount": 2,
                   "listingRowCount": 110}
            row.update({key: 100.0 * multiplier for key in comparison.METRICS})
            rows.append(row)
        (root / "samples.jsonl").write_text("\n".join(json.dumps(row) for row in rows) + "\n")
        return rows

    def testPairedImprovementAndRegression(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root / "a")
            self.fixture(root / "b", 0.8)
            result = comparison.compare(comparison.load_run(root / "a"), comparison.load_run(root / "b"))
            self.assertFalse(result["hardRegressions"])
            self.assertAlmostEqual(result["inputs"]["fixture"]["analyzeMS"]["p50Ratio"], 0.8)
            self.fixture(root / "c", 1.2)
            result = comparison.compare(comparison.load_run(root / "a"), comparison.load_run(root / "c"))
            self.assertTrue(result["hardRegressions"])

    def testRejectsDuplicateMissingHotAndChangedSemanticSamples(self):
        for mutation in ("duplicate", "missing", "thermal", "semantics", "negative", "nan"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory) / "run"
                rows = self.fixture(root)
                if mutation == "duplicate": rows[-1] = rows[-2]
                elif mutation == "missing": rows.pop()
                elif mutation == "thermal": rows[-1]["thermalState"] = 2
                elif mutation == "semantics": rows[-1]["facetSHA256"] = "c" * 64
                elif mutation == "negative": rows[-1]["analyzeMS"] = -1
                elif mutation == "nan": rows[-1]["analyzeMS"] = float("nan")
                (root / "samples.jsonl").write_text("\n".join(json.dumps(row) for row in rows))
                with self.assertRaises(ValueError): comparison.load_run(root)

    def testManifestHashTamperingIsRejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "run"
            self.fixture(root)
            with (root / "corpus.json").open("a") as stream: stream.write(" ")
            with self.assertRaises(ValueError): comparison.load_run(root)

    def testManifestBindsExactInputBytesWithoutReplacingSource(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            path.write_bytes(b"synthetic fixture")
            manifest = make_manifest.build_manifest([path], ["inProcess", "xpc"], 2, 20, None)
            self.assertEqual(manifest["inputs"][0]["sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(len(manifest["inputs"]), 2)
            self.assertEqual(path.read_bytes(), b"synthetic fixture")

    def testXctestrunEnvironmentAndTestrootAreExplicitAndOriginalIsUntouched(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            original = root / "original.xctestrun"
            value = {"TestConfigurations": [{"TestTargets": [{"BlueprintName": "CoreTests",
                      "TestBundlePath": "__TESTROOT__/Release/CoreTests.xctest",
                      "EnvironmentVariables": {"EXISTING": "kept"}}]}]}
            original.write_bytes(plistlib.dumps(value))
            before = original.read_bytes()
            destination = root / "prepared.xctestrun"
            run_benchmark.prepared_xctestrun(original, destination, {"MACSCOPE_PERF_RUN": "1"})
            prepared = plistlib.loads(destination.read_bytes())
            target = run_benchmark.test_targets(prepared)[0]
            self.assertEqual(target["EnvironmentVariables"]["EXISTING"], "kept")
            self.assertEqual(target["EnvironmentVariables"]["MACSCOPE_PERF_RUN"], "1")
            self.assertEqual(target["TestBundlePath"], str(root / "Release/CoreTests.xctest"))
            self.assertEqual(original.read_bytes(), before)

    def testOnlyListedExperimentSwitchesAreForwarded(self):
        environment = {"MACSCOPE_DYNAMIC_TILING": "1", "PATH": "/usr/bin", "MACSCOPE_OTHER": "x"}
        self.assertEqual(run_benchmark.experiment_environment(environment), {"MACSCOPE_DYNAMIC_TILING": "1"})
        self.assertEqual(run_benchmark.experiment_environment({"PATH": "/usr/bin"}), {})

    def testQuantileAndBootstrapAreDeterministic(self):
        self.assertEqual(comparison.percentile(list(range(1, 21)), 0.95), 19)
        self.assertEqual(comparison.bootstrap_ratio([100] * 20, [80] * 20), [0.8, 0.8])

    # Authored, unrun. Synthetic fixtures are not performance evidence.
    def tilingPair(self, root, multiplier=0.8, count=4096, mode="inProcess"):
        runs = []
        for name, scale, tiles in (("a", 1.0, 1), ("b", multiplier, 6)):
            path = root / name
            rows = self.fixture(path, scale)
            context = json.loads((path / "context.json").read_text())
            context["experimentEnvironment"] = {} if tiles == 1 else {"MACSCOPE_DYNAMIC_TILING": "1"}
            (path / "context.json").write_text(json.dumps(context))
            for row in rows:
                row.update(instructionCount=count, tilingObserved=True,
                           effectiveTilesPerWorker=tiles, effectiveMaximumParallelism=8)
            (path / "samples.jsonl").write_text("\n".join(json.dumps(row) for row in rows))
            run = comparison.load_run(path)
            if mode == "xpc":
                run[1]["inputs"][0]["mode"] = mode
                for row in run[2]["fixture"]:
                    row["mode"] = mode
                    for key in ("tilingObserved", "effectiveTilesPerWorker", "effectiveMaximumParallelism"):
                        row.pop(key)
            runs.append(run)
        return runs

    def testTilingGainNoGainAndInconclusive(self):
        for scale, expected in ((0.8, "GAIN"), (1.0, "NO-GAIN"), (0.98, "NO-GAIN")):
            with self.subTest(scale=scale), tempfile.TemporaryDirectory() as directory:
                pair = self.tilingPair(Path(directory), scale)
                result = comparison.compare(*pair, tiling_verdict=True)
                self.assertEqual(result["tilingVerdict"]["verdict"], expected)
                self.assertIn("Dynamic tiling: " + expected, comparison.markdown(result))
        with tempfile.TemporaryDirectory() as directory:
            pair = self.tilingPair(Path(directory))
            for index, row in enumerate(pair[1][2]["fixture"]):
                row["analyzeMS"] = 96 if index < 10 else 100
            result = comparison.compare(*pair, tiling_verdict=True)
            self.assertEqual(result["tilingVerdict"]["verdict"], "INCONCLUSIVE")

    def testTilingAcceptsExplicitOffAndUnchangedOtherExperiments(self):
        with tempfile.TemporaryDirectory() as directory:
            pair = self.tilingPair(Path(directory))
            pair[0][0]["experimentEnvironment"]["MACSCOPE_DYNAMIC_TILING"] = "0"
            for run in pair: run[0]["experimentEnvironment"]["OTHER"] = "same"
            result = comparison.compare(*pair, tiling_verdict=True)
            self.assertEqual(result["tilingVerdict"]["verdict"], "GAIN")

    def testTilingRejectsInvalidExperimentsAndBuilds(self):
        for mutation in ("same-off", "same-on", "other-switch", "non-string", "commit", "empty-commit", "build", "identity"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                pair = self.tilingPair(Path(directory))
                left, right = pair[0][0], pair[1][0]
                if mutation == "same-off": right["experimentEnvironment"] = {}
                elif mutation == "same-on": left["experimentEnvironment"] = dict(right["experimentEnvironment"])
                elif mutation == "other-switch": right["experimentEnvironment"]["OTHER"] = "1"
                elif mutation == "non-string": left["experimentEnvironment"]["MACSCOPE_DYNAMIC_TILING"] = 0
                elif mutation == "commit": right["identity"]["sourceCommit"] = "other"
                elif mutation == "empty-commit":
                    left["identity"]["sourceCommit"] = right["identity"]["sourceCommit"] = ""
                elif mutation == "build": right["buildSettings"]["other"] = {}
                elif mutation == "identity": right["identity"]["extra"] = "changed"
                with self.assertRaisesRegex(ValueError, "INVALID tiling"):
                    comparison.compare(*pair, tiling_verdict=True)

    def testTilingRejectsUnobservedMismatchedAndUnstableSamples(self):
        for key, value in (("tilingObserved", None), ("tilingObserved", 1),
                           ("effectiveTilesPerWorker", 1), ("effectiveTilesPerWorker", 6.0),
                           ("effectiveMaximumParallelism", None), ("effectiveMaximumParallelism", True),
                           ("effectiveMaximumParallelism", 0), ("effectiveMaximumParallelism", 65),
                           ("effectiveMaximumParallelism", 7)):
            with self.subTest(key=key, value=value), tempfile.TemporaryDirectory() as directory:
                pair = self.tilingPair(Path(directory))
                pair[1][2]["fixture"][-1][key] = value
                with self.assertRaisesRegex(ValueError, "INVALID tiling"):
                    comparison.compare(*pair, tiling_verdict=True)

    def testTilingExcludesXPCAndRequiresEligibleParallelWork(self):
        for mode, count, budget, expected in (("xpc", 8192, 8, "NOT-MEASURED"),
                                             ("inProcess", 4095, 8, "NO-GAIN"),
                                             ("inProcess", 4096, 1, "INCONCLUSIVE")):
            with self.subTest(mode=mode, count=count, budget=budget), tempfile.TemporaryDirectory() as directory:
                pair = self.tilingPair(Path(directory), count=count, mode=mode)
                if mode == "inProcess":
                    for run in pair:
                        for row in run[2]["fixture"]: row["effectiveMaximumParallelism"] = budget
                result = comparison.compare(*pair, tiling_verdict=True)["tilingVerdict"]
                self.assertEqual(result["cohorts"]["fixture"]["verdict"], expected)
                self.assertEqual(result["verdict"], "INCONCLUSIVE")

    def testTilingGuardCohortsBlockAnOtherwiseValidGain(self):
        for count, metric, value, expected in ((100, "cpuMS", 106, "NO-GAIN"),
                                               (100, "footprintBytes", 106, "NO-GAIN"),
                                               (100, "analyzeMS", 101, "NO-GAIN"),
                                               (100, "totalMS", 101, "NO-GAIN"),
                                               (8192, "analyzeMS", 101, "NO-GAIN"),
                                               (8192, "totalMS", 101, "NO-GAIN"),
                                               (100, "totalMS", 111, "NO-GAIN"),
                                               (100, "footprintBytes", None, "INCONCLUSIVE"),
                                               (100, "cpuMS", 0, "INCONCLUSIVE")):
            with self.subTest(count=count, metric=metric, value=value), tempfile.TemporaryDirectory() as directory:
                pair = self.tilingPair(Path(directory))
                for run in pair:
                    run[2]["guard"] = [dict(row, instructionCount=count) for row in run[2]["fixture"]]
                for row in pair[1][2]["guard"]: row[metric] = value
                result = comparison.compare(*pair, tiling_verdict=True)["tilingVerdict"]
                self.assertEqual(result["cohorts"]["fixture"]["verdict"], "GAIN")
                self.assertEqual(result["verdict"], expected)

    def testTilingResourceCapIncludesP95AndAcceptsEquality(self):
        for tail, expected in ((105, "GAIN"), (106, "NO-GAIN")):
            with self.subTest(tail=tail), tempfile.TemporaryDirectory() as directory:
                pair = self.tilingPair(Path(directory))
                for row in pair[1][2]["fixture"][-2:]: row["cpuMS"] = tail
                result = comparison.compare(*pair, tiling_verdict=True)
                self.assertEqual(result["tilingVerdict"]["verdict"], expected)

    def testOrdinaryOldSamplesAndCrossCommitOutputRemainUnchanged(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture(root / "a")
            self.fixture(root / "b", 0.8)
            pair = [comparison.load_run(root / name) for name in ("a", "b")]
            pair[1][0]["identity"]["sourceCommit"] = "other"
            result = comparison.compare(*pair)
            self.assertNotIn("tilingVerdict", result)
            self.assertNotIn("Dynamic tiling", comparison.markdown(result))
            self.assertEqual(result, comparison.compare(*pair, tiling_verdict=False))
            with self.assertRaisesRegex(ValueError, "INVALID tiling"):
                comparison.compare(*pair, tiling_verdict=True)

    def testTilingCLIExitCodesAndArtifacts(self):
        from unittest.mock import patch
        for scale, missing, expected in ((0.8, False, 0), (1.0, False, 0),
                                          (0.8, True, 2), (1.2, False, 1)):
            with self.subTest(scale=scale, missing=missing), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                self.tilingPair(root, scale)
                if missing:
                    path = root / "b" / "samples.jsonl"
                    rows = [json.loads(line) for line in path.read_text().splitlines()]
                    rows[-1]["footprintBytes"] = None
                    path.write_text("\n".join(json.dumps(row) for row in rows))
                argv = ["compare_results.py", "--baseline", str(root / "a"), "--candidate", str(root / "b"),
                        "--output", str(root / "out"), "--tiling-verdict"]
                with patch("sys.argv", argv), self.assertRaises(SystemExit) as raised:
                    comparison.main()
                self.assertEqual(raised.exception.code, expected)
                self.assertTrue((root / "out" / "comparison.json").is_file())
                self.assertTrue((root / "out" / "comparison.md").is_file())


if __name__ == "__main__":
    unittest.main()
