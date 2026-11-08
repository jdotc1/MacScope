from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile
import unittest

from Scripts.reconstruction_task10_adjudication.core import (
    _validate_task10_program_status_semantics,
)


ROOT = Path(__file__).resolve().parents[2]
EVIDENCE_ROOT = ROOT / "docs/qualification/oracles/RECON-R1-T10A"
ARCHIVE_NAME = "MacScope_RECON-R1_T10A_Source_Oracle_b732d93e.tar.xz"
PART_PATTERN = re.compile(
    rf"^{re.escape(ARCHIVE_NAME)}\.b64\.part-(\d{{3}})$"
)
SHA256 = re.compile(r"^[0-9a-f]{64}$")
EXPECTED_HERMETIC_TESTS = 71
EXPECTED_INPUT_ARCHIVE_SHA256 = (
    "9d1b153ccfb35d04daa7fce65fffde5b76b65423808c82101465cb86626af91b"
)
IMPORTED_TRANSPORT_SHA256 = (
    "b63795fb432453c12c4494a4f61ab3ec582431c45d9d3b18689a276338cc5529"
)


class ReconstructionTask10AOracleTransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.temporary = tempfile.TemporaryDirectory(prefix="macscope-t10a-gate-")
        cls.root = Path(cls.temporary.name)
        cls.evidence = cls.root / "RECON-R1-T10A"
        shutil.copytree(EVIDENCE_ROOT, cls.evidence)
        reconstructed = subprocess.run(
            [str(cls.evidence / "reconstruct.sh")],
            cwd=cls.evidence,
            capture_output=True,
            text=True,
            check=False,
        )
        if reconstructed.returncode != 0:
            raise AssertionError(
                "T10A transport reconstruction failed:\n"
                + reconstructed.stdout
                + reconstructed.stderr
            )
        cls.archive = cls.evidence / ARCHIVE_NAME
        cls.extracted = cls.root / "extracted"
        cls.extracted.mkdir()
        with tarfile.open(cls.archive, mode="r:xz") as archive:
            for member in archive.getmembers():
                relative = PurePosixPath(member.name)
                if relative.is_absolute() or ".." in relative.parts:
                    raise AssertionError(f"unsafe archive member: {member.name}")
                if not member.isdir() and not member.isfile():
                    raise AssertionError(
                        f"unsupported archive member type: {member.name}"
                    )
            archive.extractall(cls.extracted)
        cls.bundle = cls.extracted / "MacScope-RECON-R1-T10A"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.temporary.cleanup()

    def test_transport_has_exactly_seven_parts_and_matches_sidecar(self) -> None:
        parts = sorted(
            path for path in EVIDENCE_ROOT.iterdir() if PART_PATTERN.match(path.name)
        )
        self.assertEqual(
            [PART_PATTERN.match(path.name).group(1) for path in parts],
            [f"{index:03d}" for index in range(1, 8)],
        )
        line = (EVIDENCE_ROOT / "source-archive.sha256").read_text().strip()
        expected_digest, filename = line.split("  ", 1)
        self.assertRegex(expected_digest, SHA256)
        self.assertEqual(filename, ARCHIVE_NAME)
        actual_digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.assertEqual(actual_digest, expected_digest)

    def test_extracted_bundle_ledger_is_closed_and_matches(self) -> None:
        ledger_path = self.bundle / "bundle.sha256"
        self.assertTrue(ledger_path.is_file(), "source transport lacks bundle.sha256")
        expected: dict[str, str] = {}
        for line_number, line in enumerate(
            ledger_path.read_text(encoding="utf-8").splitlines(), start=1
        ):
            digest, separator, relative = line.partition("  ")
            self.assertEqual(separator, "  ", f"malformed ledger line {line_number}")
            self.assertRegex(digest, SHA256)
            path = PurePosixPath(relative)
            self.assertFalse(path.is_absolute())
            self.assertNotIn("..", path.parts)
            self.assertNotIn(relative, expected)
            expected[relative] = digest

        observed = {
            path.relative_to(self.bundle).as_posix(): path
            for path in self.bundle.rglob("*")
            if path.is_file() and path != ledger_path
        }
        self.assertEqual(set(observed), set(expected))
        mismatched = {
            relative: {
                "expected": expected[relative],
                "actual": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
            for relative, path in observed.items()
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected[relative]
        }
        self.assertEqual(mismatched, {}, json.dumps(mismatched, sort_keys=True))

    def test_provenance_distinguishes_input_transport_and_external_return(self) -> None:
        manifest = json.loads(
            (self.bundle / "T10A_RETURN_MANIFEST.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            manifest["sourceIdentity"]["inputArchiveSHA256"],
            EXPECTED_INPUT_ARCHIVE_SHA256,
        )
        self.assertEqual(
            manifest["sourceTransport"]["importedSHA256"],
            IMPORTED_TRANSPORT_SHA256,
        )
        self.assertIsNone(manifest["sourceTransport"]["currentSHA256"])
        self.assertEqual(manifest["sourceTransport"]["partCount"], 7)
        external = manifest["externalFullReturnArchive"]
        self.assertEqual(external["availability"], "external-not-in-source-transport")
        self.assertFalse(external["localVerification"])
        self.assertFalse((EVIDENCE_ROOT / external["filename"]).exists())
        external_sidecar = EVIDENCE_ROOT / "external-full-return-archive.sha256"
        sidecar_lines = [
            line
            for line in external_sidecar.read_text(encoding="utf-8").splitlines()
            if line and not line.startswith("#")
        ]
        self.assertEqual(len(sidecar_lines), 1)
        external_digest, external_filename = sidecar_lines[0].split("  ", 1)
        self.assertEqual(external_digest, external["sha256"])
        self.assertEqual(external_filename, external["filename"])
        readme = (EVIDENCE_ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(EXPECTED_INPUT_ARCHIVE_SHA256, readme)
        self.assertIn(IMPORTED_TRANSPORT_SHA256, readme)
        self.assertIn("historical external provenance", readme)

    def test_repacker_reproduces_the_committed_transport(self) -> None:
        with tempfile.TemporaryDirectory(prefix="macscope-t10a-repack-gate-") as root:
            evidence = Path(root) / "RECON-R1-T10A"
            shutil.copytree(EVIDENCE_ROOT, evidence)
            result = subprocess.run(
                [str(evidence / "repack.py"), str(self.bundle)],
                cwd=evidence,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            receipt = json.loads(result.stdout)
            self.assertEqual(receipt["base64PartCount"], 7)
            expected_files = [
                path
                for path in EVIDENCE_ROOT.iterdir()
                if PART_PATTERN.match(path.name)
            ] + [EVIDENCE_ROOT / "source-archive.sha256"]
            for expected in expected_files:
                with self.subTest(filename=expected.name):
                    self.assertEqual(
                        (evidence / expected.name).read_bytes(),
                        expected.read_bytes(),
                    )

    def test_documented_default_command_runs_exact_hermetic_count(self) -> None:
        source_contract = (self.bundle / "tests/test_source_contract.py").read_text(
            encoding="utf-8"
        )
        self.assertNotIn("/mnt/data", source_contract)
        self.assertFalse((self.bundle / "tests/test_source_audit_external.py").exists())
        self.assertTrue((self.bundle / "tests/source_audit_external.py").is_file())
        hermetic_script = self.bundle / "scripts/run_hermetic_tests.sh"
        script_text = hermetic_script.read_text(encoding="utf-8")
        self.assertIn("-p 'test_*.py'", script_text)
        run_all_text = (self.bundle / "scripts/run_all.sh").read_text(encoding="utf-8")
        self.assertEqual(
            run_all_text.count('"$ROOT/scripts/run_hermetic_tests.sh"'),
            1,
        )
        result = subprocess.run(
            [str(hermetic_script)],
            cwd=self.bundle,
            capture_output=True,
            text=True,
            check=False,
        )
        output = result.stdout + result.stderr
        self.assertEqual(result.returncode, 0, output)
        match = re.search(r"Ran (\d+) tests? in", output)
        self.assertIsNotNone(match, output)
        self.assertEqual(int(match.group(1)), EXPECTED_HERMETIC_TESTS)
        self.assertRegex(output, r"\nOK\s*$")

        generated_gate = subprocess.run(
            [str(self.bundle / "scripts/run_full_generated_validation.sh")],
            cwd=self.bundle,
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(generated_gate.returncode, 66)
        self.assertIn(
            "not included in the source-only transport",
            generated_gate.stderr,
        )

    def test_live_task10_program_status_semantics_are_exact(self) -> None:
        live_path = ROOT / "docs/roadmap/PROGRAM_STATUS.yaml"
        live = json.loads(live_path.read_text(encoding="utf-8"))
        _validate_task10_program_status_semantics(json.dumps(live))

        live["gates"]["reconstruction_task_10"]["status"] = "arbitrary"
        live["decoy"] = "implemented-locally-awaiting-task11-qualification"
        with self.assertRaisesRegex(
            ValueError,
            r"gates\.reconstruction_task_10\.status must equal",
        ):
            _validate_task10_program_status_semantics(json.dumps(live))


class Task10ProgramStatusSemanticsTests(unittest.TestCase):
    def bounded_private_status(self) -> dict:
        return {
            "gates": {
                "reconstruction_task_10": {
                    "status": "implemented-locally-awaiting-task11-qualification",
                },
                "gate_f": {
                    "status": "passed",
                    "qualification_scope": (
                        "owner-authorized private-beta bounded acceptance; "
                        "not strict22-case GUI matrix or legacy COMPLETE"
                    ),
                    "evidence_index": "docs/qualification/GATE_F_EVIDENCE_INDEX_20261004.md",
                    "post_integration_observation": (
                        "/Users\x2fexample/gatef/final-closeout.json"
                    ),
                    "installed_cases_passed": 8,
                    "installed_cases_deferred": 14,
                    "deferred_gui_trigger": "next relevant UI change or before external beta",
                    "task11_execution": {
                        "step_8": (
                            "private-candidate-accepted-proportional-evidence-index-"
                            "see-post-integration-observation"
                        ),
                    },
                },
            },
        }

    def test_historical_gated_record_remains_valid_without_private_metadata(self) -> None:
        status = self.bounded_private_status()
        status["gates"]["gate_f"] = {"status": "gated"}
        _validate_task10_program_status_semantics(json.dumps(status))

    def test_explicit_bounded_private_acceptance_is_valid(self) -> None:
        _validate_task10_program_status_semantics(json.dumps(self.bounded_private_status()))

    def test_unbounded_or_malformed_passed_record_is_rejected(self) -> None:
        cases = [
            ("qualification_scope", None),
            ("qualification_scope", "complete"),
            ("qualification_scope", "strict22-case GUI matrix passed"),
            ("qualification_scope", ["owner-authorized private-beta bounded acceptance"]),
            ("evidence_index", None),
            ("evidence_index", "docs/qualification/OLD_GATE_F_EVIDENCE_INDEX.md"),
            ("post_integration_observation", None),
            ("post_integration_observation", ""),
            ("post_integration_observation", "relative/final-closeout.json"),
            ("installed_cases_passed", None),
            ("installed_cases_passed", True),
            ("installed_cases_passed", "8"),
            ("installed_cases_passed", -1),
            ("installed_cases_passed", 9),
            ("installed_cases_deferred", None),
            ("installed_cases_deferred", 0),
            ("installed_cases_deferred", 14.0),
            ("installed_cases_deferred", False),
            ("deferred_gui_trigger", None),
            ("deferred_gui_trigger", "  "),
            ("task11_execution", None),
            ("task11_execution", {"step_8": "COMPLETE"}),
            ("task11_execution", {"step_8": "complete-bounded-local-premerge"}),
        ]
        for field, value in cases:
            with self.subTest(field=field, value=value):
                status = self.bounded_private_status()
                gate_f = status["gates"]["gate_f"]
                if value is None:
                    gate_f.pop(field)
                else:
                    gate_f[field] = value
                with self.assertRaisesRegex(ValueError, r"gates\.gate_f"):
                    _validate_task10_program_status_semantics(json.dumps(status))

    def test_arbitrary_or_legacy_completion_status_cannot_use_private_metadata(self) -> None:
        for value in ("complete", "COMPLETE", "pass", "stale", "arbitrary", None):
            with self.subTest(status=value):
                status = self.bounded_private_status()
                status["gates"]["gate_f"]["status"] = value
                with self.assertRaisesRegex(ValueError, r"gates\.gate_f\.status"):
                    _validate_task10_program_status_semantics(json.dumps(status))


if __name__ == "__main__":
    unittest.main()
