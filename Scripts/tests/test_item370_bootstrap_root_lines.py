#!/usr/bin/env python3
"""Item 370 synthetic root-line fixtures; authored only, not executed for delivery."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location(
    "item370_bootstrap_evidence",
    Path(__file__).resolve().parents[1] / "qualification/dev_bootstrap_evidence.py")
E = importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)


class Item370BootstrapRootLineTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        # macOS can spell the temporary directory through /var -> /private/var.
        # Resolve fixture roots before using them in exact path assertions.
        self.base = Path(self.temporary.name).resolve()
        self.root = self.base / "repo"
        self.root.mkdir()
        self.root = self.root.resolve(strict=True)
        self.other = self.base / "repo-other"
        self.other.mkdir()
        self.commit = "a" * 40
        self.log = self.base / "prior.log"
        self.case_number = 0

    def write_log(self, root_lines, separator="\n", extra_lines=()):
        lines = list(root_lines) + list(extra_lines) + list(dict.fromkeys(E.MARKERS.values()))
        # Bytes preserve CR/CRLF test inputs until production read_text consumes them.
        self.log.write_bytes((separator.join(lines) + separator).encode())

    def new_receipts(self):
        self.case_number += 1
        directory = self.base / f"receipts-{self.case_number}"
        directory.mkdir(mode=0o700)
        return directory

    def assert_accepts(self, root_lines, *, root_arg=None, separator="\n"):
        self.write_log(root_lines, separator)
        directory = self.new_receipts()
        requested_root = self.root if root_arg is None else root_arg

        def prior_identity(root, stage, revision="HEAD", clean=True):
            self.assertEqual(root, requested_root)
            self.assertEqual(revision, self.commit)
            self.assertFalse(clean)
            return {"stage": stage, "schema_version": E.SCHEMA,
                    "git_records": ["synthetic-committed-record"],
                    "python": [3, 9, 6], "platform": ["darwin", "arm64"],
                    "python_environment": {"PYTHONPATH": "prior-runtime-unknown"}}

        with mock.patch.object(E, "identity", side_effect=prior_identity) as identity, \
                mock.patch.object(E, "tool_version", return_value="2.46.0"), \
                mock.patch.object(E, "git", side_effect=AssertionError("no Git probe")) as git, \
                mock.patch.object(E.subprocess, "run", side_effect=AssertionError("no stage execution")) as run:
            E.import_prior(requested_root, directory, self.commit, self.log)
            self.assertEqual(identity.call_count, len(E.STAGES))
            git.assert_not_called()
            run.assert_not_called()
        receipts = [E.read(path) for path in directory.glob("*.json")]
        self.assertEqual({value["identity"]["stage"] for value in receipts}, set(E.STAGES))
        self.assertEqual(len(receipts), len(E.STAGES))
        for value in receipts:
            self.assertEqual(value["outcome"], "passed")
            self.assertEqual(value["evidence"]["transcript"], self.log.read_text())
            self.assertEqual(value["evidence"]["source_commit"], self.commit)
            self.assertEqual(value["evidence"]["runtime_attestation"], "unattested")
            for field in ("python", "platform", "python_environment"):
                self.assertIsNone(value["identity"][field])

    def assert_refuses(self, root_lines, *, extra_lines=()):
        self.write_log(root_lines, extra_lines=extra_lines)
        directory = self.new_receipts()
        with mock.patch.object(E, "identity", side_effect=lambda root, stage, revision, clean:
                               {"stage": stage, "schema_version": E.SCHEMA}) as identity, \
                mock.patch.object(E, "tool_version", return_value="2.46.0") as tool_version, \
                mock.patch.object(E, "save") as save, \
                mock.patch.object(E, "git") as git, \
                mock.patch.object(E.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "different checkout"):
                E.import_prior(self.root, directory, self.commit, self.log)
            identity.assert_not_called()
            tool_version.assert_not_called()
            save.assert_not_called()
            git.assert_not_called()
            run.assert_not_called()
        self.assertEqual(list(directory.glob("*.json")), [])

    def test_r1_exact_single_line_is_accepted(self):
        self.assert_accepts([f"    Repo root: {self.root}"])

    def test_r2_prefix_collision_is_refused(self):
        # EXPECTED FAIL ON BASE — NOT RUN: /repo is a substring of /repo-other.
        self.assert_refuses([f"    Repo root: {self.other}"])

    def test_r3_any_mixed_root_is_refused_in_both_orders(self):
        matching = f"    Repo root: {self.root}"
        different = f"    Repo root: {self.other}"
        for lines in ([matching, different], [different, matching]):
            with self.subTest(lines=lines):
                self.assert_refuses(lines)

    def test_r3_repeated_matching_lines_are_accepted(self):
        matching = f"    Repo root: {self.root}"
        self.assert_accepts([matching, matching])

    def test_r4_no_root_line_is_refused_even_with_embedded_matching_text(self):
        self.assert_refuses([])
        self.assert_refuses([], extra_lines=[f"operator note:     Repo root: {self.root}"])

    def test_r5_trailing_space_or_tab_is_untrimmed_path_data(self):
        for suffix in (" ", "\t"):
            with self.subTest(suffix=repr(suffix)):
                # Existing distinct paths make this a comparison test, not just
                # an absent-path error. No rstrip/strip may erase the suffix.
                other = self.base / ("repo" + suffix)
                other.mkdir()
                self.assert_refuses([f"    Repo root: {other}"])

    def test_r5_cr_and_crlf_are_accepted_line_endings(self):
        for separator in ("\r", "\r\n"):
            with self.subTest(separator=repr(separator)):
                self.assert_accepts([f"    Repo root: {self.root}"], separator=separator)

    def test_r5_real_whitespace_ending_alias_resolves_like_any_other_path(self):
        alias = self.base / "checkout-alias "
        alias.symlink_to(self.root, target_is_directory=True)
        self.assert_accepts([f"    Repo root: {alias}"])

    def test_r6_resolves_transcript_and_requested_root_aliases(self):
        alias = self.base / "checkout-alias"
        alias.symlink_to(self.root, target_is_directory=True)
        self.assert_accepts([f"    Repo root: {alias}"])
        self.assert_accepts([f"    Repo root: {self.root}"], root_arg=alias)
        self.assert_accepts([f"    Repo root: {alias}"], root_arg=alias)
        other_alias = self.base / "other-alias"
        other_alias.symlink_to(self.other, target_is_directory=True)
        self.assert_refuses([f"    Repo root: {other_alias}"])

    def test_empty_relative_or_unresolvable_root_never_uses_importer_cwd(self):
        for recorded in ("", ".", "repo", str(self.base / "missing"),
                         str(self.base / "missing" / ".." / "repo")):
            with self.subTest(recorded=recorded):
                self.assert_refuses([f"    Repo root: {recorded}"])

    def test_e4_current_key_started_receipt_still_refuses_without_retry(self):
        directory = self.new_receipts()
        before = {"stage": "policy", "inputs": "same"}
        path = directory / (E.receipt_key(before) + ".json")
        original = {"schema_version": E.SCHEMA, "identity": before, "outcome": "started"}
        E.save(path, original)
        with mock.patch.object(E, "identity", return_value=before), \
                mock.patch.object(E.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "no automatic retry"):
                E.consume(self.root, directory, "policy")
            run.assert_not_called()
        self.assertEqual(E.read(path), original)

    def test_e5_another_checkout_without_required_substring_still_refuses(self):
        self.assert_refuses(["    Repo root: /definitely/another/checkout"])


if __name__ == "__main__":
    unittest.main()
