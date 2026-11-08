#!/usr/bin/env python3
"""Item 367 synthetic source/receipt fixtures; no dependency stages or Git probes."""
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("item367_bootstrap_evidence", Path(__file__).resolve().parents[1] / "qualification/dev_bootstrap_evidence.py")
E = importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)


class Item367BootstrapOnboardingTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve() / "checkout"
        self.root.mkdir()
        self.receipts = Path(self.temporary.name).resolve() / "receipts"
        self.receipts.mkdir(mode=0o700)
        self.commit = "a" * 40
        self.log = Path(self.temporary.name).resolve() / "prior.log"
        self.log.write_text("    Repo root: " + str(self.root) + "\n" +
                            "\n".join(dict.fromkeys(E.MARKERS.values())) + "\n")

    def current(self, stage="policy", records="old"):
        return {"stage": stage, "scopes": ["governed"],
                "git_records": ["100644 blob " + ("a" if records == "old" else "b") * 40 + "\tgoverned"],
                "python": [3, 9, 6], "platform": ["darwin", "arm64"], "schema_version": E.SCHEMA,
                "python_environment": {k: os.environ.get(k, "") for k in
                                       ("PYTHONPATH", "PYTHONHOME", "PYTHONOPTIMIZE")}}

    def path(self, identity):
        return self.receipts / (E.receipt_key(identity) + ".json")

    def retain(self, identity, outcome="passed", **extra):
        value = {"schema_version": E.SCHEMA, "identity": identity, "outcome": outcome, **extra}
        E.save(self.path(identity), value)
        return value

    def import_log(self, log=None):
        def prior_identity(root, stage, revision="HEAD", clean=True):
            self.assertEqual(root, self.root)
            self.assertEqual(revision, self.commit)
            self.assertFalse(clean)
            return self.current(stage)
        with mock.patch.object(E, "identity", side_effect=prior_identity), \
                mock.patch.object(E, "tool_version", return_value="2.46.0"):
            E.import_prior(self.root, self.receipts, self.commit, log or self.log)

    def imported_policy(self):
        return next(E.read(p) for p in self.receipts.glob("*.json")
                    if E.read(p)["identity"]["stage"] == "policy")

    def test_e1_unattested_import_refuses_implicit_reuse_then_explicit_baseline(self):
        # The valid prior log was produced under A; it has no runtime attestation.
        with self.log.open("a") as stream:
            stream.write("Prior operator note: PYTHONPATH=A\n")
        with mock.patch.dict(os.environ, {"PYTHONPATH": "B", "PYTHONHOME": "", "PYTHONOPTIMIZE": ""}):
            self.import_log()
            imported = self.imported_policy()
            for field in ("python", "platform", "python_environment"):
                self.assertIsNone(imported["identity"][field])
            self.assertEqual(imported["evidence"]["runtime_attestation"], "unattested")
            before = self.current()
            with mock.patch.object(E, "identity", return_value=before), \
                    mock.patch.object(E.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "baseline")) as run:
                with self.assertRaisesRegex(ValueError, "imported runtime is unattested"):
                    E.consume(self.root, self.receipts, "policy")
                run.assert_not_called()
                reason = "Owner approved one current-runtime baseline; prior runtime is unknown"
                self.assertEqual(E.consume(self.root, self.receipts, "policy", first_history_reason=reason), "baseline")
                self.assertEqual(E.read(self.path(before))["evidence"]["reason"], reason)
                self.assertEqual(E.consume(self.root, self.receipts, "policy"), "baseline")
                self.assertEqual(run.call_count, 1)

    def test_e2_empty_directory_stays_implicit_refusal_but_explicit_first_history_runs_once(self):
        before = self.current()
        with mock.patch.object(E, "identity", return_value=before), \
                mock.patch.object(E.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "first")) as run:
            with self.assertRaisesRegex(ValueError, "history is missing"):
                E.consume(self.root, self.receipts, "policy")
            run.assert_not_called()
            self.assertEqual(E.consume(self.root, self.receipts, "policy", first_history_reason="Owner approved genuinely new stage"), "first")
            self.assertEqual(E.consume(self.root, self.receipts, "policy"), "first")
            self.assertEqual(run.call_count, 1)
            self.assertEqual(E.read(self.path(before))["outcome"], "passed")

    def test_e3_changed_governed_identity_runs_once_after_import(self):
        self.import_log()
        before = self.current(records="new")
        with mock.patch.object(E, "identity", return_value=before), \
                mock.patch.object(E.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "changed")) as run:
            self.assertEqual(E.consume(self.root, self.receipts, "policy"), "changed")
            self.assertEqual(E.consume(self.root, self.receipts, "policy"), "changed")
            self.assertEqual(run.call_count, 1)
            self.assertEqual(E.read(self.path(before))["outcome"], "passed")

    def test_e3_failed_changed_attempt_is_retained_without_retry(self):
        self.import_log()
        before = self.current(records="new")
        with mock.patch.object(E, "identity", return_value=before), \
                mock.patch.object(E.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "failed")) as run:
            with self.assertRaisesRegex(ValueError, "check failed"):
                E.consume(self.root, self.receipts, "policy")
            with self.assertRaisesRegex(ValueError, "no automatic retry"):
                E.consume(self.root, self.receipts, "policy")
            self.assertEqual(run.call_count, 1)
            self.assertEqual(E.read(self.path(before))["outcome"], "failed")

    def test_interrupted_first_history_keeps_reason_and_never_retries(self):
        before = self.current()
        with mock.patch.object(E, "identity", return_value=before), \
                mock.patch.object(E.subprocess, "run", side_effect=OSError("launch interrupted")) as run:
            with self.assertRaisesRegex(OSError, "launch interrupted"):
                E.consume(self.root, self.receipts, "policy", first_history_reason="Owner approved first attempt")
            retained = E.read(self.path(before))
            self.assertEqual(retained["outcome"], "started")
            self.assertEqual(retained["evidence"]["reason"], "Owner approved first attempt")
            with self.assertRaisesRegex(ValueError, "no automatic retry"):
                E.consume(self.root, self.receipts, "policy")
            with self.assertRaisesRegex(ValueError, "no automatic retry"):
                E.consume(self.root, self.receipts, "policy", first_history_reason="Not a retry grant")
            self.assertEqual(run.call_count, 1)

    def test_e4_current_key_started_receipt_never_retries(self):
        before = self.current()
        self.retain(before, outcome="started")
        with mock.patch.object(E, "identity", return_value=before), mock.patch.object(E.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "no automatic retry"):
                E.consume(self.root, self.receipts, "policy")
            run.assert_not_called()
            self.assertEqual(E.read(self.path(before))["outcome"], "started")

    def test_e5_other_checkout_without_required_substring_stays_rejected(self):
        self.log.write_text("    Repo root: /definitely/another/checkout\n" +
                            "\n".join(dict.fromkeys(E.MARKERS.values())) + "\n")
        with mock.patch.object(E, "identity") as identity, mock.patch.object(E.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "different checkout"):
                E.import_prior(self.root, self.receipts, self.commit, self.log)
            identity.assert_not_called()
            run.assert_not_called()
            self.assertEqual(list(self.receipts.glob("*.json")), [])

    def test_legacy_import_at_current_key_is_preserved_not_reused(self):
        before = self.current()
        original = self.retain(before, evidence={"kind": "observed-prior-bootstrap", "log": "legacy"})
        with mock.patch.object(E, "identity", return_value=before), mock.patch.object(E.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "legacy import runtime is unattested"):
                E.consume(self.root, self.receipts, "policy")
            run.assert_not_called()
            self.assertEqual(E.read(self.path(before)), original)

    def test_first_history_rejects_any_local_history_and_blank_reason(self):
        before = self.current(records="new")
        for outcome in ("passed", "failed", "started"):
            with self.subTest(outcome=outcome):
                self.retain(self.current(), outcome=outcome)
                with mock.patch.object(E, "identity", return_value=before), mock.patch.object(E.subprocess, "run") as run:
                    with self.assertRaisesRegex(ValueError, "local history already exists"):
                        E.consume(self.root, self.receipts, "policy", first_history_reason="Cannot hide old attempts")
                    run.assert_not_called()
        with mock.patch.object(E.subprocess, "run") as run:
            with self.assertRaisesRegex(ValueError, "explicit reason"):
                E.consume(self.root, self.receipts, "policy", first_history_reason="  ")
            run.assert_not_called()

    def test_first_history_rejects_edited_failed_or_started_import_history(self):
        for outcome in ("failed", "started"):
            with self.subTest(outcome=outcome):
                prior = self.current(records="old")
                for field in ("python", "platform", "python_environment"):
                    prior[field] = None
                self.retain(prior, outcome=outcome, evidence={"kind": "observed-prior-bootstrap"})
                with mock.patch.object(E, "identity", return_value=self.current(records="new")), \
                        mock.patch.object(E.subprocess, "run") as run:
                    with self.assertRaisesRegex(ValueError, "local history already exists"):
                        E.consume(self.root, self.receipts, "policy", first_history_reason="Not a retry grant")
                    run.assert_not_called()

    def test_real_first_then_import_preserves_real_reuse(self):
        before = self.current()
        original = self.retain(before, output="real")
        self.import_log()
        self.assertEqual(E.read(self.path(before)), original)
        self.assertEqual(len(list(self.receipts.glob("*.json"))), len(E.STAGES) + 1)
        with mock.patch.object(E, "identity", return_value=before), mock.patch.object(E.subprocess, "run") as run:
            self.assertEqual(E.consume(self.root, self.receipts, "policy"), "real")
            run.assert_not_called()

    def test_import_conflicts_preserve_different_log_metadata_and_partial_writes(self):
        self.import_log()
        original = self.imported_policy()
        self.import_log()  # Identical metadata is idempotent; no stage execution.
        alternate = self.log.with_name("same-transcript-other-path.log")
        alternate.write_text(self.log.read_text())
        with self.assertRaisesRegex(ValueError, "refusing to replace"):
            self.import_log(alternate)
        self.assertEqual(self.imported_policy(), original)
        # Retain only a later-stage conflict; earlier writes survive the failure.
        for path in self.receipts.glob("*.json"):
            value = E.read(path)
            if value["identity"]["stage"] != "inventory":
                path.unlink()
            else:
                value["evidence"]["transcript"] += "edited provenance\n"
                E.save(path, value)
        with self.assertRaisesRegex(ValueError, "refusing to replace"):
            self.import_log()
        self.assertEqual({E.read(p)["identity"]["stage"] for p in self.receipts.glob("*.json")},
                         {"policy", "inventory"})

    def test_os_python_version_change_after_observed_baseline_runs_once(self):
        self.import_log()
        old = self.current()
        self.retain(old, output="observed old Python")
        updated = self.current()
        updated["python"] = [3, 9, 7]
        with mock.patch.object(E, "identity", return_value=updated), \
                mock.patch.object(E.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "updated Python")) as run:
            self.assertEqual(E.consume(self.root, self.receipts, "policy"), "updated Python")
            self.assertEqual(E.consume(self.root, self.receipts, "policy"), "updated Python")
            self.assertEqual(run.call_count, 1)

    def test_cli_first_history_routes_reason_under_existing_lock_and_tool_guard(self):
        argv = ["evidence", "--root", str(self.root), "--receipts", str(self.receipts),
                "first-history", "policy", "--reason", "Owner approved this stage"]
        with mock.patch.object(sys, "argv", argv), mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(E.fcntl, "flock") as flock, mock.patch.object(E, "consume", return_value="") as consume:
            E.main()
            flock.assert_called_once()
            self.assertEqual(flock.call_args.args[1], E.fcntl.LOCK_EX)
            consume.assert_called_once_with(self.root, self.receipts, "policy",
                                            first_history_reason="Owner approved this stage")
        with mock.patch.object(sys, "argv", argv), \
                mock.patch.dict(os.environ, {"MACSCOPE_XCODEGEN": "/alternate/xcodegen"}), \
                mock.patch.object(E, "consume") as consume:
            with self.assertRaisesRegex(ValueError, "alternate XcodeGen"):
                E.main()
            consume.assert_not_called()

    def test_failed_or_started_local_history_does_not_lift_import_only_guard(self):
        self.import_log()
        before = self.current()
        old_runtime = self.current()
        old_runtime["python"] = [3, 9, 5]
        for outcome in ("failed", "started"):
            with self.subTest(outcome=outcome):
                self.retain(old_runtime, outcome=outcome)
                with mock.patch.object(E, "identity", return_value=before), \
                        mock.patch.object(E.subprocess, "run") as run:
                    with self.assertRaisesRegex(ValueError, "imported runtime is unattested"):
                        E.consume(self.root, self.receipts, "policy")
                    run.assert_not_called()


if __name__ == "__main__":
    unittest.main()
