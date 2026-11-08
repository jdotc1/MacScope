#!/usr/bin/env python3
"""Synthetic bootstrap receipt lifecycle; no dependency tools or real sources."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("bootstrap_evidence", Path(__file__).resolve().parents[1] / "qualification/dev_bootstrap_evidence.py")
E = importlib.util.module_from_spec(spec)
spec.loader.exec_module(E)


class BootstrapEvidenceTests(unittest.TestCase):
    def test_offline_root_ignore_deletion_is_governed(self):
        self.assertTrue(E.offline_input('.gitignore'))
        self.assertFalse(E.offline_input('nested/.gitignore'))
        with mock.patch.object(E, 'scopes', return_value=['.']), \
             mock.patch.object(E, 'git', return_value=b' D .gitignore\0') as git:
            with self.assertRaisesRegex(ValueError, 'governed inputs are dirty'):
                E.identity(Path('/synthetic'), 'offline')
            self.assertEqual(git.call_count, 1)

    def _identity_with_status(self, status):
        def fake_git(root, *arguments):
            if arguments[0] == "status":
                return status
            if arguments[0] == "ls-files":
                return b""
            return b"100644 blob abc\tThirdParty/a\0"
        with mock.patch.object(E, "scopes", return_value=["ThirdParty"]), \
             mock.patch.object(E, "git", side_effect=fake_git):
            return E.identity(Path("/synthetic"), "policy")

    def test_ignored_finder_metadata_is_admitted(self):
        value = self._identity_with_status(b"!! ThirdParty/.DS_Store\0!! ThirdParty/x/.DS_Store\0")
        self.assertEqual(value["stage"], "policy")

    def test_lookalike_ignored_names_are_still_refused(self):
        for name in ("ThirdParty/foo.DS_Store", "ThirdParty/.DS_Store.bak"):
            with self.assertRaisesRegex(ValueError, "governed inputs are dirty"):
                self._identity_with_status(f"!! {name}\0".encode())

    def test_unchanged_success_is_reused_without_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = {"stage": "policy", "inputs": "same"}
            E.save(root / (E.receipt_key(identity) + ".json"),
                   {"schema_version": E.SCHEMA, "identity": identity, "outcome": "passed", "output": ""})
            with mock.patch.object(E, "identity", return_value=identity), mock.patch.object(E.subprocess, "run") as run:
                self.assertEqual(E.consume(root, root, "policy"), "")
                run.assert_not_called()

    def test_missing_history_and_interrupted_check_never_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            identity = {"stage": "policy", "inputs": "same"}
            with mock.patch.object(E, "identity", return_value=identity), mock.patch.object(E.subprocess, "run") as run:
                with self.assertRaisesRegex(ValueError, "history is missing"):
                    E.consume(root, root, "policy")
                E.save(root / (E.receipt_key(identity) + ".json"),
                       {"schema_version": E.SCHEMA, "identity": identity, "outcome": "started"})
                with self.assertRaisesRegex(ValueError, "no automatic retry"):
                    E.consume(root, root, "policy")
                run.assert_not_called()

    def test_changed_inputs_run_once_and_failed_result_is_retained(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            old, new = {"stage": "policy", "inputs": "old"}, {"stage": "policy", "inputs": "new"}
            E.save(root / (E.receipt_key(old) + ".json"),
                   {"schema_version": E.SCHEMA, "identity": old, "outcome": "passed"})
            with mock.patch.object(E, "identity", return_value=new), mock.patch.object(E.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "failed")) as run:
                with self.assertRaisesRegex(ValueError, "check failed"):
                    E.consume(root, root, "policy")
                with self.assertRaisesRegex(ValueError, "no automatic retry"):
                    E.consume(root, root, "policy")
                self.assertEqual(run.call_count, 1)


if __name__ == "__main__":
    unittest.main()
