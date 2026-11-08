#!/usr/bin/env python3
"""Item 360 evidence-blocked adoption diagnostics; no golden execution."""
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "item360_golden_refusal", ROOT / "Scripts/native-decompiler-xpc/native_golden_receipts.py")
GOLDEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GOLDEN)


class GoldenRefusalTests(unittest.TestCase):
    def test_legacy_result_names_missing_binding_and_owner_controlled_remedy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            result = root / "golden.json"
            result.write_text('{"passed":true,"stageStampSHA256":"retained-stamp"}')
            before = result.read_bytes()
            with mock.patch.object(GOLDEN, "receipt_root", return_value=root), \
                    mock.patch.object(GOLDEN, "prior_root", return_value=None), \
                    mock.patch.object(GOLDEN, "capture_completed", side_effect=AssertionError("no adoption")), \
                    mock.patch.object(GOLDEN, "digest", side_effect=AssertionError("no hashing")), \
                    mock.patch.object(GOLDEN, "retain_document", side_effect=AssertionError("no new evidence")):
                with self.assertRaises(ValueError) as error:
                    GOLDEN.reuse_completed(result, root, root, root / "stamp", {})
                message = str(error.exception)
                for required in ("golden-completed-*", "source", "runner", "toolchain", "stage-stamp",
                                 "fresh golden run", "owner's explicit authorization", "refusing repeat"):
                    self.assertIn(required, message)
                self.assertEqual(result.read_bytes(), before)
                self.assertFalse(GOLDEN.completed_path(root, result).exists())


if __name__ == "__main__":
    unittest.main()
