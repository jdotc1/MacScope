"""Portable tests for the opt-in QBDI witness driver."""
import importlib.util
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'Scripts/arm64_golden/run_qbdi_witness.py'


class QBDIWitnessWorkflowTests(unittest.TestCase):
    def test_rejects_missing_or_ambiguous_success_marker(self):
        self.assertTrue(SCRIPT.exists(), 'QBDI witness workflow is missing')
        spec = importlib.util.spec_from_file_location('qbdi_witness', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.check_trace('QBDI 0.12.1\nPASS\n')
        for bad in ('FAIL\n', '', 'PASS\nFAIL\n', 'PASS\nPASS\n'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                module.check_trace(bad)


    def test_receipt_reuse_never_calls_compiler(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipt = Path(tmp) / 'receipt.txt'
            receipt.write_text('retained trace evidence\n')
            result = subprocess.run([sys.executable, str(SCRIPT), '--reuse-receipt', str(receipt),
                                     '--cc', '/missing/compiler'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('historical evidence; not re-verified', result.stdout)
            self.assertIn('retained trace evidence', result.stdout)

    def test_substitute_trace_failure_does_not_create_receipt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            compiler = root / 'fake-cc'
            compiler.write_text('#!/bin/sh\n'
                'while [ "$1" != "-o" ]; do shift; done\n'
                'shift\n'
                'printf "#!/bin/sh\\nprintf \"FAIL\\\\n\"\\n" > "$1"\n'
                'chmod +x "$1"\n')
            compiler.chmod(0o755)
            out = root / 'result'
            result = subprocess.run([sys.executable, str(SCRIPT), '--run', '--out', str(out),
                                     '--cc', str(compiler)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('unambiguous PASS', result.stderr)
            self.assertFalse((out / 'receipt.json').exists())

    def test_substitute_trace_success_records_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            compiler = root / 'fake-cc'
            compiler.write_text('#!/bin/sh\n'
                'while [ "$1" != "-o" ]; do shift; done\n'
                'shift\n'
                'printf "#!/bin/sh\\necho PASS\\n" > "$1"\n'
                'chmod +x "$1"\n')
            compiler.chmod(0o755)
            out = root / 'result'
            result = subprocess.run([sys.executable, str(SCRIPT), '--run', '--out', str(out),
                                     '--cc', str(compiler)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = json.loads((out / 'receipt.json').read_text())
            self.assertEqual(receipt['trace_output'], 'PASS\n')
            self.assertIn('not MacScope app runtime', receipt['scope'])

    def test_test_driver_dispatches_without_xcode_setup(self):
        result = subprocess.run([str(ROOT / 'Scripts/test.sh'), '--arm64-qbdi', '--help'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--reuse-receipt', result.stdout)


if __name__ == '__main__':
    unittest.main()
