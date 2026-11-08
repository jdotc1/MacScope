"""The opt-in ARM64 witness driver must report failures without running real tools here."""
import importlib.util
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'Scripts/arm64_golden/run_unicorn_z3.py'


class WitnessWorkflowTests(unittest.TestCase):
    def test_solver_response_must_be_unsat(self):
        self.assertTrue(SCRIPT.exists(), 'witness workflow is missing')
        spec = importlib.util.spec_from_file_location('arm64_witness', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.check_solver('unsat\n')
        for invalid in ('sat\n', 'unknown\n', '', 'unsat\nsat\n'):
            with self.subTest(invalid=invalid):
                with self.assertRaises(ValueError):
                    module.check_solver(invalid)


    def test_reuse_displays_receipt_without_invoking_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipt = Path(tmp) / 'receipt.txt'
            receipt.write_text('prior bounded evidence\n')
            result = subprocess.run([sys.executable, str(SCRIPT), '--reuse-receipt', str(receipt),
                                     '--cc', '/missing/compiler', '--z3', '/missing/solver'],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('historical evidence; not re-verified', result.stdout)
            self.assertIn('prior bounded evidence', result.stdout)

    def test_new_workflow_rejects_solver_counterexample(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            compiler = root / 'fake-cc'
            compiler.write_text('#!/bin/sh\n'
                'while [ "$1" != "-o" ]; do shift; done\n'
                'shift\n'
                'printf "#!/bin/sh\\necho PASS: result and checked unchanged registers/flags match the existing fixture\\n" > "$1"\n'
                'chmod +x "$1"\n')
            compiler.chmod(0o755)
            solver = root / 'fake-z3'
            solver.write_text('#!/bin/sh\necho sat\n')
            solver.chmod(0o755)
            out = root / 'result'
            result = subprocess.run([sys.executable, str(SCRIPT), '--run', '--out', str(out),
                                     '--cc', str(compiler), '--z3', str(solver)],
                                    capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn('did not prove', result.stderr)
            self.assertFalse((out / 'receipt.json').exists())

    def test_success_receipt_records_tool_outputs(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            compiler = root / 'fake-cc'
            compiler.write_text('#!/bin/sh\n'
                'while [ "$1" != "-o" ]; do shift; done\n'
                'shift\n'
                'printf "#!/bin/sh\\\\necho PASS: result and checked unchanged registers/flags match the existing fixture\\\\n" > "$1"\n'
                'chmod +x "$1"\n')
            compiler.chmod(0o755)
            solver = root / 'fake-z3'
            solver.write_text('#!/bin/sh\necho unsat\n')
            solver.chmod(0o755)
            out = root / 'result'
            result = subprocess.run([sys.executable, str(SCRIPT), '--run', '--out', str(out),
                                     '--cc', str(compiler), '--z3', str(solver)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            receipt = json.loads((out / 'receipt.json').read_text())
            self.assertEqual(receipt['z3_output'], 'unsat\n')
            self.assertIn('PASS:', receipt['unicorn_output'])
            self.assertIn('not a fresh MacIR test', receipt['scope'])

    def test_test_driver_dispatches_without_xcode_setup(self):
        result = subprocess.run([str(ROOT / 'Scripts/test.sh'), '--arm64-witness', '--help'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--reuse-receipt', result.stdout)


if __name__ == '__main__':
    unittest.main()
