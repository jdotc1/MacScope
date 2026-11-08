"""Portable checks for the bounded BinDiff comparison driver."""
import importlib.util
from contextlib import closing
from pathlib import Path
import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / 'Scripts/version-matching/run_bindiff_comparison.py'


class BinDiffComparisonWorkflowTests(unittest.TestCase):
    def test_matcher_contract_detects_wrong_pair_and_missing_change(self):
        self.assertTrue(SCRIPT.exists(), 'comparison workflow missing')
        spec = importlib.util.spec_from_file_location('bindiff_comparison', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        good = {'matches': [
            {'oldID': 'old.alpha', 'newID': 'new.alpha', 'basis': 'symbolName', 'differences': []},
            {'oldID': 'old.beta', 'newID': 'new.beta', 'basis': 'symbolName', 'differences': ['body']},
        ], 'addedIDs': ['new.added'], 'removedIDs': ['old.removed'], 'unresolved': []}
        module.check_matcher(good)
        good['matches'][1]['differences'] = []
        with self.assertRaises(ValueError):
            module.check_matcher(good)


    def test_reuse_receipt_does_not_invoke_tools(self):
        with tempfile.TemporaryDirectory() as tmp:
            receipt = Path(tmp) / 'retained.txt'
            receipt.write_text('historical comparison\n')
            result = subprocess.run([sys.executable, str(SCRIPT), '--reuse-receipt', str(receipt),
                                     '--bindiff', '/no/bindiff'], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('historical evidence; not re-verified', result.stdout)
            self.assertIn('historical comparison', result.stdout)

    def test_workflow_records_fake_bindiff_results(self):
        spec = importlib.util.spec_from_file_location('bindiff_comparison', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        matcher = {'matches': [
            {'oldID': 'old.alpha', 'newID': 'new.alpha', 'basis': 'symbolName', 'differences': []},
            {'oldID': 'old.beta', 'newID': 'new.beta', 'basis': 'symbolName', 'differences': ['body']},
        ], 'addedIDs': ['new.added'], 'removedIDs': ['old.removed'], 'unresolved': []}
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp).resolve() / 'result'
            def fake_run(cmd, input_data=None):
                if cmd[0] == 'protoc':
                    self.assertIsNotNone(input_data)
                    return b'synthetic protobuf'
                if cmd[0] == 'swiftc':
                    return b''
                if cmd[0] == str(out / 'macscope-matcher'):
                    return json.dumps(matcher).encode()
                if cmd[0] == 'bindiff':
                    with closing(sqlite3.connect(out / 'synthetic-output.BinDiff')) as db:
                        db.executescript('CREATE TABLE functionalgorithm (id INTEGER, name TEXT);'
                            'CREATE TABLE function (address1 INTEGER, name1 TEXT, address2 INTEGER, '
                            'name2 TEXT, similarity REAL, confidence REAL, algorithm INTEGER);'
                            "INSERT INTO functionalgorithm VALUES (1, 'fixture');"
                            "INSERT INTO function VALUES (4096, '_alpha', 8192, '_alpha', 1.0, 1.0, 1);")
                        db.commit()
                    return b'fake bindiff output\n'
                raise AssertionError(cmd)
            with patch.object(module, 'run_command', side_effect=fake_run), \
                 patch.object(sys, 'argv', ['driver', '--run', '--out', str(out)]):
                self.assertEqual(module.main(), 0)
            report = json.loads((out / 'comparison.json').read_text())
            self.assertEqual(report['bindiff_pairs'][0]['old_name'], '_alpha')
            self.assertIn('not full app analysis', report['scope'])

    def test_existing_driver_exposes_mode_without_xcode_setup(self):
        result = subprocess.run([str(ROOT / 'Scripts/test.sh'), '--bindiff-comparison', '--help'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--reuse-receipt', result.stdout)


if __name__ == '__main__':
    unittest.main()
