"""Focused comparison must preserve address and failed-decode alignment."""
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parents[1] / 'arm64_golden' / 'compare_capstone.py'


class CompareCapstoneTests(unittest.TestCase):
    def test_valid_and_rejected_word_are_reported_in_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'sweep.tsv'
            output = Path(tmp) / 'comparison.json'
            tool = Path(tmp) / 'cstool'
            tool.write_text('#!/bin/sh\n'
                            'if [ "$1" = -v ]; then echo fixture-capstone; exit 0; fi\n'
                            'if [ "$2" = 1f2003d5 ]; then '
                            'printf "%s  1f 20 03 d5  nop\\n" "${3#0x}"; exit 0; fi\n'
                            'echo "ERROR: invalid assembly code"; exit 252\n')
            tool.chmod(0o755)
            source.write_text(
                '# word\tsource\tcategory\tdetail\tgroup\tfields\tknown\tllvm\tmacscope\n'
                'd503201f\tfile\tmatch\t\tbranch\t\t\tnop\tnop\n'
                'ffffffff\tfile\tboth-reject\t\tunknown\t\t\t<unknown>\tunknown\n'
            )
            (Path(tmp) / 'summary.json').write_text(json.dumps({'header': ['# seed=1 unique_words=2 base=0x100000000']}))
            result = subprocess.run(
                [sys.executable, str(SCRIPT), '--sweep', str(source), '--base', '0x100000000',
                 '--out', str(output), '--cstool', str(tool)], capture_output=True, text=True
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            rows = json.loads(output.read_text())['rows']
            self.assertEqual([r['address'] for r in rows], ['0x100000000', '0x100000004'])
            self.assertEqual(rows[0]['capstone'], 'nop')
            self.assertIsNone(rows[1]['capstone'])
            self.assertEqual(rows[1]['capstone_status'], 'not-decoded')

            bad_output = Path(tmp) / 'bad.json'
            result = subprocess.run(
                [sys.executable, str(SCRIPT), '--sweep', str(source), '--base', '0x100000004',
                 '--out', str(bad_output), '--cstool', str(tool)], capture_output=True, text=True
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse(bad_output.exists())
            self.assertIn('base does not match', result.stderr)


if __name__ == '__main__':
    unittest.main()
