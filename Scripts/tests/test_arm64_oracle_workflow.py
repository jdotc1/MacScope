"""Bounded fixture selection for the opt-in ARM64 oracle workflow."""
import importlib.util
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[2]
PATH = ROOT / 'Scripts/arm64_golden/run_focused_oracles.py'


class Arm64OracleWorkflowTests(unittest.TestCase):
    def test_fixture_selection_preserves_addresses_and_rejects_non_arm64(self):
        self.assertTrue(PATH.exists(), 'focused oracle workflow is missing')
        spec = importlib.util.spec_from_file_location('focused_oracles', PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        dump = ('fixture.o: file format mach-o arm64\n'
                'Disassembly of section __TEXT,__text:\n'
                '0000000000000000 <_main>:\n'
                '       0: d101c3ff  sub sp, sp, #0x70\n'
                '       4: a9016ffc  stp x28, x27, [sp, #0x10]\n')
        self.assertEqual(module.fixture_words(dump, 2), [(0, 0xd101c3ff), (4, 0xa9016ffc)])
        with self.assertRaises(ValueError):
            module.fixture_words(dump.replace('mach-o arm64', 'mach-o x86-64'), 2)

    def test_curated_cases_fail_on_decode_regressions(self):
        spec = importlib.util.spec_from_file_location('focused_oracles', PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        good = [dict(word=w, category='match', detail='', capstone_status='decoded')
                for w in ('d503201f', '91000400', '8b020020', 'f9400020', '14000002', 'd65f03c0')]
        good.append(dict(word='ffffffff', category='both-reject', detail='', capstone_status='not-decoded'))
        module.check_curated(good)
        good[0]['capstone_status'] = 'not-decoded'
        with self.assertRaises(ValueError):
            module.check_curated(good)

    def test_existing_test_entrypoint_exposes_the_focused_mode(self):
        result = subprocess.run([str(ROOT / 'Scripts/test.sh'), '--arm64-oracles', '--help'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--fixture-objects', result.stdout)
        self.assertIn('--probe', result.stdout)


if __name__ == '__main__':
    unittest.main()
