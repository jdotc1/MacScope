import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import unsigned_development as development


class RetainedToolIdentityTests(unittest.TestCase):
    def rows(self, device):
        return [[name, '/tools/' + name, device, 100 + index, 200, 300, 400]
                for index, name in enumerate(('compiler', 'sdk', 'system'))]

    def candidate(self, rows, identity='a' * 64):
        return {'source_memo': '/memo/accepted.json', 'observed': rows, 'identity': identity}

    def test_exact_memo_identity_is_reused(self):
        rows = self.rows(29)
        result = development.select_retained_tool_identity(rows, [self.candidate(rows)])
        self.assertEqual(result['identity'], 'a' * 64)
        self.assertFalse(result['device_transition'])

    def test_coherent_device_only_transition_preserves_identity(self):
        result = development.select_retained_tool_identity(self.rows(30), [self.candidate(self.rows(29))])
        self.assertEqual(result['identity'], 'a' * 64)
        self.assertTrue(result['device_transition'])
        self.assertEqual(result['prior_observed'], self.rows(29))
        self.assertEqual(result['current_observed'], self.rows(30))

    def test_any_nondevice_drift_is_refused(self):
        for column, value in [(0, 'other'), (1, '/other/compiler'), (3, 999), (4, 999), (5, 999), (6, 999)]:
            current = self.rows(30)
            current[0][column] = value
            with self.assertRaises(ValueError):
                development.select_retained_tool_identity(current, [self.candidate(self.rows(29))])

    def test_partial_or_inconsistent_device_mapping_is_refused(self):
        for device in (29, 31):
            current = self.rows(30)
            current[1][2] = device
            with self.assertRaises(ValueError):
                development.select_retained_tool_identity(current, [self.candidate(self.rows(29))])

    def test_missing_conflicting_or_malformed_receipts_are_refused(self):
        for candidates in ([], [self.candidate(self.rows(29), 'bad')],
                           [self.candidate(self.rows(29)), self.candidate(self.rows(29), 'b' * 64)]):
            with self.assertRaises(ValueError):
                development.select_retained_tool_identity(self.rows(30), candidates)


if __name__ == '__main__':
    unittest.main()
