import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import unsigned_development as development


class LegacyViewAdmissionTests(unittest.TestCase):
    def cache(self, structure, state):
        return SimpleNamespace(view_receipt_structure_valid=Mock(return_value=structure),
                               view_stamp_state=Mock(return_value=state), write_view_stamps=Mock())

    def invoke(self, cache):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'surface').mkdir()
            return development.admit_retained_view(cache, root/'surface/key/VIEW.json',
                root/'entry', root/'surface/key/view', 'ghostty-surface', 'key')

    def test_valid_stamped_view_is_reused_without_rewrite(self):
        cache = self.cache({'accepted': True}, 'valid')
        self.assertEqual(self.invoke(cache), ({'accepted': True}, False))
        cache.write_view_stamps.assert_not_called()

    def test_missing_legacy_stamps_are_adopted_once_under_existing_lock(self):
        cache = self.cache({'accepted': True}, 'missing')
        self.assertEqual(self.invoke(cache), ({'accepted': True}, True))
        cache.write_view_stamps.assert_called_once()

    def test_invalid_existing_stamps_are_never_repaired(self):
        cache = self.cache({'accepted': True}, 'invalid')
        with self.assertRaises(ValueError): self.invoke(cache)
        cache.write_view_stamps.assert_not_called()

    def test_invalid_structure_has_no_materialization_or_verification_fallback(self):
        cache = self.cache(None, 'missing')
        with self.assertRaises(ValueError): self.invoke(cache)
        cache.view_stamp_state.assert_not_called()
        cache.write_view_stamps.assert_not_called()


if __name__ == '__main__': unittest.main()

class SleighViewAdmissionTests(unittest.TestCase):
    def test_sleigh_uses_occupied_view_admission_and_never_generic_stamp_writer(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cache = SimpleNamespace(sleigh_occupied_view=Mock(side_effect=ValueError('missing occupied stamps')),
                                    view_receipt_structure_valid=Mock(), view_stamp_state=Mock(), write_view_stamps=Mock())
            entry = root/'artifacts/v1/sleigh-native-source/key'
            receipt = root/'views/sleigh-native-source/key/VIEW.json'
            with self.assertRaisesRegex(ValueError, 'missing occupied stamps'):
                development.admit_retained_view(cache, receipt, entry, receipt.parent/'SleighNativeSource', 'sleigh-native-source', 'key')
            cache.sleigh_occupied_view.assert_called_once_with(root, root/'views', 'key')
            cache.view_receipt_structure_valid.assert_not_called()
            cache.write_view_stamps.assert_not_called()
