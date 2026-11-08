"""First synthetic specifications for occupied SLEIGH resolve admission."""
import contextlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock
from test_dev_dependency_cache import DEV


class PartialFenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()  # /var is a symlink; e1c59ab0c refuses indirect ancestors
        self.cache, self.views = self.root / 'cache', self.root / 'views'
        self.key = 'b' * 64
        self.component = 'sleigh-native-source'
        self.entry = self.cache / 'artifacts/v1' / self.component / self.key
        self.directory = self.views / self.component / self.key
        self.guard = self.cache / 'lock-guards/v1' / self.component / (self.key + '.guard')
        self.lock = self.cache / 'locks/v1' / self.component / (self.key + '.lock')
        self.view_lock = self.views / self.component / ('.' + self.key + '.lock')
        for path in (self.guard, self.view_lock):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.touch()
        self.entry.mkdir(parents=True)
        (self.entry / 'evidence').write_text('preserve')

    def call(self, valid=None, build=False, compatibility=False):
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(DEV, 'retained_component_key', return_value=(self.key, compatibility)))
            stack.enter_context(mock.patch.object(DEV, 'view_receipt_valid', side_effect=valid if isinstance(valid, list) else None, return_value=valid))
            for owner, name in ((DEV, 'ensure_entry'), (DEV, 'remove_tree'), (DEV, 'verify_view'),
                                (DEV, 'write_view_stamps'), (DEV.CACHE, 'materialize_command')):
                stack.enter_context(mock.patch.object(owner, name, side_effect=AssertionError('forbidden effect: ' + name)))
            return DEV.resolve(self.component, self.root, self.cache, self.views, build)

    def test_entry_only_refuses_before_any_fallback(self):
        for build in (False, True):
            for compatibility in (False, True):
                with self.subTest(build=build, compatibility=compatibility):
                    with self.assertRaises(DEV.DevCacheError):
                        self.call(build=build, compatibility=compatibility)
        self.assertEqual((self.entry / 'evidence').read_text(), 'preserve')
        self.assertFalse(self.directory.exists())

    def test_valid_view_reuses_without_entry_stamp(self):
        self.directory.mkdir()
        value = {'verified_at': 'historical'}
        self.assertEqual(self.call(value)['status'], 'view-reused')
        self.assertFalse((self.entry / 'ENTRY-STAMPS.json').exists())

    def test_changed_admission_refuses(self):
        self.directory.mkdir()
        with self.assertRaises(DEV.DevCacheError):
            self.call([{'verified_at': 'historical'}, None])

    def test_missing_or_busy_domain_preserves_orphans(self):
        self.lock.parent.mkdir(parents=True)
        self.lock.mkdir()
        (self.lock / 'orphan').write_text('unowned')
        with self.assertRaises(DEV.DevCacheError):
            self.call()
        self.assertEqual((self.lock / 'orphan').read_text(), 'unowned')
        self.guard.unlink()
        with self.assertRaises(DEV.DevCacheError):
            self.call()
        self.assertFalse(self.guard.exists())

    def test_indirect_destinations_refuse(self):
        self.directory.symlink_to(self.root / 'missing')
        with self.assertRaises(DEV.DevCacheError):
            self.call({'verified_at': 'historical'})
        self.assertTrue(self.directory.is_symlink())

    def test_admission_exception_preserves_destinations(self):
        self.directory.mkdir()
        with mock.patch.object(DEV, 'view_receipt_valid', side_effect=OSError('unknown')):
            with self.assertRaises(DEV.DevCacheError):
                DEV.sleigh_occupied_view(self.cache, self.views, self.key)
        self.assertTrue(self.entry.is_dir())
        self.assertTrue(self.directory.is_dir())
