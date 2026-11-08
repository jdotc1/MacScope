"""Isolated first-view controls; no real producer, source or payload verification."""
import contextlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from test_dev_dependency_cache import DEV


class FreshCrashSleighTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name).resolve()
        self.cache, self.views = self.root / 'cache', self.root / 'views'
        self.cache.mkdir()
        self.views.mkdir()
        self.key = 'a' * 64
        self.entry = self.cache / 'artifacts/v1/sleigh-native-source' / self.key
        self.directory = self.views / 'sleigh-native-source' / self.key
        self.guard = self.cache / 'lock-guards/v1/sleigh-native-source' / (self.key + '.guard')
        self.lock = self.cache / 'locks/v1/sleigh-native-source' / (self.key + '.lock')
        self.calls = []

    def produce(self, component, repository, temporary):
        with DEV.entry_lock_guard(self.guard) as acquired:
            self.assertFalse(acquired)
        self.assertTrue(self.lock.is_dir())
        self.assertFalse(self.entry.exists())
        self.assertFalse(self.directory.exists())
        payload = temporary / 'payload'
        payload.mkdir()
        (payload / 'synthetic').write_text('fixture')
        self.calls.append('producer')
        return payload

    def publish(self, args):
        args.entry.mkdir(parents=True)
        (args.entry / 'ENTRY.json').write_text('{}')
        self.calls.append('entry')

    def materialize(self, args):
        args.destination.mkdir()
        self.calls.append('clone')

    def run_fresh(self, producer=None, publish=None, key=None, structure=True, stamps=None):
        with contextlib.ExitStack() as stack:
            stack.enter_context(mock.patch.object(DEV, 'build_payload', side_effect=producer or self.produce))
            stack.enter_context(mock.patch.object(DEV.CACHE, 'publish_command', side_effect=publish or self.publish))
            stack.enter_context(mock.patch.object(DEV.CACHE, 'materialize_command', side_effect=self.materialize))
            stack.enter_context(mock.patch.object(DEV, 'verify_view', side_effect=lambda *a: self.calls.append('domain')))
            stack.enter_context(mock.patch.object(DEV.CACHE, 'entry_metadata_digest', return_value='b' * 64))
            stack.enter_context(mock.patch.object(DEV.CACHE, 'sha256', return_value='c' * 64))
            stack.enter_context(mock.patch.object(DEV, 'view_receipt_structure_valid', return_value={'fixture': True} if structure else None))
            stack.enter_context(mock.patch.object(DEV, 'write_view_stamps', side_effect=stamps or (lambda *a: self.calls.append('stamps'))))
            stack.enter_context(mock.patch.object(DEV, 'component_key', return_value=key or self.key))
            stack.enter_context(mock.patch.object(DEV.CACHE, 'stable_file_sha256', side_effect=AssertionError('no payload hashes')))
            return DEV.fresh_sleigh_view(self.root, self.cache, self.views, self.key)

    def test_fresh_producer_publishes_bound_view_under_existing_locks(self):
        result = self.run_fresh()
        self.assertEqual(self.calls, ['producer', 'entry', 'clone', 'domain', 'stamps'])
        self.assertEqual(result['status'], 'published-miss')
        receipt = json.loads((self.directory / 'VIEW.json').read_text())
        self.assertEqual(receipt['key'], self.key)
        self.assertEqual(receipt['entry'], str(self.entry))
        self.assertEqual(receipt['view'], str(self.directory / 'SleighNativeSource'))
        self.assertFalse(self.lock.exists())

    def test_existing_entry_or_view_never_invokes_producer(self):
        for occupied in (self.entry, self.directory):
            occupied.mkdir(parents=True)
            with self.assertRaisesRegex(DEV.DevCacheError, 'occupied'):
                self.run_fresh()
            self.assertEqual(self.calls, [])
            occupied.rmdir()

    def test_busy_guard_preserves_destinations(self):
        with DEV.entry_lock_guard(self.guard):
            with self.assertRaisesRegex(DEV.DevCacheError, 'busy'):
                self.run_fresh()
        self.assertEqual(self.calls, [])

    def test_existing_producer_lock_is_not_reclaimed(self):
        self.lock.mkdir(parents=True)
        with self.assertRaises(DEV.DevCacheError):
            self.run_fresh()
        self.assertTrue(self.lock.exists())
        self.assertEqual(self.calls, [])

    def test_collision_during_producer_is_preserved_without_publication(self):
        def collision(*args):
            payload = self.produce(*args)
            self.directory.mkdir()
            (self.directory / 'foreign').write_text('preserve')
            return payload
        with self.assertRaisesRegex(DEV.DevCacheError, 'occupied'):
            self.run_fresh(producer=collision)
        self.assertEqual((self.directory / 'foreign').read_text(), 'preserve')
        self.assertFalse(self.entry.exists())
        self.assertEqual(self.calls, ['producer'])

    def test_producer_failure_never_creates_entry_or_view(self):
        with self.assertRaisesRegex(RuntimeError, 'producer failed'):
            self.run_fresh(producer=mock.Mock(side_effect=RuntimeError('producer failed')))
        self.assertFalse(self.entry.exists())
        self.assertFalse(self.directory.exists())
        self.assertFalse(self.lock.exists())

    def test_occupied_resolve_does_not_enter_fresh_path(self):
        with mock.patch.object(DEV, 'retained_component_key', return_value=(self.key, False)), \
             mock.patch.object(DEV, 'sleigh_destination_occupied', return_value=True), \
             mock.patch.object(DEV, 'sleigh_occupied_view', return_value={'status': 'existing'}), \
             mock.patch.object(DEV, 'fresh_sleigh_view', side_effect=AssertionError('fresh forbidden')):
            self.assertEqual(DEV.resolve('sleigh-native-source', self.root, self.cache, self.views, True),
                             {'status': 'existing'})

    def test_generic_resolve_requires_explicit_fresh_producer_opt_in(self):
        with mock.patch.object(DEV, 'retained_component_key', return_value=(self.key, False)), \
             mock.patch.object(DEV, 'sleigh_destination_occupied', return_value=False), \
             mock.patch.object(DEV, 'fresh_sleigh_view', side_effect=AssertionError('producer forbidden')):
            with self.assertRaisesRegex(DEV.Unavailable, 'explicit fresh'):
                DEV.resolve('sleigh-native-source', self.root, self.cache, self.views, True)

    def test_explicit_fresh_option_routes_only_vacant_current_key(self):
        with mock.patch.object(DEV, 'retained_component_key', return_value=(self.key, False)), \
             mock.patch.object(DEV, 'sleigh_destination_occupied', return_value=False), \
             mock.patch.object(DEV, 'fresh_sleigh_view', return_value={'fresh': True}):
            self.assertEqual(DEV.resolve('sleigh-native-source', self.root, self.cache, self.views, True,
                                         fresh_sleigh=True), {'fresh': True})

    def test_changed_producer_key_refuses_entry_publication(self):
        with self.assertRaisesRegex(DEV.DevCacheError, 'key changed'):
            self.run_fresh(key='b' * 64)
        self.assertFalse(self.entry.exists())
        self.assertFalse(self.directory.exists())

    def test_invalid_first_view_receipt_preserves_entry_without_view(self):
        with self.assertRaisesRegex(DEV.DevCacheError, 'structural receipt'):
            self.run_fresh(structure=False)
        self.assertTrue(self.entry.exists())
        self.assertFalse(self.directory.exists())
        self.assertNotIn('stamps', self.calls)

    def test_late_destination_collision_preserves_foreign_view(self):
        def collide(*args):
            self.directory.mkdir()
            (self.directory / 'foreign').write_text('preserve')
        with self.assertRaisesRegex(DEV.DevCacheError, 'occupied at publication'):
            self.run_fresh(stamps=collide)
        self.assertEqual((self.directory / 'foreign').read_text(), 'preserve')
        self.assertFalse((self.directory / 'VIEW.json').exists())

    def test_busy_view_lock_refuses_without_producer_or_reclaim(self):
        path = self.views / 'sleigh-native-source' / ('.' + self.key + '.lock')
        path.parent.mkdir()
        with path.open('w') as held:
            DEV.fcntl.flock(held.fileno(), DEV.fcntl.LOCK_EX | DEV.fcntl.LOCK_NB)
            with self.assertRaisesRegex(DEV.DevCacheError, 'view lock is busy'):
                self.run_fresh()
        self.assertEqual(self.calls, [])
        self.assertFalse(self.lock.exists())

    def test_symlink_destination_is_occupied_and_preserved(self):
        self.entry.parent.mkdir(parents=True)
        self.entry.symlink_to(self.root / 'missing')
        with self.assertRaisesRegex(DEV.DevCacheError, 'occupied'):
            self.run_fresh()
        self.assertTrue(self.entry.is_symlink())
        self.assertEqual(self.calls, [])

    def test_unsafe_view_lock_refuses_without_producer(self):
        path = self.views / 'sleigh-native-source' / ('.' + self.key + '.lock')
        path.parent.mkdir()
        path.write_text('foreign')
        path.chmod(0o666)
        with self.assertRaisesRegex(DEV.DevCacheError, 'view lock is unsafe'):
            self.run_fresh()
        self.assertEqual(path.read_text(), 'foreign')
        self.assertEqual(self.calls, [])

    def test_first_view_uses_real_structural_admission_and_readonly_receipt(self):
        def publish(args):
            args.entry.mkdir(parents=True)
            records, size = DEV.CACHE.payload_records(args.payload, hash_files=False)
            manifest = {'payload_records': records, 'total_bytes': size}
            DEV.CACHE.write_new_canonical(args.entry / 'ENTRY.json', manifest)
        def materialize(args):
            args.destination.mkdir()
            (args.destination / 'synthetic').write_text('fixture')
            DEV.CACHE.freeze_tree(args.destination)
        with contextlib.ExitStack() as stack:
            for name, replacement in (
                ('build_payload', self.produce),
                ('verify_view', lambda *a: None),
                ('component_key', lambda *a: self.key),
            ):
                stack.enter_context(mock.patch.object(DEV, name, side_effect=replacement))
            stack.enter_context(mock.patch.object(DEV.CACHE, 'publish_command', side_effect=publish))
            stack.enter_context(mock.patch.object(DEV.CACHE, 'materialize_command', side_effect=materialize))
            stack.enter_context(mock.patch.object(DEV.CACHE, 'sha256', return_value='c' * 64))
            stack.enter_context(mock.patch.object(DEV.CACHE, 'stable_file_sha256', side_effect=AssertionError('payload hash forbidden')))
            result = DEV.fresh_sleigh_view(self.root, self.cache, self.views, self.key)
            receipt = self.directory / 'VIEW.json'
            self.assertEqual(receipt.stat().st_mode & 0o222, 0)
            self.assertIsNotNone(DEV.view_receipt_valid(receipt, self.entry, result['view'],
                                                     'sleigh-native-source', self.key))
