"""Synthetic metadata-only MachOKit device-transition admission."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    sys.modules[name] = value
    spec.loader.exec_module(value)
    return value
U = module('unsigned_machokit_device', ROOT / 'Scripts/unsigned_development.py')

class SavedMachOKitDeviceRowsTests(unittest.TestCase):
    def fixture(self):
        rows = [['.', 16777230, 101, 16749, 128, 100, 100],
                ['synthetic', 16777230, 102, 33060, 8, 200, 200]]
        digest = lambda value: hashlib.sha256(json.dumps(value, separators=(',', ':')).encode()).hexdigest()
        current = {'schema_version': 1, 'root': '/synthetic', 'version': '0.52.2',
                   'metadata_sha256': digest(rows)}
        prior = [[r[0], 16777229, *r[2:]] for r in rows]
        saved = dict(current, metadata_sha256=digest(prior))
        return saved, current, rows

    def test_saved_rows_exact_device_only_match(self):
        saved, current, rows = self.fixture()
        result = U.machokit_device_transition(saved, current, rows, 16777229)
        self.assertEqual(result['current_device'], 16777230)
        self.assertEqual(result['prior_device'], 16777229)
        self.assertEqual(result['rows'], 2)

    def test_saved_rows_reject_other_metadata_or_pinned_changes(self):
        for mode in ('inode', 'ctime', 'pinned', 'missing', 'mixed-device'):
            saved, current, rows = self.fixture()
            if mode == 'inode': rows[1][2] += 1
            elif mode == 'ctime': rows[1][6] += 1
            elif mode == 'pinned': current['version'] = 'other'
            elif mode == 'missing': rows.pop()
            else: rows[1][1] = 999
            with self.assertRaises(ValueError): U.machokit_device_transition(saved, current, rows, 16777229)

    def record_fixture(self, writable_original=False):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        parent = Path(temp.name).resolve()
        root = parent / 'root'
        root.mkdir()
        saved, current, rows = self.fixture()
        saved['root'] = current['root'] = str(root)
        original = parent / '.root.admission.json'
        original.write_text(json.dumps(saved))
        original.chmod(0o644 if writable_original else 0o444)
        historical = parent / 'historical.json'
        historical.write_text(json.dumps({'observed': [['tool', '/recorded/tool', 16777229, 1, 2, 3, 4]]}))
        captured = parent / 'captured.json'
        captured.write_text(json.dumps({'completed': True, 'prior_match': True, 'root': str(root), 'current_identity': current,
                            'rows': rows, 'prior_device': 16777229, 'historical_tool_memo': str(historical)}))
        captured.chmod(0o400)
        return captured, root, saved, current

    def test_saved_record_consumer_requires_immutable_original_receipt(self):
        path, root, saved, current = self.record_fixture(writable_original=True)
        with self.assertRaises(ValueError): U.retained_machokit_transition(path, root, saved, current)

    def test_saved_record_consumer_uses_captured_rows_without_tree_walk(self):
        path, root, saved, current = self.record_fixture()
        with mock.patch.object(Path, 'rglob', side_effect=AssertionError('no tree walk')):
            result = U.retained_machokit_transition(path, root, saved, current)
        self.assertEqual(result['rows'], 2)

    def test_failed_capture_record_is_not_admitted(self):
        path, root, saved, current = self.record_fixture()
        path.chmod(0o600)
        value = json.loads(path.read_text())
        value['completed'] = False
        path.write_text(json.dumps(value))
        path.chmod(0o400)
        with self.assertRaises(ValueError): U.retained_machokit_transition(path, root, saved, current)

    def test_access_time_change_does_not_invalidate_saved_record(self):
        from types import SimpleNamespace
        path, root, saved, current = self.record_fixture()
        original = root.parent / '.root.admission.json'
        real_lstat = Path.lstat
        counts = {}
        def access_change(candidate, *args, **kwargs):
            value = real_lstat(candidate, *args, **kwargs)
            if candidate not in (path, original): return value
            counts[candidate] = counts.get(candidate, 0) + 1
            fields = {name: getattr(value, name) for name in
                      ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns','st_uid')}
            return SimpleNamespace(**fields, st_atime_ns=counts[candidate])
        with mock.patch.object(Path, 'lstat', access_change):
            result = U.retained_machokit_transition(path, root, saved, current)
        self.assertEqual(result['rows'], 2)
