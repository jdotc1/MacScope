"""Tiny completed-golden admission controls; no source/tool/payload hashing."""
import importlib.util
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location('unsigned_completed_golden', ROOT / 'Scripts/unsigned_development.py')
U = importlib.util.module_from_spec(spec)
spec.loader.exec_module(U)

class CompletedGoldenTests(unittest.TestCase):
    def fixture(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name).resolve()
        result = root / 'result.json'
        golden = {'passed': True, 'schemaVersion': 1, 'wrapperGitRevision': 'new', 'goldenSourceSHA256': 'd' * 64}
        result.write_text(json.dumps(golden))
        fields = lambda path: [getattr(path.stat(), name) for name in ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')]
        record_path = root / 'completion.json'
        record_path.touch()
        saved = {'version': 1, 'resultPath': str(result), 'resultMetadata': fields(result),
                 'result': golden, 'tools': 'current-tools',
                 'source': {'repository': str(ROOT), 'profile': 'golden', 'files': ['current'], 'sha256': 'd' * 64}}
        helper = SimpleNamespace(owned_receipt=lambda p: saved, fields=lambda st: [getattr(st,n) for n in ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')],
                                 ordinary=lambda p: p.lstat(), completed_path=lambda *a: record_path)
        identity = SimpleNamespace(profile_paths=lambda *a: [], _profile_snapshot=lambda *a: ['current'])
        return record_path, result, saved, helper, identity

    def test_exact_completed_new_golden_is_consumed(self):
        path, result, saved, helper, identity = self.fixture()
        value = U.completed_golden(path, ROOT, helper, identity, 'current-tools')
        self.assertEqual(value, saved['result'])

    def test_changed_result_refuses(self):
        path, result, saved, helper, identity = self.fixture()
        result.write_text('{"passed":false}')
        with self.assertRaises(ValueError): U.completed_golden(path, ROOT, helper, identity, 'current-tools')

    def test_changed_source_or_tools_refuses(self):
        for change in ('source', 'tools'):
            path, result, saved, helper, identity = self.fixture()
            if change == 'source': saved['source']['files'] = ['old']
            else: saved['tools'] = 'old-tools'
            with self.assertRaises(ValueError): U.completed_golden(path, ROOT, helper, identity, 'current-tools')

    def test_completion_source_digest_must_bind_result(self):
        path, result, saved, helper, identity = self.fixture()
        saved['source']['sha256'] = 'e' * 64
        with self.assertRaises(ValueError): U.completed_golden(path, ROOT, helper, identity, 'current-tools')

    def test_completed_result_requires_current_owner(self):
        import os
        path, result, saved, helper, identity = self.fixture()
        original = helper.ordinary
        def foreign(candidate):
            value = original(candidate)
            fields = {name: getattr(value, name) for name in
                      ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
            return SimpleNamespace(**fields, st_uid=os.getuid() + 1)
        helper.ordinary = foreign
        with self.assertRaises(ValueError): U.completed_golden(path, ROOT, helper, identity, 'current-tools')

    def test_completed_result_ignores_access_time_changes(self):
        import os
        path, result, saved, helper, identity = self.fixture()
        original = helper.ordinary
        count = [0]
        def changed_access(candidate):
            value = original(candidate)
            fields = {name: getattr(value, name) for name in
                      ('st_dev','st_ino','st_mode','st_nlink','st_size','st_mtime_ns','st_ctime_ns')}
            count[0] += 1
            return SimpleNamespace(**fields, st_uid=os.getuid(), st_atime_ns=count[0])
        helper.ordinary = changed_access
        self.assertEqual(U.completed_golden(path, ROOT, helper, identity, 'current-tools'), saved['result'])
