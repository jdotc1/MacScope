#!/usr/bin/env python3
"""Synthetic native-tool identity regression; no real dependency is inspected."""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "dev_cache_tool_identity", ROOT / "Scripts/qualification/dev_dependency_cache.py")
DEV = importlib.util.module_from_spec(spec)
spec.loader.exec_module(DEV)


class GuardedToolIdentityTests(unittest.TestCase):
    def test_guard_shims_preserve_tool_identity_and_guarded_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "views").mkdir()
            real = root / "real"
            shims = root / "shims"
            custom = root / "custom"
            for directory in (real, shims, custom):
                directory.mkdir()
            for tool in ("cmake", "ninja"):
                executable = real / tool
                executable.write_text('#!/bin/sh\nprintf "tool\\n"\n')
                executable.chmod(0o755)
                shim = shims / tool
                shim.write_text(
                    '#!/bin/sh\n# storage-guard tool shim: synthetic regression\n'
                    'printf "guard\\n"\n'
                    f'exec "{executable}" "$@"\n')
                shim.chmod(0o755)
            files = (("cmake", "@CMAKE@"), ("ninja", "@NINJA@"))
            with mock.patch.object(DEV, "NATIVE_TOOL_FILES", files), \
                    mock.patch.dict(os.environ, {"PATH": str(real)}):
                baseline = DEV.native_tools_identity(root / "views")
                guarded_path = os.pathsep.join((str(shims), str(real)))
                with mock.patch.dict(os.environ, {"PATH": guarded_path}):
                    self.assertEqual(DEV.native_tools_identity(root / "views"), baseline)
                    self.assertEqual(shutil.which("cmake"), str(shims / "cmake"))
                    self.assertEqual(subprocess.check_output(["cmake"], text=True), "guard\ntool\n")
                    self.assertEqual(os.environ["PATH"], guarded_path)
                # Other wrappers remain identity-bearing; only guard adapters are transparent.
                alternate = custom / "cmake"
                alternate.write_text('#!/bin/sh\nprintf "different-tool\\n"\n')
                alternate.chmod(0o755)
                with mock.patch.dict(os.environ, {"PATH": os.pathsep.join((str(custom), guarded_path))}):
                    self.assertNotEqual(DEV.native_tools_identity(root / "views"), baseline)
                # Changing the underlying tool must invalidate identity even behind the guard.
                (real / "cmake").write_text('#!/bin/sh\nprintf "new-tool-version\\n"\n')
                with mock.patch.dict(os.environ, {"PATH": guarded_path}):
                    self.assertNotEqual(DEV.native_tools_identity(root / "views"), baseline)


class SleighToolProbeCompatibilityTests(unittest.TestCase):
    def test_only_exact_reviewed_record_has_a_predecessor(self):
        source = {"path": "ThirdParty/SleighNative/source", "blob_oid": "source"}
        current = [source, dict(DEV.SLEIGH_TOOL_PROBE_RECORD)]
        prior = DEV.sleigh_prior_records(current)
        self.assertEqual(prior, [source, DEV.SLEIGH_PRIOR_TOOL_PROBE_RECORD])
        self.assertEqual(current[1], DEV.SLEIGH_TOOL_PROBE_RECORD)
        for field in ("blob_oid", "sha256", "size", "mode"):
            changed = [source, dict(DEV.SLEIGH_TOOL_PROBE_RECORD)]
            changed[1][field] = "different"
            self.assertIsNone(DEV.sleigh_prior_records(changed))
        self.assertIsNone(DEV.sleigh_prior_records([source]))
        self.assertIsNone(DEV.sleigh_prior_records(current + [current[1]]))

    def test_invalid_predecessor_receipt_never_builds_or_repairs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()  # /var is a symlink; e1c59ab0c refuses indirect ancestors
            cache, views = root / "cache", root / "views"
            component, current, prior = "sleigh-native-source", "a" * 64, "b" * 64
            entry = cache / "artifacts/v1" / component / prior
            directory = views / component / prior
            entry.mkdir(parents=True)
            directory.mkdir(parents=True)
            receipt = directory / "VIEW.json"
            receipt.write_text("{}")
            # e1c59ab0c: an occupied SLEIGH destination is observed under existing lock domains.
            for lock_domain in (cache / "lock-guards/v1" / component / f"{prior}.guard",
                                views / component / f".{prior}.lock"):
                lock_domain.parent.mkdir(parents=True, exist_ok=True)
                lock_domain.touch()
            with mock.patch.object(DEV, "component_keys", return_value=[current, prior]), \
                    mock.patch.object(DEV, "view_receipt_valid", return_value=None), \
                    mock.patch.object(DEV, "build_payload") as build, \
                    mock.patch.object(DEV.CACHE, "materialize_command") as materialize, \
                    mock.patch.object(DEV, "verify_view") as verify:
                with self.assertRaisesRegex(DEV.DevCacheError, "REFUSED_OCCUPIED_OR_UNADMITTED"):
                    DEV.resolve(component, root, cache, views, build=True)
                build.assert_not_called()
                materialize.assert_not_called()
                verify.assert_not_called()
                self.assertEqual(receipt.read_text(), "{}")
                receipt.unlink()
                with self.assertRaisesRegex(DEV.DevCacheError, "refusing unchanged"):
                    DEV.retained_component_key(component, root, cache, views)


if __name__ == "__main__":
    unittest.main()
