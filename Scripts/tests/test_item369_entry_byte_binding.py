#!/usr/bin/env python3
"""Item 369 E1–E6 source assertions. Delivered without execution or import.

The independent stamp fixture makes the base E3 source walk reach the real
reuse gate rather than failing on a missing new migration helper.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "item369_entry_byte_binding", ROOT / "Scripts/qualification/dependency_cache.py")
CACHE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CACHE)


class EntryByteBindingTests(unittest.TestCase):
    def fixture(self):
        temporary = tempfile.TemporaryDirectory()
        root = Path(temporary.name).resolve()
        self.addCleanup(temporary.cleanup)
        # Immutable entry directories need owner-write restored for fixture cleanup.
        self.addCleanup(self.thaw, root)
        entry = root / "cache" / ("a" * 64)
        payload = entry / "payload"
        payload.mkdir(parents=True)
        (payload / "data.bin").write_bytes(b"original")
        records, total = CACHE.payload_records(payload)
        document = {"component": "ghostty-vt", "key": "a" * 64,
                    "schema_version": 1, "payload_records": records,
                    "payload_tree_sha256": CACHE.payload_tree_digest(records),
                    "file_count": 1, "total_bytes": total}
        (entry / "ENTRY.json").write_bytes(CACHE.canonical_json(document))
        CACHE.freeze_tree(entry)
        verification_root = root / "verification"
        verification_root.mkdir(mode=0o700)
        arguments = SimpleNamespace(entry=entry, component="ghostty-vt", key="a" * 64,
                                    verification_root=verification_root, binding=["domain=fixture"],
                                    destination=root / "run" / "view")
        key, receipt, identity = CACHE.verification_identity(arguments)
        value = {**identity, "entry": str(entry), "entry_metadata_sha256": "b" * 64,
                 "verification_key": key, "verification": "fixture domain accepted",
                 "verified_at": "2026-10-26T00:00:00Z", "verified_run_view": "/fixture/view"}
        receipt.parent.mkdir(parents=True, mode=0o700)
        receipt.write_bytes(CACHE.canonical_json(value))
        receipt.chmod(0o444)
        return SimpleNamespace(root=root, entry=entry, payload=payload,
                               leaf=payload / "data.bin", arguments=arguments,
                               receipt=receipt, value=value,
                               sidecar=entry / "ENTRY-STAMPS.json")

    def thaw(self, root):
        for path in [root, *root.rglob("*")]:
            if not path.is_symlink():
                path.chmod(0o700 if path.is_dir() else 0o600)

    def seed_stamps(self, fixture):
        """Independent stamped baseline; no new production helper is required."""
        files = []
        for path in sorted(fixture.payload.rglob("*"), key=lambda item: os.fsencode(item.relative_to(fixture.payload))):
            metadata = path.lstat()
            if stat.S_ISREG(metadata.st_mode):
                files.append({"path": path.relative_to(fixture.payload).as_posix(),
                              **{field: getattr(metadata, field) for field in
                                 ("st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")}})
        fixture.entry.chmod(0o755)
        fixture.sidecar.write_bytes(CACHE.canonical_json(
            {"schema_version": 1,
             "entry_receipt_sha256": hashlib.sha256((fixture.entry / "ENTRY.json").read_bytes()).hexdigest(),
             "files": files}))
        fixture.sidecar.chmod(0o444)
        fixture.entry.chmod(0o555)

    @contextlib.contextmanager
    def no_payload_hashes(self, fixture):
        real_records, real_sha256 = CACHE.payload_records, CACHE.sha256
        def metadata_only(root, **options):
            self.assertIs(options.get("hash_files"), False)
            return real_records(root, **options)
        def receipts_only(path):
            self.assertNotIn(fixture.payload, Path(path).parents)
            return real_sha256(path)
        with mock.patch.object(CACHE, "payload_records", side_effect=metadata_only), \
                mock.patch.object(CACHE, "sha256", side_effect=receipts_only), \
                mock.patch.object(CACHE, "stable_file_sha256", side_effect=AssertionError("payload rehash forbidden")):
            yield

    @contextlib.contextmanager
    def clone_calls(self):
        # Replace only macOS clonefile: admission, inventories, freezing and
        # within-run lease comparisons remain the actual production functions.
        def copy(source, destination):
            shutil.copytree(source, destination, copy_function=shutil.copy2)
        with mock.patch.object(CACHE, "clonefile_tree", side_effect=copy) as clone, \
                mock.patch.object(CACHE, "remove_view") as remove:
            yield SimpleNamespace(clone=clone, remove=remove)

    def test_e1_legacy_stamped_once_under_lock(self):
        fixture = self.fixture()
        original_mode = stat.S_IMODE(fixture.entry.lstat().st_mode)
        locked = False
        real_flock, real_write = CACHE.fcntl.flock, CACHE.write_entry_stamps
        def flock(descriptor, operation):
            nonlocal locked
            result = real_flock(descriptor, operation)
            locked = operation == CACHE.fcntl.LOCK_EX
            return result
        def write(entry):
            self.assertTrue(locked)
            return real_write(entry)
        with mock.patch.object(CACHE.fcntl, "flock", side_effect=flock), \
                mock.patch.object(CACHE, "write_entry_stamps", side_effect=write) as writer, \
                self.no_payload_hashes(fixture), contextlib.redirect_stderr(io.StringIO()) as output:
            self.assertEqual(CACHE.stamp_entry_command(fixture.arguments), 0)
            sidecar = fixture.sidecar.read_bytes()
            self.assertEqual(CACHE.stamp_entry_command(fixture.arguments), 0)
            writer.assert_called_once_with(fixture.entry)
        self.assertFalse(locked)
        self.assertIn("legacy entry was stamped", output.getvalue())
        self.assertEqual(fixture.sidecar.read_bytes(), sidecar)
        self.assertEqual(stat.S_IMODE(fixture.entry.lstat().st_mode), original_mode)
        self.assertEqual(stat.S_IMODE(fixture.sidecar.lstat().st_mode), 0o444)
        value = json.loads(sidecar)
        self.assertEqual(set(value), {"schema_version", "entry_receipt_sha256", "files"})
        self.assertEqual(value["entry_receipt_sha256"], CACHE.sha256(fixture.entry / "ENTRY.json"))
        self.assertEqual(len(value["files"]), 1)
        record = value["files"][0]
        self.assertEqual(record["path"], "data.bin")
        self.assertEqual(set(record), {"path", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"})
        for field in set(record) - {"path"}:
            self.assertEqual(record[field], getattr(fixture.leaf.lstat(), field))
        self.assertEqual(json.loads(fixture.receipt.read_bytes()), fixture.value)

        failed = self.fixture()
        with self.no_payload_hashes(failed), \
                mock.patch.object(CACHE.os, "replace", side_effect=OSError("publication interrupted")):
            with self.assertRaisesRegex(OSError, "publication interrupted"):
                CACHE.stamp_entry_command(failed.arguments)
        self.assertEqual(stat.S_IMODE(failed.entry.lstat().st_mode), 0o555)
        self.assertFalse(failed.sidecar.exists())
        temporary = failed.entry / f".ENTRY-STAMPS.json.tmp.{os.getpid()}"
        retained = temporary.read_bytes()
        self.assertEqual(stat.S_IMODE(temporary.lstat().st_mode), 0o444)
        with self.assertRaises(FileExistsError):
            CACHE.stamp_entry_command(failed.arguments)
        self.assertEqual(temporary.read_bytes(), retained)
        self.assertEqual(stat.S_IMODE(failed.entry.lstat().st_mode), 0o555)

    def test_e2_unchanged_stamped_entry_reused_without_sidecar_write(self):
        fixture = self.fixture()
        self.seed_stamps(fixture)
        sidecar = fixture.sidecar.read_bytes()
        with self.no_payload_hashes(fixture), self.clone_calls() as calls, \
                contextlib.redirect_stdout(io.StringIO()):
            CACHE.load_verification_receipt(fixture.arguments)
            self.assertEqual(CACHE.reuse_verified_command(fixture.arguments), 0)
            calls.clone.assert_called_once()
            calls.remove.assert_not_called()
        self.assertEqual(fixture.sidecar.read_bytes(), sidecar)
        self.assertEqual((fixture.arguments.destination / "data.bin").read_bytes(), b"original")
        self.assertEqual(stat.S_IMODE((fixture.arguments.destination / "data.bin").stat().st_mode), 0o444)

    def test_e3_same_size_rewrite_refused_without_removal_or_clone(self):
        fixture = self.fixture()
        self.seed_stamps(fixture)
        before = fixture.leaf.lstat()
        fixture.leaf.chmod(0o644)
        fixture.leaf.write_bytes(b"tampered")
        # Restore mtime only for E3: isolate ctime as the deciding stamp.
        # Non-root os.utime cannot restore ctime.
        os.utime(fixture.leaf, ns=(before.st_atime_ns, before.st_mtime_ns))
        fixture.leaf.chmod(0o444)
        after = fixture.leaf.lstat()
        self.assertEqual((after.st_ino, after.st_size, after.st_mtime_ns),
                         (before.st_ino, before.st_size, before.st_mtime_ns))
        self.assertNotEqual(after.st_ctime_ns, before.st_ctime_ns)
        preserved = (fixture.sidecar.read_bytes(), fixture.receipt.read_bytes(), fixture.leaf.read_bytes())
        with self.no_payload_hashes(fixture), self.clone_calls() as calls:
            with self.assertRaisesRegex(CACHE.CacheError, "entry stamp.*refusing.*re-verification"):
                CACHE.load_verification_receipt(fixture.arguments)
            with self.assertRaisesRegex(CACHE.CacheError, "entry stamp.*refusing.*re-verification"):
                CACHE.reuse_verified_command(fixture.arguments)
            with self.assertRaisesRegex(CACHE.CacheError, "entry stamp.*refusing.*re-verification"):
                CACHE.stamp_entry_command(fixture.arguments)
            calls.clone.assert_not_called()
            calls.remove.assert_not_called()
        self.assertEqual(preserved, (fixture.sidecar.read_bytes(), fixture.receipt.read_bytes(), fixture.leaf.read_bytes()))
        self.assertFalse(fixture.arguments.destination.exists())

    def test_e4_device_number_only_change_reuses(self):
        fixture = self.fixture()
        self.seed_stamps(fixture)
        sidecar = fixture.sidecar.read_bytes()
        real_lstat = Path.lstat
        def renumbered(path):
            metadata = real_lstat(path)
            if fixture.payload in path.parents and stat.S_ISREG(metadata.st_mode):
                values = {name: getattr(metadata, name) for name in dir(metadata) if name.startswith("st_")}
                values["st_dev"] += 1
                return SimpleNamespace(**values)
            return metadata
        with mock.patch.object(Path, "lstat", renumbered), self.no_payload_hashes(fixture), \
                self.clone_calls() as calls, contextlib.redirect_stdout(io.StringIO()):
            CACHE.load_verification_receipt(fixture.arguments)
            self.assertEqual(CACHE.reuse_verified_command(fixture.arguments), 0)
            calls.clone.assert_called_once()
            calls.remove.assert_not_called()
        self.assertEqual(fixture.sidecar.read_bytes(), sidecar)

    def test_e5_invalid_sidecars_refuse_without_repair(self):
        for variant in ("owner-writable", "group-writable", "symlink", "wrong-owner", "wrong-receipt-sha"):
            with self.subTest(variant=variant):
                fixture = self.fixture()
                self.seed_stamps(fixture)
                if variant == "owner-writable":
                    fixture.sidecar.chmod(0o644)
                elif variant == "group-writable":
                    fixture.sidecar.chmod(0o664)
                elif variant == "symlink":
                    fixture.entry.chmod(0o755)
                    stored = fixture.entry / "saved-stamps.json"
                    fixture.sidecar.rename(stored)
                    fixture.sidecar.symlink_to(stored.name)
                    fixture.entry.chmod(0o555)
                elif variant == "wrong-receipt-sha":
                    value = json.loads(fixture.sidecar.read_bytes())
                    value["entry_receipt_sha256"] = "0" * 64
                    fixture.sidecar.chmod(0o644)
                    fixture.sidecar.write_bytes(CACHE.canonical_json(value))
                    fixture.sidecar.chmod(0o444)
                real_lstat = Path.lstat
                def wrong_owner(path):
                    metadata = real_lstat(path)
                    if path == fixture.sidecar and variant == "wrong-owner":
                        values = {name: getattr(metadata, name) for name in dir(metadata) if name.startswith("st_")}
                        values["st_uid"] += 1
                        return SimpleNamespace(**values)
                    return metadata
                preserved = fixture.sidecar.read_bytes()
                mode = real_lstat(fixture.sidecar).st_mode
                with mock.patch.object(Path, "lstat", wrong_owner), self.no_payload_hashes(fixture), self.clone_calls() as calls:
                    for command in (CACHE.load_verification_receipt, CACHE.reuse_verified_command, CACHE.stamp_entry_command):
                        with self.assertRaisesRegex(CACHE.CacheError, "entry stamp.*refusing.*re-verification"):
                            command(fixture.arguments)
                    calls.clone.assert_not_called()
                    calls.remove.assert_not_called()
                self.assertEqual(fixture.sidecar.read_bytes(), preserved)
                self.assertEqual(real_lstat(fixture.sidecar).st_mode, mode)

    def test_e6_lock_free_unstamped_refuses_and_names_migration(self):
        fixture = self.fixture()
        with self.no_payload_hashes(fixture), self.clone_calls() as calls:
            for command in (CACHE.reuse_check_command, CACHE.reuse_verified_command):
                with self.assertRaisesRegex(CACHE.CacheError, "dependency_cache.py stamp-entry"):
                    command(fixture.arguments)
            self.assertFalse(fixture.sidecar.exists())
            calls.clone.assert_not_called()
            calls.remove.assert_not_called()


if __name__ == "__main__":
    unittest.main()
