#!/usr/bin/env python3
"""Synthetic Item 366 source coverage; no real dependency is inspected.

This file is delivered without executing or importing it in the Item 366 task.
"""
from __future__ import annotations

import contextlib
import importlib.util
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "item366_view_byte_binding", ROOT / "Scripts/qualification/dev_dependency_cache.py")
DEV = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEV)


class ViewByteBindingTests(unittest.TestCase):
    def fixture(self, component="sleigh-native-source"):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name).resolve()
        cache, views, key = root / "cache", root / "views", "a" * 64
        entry = cache / "artifacts/v1" / component / key
        directory = views / component / key
        entry.mkdir(parents=True)
        directory.mkdir(parents=True)
        view = directory / DEV.COMPONENTS[component]["view_name"]
        self.write_payload(view)
        records, total = DEV.CACHE.payload_records(view)
        manifest = {"payload_records": records, "total_bytes": total}
        (entry / "ENTRY.json").write_bytes(DEV.canonical_json(manifest))
        receipt = directory / "VIEW.json"
        value = {"schema_version": DEV.VIEW_SCHEMA_VERSION, "component": component,
                 "key": key, "entry": str(entry), "view": str(view),
                 "entry_receipt_sha256": DEV.CACHE.sha256(entry / "ENTRY.json"),
                 "descriptors": {}}
        receipt.write_bytes(DEV.canonical_json(value))
        receipt.chmod(0o444)
        return SimpleNamespace(root=root, cache=cache, views=views, key=key, entry=entry,
                               directory=directory, view=view, receipt=receipt,
                               sidecar=directory / "VIEW-STAMPS.json", component=component,
                               manifest=manifest, value=value)

    def write_payload(self, view):
        materialization = view / "materialization"
        (materialization / "package").mkdir(parents=True)
        (materialization / "MATERIALIZATION.json").write_bytes(b'{"fixture":true}\n')
        (materialization / "package/data.bin").write_bytes(b"original")
        DEV.CACHE.freeze_tree(view)

    @contextlib.contextmanager
    def resolver(self, fixture, *, compatibility=False):
        with mock.patch.object(DEV, "retained_component_key", return_value=(fixture.key, compatibility)), \
                mock.patch.object(DEV, "ensure_entry", return_value=(fixture.entry, "verified-hit")), \
                mock.patch.object(DEV, "native_bridge_materialization", return_value=fixture.view / "materialization"), \
                mock.patch.object(DEV, "remove_tree") as remove, \
                mock.patch.object(DEV.CACHE, "materialize_command") as materialize, \
                mock.patch.object(DEV, "verify_view") as verify:
            yield SimpleNamespace(remove=remove, materialize=materialize, verify=verify)

    def resolve(self, fixture, build=False):
        return DEV.resolve(fixture.component, fixture.root, fixture.cache, fixture.views, build=build)

    def valid(self, fixture):
        return DEV.view_receipt_valid(fixture.receipt, fixture.entry, fixture.view,
                                      fixture.component, fixture.key)

    def adopt(self, fixture):
        with self.resolver(fixture) as calls:
            result = self.resolve(fixture)
            calls.remove.assert_not_called()
            calls.materialize.assert_not_called()
            calls.verify.assert_not_called()
        return result

    def seed_stamps(self, fixture):
        """Independent stamped fixture, also usable for the base source walk."""
        records = []
        for path in sorted(fixture.view.rglob("*"), key=lambda item: os.fsencode(item.relative_to(fixture.view))):
            metadata = path.lstat()
            if stat.S_ISREG(metadata.st_mode):
                records.append({"path": path.relative_to(fixture.view).as_posix(),
                                **{field: getattr(metadata, field) for field in
                                   ("st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")}})
        fixture.sidecar.write_bytes(DEV.canonical_json(
            {"schema_version": 1, "view_receipt_sha256": DEV.sha256_bytes(fixture.receipt.read_bytes()),
             "files": records}))
        fixture.sidecar.chmod(0o444)

    def assert_refuses_without_repair(self, fixture, *, compatibility=False, build=True):
        before = (fixture.receipt.read_bytes(), fixture.sidecar.read_bytes(),
                  (fixture.view / "materialization/package/data.bin").read_bytes())
        with self.resolver(fixture, compatibility=compatibility) as calls:
            with self.assertRaisesRegex(DEV.DevCacheError, "stamp.*refusing.*re-verification"):
                self.resolve(fixture, build=build)
            calls.remove.assert_not_called()
            calls.materialize.assert_not_called()
            calls.verify.assert_not_called()
        self.assertEqual(before, (fixture.receipt.read_bytes(), fixture.sidecar.read_bytes(),
                                 (fixture.view / "materialization/package/data.bin").read_bytes()))

    def test_v1_locked_legacy_adoption(self):
        fixture = self.fixture()
        with mock.patch.object(DEV, "log") as log:
            self.assertEqual(self.adopt(fixture)["status"], "view-reused")
        self.assertTrue(any("view was stamped" in call.args[0] for call in log.call_args_list))
        sidecar = json.loads(fixture.sidecar.read_bytes())
        self.assertEqual(stat.S_IMODE(fixture.sidecar.lstat().st_mode), 0o444)
        self.assertEqual(sidecar["view_receipt_sha256"], DEV.sha256_bytes(fixture.receipt.read_bytes()))
        files = {record["path"]: record for record in sidecar["files"]}
        self.assertEqual(set(files), {"materialization/MATERIALIZATION.json", "materialization/package/data.bin"})
        for relative, record in files.items():
            metadata = (fixture.view / relative).lstat()
            self.assertEqual(set(record), {"path", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"})
            for field in set(record) - {"path"}:
                self.assertEqual(record[field], getattr(metadata, field))
        self.assertEqual(json.loads(fixture.receipt.read_bytes()), fixture.value)

    def test_v2_unchanged_reuse_preserves_sidecar_without_payload_hashing(self):
        fixture = self.fixture()
        self.seed_stamps(fixture)
        before = fixture.sidecar.read_bytes()
        real_sha256 = DEV.CACHE.sha256
        real_records = DEV.CACHE.payload_records
        def metadata_only(root, **options):
            self.assertIs(options.get("hash_files"), False)
            return real_records(root, **options)
        def receipt_only(path):
            self.assertNotIn(fixture.view, Path(path).parents)
            return real_sha256(path)
        with mock.patch.object(DEV.CACHE, "payload_records", side_effect=metadata_only), \
                mock.patch.object(DEV.CACHE, "sha256", side_effect=receipt_only), \
                mock.patch.object(DEV.CACHE, "stable_file_sha256", side_effect=AssertionError("payload rehash forbidden")):
            self.assertEqual(self.adopt(fixture)["status"], "view-reused")
        self.assertEqual(fixture.sidecar.read_bytes(), before)

    def test_v3_same_size_owner_rewrite_refuses_every_component_and_mode(self):
        for component in DEV.COMPONENTS:
            for compatibility, build in ((True, False), (False, True), (False, False)):
                with self.subTest(component=component, compatibility=compatibility, build=build):
                    fixture = self.fixture(component)
                    self.seed_stamps(fixture)
                    leaf = fixture.view / "materialization/package/data.bin"
                    before = leaf.lstat()
                    leaf.chmod(0o644)
                    leaf.write_bytes(b"tampered")
                    # Restore mtime only in V3 to isolate ctime from the other stamp fields.
                    # A non-root owner cannot restore ctime through os.utime.
                    os.utime(leaf, ns=(before.st_atime_ns, before.st_mtime_ns))
                    leaf.chmod(0o444)
                    after = leaf.lstat()
                    self.assertEqual((after.st_ino, after.st_size, after.st_mtime_ns),
                                     (before.st_ino, before.st_size, before.st_mtime_ns))
                    self.assertNotEqual(after.st_ctime_ns, before.st_ctime_ns)
                    self.assertIsNone(self.valid(fixture))
                    self.assert_refuses_without_repair(fixture, compatibility=compatibility, build=build)

    def test_v4_device_number_alone_does_not_invalidate(self):
        fixture = self.fixture()
        self.seed_stamps(fixture)
        real_lstat = Path.lstat
        def renumbered(path):
            metadata = real_lstat(path)
            if fixture.view in path.parents and stat.S_ISREG(metadata.st_mode):
                fields = {name: getattr(metadata, name) for name in dir(metadata) if name.startswith("st_")}
                fields["st_dev"] += 1
                return SimpleNamespace(**fields)
            return metadata
        with mock.patch.object(Path, "lstat", renumbered):
            self.assertIsNotNone(self.valid(fixture))
            self.assertEqual(self.adopt(fixture)["status"], "view-reused")

    def change_binding(self, fixture):
        value = json.loads(fixture.sidecar.read_bytes())
        value["view_receipt_sha256"] = "0" * 64
        fixture.sidecar.chmod(0o644)
        fixture.sidecar.write_bytes(DEV.canonical_json(value))
        fixture.sidecar.chmod(0o444)

    def test_v5_wrong_view_digest_refuses_without_sidecar_rewrite(self):
        fixture = self.fixture()
        self.seed_stamps(fixture)
        self.change_binding(fixture)
        before = fixture.sidecar.read_bytes()
        self.assertIsNone(self.valid(fixture))
        self.assertEqual(fixture.sidecar.read_bytes(), before)

    def test_v6_owner_write_group_write_and_symlink_are_invalid(self):
        for mode in (0o644, 0o664, "symlink"):
            with self.subTest(mode=mode):
                fixture = self.fixture()
                self.seed_stamps(fixture)
                if mode == "symlink":
                    target = fixture.directory / "saved-stamps.json"
                    fixture.sidecar.rename(target)
                    fixture.sidecar.symlink_to(target.name)
                else:
                    fixture.sidecar.chmod(mode)
                self.assertIsNone(self.valid(fixture))
                self.assert_refuses_without_repair(fixture)

    def test_v7_added_and_deleted_files_keep_structural_miss_behavior(self):
        for change in ("add", "delete"):
            with self.subTest(change=change):
                fixture = self.fixture()
                self.seed_stamps(fixture)
                directory = fixture.view / "materialization/package"
                directory.chmod(0o755)
                if change == "add":
                    (directory / "extra.bin").write_bytes(b"extra")
                    (directory / "extra.bin").chmod(0o444)
                else:
                    (directory / "data.bin").unlink()  # MATERIALIZATION.json remains a regular file.
                directory.chmod(0o555)
                with mock.patch.object(DEV, "view_stamp_state", create=True,
                                       side_effect=AssertionError("structure must decide first")):
                    self.assertIsNone(self.valid(fixture))
                    with self.resolver(fixture, compatibility=True) as calls:
                        with self.assertRaisesRegex(DEV.DevCacheError, "retained dependency receipt is invalid"):
                            self.resolve(fixture, build=True)
                        calls.remove.assert_not_called()
                    with self.resolver(fixture) as calls:
                        calls.remove.side_effect = DEV.DevCacheError("structural rebuild branch reached")
                        with self.assertRaisesRegex(DEV.DevCacheError, "structural rebuild branch reached"):
                            self.resolve(fixture, build=True)
                        calls.remove.assert_called_once_with(fixture.directory)

    def test_v8_bad_binding_refuses_build_enabled_resolve_before_remove(self):
        fixture = self.fixture()
        self.seed_stamps(fixture)
        self.change_binding(fixture)
        self.assert_refuses_without_repair(fixture, compatibility=False, build=True)

    def test_v9_lock_free_legacy_sleigh_requires_explicit_migration(self):
        fixture = self.fixture()
        with mock.patch.object(DEV, "retained_component_key", return_value=(fixture.key, False)), \
                mock.patch.object(DEV.CACHE, "load_entry_receipt", return_value=fixture.manifest), \
                mock.patch.object(DEV, "resolve", side_effect=AssertionError("implicit migration forbidden")):
            with self.assertRaisesRegex(DEV.DevCacheError, r"resolve\(sleigh-native-source\)"):
                DEV.reused_sleigh_materialization(fixture.root, fixture.view / "materialization",
                                                 fixture.cache, fixture.views)
        self.assertFalse(fixture.sidecar.exists())

    def test_v10_explicit_locked_migration_enables_lock_free_sleigh(self):
        fixture = self.fixture()
        self.adopt(fixture)
        before = fixture.sidecar.read_bytes()
        with mock.patch.object(DEV, "retained_component_key", return_value=(fixture.key, False)), \
                mock.patch.object(DEV.CACHE, "load_entry_receipt", return_value=fixture.manifest), \
                mock.patch.object(DEV, "resolve", side_effect=AssertionError("implicit migration forbidden")):
            result = DEV.reused_sleigh_materialization(fixture.root, fixture.view / "materialization",
                                                       fixture.cache, fixture.views)
        self.assertEqual(result["key"], fixture.key)
        self.assertEqual(result["identity"], {"fixture": True})
        self.assertIn("package/data.bin", result["files"])
        self.assertEqual(fixture.sidecar.read_bytes(), before)

    def test_invalid_unreadable_foreign_and_nonregular_sidecars_fail_closed(self):
        for condition in ("malformed", "unreadable", "foreign", "directory", "dangling"):
            with self.subTest(condition=condition):
                fixture = self.fixture()
                self.seed_stamps(fixture)
                if condition == "malformed":
                    fixture.sidecar.chmod(0o644)
                    fixture.sidecar.write_bytes(b"not JSON")
                    fixture.sidecar.chmod(0o444)
                elif condition in ("directory", "dangling"):
                    fixture.sidecar.unlink()
                    if condition == "directory":
                        fixture.sidecar.mkdir()
                    else:
                        fixture.sidecar.symlink_to("missing.json")
                real_lstat, real_read = Path.lstat, Path.read_bytes
                def metadata(path):
                    value = real_lstat(path)
                    if path == fixture.sidecar and condition == "foreign":
                        fields = {name: getattr(value, name) for name in dir(value) if name.startswith("st_")}
                        fields["st_uid"] = os.getuid() + 1
                        return SimpleNamespace(**fields)
                    return value
                def read(path):
                    if path == fixture.sidecar and condition == "unreadable":
                        raise PermissionError("synthetic unreadable sidecar")
                    return real_read(path)
                with mock.patch.object(Path, "lstat", metadata), mock.patch.object(Path, "read_bytes", read):
                    self.assertIsNone(self.valid(fixture))
                    with self.resolver(fixture) as calls:
                        with self.assertRaisesRegex(DEV.DevCacheError, "stamp.*refusing.*re-verification"):
                            self.resolve(fixture, build=True)
                        calls.remove.assert_not_called()
                        calls.materialize.assert_not_called()
                        calls.verify.assert_not_called()

    def test_new_verified_view_gets_read_only_bound_sidecar(self):
        fixture = self.fixture()
        fixture.receipt.unlink()
        with mock.patch.object(DEV, "retained_component_key", return_value=(fixture.key, False)), \
                mock.patch.object(DEV, "ensure_entry", return_value=(fixture.entry, "verified-hit")), \
                mock.patch.object(DEV.CACHE, "entry_metadata_digest", return_value="b" * 64), \
                mock.patch.object(DEV.CACHE, "materialize_command", side_effect=lambda args: self.write_payload(args.destination)), \
                mock.patch.object(DEV, "verify_view") as verify, \
                mock.patch.object(DEV, "descriptors", return_value={}):
            self.assertEqual(self.resolve(fixture, build=True)["status"], "view-verified")
        verify.assert_called_once()
        self.assertEqual(stat.S_IMODE(fixture.sidecar.lstat().st_mode), 0o444)
        self.assertIsNotNone(self.valid(fixture))


if __name__ == "__main__":
    unittest.main()
