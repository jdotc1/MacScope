#!/usr/bin/env python3
"""Synthetic coverage for explicit SLEIGH artifact adoption."""
from __future__ import annotations

import argparse
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock

from test_dev_dependency_cache import DEV

sys.path.insert(0, str(DEV.SCRIPTS / "native-decompiler-direct"))
from sleigh_package import FIRST_PARTY_MULTISTAGE_PATCH  # noqa: E402


class RetainedSleighAdoptionTests(unittest.TestCase):
    def setUp(self):
        self.scratch = tempfile.TemporaryDirectory()
        self.root = Path(self.scratch.name).resolve()
        self.cache = self.root / "cache"
        self.views = self.root / "views"
        self.repository = self.root / "repository"
        self.retained = self.root / "retained"
        for path in (self.cache, self.views, self.repository, self.retained):
            path.mkdir()
        self.old_key, self.new_key = "a" * 64, "b" * 64
        self.first_party_patch = {"path": FIRST_PARTY_MULTISTAGE_PATCH[0],
                                  "sha256": FIRST_PARTY_MULTISTAGE_PATCH[1]}
        self.source = {"componentId": "source-component", "patches": [],
                       "sleigh": {"revision": "s", "gitTree": "st", "treeSha256": "sd"},
                       "ghidra": {"revision": "g", "gitTree": "gt", "treeSha256": "gd"}}
        source_path = self.repository / "ThirdParty/SleighNative/Source/MATERIALIZATION.json"
        source_path.parent.mkdir(parents=True)
        source_path.write_text(json.dumps(self.source))
        self.package_receipt = {"sourceComponentId": "source-component", "package": {"treeSha256": "p"}}
        (self.retained / "SOURCE_BUILD_MATERIALIZATION.json").write_text(json.dumps(self.package_receipt))
        self.verification_root = self.cache / "verification.noindex"
        self.verification_root.mkdir()
        self.publish_accepted(self.old_key, [self.first_party_patch])

    def publish_accepted(self, key, accepted_patches):
        self.entry = self.cache / "artifacts/v1/sleigh-native-source" / key
        payload = self.root / ("payload-" + key[:8])
        (payload / "materialization/package").mkdir(parents=True)
        (payload / "materialization/package/lib.a").write_bytes(b"accepted synthetic archive")
        (payload / "SOURCE_BUILD_MATERIALIZATION.json").write_text(json.dumps(self.package_receipt))
        self.materialization = {
            "componentId": "source-component", "sleighGitRevision": "s", "ghidraGitRevision": "g",
            "sourceBuild": {"patches": accepted_patches, "sleighGitTree": "st", "sleighTreeSha256": "sd",
                            "ghidraGitTree": "gt", "ghidraTreeSha256": "gd",
                            "toolchain": {"compiler": {"path": "historical-compiler"}}},
        }
        (payload / "materialization/MATERIALIZATION.json").write_text(json.dumps(self.materialization))
        with contextlib.redirect_stdout(io.StringIO()):
            DEV.CACHE.publish_command(argparse.Namespace(entry=self.entry, component="sleigh-native-source",
                                                        key=key, payload=payload))
        args = argparse.Namespace(entry=self.entry, component="sleigh-native-source", key=key,
                                  verification_root=self.verification_root,
                                  binding=["domain-verifier=verify_sleigh_view", "native-tools=historical"])
        vk, self.receipt, identity = DEV.CACHE.verification_identity(args)
        self.authority = dict(identity, entry=str(self.entry),
                              entry_metadata_sha256=DEV.CACHE.entry_metadata_digest(self.entry),
                              verification="synthetic domain acceptance", verification_key=vk,
                              verified_at="2026-01-01T00:00:00Z", verified_run_view=str(payload))
        self.receipt.parent.mkdir(parents=True, exist_ok=True)
        self.receipt.write_bytes(DEV.CACHE.canonical_json(self.authority))
        self.receipt.chmod(0o444)

    def tearDown(self):
        DEV.remove_tree(self.root)
        self.scratch.cleanup()

    def adopt(self, corrupt=False):
        original_records = DEV.CACHE.payload_records
        original_sha256 = DEV.CACHE.sha256
        def receipt_hash(path):
            self.assertNotIn("payload", Path(path).parts, "adoption must not hash payload bytes")
            self.assertNotIn(DEV.COMPONENTS["sleigh-native-source"]["view_name"], Path(path).parts,
                             "adoption must not hash view payload bytes")
            return original_sha256(path)
        def records(root, **kwargs):
            self.assertIs(kwargs.get("hash_files"), False, "adoption must not hash payloads")
            return original_records(root, **kwargs)
        def clone(source, destination):
            shutil.copytree(source, destination, symlinks=True)
            if corrupt:
                target = destination / "materialization/package/lib.a"
                target.chmod(0o600)
                target.write_bytes(b"different size")
        with mock.patch.object(DEV, "component_key", return_value=self.new_key), \
             mock.patch.object(DEV, "admit_retained_build_sources", return_value="c" * 40), \
             mock.patch.object(DEV.CACHE, "clonefile_tree", side_effect=clone), \
             mock.patch.object(DEV.CACHE, "payload_records", side_effect=records), \
             mock.patch.object(DEV.CACHE, "sha256", side_effect=receipt_hash), \
             mock.patch.object(DEV.CACHE, "stable_file_sha256", side_effect=AssertionError("no payload rehash")), \
             mock.patch.object(DEV, "build_payload", side_effect=AssertionError("no build")), \
             mock.patch.object(DEV, "verify_view", side_effect=AssertionError("no domain rerun")), \
             mock.patch.object(DEV.CACHE, "publish_command", side_effect=AssertionError("no rehash publish")), \
             mock.patch.object(DEV.CACHE, "materialize_command", side_effect=AssertionError("no rehash clone")), \
             mock.patch.object(DEV.CACHE, "record_verification_command", side_effect=AssertionError("no new authority")):
            return DEV.adopt_retained_sleigh(self.repository, self.cache, self.views,
                                            self.entry, self.receipt, self.retained, "c" * 40)

    def test_build_resource_changes_refuse_adoption(self):
        for changed in (b"ThirdParty/SleighNative/AARCH64/profile.sla\0",
                        b"Scripts/dependencies/build_vendored_sleigh_native_source.sh\0"):
            with mock.patch.object(DEV, "git", side_effect=[b"c" * 40 + b"\n", changed]):
                with self.assertRaisesRegex(DEV.DevCacheError, "build recipe changed"):
                    DEV.admit_retained_build_sources(self.repository, "c" * 40)

    def test_verifier_only_change_keeps_compiled_inputs_eligible(self):
        with mock.patch.object(DEV, "git", side_effect=[b"c" * 40 + b"\n",
                b"Scripts/native-decompiler-direct/verify_sleigh_package.py\0"]):
            self.assertEqual(DEV.admit_retained_build_sources(self.repository, "c" * 40), "c" * 40)

    def test_adoption_preserves_historical_authority_and_payload(self):
        result = self.adopt()
        self.assertEqual(result["status"], "receipt-adopted")
        value = result["receipt"]
        self.assertEqual(value["verified_at"], self.authority["verified_at"])
        self.assertEqual(value["adoption"]["bindings"], self.authority["bindings"])
        self.assertEqual(json.loads((result["view"] / "materialization/MATERIALIZATION.json").read_text()),
                         self.materialization)
        new_entry = self.entry.parent / self.new_key
        self.assertIsNotNone(DEV.view_receipt_valid(result["view"].parent / "VIEW.json", new_entry,
                                                  result["view"], "sleigh-native-source", self.new_key))
        self.assertEqual(json.loads(self.receipt.read_text()), self.authority)

    def test_busy_key_guard_refuses_adoption_without_publication(self):
        guard = self.cache / 'lock-guards/v1/sleigh-native-source' / (self.new_key + '.guard')
        with DEV.entry_lock_guard(guard) as acquired:
            self.assertTrue(acquired)
            with self.assertRaisesRegex(DEV.DevCacheError, 'cache key is busy'):
                self.adopt()
        self.assertFalse((self.entry.parent / self.new_key).exists())

    def test_adoption_holds_key_guard_during_clones_and_releases_after_cleanup(self):
        guard = self.cache / 'lock-guards/v1/sleigh-native-source' / (self.new_key + '.guard')
        lock = self.cache / 'locks/v1/sleigh-native-source' / (self.new_key + '.lock')
        original_records = DEV.CACHE.payload_records
        observed = []
        def records(root, **kwargs):
            if '.adopt-' in str(root):
                with DEV.entry_lock_guard(guard) as acquired:
                    self.assertFalse(acquired)
                self.assertTrue(lock.is_dir())
                observed.append(root)
            return original_records(root, **kwargs)
        with mock.patch.object(DEV.CACHE, 'payload_records', side_effect=records):
            self.adopt()
        self.assertGreaterEqual(len(observed), 2)
        self.assertFalse(lock.exists())
        with DEV.entry_lock_guard(guard) as acquired:
            self.assertTrue(acquired)

    def test_mismatched_retained_receipt_fails_without_publishing(self):
        (self.retained / "SOURCE_BUILD_MATERIALIZATION.json").write_text("{}")
        with self.assertRaisesRegex(DEV.DevCacheError, "differs from accepted"):
            self.adopt()
        self.assertFalse((self.entry.parent / self.new_key).exists())

    def test_writable_domain_receipt_is_rejected(self):
        self.receipt.chmod(0o644)
        with self.assertRaises(DEV.CACHE.CacheError):
            self.adopt()
        self.assertFalse((self.entry.parent / self.new_key).exists())

    def test_source_change_is_rejected(self):
        source_path = self.repository / "ThirdParty/SleighNative/Source/MATERIALIZATION.json"
        self.source["sleigh"]["gitTree"] = "changed"
        source_path.write_text(json.dumps(self.source))
        with self.assertRaisesRegex(DEV.DevCacheError, "source manifest differs"):
            self.adopt()

    def test_accepted_provenance_without_first_party_patch_is_refused(self):
        self.publish_accepted("c" * 64, [])
        with self.assertRaisesRegex(DEV.DevCacheError, "source manifest differs"):
            self.adopt()
        self.assertFalse((self.entry.parent / self.new_key).exists())

    def test_manifest_patch_list_is_appended_with_first_party_record(self):
        extra = {"path": "extra.patch", "sha256": "e" * 64}
        self.source["patches"] = [extra]
        source_path = self.repository / "ThirdParty/SleighNative/Source/MATERIALIZATION.json"
        source_path.write_text(json.dumps(self.source))
        self.publish_accepted("d" * 64, [extra, self.first_party_patch])
        result = self.adopt()
        self.assertEqual(result["status"], "receipt-adopted")

    def test_structurally_changed_clone_is_never_published(self):
        with self.assertRaisesRegex(DEV.DevCacheError, "differs structurally"):
            self.adopt(corrupt=True)
        self.assertFalse((self.entry.parent / self.new_key).exists())
        self.assertFalse((self.views / "sleigh-native-source" / self.new_key).exists())


    def test_view_stamps_fresh_adoption_binds_final_receipt_and_rename_tuples(self):
        """C1/C2/C4/C12: final bytes and renamed descendants, not a staged digest."""
        captured = {}
        original_writer = DEV.write_view_stamps
        authority_before = self.receipt.read_bytes()
        entry_before = (self.entry / "ENTRY.json").read_bytes()
        def writer(receipt, view):
            captured["receipt"] = receipt.read_bytes()
            captured["files"] = DEV.view_file_stamps(view)
            original_writer(receipt, view)
        with mock.patch.object(DEV, "write_view_stamps", side_effect=writer) as stamps:
            result = self.adopt()
        stamps.assert_called_once()
        view = result["view"]
        entry = self.entry.parent / self.new_key
        receipt = view.parent / "VIEW.json"
        sidecar = receipt.with_name("VIEW-STAMPS.json")
        value = json.loads(receipt.read_bytes())
        saved = json.loads(sidecar.read_bytes())
        self.assertEqual(result["status"], "receipt-adopted")
        self.assertTrue(entry.is_dir())
        self.assertTrue(view.is_dir())
        self.assertEqual((value["entry"], value["view"]), (str(entry), str(view)))
        self.assertEqual(captured["receipt"], receipt.read_bytes())
        self.assertEqual(saved["view_receipt_sha256"], DEV.sha256_bytes(receipt.read_bytes()))
        self.assertEqual(saved["files"], captured["files"])
        self.assertEqual(saved["files"], DEV.view_file_stamps(view))
        self.assertTrue(saved["files"])
        for record in saved["files"]:
            self.assertEqual(set(record), {"path", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"})
            metadata = (view / record["path"]).lstat()
            self.assertTrue(stat.S_ISREG(metadata.st_mode))
            for field in set(record) - {"path"}:
                self.assertEqual(record[field], getattr(metadata, field))
        metadata = sidecar.lstat()
        self.assertTrue(stat.S_ISREG(metadata.st_mode))
        self.assertEqual(metadata.st_uid, os.getuid())
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o444)
        self.assertIsNotNone(DEV.view_receipt_valid(receipt, entry, view, "sleigh-native-source", self.new_key))
        self.assertEqual(value["verified_at"], self.authority["verified_at"])
        self.assertEqual(value["adoption"]["bindings"], self.authority["bindings"])
        self.assertEqual(value["adoption"]["accepted_entry"], str(self.entry))
        self.assertEqual(value["adoption"]["verification_receipt"], str(self.receipt))
        self.assertEqual(value["adoption"]["retained_package_receipt"], self.package_receipt)
        self.assertEqual(json.loads((view / "materialization/MATERIALIZATION.json").read_bytes()),
                         self.materialization)
        self.assertEqual((self.receipt.read_bytes(), (self.entry / "ENTRY.json").read_bytes()),
                         (authority_before, entry_before))
        self.assertFalse((entry / "ENTRY-STAMPS.json").exists())

    def test_view_stamps_structure_final_write_stamp_publication_order(self):
        """C3: no transient staged-bound sidecar is created or repaired."""
        events = []
        real_structure = DEV.view_receipt_structure_valid
        real_write = DEV.CACHE.write_new_canonical
        real_stamps = DEV.write_view_stamps
        real_rename = Path.rename
        final_entry = self.entry.parent / self.new_key
        final_directory = self.views / "sleigh-native-source" / self.new_key
        def structure(receipt, entry, view, component, key):
            self.assertFalse(receipt.with_name("VIEW-STAMPS.json").exists())
            admitted = real_structure(receipt, entry, view, component, key)
            self.assertIsNotNone(admitted)
            self.assertEqual((admitted["entry"], admitted["view"]), (str(entry), str(view)))
            events.append("structure")
            return admitted
        def write(path, value):
            if path.name == "VIEW.json":
                events.append("final-write" if value["entry"] == str(final_entry) else "staged-write")
            return real_write(path, value)
        def stamps(receipt, view):
            self.assertEqual(events, ["staged-write", "structure", "final-write"])
            self.assertFalse(final_entry.exists())
            self.assertFalse(final_directory.exists())
            value = json.loads(receipt.read_bytes())
            self.assertEqual(value["entry"], str(final_entry))
            self.assertEqual(value["view"], str(final_directory / DEV.COMPONENTS["sleigh-native-source"]["view_name"]))
            real_stamps(receipt, view)
            self.assertEqual(DEV.view_stamp_state(receipt, view), "valid")
            events.append("stamp")
        def rename(path, destination):
            if destination in (final_entry, final_directory):
                self.assertIn("stamp", events)
                events.append("entry-publish" if destination == final_entry else "view-publish")
            return real_rename(path, destination)
        with mock.patch.object(DEV, "view_receipt_structure_valid", side_effect=structure), \
             mock.patch.object(DEV.CACHE, "write_new_canonical", side_effect=write), \
             mock.patch.object(DEV, "write_view_stamps", side_effect=stamps) as writer, \
             mock.patch.object(Path, "rename", rename):
            self.adopt()
        writer.assert_called_once()
        self.assertEqual(events, ["staged-write", "structure", "final-write", "stamp",
                                  "entry-publish", "view-publish"])

    def test_view_stamps_same_size_and_metadata_mutations_refuse_without_repair(self):
        """C5: strict existing validator rejects a changed frozen view."""
        for index, mutation in enumerate(("same-size", "metadata"), start=1):
            with self.subTest(mutation=mutation):
                self.new_key = f"{index:064x}"
                result = self.adopt()
                view = result["view"]
                receipt = view.parent / "VIEW.json"
                sidecar = receipt.with_name("VIEW-STAMPS.json")
                before = (receipt.read_bytes(), sidecar.read_bytes())
                leaf = view / "materialization/package/lib.a"
                metadata = leaf.lstat()
                if mutation == "same-size":
                    leaf.chmod(0o644)
                    leaf.write_bytes(b"X" * metadata.st_size)
                    leaf.chmod(0o444)
                    # Keep size/mtime unchanged; ctime records the owner write.
                    os.utime(leaf, ns=(metadata.st_atime_ns, metadata.st_mtime_ns))
                    self.assertEqual(leaf.stat().st_size, metadata.st_size)
                    self.assertNotEqual(leaf.stat().st_ctime_ns, metadata.st_ctime_ns)
                else:
                    os.utime(leaf, ns=(metadata.st_atime_ns, metadata.st_mtime_ns + 1_000_000_000))
                with mock.patch.object(DEV, "write_view_stamps", side_effect=AssertionError("no repair")), \
                     mock.patch.object(DEV, "verify_view", side_effect=AssertionError("no verifier")), \
                     mock.patch.object(DEV, "build_payload", side_effect=AssertionError("no build")), \
                     mock.patch.object(DEV.CACHE, "stable_file_sha256", side_effect=AssertionError("no payload hash")):
                    self.assertEqual(DEV.view_stamp_state(receipt, view), "invalid")
                    self.assertIsNone(DEV.view_receipt_valid(receipt, self.entry.parent / self.new_key,
                                                            view, "sleigh-native-source", self.new_key))
                self.assertEqual((receipt.read_bytes(), sidecar.read_bytes()), before)

    def test_view_stamps_preexisting_sidecar_preserved_at_writer_refusal_boundary(self):
        """C6: cleanup owns staging, never an external symlink target."""
        real_writer = DEV.write_view_stamps
        external = self.root / "external-stamps-evidence"
        external.write_bytes(b"external evidence must survive")
        for index, condition in enumerate(("malformed", "read-write", "symlink"), start=3):
            with self.subTest(condition=condition):
                self.new_key = f"{index:064x}"
                seen = []
                def writer(receipt, view):
                    sidecar = receipt.with_name("VIEW-STAMPS.json")
                    if condition == "symlink":
                        sidecar.symlink_to(external)
                    else:
                        sidecar.write_bytes(b"not JSON" if condition == "malformed" else b"{}\n")
                        sidecar.chmod(0o444 if condition == "malformed" else 0o644)
                    metadata = sidecar.lstat()
                    evidence = (sidecar.read_bytes(), metadata.st_ino, metadata.st_mode,
                                metadata.st_mtime_ns, metadata.st_ctime_ns,
                                os.readlink(sidecar) if sidecar.is_symlink() else None)
                    receipt_bytes = receipt.read_bytes()
                    try:
                        real_writer(receipt, view)
                    except DEV.DevCacheError:
                        after = sidecar.lstat()
                        self.assertEqual(evidence, (sidecar.read_bytes(), after.st_ino, after.st_mode,
                                                    after.st_mtime_ns, after.st_ctime_ns,
                                                    os.readlink(sidecar) if sidecar.is_symlink() else None))
                        self.assertEqual(receipt.read_bytes(), receipt_bytes)
                        self.assertEqual(external.read_bytes(), b"external evidence must survive")
                        seen.append(receipt.parent)
                        raise
                    self.fail("preexisting sidecar was overwritten")
                with mock.patch.object(DEV, "write_view_stamps", side_effect=writer) as stamps:
                    with self.assertRaisesRegex(DEV.DevCacheError, "already exist.*refusing repair"):
                        self.adopt()
                stamps.assert_called_once()
                self.assertEqual(len(seen), 1)
                self.assertFalse(seen[0].exists())  # Owned unpublished staging cleanup is allowed.
                self.assertFalse((self.entry.parent / self.new_key).exists())
                self.assertFalse((self.views / "sleigh-native-source" / self.new_key).exists())
                self.assertEqual(external.read_bytes(), b"external evidence must survive")

    def test_view_stamps_existing_entry_view_and_symlink_destinations_refuse(self):
        """C7: existing destinations and their original evidence are not replaced."""
        original = (self.receipt.read_bytes(), (self.entry / "ENTRY.json").read_bytes())
        external = self.root / "external-destination"
        external.mkdir()
        (external / "evidence").write_bytes(b"keep external")
        for index, (which, indirect) in enumerate((("entry", False), ("view", False),
                                                   ("entry", True), ("view", True),
                                                   ("entry", "dangling"), ("view", "dangling")), start=6):
            with self.subTest(which=which, indirect=indirect):
                self.new_key = f"{index:064x}"
                entry = self.entry.parent / self.new_key
                directory = self.views / "sleigh-native-source" / self.new_key
                target = entry if which == "entry" else directory
                target.parent.mkdir(parents=True, exist_ok=True)
                if indirect:
                    link_target = external if indirect is True else self.root / "missing-destination"
                    target.symlink_to(link_target, target_is_directory=True)
                else:
                    target.mkdir()
                    (target / "evidence").write_bytes(b"keep destination")
                inode = target.lstat().st_ino
                with mock.patch.object(DEV, "write_view_stamps") as stamps:
                    with self.assertRaisesRegex(DEV.DevCacheError, "destination already exists"):
                        self.adopt()
                stamps.assert_not_called()
                self.assertEqual(target.lstat().st_ino, inode)
                self.assertEqual((external / "evidence").read_bytes(), b"keep external")
                if indirect:
                    self.assertEqual(os.readlink(target), str(link_target))
                    if indirect == "dangling":
                        self.assertFalse(target.exists())
                        self.assertTrue(target.is_symlink())
                else:
                    self.assertEqual((target / "evidence").read_bytes(), b"keep destination")
                other = directory if which == "entry" else entry
                self.assertFalse(other.exists())
                self.assertEqual((self.receipt.read_bytes(), (self.entry / "ENTRY.json").read_bytes()), original)

    def test_view_stamps_corrupt_clone_refuses_before_stamp_or_publication(self):
        """C8: retain real clone structural mismatch, not a missing-stamp failure."""
        with mock.patch.object(DEV, "write_view_stamps") as stamps:
            with self.assertRaisesRegex(DEV.DevCacheError, "differs structurally"):
                self.adopt(corrupt=True)
        stamps.assert_not_called()
        self.assertFalse((self.entry.parent / self.new_key).exists())
        self.assertFalse((self.views / "sleigh-native-source" / self.new_key).exists())

    def test_view_stamps_staged_receipt_structure_refusal_precedes_writer(self):
        """C8: a real staging-path receipt mismatch is rejected before seeding."""
        real_write = DEV.CACHE.write_new_canonical
        def write(path, value):
            if path.name == "VIEW.json":
                value = dict(value, entry=str(self.root / "unbound-entry"))
            return real_write(path, value)
        with mock.patch.object(DEV.CACHE, "write_new_canonical", side_effect=write), \
             mock.patch.object(DEV, "write_view_stamps") as stamps:
            with self.assertRaisesRegex(DEV.DevCacheError, "failed structural admission"):
                self.adopt()
        stamps.assert_not_called()
        self.assertFalse((self.entry.parent / self.new_key).exists())
        self.assertFalse((self.views / "sleigh-native-source" / self.new_key).exists())

    def test_view_stamps_authority_provenance_and_package_guards_remain(self):
        """C9: reach actual authority/source/package rejection branches."""
        source_path = self.repository / "ThirdParty/SleighNative/Source/MATERIALIZATION.json"
        retained_path = self.retained / "SOURCE_BUILD_MATERIALIZATION.json"
        source_bytes, retained_bytes = source_path.read_bytes(), retained_path.read_bytes()
        original_entry, original_receipt = self.entry, self.receipt
        original_authority = self.receipt.read_bytes()
        original_entry_receipt = (self.entry / "ENTRY.json").read_bytes()
        expected_errors = {
            "outside-entry": "outside the selected cache layout",
            "unbound-receipt": "not its canonical bound location",
            "writable-authority": "stored verification receipt is writable",
            "wrong-domain": "lacks SLEIGH domain authority",
            "source": "current SLEIGH source manifest differs from accepted provenance",
            "retained": "retained SLEIGH package differs from accepted content",
        }
        for condition in expected_errors:
            with self.subTest(condition=condition):
                try:
                    if condition == "outside-entry":
                        self.entry = self.root / self.old_key
                    elif condition == "unbound-receipt":
                        self.receipt = self.root / "unbound-authority.json"
                        self.receipt.write_bytes(original_authority)
                        self.receipt.chmod(0o444)
                    elif condition == "writable-authority":
                        self.receipt.chmod(0o644)
                    elif condition == "wrong-domain":
                        value = dict(self.authority, bindings={"domain-verifier": "other"})
                        self.receipt.chmod(0o644)
                        self.receipt.write_bytes(DEV.CACHE.canonical_json(value))
                        self.receipt.chmod(0o444)
                    elif condition == "source":
                        value = json.loads(source_bytes)
                        value["sleigh"]["gitTree"] = "changed"
                        source_path.write_text(json.dumps(value))
                    else:
                        retained_path.write_text("{}")
                    with mock.patch.object(DEV, "write_view_stamps") as stamps:
                        with self.assertRaisesRegex((DEV.DevCacheError, DEV.CACHE.CacheError),
                                                    expected_errors[condition]):
                            self.adopt()
                    stamps.assert_not_called()
                    self.assertFalse((original_entry.parent / self.new_key).exists())
                    self.assertFalse((self.views / "sleigh-native-source" / self.new_key).exists())
                    self.assertEqual((original_entry / "ENTRY.json").read_bytes(), original_entry_receipt)
                finally:
                    self.entry, self.receipt = original_entry, original_receipt
                    self.receipt.chmod(0o644)
                    self.receipt.write_bytes(original_authority)
                    self.receipt.chmod(0o444)
                    source_path.write_bytes(source_bytes)
                    retained_path.write_bytes(retained_bytes)

    def test_view_stamps_busy_stable_guard_and_ownerless_lock_refuse(self):
        """C10: no reclaim, wait, producer, or cleanup of another lock owner."""
        guard = self.cache / "lock-guards/v1/sleigh-native-source" / f"{self.new_key}.guard"
        lock = self.cache / "locks/v1/sleigh-native-source" / f"{self.new_key}.lock"
        with DEV.entry_lock_guard(guard) as acquired:
            self.assertTrue(acquired)
            with mock.patch.object(DEV, "write_view_stamps") as stamps:
                with self.assertRaisesRegex(DEV.DevCacheError, "cache key is busy"):
                    self.adopt()
            stamps.assert_not_called()
            self.assertFalse(lock.exists())
        lock.parent.mkdir(parents=True, exist_ok=True)
        lock.mkdir()
        os.utime(lock, (1, 1))  # Old age does not authorize adoption to reclaim it.
        inode = lock.lstat().st_ino
        with mock.patch.object(DEV, "write_view_stamps") as stamps:
            with self.assertRaises(FileExistsError):
                self.adopt()
        stamps.assert_not_called()
        self.assertEqual(lock.lstat().st_ino, inode)
        self.assertEqual(list(lock.iterdir()), [])
        self.assertFalse((self.entry.parent / self.new_key).exists())
        self.assertFalse((self.views / "sleigh-native-source" / self.new_key).exists())

    def test_adoption_occupied_lock_owner_summaries_preserve_exception_and_contents(self):
        lock = self.cache / "locks/v1/sleigh-native-source" / f"{self.new_key}.lock"
        lock.mkdir(parents=True)
        cases = [(None, "owner-less"),
                 ({"pid": str(os.getpid()), "hostname": DEV.socket.gethostname(),
                   "start": "fixture-start"}, "live pid"),
                 ({"pid": "123", "hostname": DEV.socket.gethostname() + ".foreign", "start": "former"}, "foreign host")]
        for owner, expected in cases:
            with self.subTest(expected=expected):
                if owner is not None:
                    (lock / "owner").write_text("".join(f"{k}={v}\n" for k, v in owner.items()))
                before = (lock.lstat().st_ino, {p.name: p.read_bytes() for p in lock.iterdir()})
                with mock.patch.object(DEV, "process_start_identity", return_value="fixture-start"), \
                        self.assertRaises(FileExistsError) as raised:
                    self.adopt()
                self.assertIn(expected, str(raised.exception))
                self.assertIn("nothing was removed", str(raised.exception))
                self.assertEqual(raised.exception.filename, str(lock))
                self.assertIsInstance(raised.exception.__cause__, FileExistsError)
                self.assertEqual(raised.exception.errno, raised.exception.__cause__.errno)
                self.assertEqual(before, (lock.lstat().st_ino, {p.name: p.read_bytes() for p in lock.iterdir()}))

    def test_view_stamps_whole_transaction_guard_includes_publish_and_release(self):
        """C10/C11: F3 guard stays held through both renames and lock removal."""
        active = []
        observed = []
        real_guard, real_stamps = DEV.entry_lock_guard, DEV.write_view_stamps
        real_rename, real_rmdir = Path.rename, Path.rmdir
        lock = self.cache / "locks/v1/sleigh-native-source" / f"{self.new_key}.lock"
        @contextlib.contextmanager
        def guard(path, **options):
            self.assertFalse(options.get("blocking", False))
            with real_guard(path, **options) as acquired:
                self.assertTrue(acquired)
                active.append(path)
                try:
                    yield acquired
                finally:
                    self.assertFalse(lock.exists())
                    active.pop()
        def stamps(receipt, view):
            self.assertEqual(len(active), 1)
            observed.append("stamp")
            return real_stamps(receipt, view)
        def rename(path, destination):
            self.assertEqual(len(active), 1)
            observed.append("rename")
            return real_rename(path, destination)
        def rmdir(path):
            if path == lock:
                self.assertEqual(len(active), 1)
                observed.append("release")
            return real_rmdir(path)
        with mock.patch.object(DEV, "entry_lock_guard", side_effect=guard), \
             mock.patch.object(DEV, "write_view_stamps", side_effect=stamps), \
             mock.patch.object(Path, "rename", rename), mock.patch.object(Path, "rmdir", rmdir):
            self.adopt()
        self.assertEqual(observed, ["stamp", "rename", "rename", "release"])
        self.assertEqual(active, [])

    def test_view_stamps_stamp_failure_cleans_only_owned_unpublished_staging(self):
        """C11: preserve original authority and hold guard throughout failure cleanup."""
        real_guard, real_remove = DEV.entry_lock_guard, DEV.remove_tree
        active, removed = [], []
        original = (self.receipt.read_bytes(), (self.entry / "ENTRY.json").read_bytes())
        external = self.root / "external-failure-evidence"
        external.write_bytes(b"keep")
        lock = self.cache / "locks/v1/sleigh-native-source" / f"{self.new_key}.lock"
        @contextlib.contextmanager
        def guard(path, **options):
            with real_guard(path, **options) as acquired:
                active.append(path)
                try:
                    yield acquired
                finally:
                    self.assertFalse(lock.exists())
                    active.pop()
        def remove(path):
            self.assertEqual(len(active), 1)
            self.assertTrue(path.name.startswith(f".{self.new_key}.adopt-"))
            self.assertIn(path.parent, (self.entry.parent, self.views / "sleigh-native-source"))
            removed.append(path)
            return real_remove(path)
        def fail(receipt, view):
            self.assertEqual(len(active), 1)
            receipt.with_name(".VIEW-STAMPS.partial").write_bytes(b"interrupted")
            raise OSError("synthetic stamp failure")
        with mock.patch.object(DEV, "entry_lock_guard", side_effect=guard), \
             mock.patch.object(DEV, "remove_tree", side_effect=remove), \
             mock.patch.object(DEV, "write_view_stamps", side_effect=fail):
            with self.assertRaisesRegex(OSError, "synthetic stamp failure"):
                self.adopt()
        self.assertEqual(len(removed), 2)
        self.assertTrue(all(not path.exists() for path in removed))
        self.assertFalse((self.entry.parent / self.new_key).exists())
        self.assertFalse((self.views / "sleigh-native-source" / self.new_key).exists())
        self.assertEqual((self.receipt.read_bytes(), (self.entry / "ENTRY.json").read_bytes()), original)
        self.assertEqual(external.read_bytes(), b"keep")
        self.assertEqual(active, [])

    def test_view_stamps_publication_failures_preserve_two_rename_boundary(self):
        """C11: second-rename failure may leave entry published; never remove it."""
        original = (self.receipt.read_bytes(), (self.entry / "ENTRY.json").read_bytes())
        real_rename, real_remove = Path.rename, DEV.remove_tree
        for index, failed_target in enumerate(("entry", "view"), start=10):
            with self.subTest(failed_target=failed_target):
                self.new_key = f"{index:064x}"
                entry = self.entry.parent / self.new_key
                directory = self.views / "sleigh-native-source" / self.new_key
                removed = []
                def rename(path, destination):
                    if destination == (entry if failed_target == "entry" else directory):
                        raise OSError("synthetic publication failure")
                    return real_rename(path, destination)
                def remove(path):
                    self.assertNotIn(path, (entry, directory, self.entry, self.receipt.parent))
                    removed.append(path)
                    return real_remove(path)
                with mock.patch.object(Path, "rename", rename), \
                     mock.patch.object(DEV, "remove_tree", side_effect=remove):
                    with self.assertRaisesRegex(OSError, "synthetic publication failure"):
                        self.adopt()
                self.assertEqual(entry.exists(), failed_target == "view")
                self.assertFalse(directory.exists())
                self.assertEqual(len(removed), 2 if failed_target == "entry" else 1)
                self.assertTrue(all(not path.exists() for path in removed))
                self.assertFalse((self.cache / "locks/v1/sleigh-native-source" / f"{self.new_key}.lock").exists())
                self.assertEqual((self.receipt.read_bytes(), (self.entry / "ENTRY.json").read_bytes()), original)


if __name__ == "__main__":
    unittest.main()
