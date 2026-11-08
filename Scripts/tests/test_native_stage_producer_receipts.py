"""Synthetic producer-receipt definitions. Source-only delivery: ALL UNRUN.

No tools, subprocesses, native archives, network, cache, or complete checkout are
needed. The fixture's .a files are literal synthetic bytes, not native products.
"""
from __future__ import annotations

from collections import Counter
from contextlib import ExitStack, contextmanager
import importlib.util
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tempfile
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from Scripts.tests.test_sleigh_native_package import SleighPackageFixture, canonical_manifest


def load(name, filename):
    specification = importlib.util.spec_from_file_location(
        name, ROOT / "Scripts/native-decompiler-xpc" / filename
    )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class ProducerReceiptTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.source = self.root / "source"
        package = self.source / "package"
        package.mkdir(parents=True)
        SleighPackageFixture(package).create()
        self.identity = canonical_manifest(package)
        (self.source / "MATERIALIZATION.json").write_text(
            json.dumps(self.identity, sort_keys=True, separators=(",", ":")) + "\n"
        )
        self.file_count = self.identity["package"]["fileCount"] + 1
        self.receipts = self.root / "receipts"
        self.receipts.mkdir(mode=0o700)
        self.prior = self.root / "prior"
        self.prior.mkdir(mode=0o700)
        self.destination = self.root / "destination"
        self.inputs = self.root / "inputs.xcfilelist"
        self.outputs = self.root / "outputs.xcfilelist"
        self.target = self.root / "target"
        self.target.mkdir()
        self.metadata = self.root / "metadata"
        self.metadata.mkdir()
        self.resources = PurePosixPath("Service.xpc/Contents/Resources")
        self.s = load("producer_receipt_stager", "stage_verified_package.py")
        self.x = load("producer_receipt_xcode", "stage_xcode_resources.py")
        self.x._STAGER = self.s
        environment = mock.patch.dict(os.environ, {
            "MACSCOPE_NATIVE_VERIFICATION_RECEIPT_MODE": "producer",
            "MACSCOPE_NATIVE_SOURCE_IDENTITY_RECEIPT_ROOT": str(self.receipts),
            "MACSCOPE_NATIVE_PRIOR_RECEIPT_ROOT": "",
        })
        environment.start()
        self.addCleanup(environment.stop)

    def receipt(self, path=None, root=None):
        return self.s._staged_receipt_path(path or self.source, str(root) if root else None)

    def open_source(self, capture=False):
        anchor = self.s._open_verified_materialization(
            self.source, "synthetic source", capture_source_receipt=capture
        )
        try:
            return anchor[4], tuple(anchor[3])
        finally:
            os.close(anchor[1])

    def direct(self, capture=False):
        return self.s.stage_verified_package(
            self.source, self.destination, self.inputs, self.outputs,
            capture_source_receipt=capture,
        )

    def xcode(self, capture=False):
        return self.x.stage_xcode_resources(
            self.source, self.target, self.resources, self.metadata,
            capture_source_receipt=capture,
        )

    def xpaths(self):
        return (self.target / self.resources / self.x.DESTINATION_NAME,
                self.metadata / self.x.INPUT_LIST_NAME,
                self.metadata / self.x.OUTPUT_LIST_NAME,
                self.metadata / self.x.STAMP_NAME)

    def stable_state(self, roots):
        paths = set(roots)
        for root in roots:
            if root.is_dir():
                paths.update(root.rglob("*"))
        return {str(path): (self.s._stable_tree_fields(path.lstat()),
                           path.read_bytes() if path.is_file() and not path.is_symlink() else None)
                for path in paths}

    @contextmanager
    def observe(self, *, no_work=False, no_copy=False):
        counts = Counter()
        snapshot = self.s._closed_tree_snapshot
        verify = self.s._checked_verify
        copy = self.s._copy_file
        publisher = self.s._stage_verified_package_anchored

        def observed_snapshot(descriptor, **keywords):
            hashes = (keywords.get("prior_snapshot") is None
                      and keywords.get("digest_evidence") is None
                      and keywords.get("hash_files", True))
            if hashes:
                if no_work:
                    self.fail("payload-hashing snapshot branch invoked")
                fields = os.fstat(descriptor)
                source_fields = self.source.stat()
                where = "source" if (fields.st_dev, fields.st_ino) == (
                    source_fields.st_dev, source_fields.st_ino) else "destination"
                counts[where + "_hash_traversals"] += 1
                result = snapshot(descriptor, **keywords)
                counts[where + "_file_hashes"] += sum(record[1] == "file" for record in result)
                return result
            counts["metadata_traversals"] += 1
            return snapshot(descriptor, **keywords)

        def observed_verify(path, *args, **kwargs):
            if no_work:
                self.fail("strict package verifier invoked")
            counts["source_verify" if path == self.source else "destination_verify"] += 1
            return verify(path, *args, **kwargs)

        def observed_copy(*args, **kwargs):
            if no_copy:
                self.fail("payload copy invoked")
            counts["file_copies"] += 1
            return copy(*args, **kwargs)

        def observed_publish(*args, **kwargs):
            if no_copy:
                self.fail("replacement publisher invoked")
            counts["full_copies"] += 1
            return publisher(*args, **kwargs)

        with ExitStack() as stack:
            stack.enter_context(mock.patch.object(self.s, "_closed_tree_snapshot", side_effect=observed_snapshot))
            stack.enter_context(mock.patch.object(self.s, "_checked_verify", side_effect=observed_verify))
            stack.enter_context(mock.patch.object(self.s, "_copy_file", side_effect=observed_copy))
            stack.enter_context(mock.patch.object(self.s, "_stage_verified_package_anchored", side_effect=observed_publish))
            if no_copy:
                stack.enter_context(mock.patch.object(self.x, "_sha256", side_effect=AssertionError("unexpected stamp/library rehash")))
            yield counts

    def same_size_mutation(self, path):
        before = path.stat()
        payload = path.read_bytes()
        path.write_bytes(bytes([payload[0] ^ 1]) + payload[1:])
        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns))
        after = path.stat()
        self.assertEqual(after.st_size, before.st_size)
        self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)
        self.assertNotEqual(after.st_ctime_ns, before.st_ctime_ns)

    def test_capture_is_create_once_immutable_and_uses_fresh_closed_tree_evidence(self):
        original = self.s._checked_verify
        observed = []

        def strict(path, label, evidence):
            self.assertFalse(self.receipt().exists(), "receipt published before verifier")
            self.assertEqual(set(evidence), {
                path.relative_to(self.source / "package").as_posix()
                for path in (self.source / "package").rglob("*") if path.is_file()
            })
            value = original(path, label, evidence)
            observed.append(evidence)
            return value

        with self.observe() as counts, mock.patch.object(self.s, "_checked_verify", side_effect=strict), mock.patch.dict(
            self.s.verify_materialization.__globals__,
            {"_sha256": mock.Mock(side_effect=AssertionError("verifier rehashed package content"))},
        ):
            identity, snapshot = self.open_source(capture=True)
        # Strict wrapper above deliberately replaces observe's verifier hook.
        self.assertEqual(len(observed), 1)
        self.assertEqual(counts["source_hash_traversals"], 1)
        self.assertEqual(counts["source_file_hashes"], self.file_count)
        self.assertEqual(counts["destination_file_hashes"], 0)
        receipt = self.receipt()
        metadata = receipt.stat()
        self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o400)
        self.assertEqual(metadata.st_nlink, 1)
        self.assertEqual(metadata.st_uid, os.getuid())
        value = json.loads(receipt.read_bytes())
        self.assertEqual(value["version"], 1)
        self.assertEqual(value["root"], str(self.source))
        self.assertEqual(value["rootFields"], list(self.s._stable_tree_fields(self.source.stat())))
        self.assertEqual(value["snapshot"], json.loads(json.dumps(snapshot)))
        self.assertEqual(identity, self.identity)
        for relative, kind, fields, digest in snapshot:
            if kind == "file" and relative.startswith("package/"):
                self.assertEqual(observed[0][relative.removeprefix("package/")], (fields[4], digest))

    def test_wrong_capture_mode_and_missing_receipt_never_hash_verify_or_copy(self):
        for mode in ("", "shared-view", "unsupported"):
            with self.subTest(mode=mode), mock.patch.dict(os.environ, {"MACSCOPE_NATIVE_VERIFICATION_RECEIPT_MODE": mode}), self.observe(no_work=True, no_copy=True):
                with self.assertRaisesRegex(self.s.PackageStageError, "capture requires producer"):
                    self.direct(capture=True)
                with self.assertRaisesRegex(self.x.XcodeResourceStageError, "capture requires producer"):
                    self.xcode(capture=True)
        with self.observe(no_work=True, no_copy=True):
            with self.assertRaisesRegex(self.s.PackageStageError, "absent or conflicting"):
                self.open_source()
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.receipt().exists())

    def test_existing_active_prior_partial_and_conflicting_receipts_refuse_before_content(self):
        self.open_source(capture=True)
        valid = self.receipt().read_bytes()
        for store, payload in ((self.receipts, valid), (self.receipts, b"{"),
                               (self.prior, valid), (self.prior, b"")):
            with self.subTest(store=store.name, payload=payload[:1]):
                for root in (self.receipts, self.prior):
                    self.receipt(root=root).unlink(missing_ok=True)
                incumbent = self.receipt(root=store)
                incumbent.write_bytes(payload)
                incumbent.chmod(0o400)
                before = self.stable_state([incumbent])
                with mock.patch.dict(os.environ, {"MACSCOPE_NATIVE_PRIOR_RECEIPT_ROOT": str(self.prior)}), self.observe(no_work=True, no_copy=True):
                    with self.assertRaisesRegex(self.s.PackageStageError, "already exists in active or prior"):
                        self.open_source(capture=True)
                self.assertEqual(self.stable_state([incumbent]), before)
        self.receipt().write_bytes(valid)
        self.receipt().chmod(0o400)
        with mock.patch.dict(os.environ, {"MACSCOPE_NATIVE_PRIOR_RECEIPT_ROOT": str(self.prior)}), self.observe(no_work=True, no_copy=True):
            with self.assertRaisesRegex(self.s.PackageStageError, "absent or conflicting"):
                self.open_source()

    def test_malformed_writable_linked_and_unowned_receipts_refuse_without_fallback(self):
        self.open_source(capture=True)
        original = self.receipt().read_bytes()
        for defect in ("json", "shape", "digest", "duplicate-path", "unsafe-path", "writable", "hardlink", "symlink", "special", "unowned"):
            with self.subTest(defect=defect):
                receipt = self.receipt()
                receipt.unlink()
                receipt.write_bytes(original)
                receipt.chmod(0o400)
                alias = self.root / "receipt-alias"
                if defect in {"json", "shape", "digest", "duplicate-path", "unsafe-path"}:
                    value = json.loads(original)
                    if defect == "shape":
                        value["snapshot"] = [["broken"]]
                    elif defect == "digest":
                        next(record for record in value["snapshot"] if record[1] == "file")[3] = "not-a-digest"
                    elif defect == "duplicate-path":
                        value["snapshot"].append(value["snapshot"][0])
                    elif defect == "unsafe-path":
                        value["snapshot"][0][0] = "../escape"
                    receipt.chmod(0o600)
                    receipt.write_bytes(b"{" if defect == "json" else (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode())
                    receipt.chmod(0o400)
                elif defect == "writable":
                    receipt.chmod(0o600)
                elif defect == "hardlink":
                    os.link(receipt, alias)
                elif defect == "symlink":
                    receipt.rename(alias)
                    receipt.symlink_to(alias)
                elif defect == "special":
                    receipt.unlink()
                    os.mkfifo(receipt)
                with ExitStack() as stack:
                    if defect == "unowned":
                        real_lstat = Path.lstat

                        def unowned(path, *args, **kwargs):
                            observed = real_lstat(path, *args, **kwargs)
                            if path == receipt:
                                fields = list(observed)
                                fields[4] = observed.st_uid + 1
                                return os.stat_result(fields)
                            return observed

                        stack.enter_context(mock.patch.object(Path, "lstat", new=unowned))
                    stack.enter_context(self.observe(no_work=True, no_copy=True))
                    expression = ("immutable and owner-controlled" if defect in {
                        "writable", "hardlink", "symlink", "special", "unowned"
                    } else "producer receipt admission refused")
                    with self.assertRaisesRegex(self.s.PackageStageError, expression):
                        self.open_source()
                alias.unlink(missing_ok=True)

    def test_exact_reuse_and_prior_only_selection_do_no_payload_work(self):
        captured, _snapshot = self.open_source(capture=True)
        receipt_before = self.stable_state([self.receipt()])
        with self.observe(no_work=True, no_copy=True) as counts:
            reused, _snapshot = self.open_source()
        self.assertEqual(reused, captured)
        self.assertGreater(counts["metadata_traversals"], 0)
        self.assertEqual(counts["source_verify"], 0)
        self.assertEqual(self.stable_state([self.receipt()]), receipt_before)
        # Moving immutable receipt bytes to the declared private prior store is
        # permitted; a conflicting active name still vetoes all selection.
        self.receipt().rename(self.receipt(root=self.prior))
        with mock.patch.dict(os.environ, {"MACSCOPE_NATIVE_PRIOR_RECEIPT_ROOT": str(self.prior)}), self.observe(no_work=True, no_copy=True):
            self.assertEqual(self.open_source()[0], captured)
            self.receipt().write_bytes(b"{")
            self.receipt().chmod(0o400)
            with self.assertRaisesRegex(self.s.PackageStageError, "absent or conflicting"):
                self.open_source()

    def test_path_kind_inode_root_mode_and_complete_set_changes_refuse(self):
        for defect in ("missing", "extra-file", "extra-directory", "kind", "inode", "root", "mode", "ancestor"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as temporary:
                # A separate fixture per mutation avoids restoring trusted metadata.
                child = type(self)("runTest")
                child.setUp()
                try:
                    child.open_source(capture=True)
                    leaf = child.source / "package/lib/libsla.a"
                    if defect == "missing":
                        leaf.unlink()
                    elif defect == "extra-file":
                        (child.source / "extra").write_bytes(b"extra")
                    elif defect == "extra-directory":
                        (child.source / "empty").mkdir()
                    elif defect == "kind":
                        leaf.unlink()
                        leaf.mkdir()
                    elif defect == "inode":
                        replacement = child.root / "new-inode"
                        replacement.write_bytes(leaf.read_bytes())
                        replacement.replace(leaf)
                    elif defect == "root":
                        child.source.rename(child.root / "displaced")
                        shutil.copytree(child.root / "displaced", child.source)
                    elif defect == "mode":
                        leaf.chmod(0o600)
                    else:
                        # Keep an anchor alive while its ancestor is replaced.
                        anchor = child.s._open_verified_materialization(child.source, "source")
                        displaced = child.root.with_name(child.root.name + "-displaced")
                        child.root.rename(displaced)
                        child.root.symlink_to(displaced, target_is_directory=True)
                        try:
                            with child.observe(no_work=True, no_copy=True):
                                with child.assertRaisesRegex(child.s.PackageStageError, "path binding|indirect"):
                                    child.s._revalidate_anchored_materialization(*anchor[:4], "source")
                        finally:
                            os.close(anchor[1])
                            child.root.unlink()
                            displaced.rename(child.root)
                        continue
                    with child.observe(no_work=True, no_copy=True):
                        with child.assertRaisesRegex(child.s.PackageStageError, "metadata differs|changed|receipt-bound|hard-linked"):
                            child.open_source()
                finally:
                    child.doCleanups()

    def test_same_size_source_mutation_with_restored_mtime_refuses_ctime_lease(self):
        self.open_source(capture=True)
        self.same_size_mutation(self.source / "package/lib/libdecomp.a")
        with self.observe(no_work=True, no_copy=True):
            with self.assertRaisesRegex(self.s.PackageStageError, "changed after its verified snapshot"):
                self.open_source()

    def test_verification_failure_and_mutation_never_publish_reusable_source_evidence(self):
        for scenario in ("failure", "mutation", "root-substitution"):
            with self.subTest(scenario=scenario):
                receipt = self.receipt()
                self.assertFalse(receipt.exists())
                original = self.s._checked_verify
                leaf = self.source / "package/lib/libsla.a"
                payload = leaf.read_bytes()
                saved = self.root / "saved-source"

                def verify_then_change(path, label, evidence):
                    value = original(path, label, evidence)
                    if scenario == "failure":
                        raise self.s.PackageStageError("injected strict rejection")
                    if scenario == "mutation":
                        self.same_size_mutation(leaf)
                    else:
                        self.source.rename(saved)
                        shutil.copytree(saved, self.source)
                    return value

                with mock.patch.object(self.s, "_checked_verify", side_effect=verify_then_change) as strict:
                    expression = "strict rejection" if scenario == "failure" else "changed|path"
                    with self.assertRaisesRegex(self.s.PackageStageError, expression):
                        self.open_source(capture=True)
                strict.assert_called_once()
                self.assertFalse(receipt.exists())
                if saved.exists():
                    shutil.rmtree(self.source)
                    saved.rename(self.source)
                leaf.write_bytes(payload)

    def test_publication_mutation_invalidates_only_our_new_receipt(self):
        real_write = os.write
        changed = False

        def write_then_mutate(descriptor, payload):
            nonlocal changed
            result = real_write(descriptor, payload)
            if not changed and b'"rootFields"' in payload:
                changed = True
                self.same_size_mutation(self.source / "package/lib/libsla.a")
            return result

        with mock.patch.object(self.s.os, "write", side_effect=write_then_mutate):
            with self.assertRaisesRegex(self.s.PackageStageError, "changed after its verified snapshot"):
                self.open_source(capture=True)
        self.assertTrue(changed)
        self.assertEqual(self.receipt().read_bytes(), b"", "partial record must not remain reusable")
        with self.observe(no_work=True, no_copy=True):
            with self.assertRaisesRegex(self.s.PackageStageError, "already exists"):
                self.open_source(capture=True)

    def test_receipt_creation_and_prior_appearance_races_preserve_incumbents(self):
        real_open = os.open
        raced = False
        incumbent = b"incumbent-partial-evidence\n"

        def race_before_exclusive_open(path, flags, mode=0o777, *, dir_fd=None):
            nonlocal raced
            if path == self.receipt().name and flags & os.O_EXCL and not raced:
                raced = True
                self.receipt().write_bytes(incumbent)
                self.receipt().chmod(0o400)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch.object(self.s.os, "open", side_effect=race_before_exclusive_open):
            with self.assertRaisesRegex(self.s.PackageStageError, "publication refused"):
                self.open_source(capture=True)
        self.assertTrue(raced)
        self.assertEqual(self.receipt().read_bytes(), incumbent)
        self.receipt().unlink()
        original_verify = self.s._checked_verify

        def prior_appears(path, label, evidence):
            value = original_verify(path, label, evidence)
            self.receipt(root=self.prior).write_bytes(incumbent)
            return value

        with mock.patch.dict(os.environ, {"MACSCOPE_NATIVE_PRIOR_RECEIPT_ROOT": str(self.prior)}), mock.patch.object(self.s, "_checked_verify", side_effect=prior_appears):
            with self.assertRaisesRegex(self.s.PackageStageError, "already exists in active or prior"):
                self.open_source(capture=True)
        self.assertFalse(self.receipt().exists())
        self.assertEqual(self.receipt(root=self.prior).read_bytes(), incumbent)

    def test_fresh_xcode_capture_has_two_verifiers_two_hash_passes_and_one_full_copy(self):
        original_sha = self.x._sha256

        def metadata_only_sha(path):
            self.assertIn(path, self.xpaths()[1:3], "native library was redundantly rehashed")
            return original_sha(path)

        with self.observe() as counts, mock.patch.object(self.x, "_sha256", side_effect=metadata_only_sha), mock.patch.dict(
            self.s.verify_materialization.__globals__,
            {"_sha256": mock.Mock(side_effect=AssertionError("verifier rehashed package content"))},
        ):
            self.assertEqual(self.xcode(capture=True), self.identity)
        self.assertEqual(counts["source_verify"], 1)
        self.assertEqual(counts["destination_verify"], 1)
        self.assertEqual(counts["source_hash_traversals"], 1)
        self.assertEqual(counts["destination_hash_traversals"], 1)
        self.assertEqual(counts["source_file_hashes"], self.file_count)
        self.assertEqual(counts["destination_file_hashes"], self.file_count)
        self.assertEqual(counts["full_copies"], 1)
        self.assertEqual(counts["file_copies"], self.file_count)
        destination, inputs, outputs, stamp_path = self.xpaths()
        receipt = json.loads(self.receipt(destination).read_bytes())
        stamp = json.loads(stamp_path.read_bytes())
        self.assertEqual(stamp["materialization"], receipt["identity"])
        self.assertEqual(stamp["linkInputs"], self.x._link_input_records_from_snapshot(receipt["snapshot"]))
        files = [record[0] for record in receipt["snapshot"] if record[1] == "file"]
        self.assertEqual(inputs.read_text().splitlines(), [str(self.source / relative) for relative in files])
        self.assertEqual(outputs.read_text().splitlines(), [str(destination / relative) for relative in files])
        self.assertEqual(receipt["rootFields"], list(self.s._stable_tree_fields(destination.stat())))
        with self.observe(no_work=True, no_copy=True):
            state = self.x._existing_owned_state(*self.xpaths())
            self.x._close_owned_state(state)

    def test_same_size_destination_mutation_after_receipt_fails_real_final_admission(self):
        original = self.x._write_stamp_exclusively
        changed = False

        def stamp_then_change(*args, **kwargs):
            nonlocal changed
            result = original(*args, **kwargs)
            self.same_size_mutation(self.xpaths()[0] / "package/lib/libsla.a")
            changed = True
            return result

        with self.observe() as counts, mock.patch.object(self.x, "_write_stamp_exclusively", side_effect=stamp_then_change):
            with self.assertRaisesRegex(self.x.XcodeResourceStageError, "failed final validation") as failure:
                self.xcode(capture=True)
        self.assertTrue(changed)
        self.assertRegex(str(failure.exception.__cause__.__cause__), "changed after its verified snapshot")
        self.assertEqual(counts["source_verify"], 1)
        self.assertEqual(counts["destination_verify"], 1)
        self.assertEqual(counts["destination_file_hashes"], self.file_count)
        self.assertTrue(all(path.exists() for path in self.xpaths()), "partial owned set must be preserved")
        with self.observe(no_work=True, no_copy=True):
            with self.assertRaisesRegex(self.x.PackageAdmissionError, "admission refused"):
                self.x._existing_owned_state(*self.xpaths())

    def test_later_exact_xcode_reuse_preserves_all_state_with_zero_payload_work(self):
        first = self.xcode(capture=True)
        roots = [*self.xpaths(), self.receipts]
        before = self.stable_state(roots)
        with self.observe(no_work=True, no_copy=True) as counts:
            self.assertEqual(self.xcode(), first)
        self.assertGreater(counts["metadata_traversals"], 0)
        for key in ("source_verify", "destination_verify", "source_file_hashes", "destination_file_hashes", "full_copies", "file_copies"):
            self.assertEqual(counts[key], 0, key)
        self.assertEqual(self.stable_state(roots), before)

    def test_source_receipt_survives_destination_failure_without_destination_success_evidence(self):
        original = self.s._checked_verify

        def reject_destination(path, label, evidence):
            if path != self.source:
                raise self.s.PackageStageError("injected destination rejection")
            return original(path, label, evidence)

        with self.observe() as counts, mock.patch.object(self.s, "_checked_verify", side_effect=reject_destination):
            with self.assertRaisesRegex(self.s.PackageStageError, "destination rejection"):
                self.direct(capture=True)
        self.assertTrue(self.destination.is_dir())
        self.assertFalse(self.inputs.exists())
        self.assertFalse(self.outputs.exists())
        self.assertFalse(self.receipt(self.destination).exists())
        self.assertTrue(self.receipt().is_file())
        self.assertEqual(counts["source_file_hashes"], self.file_count)
        with self.observe(no_work=True, no_copy=True):
            self.assertEqual(self.open_source()[0], self.identity)

    def test_producer_missing_stale_partial_and_unowned_xcode_states_never_repair(self):
        self.xcode(capture=True)
        destination, inputs, outputs, stamp = self.xpaths()
        receipt = self.receipt(destination)
        receipt.unlink()
        before = self.stable_state([*self.xpaths(), self.receipts])
        with self.observe(no_work=True, no_copy=True):
            with self.assertRaisesRegex(self.x.PackageAdmissionError, "admission refused"):
                self.xcode()
        self.assertEqual(self.stable_state([*self.xpaths(), self.receipts]), before)
        # Complete owned metadata without the product is not authority to recopy.
        shutil.rmtree(destination)
        before = self.stable_state([inputs, outputs, stamp, self.receipts])
        with self.observe(no_work=True, no_copy=True):
            with self.assertRaisesRegex(self.x.PackageAdmissionError, "never repairs owned metadata"):
                self.xcode()
        self.assertEqual(self.stable_state([inputs, outputs, stamp, self.receipts]), before)
        outputs.unlink()
        with self.observe(no_work=True, no_copy=True):
            with self.assertRaisesRegex(self.x.XcodeResourceStageError, "complete owned attested set"):
                self.xcode()
        inputs.unlink()
        stamp.unlink()
        destination.mkdir()
        marker = destination / "foreign"
        marker.write_bytes(b"preserve")
        before = self.stable_state([destination])
        with self.observe(no_work=True, no_copy=True):
            with self.assertRaisesRegex(self.x.XcodeResourceStageError, "complete owned attested set"):
                self.xcode()
        self.assertEqual(self.stable_state([destination]), before)

    def test_default_and_shared_view_keep_existing_verification_and_historical_metadata_semantics(self):
        with mock.patch.dict(os.environ, {"MACSCOPE_NATIVE_VERIFICATION_RECEIPT_MODE": ""}), self.observe() as counts:
            self.assertEqual(self.direct(), self.identity)
        self.assertEqual(counts["source_verify"], 1)
        self.assertEqual(counts["destination_verify"], 1)
        self.assertFalse(list(self.receipts.iterdir()))
        shutil.rmtree(self.destination)
        self.inputs.unlink()
        self.outputs.unlink()
        # Fresh synthetic shared-view authority is obtained from a genuinely
        # strict fixture snapshot here, not inferred from build metadata.
        with mock.patch.dict(os.environ, {"MACSCOPE_NATIVE_VERIFICATION_RECEIPT_MODE": ""}):
            _identity, snapshot = self.open_source()
        accepted = {"identity": self.identity,
                    "files": {relative: (fields[4], digest)
                              for relative, kind, fields, digest in snapshot if kind == "file"}}
        with mock.patch.dict(os.environ, {"MACSCOPE_NATIVE_VERIFICATION_RECEIPT_MODE": "shared-view"}), mock.patch.object(self.s, "_reused_source_receipt", return_value=accepted):
            with self.observe() as counts:
                self.assertEqual(self.direct(), self.identity)
            self.assertEqual(counts["source_verify"], 0)
            self.assertEqual(counts["destination_verify"], 1)
            os.utime(self.destination / "package/lib/libsla.a", ns=(1, 1))
            os.utime(self.destination, ns=(1, 1))
            with self.observe(no_work=True, no_copy=True):
                anchor = self.s._open_verified_materialization(self.destination, "historical shared view")
                os.close(anchor[1])
            (self.destination / "package/lib/libsla.a").write_bytes(b"different size")
            with self.observe(no_work=True, no_copy=True):
                with self.assertRaisesRegex(self.s.PackageStageError, "changed after first verification"):
                    self.s._open_verified_materialization(self.destination, "historical shared view")

    def test_receipt_and_path_binding_changes_during_reuse_refuse_without_content_work(self):
        self.open_source(capture=True)
        anchor = self.s._open_verified_materialization(self.source, "source")
        try:
            payload = self.receipt().read_bytes()
            self.receipt().chmod(0o600)
            self.receipt().write_bytes(payload)
            self.receipt().chmod(0o400)
            with self.observe(no_work=True, no_copy=True):
                with self.assertRaisesRegex(self.s.PackageStageError, "receipt changed after admission"):
                    self.s._revalidate_anchored_materialization(*anchor[:4], "source")
        finally:
            os.close(anchor[1])

    def test_receipt_mutation_during_descriptor_read_refuses_without_payload_fallback(self):
        self.open_source(capture=True)
        receipt = self.receipt()
        before = receipt.stat()
        payload = receipt.read_bytes()
        original_read = os.read
        changed = False

        def read_then_change(descriptor, count):
            nonlocal changed
            block = original_read(descriptor, count)
            opened = os.fstat(descriptor)
            if not changed and (opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino):
                changed = True
                receipt.chmod(0o600)
                receipt.write_bytes(payload)
                receipt.chmod(0o400)
            return block

        with self.observe(no_work=True, no_copy=True), mock.patch.object(self.s.os, "read", side_effect=read_then_change):
            with self.assertRaisesRegex(self.s.PackageStageError, "receipt changed while reading"):
                self.open_source()
        self.assertTrue(changed)

    def test_capture_rejects_ancestor_aba_during_strict_verification(self):
        original = self.s._checked_verify
        changed = False

        def verify_then_swap_ancestor_back(path, label, evidence):
            nonlocal changed
            value = original(path, label, evidence)
            displaced = self.root.with_name(self.root.name + "-displaced")
            self.root.rename(displaced)
            self.root.mkdir()
            self.root.rmdir()
            displaced.rename(self.root)
            changed = True
            return value

        with mock.patch.object(self.s, "_checked_verify", side_effect=verify_then_swap_ancestor_back):
            with self.assertRaisesRegex(self.s.PackageStageError, "path changed during verification"):
                self.open_source(capture=True)
        self.assertTrue(changed)
        self.assertFalse(self.receipt().exists())

    def test_capture_retains_actual_verifier_identity_and_exact_publication_lease(self):
        original_verify = self.s._checked_verify
        original_publish = self.s._publish_exact_staged_receipt
        verified = []
        published = []

        def retain_verifier_result(*args, **kwargs):
            identity = original_verify(*args, **kwargs)
            verified.append(identity)
            return identity

        def retain_publication(*args, **kwargs):
            lease = original_publish(*args, **kwargs)
            published.append(lease)
            return lease

        with self.observe() as counts, mock.patch.object(
            self.s, "_checked_verify", side_effect=retain_verifier_result
        ), mock.patch.object(self.s, "_publish_exact_staged_receipt", side_effect=retain_publication):
            anchor = self.s._open_verified_materialization(
                self.source, "source", capture_source_receipt=True
            )
        try:
            self.assertEqual(len(verified), 1)
            self.assertEqual(len(published), 1)
            self.assertIs(anchor[4], verified[0], "receipt admission replaced the verifier result")
            receipt, fields, payload = published[0]
            self.assertEqual(receipt, self.receipt())
            self.assertEqual(fields, self.s._stable_tree_fields(receipt.stat()))
            self.assertEqual(payload, receipt.read_bytes())
            self.assertEqual(anchor[3].receipts, (published[0],))
            recorded = json.loads(payload)
            self.assertEqual(recorded["identity"], verified[0])
            self.assertEqual(recorded["snapshot"], json.loads(json.dumps(tuple(anchor[3]))))
            self.assertEqual(counts["source_hash_traversals"], 1)
            self.assertEqual(counts["source_file_hashes"], self.file_count)
        finally:
            os.close(anchor[1])

    def _assert_atomic_late_receipt_replacement_refused(self, *, change_identity):
        original_publish = self.s._publish_exact_staged_receipt
        replacement_state = {}

        def publish_then_replace(*args, **kwargs):
            publication_lease = original_publish(*args, **kwargs)
            receipt, published_fields, expected_payload = publication_lease
            original = json.loads(expected_payload)
            replacement = json.loads(expected_payload)
            if change_identity:
                replacement["identity"]["sleighVersion"] = "late-forged-identity"
            payload = (json.dumps(replacement, sort_keys=True, separators=(",", ":")) + "\n").encode()
            self.assertEqual(replacement["rootFields"], original["rootFields"])
            self.assertEqual(replacement["snapshot"], original["snapshot"])
            prepared = self.receipts / "late-replacement"
            prepared.write_bytes(payload)
            prepared.chmod(0o400)
            prepared.replace(receipt)
            self.assertEqual(stat.S_IMODE(receipt.stat().st_mode), 0o400)
            self.assertEqual(receipt.stat().st_uid, os.getuid())
            self.assertEqual(receipt.stat().st_nlink, 1)
            self.assertNotEqual(self.s._stable_tree_fields(receipt.stat()), published_fields)
            replacement_state.update(self.stable_state([receipt]))
            # Return the original publication, never the replacement's lease.
            return publication_lease

        with self.observe() as counts, mock.patch.object(
            self.s, "_publish_exact_staged_receipt", side_effect=publish_then_replace
        ) as publication:
            with self.assertRaisesRegex(
                self.s.PackageStageError, "capture receipt differs from its exact publication"
            ):
                self.direct(capture=True)
        publication.assert_called_once()
        self.assertEqual(counts["source_verify"], 1)
        self.assertEqual(counts["source_hash_traversals"], 1)
        self.assertEqual(counts["source_file_hashes"], self.file_count)
        for key in ("destination_verify", "destination_hash_traversals", "destination_file_hashes",
                    "full_copies", "file_copies"):
            self.assertEqual(counts[key], 0, key)
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.inputs.exists())
        self.assertFalse(self.outputs.exists())
        self.assertEqual(self.stable_state([self.receipt()]), replacement_state)
        # Refusal does not erase the incumbent or authorize an automatic retry.
        with self.observe(no_work=True, no_copy=True):
            with self.assertRaisesRegex(self.s.PackageStageError, "already exists in active or prior"):
                self.direct(capture=True)
        self.assertEqual(self.stable_state([self.receipt()]), replacement_state)

    def test_late_identity_receipt_replacement_refuses_atomically_without_fallback(self):
        self._assert_atomic_late_receipt_replacement_refused(change_identity=True)

    def test_late_identical_bytes_receipt_replacement_refuses_new_inode_without_fallback(self):
        self._assert_atomic_late_receipt_replacement_refused(change_identity=False)

    def test_capture_requires_disjoint_private_canonical_store(self):
        nested = self.source / "receipts"
        nested.mkdir(mode=0o700)
        alias = self.root / "receipt-store-alias"
        alias.symlink_to(self.receipts, target_is_directory=True)
        for store, expression in ((nested, "disjoint"), (self.root, "disjoint"),
                                  (alias, "private canonical directory")):
            with self.subTest(store=store), mock.patch.dict(os.environ, {
                "MACSCOPE_NATIVE_SOURCE_IDENTITY_RECEIPT_ROOT": str(store)
            }), self.observe(no_work=True, no_copy=True):
                with self.assertRaisesRegex(self.s.PackageStageError, expression):
                    self.open_source(capture=True)
        self.receipts.chmod(0o755)
        with self.observe(no_work=True, no_copy=True):
            with self.assertRaisesRegex(self.s.PackageStageError, "private canonical directory"):
                self.open_source(capture=True)

    def test_default_xcode_exact_reuse_and_shared_view_absent_receipt_recovery_are_unchanged(self):
        with mock.patch.dict(os.environ, {"MACSCOPE_NATIVE_VERIFICATION_RECEIPT_MODE": ""}):
            with self.observe() as fresh:
                self.assertEqual(self.xcode(), self.identity)
            self.assertEqual(fresh["source_verify"], 1)
            self.assertEqual(fresh["destination_verify"], 2, "ordinary final admission remains strict")
            before = self.stable_state(list(self.xpaths()))
            with self.observe() as reused:
                self.assertEqual(self.xcode(), self.identity)
            self.assertEqual(reused["source_verify"], 1)
            self.assertEqual(reused["destination_verify"], 1)
            self.assertEqual(reused["file_copies"], 0)
            self.assertEqual(self.stable_state(list(self.xpaths())), before)
            _identity, snapshot = self.open_source()
        accepted = {"identity": self.identity,
                    "files": {relative: (fields[4], digest)
                              for relative, kind, fields, digest in snapshot if kind == "file"}}
        with mock.patch.dict(os.environ, {"MACSCOPE_NATIVE_VERIFICATION_RECEIPT_MODE": "shared-view"}), mock.patch.object(self.s, "_reused_source_receipt", return_value=accepted):
            with self.observe() as recovery, mock.patch.object(self.x, "_retire_owned_state", wraps=self.x._retire_owned_state) as retire:
                self.assertEqual(self.xcode(), self.identity)
            retire.assert_called_once()
            self.assertEqual(recovery["source_verify"], 0)
            self.assertEqual(recovery["destination_verify"], 1)
            self.assertEqual(recovery["full_copies"], 1)
            before = self.stable_state([*self.xpaths(), self.receipts])
            with self.observe(no_work=True, no_copy=True):
                self.assertEqual(self.xcode(), self.identity)
            self.assertEqual(self.stable_state([*self.xpaths(), self.receipts]), before)


if __name__ == "__main__":
    unittest.main()
