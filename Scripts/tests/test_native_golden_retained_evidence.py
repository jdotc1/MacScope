#!/usr/bin/env python3
"""Synthetic retained-evidence tests; no native build or real artifact reads."""
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("golden_reuse", ROOT / "Scripts/native-decompiler-xpc/native_golden_receipts.py")
GOLDEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GOLDEN)
REAL_DIGEST, REAL_STABLE_HASH = GOLDEN.digest, GOLDEN.stable_hash


class RetainedGoldenTests(unittest.TestCase):
    def test_prior_digest_reused_without_hashing(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            current, prior = root / "current", root / "prior"
            current.mkdir(mode=0o700)
            prior.mkdir(mode=0o700)
            artifact = root / "stamp"
            artifact.write_text("synthetic")
            key = GOLDEN.hashlib.sha256(str(artifact).encode()).hexdigest()
            receipt = prior / ("golden-digest-" + key + ".json")
            GOLDEN.retain_document(receipt, {"version": 1, "path": str(artifact),
                "metadata": GOLDEN.fields(artifact.stat()), "sha256": "a" * 64})
            with mock.patch.dict(os.environ, {"MACSCOPE_NATIVE_VERIFICATION_RECEIPT_MODE": "shared-view",
                    "MACSCOPE_NATIVE_SOURCE_IDENTITY_RECEIPT_ROOT": str(current),
                    "MACSCOPE_NATIVE_PRIOR_RECEIPT_ROOT": str(prior)}), \
                    mock.patch.object(GOLDEN, "bridge_digest", return_value=None), \
                    mock.patch.object(GOLDEN, "stable_hash", side_effect=AssertionError("repeat hashing")):
                self.assertEqual(GOLDEN.digest(artifact), "a" * 64)
                artifact.write_text("changed")
                with self.assertRaisesRegex(ValueError, "stale"):
                    GOLDEN.digest(artifact)

    def test_admitted_native_digest_never_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            artifact = Path(temporary).resolve() / "archive"
            artifact.write_text("synthetic")
            with mock.patch.dict(os.environ, {"MACSCOPE_NATIVE_VERIFICATION_RECEIPT_MODE": "shared-view"}), \
                    mock.patch.object(GOLDEN, "bridge_digest", return_value="b" * 64), \
                    mock.patch.object(GOLDEN, "stable_hash", side_effect=AssertionError("repeat hashing")):
                self.assertEqual(GOLDEN.digest(artifact), "b" * 64)

    def test_completed_digest_without_receipt_never_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            artifact = root / "stamp"
            artifact.write_text("synthetic")
            with mock.patch.dict(os.environ, {"MACSCOPE_NATIVE_VERIFICATION_RECEIPT_MODE": "shared-view"}), \
                    mock.patch.object(GOLDEN, "receipt_root", return_value=root), \
                    mock.patch.object(GOLDEN, "prior_root", return_value=None), \
                    mock.patch.object(GOLDEN, "bridge_digest", return_value=None), \
                    mock.patch.object(GOLDEN, "stable_hash", side_effect=AssertionError("repeat hashing")):
                with self.assertRaisesRegex(ValueError, "refusing repeat hashing"):
                    GOLDEN.digest(artifact, allow_new=False)

    def test_completed_result_survives_transport_change_without_execution(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            result = root / "result.json"
            value = {"passed": True, "contractArchiveSHA256": "a", "contractBuildIdentitySHA256": "a",
                     "materializationManifestSHA256": "a", "decompilerArchiveSHA256": "a",
                     "sleighArchiveSHA256": "a", "stageStampSHA256": "a"}
            probes = {"xcodeVersion": "27.0", "xcodeBuild": "18A1", "sdkVersion": "27.0",
                      "sdkBuild": "18A2", "swiftCompilerVersion": "6.3", "swiftTargetTriple": "arm64-apple-macosx27.0"}
            value.update(probes)
            toolchain = {"developer": str(root / "Developer"), "sdk": str(root / "SDK"), "sdkName": "macosx"}
            result.write_text(json.dumps(value))
            source = [["fixture.cpp", 1], [next(iter(GOLDEN.TRANSPORT_ONLY)), 2]]
            saved = {"result": value, "resultMetadata": GOLDEN.fields(result.stat()),
                     "toolchain": toolchain, "runnerBlob": "runner", "source": {"files": source}, "sourceGitRecords": [["fixture.cpp", "100644", "blob"]]}
            receipt = GOLDEN.completed_path(root, result)
            GOLDEN.retain_document(receipt, saved)
            identity = types.SimpleNamespace(profile_paths=lambda *args: [],
                _profile_snapshot=lambda *args: [["fixture.cpp", 1], [source[1][0], 9]])
            with mock.patch.dict(sys.modules, {"native_decompiler_source_identity": identity}), \
                    mock.patch.dict(os.environ, {"MACSCOPE_NATIVE_DECOMPILER_BUILD_ROOT": str(root)}), \
                    mock.patch.object(GOLDEN, "receipt_root", return_value=root), \
                    mock.patch.object(GOLDEN, "prior_root", return_value=None), \
                    mock.patch.object(GOLDEN, "runner_blob", return_value="runner"), \
                    mock.patch.object(GOLDEN, "tool_identity", return_value="tools", create=True), \
                    mock.patch.object(GOLDEN, "probe_toolchain", return_value=probes, create=True), \
                    mock.patch.object(GOLDEN, "digest", return_value="a"), \
                    mock.patch.object(GOLDEN, "stable_hash", side_effect=AssertionError("repeat hashing")):
                before = result.read_bytes()
                self.assertTrue(GOLDEN.reuse_completed(result, root, root, root / "stamp", toolchain))
                self.assertEqual(result.read_bytes(), before)
                with self.assertRaisesRegex(ValueError, "toolchain"):
                    GOLDEN.reuse_completed(result, root, root, root / "stamp", dict(toolchain, sdkName="different"))
                with mock.patch.object(GOLDEN, "runner_blob", return_value="new-runner"):
                    self.assertFalse(GOLDEN.reuse_completed(result, root, root, root / "stamp", toolchain))
                identity._profile_snapshot = lambda *args: [["fixture.cpp", 3], source[1]]
                with mock.patch.object(GOLDEN, "semantic_sources", return_value=saved["sourceGitRecords"]):
                    with self.assertRaisesRegex(ValueError, "unchanged golden sources"):
                        GOLDEN.reuse_completed(result, root, root, root / "stamp", toolchain)

    @contextmanager
    def _completed_fixture(self, *, bound=True, prior_record=False, stamp_sha=None):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            current, prior = root / "current", root / "prior"
            current.mkdir(mode=0o700)
            prior.mkdir(mode=0o700)
            result = root / "result.json"
            probes = {"xcodeVersion": "27.0", "xcodeBuild": "18A1", "sdkVersion": "27.0",
                      "sdkBuild": "18A2", "swiftCompilerVersion": "6.3", "swiftTargetTriple": "arm64-apple-macosx27.0"}
            inputs = {"contractArchiveSHA256": root / "libmacscope_native_decompiler_contract.a",
                      "contractBuildIdentitySHA256": root / "generated/MacScopeNativeDecompiler/GhidraBuildIdentity.hpp",
                      "materializationManifestSHA256": root / "MATERIALIZATION.json",
                      "decompilerArchiveSHA256": root / "package/lib/libdecomp.a",
                      "sleighArchiveSHA256": root / "package/lib/libsla.a",
                      "stageStampSHA256": root / "stamp"}
            value = dict(probes, passed=True, **{name: "a" for name in inputs})
            if stamp_sha is not None:
                value["stageStampSHA256"] = stamp_sha
            result.write_text(json.dumps(value))
            toolchain = {"developer": str(root / "Developer"), "sdk": str(root / "SDK"), "sdkName": "macosx"}
            source = [["fixture.cpp", 1], [next(iter(GOLDEN.TRANSPORT_ONLY)), 2]]
            saved = {"result": value, "resultMetadata": GOLDEN.fields(result.stat()),
                     "toolchain": toolchain, "runnerBlob": "runner", "source": {"files": source},
                     "sourceGitRecords": [["fixture.cpp", "100644", "blob"]]}
            if bound:
                saved["tools"] = "tools"
            record = GOLDEN.completed_path(prior if prior_record else current, result)
            GOLDEN.retain_document(record, saved)
            sidecar = current / record.name.replace("golden-completed-", "golden-toolbind-", 1)
            identity = types.SimpleNamespace(profile_paths=lambda *args: [], files=list(source),
                                            _profile_snapshot=lambda *args: identity.files)
            with mock.patch.dict(sys.modules, {"native_decompiler_source_identity": identity}), \
                    mock.patch.dict(os.environ, {"MACSCOPE_NATIVE_DECOMPILER_BUILD_ROOT": str(root)}), \
                    mock.patch.object(GOLDEN, "receipt_root", return_value=current), \
                    mock.patch.object(GOLDEN, "prior_root", return_value=prior), \
                    mock.patch.object(GOLDEN, "runner_blob", return_value="runner"), \
                    mock.patch.object(GOLDEN, "tool_identity", return_value="tools", create=True) as tools, \
                    mock.patch.object(GOLDEN, "probe_toolchain", return_value=probes, create=True) as probe, \
                    mock.patch.object(GOLDEN, "digest", return_value="a") as digest, \
                    mock.patch.object(GOLDEN, "stable_hash", side_effect=AssertionError("repeat hashing")):
                yield types.SimpleNamespace(identity=identity, source=source, root=root, current=current, prior=prior, result=result,
                    probes=probes, inputs=inputs, toolchain=toolchain, record=record, sidecar=sidecar,
                    saved=saved, tools=tools, probe=probe, digest=digest,
                    reuse=lambda requested=None: GOLDEN.reuse_completed(result, root, root, root / "stamp",
                        toolchain if requested is None else requested))

    def _binding(self, fixture, *, tools="tools", record_sha256=None):
        return {"version": 1,
                "recordSHA256": GOLDEN.hashlib.sha256(fixture.record.read_bytes()).hexdigest()
                    if record_sha256 is None else record_sha256,
                "tools": tools, "probes": fixture.probes}

    def test_g1_bound_tools_equal_reuses_without_probe(self):
        with self._completed_fixture() as fixture:
            fixture.probe.side_effect = AssertionError("bound record must not probe")
            self.assertTrue(fixture.reuse())
            self.assertFalse(fixture.sidecar.exists())

    def test_g2_bound_tools_changed_refuses_without_evidence(self):
        with self._completed_fixture() as fixture:
            fixture.tools.return_value = "swiftc-replaced-in-place"
            fixture.probe.side_effect = AssertionError("bound record must not probe")
            before = fixture.record.read_bytes()
            with mock.patch.object(GOLDEN, "retain_document", side_effect=AssertionError("no new evidence")):
                self.assertFalse(fixture.reuse())
            self.assertEqual(fixture.record.read_bytes(), before)
            self.assertEqual(list(fixture.current.iterdir()), [fixture.record])

    def test_g3_path_and_sdk_name_refuse_before_identity_or_probe(self):
        for name in ("developer", "sdk", "sdkName"):
            with self.subTest(field=name), self._completed_fixture() as fixture:
                requested = dict(fixture.toolchain)
                requested[name] += "-different"
                with self.assertRaisesRegex(ValueError, "toolchain"):
                    fixture.reuse(requested)
                fixture.tools.assert_not_called()
                fixture.probe.assert_not_called()

    def test_g4_legacy_matching_probes_retain_byte_bound_sidecar(self):
        with self._completed_fixture(bound=False) as fixture:
            before = fixture.record.read_bytes()
            self.assertTrue(fixture.reuse())
            self.assertEqual(GOLDEN.owned_receipt(fixture.sidecar), self._binding(fixture))
            self.assertEqual(fixture.sidecar.stat().st_mode & 0o777, 0o400)
            self.assertEqual(fixture.record.read_bytes(), before)

    def test_g5_legacy_different_or_missing_probe_refuses_without_sidecar(self):
        for name in ("xcodeVersion", "xcodeBuild", "sdkVersion", "sdkBuild",
                     "swiftCompilerVersion", "swiftTargetTriple"):
            for missing in (False, True):
                with self.subTest(field=name, missing=missing), self._completed_fixture(bound=False) as fixture:
                    observed = dict(fixture.probes)
                    if missing:
                        del observed[name]
                    else:
                        observed[name] += " "
                    fixture.probe.return_value = observed
                    with mock.patch.object(GOLDEN, "retain_document", side_effect=AssertionError("no new evidence")):
                        self.assertFalse(fixture.reuse())
                    self.assertFalse(fixture.sidecar.exists())

    def test_g6_legacy_bound_sidecar_reuses_without_probe(self):
        with self._completed_fixture(bound=False) as fixture:
            GOLDEN.retain_document(fixture.sidecar, self._binding(fixture))
            fixture.probe.side_effect = AssertionError("sidecar must avoid probes")
            before = fixture.sidecar.read_bytes()
            self.assertTrue(fixture.reuse())
            self.assertEqual(fixture.sidecar.read_bytes(), before)

    def test_g7_legacy_sidecar_changed_tools_or_wrong_record_refuses(self):
        for wrong_record in (False, True):
            with self.subTest(wrong_record=wrong_record), self._completed_fixture(bound=False) as fixture:
                binding = self._binding(fixture, tools="different" if not wrong_record else "tools",
                    record_sha256="0" * 64 if wrong_record else None)
                GOLDEN.retain_document(fixture.sidecar, binding)
                fixture.probe.side_effect = AssertionError("sidecar must avoid probes")
                before = fixture.sidecar.read_bytes()
                with mock.patch.object(GOLDEN, "retain_document", side_effect=AssertionError("no new evidence")):
                    if wrong_record:
                        with self.assertRaisesRegex(ValueError, "completion record"):
                            fixture.reuse()
                    else:
                        self.assertFalse(fixture.reuse())
                self.assertEqual(fixture.sidecar.read_bytes(), before)

    def test_g8_each_input_digest_difference_refuses_without_new_evidence(self):
        names = ("contractArchiveSHA256", "contractBuildIdentitySHA256", "materializationManifestSHA256",
                 "decompilerArchiveSHA256", "sleighArchiveSHA256", "stageStampSHA256")
        for name in names:
            with self.subTest(digest=name), self._completed_fixture() as fixture:
                fixture.probe.side_effect = AssertionError("bound record must not probe")
                fixture.digest.side_effect = lambda path, *args, **kwargs: "different" if path == fixture.inputs[name] else "a"
                before = {path.name: path.read_bytes() for path in fixture.current.iterdir()}
                result_before = fixture.result.read_bytes()
                with mock.patch.object(GOLDEN, "retain_document", side_effect=AssertionError("no new evidence")):
                    with self.assertRaisesRegex(ValueError, "completed golden inputs differ"):
                        fixture.reuse()
                self.assertEqual({path.name: path.read_bytes() for path in fixture.current.iterdir()}, before)
                self.assertEqual(fixture.result.read_bytes(), result_before)
                self.assertFalse(fixture.sidecar.exists())

    def _metadata_only_change(self, fixture, git_records):
        fixture.identity.files[:] = [["fixture.cpp", 3], fixture.source[1]]
        return mock.patch.object(GOLDEN, "semantic_sources", return_value=git_records)

    def test_gold_refresh_a_metadata_only_change_reuses_and_refreshes_record(self):
        with self._completed_fixture() as fixture:
            fixture.probe.side_effect = AssertionError("bound record must not probe")
            old_bytes = fixture.record.read_bytes()
            with self._metadata_only_change(fixture, fixture.saved["sourceGitRecords"]), \
                    mock.patch.dict(os.environ, {"MACSCOPE_NATIVE_RETIRE_STALE_RECEIPTS": "1"}):
                self.assertTrue(fixture.reuse())
            refreshed = GOLDEN.owned_receipt(fixture.record)
            self.assertEqual(refreshed["source"]["files"], [["fixture.cpp", 3], fixture.source[1]])
            self.assertEqual(refreshed["result"], fixture.saved["result"])
            self.assertFalse(fixture.record.stat().st_mode & 0o222)
            moved = list((fixture.current / "NativePhaseReuseRetired").glob("*/golden-completed-*.json"))
            self.assertEqual([path.read_bytes() for path in moved], [old_bytes])
            # The refreshed record now matches without another refresh.
            with mock.patch.object(GOLDEN, "semantic_sources", side_effect=AssertionError("no refresh needed")):
                self.assertTrue(fixture.reuse())

    def test_gold_refresh_a2_metadata_only_change_without_optin_keeps_raise(self):
        with self._completed_fixture() as fixture:
            before = fixture.record.read_bytes()
            environment = {key: value for key, value in os.environ.items() if key != "MACSCOPE_NATIVE_RETIRE_STALE_RECEIPTS"}
            with self._metadata_only_change(fixture, fixture.saved["sourceGitRecords"]), \
                    mock.patch.dict(os.environ, environment, clear=True):
                with self.assertRaisesRegex(ValueError, "unchanged golden sources have changed metadata"):
                    fixture.reuse()
            self.assertEqual(fixture.record.read_bytes(), before)
            self.assertFalse((fixture.current / "NativePhaseReuseRetired").exists())

    def test_gold_refresh_b_differing_git_records_still_needs_execution(self):
        with self._completed_fixture() as fixture:
            before = fixture.record.read_bytes()
            with self._metadata_only_change(fixture, [["fixture.cpp", "100644", "other"]]):
                self.assertFalse(fixture.reuse())
            self.assertEqual(fixture.record.read_bytes(), before)
            self.assertFalse((fixture.current / "NativePhaseReuseRetired").exists())

    @contextmanager
    def _regenerated_digest(self, *, malformed=False, optin=True, prior=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            current, other = root / "current", root / "prior"
            current.mkdir(mode=0o700)
            other.mkdir(mode=0o700)
            artifact = root / "stage.json"
            artifact.write_text("old")
            key = GOLDEN.hashlib.sha256(str(artifact).encode()).hexdigest()
            holder = other if prior else current
            receipt = holder / ("golden-digest-" + key + ".json")
            document = {"version": 1, "path": str(artifact), "metadata": GOLDEN.fields(artifact.stat()), "sha256": "a" * 64}
            if malformed:
                document["extra"] = True
            GOLDEN.retain_document(receipt, document)
            replacement = root / "stage.new"
            replacement.write_text("regenerated")
            os.replace(replacement, artifact)  # new inode, as a rebuilt product
            environment = {"MACSCOPE_NATIVE_VERIFICATION_RECEIPT_MODE": "shared-view",
                           "MACSCOPE_NATIVE_SOURCE_IDENTITY_RECEIPT_ROOT": str(current),
                           "MACSCOPE_NATIVE_PRIOR_RECEIPT_ROOT": str(other)}
            if optin:
                environment["MACSCOPE_NATIVE_RETIRE_STALE_RECEIPTS"] = "1"
            with mock.patch.dict(os.environ, environment), mock.patch.object(GOLDEN, "bridge_digest", return_value=None):
                yield types.SimpleNamespace(artifact=artifact, current=current, receipt=receipt, document=document)

    def test_gold_refresh_c_regenerated_file_with_optin_retires_old_receipt_and_hashes_once(self):
        for prior in (False, True):
            with self.subTest(prior=prior), self._regenerated_digest(prior=prior) as fixture:
                digest = GOLDEN.hashlib.sha256(b"regenerated").hexdigest()
                self.assertEqual(GOLDEN.digest(fixture.artifact), digest)
                new = fixture.current / fixture.receipt.name
                written = GOLDEN.owned_receipt(new)
                self.assertEqual((written["metadata"], written["sha256"]), (GOLDEN.fields(fixture.artifact.stat()), digest))
                self.assertFalse(new.stat().st_mode & 0o222)
                if prior:
                    self.assertTrue(fixture.receipt.exists())  # the prior root is never modified
                else:
                    moved = list((fixture.current / "NativePhaseReuseRetired").glob("*/golden-digest-*.json"))
                    self.assertEqual(len(moved), 1)
                    self.assertEqual(GOLDEN.owned_receipt(moved[0]), fixture.document)
                with mock.patch.object(GOLDEN, "stable_hash", side_effect=AssertionError("repeat hashing")):
                    self.assertEqual(GOLDEN.digest(fixture.artifact), digest)

    def test_gold_refresh_d_regenerated_file_without_optin_keeps_refusal(self):
        with self._regenerated_digest(optin=False) as fixture:
            with mock.patch.object(GOLDEN, "stable_hash", side_effect=AssertionError("repeat hashing")):
                with self.assertRaisesRegex(ValueError, "stale or malformed"):
                    GOLDEN.digest(fixture.artifact)
            self.assertTrue(fixture.receipt.exists())
            self.assertFalse((fixture.current / "NativePhaseReuseRetired").exists())

    def test_gold_refresh_e_malformed_receipt_refuses_even_with_optin(self):
        with self._regenerated_digest(malformed=True) as fixture:
            with mock.patch.object(GOLDEN, "stable_hash", side_effect=AssertionError("repeat hashing")):
                with self.assertRaisesRegex(ValueError, "stale or malformed"):
                    GOLDEN.digest(fixture.artifact)
            self.assertTrue(fixture.receipt.exists())
            self.assertFalse((fixture.current / "NativePhaseReuseRetired").exists())

    @contextmanager
    def _stage_stamp_case(self, new_bytes, *, optin):
        """A stage stamp regenerated with a new inode after its digest receipt was retained."""
        sha = GOLDEN.hashlib.sha256(b"same").hexdigest()
        environment = {"MACSCOPE_NATIVE_VERIFICATION_RECEIPT_MODE": "shared-view"}
        if optin:
            environment["MACSCOPE_NATIVE_RETIRE_STALE_RECEIPTS"] = "1"
        with self._completed_fixture(stamp_sha=sha) as fixture:
            stamp = fixture.root / "stage.json"
            stamp.write_bytes(b"same")
            wrapped = lambda path, *args, **kwargs: (REAL_DIGEST(path, *args, **kwargs) if path == stamp else "a")
            with mock.patch.dict(os.environ, environment), \
                    mock.patch.object(GOLDEN, "bridge_digest", return_value=None), \
                    mock.patch.object(GOLDEN, "stable_hash", REAL_STABLE_HASH), \
                    mock.patch.object(GOLDEN, "digest", REAL_DIGEST):
                self.assertEqual(GOLDEN.digest(stamp), sha)
            replacement = fixture.root / "stage.new"
            replacement.write_bytes(new_bytes)
            os.replace(replacement, stamp)
            fixture.digest.side_effect = wrapped
            yield fixture, stamp, environment

    def _reuse_stamp(self, fixture, stamp, environment):
        with mock.patch.dict(os.environ, environment), \
                mock.patch.object(GOLDEN, "bridge_digest", return_value=None), \
                mock.patch.object(GOLDEN, "stable_hash", REAL_STABLE_HASH), \
                mock.patch.object(GOLDEN, "digest", lambda path, *a, **k: REAL_DIGEST(path, *a, **k) if path == stamp else "a"):
            return GOLDEN.reuse_completed(fixture.result, fixture.root, fixture.root / "mat", stamp, fixture.toolchain)

    def test_gold_refresh_f_regenerated_stage_stamp_with_same_bytes_reuses(self):
        with self._stage_stamp_case(b"same", optin=True) as (fixture, stamp, environment):
            self.assertTrue(self._reuse_stamp(fixture, stamp, environment))
            self.assertEqual(len(list((fixture.current / "NativePhaseReuseRetired").glob("*/golden-digest-*.json"))), 1)

    def test_gold_refresh_g_regenerated_stage_stamp_with_different_bytes_refuses(self):
        with self._stage_stamp_case(b"different", optin=True) as (fixture, stamp, environment):
            with self.assertRaisesRegex(ValueError, "completed golden inputs differ"):
                self._reuse_stamp(fixture, stamp, environment)

    def test_gold_refresh_h_regenerated_stage_stamp_without_optin_keeps_refusal(self):
        with self._stage_stamp_case(b"same", optin=False) as (fixture, stamp, environment):
            with self.assertRaisesRegex(ValueError, "stale or malformed"):
                self._reuse_stamp(fixture, stamp, environment)
            self.assertFalse((fixture.current / "NativePhaseReuseRetired").exists())

    def test_prior_record_uses_current_sidecar_before_prior_sidecar(self):
        with self._completed_fixture(bound=False, prior_record=True) as fixture:
            GOLDEN.retain_document(fixture.sidecar, self._binding(fixture))
            GOLDEN.retain_document(fixture.prior / fixture.sidecar.name, self._binding(fixture, tools="different"))
            fixture.probe.side_effect = AssertionError("current sidecar must avoid probes")
            self.assertTrue(fixture.reuse())
            self.assertEqual((fixture.current / fixture.record.name).read_bytes(), fixture.record.read_bytes())

    def test_prior_sidecar_is_copied_with_identical_bytes(self):
        with self._completed_fixture(bound=False, prior_record=True) as fixture:
            prior_sidecar = fixture.prior / fixture.sidecar.name
            encoded = json.dumps(self._binding(fixture), indent=2).encode() + b"\n"
            prior_sidecar.write_bytes(encoded)
            prior_sidecar.chmod(0o400)
            fixture.probe.side_effect = AssertionError("prior sidecar must avoid probes")
            self.assertTrue(fixture.reuse())
            self.assertEqual(fixture.sidecar.read_bytes(), encoded)
            self.assertEqual(fixture.sidecar.stat().st_mode & 0o777, 0o400)

    def test_tool_identity_uses_exact_five_paths_and_shared_view_root(self):
        developer, sdk, view = Path("/selected/Developer"), Path("/selected/SDK"), Path("/shared.noindex/view")
        cache = types.SimpleNamespace(roots=mock.Mock(return_value=(Path("/cache"), view)),
                                      external_identity=mock.Mock(return_value="tools"))
        with mock.patch.dict(sys.modules, {"dev_dependency_cache": cache}):
            self.assertEqual(GOLDEN.tool_identity(developer, sdk), "tools")
        cache.external_identity.assert_called_once_with([
            ("clang", str(developer / "Toolchains/XcodeDefault.xctoolchain/usr/bin/clang++")),
            ("swiftc", str(developer / "Toolchains/XcodeDefault.xctoolchain/usr/bin/swiftc")),
            ("lipo", str(developer / "Toolchains/XcodeDefault.xctoolchain/usr/bin/lipo")),
            ("xcode-version", str(developer.parent / "version.plist")),
            ("sdk-settings", str(sdk / "SDKSettings.plist"))], view)
        arguments = cache.roots.call_args.args[0]
        self.assertIsNone(arguments.cache_root)
        self.assertIsNone(arguments.view_root)

    def test_probe_toolchain_preserves_shell_trailing_whitespace(self):
        outputs = [b"Xcode 27.0  \nBuild version 18A1\t\n\n", b"27.0  \n\n", b"18A2\t\n",
                   b"Apple Swift version 6.3 (swiftlang)\nTarget: arm64-apple-macosx27.0  \n\n"]
        developer, sdk = Path("/selected/Developer"), Path("/selected/SDK")
        with mock.patch.object(GOLDEN.subprocess, "run", side_effect=[types.SimpleNamespace(stdout=out) for out in outputs]) as run:
            self.assertEqual(GOLDEN.probe_toolchain(developer, sdk), {
                "xcodeVersion": "27.0  ", "xcodeBuild": "18A1\t", "sdkVersion": "27.0  ",
                "sdkBuild": "18A2\t", "swiftCompilerVersion": "6.3", "swiftTargetTriple": "arm64-apple-macosx27.0  "})
        self.assertEqual([call.args[0] for call in run.call_args_list], [
            [str(developer / "usr/bin/xcodebuild"), "-version"],
            [str(developer / "usr/bin/xcodebuild"), "-version", "-sdk", str(sdk), "SDKVersion"],
            [str(developer / "usr/bin/xcodebuild"), "-version", "-sdk", str(sdk), "ProductBuildVersion"],
            [str(developer / "Toolchains/XcodeDefault.xctoolchain/usr/bin/swiftc"), "--version"]])
        for call in run.call_args_list:
            self.assertEqual(call.kwargs["env"]["DEVELOPER_DIR"], str(developer))
            self.assertTrue(call.kwargs["check"])

    def test_existing_result_without_completion_receipt_refuses_repeat(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            result = root / "result.json"
            result.write_text('{"passed":true}')
            with mock.patch.object(GOLDEN, "receipt_root", return_value=root), \
                    mock.patch.object(GOLDEN, "prior_root", return_value=None):
                with self.assertRaisesRegex(ValueError, "refusing repeat"):
                    GOLDEN.reuse_completed(result, root, root, root / "stamp", {})

    def _record_with_missing_result(self, root):
        result = root / "result.json"
        GOLDEN.retain_document(GOLDEN.completed_path(root, result), {"result": {}, "toolchain": {}})
        self.assertFalse(result.exists())
        return result

    def test_completed_record_with_retired_result_returns_false_when_retiring(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            result = self._record_with_missing_result(root)
            with mock.patch.dict(os.environ, {"MACSCOPE_NATIVE_RETIRE_STALE_RECEIPTS": "1"}), \
                    mock.patch.object(GOLDEN, "receipt_root", return_value=root), \
                    mock.patch.object(GOLDEN, "prior_root", return_value=None):
                self.assertFalse(GOLDEN.reuse_completed(result, root, root, root / "stamp", {}))
            # The stale record leaves the current root, so the fresh run's capture can write it.
            self.assertFalse(GOLDEN.completed_path(root, result).exists())
            self.assertTrue(any((root / "NativePhaseReuseRetired").glob("*-golden-completed-*")))

    def test_completed_record_with_missing_result_refuses_without_retiring(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            result = self._record_with_missing_result(root)
            environment = {k: v for k, v in os.environ.items() if k != "MACSCOPE_NATIVE_RETIRE_STALE_RECEIPTS"}
            with mock.patch.dict(os.environ, environment, clear=True), \
                    mock.patch.object(GOLDEN, "receipt_root", return_value=root), \
                    mock.patch.object(GOLDEN, "prior_root", return_value=None):
                with self.assertRaisesRegex(ValueError, "result is missing"):
                    GOLDEN.reuse_completed(result, root, root, root / "stamp", {})


if __name__ == "__main__":
    unittest.main()
