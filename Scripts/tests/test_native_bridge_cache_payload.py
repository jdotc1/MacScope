#!/usr/bin/env python3
"""Path-free native bridge cache payload and its routine-Debug Xcode wiring (R11.2)."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "Scripts/native-decompiler-xpc/native_bridge_cache_payload.py"
DEV_TOOL = ROOT / "Scripts/qualification/dev_dependency_cache.py"
PROJECT = ROOT / "MacScope/project.yml"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


PAYLOAD = load("macscope_native_bridge_cache_payload_under_test", TOOL)
WRAPPER = "a" * 64


class NativeBridgeReceiptDigestTests(unittest.TestCase):
    def test_manifest_digest_uses_admitted_receipt_and_missing_receipt_never_rehashes(self) -> None:
        receipt = subprocess.CompletedProcess([], 0, stdout=json.dumps({"identity": {}, "manifest_sha256": "b" * 64}))
        with mock.patch.dict(os.environ, {"MACSCOPE_NATIVE_VERIFICATION_RECEIPT_MODE": "shared-view"}), \
             mock.patch.object(PAYLOAD, "sha256", side_effect=AssertionError("unchanged manifest rehashed")), \
             mock.patch.object(PAYLOAD.subprocess, "run", return_value=receipt) as admit:
            self.assertEqual(PAYLOAD.materialization_manifest_digest(ROOT, Path("/synthetic/materialization")), "b" * 64)
            self.assertIn("reuse-sleigh", admit.call_args.args[0])
            self.assertIn("--output-json", admit.call_args.args[0])
            admit.side_effect = subprocess.CalledProcessError(1, "reuse-sleigh")
            with self.assertRaises(subprocess.CalledProcessError):
                PAYLOAD.materialization_manifest_digest(ROOT, Path("/synthetic/materialization"))


@unittest.skipUnless(shutil.which("xcrun") and os.uname().machine == "arm64", "needs Xcode on arm64")
class NativeBridgeCachePayloadTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        # Deliberately outside /private/tmp-style markers is impossible on macOS;
        # the scan's generic markers are patched to the fixture's own roots.
        self.root = Path(self.temporary.name).resolve()
        self.build = self.root / "build"
        self.materialization = self.root / "materialization"
        (self.build / "generated/MacScopeNativeDecompiler").mkdir(parents=True)
        self.materialization.mkdir()
        manifest = self.materialization / "MATERIALIZATION.json"
        manifest.write_text('{"package":{}}\n')
        manifest_sha = PAYLOAD.sha256(manifest)
        source = self.root / "probe.c"
        source.write_text("int macscope_probe(void) { return 7; }\n")
        subprocess.run(["xcrun", "clang", "-arch", "arm64", "-c", str(source), "-o", str(self.root / "probe.o")],
                       check=True)
        subprocess.run(["xcrun", "ar", "rcs", str(self.build / PAYLOAD.ARCHIVE), str(self.root / "probe.o")],
                       check=True)
        (self.build / PAYLOAD.IDENTITY).write_text(
            f'inline constexpr std::string_view kRoot =\n    "";\n'
            f'inline constexpr std::string_view kManifest =\n    "{manifest_sha}";\n'
            f'inline constexpr std::string_view kWrapper =\n    "{WRAPPER}";\n'
        )
        (self.build / PAYLOAD.INSPECTION).write_text("file=Mach-O 64-bit executable arm64\n")
        (self.build / "CMakeCache.txt").write_text(
            f"CMAKE_HOME_DIRECTORY:INTERNAL={ROOT}/Tools/NativeDecompilerBridge\n"
            f"MACSCOPE_SLEIGH_MATERIALIZATION_ROOT:PATH={self.materialization}\n"
            "CMAKE_OSX_ARCHITECTURES:STRING=arm64\n"
            "CMAKE_OSX_DEPLOYMENT_TARGET:STRING=27.0\n"
            "MACSCOPE_ENABLE_GHIDRA_PROVIDER:BOOL=ON\n"
            "MACSCOPE_GHIDRA_PROVIDER_RELOCATABLE_MATERIALIZATION:BOOL=ON\n"
            f"MACSCOPE_NATIVE_DECOMPILER_WRAPPER_GIT_REVISION:STRING={WRAPPER}\n"
        )
        (self.build / PAYLOAD.LINK_INPUTS).write_text(f"{self.build}/{PAYLOAD.ARCHIVE}\n")
        patches = [
            mock.patch.object(PAYLOAD, "wrapper_revision", return_value=WRAPPER),
            mock.patch.object(PAYLOAD, "FORBIDDEN_MARKERS", (b"/Users\x2f", b"/home/", b"DerivedData", b".noindex")),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.addCleanup(self.temporary.cleanup)

    def test_extract_keeps_absolute_cmake_and_link_input_paths_out_of_the_payload(self) -> None:
        payload = self.root / "payload"
        PAYLOAD.extract(self.build, payload, ROOT, self.materialization)
        files = sorted(p.relative_to(payload).as_posix() for p in payload.rglob("*") if p.is_file())
        self.assertEqual(files, sorted(PAYLOAD.PAYLOAD_FILES))
        self.assertNotIn("CMakeCache.txt", files)
        self.assertNotIn(PAYLOAD.LINK_INPUTS, files)
        for relative in files:
            data = (payload / relative).read_bytes()
            self.assertNotIn(os.fsencode(str(self.root)), data)
            self.assertNotIn(os.fsencode(str(ROOT)), data)
        configuration = json.loads((payload / PAYLOAD.CONFIGURATION).read_bytes())
        self.assertEqual(configuration["wrapper_revision"], WRAPPER)

    def test_a_local_path_in_a_payload_file_is_refused(self) -> None:
        (self.build / PAYLOAD.INSPECTION).write_text(f"probe={self.build}/probe\n")
        with self.assertRaises(PAYLOAD.PayloadError):
            PAYLOAD.extract(self.build, self.root / "payload", ROOT, self.materialization)

    def test_a_different_sleigh_manifest_or_wrapper_fails_verification(self) -> None:
        payload = self.root / "payload"
        PAYLOAD.extract(self.build, payload, ROOT, self.materialization)
        (self.materialization / "MATERIALIZATION.json").write_text('{"package":{"other":1}}\n')
        with self.assertRaises(PAYLOAD.PayloadError):
            PAYLOAD.verify(payload, ROOT, self.materialization)

    def test_stage_accepts_the_sdk_zlib_symlink_but_not_one_leaving_the_sdk(self) -> None:
        # Xcode SDKs ship usr/lib/libz.tbd as a symlink to libz.1.tbd.
        payload = self.root / "payload"
        PAYLOAD.extract(self.build, payload, ROOT, self.materialization)
        sdk = self.root / "sdk"
        (sdk / "usr/lib").mkdir(parents=True)
        (sdk / "usr/lib/libz.1.tbd").write_text("--- !tapi-tbd\n")
        (sdk / "usr/lib/libz.tbd").symlink_to("libz.1.tbd")
        consumer = self.root / "consumer"
        PAYLOAD.stage(payload, consumer, ROOT, self.materialization, sdk)
        self.assertEqual((consumer / PAYLOAD.LINK_INPUTS).read_text().splitlines()[-1], str(sdk / "usr/lib/libz.tbd"))
        outside = self.root / "outside.tbd"
        outside.write_text("--- !tapi-tbd\n")
        (sdk / "usr/lib/libz.tbd").unlink()
        (sdk / "usr/lib/libz.tbd").symlink_to(outside)
        with self.assertRaises(PAYLOAD.PayloadError):
            PAYLOAD.stage(payload, self.root / "consumer2", ROOT, self.materialization, sdk)

    def test_stage_regenerates_local_cmake_projection_and_link_inputs_then_clears_for_local_builds(self) -> None:
        payload = self.root / "payload"
        PAYLOAD.extract(self.build, payload, ROOT, self.materialization)
        consumer = self.root / "consumer"
        sdk = self.root / "sdk"
        (sdk / "usr/lib").mkdir(parents=True)
        (sdk / "usr/lib/libz.tbd").write_text("--- !tapi-tbd\n")
        PAYLOAD.stage(payload, consumer, ROOT, self.materialization, sdk)
        cache = (consumer / "CMakeCache.txt").read_text()
        self.assertTrue(cache.startswith(PAYLOAD.PROJECTION_MARKER))
        # The golden check's exact anchored greps.
        for line in ("CMAKE_OSX_ARCHITECTURES:STRING=arm64", "CMAKE_OSX_DEPLOYMENT_TARGET:STRING=27.0",
                     "MACSCOPE_ENABLE_GHIDRA_PROVIDER:BOOL=ON",
                     "MACSCOPE_GHIDRA_PROVIDER_RELOCATABLE_MATERIALIZATION:BOOL=ON",
                     f"MACSCOPE_NATIVE_DECOMPILER_WRAPPER_GIT_REVISION:STRING={WRAPPER}"):
            self.assertIn(line + "\n", cache)
        for relative in (PAYLOAD.ARCHIVE, PAYLOAD.IDENTITY):
            self.assertEqual((consumer / relative).lstat().st_nlink, 1)
        self.assertEqual(
            (consumer / PAYLOAD.LINK_INPUTS).read_text().splitlines(),
            [str(consumer / PAYLOAD.ARCHIVE), str(self.materialization / "package/lib/libdecomp.a"),
             str(self.materialization / "package/lib/libsla.a"), str(sdk / "usr/lib/libz.tbd")],
        )
        mtime = (consumer / PAYLOAD.ARCHIVE).stat().st_mtime_ns
        PAYLOAD.stage(payload, consumer, ROOT, self.materialization, sdk)
        self.assertEqual((consumer / PAYLOAD.ARCHIVE).stat().st_mtime_ns, mtime, "unchanged stage must not relink")
        PAYLOAD.clear_projection(consumer)
        self.assertFalse((consumer / "CMakeCache.txt").exists())
        PAYLOAD.clear_projection(self.build)
        self.assertTrue((self.build / "CMakeCache.txt").exists(), "a real CMake cache is never removed")


class NativeBridgeCacheWiringTests(unittest.TestCase):
    def test_component_is_developer_only_and_keyed_by_wrapper_sleigh_and_toolchain(self) -> None:
        dev = load("macscope_dev_dependency_cache_bridge_under_test", DEV_TOOL)
        spec = dev.COMPONENTS["native-bridge"]
        self.assertNotIn("native-bridge", dev.QUALIFIER_COMPONENTS)
        identity = load("macscope_native_identity_under_test",
                        ROOT / "Scripts/native-decompiler-xpc/native_decompiler_source_identity.py")
        wrapper_inputs = set(identity.WRAPPER_FIXED) | set(identity.WRAPPER_TREES)
        self.assertTrue(wrapper_inputs.issubset(set(spec["prefixes"])))
        values = dict(spec["values"])
        self.assertEqual(values["sleigh-native-source"], "@SLEIGH_KEY@")
        self.assertEqual(values["platform-toolchain"], "@PLATFORM@")
        self.assertEqual(values["native-tools"], "@NATIVE_TOOLS@")

    def test_xcode_phase_uses_existing_cache_for_routine_debug_and_fails_closed(self) -> None:
        project = PROJECT.read_text(encoding="utf-8")
        start = project.index("- name: Build verified native decompiler bridge")
        phase = project[start:project.index("- name: Stage verified native decompiler package", start)]
        gate = phase.index('[ "${CONFIGURATION:-}" = Debug ] && [ "${MACSCOPE_DEBUG_SOURCE_IDENTITY:-}" = runtime-only ]')
        resolve = phase.index("resolve --no-build --component native-bridge")
        local = phase.index('"$SRCROOT/../Scripts/native-decompiler-xpc/build_native_bridge.sh"')
        self.assertLess(gate, resolve)
        self.assertLess(resolve, local)
        refusal = phase.index('echo "ERROR: shared dependency cache rejected the native decompiler bridge"')
        self.assertLess(resolve, refusal)
        self.assertLess(refusal, local)
        self.assertIn('exit 1', phase[refusal:phase.index('clear-projection')])
        self.assertLess(phase.index('abandon --phase bridge'), refusal)
        self.assertLess(phase.index("clear-projection"), local)
        self.assertIn("--configuration Release", phase[local:])

        # Execute the actual extracted phase with synthetic dispatchers. No
        # repository Python helper, native producer, SDK or payload is invoked.
        script = textwrap.dedent(phase.split('script: |\n', 1)[1])
        script = script.replace('/usr/bin/python3 -B', 'python_stub')
        script = script.replace('"$SRCROOT/../Scripts/native-decompiler-xpc/build_native_bridge.sh"',
                                'producer_stub')
        stubs = r'''
python_stub() {
  case "$1" in
    */native_phase_reuse.py)
      printf 'reuse-%s\n' "$2" >> "$CALLS"
      if [ "$2" = check ]; then return 3; fi
      return 0 ;;
    */dev_dependency_cache.py)
      printf 'resolve\n' >> "$CALLS"
      printf 'MACSCOPE_NATIVE_DECOMPILER_CACHED_VIEW=/synthetic/view\n'
      return "$CACHE_STATUS" ;;
    */native_bridge_cache_payload.py)
      printf 'payload-%s\n' "$2" >> "$CALLS"
      return 0 ;;
    *) printf 'unexpected-helper\n' >> "$CALLS"; return 99 ;;
  esac
}
producer_stub() { printf 'PRODUCER\n' >> "$CALLS"; return 98; }
'''
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'MacScope').mkdir()
            for status in (0, 3, 7):
                with self.subTest(cache_status=status):
                    calls = root / f'calls-{status}'
                    env = dict(os.environ, SRCROOT=str(root / 'MacScope'),
                               CONFIGURATION='Debug', MACSCOPE_DEBUG_SOURCE_IDENTITY='runtime-only',
                               MACSCOPE_NATIVE_RELEASE_ADMISSION='',
                               MACSCOPE_SLEIGH_MATERIALIZATION_ROOT='/synthetic/materialization',
                               MACSCOPE_NATIVE_DECOMPILER_BUILD_ROOT='/synthetic/build',
                               SDKROOT='/synthetic/sdk', CALLS=str(calls), CACHE_STATUS=str(status))
                    result = subprocess.run(['/bin/bash', '-c', stubs + script], env=env,
                                            capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode, 0 if status == 0 else 1, result.stderr)
                    self.assertEqual(calls.read_text().splitlines(),
                                     ['reuse-check', 'resolve', 'payload-stage', 'reuse-record']
                                     if status == 0 else ['reuse-check', 'resolve', 'reuse-abandon'])
                    if status:
                        self.assertIn('shared dependency cache rejected', result.stderr)


if __name__ == "__main__":
    unittest.main()
