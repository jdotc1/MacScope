#!/usr/bin/env python3
"""Fake-child coverage only. Never launches Xcode or acquires the real gate."""
import importlib.util
import errno
import json
import io
import os
from pathlib import Path
import signal
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).resolve().parents[1] / "child_selector_host.py"
SPEC = importlib.util.spec_from_file_location("child_selector_host", SCRIPT)
host = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(host)


class ChildSelectorHostTests(unittest.TestCase):
    def run_child(self, source, *, timeout=3, grace=0.15):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            run = root / "run"
            record = host.supervise(
                [sys.executable, "-u", "-c", source], environment={}, work_root=root,
                run_root=run, candidate="a" * 40, selector="CoreTests/FakeTests",
                result=run / "result.xcresult", timeout=timeout, grace=grace)
            self.assertEqual(record, json.loads((run / "run.json").read_text()))
            self.assertEqual(record["pid"], record["pgid"])
            self.assertEqual(record["parent_pid"], os.getpid())
            self.assertEqual(record["candidate_sha"], "a" * 40)
            self.assertEqual(record["selector"], "CoreTests/FakeTests")
            self.assertTrue(record["nonce"])
            return record, (run / "stdout.log").read_text(), (run / "stderr.log").read_text()

    def test_records_exact_exit_separate_streams_and_phase_order(self):
        record, out, err = self.run_child(
            "import sys,time; print(\"Test Suite 'FakeTests' started\"); "
            "print('diagnostic',file=sys.stderr); time.sleep(.02); "
            "print(\"Test Suite 'FakeTests' passed\"); sys.exit(7)")
        self.assertEqual(record["returncode"], 7)
        self.assertEqual(record["exit_code"], 7)
        self.assertIsNone(record["signal"])
        self.assertFalse(record["timed_out"])
        self.assertIn("started", out)
        self.assertNotIn("diagnostic", out)
        self.assertEqual(err, "diagnostic\n")
        times = [record["phases"][name] for name in
                 ("spawn", "first-output", "test-start", "test-end", "exit")]
        self.assertEqual(times, sorted(times))
        self.assertLessEqual(record["parent_start_monotonic"], times[0])

    def test_records_child_signal_without_mapping_it_to_exit_code(self):
        record, _, _ = self.run_child("import os,signal; os.kill(os.getpid(),signal.SIGTERM)")
        self.assertEqual(record["returncode"], -signal.SIGTERM)
        self.assertEqual(record["signal"], signal.SIGTERM)
        self.assertIsNone(record["exit_code"])
        self.assertIsNone(record["phases"]["test-start"])

    def test_timeout_escalates_owned_group_and_waits_for_exit(self):
        record, out, _ = self.run_child(
            "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); "
            "print('ready'); time.sleep(30)", timeout=0.5)
        self.assertEqual(out, "ready\n")
        self.assertTrue(record["timed_out"])
        self.assertEqual(record["signals_sent"], ["SIGTERM", "SIGKILL"])
        self.assertEqual(record["signal"], signal.SIGKILL)
        self.assertIsNotNone(record["phases"]["exit"])
        with self.assertRaises(ProcessLookupError):
            os.kill(record["pid"], 0)

    def test_timeout_accepts_term_exit_without_kill(self):
        record, _, _ = self.run_child("import time; time.sleep(30)", timeout=0.25)
        self.assertTrue(record["timed_out"])
        self.assertEqual(record["signals_sent"], ["SIGTERM"])
        self.assertEqual(record["signal"], signal.SIGTERM)

    def test_unreaped_leader_reserves_group_until_last_signal_and_drain_is_bounded(self):
        # A parent-held writer models a pipe retained by an escaped descendant,
        # without leaving an actual background process behind after the test.
        original_popen = host.subprocess.Popen
        original_killpg = os.killpg
        children = []
        held_writers = []
        signals = []

        def launch(*args, **kwargs):
            read_fd, write_fd = os.pipe()
            held_writers.append(write_fd)
            kwargs["stdout"] = write_fd
            child = original_popen(*args, **kwargs)
            child.stdout = os.fdopen(read_fd, "rb")
            child.poll = lambda: self.fail("poll must not reap before the signal boundary")
            children.append(child)
            return child

        def send(group, sent_signal):
            self.assertEqual(group, children[0].pid)
            self.assertIsNone(children[0].returncode, "never signal after reaping")
            signals.append(sent_signal)
            return original_killpg(group, sent_signal)

        started = time.monotonic()
        try:
            with patch.object(host.subprocess, "Popen", side_effect=launch), \
                 patch.object(host.os, "killpg", side_effect=send):
                record, _, _ = self.run_child("pass", timeout=0.15, grace=0.1)
        finally:
            for descriptor in held_writers:
                os.close(descriptor)
        self.assertEqual(signals, [signal.SIGTERM, signal.SIGKILL])
        self.assertEqual(record["exit_code"], 0)
        self.assertTrue(record["timed_out"])
        self.assertFalse(record["output_complete"])
        self.assertEqual(record["unresolved_output_channels"], ["stdout"])
        self.assertLess(time.monotonic() - started, 2)

    def test_unsignalable_outcomes_preserve_errno_without_claiming_exit(self):
        for error_number in (errno.EPERM, errno.ESRCH):
            with self.subTest(errno=error_number):
                process = type("Owned", (), {"pid": 12345, "returncode": None})()
                record = {"signals_sent": [], "signal_attempts": [], "returncode": None}
                with patch.object(host.os, "killpg", side_effect=OSError(error_number, "injected")):
                    host.signal_owned_group(process, signal.SIGKILL, record, lambda: None)
                self.assertEqual(record["signals_sent"], ["SIGKILL"])
                self.assertEqual(record["signal_attempts"][0]["errno"], error_number)
                self.assertEqual(record["signal_attempts"][0]["outcome"], "unsignalable")
                self.assertIsNone(record["returncode"])
                self.assertIsNone(process.returncode)

    def test_unconfirmed_exit_quarantines_owner_until_actual_wait_without_signaling(self):
        process = unittest.mock.Mock()
        process.pid = 12345
        process.wait.side_effect = [host.subprocess.TimeoutExpired("fake", 0.1), 0]
        record = {"returncode": None, "owner_quarantined": False}
        snapshots = []
        with patch.object(host.os, "killpg", side_effect=AssertionError("no signals in quarantine")), \
             patch.object(host.sys, "stderr", new_callable=io.StringIO) as status_output:
            result = host.wait_after_final_signal(
                process, record, lambda: snapshots.append(dict(record)), 0.1)
        self.assertEqual(result, 0)
        self.assertTrue(record["owner_quarantined"])
        self.assertEqual(record["owner_state"], "exited_after_quarantine")
        self.assertEqual(snapshots[0]["owner_state"], "owner_quarantined")
        self.assertIsNone(snapshots[0]["returncode"])
        self.assertEqual(process.wait.call_args_list,
                         [unittest.mock.call(timeout=0.1), unittest.mock.call()])
        self.assertIn("OWNER QUARANTINED pid=12345 pgid=12345", status_output.getvalue())

    def test_closed_pipes_do_not_bypass_child_exit_timeout(self):
        record, _, _ = self.run_child(
            "import os,time; os.close(1); os.close(2); time.sleep(30)", timeout=0.25)
        self.assertTrue(record["timed_out"])
        self.assertEqual(record["signal"], signal.SIGTERM)
        self.assertTrue(record["output_complete"])

    def test_fixed_command_has_one_selector_and_no_build_or_derived_data(self):
        command = host.selector_command(Path("/retained/a.xctestrun"),
                                        "CoreTests/FakeTests/testExample", Path("/run/result.xcresult"))
        self.assertEqual(sum(item.startswith("-only-testing:") for item in command), 1)
        self.assertIn("test-without-building", command)
        self.assertNotIn("build-for-testing", command)
        self.assertNotIn("-derivedDataPath", command)
        for invalid in ("", "CoreTests", "-only-testing:CoreTests/X", "CoreTests/X CoreTests/Y"):
            with self.assertRaises(ValueError):
                host.selector_command(Path("/a"), invalid, Path("/r"))

    def test_environment_is_explicit_and_never_copies_ambient_values(self):
        with patch.dict(os.environ, {"HOST_SECRET": "private", "DEVELOPER_DIR": "/wrong"}):
            environment = host.named_environment(Path("/Xcode/Contents/Developer"), ["HOME=/home"])
        self.assertEqual(environment, {"DEVELOPER_DIR": "/Xcode/Contents/Developer", "HOME": "/home"})
        with self.assertRaises(ValueError):
            host.named_environment(Path("/Xcode"), ["DEVELOPER_DIR=/other"])

    def test_gate_delegates_to_existing_helper_and_releases_descriptor(self):
        # Exercise helper delegation against a fake module, without taking a lock.
        calls = []
        class FakeGate:
            @staticmethod
            def acquire_command(arguments):
                calls.append(("acquire", arguments))
                return 0
            @staticmethod
            def release_command(arguments):
                calls.append(("release", arguments))
        specification = type("Spec", (), {"loader": type("Loader", (), {
            "exec_module": staticmethod(lambda module: None)})()})()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(host.importlib.util, "spec_from_file_location", return_value=specification), \
                 patch.object(host.importlib.util, "module_from_spec", return_value=FakeGate):
                with host.heavy_gate(root / "lock", root, root, "a" * 40, 10):
                    descriptor = calls[0][1].fd
                    os.fstat(descriptor)
            self.assertEqual([call[0] for call in calls], ["acquire", "release"])
            self.assertFalse(calls[0][1].shared)
            with self.assertRaises(OSError):
                os.fstat(descriptor)


class ChildSelectorProfileTests(unittest.TestCase):
    def test_named_profiles_preserve_stack_and_phase_evidence(self):
        manifest = SCRIPT.with_name("child_selector_profiles.json")
        a54 = host.load_profile(manifest, "a54-headroom")
        s2 = host.load_profile(manifest, "s2-phase-timing")
        self.assertEqual(a54["selector"], "CoreTests/OperationCoreStackHeadroomTests")
        self.assertEqual(a54["evidence"]["expected_usable_stack_bytes"], 512 * 1024)
        self.assertEqual((a54["timeout"], a54["grace"]), (120, 10))
        self.assertEqual((s2["timeout"], s2["grace"]), (1500, 30))
        self.assertEqual(s2["selector"], "CoreTests/MacIRCFGTests/testLibjpegExplicitGraphAcceptanceAndExport")
        self.assertEqual(s2["test_execution_allowance"], 1200)
        self.assertEqual(s2["evidence"]["identity_binding"], ["nonce", "candidate_sha", "selector"])
        self.assertEqual(s2["evidence"]["phases"],
                         ["spawn", "first-output", "test-start", "test-end", "exit"])
        for profile in (a54, s2):
            self.assertEqual(profile["developer_dir"], host.system_default_developer_dir())
            self.assertEqual(profile["result_path"], "{run_root}/result.xcresult")

    def test_pending_budget_or_operation_refuses_before_build_product_lookup(self):
        profile = host.load_profile(SCRIPT.with_name("child_selector_profiles.json"), "a54-headroom")
        for field in ("selector", "timeout", "grace"):
            pending = dict(profile, selector="CoreTests/FakeTests", timeout=1, grace=1)
            pending[field] = None
            with patch.object(Path, "glob", side_effect=AssertionError("must not inspect retained products")):
                with self.assertRaisesRegex(ValueError, "requires Plan decisions"):
                    host.resolve_profile(pending, Path("/fake/run"))

    def test_fake_retained_profile_resolves_one_selector_without_launching_child(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            products = root / "Build/Products"
            products.mkdir(parents=True)
            retained = products / "CoreTests_fake.xctestrun"
            retained.write_text("fake retained descriptor, never executed")
            profile = host.load_profile(SCRIPT.with_name("child_selector_profiles.json"), "a54-headroom")
            profile.update(retained_root=str(root), selector="CoreTests/FakeTests", timeout=1, grace=0.1)
            with patch.object(host.subprocess, "Popen", side_effect=AssertionError("parsing must not spawn")):
                settings = host.resolve_profile(profile, root / "run")
            self.assertEqual(settings["xctestrun"], retained)
            self.assertEqual(settings["selector"], "CoreTests/FakeTests")
            self.assertEqual(settings["result"], root / "run/result.xcresult")
            s2 = host.load_profile(SCRIPT.with_name("child_selector_profiles.json"), "s2-phase-timing")
            s2["retained_root"] = str(root)
            settings = host.resolve_profile(s2, root / "run", "a" * 40)
            self.assertIn("TEST_RUNNER_MACSCOPE_CFG_OUT=" + str(root / "run/witness"), settings["env"])
            self.assertIn("TEST_RUNNER_MACSCOPE_WITNESS_SOURCE_HEAD=" + "a" * 40, settings["env"])
            command = host.selector_command(settings["xctestrun"], settings["selector"],
                                            settings["result"], settings["test_execution_allowance"])
            self.assertEqual(command[command.index("-maximum-test-execution-time-allowance") + 1], "1200")
            self.assertNotIn("1500", command)  # Outer host bound is separate.
            (products / "CoreTests_second.xctestrun").write_text("fake second descriptor")
            with self.assertRaisesRegex(ValueError, "exactly one"):
                host.resolve_profile(profile, root / "run")

    def test_profile_rejects_unknown_name_unsafe_pattern_and_invalid_budget(self):
        manifest = SCRIPT.with_name("child_selector_profiles.json")
        with self.assertRaisesRegex(ValueError, "unknown selector profile"):
            host.load_profile(manifest, "unknown")
        source = json.loads(manifest.read_text())
        for field, value in (("xctestrun_pattern", "../outside.xctestrun"),
                             ("xctestrun_pattern", "**/*.xctestrun"),
                             ("result_path", "/outside/result.xcresult"),
                             ("timeout", -1), ("grace", True)):
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as directory:
                modified = json.loads(json.dumps(source))
                modified["profiles"]["a54-headroom"][field] = value
                fake = Path(directory) / "profiles.json"
                fake.write_text(json.dumps(modified))
                with self.assertRaises(ValueError):
                    host.load_profile(fake, "a54-headroom")


class ChildSelectorCallerContractTests(unittest.TestCase):
    def diagnostic(self, *, run_root_exists, gate_timeout):
        argv = [str(SCRIPT), "--work-root", "/fake/work", "--retained-root", "/fake/retained",
                "--xctestrun", "/fake/retained/CoreTests.xctestrun", "--run-root", "/fake/output",
                "--developer-dir", "/fake/Xcode", "--candidate-sha", "a" * 40,
                "--selector", "CoreTests/FakeTests", "--timeout", "1",
                "--gate-timeout", str(gate_timeout)]
        with patch.object(host.sys, "argv", argv), \
             patch.object(host.sys, "stderr", new_callable=io.StringIO) as stderr, \
             patch.object(Path, "is_dir", return_value=True), \
             patch.object(Path, "is_file", return_value=True), \
             patch.object(Path, "resolve", return_value=Path("/fake")), \
             patch.object(Path, "exists", return_value=run_root_exists), \
             patch.object(host, "heavy_gate", side_effect=AssertionError("invalid caller must not acquire gate")), \
             patch.object(host.subprocess, "Popen", side_effect=AssertionError("invalid caller must not spawn")):
            with self.assertRaises(SystemExit) as stopped:
                host.main()
            self.assertEqual(stopped.exception.code, 2)
            return stderr.getvalue()

    def test_existing_run_root_names_only_the_run_root_contract(self):
        diagnostic = self.diagnostic(run_root_exists=True, gate_timeout=1800)
        self.assertIn("error: run root must not exist; write host logs outside the run root", diagnostic)
        self.assertNotIn("gate timeout must be nonnegative", diagnostic)

    def test_negative_gate_timeout_names_only_the_timeout_contract(self):
        diagnostic = self.diagnostic(run_root_exists=False, gate_timeout=-1)
        self.assertIn("error: gate timeout must be nonnegative", diagnostic)
        self.assertNotIn("run root must not exist", diagnostic)


if __name__ == "__main__":
    unittest.main()
