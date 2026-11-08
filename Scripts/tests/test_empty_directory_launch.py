"""Item 1271: one real subprocess launch and one independent positive control.

Authored, NOT RUN. A skip or NOT RUN proves nothing about an installed app.
The parent reads MACSCOPE_BINARY; the child receives no MACSCOPE_* variable
(even MACSCOPE_BINARY is unnecessary once argv[0] is resolved), and no
LLVM_PROFILE_FILE. The supplied live-gate injection/proxy denylist is also
removed, case-insensitively. No profile destination is set or redirected.

Observable: entries left in the actual launch cwd by the process/session.
Not observable: sandbox/container relocation or denied writes, instrumentation
provenance, writes outside cwd, or other binaries/build configurations.
Potential sources are sandbox/container policy; MacScopeApp's coverage-gathering
test scheme; ENABLE_CODE_COVERAGE overrides and CLANG_COVERAGE_MAPPING; reused
full-test products or an older instrumented install. The other three
supplied schemes do not declare gatherCoverageData. See REVIEW.md, SPEC 3.
Only an owner-selected genuine post-landing app can support real-app evidence;
Mach-O structure and protocol replies are not proof of binary provenance.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

TARGET_BINARY = None
MACHO_MAGIC = {
    b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca",
    b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
}


def assert_empty_directory(directory):
    entries = sorted(path.name for path in directory.iterdir())
    if entries:
        raise AssertionError(f"launch directory is not empty: {entries!r}")
    return entries


def unsafe_environment_key(key):
    normalized = key.upper()
    return ("DYLD_" in normalized or normalized.startswith("MACSCOPE_")
            or "XCTEST" in normalized or "XCINJECTBUNDLEINTO" in normalized
            or normalized == "LLVM_PROFILE_FILE"
            or normalized in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"})


def scrub_environment(environment):
    return {key: value for key, value in environment.items()
            if not unsafe_environment_key(key)}


def require_macho(path):
    with path.open("rb") as stream:
        if stream.read(4) not in MACHO_MAGIC:
            raise AssertionError(f"not a Mach-O executable (script/stub refused): {path}")


class RPC:
    """Bounded newline JSON-RPC; a single total deadline includes readiness."""
    def __init__(self, proc, seconds=300):
        self.proc = proc
        self.deadline = time.monotonic() + seconds
        self.buffer = bytearray()
        self.next_id = 0
        os.set_blocking(proc.stdout.fileno(), False)
        os.set_blocking(proc.stdin.fileno(), False)

    def wait(self, stream, event):
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise AssertionError("MCP startup/readiness deadline expired")
        with selectors.DefaultSelector() as selector:
            selector.register(stream, event)
            if not selector.select(remaining):
                raise AssertionError("MCP startup/readiness deadline expired")

    def send(self, message):
        data = memoryview((json.dumps(message, allow_nan=False) + "\n").encode())
        while data:
            self.wait(self.proc.stdin, selectors.EVENT_WRITE)
            try:
                count = os.write(self.proc.stdin.fileno(), data)
            except BlockingIOError:
                continue
            if count == 0:
                raise AssertionError("MCP stdin accepted no bytes")
            data = data[count:]

    def line(self):
        while True:
            if time.monotonic() >= self.deadline:
                raise AssertionError("MCP startup/readiness deadline expired")
            newline = self.buffer.find(b"\n")
            if newline >= 0:
                if newline > 1024 * 1024:
                    raise AssertionError("MCP response exceeded one MiB")
                line = bytes(self.buffer[:newline])
                del self.buffer[:newline + 1]
                return line
            if len(self.buffer) > 1024 * 1024:
                raise AssertionError("MCP response exceeded one MiB")
            self.wait(self.proc.stdout, selectors.EVENT_READ)
            try:
                chunk = os.read(self.proc.stdout.fileno(), 65536)
            except BlockingIOError:
                continue
            if not chunk:
                raise AssertionError("MCP child exited/closed stdout before answering")
            self.buffer.extend(chunk)

    def request(self, method, params=None):
        self.next_id += 1
        message = {"jsonrpc": "2.0", "id": self.next_id, "method": method}
        if params is not None:
            message["params"] = params
        self.send(message)
        while True:
            raw = self.line()
            try:
                reply = json.loads(raw)
            except (ValueError, UnicodeDecodeError):
                continue
            if not isinstance(reply, dict):
                continue
            if reply.get("id") is None and "error" in reply:
                raise AssertionError(f"MCP unattributed error: {reply['error']!r}")
            if reply.get("id") != self.next_id:
                continue
            if reply.get("jsonrpc") != "2.0" or "error" in reply or "result" not in reply:
                raise AssertionError(f"MCP request failed: {reply!r}")
            return reply["result"]

    def ready(self):
        initial = self.request("initialize", {
            "protocolVersion": "2025-06-18", "capabilities": {},
            "clientInfo": {"name": "macscope-python", "version": "0.1.0"},
        })
        if not isinstance(initial, dict):
            raise AssertionError("initialize did not return an object")
        capabilities = initial.get("capabilities", {})
        experimental = capabilities.get("experimental", {}) if isinstance(capabilities, dict) else {}
        if not isinstance(experimental, dict) or not isinstance(experimental.get("macscope/analysis"), dict):
            raise AssertionError("initialize did not advertise MacScope analysis readiness")
        self.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        while True:
            result = self.request("tools/call", {
                "name": "info", "arguments": {"waitForReadyMs": 1000},
            })
            if not isinstance(result, dict) or result.get("isError"):
                raise AssertionError(f"info failed: {result!r}")
            if "structuredContent" in result:
                value = result["structuredContent"]
                if not isinstance(value, dict):
                    raise AssertionError("info returned invalid structured content")
                metadata = result.get("_meta")
                if isinstance(metadata, dict) and metadata.get("macscope/resultWrapper") == "result":
                    if set(value) != {"result"}:
                        raise AssertionError("info returned an invalid result wrapper")
                    value = value["result"]
            else:
                content = result.get("content")
                first = content[0] if isinstance(content, list) and content else None
                if not isinstance(first, dict) or not isinstance(first.get("text"), str):
                    raise AssertionError("info returned no JSON text content")
                value = json.loads(first["text"])
            analysis = value.get("analysis") if isinstance(value, dict) else None
            if not isinstance(analysis, dict):
                raise AssertionError("info returned no analysis state")
            if analysis.get("state") == "ready":
                return
            if analysis.get("state") != "analyzing":
                raise AssertionError(f"analysis did not become ready: {analysis!r}")


def stop_and_reap(proc):
    """EOF permits normal profile flushing; forced termination cannot pass."""
    forced = False
    try:
        proc.stdin.close()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            forced = True
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
    finally:
        proc.stdout.close()
    return proc.returncode, forced


class EmptyDirectoryLaunchTests(unittest.TestCase):
    def test_positive_control_detects_profile_entry(self):
        with tempfile.TemporaryDirectory(prefix="macscope-p5-control-") as name:
            directory = Path(name)
            self.assertEqual(assert_empty_directory(directory), [])
            (directory / "default.profraw").write_bytes(b"positive control\n")
            with self.assertRaises(AssertionError) as caught:
                assert_empty_directory(directory)
            self.assertEqual(str(caught.exception),
                             "launch directory is not empty: ['default.profraw']")

    def test_real_session_leaves_launch_directory_empty(self):
        configured = os.environ.get("MACSCOPE_BINARY")
        if not configured:
            self.skipTest("MACSCOPE_BINARY unset: no real app launched; proves nothing")
        executable = Path(configured).expanduser().resolve()
        if not executable.is_file() or not os.access(executable, os.X_OK):
            self.skipTest("MACSCOPE_BINARY not executable: no app launched; proves nothing")
        require_macho(executable)
        selected = TARGET_BINARY or shutil.which("true", path=os.defpath)
        self.assertIsNotNone(selected, "no small analysis input; supply --target-binary")
        target = Path(selected).expanduser().resolve()
        self.assertTrue(target.is_file(), "analysed binary must be a real external file")
        require_macho(target)
        environment = scrub_environment(os.environ)
        self.assertFalse(any(unsafe_environment_key(key) for key in environment))
        with tempfile.TemporaryDirectory(prefix="macscope-p5-launch-") as name:
            directory = Path(name).resolve()
            self.assertNotEqual(directory, Path.cwd().resolve())
            self.assertNotIn(directory, executable.parents)
            self.assertNotIn(directory, target.parents)
            self.assertEqual(assert_empty_directory(directory), [])
            proc = None
            problems = []
            ready = False
            returncode = None
            forced = False
            try:
                proc = subprocess.Popen([str(executable), "--mcp", str(target)],
                                        cwd=directory, env=environment,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        bufsize=0)
                RPC(proc).ready()
                self.assertIsNone(proc.poll(), "child exited instead of remaining a session")
                ready = True
            except Exception as exc:
                problems.append(f"session failed: {type(exc).__name__}: {exc}")
            finally:
                if proc is not None:
                    returncode, forced = stop_and_reap(proc)
                    if forced or returncode != 0:
                        problems.append(f"normal EOF exit required: code={returncode}, forced={forced}")
            try:
                entries = assert_empty_directory(directory)
            except AssertionError as exc:
                entries = sorted(path.name for path in directory.iterdir())
                problems.append(str(exc))
            print(json.dumps({"executable": str(executable), "analysed_binary": str(target),
                              "launch_cwd": str(directory), "initial_entries": [],
                              "final_entries": entries, "ready": ready,
                              "exit_code": returncode, "forced": forced,
                              "pid": None if proc is None else proc.pid,
                              "problems": problems}), file=sys.stderr)
            self.assertTrue(ready, f"no completed ready session: {problems!r}; entries={entries!r}")
            self.assertEqual(problems, [], f"session/empty-directory failure: {problems!r}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--target-binary")
    options, remaining = parser.parse_known_args()
    TARGET_BINARY = options.target_binary
    unittest.main(argv=[sys.argv[0], *remaining])
