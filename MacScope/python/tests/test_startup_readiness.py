"""Startup-readiness protocol fixtures; no MacScope executable is needed."""
from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import macscope  # noqa: E402

RESPONDER = r'''
import json
import os
import sys

mode = sys.argv[2]
log_path = os.environ["MACSCOPE_STARTUP_TEST_LOG"]

def receive():
    line = sys.stdin.readline()
    if not line:
        return None
    value = json.loads(line)
    with open(log_path, "a") as log:
        log.write(json.dumps(value) + "\n")
    return value

def reply(request, result):
    print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)

request = receive()
if mode == "nondict":
    initial = []
elif mode == "absent":
    initial = {}
else:
    initial = {"capabilities": {"experimental": {"macscope/analysis": {"state": "analyzing"}}}}
reply(request, initial)
receive()  # initialized notification
count = 0
while True:
    request = receive()
    if request is None:
        break
    if request["method"] != "tools/call":
        reply(request, {})
        continue
    count += 1
    state = "failed" if mode == "failed" else ("ready" if count == 2 else "analyzing")
    analysis = {"state": state, "phase": "decode", "progress": 1 if state == "ready" else 0.1, "elapsedMs": count}
    if state == "failed":
        analysis["reason"] = "fixture startup failure"
    reply(request, {"content": [{"type": "text", "text": json.dumps({"analysis": analysis})}], "isError": False})
'''

class StartupReadinessTests(unittest.TestCase):
    def setUp(self):
        if os.name != "posix":
            self.skipTest("responder fixture uses a POSIX shebang")
        self.directory = tempfile.mkdtemp(prefix="startup-readiness-")
        self.addCleanup(shutil.rmtree, self.directory, ignore_errors=True)
        self.responder = Path(self.directory) / "responder"
        self.responder.write_text("#!" + sys.executable + "\n" + RESPONDER, encoding="utf-8")
        self.responder.chmod(stat.S_IRWXU)
        self.log = Path(self.directory) / "requests.jsonl"
        environment = mock.patch.dict(os.environ, {"MACSCOPE_STARTUP_TEST_LOG": str(self.log)})
        environment.start()
        self.addCleanup(environment.stop)

    def requests(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def client(self, mode, **kwargs):
        client = macscope._MCPClient(str(self.responder), mode,
            startup_timeout=kwargs.get("startup_timeout", 10.0),
            request_timeout=5.0, terminate_timeout=0.2)
        self.addCleanup(client.close)
        return client

    def test_waits_for_two_info_replies_before_returning(self):
        self.client("ready")
        calls = self.requests()
        self.assertEqual([r["method"] for r in calls],
            ["initialize", "notifications/initialized", "tools/call", "tools/call"])
        for request in calls[2:]:
            self.assertEqual(request["params"]["name"], "info")
            wait = request["params"]["arguments"]["waitForReadyMs"]
            self.assertIs(type(wait), int)
            self.assertGreaterEqual(wait, 0)
            self.assertLessEqual(wait, 25000)

    def test_unbounded_startup_uses_25000_millisecond_waits(self):
        self.client("ready", startup_timeout=None)
        for request in self.requests()[2:]:
            self.assertEqual(request["params"]["arguments"]["waitForReadyMs"], 25000)

    def test_failed_analysis_raises_reason_and_reaps_child(self):
        spawned = []
        real_popen = subprocess.Popen
        def record(*args, **kwargs):
            proc = real_popen(*args, **kwargs)
            spawned.append(proc)
            return proc
        with mock.patch.object(macscope.subprocess, "Popen", side_effect=record):
            with self.assertRaisesRegex(macscope.MacScopeError, "fixture startup failure"):
                self.client("failed")
        self.assertEqual(len(spawned), 1)
        proc = spawned[0]
        self.assertIsNotNone(proc.returncode)
        self.assertTrue(proc.stdin.closed)
        self.assertTrue(proc.stdout.closed)
        with self.assertRaises(ChildProcessError):
            os.waitpid(proc.pid, os.WNOHANG)

    def test_absent_capability_and_nondict_result_keep_legacy_sequence(self):
        for mode in ["absent", "nondict"]:
            with self.subTest(mode=mode):
                if self.log.exists():
                    self.log.unlink()
                client = self.client(mode)
                client._request("ping")
                self.assertEqual([r["method"] for r in self.requests()],
                    ["initialize", "notifications/initialized", "ping"])
                client.close()

if __name__ == "__main__":
    unittest.main()
