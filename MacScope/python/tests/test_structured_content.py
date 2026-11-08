"""ITEM 1246: all controls authored NOT RUN; no native executable is needed.

Uses in-memory exchanges rather than launching a responder. The supplied existing
text-only subprocess fixtures remain unchanged and were not executed for this review.
"""
from __future__ import annotations

import json
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import macscope  # noqa: E402


def text_result(value, *, is_error=False):
    return {"content": [{"type": "text", "text": json.dumps(value)}], "isError": is_error}


def structured_result(value, *, wrapped=False):
    result = {"structuredContent": {"result": value} if wrapped else value,
              "content": [{"type": "text", "text": "fixture: success; data is in structuredContent."}],
              "isError": False, "_meta": {"generation": "fixture-generation"}}
    if wrapped:
        result["_meta"]["macscope/resultWrapper"] = "result"
    return result


class StructuredContentTests(unittest.TestCase):
    # NOT RUN: all test methods below are static-draft controls.
    def client(self, result):
        client = object.__new__(macscope._MCPClient)
        client._request = mock.Mock(return_value=result)
        return client

    def test_structured_object_takes_priority_over_invalid_short_text(self):
        value = {"functionCount": 3}
        self.assertEqual(self.client(structured_result(value)).call("info"), value)

    def test_unwraps_all_non_object_shapes(self):
        for value in [[], [1, 2], "_main", "", 0, 1.5, False, None]:
            with self.subTest(value=value):
                self.assertEqual(self.client(structured_result(value, wrapped=True)).call("fixture"), value)

    def test_real_result_key_is_not_a_wrapper(self):
        value = {"result": [1, 2]}
        self.assertEqual(self.client(structured_result(value)).call("fixture"), value)

    def test_marker_must_be_exact(self):
        result = structured_result({"result": 7})
        result["_meta"]["macscope/resultWrapper"] = True
        self.assertEqual(self.client(result).call("fixture"), {"result": 7})

    def test_malformed_structured_content_does_not_silently_use_short_text(self):
        for value in [None, [], "wrong", 5]:
            with self.subTest(value=value):
                result = text_result({"legacy": True})
                result["structuredContent"] = value
                with self.assertRaisesRegex(macscope.MacScopeError, "expected object"):
                    self.client(result).call("fixture")

    def test_malformed_wrapper_fails_without_losing_null(self):
        for value in [{}, {"result": 7, "extra": True}]:
            result = structured_result(value)
            result["_meta"]["macscope/resultWrapper"] = "result"
            with self.assertRaisesRegex(macscope.MacScopeError, "wrapper"):
                self.client(result).call("fixture")
        self.assertIsNone(self.client(structured_result(None, wrapped=True)).call("fixture"))

    def test_text_only_old_server_json_and_plain_text_fallbacks(self):
        for value in [{"functionCount": 3}, [1], "_main", 7, None]:
            with self.subTest(value=value):
                self.assertEqual(self.client(text_result(value)).call("fixture"), value)
        result = {"content": [{"type": "text", "text": "plain legacy text"}], "isError": False}
        self.assertEqual(self.client(result).call("fixture"), "plain legacy text")
        self.assertIsNone(self.client({"content": []}).call("fixture"))

    def test_error_text_wins_even_if_structured_content_is_present(self):
        result = structured_result({"should": "not escape"})
        result["isError"] = True
        result["content"][0]["text"] = "writeReadbackFailed: inspect state"
        with self.assertRaisesRegex(macscope.MacScopeError, "writeReadbackFailed: inspect state"):
            self.client(result).call("fixture")

    def test_initialize_offers_new_version_and_accepts_legacy_answer(self):
        for version in ["2024-11-05", "2025-06-18"]:
            client = object.__new__(macscope._MCPClient)
            client._lock = threading.Lock()
            client._exchange = mock.Mock(side_effect=[{"protocolVersion": version, "capabilities": {}}, None])
            client._initialize(macscope._Deadline(10.0))
            initial = client._exchange.call_args_list[0]
            self.assertEqual(initial.args[0], "initialize")
            self.assertEqual(initial.args[1]["protocolVersion"], "2025-06-18")
            client._request = mock.Mock(return_value=text_result({"functionCount": 1}))
            self.assertEqual(client.call("info"), {"functionCount": 1})

    def test_startup_readiness_uses_same_structured_decoder_and_old_fallback(self):
        for structured in [False, True]:
            make = structured_result if structured else text_result
            client = object.__new__(macscope._MCPClient)
            client._lock = threading.Lock()
            client._exchange = mock.Mock(side_effect=[
                {"protocolVersion": "2025-06-18" if structured else "2024-11-05",
                 "capabilities": {"experimental": {"macscope/analysis": {"state": "analyzing"}}}},
                None, make({"analysis": {"state": "analyzing"}}), make({"analysis": {"state": "ready"}})])
            client._initialize(macscope._Deadline(10.0))
            self.assertEqual([c.args[0] for c in client._exchange.call_args_list],
                             ["initialize", "notifications/initialized", "tools/call", "tools/call"])
            for call in client._exchange.call_args_list[2:]:
                self.assertEqual(call.args[1]["name"], "info")
                self.assertGreaterEqual(call.args[1]["arguments"]["waitForReadyMs"], 0)
                self.assertLessEqual(call.args[1]["arguments"]["waitForReadyMs"], 25000)

    def test_startup_failure_and_is_error_still_raise_text_or_reason(self):
        for structured in [False, True]:
            make = structured_result if structured else text_result
            client = object.__new__(macscope._MCPClient)
            client._exchange = mock.Mock(return_value=make({"analysis": {"state": "failed", "reason": "fixture failed"}}))
            with self.assertRaisesRegex(macscope.MacScopeError, "fixture failed"):
                client._await_analysis_ready(macscope._Deadline(10.0))
        result = structured_result({"analysis": {"state": "ready"}})
        result["isError"] = True
        result["content"][0]["text"] = "startup refused"
        client._exchange = mock.Mock(return_value=result)
        with self.assertRaisesRegex(macscope.MacScopeError, "startup refused"):
            client._await_analysis_ready(macscope._Deadline(10.0))

    def test_generation_and_dispatch_note_are_not_mistaken_for_payload(self):
        result = structured_result({"functionCount": 3})
        result["note"] = {"fallback": "fixture"}
        result["content"] += [{"type": "text", "text": json.dumps({"note": result["note"]})},
                              {"type": "text", "text": json.dumps({"generation": "fixture-generation"})}]
        self.assertEqual(self.client(result).call("info"), {"functionCount": 3})


if __name__ == "__main__":
    unittest.main()
