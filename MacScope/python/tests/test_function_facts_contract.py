"""1272 r1 controls: AUTHORED, NOT RUN. No app, transport, or subprocess starts."""
import sys
import unittest
from copy import deepcopy
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import macscope  # noqa: E402


class RecordingClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def call(self, name, arguments):
        self.calls.append((name, arguments))
        return self.response


class FunctionFactsContractTests(unittest.TestCase):
    def document(self, response):
        client = RecordingClient(response)
        document = object.__new__(macscope.Document)
        document._client = client
        return document, client

    def test_reply_keys_counts_absence_and_non_address_text_are_preserved(self):
        response = {
            "name": "0x1234", "requestedAddress": "0x1000", "resolvedFunction": "0x1000",
            "calls": {"address": "0x1000", "total": 14, "omitted": 6, "truncated": True,
                      "rows": [{"from": "0x1000", "to": "0x2000", "toName": None}]},
            "size": {"address": "0x1000", "bytes": "0x40", "blocks": [
                {"start": "0x1000", "end": "0x1008", "instructionCount": 2}]},
            "references": {"rows": [{"value": "0x3000", "selector": "0x4000", "kind": "0x5000"}]},
            "backend": {"status": "unavailable", "reason": "noStoredFunctionBackend"},
            "future": {"opaque": "0x6000", "nested": [None, False, 0]},
        }
        original = deepcopy(response)
        document, client = self.document(response)
        result = document.function_facts(address="0xffffffffffffffff", image_slot="owner-token")
        expected = deepcopy(response)
        expected["calls"]["address"] = 0x1000
        expected["calls"]["rows"][0].update({"from": 0x1000, "to": 0x2000})
        expected["size"]["address"] = 0x1000
        expected["size"]["blocks"][0].update({"start": 0x1000, "end": 0x1008})
        self.assertEqual(result, expected)
        self.assertEqual(response, original)
        self.assertEqual(client.calls, [("function-facts", {"address": "0xffffffffffffffff", "imageSlot": "owner-token"})])
        self.assertNotIn("selector", result["calls"]["rows"][0])
        self.assertNotIn("constants", result)

    def test_empty_selector_and_zero_slot_are_not_invented_or_dropped(self):
        document, client = self.document({})
        self.assertEqual(document.function_facts(function="", image_slot=0), {})
        self.assertEqual(client.calls, [("function-facts", {"function": "", "imageSlot": 0})])
        self.assertEqual(document.function_facts(), {})
        self.assertEqual(client.calls[-1], ("function-facts", {}))


if __name__ == "__main__":
    unittest.main()
