"""Packet 1245 controls: AUTHORED, NOT RUN. No app or subprocess is started."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import macscope  # noqa: E402


class RecordingClient:
    def __init__(self):
        self.calls = []

    def call(self, name, arguments):
        self.calls.append((name, arguments))
        return {"calls": {"rows": [{"from": "0x1000", "to": "0x2000"}]},
                "references": {"rows": [{"value": "0x3000", "cString": "0x3000"}]}}


class FunctionFactsTests(unittest.TestCase):
    def test_wrapper_selector_slot_and_existing_address_coercion(self):
        client = RecordingClient()
        document = object.__new__(macscope.Document)
        document._client = client
        result = document.function_facts(address=0x1000)
        self.assertEqual(client.calls, [("function-facts", {"address": "0x1000"})])
        self.assertEqual(result["calls"]["rows"], [{"from": 0x1000, "to": 0x2000}])
        self.assertEqual(result["references"]["rows"], [{"value": "0x3000", "cString": 0x3000}])
        document.function_facts(function="fixture", image_slot=1)
        self.assertEqual(client.calls[-1], ("function-facts", {"function": "fixture", "imageSlot": 1}))
        document.function_facts(address="0xffffffffffffffff")
        self.assertEqual(client.calls[-1], ("function-facts", {"address": "0xffffffffffffffff"}))


if __name__ == "__main__":
    unittest.main()
