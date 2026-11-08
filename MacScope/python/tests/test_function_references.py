"""Portable function-reference wrapper and address-coercion controls."""
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
        return {"references": [{"cString": "0x3010", "value": "0x3010"}]}


class FunctionReferencesTests(unittest.TestCase):
    def test_p1_function_references_arguments(self):
        client = RecordingClient()
        document = object.__new__(macscope.Document)
        document._client = client
        result = document.function_references(address=0x1000)
        self.assertEqual(client.calls, [("function-references", {"address": "0x1000"})])
        self.assertEqual(result, {"references": [{"cString": 0x3010, "value": "0x3010"}]})
        document.function_references(address=0x1000, image_slot=1, limit=2)
        self.assertEqual(client.calls[-1], ("function-references", {"address": "0x1000", "imageSlot": 1, "limit": 2}))
        document.function_references(function="smcOpen", limit=0)
        self.assertEqual(client.calls[-1], ("function-references", {"function": "smcOpen", "limit": 0}))

    def test_p2_cstring_is_address_but_value_is_text(self):
        self.assertEqual(macscope._coerce({"cString": "0x3010", "value": "0x3010"}),
                         {"cString": 0x3010, "value": "0x3010"})
        self.assertEqual(macscope._coerce({"fromFunction": "0x1000", "cString": None}),
                         {"fromFunction": 0x1000, "cString": None})


if __name__ == "__main__":
    unittest.main()
