"""Portable graph-name client tests; no MacScope process or network."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import macscope


class FakeClient:
    def __init__(self):
        self.calls = []

    def call(self, name, args):
        self.calls.append((name, args))
        return {"name": "helper", "start": "0x1010", "end": "0x1020",
                "requestedAddress": "0x1014", "resolvedFunction": "0x1010"}


class GraphRowNamesClientTests(unittest.TestCase):
    def test_p1_containing_function_arguments_and_result_coercion(self):
        document = object.__new__(macscope.Document)
        client = FakeClient()
        document._client = client
        first = document.containing_function(0x1014)
        second = document.containing_function(0x1014, image=1)
        self.assertEqual(client.calls, [
            ("containing-function", {"address": "0x1014"}),
            ("containing-function", {"address": "0x1014", "image": 1}),
        ])
        for result in (first, second):
            self.assertEqual(result.start, 0x1010)
            self.assertEqual(result.end, 0x1020)
            self.assertEqual(result.requestedAddress, "0x1014")
            self.assertEqual(result.resolvedFunction, "0x1010")

    def test_p2_owner_address_only_is_coerced(self):
        result = macscope._coerce({"fromFunction": "0x1000", "fromFunctionName": "0x1000"})
        self.assertEqual(result.fromFunction, 0x1000)
        self.assertEqual(result.fromFunctionName, "0x1000")
        self.assertIsNone(macscope._coerce({"fromFunction": None}).fromFunction)


if __name__ == "__main__":
    unittest.main()
