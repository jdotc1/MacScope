"""Portable selector-query tests; no MacScope process or network."""
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
        return [{"from": "0x1004", "to": "0x2000", "selector": "0x1234", "address": None}]


class SelectorQueryClientTests(unittest.TestCase):
    def test_p1_selector_arguments_and_coercion(self):
        doc = object.__new__(macscope.Document)
        doc._client = FakeClient()
        result = doc.callers(selector="save:")
        doc.implementations("save:")
        doc.implementations("save:", image_slot=1)
        self.assertEqual(doc._client.calls, [("callers", {"selector": "save:"}),
            ("implementations", {"selector": "save:"}), ("implementations", {"selector": "save:", "imageSlot": 1})])
        self.assertEqual(result[0]["from"], 0x1004)
        self.assertEqual(result[0]["to"], 0x2000)
        self.assertEqual(result[0]["selector"], "0x1234")
        self.assertIsNone(result[0]["address"])

    def test_c_old_callers_arguments_unchanged(self):
        doc = object.__new__(macscope.Document)
        doc._client = FakeClient()
        doc.callers(function="_main")
        doc.callers(address=0x2000)
        self.assertEqual(doc._client.calls, [("callers", {"function": "_main"}), ("callers", {"address": "0x2000"})])


if __name__ == "__main__":
    unittest.main()
