import unittest

import macscope


class FakeClient:
    def __init__(self, replies, repeat=False):
        self.replies = replies
        self.repeat = repeat
        self.calls = []

    def call(self, name, arguments):
        self.calls.append((name, arguments))
        if len(self.calls) >= 5 and self.repeat:
            raise AssertionError("runaway")
        index = 0 if self.repeat else len(self.calls) - 1
        return self.replies[index]


def document(replies, repeat=False):
    value = macscope.Document.__new__(macscope.Document)
    value._client = FakeClient(replies, repeat=repeat)
    return value


class DecompilePagesTests(unittest.TestCase):
    def test_p1_single_page(self):
        doc = document([{"pseudocode": "a\nb", "lineCount": 2, "nextCursor": None}])
        self.assertEqual(doc.decompile(function="f"), "a\nb")
        self.assertEqual(doc._client.calls, [("decompile", {"function": "f"})])

    def test_p2_continuation_keeps_selector(self):
        doc = document([
            {"pseudocode": "a\nb", "lineCount": 3, "nextCursor": "C1"},
            {"pseudocode": "c", "lineCount": 3, "nextCursor": None},
        ])
        self.assertEqual(doc.decompile(function="f"), "a\nb\nc")
        self.assertEqual(doc._client.calls, [
            ("decompile", {"function": "f"}),
            ("decompile", {"function": "f", "cursor": "C1"}),
        ])

    def test_p3_runaway_stops_at_line_count(self):
        doc = document([{"pseudocode": "a", "lineCount": 2, "nextCursor": "C"}], repeat=True)
        with self.assertRaises(macscope.MacScopeError):
            doc.decompile(function="f")
        self.assertEqual(len(doc._client.calls), 2)

    def test_p4_pin_server(self):
        doc = document([{"pseudocode": "old"}])
        self.assertEqual(doc.decompile(function="f"), "old")
        self.assertEqual(len(doc._client.calls), 1)

    def test_address_and_image_retained(self):
        doc = document([
            {"pseudocode": "a", "lineCount": 2, "nextCursor": "C1"},
            {"pseudocode": "", "lineCount": 2, "nextCursor": None},
        ])
        self.assertEqual(doc.decompile(address=4096, image=1), "a\n")
        self.assertEqual(doc._client.calls, [
            ("decompile", {"address": "0x1000", "image": 1}),
            ("decompile", {"address": "0x1000", "image": 1, "cursor": "C1"}),
        ])

    def test_cursor_without_page_bound_refuses(self):
        doc = document([{"pseudocode": "a", "nextCursor": "C"}])
        with self.assertRaises(macscope.MacScopeError):
            doc.decompile(function="f")
        self.assertEqual(len(doc._client.calls), 1)

class DecompileDisclosureTests(unittest.TestCase):
    def test_f8_first_page_disclosure_and_string_compatibility(self):
        doc = document([
            {"pseudocode": "a", "lineCount": 2, "nextCursor": "C1", "backend": "macir",
             "fallbackReason": "native-unavailable", "fallbackCause": "unknown",
             "fallbackDetail": "runtime-runtimeAuthorityUnavailable", "cache": None, "generation": None},
            {"pseudocode": "b", "lineCount": 2, "nextCursor": None, "backend": "ignored",
             "fallbackCause": "ignored", "cache": "ignored", "generation": "ignored"},
        ])
        result = doc.decompile(function="f")
        self.assertIsInstance(result, str)
        self.assertIsInstance(result, macscope.DecompileText)
        self.assertEqual(result, "a\nb")
        self.assertEqual(result.backend, "macir")
        self.assertEqual(result.fallbackReason, "native-unavailable")
        self.assertEqual(result.fallbackCause, "unknown")
        self.assertEqual(result.fallbackDetail, "runtime-runtimeAuthorityUnavailable")
        self.assertIsNone(result.cache)
        self.assertIsNone(result.generation)
        self.assertEqual(doc._client.calls, [("decompile", {"function": "f"}),
                                           ("decompile", {"function": "f", "cursor": "C1"})])

    def test_cause_truth_values_preserve_first_page_disclosure(self):
        cases = [
            ("unknown", "runtime-runtimeAuthorityUnavailable", "native-unavailable"),
            ("error", "provider-package-verification-failed", "native-failed: package-verification-failed"),
            ("error", "runtime-validation-runtimeAuthorityMismatch", "native-unavailable"),
            ("error", "custom-budget-exceeded", "native-failed: custom-budget-exceeded"),
            ("budget", "native-provider-output-budget-exceeded", "native-failed: native-failure"),
        ]
        for cause, detail, reason in cases:
            with self.subTest(cause=cause, detail=detail):
                doc = document([
                    {"pseudocode": "a", "lineCount": 2, "nextCursor": "C1", "backend": "macir",
                     "fallbackReason": reason, "fallbackCause": cause, "fallbackDetail": detail},
                    {"pseudocode": "b", "lineCount": 2, "nextCursor": None,
                     "fallbackReason": "ignored", "fallbackCause": "ignored", "fallbackDetail": "ignored"},
                ])
                result = doc.decompile(function="f")
                self.assertIsInstance(result, str)
                self.assertEqual(result, "a\nb")
                self.assertEqual(result.backend, "macir")
                self.assertEqual(result.fallbackReason, reason)
                self.assertEqual(result.fallbackCause, cause)
                self.assertEqual(result.fallbackDetail, detail)
                self.assertIsNone(result.cache)
                self.assertIsNone(result.generation)

    def test_f8_backend_retained_on_continuation_and_cache_metadata(self):
        for backend in ("native", "macir"):
            doc = document([
                {"pseudocode": "a", "lineCount": 2, "nextCursor": "C", "backend": backend,
                 "cache": "miss", "generation": "generation-one"},
                {"pseudocode": "b", "lineCount": 2, "nextCursor": None, "cache": "hit", "generation": "generation-two"},
            ])
            result = doc.decompile(function="f", backend=backend)
            self.assertEqual(result, "a\nb")
            self.assertEqual(result.backend, backend)
            self.assertEqual(result.cache, "miss")
            self.assertEqual(result.generation, "generation-one")
            self.assertEqual(doc._client.calls, [("decompile", {"function": "f", "backend": backend}),
                ("decompile", {"function": "f", "cursor": "C", "backend": backend})])

    def test_f8_invalid_choice_fails_before_transport(self):
        for backend in ("both", "glob", "", 1, [], {}):
            doc = document([])
            with self.assertRaisesRegex(ValueError, "Document.decompile supports backend None, native or macir"):
                doc.decompile(function="f", backend=backend)
            self.assertEqual(doc._client.calls, [])

    def test_f8_empty_and_legacy_reply_have_none_attributes(self):
        for page, expected in (({}, ""), ({"pseudocode": "old"}, "old")):
            doc = document([page])
            result = doc.decompile(function="f")
            self.assertEqual(result, expected)
            for key in ("backend", "fallbackReason", "fallbackCause", "fallbackDetail", "cache", "generation"):
                self.assertIsNone(getattr(result, key))
            self.assertEqual(doc._client.calls, [("decompile", {"function": "f"})])


if __name__ == "__main__":
    unittest.main()
