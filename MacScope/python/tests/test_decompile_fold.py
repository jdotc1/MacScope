import unittest

import macscope


class FakeClient:
    def __init__(self, replies):
        self.replies = replies
        self.calls = []

    def call(self, name, arguments):
        self.calls.append((name, arguments))
        reply = self.replies[len(self.calls) - 1]
        if isinstance(reply, Exception):
            raise reply
        return reply


class RecordingDocument(macscope.Document):
    def command(self, name, /, **arguments):
        self.command_calls.append((name, arguments))
        return super().command(name, **arguments)


def document(replies):
    value = RecordingDocument.__new__(RecordingDocument)
    value._client = FakeClient(replies)
    value.command_calls = []
    return value


def three_pages():
    return [
        {"pseudocode": "a", "lineCount": 3, "nextCursor": "C1"},
        {"pseudocode": "b", "lineCount": 3, "nextCursor": "C2"},
        {"pseudocode": "c", "lineCount": 3, "nextCursor": None},
    ]


class DecompileFoldTests(unittest.TestCase):
    def test_fold_reaches_first_and_every_continuation(self):
        doc = document(three_pages())
        result = doc.decompile("f", 4096, 1, "macir", fold=["arc"])
        self.assertEqual(result, "a\nb\nc")  # P1a
        self.assertEqual(doc._client.calls, [  # P1b
            ("decompile", {"function": "f", "address": "0x1000", "image": 1,
                           "backend": "macir", "fold": ["arc"]}),
            ("decompile", {"function": "f", "address": "0x1000", "image": 1,
                           "cursor": "C1", "backend": "macir", "fold": ["arc"]}),
            ("decompile", {"function": "f", "address": "0x1000", "image": 1,
                           "cursor": "C2", "backend": "macir", "fold": ["arc"]}),
        ])

    def test_omitted_and_none_do_not_add_a_fold_keyword(self):
        for options in ({}, {"fold": None}):
            with self.subTest(options=options):
                doc = document(three_pages())
                doc.decompile(function="f", **options)
                self.assertEqual(doc._client.calls, [  # P2a
                    ("decompile", {"function": "f"}),
                    ("decompile", {"function": "f", "cursor": "C1"}),
                    ("decompile", {"function": "f", "cursor": "C2"}),
                ])
                for _, arguments in doc.command_calls:
                    self.assertNotIn("fold", arguments)  # P2b

    def test_explicit_empty_fold_is_sent_on_all_pages(self):
        doc = document(three_pages())
        result = doc.decompile(function="f", fold=[])
        self.assertEqual(result, "a\nb\nc")  # P3a
        self.assertEqual(doc._client.calls, [  # P3b
            ("decompile", {"function": "f", "fold": []}),
            ("decompile", {"function": "f", "cursor": "C1", "fold": []}),
            ("decompile", {"function": "f", "cursor": "C2", "fold": []}),
        ])

    def test_invalid_fold_type_refuses_before_command_or_transport(self):
        invalid = ["arc", ("arc",), {"arc"}, {"kind": "arc"}, 1, True, b"arc",
                   macscope.JSON_NULL, [1], [True], [None], [["arc"]], ["arc", 1]]
        for fold in invalid:
            with self.subTest(fold=fold):
                doc = document([{"pseudocode": "should not be read"}])
                with self.assertRaisesRegex(  # P4a
                    TypeError, "^Document.decompile fold must be a list of strings or None$"
                ):
                    doc.decompile(function="f", fold=fold)
                self.assertEqual(doc.command_calls, [])  # P4b
                self.assertEqual(doc._client.calls, [])  # P4c

    def test_supported_kinds_and_server_refusals_remain_server_owned(self):
        failure = macscope.MacScopeError("fold: unknown kind 'future-fold'; supported: arc")
        doc = document([failure])
        with self.assertRaises(macscope.MacScopeError) as raised:  # P5a
            doc.decompile(function="f", fold=["arc", "future-fold", "arc"])
        self.assertIs(raised.exception, failure)  # P5b
        self.assertEqual(doc._client.calls, [  # P5c
            ("decompile", {"function": "f", "fold": ["arc", "future-fold", "arc"]}),
        ])

    def test_disclosure_keeps_whole_function_values_and_first_page_events(self):
        pages = three_pages()
        first_event = {"address": 0x1004, "kind": "arc", "callee": "objc_retain",
                       "role": "retain", "beforeLine": 1}
        refusal = {"count": 1, "reasons": {"branch-target": 1},
                   "entries": [{"reason": "branch-target", "address": 0x1010,
                                "callee": "objc_release"}], "entriesTruncated": False}
        pages[0].update(folded={"arc": 3}, foldRefused=refusal,
                        foldedEvents=[first_event], foldedEventsTruncated=False)
        # Deliberately distinct later-page values detect replacing first-page metadata.
        pages[1].update(folded={"arc": 99}, foldRefused={"count": 99},
                        foldedEvents=[{"address": 0x1008}], foldedEventsTruncated=True)
        pages[2].update(folded={"arc": 101}, foldRefused={"count": 101},
                        foldedEvents=[{"address": 0x100C}], foldedEventsTruncated=True)
        result = document(pages).decompile(function="f", fold=["arc"])
        self.assertIsInstance(result, macscope.DecompileText)  # P6a
        self.assertEqual(result, "a\nb\nc")  # P6b
        self.assertEqual(result.folded, {"arc": 3})  # P6c
        self.assertEqual(result.foldRefused, refusal)  # P6d
        self.assertEqual(result.foldedEvents, [first_event])  # P6e
        self.assertIs(result.foldedEventsTruncated, False)  # P6f

    def test_first_page_truncation_is_not_overwritten_by_later_false(self):
        pages = three_pages()
        pages[0]["foldedEventsTruncated"] = True
        pages[1]["foldedEventsTruncated"] = False
        pages[2]["foldedEventsTruncated"] = False
        result = document(pages).decompile(function="f", fold=["arc"])
        self.assertIs(result.foldedEventsTruncated, True)  # P7

    def test_empty_and_legacy_replies_have_none_fold_attributes(self):
        for page, expected in (({}, ""), ({"pseudocode": "old"}, "old")):
            with self.subTest(page=page):
                doc = document([page])
                result = doc.decompile(function="f", fold=["arc"])
                self.assertEqual(result, expected)  # P8a
                for key in ("folded", "foldRefused", "foldedEvents", "foldedEventsTruncated"):
                    self.assertIsNone(getattr(result, key))  # P8b

    def test_backend_error_text_and_precedence_are_unchanged(self):
        for fold in (1, ["arc"]):
            with self.subTest(fold=fold):
                doc = document([{}])
                with self.assertRaises(ValueError) as raised:  # P9a
                    doc.decompile(function="f", backend="both", fold=fold)
                self.assertEqual(str(raised.exception),  # P9b
                    'Document.decompile supports backend None, native or macir; '
                    'use command("decompile", backend="both") for the paired reply')
                self.assertEqual(doc._client.calls, [])  # P9c

    def test_folded_paging_preserves_line_count_guard(self):
        doc = document([
            {"pseudocode": "a", "lineCount": 2, "nextCursor": "C1"},
            {"pseudocode": "b", "lineCount": 2, "nextCursor": "C2"},
            {"pseudocode": "must not be read", "lineCount": 2, "nextCursor": None},
        ])
        with self.assertRaisesRegex(  # P10a
            macscope.MacScopeError, "^decompile continuation exceeded lineCount pages$"
        ):
            doc.decompile(function="f", fold=["arc"])
        self.assertEqual(doc._client.calls, [  # P10b
            ("decompile", {"function": "f", "fold": ["arc"]}),
            ("decompile", {"function": "f", "cursor": "C1", "fold": ["arc"]}),
        ])

    # Design-dependent: FD-README must land; the pinned README fails this control.
    def test_readme_describes_package_after_fd_readme(self):
        from pathlib import Path

        lines = (Path(__file__).resolve().parents[1] / "README.md").read_text(encoding="utf-8").splitlines()
        self.assertIn("- The client is the `macscope/` package with no third-party dependencies.", lines)  # P11a
        self.assertNotIn("- The client is a single file (`macscope/__init__.py`) with no third-party dependencies.", lines)  # P11b

    def test_fold_snapshot_survives_caller_and_transport_mutations(self):
        requested = ["arc"]
        observed = []

        class MutatingClient(FakeClient):
            def call(self, name, arguments):
                observed.append({**arguments, "fold": list(arguments["fold"])})
                reply = super().call(name, arguments)
                if len(self.calls) == 1:
                    requested[:] = ["caller-mutated"]
                elif len(self.calls) == 2:
                    arguments["fold"][:] = ["transport-mutated"]
                return reply

        doc = document(three_pages())
        doc._client = MutatingClient(doc._client.replies)
        doc.decompile(function="f", fold=requested)
        self.assertEqual([arguments["fold"] for arguments in observed], [["arc"], ["arc"], ["arc"]])  # P12


if __name__ == "__main__":
    unittest.main()
