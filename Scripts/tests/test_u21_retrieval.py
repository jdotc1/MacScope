#!/usr/bin/env python3

from __future__ import annotations

import unittest

from Scripts.research.u21_retrieval import evaluate, questions


def record(subject: str, operation: str = "function.references", size: int = 100, project: str = "p") -> dict:
    return {"evidenceID": f"{subject}:{operation}", "subject": subject, "operation": operation,
            "bytes": size, "project": project, "text": subject, "symbol": subject}


class U21RetrievalTests(unittest.TestCase):
    def test_identifier_parts_are_indexed_beside_the_original_token(self) -> None:
        text = evaluate.split_identifiers("calls _inflateInit2_ and mbedtls_aes_setkey_enc")
        self.assertIn("_inflateInit2_", text)
        for part in ("inflate", "Init", "2", "mbedtls", "aes", "setkey", "enc"):
            self.assertIn(part, text.split())

    def test_baseline_order_is_question_independent_and_puts_references_first(self) -> None:
        rows = [record(s, op) for s in ("a", "b", "c") for op in evaluate.OPERATION_PRIORITY]
        first = evaluate.baseline_order(rows)
        self.assertEqual(first, evaluate.baseline_order(list(reversed(rows))))
        self.assertEqual({r["operation"] for r in first[:3]}, {"function.references"})

    def test_page_stops_at_eight_records_or_eight_kibibytes(self) -> None:
        small = [record(str(i), size=100) for i in range(12)]
        self.assertEqual(len(evaluate.page_fit(small)), 8)
        large = [record("x", size=5000), record("y", size=5000), record("z", size=10)]
        self.assertEqual([r["subject"] for r in evaluate.page_fit(large)], ["x"])
        self.assertEqual(evaluate.page_fit([record("huge", size=9000)]), [])

    def test_score_counts_a_subject_hit_and_reciprocal_rank(self) -> None:
        ranked = [record("a"), record("b", "function.disassembly"), record("b")]
        scored = evaluate.score(ranked, {"b"})
        self.assertFalse(scored["hit@1"])
        self.assertTrue(scored["hit@3"])
        self.assertAlmostEqual(scored["rr"], 0.5)
        self.assertEqual(evaluate.score([], {"b"})["rr"], 0.0)

    def test_questions_never_contain_the_answer_name_or_code_identifiers(self) -> None:
        scrubbed = questions.scrub("Calls cJSON_Parse via parse_value() and returns cJSON_Invalid.", "cJSON_Parse")
        self.assertNotIn("cJSON_Parse", scrubbed)
        self.assertNotIn("parse_value", scrubbed)
        self.assertNotIn("cJSON_Invalid", scrubbed)
        self.assertIn("returns", scrubbed)
        self.assertIn("SHA", questions.scrub("Starts a SHA-3 calculation.", "mbedtls_sha3_starts"))

    def test_doxygen_brief_is_kept_and_tags_are_dropped(self) -> None:
        text = questions.clean(" * \\brief This function sets the key.\n * \\param ctx The context.\n * \\return 0.")
        self.assertEqual(text, "This function sets the key.")


if __name__ == "__main__":
    unittest.main()
