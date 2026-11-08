#!/usr/bin/env python3
"""Tests for the H22 bounded expression simplifier (portable research code).

Runs under Python 3.9 and newer. Solver-backed tests skip without z3; lift tests skip without
pypcode. Nothing here compiles or touches MacScope product code.
"""
from __future__ import annotations

import importlib.util
import random
import unittest

from Scripts.research.h22_expr_simplify import expr, rules, semantics
from Scripts.research.h22_expr_simplify.expr import BOOL_WIDTH, ExpressionError, Node, mask
from Scripts.research.h22_expr_simplify.proof import ProofGate
from Scripts.research.h22_expr_simplify.rules import A, K, L, RULES, Rule
from Scripts.research.h22_expr_simplify.simplify import Caps, Simplifier, cost

HAS_Z3 = importlib.util.find_spec("z3") is not None
HAS_PYPCODE = importlib.util.find_spec("pypcode") is not None
WIDTHS = (1, 8, 16, 32, 64)
SMALL_WIDTHS = (1, 2, 3, 4, 5, 6, 7, 8)


def gate() -> ProofGate:
    return ProofGate(timeout_ms=5000)


def random_expression(rng: random.Random, width: int, depth: int, leaves: int) -> Node:
    """Random well-formed pure tree over `leaves` named inputs at one width (plus bools)."""
    if depth == 0 or rng.random() < 0.2:
        if rng.random() < 0.3:
            return K(rng.getrandbits(width), width)
        return L("v%d_%d" % (rng.randrange(leaves), width), width)
    choice = rng.random()
    if choice < 0.55:
        op = rng.choice(sorted(expr.BINARY_SAME_WIDTH - expr.DIVISIONS))
        return A(op, width, random_expression(rng, width, depth - 1, leaves), random_expression(rng, width, depth - 1, leaves))
    if choice < 0.7:
        op = rng.choice(sorted(expr.SHIFTS))
        amount = K(rng.randrange(0, width + 2), rng.choice((8, 32)))
        return A(op, width, random_expression(rng, width, depth - 1, leaves), amount)
    if choice < 0.8:
        op = rng.choice(sorted(expr.UNARY_SAME_WIDTH))
        return A(op, width, random_expression(rng, width, depth - 1, leaves))
    if choice < 0.9 and width % 8 == 0 and width >= 16:
        half = width // 2
        inner = random_expression(rng, half, depth - 1, leaves)
        return A(rng.choice(("INT_ZEXT", "INT_SEXT")), width, inner)
    if width % 8 == 0 and 8 <= width <= 32:
        return A("SUBPIECE", width, random_expression(rng, 2 * width, depth - 1, leaves), K(rng.choice((0, 1)), 8))
    return A("INT_NEGATE", width, random_expression(rng, width, depth - 1, leaves))


class ExpressionIRTests(unittest.TestCase):
    def test_width_discipline_is_enforced(self) -> None:
        with self.assertRaises(ExpressionError):
            A("INT_ADD", 32, L("x", 32), L("y", 64))
        with self.assertRaises(ExpressionError):
            A("INT_ZEXT", 32, L("x", 32))
        with self.assertRaises(ExpressionError):
            A("SUBPIECE", 32, L("x", 32), K(1, 8))  # selects bits 8..39 of a 32-bit value
        with self.assertRaises(ExpressionError):
            A("INT_EQUAL", 32, L("x", 32), L("y", 32))  # comparisons are one byte
        with self.assertRaises(ExpressionError):
            A("LOAD", 64, L("x", 64))  # effect opcodes are never expression nodes

    def test_division_domain_is_static(self) -> None:
        with self.assertRaises(ExpressionError):
            A("INT_DIV", 32, L("x", 32), L("y", 32))
        with self.assertRaises(ExpressionError):
            A("INT_DIV", 32, L("x", 32), K(0, 32))
        with self.assertRaises(ExpressionError):
            A("INT_SDIV", 32, L("x", 32), K(mask(32), 32))
        A("INT_SDIV", 32, L("x", 32), K(7, 32))
        A("INT_DIV", 32, L("x", 32), K(mask(32), 32))

    def test_canonical_text_and_mixed_width_render(self) -> None:
        node = A("INT_ZEXT", 64, A("INT_AND", 32, L("w0", 32), K(0xFF, 32)))
        self.assertEqual(node.canonical(), "(INT_ZEXT:64 (INT_AND:32 w0:32 #32:0xff))")
        self.assertEqual(str(node), "zext64((w0 & 0xff))")
        self.assertEqual(node.leaves(), {"w0": 32})


class SemanticsTests(unittest.TestCase):
    def test_shift_edges_follow_opbehavior(self) -> None:
        x = L("x", 8)
        for amount in (7, 8, 9, 255):
            env = {"x": 0x81}
            left = semantics.evaluate(A("INT_LEFT", 8, x, K(amount, 8)), env)
            right = semantics.evaluate(A("INT_RIGHT", 8, x, K(amount, 8)), env)
            sright = semantics.evaluate(A("INT_SRIGHT", 8, x, K(amount, 8)), env)
            self.assertEqual((left, right), ((0x81 << amount) & 0xFF if amount < 8 else 0, 0x81 >> amount if amount < 8 else 0))
            self.assertEqual(sright, 0xFF if amount >= 8 else ((0x81 - 256) >> amount) & 0xFF)

    def test_boolean_negate_is_xor_one_on_the_byte(self) -> None:
        self.assertEqual(semantics.evaluate(A("BOOL_NEGATE", 8, L("b", 8)), {"b": 2}), 3)
        self.assertEqual(semantics.evaluate(A("BOOL_NEGATE", 8, L("b", 8)), {"b": 1}), 0)

    def test_signed_division_truncates_toward_zero(self) -> None:
        self.assertEqual(semantics.evaluate(A("INT_SDIV", 8, K(0xF9, 8), K(2, 8)), {}), 0xFD)  # -7 / 2 == -3
        self.assertEqual(semantics.evaluate(A("INT_SREM", 8, K(0xF9, 8), K(2, 8)), {}), 0xFF)  # -7 % 2 == -1
        with self.assertRaises(semantics.UndefinedBehaviour):
            semantics.evaluate(Node("INT_SDIV", 8, (K(0x80, 8), K(0xFF, 8))), {})

    def test_subpiece_and_piece_round_trip(self) -> None:
        x = L("x", 32)
        env = {"x": 0xA1B2C3D4}
        hi = A("SUBPIECE", 16, x, K(2, 8))
        lo = A("SUBPIECE", 16, x, K(0, 8))
        self.assertEqual(semantics.evaluate(hi, env), 0xA1B2)
        self.assertEqual(semantics.evaluate(lo, env), 0xC3D4)
        self.assertEqual(semantics.evaluate(A("PIECE", 32, hi, lo), env), 0xA1B2C3D4)

    def test_counts_carry_and_borrow(self) -> None:
        self.assertEqual(semantics.evaluate(A("POPCOUNT", 8, K(0xF0F0, 16)), {}), 8)
        self.assertEqual(semantics.evaluate(A("LZCOUNT", 8, K(1, 16)), {}), 15)
        self.assertEqual(semantics.evaluate(A("LZCOUNT", 8, K(0, 16)), {}), 16)
        self.assertEqual(semantics.evaluate(A("INT_CARRY", 8, K(0xFF, 8), K(1, 8)), {}), 1)
        self.assertEqual(semantics.evaluate(A("INT_SCARRY", 8, K(0x7F, 8), K(1, 8)), {}), 1)
        self.assertEqual(semantics.evaluate(A("INT_SBORROW", 8, K(0x80, 8), K(1, 8)), {}), 1)
        self.assertEqual(semantics.evaluate(A("INT_SBORROW", 8, K(0x05, 8), K(1, 8)), {}), 0)

    @unittest.skipUnless(HAS_Z3, "z3 is unavailable")
    def test_z3_encoding_agrees_with_reference_evaluator_exhaustively(self) -> None:
        import z3
        cases = []
        for w in (1, 2, 3, 4):
            x, y = L("x", w), L("y", w)
            for op in sorted(expr.BINARY_SAME_WIDTH - expr.DIVISIONS):
                cases.append(A(op, w, x, y))
            for op in sorted(expr.COMPARISONS):
                cases.append(A(op, BOOL_WIDTH, x, y))
            for op in sorted(expr.SHIFTS):
                cases.append(A(op, w, x, L("a", 3)))
                cases.append(A(op, w, x, L("a2", w)))
            cases.append(A("INT_NEGATE", w, x))
            cases.append(A("INT_2COMP", w, x))
            cases.append(A("POPCOUNT", w, x))
            cases.append(A("LZCOUNT", w, x))
            cases.append(A("INT_ZEXT", w + 3, x))
            cases.append(A("INT_SEXT", w + 3, x))
            for divisor in (1, 2, 3, mask(w)):
                if divisor & mask(w) == 0:
                    continue
                for op in ("INT_DIV", "INT_REM"):
                    cases.append(A(op, w, x, K(divisor, w)))
                if w > 1 and divisor & mask(w) != mask(w):
                    for op in ("INT_SDIV", "INT_SREM"):
                        cases.append(A(op, w, x, K(divisor, w)))
        cases.append(A("SUBPIECE", 8, L("p", 16), K(1, 8)))
        cases.append(A("PIECE", 16, L("h", 8), L("l", 8)))
        b1, b2 = L("b1", 8), L("b2", 8)
        cases += [A("BOOL_NEGATE", 8, b1), A("BOOL_AND", 8, b1, b2), A("BOOL_OR", 8, b1, b2), A("BOOL_XOR", 8, b1, b2)]
        for case in cases:
            variables = semantics.make_variables(case, z3)
            term = semantics.encode(case, variables, z3)
            leaves = case.leaves()
            space = 1
            for width in leaves.values():
                space *= 1 << width
            envs = semantics.environments(leaves) if space <= 4096 else (
                {name: random.Random(7 + i).getrandbits(width) for name, width in leaves.items()} for i in range(300))
            for env in envs:
                solver = z3.Solver()
                for name, variable in variables.items():
                    solver.add(variable == env[name])
                self.assertEqual(solver.check(), z3.sat)
                model = solver.model()
                self.assertEqual(model.eval(term, model_completion=True).as_long(), semantics.evaluate(case, env),
                                 "%s at %r" % (case.canonical(), env))


class RuleSoundnessTests(unittest.TestCase):
    def test_every_rule_has_a_matching_example(self) -> None:
        for r in RULES:
            matched = 0
            for w in WIDTHS:
                example = r.example(w)
                if example is None:
                    continue
                candidate = r.match(example)
                self.assertIsNotNone(candidate, r.id)
                self.assertTrue(cost(candidate) < cost(example), "%s does not reduce cost at width %d" % (r.id, w))
                matched += 1
            self.assertGreater(matched, 0, r.id)

    def test_every_rule_example_is_exhaustively_sound_at_small_widths(self) -> None:
        for r in RULES:
            for w in SMALL_WIDTHS:
                example = r.example(w)
                if example is None:
                    continue
                candidate = r.match(example)
                self.assertIsNotNone(candidate, r.id)
                try:
                    counterexample = semantics.exhaustive_equivalent(example, candidate, limit=1 << 18)
                except ExpressionError:  # too many leaves at this width: sample instead
                    counterexample = semantics.random_equivalent(example, candidate, samples=2000, seed=w)
                self.assertIsNone(counterexample, "%s width %d: %r" % (r.id, w, counterexample))

    @unittest.skipUnless(HAS_Z3, "z3 is unavailable")
    def test_every_rule_example_is_proved_at_all_widths(self) -> None:
        g = gate()
        for r in RULES:
            for w in WIDTHS:
                example = r.example(w)
                if example is None:
                    continue
                candidate = r.match(example)
                result = g.prove(example, candidate)
                self.assertEqual(result.status, "proved", "%s width %d: %s %r" % (r.id, w, result.status, result.counterexample))

    def test_alternate_rule_branches_are_sound(self) -> None:
        """Branches the examples do not reach: mirrored rotate, 0 < x, hi piece, add/sub merges, compare-of-compare, sign !=."""
        from Scripts.research.h22_expr_simplify.rules import RULES_BY_ID
        x, y = L("x", 8), L("y", 8)
        cases = [
            ("shift.rotate_mask", A("INT_AND", 8, A("INT_OR", 8, A("INT_LEFT", 8, x, K(1, 1)), A("INT_RIGHT", 8, x, K(7, 8))), K(0x01, 8))),
            ("shift.rotate_mask", A("INT_AND", 8, A("INT_OR", 8, A("INT_LEFT", 8, x, K(3, 8)), A("INT_RIGHT", 8, x, K(5, 8))), K(0xF8, 8))),
            ("cmp.unsigned_zero", A("INT_LESSEQUAL", BOOL_WIDTH, x, K(0, 8))),
            ("cmp.unsigned_zero", A("INT_LESSEQUAL", BOOL_WIDTH, K(0, 8), x)),
            ("ext.sub_piece", A("SUBPIECE", 8, A("PIECE", 16, x, y), K(1, 8))),
            ("assoc.add_sub_merge", A("INT_SUB", 8, A("INT_ADD", 8, x, K(3, 8)), K(5, 8))),
            ("assoc.add_sub_merge", A("INT_ADD", 8, A("INT_SUB", 8, x, K(3, 8)), K(5, 8))),
            ("assoc.shift_merge", A("INT_SRIGHT", 8, A("INT_SRIGHT", 8, x, K(5, 8)), K(6, 8))),
            ("assoc.shift_merge", A("INT_RIGHT", 8, A("INT_RIGHT", 8, x, K(5, 8)), K(6, 8))),
            ("cmp.of_cmp_zero", A("INT_NOTEQUAL", BOOL_WIDTH, A("INT_LESS", BOOL_WIDTH, x, y), K(0, BOOL_WIDTH))),
            ("cmp.of_cmp_zero", A("INT_EQUAL", BOOL_WIDTH, A("INT_CARRY", BOOL_WIDTH, x, y), K(0, BOOL_WIDTH))),
            ("cmp.of_cmp_zero", A("INT_EQUAL", BOOL_WIDTH, A("INT_SLESSEQUAL", BOOL_WIDTH, x, y), K(0, BOOL_WIDTH))),
            ("cmp.sign_shift_zero", A("INT_NOTEQUAL", BOOL_WIDTH, A("INT_RIGHT", 8, x, K(7, 8)), K(0, 8))),
            ("cmp.negate", A("BOOL_NEGATE", BOOL_WIDTH, A("INT_SLESSEQUAL", BOOL_WIDTH, x, y))),
            ("cmp.diff_zero", A("INT_NOTEQUAL", BOOL_WIDTH, A("INT_SUB", 8, x, y), K(0, 8))),
            ("neg.add_2comp", A("INT_ADD", 8, A("INT_2COMP", 8, y), x)),
            ("canon.negative_const", A("INT_SUB", 8, x, K(0xFE, 8))),
            ("mba.and_plus_or", A("INT_ADD", 8, A("INT_OR", 8, y, x), A("INT_AND", 8, x, y))),
            ("mba.xor_plus_two_and", A("INT_ADD", 8, A("INT_MULT", 8, A("INT_AND", 8, y, x), K(2, 8)), A("INT_XOR", 8, x, y))),
            ("mba.x_minus_and", A("INT_SUB", 8, x, A("INT_AND", 8, y, x))),
            ("mba.demorgan_collapse", A("INT_NEGATE", 8, A("INT_AND", 8, A("INT_NEGATE", 8, x), A("INT_NEGATE", 8, y)))),
            ("shift.and_then_left_mask", A("INT_AND", 8, A("INT_LEFT", 8, A("INT_AND", 8, x, K(0x3F, 8)), K(3, 8)), K(0xF0, 8))),
            ("ext.sub_and_ones", A("SUBPIECE", 8, A("INT_AND", 16, L("p", 16), K(0x10FF, 16)), K(0, 8))),
        ]
        for rule_id, tree in cases:
            candidate = RULES_BY_ID[rule_id].match(tree)
            self.assertIsNotNone(candidate, "%s did not match %s" % (rule_id, tree.canonical()))
            self.assertIsNone(semantics.exhaustive_equivalent(tree, candidate), "%s on %s" % (rule_id, tree.canonical()))
            self.assertTrue(cost(candidate) < cost(tree), rule_id)

    def test_rule_ids_are_unique_and_versioned(self) -> None:
        ids = [r.id for r in RULES]
        self.assertEqual(len(ids), len(set(ids)))
        for r in RULES:
            self.assertGreaterEqual(r.version, 1)
            self.assertTrue(r.side_conditions)


@unittest.skipUnless(HAS_Z3, "z3 is unavailable")
class ProofGateTests(unittest.TestCase):
    def test_unsound_rule_is_refused_by_the_gate(self) -> None:
        """Mutation test: an injected wrong rule must never be applied, and is recorded as refuted."""
        def swap_subtraction(node: Node):
            if node.op == "INT_SUB":
                return Node("INT_SUB", node.width, (node.args[1], node.args[0]))
            return None
        bad = Rule("mutant.swap_sub", 1, "x - y -> y - x (WRONG)", "none", swap_subtraction,
                   lambda w: A("INT_SUB", w, L("x", w), L("y", w)), "none")
        simplifier = Simplifier(gate(), rules=[bad])
        outcome = simplifier.simplify(A("INT_SUB", 32, L("y", 32), L("x", 32)))
        self.assertEqual(outcome.kind, "unchanged")
        self.assertEqual(outcome.rewrites_applied, 0)
        self.assertEqual(len(outcome.refuted), 1)
        self.assertEqual(outcome.refuted[0].result, "refuted")

    def test_byte_boolean_and_true_is_refused_without_the_comparison_guard(self) -> None:
        def and_true(node: Node):
            if node.op == "BOOL_AND" and node.args[1].is_const and node.args[1].value == 1:
                return node.args[0]
            return None
        bad = Rule("mutant.bool_and_true", 1, "b && 1 -> b for any byte (WRONG)", "none", and_true,
                   lambda w: A("BOOL_AND", 8, L("b", 8), K(1, 8)), "none")
        outcome = Simplifier(gate(), rules=[bad]).simplify(A("BOOL_AND", 8, L("b", 8), K(1, 8)))
        self.assertEqual(outcome.kind, "unchanged")
        self.assertEqual(outcome.refuted[0].rule_id, "mutant.bool_and_true")

    def test_certificates_bind_widths_and_query_hash(self) -> None:
        outcome = Simplifier(gate()).simplify(A("INT_ADD", 16, L("x", 16), K(0, 16)))
        self.assertEqual(outcome.kind, "simplified")
        self.assertEqual(outcome.result, L("x", 16))
        self.assertEqual(len(outcome.certificates), 1)
        c = outcome.certificates[0].to_json()
        self.assertEqual(c["ruleId"], "ident.neutral")
        self.assertEqual(c["rootWidth"], 16)
        self.assertEqual(c["leafWidths"], {"x": 16})
        self.assertEqual(len(c["querySha256"]), 64)
        self.assertEqual(c["result"], "proved")
        self.assertIsNotNone(outcome.whole_proof)
        self.assertTrue(outcome.whole_proof.proved)

    def test_timeout_or_unknown_blocks_the_rewrite(self) -> None:
        """A solver that answers unknown/timeout must leave the expression unchanged with a typed outcome."""
        from Scripts.research.h22_expr_simplify.proof import ProofResult

        class StuckGate(ProofGate):
            def prove(self, lhs, rhs, budget=None):
                if budget is not None:
                    budget.charge(0.001)
                return ProofResult("timeout", "ob", "q", "z3", self.solver_version, 1.0, detail="timeout")
        tree = A("INT_ADD", 32, L("x", 32), K(0, 32))
        outcome = Simplifier(StuckGate(), Caps()).simplify(tree)
        self.assertEqual(outcome.kind, "solver_unknown")
        self.assertEqual(outcome.result, tree)
        self.assertEqual(outcome.rewrites_applied, 0)
        self.assertEqual(len(outcome.blocked), 1)
        self.assertEqual(outcome.blocked[0].result, "timeout")

    def test_fresh_leaf_candidate_is_refused(self) -> None:
        """A rule may not introduce an input the original did not have, even if z3 would prove it."""
        def fresh(node: Node):
            if node.op == "INT_AND" and node.args[1].is_const and node.args[1].value == 0:
                return A("INT_AND", node.width, L("zzz_fresh", node.width), K(0, node.width))
            return None
        bad = Rule("mutant.fresh_leaf", 1, "x & 0 -> fresh & 0", "none", fresh,
                   lambda w: A("INT_AND", w, L("x", w), K(0, w)), "none")
        outcome = Simplifier(gate(), rules=[bad]).simplify(A("INT_AND", 8, A("INT_ADD", 8, L("x", 8), L("y", 8)), K(0, 8)))
        self.assertEqual(outcome.kind, "unchanged")
        self.assertEqual(outcome.solver_calls, 0)

    def test_two_width_leaf_is_a_typed_outcome(self) -> None:
        outcome = Simplifier(gate()).simplify(Node("INT_ADD", 32, (A("INT_ZEXT", 32, L("x", 16)), L("x", 32))))
        self.assertEqual(outcome.kind, "unsupported_op")
        outcome.to_json()

    def test_refuted_candidates_do_not_count_as_pending_work(self) -> None:
        def swap_sub(node: Node):
            return Node("INT_SUB", node.width, (node.args[1], node.args[0])) if node.op == "INT_SUB" else None
        bad = Rule("mutant.swap_sub", 1, "wrong", "none", swap_sub, lambda w: A("INT_SUB", w, L("x", w), L("y", w)), "none")
        tree = A("INT_SUB", 32, A("INT_ADD", 32, L("x", 32), K(0, 32)), L("y", 32))
        outcome = Simplifier(gate(), Caps(max_iterations=1), rules=[bad] + list(RULES)).simplify(tree)
        self.assertEqual(outcome.kind, "simplified")
        self.assertEqual(str(outcome.result), "(x - y)")


@unittest.skipUnless(HAS_Z3, "z3 is unavailable")
class SimplifierBehaviourTests(unittest.TestCase):
    def test_ubfiz_shape_simplifies_to_shift_and_mask(self) -> None:
        """The raw SLEIGH form of `ubfiz x0, x0, #2, #61` (rotate, two masks)."""
        x = L("x0", 64)
        rotated = A("INT_OR", 64, A("INT_RIGHT", 64, x, K(0x3E, 64)), A("INT_LEFT", 64, x, K(2, 64)))
        raw = A("INT_AND", 64, A("INT_AND", 64, rotated, K(0x7FFFFFFFFFFFFFFC, 64)), K(0x7FFFFFFFFFFFFFFF, 64))
        outcome = Simplifier(gate()).simplify(raw)
        self.assertEqual(outcome.kind, "simplified")
        self.assertEqual(str(outcome.result), "((x0 << 2) & 0x7ffffffffffffffc)")
        self.assertTrue(outcome.whole_proof.proved)
        self.assertTrue({"assoc.const_merge", "shift.rotate_mask"} <= set(outcome.rule_counts))

    def test_mba_identity_collapses(self) -> None:
        x, y = L("x", 32), L("y", 32)
        obfuscated = A("INT_ADD", 32, A("INT_AND", 32, x, y), A("INT_OR", 32, y, x))
        outcome = Simplifier(gate()).simplify(obfuscated)
        self.assertEqual(outcome.kind, "simplified")
        self.assertEqual(outcome.result.canonical(), "(INT_ADD:32 x:32 y:32)")

    def test_output_is_deterministic_under_operand_reordering(self) -> None:
        x, y = L("x", 32), L("y", 32)
        a = A("INT_ADD", 32, A("INT_AND", 32, x, y), A("INT_OR", 32, x, y))
        b = A("INT_ADD", 32, A("INT_OR", 32, y, x), A("INT_AND", 32, y, x))
        ra, rb = Simplifier(gate()).simplify(a), Simplifier(gate()).simplify(b)
        self.assertEqual(ra.result, rb.result)

    def test_differential_fuzz_random_expressions(self) -> None:
        """Simplified output equals the original: exhaustively at small widths, randomly at 64 bits."""
        rng = random.Random(20261021)
        simplifier = Simplifier(gate())
        simplified_count = 0
        for i in range(120):
            width = rng.choice((1, 2, 3, 4, 8, 16, 32, 64))
            tree = random_expression(rng, width, depth=rng.randrange(1, 4), leaves=2)
            outcome = simplifier.simplify(tree)
            self.assertIn(outcome.kind, ("simplified", "unchanged", "solver_unknown", "budget_exhausted"), outcome.detail)
            self.assertEqual(outcome.refuted, [], "refuted candidate on %s" % tree.canonical())
            if outcome.kind == "simplified":
                simplified_count += 1
                if width <= 4:
                    self.assertIsNone(semantics.exhaustive_equivalent(tree, outcome.result))
                else:
                    self.assertIsNone(semantics.random_equivalent(tree, outcome.result, samples=400, seed=i))
            else:
                self.assertEqual(outcome.result, tree)
        self.assertGreater(simplified_count, 10)

    def test_budget_exhaustion_is_truthful(self) -> None:
        x = L("x", 32)
        chain = x
        for i in range(12):
            chain = A("INT_ADD", 32, chain, K(i + 1, 32))
        outcome = Simplifier(gate(), Caps(max_rewrites=2)).simplify(chain)
        self.assertEqual(outcome.kind, "budget_exhausted")
        self.assertEqual(outcome.result, chain)
        self.assertEqual(outcome.rewrites_applied, 2)  # the proved steps are retained as evidence

    def test_oversized_expression_is_not_attempted(self) -> None:
        x = L("x", 8)
        tree = x
        for _ in range(30):
            tree = A("INT_XOR", 8, tree, x)
        outcome = Simplifier(gate(), Caps(max_nodes=10)).simplify(tree)
        self.assertEqual(outcome.kind, "budget_exhausted")
        self.assertEqual(outcome.solver_calls, 0)

    def test_cancellation_path(self) -> None:
        calls = {"n": 0}

        def cancel() -> bool:
            calls["n"] += 1
            return calls["n"] > 3
        tree = A("INT_ADD", 32, A("INT_ADD", 32, A("INT_ADD", 32, L("x", 32), K(1, 32)), K(2, 32)), K(3, 32))
        outcome = Simplifier(gate(), cancel=cancel).simplify(tree)
        self.assertEqual(outcome.kind, "cancelled")
        self.assertEqual(outcome.result, tree)

    def test_solver_unavailable_outcome(self) -> None:
        g = gate()
        g._z3 = None
        outcome = Simplifier(g).simplify(A("INT_ADD", 32, L("x", 32), K(0, 32)))
        self.assertEqual(outcome.kind, "solver_unavailable")
        self.assertEqual(outcome.rewrites_applied, 0)


class SolverFreeSimplifierTests(unittest.TestCase):
    def test_malformed_input_reports_unsupported_op(self) -> None:
        bad = Node("INT_ADD", 32, (L("x", 32), L("y", 16)))
        outcome = Simplifier(ProofGate()).simplify(bad)
        self.assertEqual(outcome.kind, "unsupported_op")


class ExtractionTests(unittest.TestCase):
    """Effect boundaries on a hand-built DCP-03 result shape (no lifter needed)."""

    @staticmethod
    def result(ops, storage):
        values = [{"id": k, "space": v[0], "offset": "0x%x" % v[1], "size": v[2], "storageClass": v[3],
                   "registerName": None, "scopeInstructionAddress": None} for k, v in storage.items()]
        pcode_ops, ssa_values, bindings = [], [], []
        ssa_of_storage = {}
        for k, v in storage.items():
            kind = "constant" if v[3] == "constant" else ("address" if v[3] == "memory" else "entry")
            ssa_values.append({"id": "s_" + k, "kind": kind, "storageValueId": k, "definingPcodeOpId": None})
            ssa_of_storage[k] = "s_" + k
        for index, (opcode, output, inputs) in enumerate(ops):
            op_id = "op%06d" % index
            pcode_ops.append({"id": op_id, "instructionIndex": index, "sequence": 0, "opcode": opcode,
                              "output": output, "inputs": inputs, "directTargetAddress": None,
                              "sourceRange": {"imageId": "i", "startAddress": "0x%x" % (0x1000 + 4 * index),
                                              "endAddressExclusive": "0x%x" % (0x1004 + 4 * index)}})
            in_ssa = [ssa_of_storage[i] for i in inputs]
            out_ssa = None
            if output is not None:
                out_ssa = "d_%s" % op_id
                ssa_values.append({"id": out_ssa, "kind": "operationResult", "storageValueId": output,
                                   "definingPcodeOpId": op_id})
                ssa_of_storage[output] = out_ssa
            bindings.append({"id": "bind%06d" % index, "pcodeOpId": op_id, "inputSsaValueIds": in_ssa,
                             "outputSsaValueId": out_ssa})
        block = {"id": "block000000", "instructionIndices": list(range(len(ops)))}
        return {"values": values, "pcodeOps": pcode_ops, "ssaValues": ssa_values, "ssaBindings": bindings,
                "basicBlocks": [block]}

    def test_load_call_and_store_stay_leaves(self) -> None:
        from Scripts.research.h22_expr_simplify.extract import extract
        storage = {"x0": ("register", 0x4000, 8, "register"), "x1": ("register", 0x4008, 8, "register"),
                   "u1": ("unique", 0x100, 8, "temporary"), "u2": ("unique", 0x200, 8, "temporary"),
                   "c8": ("const", 8, 8, "constant"), "ram": ("ram", 0x2000, 8, "memory"),
                   "u3": ("unique", 0x300, 8, "temporary")}
        ops = [
            ("INT_ADD", "u1", ["x0", "c8"]),       # pure, used once by LOAD -> root (STORE/LOAD never inline it)
            ("LOAD", "u2", ["ram", "u1"]),         # effect: its output is an opaque leaf
            ("INT_XOR", "u3", ["u2", "c8"]),       # pure root whose leaf is the LOAD output
            ("STORE", None, ["ram", "x1", "u3"]),  # effect
            ("CALL", None, ["ram"]),               # effect barrier
            ("INT_AND", "x0", ["x1", "c8"]),       # pure root after a call: x1 is an entry value here
        ]
        found = extract(self.result(ops, storage))
        kinds = {e.root_op for e in found.expressions}
        self.assertEqual(kinds, {"INT_ADD", "INT_XOR", "INT_AND"})
        xor = next(e for e in found.expressions if e.root_op == "INT_XOR")
        self.assertEqual(set(xor.leaf_reasons.values()), {"effect:LOAD"})
        self.assertEqual(found.classification["effect_boundary"], 3)
        self.assertEqual(found.classification["pure_root"], 3)

    def test_call_between_definition_and_use_blocks_inlining(self) -> None:
        from Scripts.research.h22_expr_simplify.extract import extract
        storage = {"x0": ("register", 0x4000, 8, "register"), "c1": ("const", 1, 8, "constant"),
                   "x2": ("register", 0x4010, 8, "register"), "ram": ("ram", 0x2000, 8, "memory")}
        ops = [("INT_ADD", "x2", ["x0", "c1"]), ("CALL", None, ["ram"]), ("INT_XOR", "x0", ["x2", "c1"])]
        found = extract(self.result(ops, storage))
        xor = next(e for e in found.expressions if e.root_op == "INT_XOR")
        self.assertEqual(xor.inlined_ops, 0)
        self.assertEqual(list(xor.leaf_reasons.values()), ["cross_block_or_barrier"])

    def test_overlapping_write_between_definition_and_use_blocks_inlining(self) -> None:
        from Scripts.research.h22_expr_simplify.extract import extract
        storage = {"w0": ("register", 0x4000, 4, "register"), "x0": ("register", 0x4000, 8, "register"),
                   "c1": ("const", 1, 4, "constant"), "c8": ("const", 1, 8, "constant"),
                   "u": ("unique", 0x10, 4, "temporary"), "u2": ("unique", 0x20, 4, "temporary")}
        ops = [("INT_ADD", "w0", ["u", "c1"]), ("INT_XOR", "x0", ["x0", "c8"]), ("INT_AND", "u2", ["w0", "c1"])]
        found = extract(self.result(ops, storage))
        and_expr = next(e for e in found.expressions if e.root_op == "INT_AND")
        self.assertEqual(and_expr.inlined_ops, 0)

    def test_straight_line_temporaries_inline_into_one_tree(self) -> None:
        from Scripts.research.h22_expr_simplify.extract import extract
        storage = {"x0": ("register", 0x4000, 8, "register"), "c2": ("const", 2, 8, "constant"),
                   "u1": ("unique", 0x10, 8, "temporary"), "u2": ("unique", 0x20, 8, "temporary"),
                   "x1": ("register", 0x4008, 8, "register")}
        ops = [("INT_LEFT", "u1", ["x0", "c2"]), ("INT_AND", "u2", ["u1", "c2"]), ("INT_OR", "x1", ["u2", "x0"])]
        found = extract(self.result(ops, storage))
        self.assertEqual(len(found.expressions), 1)
        self.assertEqual(found.expressions[0].inlined_ops, 2)
        self.assertEqual(found.classification["pure_inlined"], 2)
        self.assertEqual(str(found.expressions[0].tree), "(((s_x0 << 2) & 2) | s_x0)")

    def test_wider_write_between_a_read_and_its_consumer_blocks_inlining(self) -> None:
        """w1 = w0 ; x0 = x5 ; b = (w1 == w0): the two w0 reads are different values."""
        from Scripts.research.h22_expr_simplify.extract import extract
        storage = {"w0": ("register", 0x4000, 4, "register"), "x0": ("register", 0x4000, 8, "register"),
                   "x5": ("register", 0x4028, 8, "register"), "w1": ("register", 0x4008, 4, "register")}
        ops = [("COPY", "w1", ["w0"]), ("COPY", "x0", ["x5"]), ("INT_EQUAL", "u", ["w1", "w0"])]
        storage["u"] = ("unique", 0x10, 1, "temporary")
        found = extract(self.result(ops, storage))
        eq = next(e for e in found.expressions if e.root_op == "INT_EQUAL")
        self.assertEqual(eq.inlined_ops, 0)
        self.assertIn("clobbered_input", eq.leaf_reasons.values())
        self.assertEqual(found.classification["pure_root"], 3)
        self.assertEqual(found.classification["pure_inlined"], 0)

    def test_phi_incoming_counts_as_a_use_and_is_never_inlined(self) -> None:
        from Scripts.research.h22_expr_simplify.extract import extract
        storage = {"x0": ("register", 0x4000, 8, "register"), "c1": ("const", 1, 8, "constant"),
                   "x1": ("register", 0x4008, 8, "register")}
        ops = [("INT_ADD", "x1", ["x0", "c1"])]
        result = self.result(ops, storage)
        result["phis"] = [{"id": "phi000000", "blockId": "block000000", "storageValueId": "x1",
                           "outputSsaValueId": "s_phi", "incoming": [{"ssaValueId": "d_op000000"}], "isTrivial": False}]
        found = extract(result)
        self.assertEqual(len(found.expressions), 1)
        self.assertFalse(found.expressions[0].dead)
        self.assertEqual(found.expressions[0].inlined_ops, 0)

    def test_division_with_variable_divisor_is_a_boundary(self) -> None:
        from Scripts.research.h22_expr_simplify.extract import extract
        storage = {"x0": ("register", 0x4000, 8, "register"), "x1": ("register", 0x4008, 8, "register"),
                   "c0": ("const", 0, 8, "constant"), "u": ("unique", 0x10, 8, "temporary"),
                   "u2": ("unique", 0x20, 8, "temporary")}
        ops = [("INT_DIV", "u", ["x0", "x1"]), ("INT_DIV", "u2", ["x0", "c0"]), ("INT_ADD", "x0", ["u", "u2"])]
        found = extract(self.result(ops, storage))
        self.assertEqual(found.classification["division_domain"], 2)
        add = found.expressions[0]
        self.assertEqual(set(add.leaf_reasons.values()), {"division_domain"})


class EvaluationMetricTests(unittest.TestCase):
    """Report arithmetic on synthetic records (no solver, no lifter)."""

    @staticmethod
    def record(outcome: str, before: int, after: int, rules, unused=False, leaves=True, text_changed=True):
        return {"outcome": outcome, "originalSize": before, "resultSize": after, "originalDepth": 2, "resultDepth": 2,
                "ruleCounts": dict(rules), "unusedInFunction": unused, "hasLeaves": leaves, "textChanged": text_changed,
                "certificates": [{"result": "proved", "cached": False, "elapsedMs": 0.2, "querySha256": "ab"}] * len(rules),
                "refuted": [], "blocked": [], "wholeProof": None, "solverCalls": len(rules), "solverSeconds": 0.001,
                "elapsedSeconds": 0.002, "detail": "", "rewritesApplied": len(rules)}

    def test_summary_separates_material_from_trivial_and_counts_zero_reductions(self) -> None:
        from Scripts.research.h22_expr_simplify import evaluate
        functions = [{"lift": "ok", "pcodeOpCount": 10, "liftSeconds": 0.1,
                      "classification": {"pure_root": 4, "pure_inlined": 2, "marker": 2, "effect_boundary": 2}}]
        records = [
            self.record("simplified", 2, 1, {"ident.copy": 1}),                       # trivial
            self.record("simplified", 3, 1, {"fold.constant": 1}, leaves=False),       # constant-only
            self.record("simplified", 3, 3, {"canon.negative_const": 1}),              # material, zero node reduction
            self.record("simplified", 8, 4, {"shift.rotate_mask": 1}, unused=True),    # material but unused
            self.record("unchanged", 3, 3, {}),
        ]
        summary = evaluate.summarize(functions, records)
        self.assertEqual(summary["pcodeOps"]["purePerOp"], 0.75)          # markers excluded from the denominator
        self.assertEqual(summary["materiallySimplified"]["count"], 2)
        self.assertEqual(summary["materiallySimplified"]["usedInFunction"], 1)
        self.assertEqual(summary["materiallySimplified"]["zeroNodeReduction"], 1)
        self.assertEqual(summary["primary"], {"description": summary["primary"]["description"], "numerator": 1,
                                              "denominator": 3, "fraction": round(1 / 3, 4)})
        self.assertEqual(summary["reduction"]["nodesHistogram"]["0-0"], 1)
        self.assertEqual(sum(summary["reduction"]["nodesHistogram"].values()), 4)
        self.assertEqual(evaluate.percentiles([1, 2, 3, 4])["p50"], 3)

    def test_thunk_symbols_are_excluded(self) -> None:
        from Scripts.research.h22_expr_simplify import lift
        self.assertTrue(lift.is_thunk("_bzero__thunk"))
        self.assertFalse(lift.is_thunk("_bzero"))


@unittest.skipUnless(HAS_PYPCODE and HAS_Z3, "pypcode or z3 is unavailable")
class LiftIntegrationTests(unittest.TestCase):
    def test_fixture_function_lifts_extracts_and_simplifies(self) -> None:
        from Scripts.research.h22_expr_simplify import lift
        from Scripts.research.h22_expr_simplify.extract import extract
        # add w0,w0,w2 ; ubfiz x0,x0,#2,#61 ; and w1,w1,#0xff ; eor x2,x2,x2 ; ldr x3,[x1] ; bl +0x100 ; ret
        code = bytes.fromhex("0000020a00f07ed3211c0012420002ca230040f940000094c0035fd6")
        request = lift.build_request(image_id="fixture", image_uuid="00000000-0000-4000-8000-00000000c0de",
                                     function_name="_fixture", entry=0x100001000, code=code,
                                     preferred_load_address=0x100000000)
        result, error = lift.lift_outcome(request)
        self.assertIsNone(error)
        found = extract(result)
        texts = {e.root_op: str(e.tree) for e in found.expressions}
        self.assertIn("INT_AND", texts)
        simplifier = Simplifier(gate())
        outcomes = {e.root_ssa: simplifier.simplify(e.tree) for e in found.expressions}
        kinds = {o.kind for o in outcomes.values()}
        self.assertTrue(kinds <= {"simplified", "unchanged"})
        self.assertTrue(any(o.kind == "simplified" and "<< 2" in str(o.result) for o in outcomes.values()))
        self.assertGreaterEqual(found.classification["effect_boundary"], 3)

    def test_sxtw_after_wider_write_does_not_collapse_to_zero(self) -> None:
        """sxtw x1, w0 ; mov x0, x5 ; sub x2, x1, w0, sxtw ; ret  --  x2 is not identically zero."""
        from Scripts.research.h22_expr_simplify import lift
        from Scripts.research.h22_expr_simplify.extract import extract
        code = bytes.fromhex("017c4093e003 05aa22c020cbc0035fd6".replace(" ", ""))
        request = lift.build_request(image_id="fixture", image_uuid="00000000-0000-4000-8000-00000000c0df",
                                     function_name="_clobber", entry=0x100001000, code=code, preferred_load_address=0x100000000)
        result, error = lift.lift_outcome(request)
        self.assertIsNone(error)
        found = extract(result)
        sub = next(e for e in found.expressions if e.root_op == "INT_SUB")
        outcome = Simplifier(gate()).simplify(sub.tree)
        self.assertNotEqual(outcome.result.canonical(), "#64:0x0")
        self.assertIn("clobbered_input", sub.leaf_reasons.values())


if __name__ == "__main__":
    unittest.main()
