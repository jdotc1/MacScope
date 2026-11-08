"""Tests for the navigator-engine contract v1 reference (Scripts/research/n0_contract)."""
from __future__ import annotations

import copy
import json
import random
import sys
import tempfile
import unittest
from pathlib import Path

RESEARCH = Path(__file__).resolve().parents[1] / "research"
sys.path.insert(0, str(RESEARCH))

from n0_contract import adapters, cli, contract as C  # noqa: E402
from h18_known_library import project  # noqa: E402

try:
    import jsonschema  # optional: the structural schema is cross-checked when available
except ImportError:  # pragma: no cover
    jsonschema = None

SCHEMA = json.loads((C.CONTRACT_DIR / "navigator-engine.schema.json").read_text())
CHAIN = "test-toolchain"
# A well-formed certificate reference; resolution is the store's job, so the fixture need not exist.
CERT = "sha256:" + "0" * 64
IMG = "test.dylib"


def fn(start: int) -> dict:
    return C.subject("function", f"{start:#x}", IMG)


def auth(subj, predicate, value, ref="lc"):
    return C.make_fact(subj, predicate, value, "authoritative", [C.provenance("loaderRecord", ref)], CHAIN)


def derived(subj, predicate, value, parents, tier=2, rule="r"):
    return C.make_fact(subj, predicate, value, "derived", [C.provenance("rule", "x", rule, "1")], CHAIN,
                       tier=tier, derived_from=parents)


class CanonicalAndIdTests(unittest.TestCase):
    def test_canonical_matches_documented_json_dumps(self):
        value = {"b": [1, True, None, "é\n\u0001\"\\"], "a": {"z": 0, "_y": "日本"}}
        self.assertEqual(C.canonical(value), '{"a":{"_y":"日本","z":0},"b":[1,true,null,"é\\n\\u0001\\"\\\\"]}')

    def test_canonical_refuses_floats_and_non_identifier_keys(self):
        for bad in (1.5, {"a b": 1}, {"é": 1}, [{"1x": 0}], {"a": float("nan")}):
            with self.assertRaises(C.ContractError):
                C.canonical(bad)

    def test_fact_id_depends_on_rule_not_on_evidence_reference(self):
        s = fn(0x10)
        a = C.make_fact(s, "hasName", "f", "proven", [C.provenance("rule", "one", "r", "1"), C.provenance("proofCertificate", CERT)], CHAIN)
        b = C.make_fact(s, "hasName", "f", "proven", [C.provenance("rule", "two", "r", "1"), C.provenance("proofCertificate", CERT)], CHAIN)
        c = C.make_fact(s, "hasName", "f", "proven", [C.provenance("rule", "one", "r", "2"), C.provenance("proofCertificate", CERT)], CHAIN)
        self.assertEqual(a["id"], b["id"])
        self.assertNotEqual(a["id"], c["id"])

    def test_annotation_id_ignores_citation_order(self):
        x = C.make_annotation("s", 1, "navigator", "rename", fn(1), "hasName", "n", cites=["f-" + "1" * 32, "f-" + "2" * 32], rationale="r")
        y = C.make_annotation("s", 1, "navigator", "rename", fn(1), "hasName", "n", cites=["f-" + "2" * 32, "f-" + "1" * 32], rationale="r")
        self.assertEqual(x["id"], y["id"])


def _mutations(record: dict):
    """Structural mutations: (label, mutated record)."""
    def m(label, fn_):
        clone = copy.deepcopy(record)
        fn_(clone)
        return label, clone
    yield m("drop-kind", lambda r: r.pop("kind"))
    yield m("extra-key", lambda r: r.__setitem__("extra", 1))
    yield m("schema-2", lambda r: r.__setitem__("schemaVersion", 2))
    yield m("schema-bool", lambda r: r.__setitem__("schemaVersion", True))
    if "subject" in record:
        yield m("subject-kind", lambda r: r["subject"].__setitem__("kind", "galaxy"))
        yield m("subject-ref-empty", lambda r: r["subject"].__setitem__("ref", ""))
        yield m("subject-extra", lambda r: r["subject"].__setitem__("x", "y"))
    if record.get("kind") == "Fact":
        yield m("status", lambda r: r.__setitem__("status", "probable"))
        yield m("prov-empty", lambda r: r.__setitem__("provenance", []))
        yield m("prov-half-rule", lambda r: r["provenance"][0].pop("ruleVersion", None) or r["provenance"][0].__setitem__("rule", "x"))
        yield m("tier-on-authoritative", lambda r: r.__setitem__("tier", 2) if r["status"] == "authoritative" else r.__setitem__("tier", 9))
        yield m("float-value", lambda r: r.__setitem__("value", 1.5))
        yield m("bad-key-value", lambda r: r.__setitem__("value", {"a-b": 1}))
        yield m("revert-pattern", lambda r: r.__setitem__("revert", "undo"))
    if record.get("kind") == "Annotation":
        yield m("author", lambda r: r.__setitem__("author", "model"))
        yield m("action", lambda r: r.__setitem__("action", "delete"))
        yield m("seq-negative", lambda r: r.__setitem__("seq", -1))
        yield m("cites-dup", lambda r: r.__setitem__("cites", r["cites"] + r["cites"][:1]) if r["cites"] else r.__setitem__("cites", ["bad"]))
    if record.get("kind") == "FrontierItem":
        yield m("leverage-negative", lambda r: r.__setitem__("leverage", -1))
        yield m("cost-key", lambda r: r.__setitem__("cost", {"dollars": 1}))
        yield m("refusal-code", lambda r: r.__setitem__("reason", [{"code": "nope", "detail": "", "retryable": False}]))
        yield m("primitive-shape", lambda r: r.__setitem__("primitives", [{"name": "x"}]))


class StructuralValidationTests(unittest.TestCase):
    def setUp(self):
        s = fn(0x100)
        self.boundary = auth(s, "isFunctionStart", True)
        self.records = [
            self.boundary,
            derived(s, "hasName", "n", [[self.boundary["id"]]]),
            C.make_fact(s, "libraryIdentity", {"alternatives": [{"name": "a"}, {"name": "b"}]}, "candidate",
                        [C.provenance("signatureRecord", "p")], CHAIN, tier=1),
            C.make_fact(s, "hasType", None, "unknown", [C.provenance("rule", "x", "r", "1")], CHAIN),
            C.make_frontier(s, "unnamedFunction", "d", CHAIN, blocked_by=[self.boundary["id"]],
                            primitives=[{"name": "p", "preconditions": []}], cost={"bytes": 4}, leverage=1,
                            reason=[C.refusal("budgetExceeded", "x", True)]),
            C.make_annotation("s", 0, "navigator", "rename", s, "hasName", "n", cites=[self.boundary["id"]], rationale="r"),
            C.make_annotation("s", 1, "analyst", "rename", s, "hasName", "m"),
            C.make_result("p", "1", s, {"instructions": 1}, facts=[self.boundary]),
            C.make_result("p", "1", s, {}, refused=C.refusal("outOfBounds", "x")),
        ]

    def test_valid_records_pass(self):
        for record in self.records:
            self.assertEqual(C.validate_record(record), [], record)

    def test_mutations_fail_in_reference_validator(self):
        for record in self.records:
            for label, mutated in _mutations(record):
                self.assertTrue(C.validate_record(mutated), f"{record['kind']} {label} accepted")

    @unittest.skipIf(jsonschema is None, "jsonschema not installed")
    def test_reference_validator_agrees_with_json_schema_structurally(self):
        validator = jsonschema.Draft202012Validator(SCHEMA)
        for record in self.records:
            self.assertTrue(validator.is_valid(record), list(validator.iter_errors(record))[:1])
            for label, mutated in _mutations(record):
                schema_ok = validator.is_valid(mutated)
                ours_ok = not C.validate_record(mutated)
                # The reference validator is stricter (vocabulary of predicates/gaps, id recomputation);
                # it must never accept what the schema rejects.
                if not schema_ok:
                    self.assertFalse(ours_ok, f"{record['kind']} {label}: schema rejects, reference accepts")

    def test_semantic_rules_beyond_schema(self):
        s = fn(0x100)
        wrong_id = dict(self.boundary, id="f-" + "0" * 32, revert="revert:f-" + "0" * 32)
        self.assertIn("recomputed", " ".join(C.validate_record(wrong_id)))
        bad_predicate = C.make_fact(s, "smellsLike", "x", "authoritative", [C.provenance("loaderRecord", "x")], CHAIN)
        self.assertIn("not in vocabulary", " ".join(C.validate_record(bad_predicate)))
        bad_type = C.make_fact(s, "isGeneric", "yes", "authoritative", [C.provenance("loaderRecord", "x")], CHAIN)
        self.assertIn("expects boolean", " ".join(C.validate_record(bad_type)))
        bad_enum = C.make_fact(s, "nominalKind", "union", "authoritative", [C.provenance("loaderRecord", "x")], CHAIN)
        self.assertIn("not allowed", " ".join(C.validate_record(bad_enum)))
        one_alt = C.make_fact(s, "libraryIdentity", {"alternatives": [{"name": "a"}]}, "candidate",
                              [C.provenance("signatureRecord", "p")], CHAIN, tier=1)
        self.assertTrue(C.validate_record(one_alt))
        nav_no_cite = C.make_annotation("s", 0, "navigator", "rename", s, "hasName", "n", rationale="r")
        self.assertTrue(C.validate_record(nav_no_cite))
        nav_no_why = C.make_annotation("s", 0, "navigator", "rename", s, "hasName", "n", cites=[self.boundary["id"]])
        self.assertTrue(C.validate_record(nav_no_why))
        derived_no_parents = C.make_fact(s, "hasName", "n", "derived", [C.provenance("rule", "x", "r", "1")], CHAIN, tier=1)
        self.assertTrue(C.validate_record(derived_no_parents))
        refusal_with_facts = C.make_result("p", "1", s, {}, facts=[self.boundary], refused=C.refusal("cancelled", ""))
        self.assertTrue(C.validate_record(refusal_with_facts))

    def test_state_cross_record_rules(self):
        s = fn(0x100)
        base = self.boundary
        child = derived(s, "hasName", "n", [[base["id"]]])
        self.assertEqual(C.validate_state(C.make_state(CHAIN, [base, child])), [])
        orphan = C.make_state(CHAIN, [child])
        self.assertEqual(C.validate_state(orphan), [])  # dangling premise: valid state, dead derivation
        self.assertNotIn(child["id"], C.Store.from_state(orphan)._live_facts())
        cand = C.make_fact(s, "libraryIdentity", {"alternatives": [{"name": "a"}, {"name": "b"}]}, "candidate",
                           [C.provenance("signatureRecord", "p")], CHAIN, tier=1)
        on_candidate = derived(s, "hasName", "n", [[cand["id"]]])
        self.assertIn("rests on candidate", " ".join(C.validate_state(C.make_state(CHAIN, [cand, on_candidate]))))
        a = derived(s, "hasName", "a", [["f-" + "b" * 32]], rule="ra")
        b = derived(s, "hasType", "b", [[a["id"]]], rule="rb")
        a = derived(s, "hasName", "a", [[b["id"]]], rule="ra")  # id unchanged: parents are not hashed
        self.assertIn("cycle", " ".join(C.validate_state(C.make_state(CHAIN, [a, b]))))
        note = C.make_annotation("s", 0, "navigator", "rename", s, "hasName", "n", cites=[child["id"]], rationale="r")
        dangling = C.make_state(CHAIN, [base], annotations=[note])
        self.assertEqual(C.validate_state(dangling), [])  # dangling citation: valid state, stale annotation
        restored = C.Store.from_state(dangling)
        self.assertEqual([a["id"] for a in restored.stale_annotations()], [note["id"]])
        self.assertIn("staleAnnotation", [i["gap"] for i in restored.frontier()])
        self.assertIn("duplicate fact", " ".join(C.validate_state(C.make_state(CHAIN, [base, base]))))


class StoreTests(unittest.TestCase):
    def test_precedence_ladder(self):
        s = fn(1)
        boundary = auth(s, "isFunctionStart", True)
        d = derived(s, "hasName", "derived_name", [[boundary["id"]]])
        p = C.make_fact(s, "hasName", "proven_name", "proven", [C.provenance("proofCertificate", CERT, "pr", "1")], CHAIN,
                        derived_from=[[boundary["id"]]])
        a = auth(s, "hasName", "symbol_name", ref="symtab")
        store = C.Store(CHAIN, [boundary, d])
        self.assertEqual(store.display(s, "hasName").source, "derived")
        nav = C.make_annotation("n", 0, "navigator", "rename", s, "hasName", "nav_name", cites=[d["id"]], rationale="r")
        self.assertIsNone(store.accept(nav))
        self.assertEqual(store.display(s, "hasName").values, ('"nav_name"',))
        store.base_facts.append(p)
        self.assertEqual(store.display(s, "hasName").source, "proven")
        an = C.make_annotation("x", 1, "analyst", "rename", s, "hasName", "analyst_name")
        self.assertIsNone(store.accept(an))
        self.assertEqual(store.display(s, "hasName").source, "analyst")
        store.base_facts.append(a)
        self.assertEqual(store.display(s, "hasName"), C.Displayed("authoritative", ('"symbol_name"',), (a["id"],)))

    def test_navigator_cannot_contradict_authority_but_analyst_can(self):
        s = fn(2)
        a = auth(s, "hasName", "sym")
        store = C.Store(CHAIN, [a])
        nav = C.make_annotation("n", 0, "navigator", "rename", s, "hasName", "other", cites=[a["id"]], rationale="r")
        self.assertEqual(store.accept(nav)["code"], "conflictsWithAuthority")
        agree = C.make_annotation("n", 1, "navigator", "rename", s, "hasName", "sym", cites=[a["id"]], rationale="r")
        self.assertIsNone(store.accept(agree))
        analyst = C.make_annotation("x", 2, "analyst", "rename", s, "hasName", "other")
        self.assertIsNone(store.accept(analyst))
        self.assertEqual(store.display(s, "hasName").source, "authoritative")

    def test_refusals(self):
        s = fn(3)
        a = auth(s, "isFunctionStart", True)
        store = C.Store(CHAIN, [a])
        ghost = C.make_annotation("n", 0, "navigator", "rename", s, "hasName", "x", cites=["f-" + "9" * 32], rationale="r")
        self.assertEqual(store.accept(ghost)["code"], "unknownFact")
        self.assertEqual(store.revert("n", a["revert"])["code"], "notReversible")
        self.assertEqual(store.revert("n", "revert:zzz")["code"], "malformedInput")
        ok = C.make_annotation("n", 1, "navigator", "rename", s, "hasName", "x", cites=[a["id"]], rationale="r")
        self.assertIsNone(store.accept(ok))
        self.assertEqual(store.accept(ok)["code"], "preconditionFailed")
        self.assertIsNone(store.revert("n", ok["revert"]))
        self.assertEqual(store.revert("n", ok["revert"])["code"], "unknownFact")
        bad = C.make_result("p", "1", s, {}, facts=[derived(s, "hasName", "y", [["f-" + "8" * 32]])])
        self.assertEqual(store.add_result("n", bad)["code"], "unknownFact")
        refused = C.make_result("p", "1", s, {}, refused=C.refusal("budgetExceeded", "64 instructions"))
        self.assertEqual(store.add_result("n", refused)["code"], "budgetExceeded")

    def test_result_rejects_self_and_intra_result_cycles_without_journaling(self):
        s = fn(0x31)
        seed_a = derived(s, "hasName", "a", [["f-" + "0" * 32]], rule="a")
        self_derived = derived(s, "hasName", "a", [[seed_a["id"]]], rule="a")
        store = C.Store(CHAIN)

        self_result = C.make_result("p", "1", s, {}, facts=[self_derived])
        self.assertEqual(store.add_result("self", self_result)["code"], "preconditionFailed")
        self.assertEqual(store.journal, [])

        seed_b = derived(s, "hasType", "b", [[seed_a["id"]]], rule="b")
        cycle_a = derived(s, "hasName", "a", [[seed_b["id"]]], rule="a")
        cycle_result = C.make_result("p", "1", s, {}, facts=[cycle_a, seed_b])
        self.assertEqual(store.add_result("pair", cycle_result)["code"], "preconditionFailed")
        self.assertEqual(store.journal, [])

    def test_restore_preserves_supplied_annotation_gaps_and_regenerates_derived_once(self):
        s = fn(0x32)
        nfc = "\u00e9"
        nfd = "e\u0301"
        stale_evidence = C.make_fact(s, "isFunctionStart", True, "proven",
                                     [C.provenance("proofCertificate", CERT)], CHAIN)
        live_evidence = auth(s, "callsTarget", "target", ref="live")
        annotations = [
            C.make_annotation("navigator", 0, "navigator", "rename", s, "hasName", "stale",
                              cites=[stale_evidence["id"]], rationale="test"),
            C.make_annotation("navigator", 1, "navigator", "rename", s, "hasName", "left",
                              cites=[live_evidence["id"]], rationale="test"),
            C.make_annotation("navigator", 2, "navigator", "rename", s, "hasName", "right",
                              cites=[live_evidence["id"]], rationale="test"),
        ]
        supplied = [C.make_frontier(s, "staleAnnotation",
                                    f"{annotations[0]['id']} cites a reverted fact", nfc),
                    C.make_frontier(s, "conflictingAnnotations", "supplied conflict", nfd)]
        store = C.Store(nfd, [stale_evidence, live_evidence], supplied)
        for annotation in annotations:
            self.assertIsNone(store.accept(annotation))
        self.assertIsNone(store.revert("revert", stale_evidence["revert"]))

        state = store.to_state()
        restored = C.Store.from_state(state)

        self.assertEqual(restored.frontier(), state["frontier"])
        self.assertEqual(C.canonical(next(item for item in restored.frontier()
                                          if item["id"] == supplied[0]["id"])), C.canonical(supplied[0]))

    def test_revert_closure_respects_alternative_derivations(self):
        s = fn(4)
        p1 = C.make_fact(s, "isFunctionStart", True, "proven", [C.provenance("rule", "a", "r1", "1"), C.provenance("proofCertificate", CERT)], CHAIN)
        p2 = C.make_fact(s, "callsTarget", "x", "proven", [C.provenance("rule", "b", "r2", "1"), C.provenance("proofCertificate", CERT)], CHAIN)
        p3 = C.make_fact(s, "selectorOf", "y", "proven", [C.provenance("rule", "c", "r3", "1"), C.provenance("proofCertificate", CERT)], CHAIN)
        both = derived(s, "hasName", "n", [[p1["id"], p2["id"]], [p3["id"]]])
        grand = derived(s, "hasType", "t", [[both["id"]]])
        store = C.Store(CHAIN, [p1, p2, p3, both, grand])
        self.assertIsNone(store.revert("u", p1["revert"]))
        self.assertIn(grand["id"], store._live_facts())  # survives on the p3 derivation
        self.assertIsNone(store.revert("u", p3["revert"]))
        self.assertNotIn(both["id"], store._live_facts())
        self.assertNotIn(grand["id"], store._live_facts())
        self.assertIn(p2["id"], store._live_facts())

    def test_stale_annotation_hidden_and_reported_then_restored(self):
        s = fn(5)
        p = C.make_fact(s, "hasType", "T", "proven", [C.provenance("rule", "a", "r", "1"), C.provenance("proofCertificate", CERT)], CHAIN)
        store = C.Store(CHAIN, [p])
        nav = C.make_annotation("n", 0, "navigator", "rename", s, "hasName", "x", cites=[p["id"]], rationale="r")
        self.assertIsNone(store.accept(nav))
        self.assertIsNone(store.revert("v", p["revert"]))
        self.assertEqual(store.display(s, "hasName").source, "fallback")
        self.assertIn("staleAnnotation", [i["gap"] for i in store.frontier()])
        store.undo_session("v")
        self.assertEqual(store.display(s, "hasName").values, ('"x"',))

    def test_multi_valued_predicates_union_instead_of_conflict(self):
        s = C.subject("type", "M.T", IMG)
        f1 = auth(s, "storedField", {"name": "a", "type": "Si", "var": True})
        f2 = auth(s, "storedField", {"name": "b", "type": "SS", "var": False})
        shown = C.Store(CHAIN, [f1, f2]).display(s, "storedField")
        self.assertEqual((shown.source, len(shown.values), shown.conflict), ("authoritative", 2, False))

    def test_random_sessions_undo_to_exact_snapshot(self):
        rng = random.Random(7)
        for trial in range(60):
            subjects = [fn(0x1000 + i) for i in range(3)]
            base = [auth(s, "isFunctionStart", True) for s in subjects]
            base += [derived(s, "hasName", f"d{i}", [[base[i]["id"]]], tier=rng.randint(1, 3)) for i, s in enumerate(subjects)]
            store = C.Store(CHAIN, base)
            keys = [(s, p) for s in subjects for p in ("hasName", "hasType")]
            before = store.snapshot(keys)
            for seq in range(rng.randint(1, 12)):
                session = rng.choice(["a", "b"])
                s = rng.choice(subjects)
                live = sorted(store._live_facts())
                choice = rng.random()
                if choice < 0.4 and live:
                    store.accept(C.make_annotation(session, seq, "navigator", "rename", s, "hasName", f"n{rng.randint(0, 2)}",
                                                   cites=[rng.choice(live)], rationale="r"))
                elif choice < 0.55:
                    store.accept(C.make_annotation(session, seq, "analyst", "rename", s, "hasName", f"a{seq}"))
                elif choice < 0.8 and live:
                    parent = rng.choice(live)
                    fact = derived(s, "hasType", f"t{seq}", [[parent]], tier=2, rule=f"r{seq}")
                    store.add_result(session, C.make_result("p", "1", s, {}, facts=[fact]))
                else:
                    handles = [f["revert"] for f in store._live_facts().values() if f["status"] != "authoritative"]
                    handles += [a["revert"] for a in store.live_annotations()]
                    if handles:
                        store.revert(session, rng.choice(handles))
                persisted = store.to_state()
                self.assertEqual(C.validate_state(persisted), [], trial)
                restored = C.Store.from_state(json.loads(json.dumps(persisted)))
                self.assertEqual(restored.snapshot(keys), store.snapshot(keys), trial)
            store.undo_session("a")
            store.undo_session("b")
            self.assertEqual(store.snapshot(keys), before, trial)


class H18ParityTests(unittest.TestCase):
    """The generic contract, fed H18 results, displays exactly what `project.effective_name` does."""

    PACKS = [{"pack_id": pid, "records": [{"id": f"{pid}-{name}", "provenance": {"library_version": v}}
                                          for name in ("alpha", "beta", "gamma") for v in ("1",)]}
             for pid in ("p1", "p2")]

    def _random_case(self, rng):
        starts = [0x1000 + 0x10 * i for i in range(6)]
        functions, classifications, analyst = {}, {}, {}
        state = project.NamingState({}, min_tier=rng.choice(["low", "medium", "high"]))
        for start in starts:
            authoritative = ("sym_%x" % start, rng.choice(["symbol", "export"])) if rng.random() < 0.15 else None
            functions[start] = authoritative
            state.functions[start] = project.Function(start, *(authoritative or (None, None)))
            for _ in range(rng.randint(0, 3)):
                pack = rng.choice(self.PACKS)
                if rng.random() < 0.25:
                    ids = sorted({(rng.choice(["alpha", "beta", "gamma"]), "lib") for _ in range(3)})
                    if len(ids) < 2:
                        ids = [("alpha", "lib"), ("beta", "lib")]
                    result = {"kind": "candidates", "identities": [list(i) for i in ids], "why": "ambiguous"}
                else:
                    name = rng.choice(["alpha", "beta", "gamma"])
                    result = {"kind": "name", "identity": [name, "lib"], "record": f"{pack['pack_id']}-{name}",
                              "tier": rng.choice(["low", "medium", "high"])}
                if project.annotate(state, start, result, pack) is not None:
                    classifications.setdefault(start, []).append((result, pack))
            if rng.random() < 0.15:
                analyst[start] = "analyst_%x" % start
                project.rename(state, start, analyst[start])
        return state, functions, classifications, analyst

    def test_random_states_match_h18_effective_name(self):
        rng = random.Random(18)
        compared = 0
        for _ in range(400):
            state, functions, classifications, analyst = self._random_case(rng)
            store = adapters.h18_store(IMG, CHAIN, functions, classifications, analyst, min_tier=state.min_tier)
            self.assertEqual(C.validate_state(store.to_state()), [])
            for start in functions:
                expected = project.effective_name(state, start)
                got = adapters.h18_displayed_name(store, IMG, start)
                expected = (expected[0], "authoritative" if expected[1] in ("symbol", "export") else expected[1])
                self.assertEqual(got, expected, (start, classifications.get(start), state.min_tier))
                compared += 1
        self.assertGreater(compared, 2000)

    def test_reverting_an_identity_matches_h18_revert(self):
        pack = self.PACKS[0]
        result = {"kind": "name", "identity": ["alpha", "lib"], "record": "p1-alpha", "tier": "high"}
        store = adapters.h18_store(IMG, CHAIN, {0x10: None}, {0x10: [(result, pack)]}, {})
        self.assertEqual(adapters.h18_displayed_name(store, IMG, 0x10), ("alpha", "library-signature"))
        identity = next(f for f in store.base_facts if f["predicate"] == "libraryIdentity")
        self.assertIsNone(store.revert("analyst", identity["revert"]))
        self.assertEqual(adapters.h18_displayed_name(store, IMG, 0x10), ("sub_10", "fallback"))


class ExampleTests(unittest.TestCase):
    def test_checked_in_examples_are_valid_and_current(self):
        with tempfile.TemporaryDirectory() as tmp:
            cli.write_examples(Path(tmp))
            for path in sorted(Path(tmp).iterdir()):
                checked_in = cli.EXAMPLES / path.name
                self.assertEqual(path.read_text(), checked_in.read_text(), f"{path.name} is stale; run cli.py examples")
        for name in ("h18-demo.state.json", "n1-fixture.state.json"):
            self.assertEqual(C.validate_state(json.loads((cli.EXAMPLES / name).read_text())), [], name)
        session = json.loads((cli.EXAMPLES / "navigator-session.json").read_text())
        self.assertTrue(session["undoRestoresSnapshot"])
        self.assertEqual(C.validate_state(session["baseState"]), [])
        self.assertEqual(C.validate_state(session["finalState"]), [])
        codes = [step["outcome"]["code"] for step in session["steps"] if step["outcome"]]
        self.assertEqual(codes, ["conflictsWithAuthority", "notReversible"])

    def test_n1_sample_facts_convert_and_validate(self):
        for path in sorted((cli.REPO / "docs/roadmap/n1-swift-metadata-20261022").glob("sample-facts.*.jsonl")):
            facts, frontier = adapters.from_n1(path.read_text().splitlines(), "img")
            self.assertTrue(facts)
            self.assertEqual(C.validate_state(C.make_state("t", facts, frontier)), [], path.name)


if __name__ == "__main__":
    unittest.main()
