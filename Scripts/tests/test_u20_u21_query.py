#!/usr/bin/env python3
"""U20/U21 portable query lane: contract, adapters, predicates, recipes, extractor logic."""

from __future__ import annotations

import contextlib
import copy
import io
import itertools
import json
import random
import sqlite3
import tempfile
import unittest
from pathlib import Path

from Scripts.research.u20_u21_query import adapters, cli, contract, envelope, evaluate, facts, query, rank, runtime, service, splits
from Scripts.research.u20_u21_query.contract import ProjectionError

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "u20_u21_query"
SYNTH_FACTS = FIXTURES / "synthetic.facts.json"
SYNTH_ATLAS = FIXTURES / "synthetic.type-atlas.json"


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def write(directory: str, name: str, value) -> Path:
    path = Path(directory) / name
    path.write_text(json.dumps(value))
    return path


def synthetic_view(facts_doc=None, atlas_doc=None) -> query.View:
    with tempfile.TemporaryDirectory() as d:
        f = write(d, "f.json", facts_doc if facts_doc is not None else load(SYNTH_FACTS))
        a = write(d, "a.json", atlas_doc if atlas_doc is not None else load(SYNTH_ATLAS))
        return query.View(adapters.project(f, a, binding_asserted=True))


def function(view: query.View, address: int) -> str:
    return next(s.subject_id for s in view.subjects.values() if s.kind == "function" and s.address == address)


def fts5_available() -> bool:
    conn = sqlite3.connect(":memory:")
    try:
        return rank.probe(conn)["fts5"]
    finally:
        conn.close()


class ContractAndAdapterTests(unittest.TestCase):
    def test_join_requires_an_asserted_binding_and_reports_omitted_export_fields(self) -> None:
        with self.assertRaises(ProjectionError) as caught:
            adapters.project(SYNTH_FACTS, SYNTH_ATLAS)
        self.assertEqual(caught.exception.code, "unbound_join")
        view = synthetic_view()
        atlas = next(i for i in view.projection.inputs if i.source == "type_atlas")
        self.assertEqual(atlas.status, "partial")  # one unsupported row kind
        for field in ("declaredProperties", "swiftConformanceMethods", "swiftMethodTableResolved",
                      "methods[].isOptionalRequirement", "methods[].swiftMetadata"):
            self.assertIn(field, atlas.omitted_fields)
        self.assertIn("user-authored", atlas.detail)
        self.assertEqual(view.projection.scope.frontier_status, "unavailable")
        self.assertTrue(all(f.acceptance == "unaccepted" for f in view.projection.facts.values()))

    def test_same_address_in_two_images_has_distinct_identities_and_cannot_join(self) -> None:
        doc = load(SYNTH_FACTS)
        other = copy.deepcopy(doc)
        other["image"]["sha256"] = "ab" * 32
        with tempfile.TemporaryDirectory() as d:
            p1 = adapters.project(write(d, "1.json", doc))
            p2 = adapters.project(write(d, "2.json", other))
        a, b = (next(s for s in p.subjects.values() if s.kind == "function" and s.address == 0x1000) for p in (p1, p2))
        self.assertNotEqual(a.subject_id, b.subject_id)
        builder = contract.Builder(p1.scope)
        builder.subjects = dict(p1.subjects)
        builder.subjects[b.subject_id] = b
        with self.assertRaises(ProjectionError) as caught:
            builder.freeze()
        self.assertEqual(caught.exception.code, "cross_scope_subject")
        builder = contract.Builder(p1.scope)
        builder.subjects = dict(p1.subjects)
        builder.fact("call.direct", a.subject_id, b.subject_id, ("instruction", 0x1004, None), "function_start", "t", "t")
        with self.assertRaises(ProjectionError) as caught:
            builder.freeze()
        self.assertEqual(caught.exception.code, "cross_scope_join")

    def test_role_aware_endpoint_validation(self) -> None:
        view = synthetic_view()
        scope = view.projection.scope
        fn = function(view, 0x1000)
        string = next(s.subject_id for s in view.subjects.values() if s.kind == "string_literal")
        cases = [
            ("call.direct", fn, string, ("instruction", 1, None), "function_start", "to_role_mismatch"),
            ("call.direct", string, fn, ("instruction", 1, None), "function_start", "from_role_mismatch"),
            ("call.indirect", fn, fn, ("instruction", 1, None), "target_unknown", "unexpected_target"),
            ("call.import", fn, None, ("instruction", 1, None), "stub_indirect_symbol", "missing_to_subject"),
            ("ref.string", fn, string, ("row", None, 0), "materialized_on_all_paths", "coordinate_mismatch"),
            ("call.direct", fn, fn, ("instruction", 1, None), "guessed", "unknown_resolution"),
        ]
        for relation, src, dst, coord, resolution, code in cases:
            builder = contract.Builder(scope)
            builder.subjects = dict(view.subjects)
            builder.facts[contract.fact_id(scope, relation, src, dst, coord)] = contract.Fact(
                contract.fact_id(scope, relation, src, dst, coord), relation, src, dst, coord, resolution,
                "binary_observation", "t", ("t",))
            with self.subTest(code=code), self.assertRaises(ProjectionError) as caught:
                builder.freeze()
            self.assertEqual(caught.exception.code, code)

    def test_renamed_display_label_keeps_canonical_identity(self) -> None:
        doc = load(SYNTH_FACTS)
        renamed = copy.deepcopy(doc)
        renamed["functions"][0]["names"] = ["-[Vault fetchSecret]"]
        a, b = synthetic_view(doc), synthetic_view(renamed)
        self.assertEqual(function(a, 0x1000), function(b, 0x1000))
        self.assertNotEqual(a.name(function(a, 0x1000)), b.name(function(b, 0x1000)))

    def test_duplicate_and_conflicting_identities_are_refused(self) -> None:
        doc = load(SYNTH_FACTS)
        doc["functions"].append(copy.deepcopy(doc["functions"][0]))
        with self.assertRaises(ProjectionError) as caught:
            synthetic_view(doc)
        self.assertEqual(caught.exception.code, "conflicting_subject")
        atlas = load(SYNTH_ATLAS)
        atlas["types"][0]["methods"].append({"name": "readPassword", "implementation": "0x1100",
                                             "isClassMethod": False, "selectorUsers": []})
        with self.assertRaises(ProjectionError) as caught:
            synthetic_view(atlas_doc=atlas)
        self.assertEqual(caught.exception.code, "conflicting_subject")
        # Imported declarations with the same identity but another SDK are a conflict, not a merge.
        atlas = load(SYNTH_ATLAS)
        imported = {"id": {"slot": 0, "kind": "importedType", "name": "struct stat"}, "kind": "importedType",
                    "name": "struct stat", "superclass": None, "members": [], "conformances": [], "methods": [],
                    "users": [], "evidence": "compilerImport",
                    "imported": {"sdkIdentity": "MacOSX27.0", "targetTriple": "arm64-apple-macos27"}}
        other = copy.deepcopy(imported)
        other["imported"]["sdkIdentity"] = "MacOSX26.4"
        atlas["types"] += [imported, other]
        atlas["total"] = len(atlas["types"])
        with self.assertRaises(ProjectionError) as caught:
            synthetic_view(atlas_doc=atlas)
        self.assertEqual(caught.exception.code, "conflicting_subject")

    def test_identical_repeated_observations_merge_citations(self) -> None:
        view = synthetic_view()
        refs = [f for f in view.projection.facts.values() if f.relation == "objc.selector_reference"]
        self.assertEqual(len(refs), 2)  # 0x1310 and 0x1508, repeated under four declarations
        self.assertTrue(all(len(f.citations) >= 3 for f in refs))

    def test_input_status_classification(self) -> None:
        atlas = load(SYNTH_ATLAS)
        empty = dict(atlas, total=0, types=[])
        truncated = dict(atlas, total=atlas["total"] + 5)
        with tempfile.TemporaryDirectory() as d:
            facts_path = write(d, "f.json", load(SYNTH_FACTS))
            for doc, status in ((empty, "complete_empty"), (truncated, "truncated")):
                p = adapters.project(facts_path, write(d, "a.json", doc), binding_asserted=True)
                self.assertEqual(next(i for i in p.inputs if i.source == "type_atlas").status, status)
            p = adapters.project(facts_path, write(d, "a.json", truncated), binding_asserted=True)
            self.assertEqual(p.coverage_of("*", "objc.methods"), "truncated")
            for doc, code in ((dict(atlas, total=1), "malformed"), (dict(atlas, types={}), "unsupported"),
                              (dict(atlas, imageSlot=3), "cross_scope_join")):
                with self.subTest(code=code), self.assertRaises(ProjectionError) as caught:
                    adapters.project(facts_path, write(d, "a.json", doc), binding_asserted=True)
                self.assertIn(caught.exception.code, (code, "cross_scope_join"))
            bad_hex = copy.deepcopy(atlas)
            bad_hex["types"][0]["methods"][0]["implementation"] = "4096"
            with self.assertRaises(ProjectionError) as caught:
                adapters.project(facts_path, write(d, "a.json", bad_hex), binding_asserted=True)
            self.assertEqual(caught.exception.code, "malformed")
            with self.assertRaises(ProjectionError) as caught:
                adapters.project(Path(d) / "missing.json")
            self.assertEqual(caught.exception.code, "missing")

    def test_bounded_strict_reads(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            path = Path(d) / "x.json"
            path.write_bytes(b"[" * 10 + b"]" * 10)
            with self.assertRaises(ProjectionError) as caught:
                runtime.read_bounded(path, 8)
            self.assertEqual(caught.exception.code, "oversize")
        for raw in (b'{"a": 1, "a": 2}', b"[NaN]", b"[" * 100 + b"]" * 100, b"\xff\xfe", b"{"):
            with self.subTest(raw=raw[:12]), self.assertRaises(ProjectionError) as caught:
                runtime.parse_json(raw)
            self.assertEqual(caught.exception.code, "malformed")

    def test_hostile_counts_and_lengths_are_refused(self) -> None:
        doc = load(SYNTH_FACTS)
        with tempfile.TemporaryDirectory() as d:
            path = write(d, "f.json", doc)
            with self.assertRaises(ProjectionError) as caught:
                adapters.project(path, limits=contract.Limits(max_subjects=3))
            self.assertEqual(caught.exception.code, "too_many_subjects")
            long = copy.deepcopy(doc)
            long["functions"][0]["names"] = ["x" * 5000]
            with self.assertRaises(ProjectionError) as caught:
                adapters.project(write(d, "g.json", long))
            self.assertEqual(caught.exception.code, "text_too_long")
            with self.assertRaises(ProjectionError) as caught:
                adapters.project(path, limits=contract.Limits(max_input_bytes=100))
            self.assertEqual(caught.exception.code, "oversize")


class PredicateTests(unittest.TestCase):
    def test_kleene_connectives_match_their_truth_tables(self) -> None:
        order = {query.NONMATCH: 0, query.UNKNOWN: 1, query.MATCH: 2}
        values = list(order)
        for combo in itertools.product(values, repeat=3):
            outcomes = [query.Outcome(v) for v in combo]
            self.assertEqual(query.all_of(outcomes).truth, min(combo, key=order.get))
            self.assertEqual(query.any_of(outcomes).truth, max(combo, key=order.get))
            self.assertEqual(query.negate(query.negate(outcomes[0])).truth, combo[0])

    def test_negatives_need_complete_coverage_and_no_hidden_transfers(self) -> None:
        view = synthetic_view()
        self.assertEqual(query.calls_import(view, function(view, 0x1000), "_SecItemCopyMatching").truth, query.MATCH)
        self.assertEqual(query.calls_import(view, function(view, 0x1a00), "_SecItemCopyMatching").truth, query.NONMATCH)
        partial = query.calls_import(view, function(view, 0x1800), "_SecItemCopyMatching")
        self.assertEqual(partial.truth, query.UNKNOWN)
        self.assertIn("call coverage is partial", partial.reasons)
        hidden = query.calls_import(view, function(view, 0x1700), "_SecItemCopyMatching")
        self.assertEqual(hidden.truth, query.UNKNOWN)  # an authenticated call could reach it
        # String coverage is never complete for static materialization: no string negative exists.
        self.assertEqual(query.references_string(view, function(view, 0x1a00), "password").truth, query.UNKNOWN)

    def test_pac_modifier_holding_a_code_address_is_not_a_target(self) -> None:
        view = synthetic_view()
        pac = function(view, 0x1700)
        auth = view.outgoing(pac, {"call.indirect_authenticated"})
        self.assertEqual(len(auth), 1)
        self.assertIsNone(auth[0].to_id)
        self.assertEqual(auth[0].attribute("modifier"), "x9")
        calls = [f for f in view.outgoing(pac, query.CALL_RELATIONS) if f.to_id == function(view, 0x1000)]
        self.assertEqual(calls, [])  # only a ref.code_address fact names 0x1000

    def test_sends_selector_is_unknown_with_anonymous_dispatch(self) -> None:
        view = synthetic_view()
        self.assertEqual(query.sends_selector(view, function(view, 0x1300), "render:").truth, query.MATCH)
        self.assertEqual(query.sends_selector(view, function(view, 0x1400), "render:").truth, query.UNKNOWN)
        self.assertEqual(query.sends_selector(view, function(view, 0x1500), "render:").truth, query.NONMATCH)
        self.assertEqual(query.sends_selector(view, function(view, 0x1600), "close").truth, query.MATCH)

    def test_calls_import_agrees_with_a_brute_force_oracle(self) -> None:
        rng = random.Random(20)
        names = ["_a", "_b", "_c"]
        for trial in range(60):
            functions = []
            for i in range(6):
                start = 0x1000 + 0x100 * i
                fs = []
                for j in range(rng.randrange(0, 5)):
                    at = start + 4 * (j + 1)
                    choice = rng.randrange(6)
                    if choice == 0:
                        fs.append({"kind": "call.import", "at": at, "target": 0x9000, "name": rng.choice(names),
                                   "tail": False, "resolution": "stub_indirect_symbol"})
                    elif choice == 1:
                        fs.append({"kind": "call.indirect", "at": at, "form": "register", "register": "x8",
                                   "resolution": "target_unknown"})
                    elif choice == 2:
                        fs.append({"kind": "call.indirect", "at": at, "form": "register", "register": "x8",
                                   "resolution": "loaded_from_import_slot", "slot": 0xa000, "name": rng.choice(names)})
                    elif choice == 3:
                        fs.append({"kind": "jump.indirect_authenticated", "at": at, "form": "braa", "register": "x8",
                                   "key": "A", "modifier": "x9", "resolution": "target_unknown"})
                    elif choice == 4:
                        fs.append({"kind": "call.direct", "at": at, "target": 0x1000, "resolution": "function_start"})
                    else:
                        fs.append({"kind": "call.indirect", "at": at, "form": "register", "register": "x8",
                                   "resolution": "register_holds_materialized_code_address", "candidate": 0x1000})
                functions.append({"address": start, "end": start + 0x100, "names": [f"_f{i}"],
                                  "subjectKind": "function", "undecoded": int(rng.random() < 0.2), "facts": fs})
            doc = {"schema": "u20_u21_query.research_facts/1", "image": {"sha256": f"{trial:064x}"}, "functions": functions}
            with tempfile.TemporaryDirectory() as d:
                view = query.View(adapters.project(write(d, "f.json", doc)))
            for f in functions:
                sid = function(view, f["address"])
                for name in names:
                    hit = any(k.get("name") == name and (k["kind"] == "call.import" or k.get("resolution") == "loaded_from_import_slot")
                              for k in f["facts"])
                    hidden = any(k["kind"] in ("call.indirect", "jump.indirect_authenticated") and k["resolution"] in
                                 ("target_unknown", "register_holds_materialized_code_address") for k in f["facts"])
                    expected = query.MATCH if hit else query.UNKNOWN if (f["undecoded"] or hidden) else query.NONMATCH
                    self.assertEqual(query.calls_import(view, sid, name).truth, expected, (trial, f, name))


class ReviewRegressionTests(unittest.TestCase):
    """Defects found by the independent adversarial review, kept as regressions."""

    def doc(self, functions, **image):
        return {"schema": "u20_u21_query.research_facts/1",
                "image": dict({"sha256": "ab" * 32, "architecture": "arm64"}, **image), "functions": functions}

    def fn(self, address, facts, names=("_f",), role="function", undecoded=0):
        return {"address": address, "end": address + 0x40, "names": list(names), "subjectKind": role,
                "undecoded": undecoded, "facts": facts}

    def view(self, doc):
        with tempfile.TemporaryDirectory() as d:
            return query.View(adapters.project(write(d, "f.json", doc)))

    def test_hidden_transfers_and_dispatch_never_yield_false_negatives(self) -> None:
        got_send = self.fn(0x1000, [{"kind": "call.indirect", "at": 0x1010, "form": "register", "register": "x8",
                                     "resolution": "loaded_from_import_slot", "slot": 0x9000, "name": "_objc_msgSend"}])
        interior = self.fn(0x1100, [{"kind": "call.direct", "at": 0x1110, "target": 0x6000,
                                     "resolution": "target_not_function_start"}])
        stub = self.fn(0x1200, [{"kind": "call.objc_stub", "at": 0x1210, "target": 0x6100,
                                 "name": "_objc_msgSend$close", "resolution": "objc_stub_symbol"}])
        thunk = self.fn(0x1300, [{"kind": "jump.indirect", "at": 0x1308, "form": "register", "register": "x16",
                                  "stub": 0x7000, "name": "_SecItemCopyMatching",
                                  "resolution": "register_holds_import_stub_address"}], names=("_t",), role="import_thunk")
        caller = self.fn(0x1400, [{"kind": "call.direct", "at": 0x1404, "target": 0x1300, "resolution": "function_start"}])
        view = self.view(self.doc([got_send, interior, stub, thunk, caller]))
        self.assertEqual(query.sends_selector(view, function(view, 0x1000), "close").truth, query.UNKNOWN)
        self.assertEqual(len(query.selector_sites(view, "close")["dispatchWithUnknownSelector"]), 1)
        self.assertEqual(query.calls_import(view, function(view, 0x1100), "_free").truth, query.UNKNOWN)
        self.assertEqual(query.calls_import(view, function(view, 0x1200), "_objc_msgSend").truth, query.UNKNOWN)
        self.assertEqual(query.calls_import(view, function(view, 0x1400), "_SecItemCopyMatching").truth, query.MATCH)
        recovered = self.view(self.doc([caller], mode="recovered-boundaries"))
        self.assertEqual(recovered.coverage(function(recovered, 0x1400), "calls"), "partial")

    def test_identity_and_conflict_refusals(self) -> None:
        with self.assertRaises(ProjectionError) as caught:
            self.view({"schema": "u20_u21_query.research_facts/1", "image": {}, "functions": []})
        self.assertEqual(caught.exception.code, "missing_image_identity")
        clash = [self.fn(0x1000, [{"kind": "ref.string", "at": 0x1010, "target": 0x3000, "value": "password"}]),
                 self.fn(0x1100, [{"kind": "ref.string", "at": 0x1110, "target": 0x3000, "value": "aaa"}], ("_g",))]
        with self.assertRaises(ProjectionError) as caught:
            self.view(self.doc(clash))
        self.assertEqual(caught.exception.code, "conflicting_subject")
        for bad in ([1], [{"address": True, "end": 8, "facts": []}],
                    [self.fn(0x1000, [{"kind": "call.import", "at": 0x1004}])]):
            with self.subTest(bad=bad), self.assertRaises(ProjectionError) as caught:
                self.view(self.doc(bad))
            self.assertEqual(caught.exception.code, "malformed")

    def test_type_atlas_rows_are_type_checked_and_coverage_is_never_overstated(self) -> None:
        atlas = load(SYNTH_ATLAS)
        for change in ({"types": atlas["types"] + [atlas["types"][0]]}, {"types": [1] + atlas["types"]}):
            with self.subTest(change=list(change)), self.assertRaises(ProjectionError):
                synthetic_view(atlas_doc=dict(atlas, total=len(change["types"]), **change))
        bad = copy.deepcopy(atlas)
        bad["types"][5]["conformances"] = "Sendable"
        with self.assertRaises(ProjectionError):
            synthetic_view(atlas_doc=bad)
        bad = copy.deepcopy(atlas)
        bad["types"][5]["swiftConformanceMethods"] = [5]
        with self.assertRaises(ProjectionError):
            synthetic_view(atlas_doc=bad)
        view = synthetic_view()
        self.assertEqual(view.coverage("*", "objc.methods"), "partial")  # kind filter is not echoed
        name_only = next(s.subject_id for s in view.subjects.values() if s.kind == "objc_protocol"
                         and s.names[0].text == "NSCopying")
        self.assertEqual(view.coverage(name_only, "objc.methods"), "unavailable")

    def test_register_model_review_cases(self) -> None:
        image = ExtractorLogicTests.FakeImage()
        image.sections = image.sections + [("__objc_selrefs", 0x5000, 0x5100)]

        def run(lines):
            body = [(0x1000 + 4 * i, m, o) for i, (m, o) in enumerate(lines)]
            return facts.function_facts(image, 0x1000, 0x1000 + 4 * len(body), ["_f"], body, {0x1000})["facts"]

        merged = run([("cbz", "x2, 0x1010"), ("adrp", "x8, 0x5000"), ("ldr", "x1, [x8, #0x10]"), ("b", "0x101c"),
                      ("adrp", "x9, 0x5000"), ("ldr", "x1, [x9, #0x10]"), ("nop", ""), ("bl", "0x1800")])
        self.assertTrue(any(f["kind"] == "call.direct" for f in merged))  # no crash on a merged origin
        image.stubs = {0x1800: "_objc_msgSend"}
        for lines in ([("adrp", "x8, 0x5000"), ("ldr", "x1, [x8, #0x10]"), ("swp", "x0, x1, [x10]"), ("bl", "0x1800")],
                      [("adrp", "x8, 0x5000"), ("ldr", "x1, [x8, #0x10]"), ("ldaddal", "x3, x1, [x10]"), ("bl", "0x1800")],
                      [("adrp", "x8, 0x5000"), ("ldr", "x1, [x8, #0x10]"), ("adr", "x9, 0x1014"), ("br", "x9"),
                       ("bl", "0x1800")]):
            with self.subTest(lines=lines[2][0]):
                call = next(f for f in run(lines) if f["kind"] == "call.import")
                self.assertNotIn("x1", call["arguments"])
        self.assertEqual([f for f in run([("adrp", "x8, 0x3000"), ("add", "w0, w8, #0x8")]) if f["kind"] == "ref.string"], [])
        ldrb = run([("adrp", "x8, 0x4000"), ("ldrb", "w0, [x8]"), ("blr", "x0")])
        self.assertEqual(next(f for f in ldrb if f["kind"] == "call.indirect")["resolution"], "target_unknown")


class SourceReviewPR945Tests(unittest.TestCase):
    """Orchestrator source review of PR 945: immutable projections and thunk-aware negatives."""

    def thunk_case(self, thunk_coverage="complete", thunk_facts=(), dispatch=False):
        b = contract.Builder(contract.make_scope("review-fixture", "main", "arm64", []))
        f = b.subject("function", 0x1000)
        t = b.subject("function", 0x2000, attributes={"role": "import_thunk"})
        b.fact("call.direct", f, t, ("instruction", 0x1000, None), "function_start", "review-fixture", "direct call")
        for relation, to, resolution in thunk_facts:
            target = b.subject("import", to, [contract.Name(to, "import_name")]) if to else None
            b.fact(relation, t, target, ("instruction", 0x2000, None), resolution, "review-fixture", "thunk transfer")
        b.cover(f, "calls", "complete", "review-fixture")
        b.cover(t, "calls", thunk_coverage, "review-fixture")
        return query.View(b.freeze()), f

    def test_traversed_thunk_uncertainty_blocks_negatives(self) -> None:
        view, f = self.thunk_case(thunk_coverage="partial")
        self.assertEqual(query.calls_import(view, f, "_target").truth, query.UNKNOWN)
        self.assertEqual(query.sends_selector(view, f, "close").truth, query.UNKNOWN)
        view, f = self.thunk_case(thunk_facts=[("call.indirect", None, "target_unknown")])
        self.assertEqual(query.calls_import(view, f, "_target").truth, query.UNKNOWN)
        self.assertEqual(query.sends_selector(view, f, "close").truth, query.UNKNOWN)
        view, f = self.thunk_case()  # fully observed thunk without the target
        self.assertEqual(query.calls_import(view, f, "_target").truth, query.NONMATCH)
        self.assertEqual(query.sends_selector(view, f, "close").truth, query.NONMATCH)
        view, f = self.thunk_case(thunk_facts=[("jump.indirect", "_target", "register_holds_import_stub_address")])
        self.assertEqual(query.calls_import(view, f, "_target").truth, query.MATCH)
        view, f = self.thunk_case(thunk_coverage="partial",
                                  thunk_facts=[("jump.indirect", "_target", "register_holds_import_stub_address")])
        self.assertEqual(query.calls_import(view, f, "_target").truth, query.MATCH)  # positive evidence kept

    def test_frozen_projection_cannot_be_mutated(self) -> None:
        b = contract.Builder(contract.make_scope("review-fixture", "main", "arm64", []))
        f = b.subject("function", 0x1000)
        b.fact("call.import", f, b.subject("import", "_free", [contract.Name("_free", "import_name")]),
               ("instruction", 0x1004, None), "stub_indirect_symbol", "review-fixture", "call")
        b.cover(f, "calls", "partial", "review-fixture")
        p = b.freeze()
        view = query.View(p)
        before = (dict(p.facts), dict(p.coverage), p.scope.input_digest)
        for mapping in (p.subjects, p.facts, p.coverage):
            with self.assertRaises((TypeError, AttributeError)):
                mapping.clear()
            with self.assertRaises(TypeError):
                mapping["x"] = None
        b.facts.clear()  # caller-held builder aliases do not reach the frozen copy
        b.coverage[(f, "calls")] = contract.Coverage(f, "calls", "complete", "review-fixture")
        self.assertEqual((dict(p.facts), dict(p.coverage), p.scope.input_digest), before)
        self.assertEqual(query.calls_import(view, f, "_malloc").truth, query.UNKNOWN)
        self.assertEqual(query.calls_import(view, f, "_free").truth, query.MATCH)
        self.assertTrue(all(w in p.facts for w in query.calls_import(view, f, "_free").witnesses))
        self.assertEqual(json.loads(json.dumps(p.to_json()))["facts"][0]["relation"], "call.import")


class SourceReviewPR945FollowUpTests(unittest.TestCase):
    """Second orchestrator review of PR 945: emitted CLI bytes and byte-addressed string suffixes."""

    def run_cli(self, argv):
        stream = io.TextIOWrapper(io.BytesIO(), encoding="utf-8")
        with contextlib.redirect_stdout(stream):
            code = cli.main(argv)
        stream.flush()
        return code, stream.buffer.getvalue()

    def common(self):
        return ["--facts", str(SYNTH_FACTS), "--type-atlas", str(SYNTH_ATLAS), "--assert-binding"]

    @unittest.skipUnless(fts5_available(), "the linked SQLite has no FTS5")
    def test_cli_output_is_the_budgeted_compact_line_at_the_boundary(self) -> None:
        argv = ["rank", *self.common(), "--question", "which method reads a password from the keychain?"]
        budget = 65536
        for _ in range(4):  # the document embeds its own budget, so settle on a fixed point
            code, line = self.run_cli(argv + ["--max-bytes", str(budget)])
            self.assertEqual(code, 0)
            if len(line) == budget:
                break
            budget = len(line)
        doc = json.loads(line)
        self.assertEqual(len(line), budget)  # exactly fits: LF included, no indentation
        self.assertTrue(line.endswith(b"\n") and b"\n" not in line[:-1])
        self.assertEqual(doc["budget"]["usedBytes"], len(line) - 1)
        self.assertEqual(doc["selection"]["returned"], doc["selection"]["ranked"])
        code, smaller = self.run_cli(argv + ["--max-bytes", str(budget - 1)])
        self.assertEqual(code, 0)
        self.assertLessEqual(len(smaller), budget - 1)
        self.assertEqual(json.loads(smaller)["budget"]["usedBytes"], len(smaller) - 1)
        self.assertLess(json.loads(smaller)["selection"]["returned"], doc["selection"]["returned"])

    def test_cli_too_small_budgets_and_project_are_typed_failures(self) -> None:
        code, line = self.run_cli(["sites", *self.common(), "--selector", "render:", "--max-bytes", "260"])
        self.assertEqual((code, json.loads(line)["code"]), (2, "budget_too_small"))
        self.assertLessEqual(len(line), 260)
        code, line = self.run_cli(["project", *self.common(), "--max-bytes", "300"])
        self.assertEqual((code, json.loads(line)["code"]), (2, "result_too_large"))
        self.assertLessEqual(len(line), 300)
        code, line = self.run_cli(["project", *self.common(), "--max-bytes", "65536"])
        self.assertEqual(code, 0)
        self.assertLessEqual(len(line), 65536)
        code, line = self.run_cli(["project", *self.common(), "--max-bytes", "10"])
        self.assertEqual((code, json.loads(line)["code"]), (2, "invalid_request"))

    def test_error_lines_are_bounded_after_json_escaping(self) -> None:
        for detail in ("\\" * 400, "\x01" * 300, '"' * 300, "\ud800" * 50 + "x" * 300, "é" * 300, ""):
            with self.subTest(detail=detail[:3]):
                data = cli.error_line("missing", detail)
                self.assertLessEqual(len(data) + 1, cli.ERROR_LINE_BYTES)  # serialized line, LF included
                doc = json.loads(data.decode("utf-8"))
                self.assertEqual((doc["status"], doc["code"]), ("error", "missing"))
                clean = detail.encode("utf-8", "replace").decode("utf-8")
                self.assertTrue(clean.startswith(doc["detail"]))
                if doc.get("detailTruncated"):
                    # Maximal: one more character of detail would exceed the ceiling.
                    longer = envelope.encode({"status": "error", "code": "missing",
                                              "detail": clean[:len(doc["detail"]) + 1], "detailTruncated": True})
                    self.assertGreater(len(longer) + 1, cli.ERROR_LINE_BYTES)
                else:
                    self.assertEqual(doc["detail"], clean)
        escaped_path = ("\\" * 100 + "/") * 3 + "x.json"  # path components stay under NAME_MAX
        code, line = self.run_cli(["project", "--facts", escaped_path, "--max-bytes", "257"])
        self.assertEqual((code, json.loads(line)["code"]), (2, "missing"))
        self.assertLessEqual(len(line), cli.ERROR_LINE_BYTES)
        self.assertTrue(line.endswith(b"\n"))

    def test_unreadable_inputs_are_typed(self) -> None:
        with self.assertRaises(ProjectionError) as caught:
            runtime.read_bounded("x" * 300 + ".json", 1024)  # a single name longer than NAME_MAX
        self.assertEqual(caught.exception.code, "unreadable")
        with tempfile.TemporaryDirectory() as d, self.assertRaises(ProjectionError) as caught:
            runtime.read_bounded(d, 1024)  # a directory
        self.assertEqual(caught.exception.code, "unreadable")

    def test_string_suffixes_are_sliced_by_byte_address(self) -> None:
        image = object.__new__(facts.Image)
        image.string_bytes = {0x3000: bytes.fromhex("c3a958595a"), 0x3010: b"plain ascii"}
        image._string_starts = sorted(image.string_bytes)
        self.assertEqual(image.string_at(0x3000), "\u00e9XYZ")
        self.assertEqual(image.string_at(0x3002), "XYZ")
        self.assertEqual(image.string_at(0x3001), "\ufffdXYZ")  # starts inside a character
        self.assertEqual(image.string_at(0x3016), "ascii")
        self.assertIsNone(image.string_at(0x3005))  # past the literal's bytes


class RecipeTests(unittest.TestCase):
    def test_selector_sites_separate_declarations_references_and_sends(self) -> None:
        view = synthetic_view()
        result = query.selector_sites(view, "render:")
        owners = sorted((d["ownerName"], d["side"]) for d in result["declarations"])
        self.assertEqual(owners, [("Gadget", "instance"), ("Renderable", "instance"), ("Vault", "class"),
                                  ("Vault", "instance")])
        shared = [d for d in result["declarations"] if d["implementation"].get("name") == "-[Vault render:]"]
        self.assertEqual(len(shared), 2)  # one IMP behind two methods
        protocol = next(d for d in result["declarations"] if d["ownerKind"] == "objc_protocol")
        self.assertEqual((protocol["requirement"], protocol["implementation"]["status"]), ("unavailable", "unavailable"))
        users = {u["instruction"]: view.name(u["site"]) for u in result["selectorReferenceUsers"]}
        self.assertEqual(users, {"0x1310": "_drive", "0x1508": "_selref_only"})
        sends = result["messageSends"]
        self.assertEqual([(s["functionName"], s["instruction"]) for s in sends], [("_drive", "0x1314")])
        send = sends[0]
        self.assertEqual(send["receiver"]["className"], "Vault")
        self.assertEqual([c["implementation"]["name"] for c in send["candidateTargets"]], ["+[Vault render:]"])
        self.assertEqual([e["relation"] for e in send["chain"]],
                         ["objc.class_reference", "objc.selector_reference", "objc.message_send"])
        self.assertEqual([view.name(a["function"]) for a in result["dispatchWithUnknownSelector"]], ["_anon_dispatch"])
        self.assertNotIn("calls", json.dumps(result).replace("call.", ""))  # no executed-call claim

    def test_receiver_or_selector_ambiguity_yields_no_send_or_no_target(self) -> None:
        atlas = load(SYNTH_ATLAS)
        atlas["types"][1]["users"] = ["0x130c"]  # the x0 load now names two classes
        view = synthetic_view(atlas_doc=atlas)
        send = query.selector_sites(view, "render:")["messageSends"][0]
        self.assertEqual(send["receiver"]["status"], "unknown")
        self.assertEqual(send["candidateTargets"], [])
        atlas = load(SYNTH_ATLAS)
        atlas["types"][1]["methods"][1]["selectorUsers"] = ["0x1310"]  # x1 load names two selectors
        view = synthetic_view(atlas_doc=atlas)
        self.assertEqual(query.selector_sites(view, "render:")["messageSends"], [])
        self.assertEqual(len(query.selector_sites(view, "render:")["dispatchWithUnknownSelector"]), 2)

    def test_research_input_alone_reports_metadata_sections_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            view = query.View(adapters.project(write(d, "f.json", load(SYNTH_FACTS))))
        result = query.selector_sites(view, "close")
        self.assertEqual(result["coverage"]["declarations"], "unavailable")
        self.assertEqual(result["coverage"]["messageSends"], "unavailable")
        self.assertEqual(len(result["messageSends"]), 1)  # the selector stub needs no metadata

    def test_implementation_observations_chains_and_unknowns(self) -> None:
        view = synthetic_view()
        result = query.implementation_observations(view, imports=["_SecItemCopyMatching"], strings=["password"])
        found = {m["functionName"]: [e["relation"] for e in m["chain"]] for m in result["matches"]}
        self.assertEqual(found["-[Vault readPassword]"][:2], ["objc.declares_method", "objc.method_implementation"])
        self.assertEqual(found["_$s3Kit5VaultC4openyyF"][:2], ["swift.method_slot", "swift.slot_implementation"])
        self.assertTrue(all(m["label"] is None for m in result["matches"] if m["ownerKind"] == "swift_method_slot"))
        reasons = [u["reason"] for u in result["unknown"]]
        self.assertIn("implementation implementation_unavailable", reasons)
        self.assertIn("implementation descriptor_imp_outside_functions", reasons)
        self.assertEqual(result["nonmatchCount"], 0)  # string concerns never yield negatives
        with self.assertRaises(ProjectionError):
            query.implementation_observations(view)

    def test_swift_rows_keep_unknowns(self) -> None:
        view = synthetic_view()
        token = next(s for s in view.subjects.values() if s.kind == "swift_type" and s.names[0].text == "Token")
        self.assertEqual(view.coverage(token.subject_id, "swift.witnesses"), "unavailable")
        self.assertEqual(view.coverage(token.subject_id, "swift.methods"), "unavailable")
        slots = [s for s in view.subjects.values() if s.kind == "swift_method_slot"]
        self.assertTrue(slots and all(not n.searchable for s in slots for n in s.names))
        self.assertTrue(all(s.attribute("slotIndex") == "unavailable" for s in slots))

    def test_recipe_bounds(self) -> None:
        view = synthetic_view()
        small = query.selector_sites(view, "render:", query.RecipeLimits(max_items=1))
        self.assertEqual((len(small["declarations"]), small["omitted"]["declarations"]), (1, 3))
        with self.assertRaises(ProjectionError) as caught:
            query.selector_sites(view, "render:", query.RecipeLimits(max_work=2))
        self.assertEqual(caught.exception.code, "work_limit")
        with self.assertRaises(ProjectionError):
            query.selector_sites(view, "x" * 2000)

    def test_stale_scope_or_frontier_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as d:
            projection = adapters.project(write(d, "f.json", load(SYNTH_FACTS)))
        query.View(projection, projection.scope.scope_id, projection.scope.input_digest)
        for kwargs, code in (({"expected_scope": "0" * 64}, "stale_scope"),
                             ({"expected_inputs": "1" * 64}, "stale_inputs")):
            with self.assertRaises(ProjectionError) as caught:
                query.View(projection, **kwargs)
            self.assertEqual(caught.exception.code, code)

    def test_real_objc_fixture_dispatch_provenance(self) -> None:
        view = query.View(adapters.project(FIXTURES / "libw.facts.json", FIXTURES / "libw.type-atlas.json",
                                           binding_asserted=True))
        sends = {s["instruction"]: s for name in ("render:", "close")
                 for s in query.selector_sites(view, name)["messageSends"]}
        self.assertEqual(set(sends), {"0x1930", "0x194c"})
        self.assertTrue(all(s["receiver"]["status"] == "unknown" and not s["candidateTargets"] for s in sends.values()))


class ExtractorLogicTests(unittest.TestCase):
    class FakeImage:
        sections = [("__text", 0x1000, 0x2000), ("__cstring", 0x3000, 0x3100), ("__got", 0x4000, 0x4010)]
        stubs, got, objc_stub_symbols, exported = {}, {0x4000: "_free"}, {}, set()

        def section_of(self, address):
            return next((n for n, a, b in self.sections if a <= address < b), None)

        def string_at(self, address):
            return {0x3000: "hello", 0x3008: "world"}.get(address)

        def data_name(self, address):
            return None, None

    def run_body(self, lines):
        body = [(0x1000 + 4 * i, m, o) for i, (m, o) in enumerate(lines)]
        result = facts.function_facts(self.FakeImage(), 0x1000, 0x1000 + 4 * len(body), ["_f"], body, {0x1000})
        return result["facts"]

    def test_register_writes_and_calls_invalidate_materialized_pages(self) -> None:
        strings = lambda fs: [f["value"] for f in fs if f["kind"] == "ref.string"]
        self.assertEqual(strings(self.run_body([("adrp", "x0, 0x3000"), ("add", "x0, x0, #0x0")])), ["hello"])
        self.assertEqual(strings(self.run_body([("adrp", "x0, 0x3000"), ("mov", "w0, #0x1"), ("add", "x0, x0, #0x0")])), [])
        self.assertEqual(strings(self.run_body([("adrp", "x1, 0x3000"), ("bl", "0x1800"), ("add", "x1, x1, #0x8")])), [])
        self.assertEqual(strings(self.run_body([("adrp", "x19, 0x3000"), ("bl", "0x1800"), ("add", "x1, x19, #0x8")])), ["world"])
        self.assertEqual(strings(self.run_body([("adrp", "x0, 0x3000"), ("ldp", "x0, x1, [sp]"), ("add", "x0, x0, #0x0")])), [])

    def test_block_states_meet_only_when_all_predecessors_agree(self) -> None:
        agree = [("adrp", "x0, 0x3000"), ("cbz", "x2, 0x100c"), ("nop", ""), ("add", "x0, x0, #0x0"), ("ret", "")]
        self.assertEqual([f["value"] for f in self.run_body(agree) if f["kind"] == "ref.string"], ["hello"])
        differ = [("cbz", "x2, 0x100c"), ("adrp", "x0, 0x3000"), ("b", "0x1010"), ("mov", "x0, x5"),
                  ("add", "x0, x0, #0x0"), ("ret", "")]
        self.assertEqual([f for f in self.run_body(differ) if f["kind"] == "ref.string"], [])

    def test_authenticated_calls_keep_the_modifier_out_of_the_target(self) -> None:
        fs = self.run_body([("adrp", "x9, 0x1000"), ("add", "x9, x9, #0x0"), ("blraa", "x8, x9")])
        auth = [f for f in fs if f["kind"] == "call.indirect_authenticated"]
        self.assertEqual(auth, [{"kind": "call.indirect_authenticated", "at": 0x1008, "form": "blraa",
                                 "register": "x8", "key": "A", "modifier": "x9", "resolution": "target_unknown"}])
        got = self.run_body([("adrp", "x8, 0x4000"), ("ldr", "x8, [x8]"), ("blr", "x8")])
        call = next(f for f in got if f["kind"] == "call.indirect")
        self.assertEqual((call["resolution"], call["name"]), ("loaded_from_import_slot", "_free"))

    def test_operand_splitting_and_data_pointer_scan(self) -> None:
        self.assertEqual(facts.split_operands("x0, [x1, #0x8]!, x2"), ["x0", "[x1, #0x8]!", "x2"])
        blob = bytearray((0x1004).to_bytes(8, "little") + (0x9999).to_bytes(8, "little") + (0x1002).to_bytes(8, "little"))
        self.assertEqual(facts._scan(blob, 0x5000, ("__text", 0x1000, 0x2000)), {0x1004})


@unittest.skipUnless(fts5_available(), "the linked SQLite has no FTS5")
class RankingTests(unittest.TestCase):
    def ranking(self, view, question, system="C1_fielded", excluded=(), k=8):
        admission = rank.Admission(view, rank.function_universe(view), excluded)
        ranker = service.Ranker(view, admission, system)
        try:
            return ranker.ranking(question, k)[1], ranker.answer(question, k, 16384)[1]
        finally:
            ranker.close()

    def test_excluded_subjects_cannot_change_results_scores_or_bytes(self) -> None:
        doc = load(SYNTH_FACTS)
        full = synthetic_view(doc)
        excluded = function(full, 0x1900)  # matches "password" and calls 0x1000
        reduced_doc = copy.deepcopy(doc)
        reduced_doc["functions"] = [f for f in reduced_doc["functions"] if f["address"] != 0x1900]
        reduced = synthetic_view(reduced_doc)
        question = "which method reads a password from the keychain?"
        a, doc_a = self.ranking(full, question, excluded=[excluded])
        b, doc_b = self.ranking(reduced, question)
        addr = lambda view, r: [(view.subjects[s].address, score) for s, score in r]
        self.assertEqual(addr(full, a), addr(reduced, b))
        self.assertEqual(doc_a["budget"]["usedBytes"], doc_b["budget"]["usedBytes"])
        strip = lambda d: [(c["address"], c["score"], [(w["field"], w["terms"], w["text"]) for w in c["witness"]])
                           for c in d["candidates"]]
        self.assertEqual(strip(doc_a), strip(doc_b))
        c, _ = self.ranking(full, question)
        self.assertIn(0x1900, [full.subjects[s].address for s, _ in c])

    def test_ties_are_stable_under_input_reordering(self) -> None:
        doc = load(SYNTH_FACTS)
        for i in range(3):  # three subjects with identical text
            doc["functions"].append({"address": 0x2000 + 0x10 * i, "end": 0x2008 + 0x10 * i, "names": ["_twin"],
                                     "subjectKind": "function", "undecoded": 0, "facts": []})
        shuffled = copy.deepcopy(doc)
        random.Random(4).shuffle(shuffled["functions"])
        a, _ = self.ranking(synthetic_view(doc), "twin")
        b, _ = self.ranking(synthetic_view(shuffled), "twin")
        view = synthetic_view(doc)
        self.assertEqual([view.subjects[s].address for s, _ in a], [0x2000, 0x2010, 0x2020])
        self.assertEqual(a, b)

    def test_identifiers_citations_and_addresses_are_not_searchable(self) -> None:
        view = synthetic_view()
        for probe in ("0x1000", "1000", "research_facts", "type_atlas", "function", "subject", "5e5e5e5e",
                      view.projection.scope.scope_id[:12], next(iter(view.projection.facts))[2:14]):
            with self.subTest(probe=probe):
                self.assertEqual(self.ranking(view, probe)[0], [])

    def test_adversarial_query_text_is_literal(self) -> None:
        view = synthetic_view()
        for question in ('NEAR(password keychain) OR *', 'name:password', '"password" AND -keychain',
                         "password\x00keychain", "パスワード password", "^password$", ") OR (", ""):
            with self.subTest(question=question):
                ranked, doc = self.ranking(view, question)
                self.assertIn(doc["status"], ("ok", "empty"))
        with self.assertRaises(ProjectionError):
            rank.query_terms(None)
        with self.assertRaises(ProjectionError):
            rank.query_terms("word " * 2000)
        self.assertEqual(len(rank.query_terms(" ".join(f"w{i}x" for i in range(100)))), 32)

    def test_missing_fts5_is_a_typed_refusal(self) -> None:
        class NoFTS:
            def __init__(self):
                self.real = sqlite3.connect(":memory:")

            def execute(self, sql, *args):
                if "fts5" in sql.lower():
                    raise sqlite3.OperationalError("no such module: fts5")
                return self.real.execute(sql, *args)

        view = synthetic_view()
        admission = rank.Admission(view, rank.function_universe(view))
        with self.assertRaises(ProjectionError) as caught:
            rank.ScopeIndex(view, admission, rank.System.fielded(), connect=lambda _: NoFTS())
        self.assertEqual(caught.exception.code, "fts5_unavailable")

    def test_cancellation_and_work_limits(self) -> None:
        view = synthetic_view()
        admission = rank.Admission(view, rank.function_universe(view))
        token = runtime.CancelToken()
        token.cancel()
        with self.assertRaises(ProjectionError) as caught:
            rank.ScopeIndex(view, admission, rank.System.fielded(), token=token)
        self.assertEqual(caught.exception.code, "cancelled")

        class LateToken(runtime.CancelToken):
            checks = 0

            @property
            def cancelled(self):
                LateToken.checks += 1
                return LateToken.checks > 3

        index = rank.ScopeIndex(view, admission, rank.System.fielded(),
                                limits=rank.RankLimits(progress_interval=1), token=runtime.CancelToken())
        index.token = LateToken()
        with self.assertRaises(ProjectionError) as caught:
            index.search(["password", "keychain"], 8)
        self.assertEqual(caught.exception.code, "cancelled")
        tiny = rank.ScopeIndex(view, admission, rank.System.fielded(),
                               limits=rank.RankLimits(progress_interval=1, max_vm_steps=5))
        with self.assertRaises(ProjectionError) as caught:
            tiny.search(["password", "keychain"], 8)
        self.assertEqual(caught.exception.code, "work_limit")

    def test_stems_count_once_and_witnesses_follow_the_system_fields(self) -> None:
        view = synthetic_view()
        admission = rank.Admission(view, rank.function_universe(view))
        ranker = service.Ranker(view, admission, "C1_fielded")
        try:
            terms, _ = ranker.ranking("password passwords keychain", 8)
            self.assertEqual(len(terms), 2)
            with self.assertRaises(ProjectionError):
                ranker.ranking("password", "3")
        finally:
            ranker.close()
        names = service.Ranker(view, admission, "B1_names_only")
        try:
            _, doc = names.answer("which method reads a password from the keychain?", 8, 16384)
            self.assertTrue(doc["candidates"])
            self.assertEqual({w["field"] for c in doc["candidates"] for w in c["witness"]}, {"name"})
        finally:
            names.close()

    def test_alias_names_are_separate_witnesses(self) -> None:
        doc = load(SYNTH_FACTS)
        doc["functions"][10]["names"] = ["_complete_leaf", "_zebrafinch_alias"]
        view = synthetic_view(doc)
        admission = rank.Admission(view, rank.function_universe(view))
        ranker = service.Ranker(view, admission, "B1_names_only")
        try:
            _, result = ranker.answer("zebrafinch", 8, 16384)
        finally:
            ranker.close()
        witness = result["candidates"][0]["witness"][0]
        subject = view.subjects[result["candidates"][0]["subject"]]
        self.assertIn("zebrafinch", witness["text"])
        self.assertEqual(subject.names[witness["nameIndex"]].text, "_zebrafinch_alias")

    def test_witnesses_cite_admitted_facts_of_the_candidate(self) -> None:
        view = synthetic_view()
        _, doc = self.ranking(view, "which method reads a password from the keychain?")
        self.assertTrue(doc["candidates"])
        for c in doc["candidates"]:
            for w in c["witness"]:
                if w["kind"] == "fact":
                    fact = view.projection.facts[w["fact"]]
                    self.assertEqual(fact.from_id, c["subject"])
                    self.assertEqual(w["relation"], fact.relation)


class EnvelopeTests(unittest.TestCase):
    def test_whole_utf8_envelope_is_charged_and_omissions_are_truthful(self) -> None:
        header = {"kind": "rank", "note": "naïve – ünïcode ✓"}
        candidates = [{"rank": i + 1, "subject": f"s{i}", "text": "é" * 300} for i in range(10)]
        data, doc = envelope.pack(header, candidates, 4096)
        self.assertEqual(len(data), doc["budget"]["usedBytes"])
        self.assertLessEqual(len(data), 4096)
        self.assertEqual(json.loads(data.decode("utf-8")), doc)
        returned = doc["selection"]["returned"]
        self.assertTrue(0 < returned < 10)
        self.assertEqual(doc["selection"]["omittedCount"], 10 - returned)
        self.assertTrue(doc["selection"]["truncated"])
        self.assertEqual([o["rank"] for o in doc["selection"]["omitted"]],
                         list(range(returned + 1, 11))[: envelope.MAX_OMISSION_DETAILS])

    def test_a_single_oversize_record_is_reported_not_trimmed(self) -> None:
        data, doc = envelope.pack({"kind": "rank"}, [{"rank": 1, "subject": "s", "witness": "w" * 9000}], 8192)
        self.assertEqual((doc["status"], doc["selection"]["returned"]), ("record_too_large", 0))
        self.assertEqual(doc["selection"]["omitted"][0]["reason"], "record_too_large")
        tiny_data, tiny = envelope.pack({"kind": "rank", "pad": "p" * 600}, [{"rank": 1, "subject": "s"}], 256)
        self.assertEqual((tiny_data, tiny["status"], tiny["budget"]["maxBytes"]), (None, "budget_too_small", 256))
        self.assertLessEqual(len(data), 8192)
        data, doc = envelope.pack({"kind": "rank"}, [], 8192)
        self.assertEqual(doc["status"], "empty")
        with self.assertRaises(ValueError):
            envelope.pack({}, [], 10)


class EvaluationLogicTests(unittest.TestCase):
    def test_metrics_and_family_split(self) -> None:
        m = evaluate.metrics([("a", 1), ("b", 1), ("c", 1)], {"b": 2, "z": 1}, {"b", "c", "z"})
        self.assertEqual((m["hit@1"], m["hit@3"], m["rr@10"], m["firstRelevantRank"]), (0, 1, 0.5, 2))
        self.assertAlmostEqual(m["judged@8"], 2 / 3)
        self.assertGreater(m["ndcg@8"], 0)
        self.assertEqual(evaluate.metrics([], {"b": 2}, {"b"})["rr@10"], 0.0)
        qs = [{"questionID": f"p:{i}", "project": "p", "family": f"f{i}", "relevant": [{"symbol": "s" if i < 2 else f"t{i}"}],
               "nearMiss": []} for i in range(9)]
        split = splits.assign(qs)
        self.assertEqual(split["p:0"], split["p:1"])  # merged through the shared symbol
        self.assertGreaterEqual(sum(v == "dev" for v in split.values()), 3)

    def test_paired_bootstrap_is_deterministic_and_zero_for_identical_systems(self) -> None:
        rows = [{"questionID": f"q{i}", "project": "p" if i % 2 else "r", "family": f"f{i // 3}", "answerable": True,
                 "rr@10": (i % 4) / 4} for i in range(24)]
        result = evaluate.paired_bootstrap(rows, rows, rounds=200)
        self.assertEqual((result["observed"], result["ci95"]), (0.0, [0.0, 0.0]))
        better = [dict(r, **{"rr@10": min(1.0, r["rr@10"] + 0.25)}) for r in rows]
        self.assertEqual(evaluate.paired_bootstrap(better, rows, rounds=200), evaluate.paired_bootstrap(better, rows, rounds=200))


if __name__ == "__main__":
    unittest.main()
