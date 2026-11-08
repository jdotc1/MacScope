#!/usr/bin/env python3
"""H18 portable tests: reference-matcher differential, masking, collisions, determinism,
reversible-name contract and typed refusals. Python 3.9+, standard library only, hermetic
(synthetic Mach-O objects; no zig, network or Apple tools)."""
import importlib.util
import json
import random
import struct
import sys
import tempfile
import unittest
import zlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "Scripts/research"))

from h18_known_library import evaluate, generate, image, project, refmatch as R, swiftcorpus  # noqa: E402

_spec = importlib.util.spec_from_file_location(
    "h18_fs_test_builders", REPO / "Scripts/function-signatures/tests/test_generate_compiler_rt_signatures.py")
B = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(B)
G = generate.G

N_SECT_EXT = 0x0F
N_SECT_LOCAL = 0x0E
N_UNDF_EXT = 0x01


def words(seed, count):
    rng = random.Random(seed)
    return b"".join(struct.pack("<I", rng.getrandbits(32) | 0x0800_0000) for _ in range(count))


def add_loh(obj: bytes, addresses_groups) -> bytes:
    """Append an LC_LINKER_OPTIMIZATION_HINT to a builder object (data at end of file)."""
    data = bytearray()
    for group in addresses_groups:
        data += _uleb(1) + _uleb(len(group))
        for address in group:
            data += _uleb(address)
    while len(data) % 8:
        data.append(0)
    ncmds, sizeofcmds = struct.unpack_from("<II", obj, 16)
    # Insert the 16-byte command right after the existing commands and shift every file offset.
    insert_at = 32 + sizeofcmds
    shifted = bytearray(obj[:insert_at]) + bytearray(16) + bytearray(obj[insert_at:])
    struct.pack_into("<II", shifted, 16, ncmds + 1, sizeofcmds + 16)
    # Fix the offsets in the segment/section/symtab built by B.macho64_object.
    seg = 32
    struct.pack_into("<Q", shifted, seg + 40, struct.unpack_from("<Q", shifted, seg + 40)[0] + 16)  # fileoff
    sect = seg + 72
    struct.pack_into("<I", shifted, sect + 48, struct.unpack_from("<I", shifted, sect + 48)[0] + 16)
    reloff = struct.unpack_from("<I", shifted, sect + 56)[0]
    if reloff:
        struct.pack_into("<I", shifted, sect + 56, reloff + 16)
    symtab = seg + 72 + 80
    symoff, nsyms, stroff, strsize = struct.unpack_from("<IIII", shifted, symtab + 8)
    struct.pack_into("<IIII", shifted, symtab + 8, symoff + 16, nsyms, stroff + 16, strsize)
    struct.pack_into("<IIII", shifted, insert_at, 0x2E, 16, len(shifted), len(data))
    return bytes(shifted + data)


def _uleb(value):
    out = bytearray()
    while True:
        byte = value & 0x7F
        value >>= 7
        out.append(byte | (0x80 if value else 0))
        if not value:
            return bytes(out)


def write_archive(directory: Path, name: str, objects) -> Path:
    path = directory / f"lib{name}.a"
    path.write_bytes(B.archive_with_symdef(objects))
    return path


def library_input(path, library="libx", profile="z13-O2", role="pack", version="1.0"):
    return generate.LibraryInput(library, version, "commit", profile, path, role)


class ReferenceMatcherDifferentialTests(unittest.TestCase):
    """The port against the shipped compiler-rt corpus and its oracle fixtures (the same
    assertions as CompilerRTFunctionSignatureOracleTests and FunctionSignatureCorpusTests)."""

    @classmethod
    def setUpClass(cls):
        cls.signatures = swiftcorpus.load_shipped_corpus()
        cls.matcher = R.Matcher(cls.signatures)
        cls.fixtures = json.loads(swiftcorpus.FIXTURES_PATH.read_text())
        cls.by_identity = {(s.name, s.library_name): s for s in cls.signatures}

    def candidate(self, fixture, data=None, refs=None):
        references = {r["instruction_offset"]: r["symbol_name"] for r in fixture["references"]}
        return R.Candidate(bytes(fixture["bytes"] if data is None else data),
                           references if refs is None else refs)

    def test_shipped_corpus_validates_completely(self):
        self.assertEqual(len(self.signatures), 244)
        self.assertEqual(self.matcher.validated_signature_count, 244)
        self.assertEqual(self.matcher.validation_issues, [])

    def test_reader_round_trips_the_generated_swift_bytes(self):
        records = [G.SignatureRecord(
            s.name, s.library_name, s.total_length, G.MaskedPattern(s.prefix.bytes, s.prefix.mask),
            G.ChecksumSpan(s.checksum.offset, s.checksum.byte_count, s.checksum.crc32),
            tuple(G.TailByteRun(r.offset, r.bytes, r.mask) for r in s.tail_runs),
            tuple(G.ImportedReference(r.instruction_offset, r.symbol_name) for r in s.references))
            for s in self.signatures]
        self.assertEqual(G.render_swift_corpus(records), swiftcorpus.CORPUS_PATH.read_bytes())

    def test_every_fixture_matches_its_identity_uniquely(self):
        self.assertEqual(len(self.fixtures), 244)
        for fixture in self.fixtures:
            result = self.matcher.match(self.candidate(fixture))
            self.assertEqual((result.kind, result.keys), ("unique", ((fixture["name"], fixture["library_name"]),)))

    def test_wildcard_mutations_preserve_identity_and_fixed_mutations_reject(self):
        mutated = checksum = tail = reference = 0
        for fixture in self.fixtures:
            sig = self.by_identity[(fixture["name"], fixture["library_name"])]
            data = bytearray(fixture["bytes"])
            changed = False
            for index, mask in enumerate(sig.prefix.mask):
                if mask == 0:
                    data[index] ^= 0xA5
                    changed = True
            for run in sig.tail_runs:
                for index, mask in enumerate(run.mask):
                    if mask == 0:
                        data[run.offset + index] ^= 0xA5
                        changed = True
            if changed:
                mutated += 1
                self.assertEqual(self.matcher.match(self.candidate(fixture, data)).kind, "unique")

            def rejected(index):
                d = bytearray(fixture["bytes"])
                d[index] ^= 1
                return self.matcher.match(self.candidate(fixture, d)).kind == "noMatch"

            self.assertTrue(rejected(list(sig.prefix.mask).index(0xFF)))
            if sig.checksum.byte_count:
                checksum += 1
                self.assertTrue(rejected(sig.checksum.offset))
            if sig.tail_runs:
                tail += 1
                self.assertTrue(rejected(sig.tail_runs[0].offset + list(sig.tail_runs[0].mask).index(0xFF)))
            if sig.references:
                reference += 1
                refs = {r["instruction_offset"]: r["symbol_name"] for r in fixture["references"]}
                refs[sig.references[0].instruction_offset] = "__MacScope_mutated_reference__"
                self.assertEqual(self.matcher.match(self.candidate(fixture, refs=refs)).kind, "noMatch")
            self.assertEqual(self.matcher.match(self.candidate(fixture, fixture["bytes"][:-1])).kind, "noMatch")
            self.assertEqual(self.matcher.match(self.candidate(fixture, fixture["bytes"] + [0])).kind, "noMatch")
        self.assertGreater(mutated, 0)
        self.assertGreater(checksum, 0)
        self.assertGreater(tail, 0)
        self.assertGreater(reference, 0)

    def test_crc_reference_vectors(self):
        self.assertEqual(R.crc32_iso_hdlc(b"123456789"), 0xCBF43926)
        self.assertEqual(R.crc32_iso_hdlc(b""), 0)
        data = bytes(range(256)) * 3
        self.assertEqual(R.crc32_iso_hdlc(data), zlib.crc32(data) & 0xFFFFFFFF)

    def test_swift_string_semantics_use_canonical_equivalence(self):
        base = self.signatures[0]
        composed = R.Signature("café", "lib", base.total_length, base.prefix, base.checksum, base.tail_runs,
                               base.references)
        decomposed = R.Signature("café", "lib", base.total_length, base.prefix, base.checksum,
                                 base.tail_runs, base.references)
        matcher = R.Matcher([composed, decomposed])
        self.assertEqual([i.reason for i in matcher.validation_issues], ["duplicatePredicate"])
        self.assertEqual(R.validation_reasons(R.Signature("a​b", "lib", base.total_length, base.prefix,
                                                          base.checksum)), ["invalidName"])  # Cf


class MaskingTests(unittest.TestCase):
    def _object(self, *, loh=None):
        code = bytearray(words(1, 32))  # 128 bytes, one exported function
        relocs = B.relocation(8, symbol_index=1, pcrel=True, length=2, external=True, kind=2)  # BRANCH26 @8
        relocs += B.relocation(40, symbol_index=1, pcrel=True, length=2, external=True, kind=3)  # PAGE21 @40
        relocs += B.relocation(44, symbol_index=1, pcrel=False, length=2, external=True, kind=4)  # PAGEOFF12
        obj = B.macho64_object(code=bytes(code), symbols=[("_f", N_SECT_EXT, 0), ("_ext", N_UNDF_EXT, 0, 0)],
                               relocations=relocs)
        return add_loh(obj, loh) if loh else obj

    def _derive(self, obj):
        parsed = G.parse_macho_object(obj, member_name="a.o", member_header_offset=8)
        parsed, added = generate.with_loh_sites(parsed, obj)
        atoms, drops = G.discover_function_atoms([parsed], ranlib_names_by_member={8: {"_f"}})
        self.assertEqual(drops, [])
        result = G.derive_signature(atoms[0], archive_defined_names={"_f"}, library_name="libx")
        return parsed, result.signature, added

    def assert_never_exact(self, sig, offsets):
        for site in offsets:
            for byte in range(site, site + 4):
                if byte < len(sig.prefix.mask):
                    self.assertEqual(sig.prefix.mask[byte], 0, f"prefix byte {byte} exact")
                    self.assertEqual(sig.prefix.bytes[byte], 0)
                end = sig.checksum.offset + sig.checksum.byte_count
                self.assertFalse(sig.checksum.byte_count and sig.checksum.offset <= byte < end,
                                 f"byte {byte} inside checksum span")
                for run in sig.tail_runs:
                    if run.offset <= byte < run.offset + len(run.bytes):
                        self.assertEqual(run.mask[byte - run.offset], 0, f"tail byte {byte} exact")

    def test_relocated_and_loh_bytes_are_never_exact_constraints(self):
        # LOH at 72/76/80: an ADRP/LDR/LDR triple whose third word carries no relocation.
        obj = self._object(loh=[(40, 44), (72, 76, 80)])
        parsed, sig, added = self._derive(obj)
        self.assertEqual(added, 3)  # 72, 76, 80 are new; 40/44 already relocation sites
        self.assert_never_exact(sig, [8, 40, 44, 72, 76, 80])
        self.assertEqual([(r.instruction_offset, r.symbol_name) for r in sig.references], [(8, "_ext")])

    def test_every_site_in_random_objects_is_masked(self):
        rng = random.Random(7)
        for trial in range(40):
            count = rng.randint(9, 64)
            code = words(100 + trial, count)
            sites = sorted(rng.sample(range(count), rng.randint(1, min(6, count))))
            relocs = b"".join(B.relocation(s * 4, symbol_index=1, pcrel=True, length=2, external=True, kind=2)
                              for s in sites)
            loh_sites = sorted(rng.sample(range(count), 2))
            obj = add_loh(B.macho64_object(code=code, symbols=[("_f", N_SECT_EXT, 0), ("_ext", N_UNDF_EXT, 0, 0)],
                                           relocations=relocs), [tuple(s * 4 for s in loh_sites)])
            parsed = G.parse_macho_object(obj, member_name="a.o", member_header_offset=8)
            parsed, _ = generate.with_loh_sites(parsed, obj)
            atoms, _ = G.discover_function_atoms([parsed], ranlib_names_by_member={8: {"_f"}})
            result = G.derive_signature(atoms[0], archive_defined_names={"_f"}, library_name="libx")
            if result.signature is None:
                continue
            self.assert_never_exact(result.signature, [s * 4 for s in sites + loh_sites])

    def test_malformed_loh_is_a_typed_parse_error(self):
        obj = bytearray(self._object(loh=[(8,)]))
        ncmds, sizeofcmds = struct.unpack_from("<II", obj, 16)
        loh_cmd = 32 + sizeofcmds - 16
        offset, size = struct.unpack_from("<II", obj, loh_cmd + 8)
        obj[offset:offset + size] = b"\x01\x81" + b"\xff" * (size - 2)  # unterminated ULEB
        with self.assertRaises(G.ParseError):
            generate.linker_optimization_hint_addresses(bytes(obj))


class PackTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_static_twin_and_cross_library_twin_become_candidates_not_names(self):
        body = words(11, 16)  # 64 bytes
        # libA: exported _pub and a static _helper with identical bytes.
        a = B.macho64_object(code=body + body, symbols=[("_pub", N_SECT_EXT, 0), ("_helper", N_SECT_LOCAL, 64)])
        # libB: exported _other with the same bytes as libA's _solo; libA's _solo is unique otherwise.
        solo = words(12, 16)
        a2 = B.macho64_object(code=solo, symbols=[("_solo", N_SECT_EXT, 0)])
        b = B.macho64_object(code=solo, symbols=[("_other", N_SECT_EXT, 0)])
        unique = B.macho64_object(code=words(13, 16), symbols=[("_alone", N_SECT_EXT, 0)])
        lib_a = write_archive(self.dir, "a", [("a.o", "_pub", a), ("a2.o", "_solo", a2), ("u.o", "_alone", unique)])
        lib_b = write_archive(self.dir, "b", [("b.o", "_other", b)])
        pack = generate.build_pack([library_input(lib_a, "liba"), library_input(lib_b, "libb")], [],
                                   mask_loh=True, pack_id="t")
        status = {(r["name"], r["library"]): r for r in pack["records"]}
        self.assertEqual(status[("_alone", "liba")]["status"], "accepted")
        self.assertEqual(status[("_pub", "liba")]["status"], "candidate-only")
        self.assertIn(["_helper", "liba"], status[("_pub", "liba")]["collision_identities"])
        self.assertEqual(status[("_solo", "liba")]["status"], "candidate-only")
        self.assertEqual(status[("_other", "libb")]["collision_identities"], [["_other", "libb"], ["_solo", "liba"]])
        # Rejections are retained with the reason even though the records stay as candidates.
        self.assertEqual(sum(1 for r in pack["rejections"] if r["reason"] == "predicate-collision"), 3)
        # Projection: the twin is a candidate set, never a name; v1 (accepted-only) abstains.
        matcher = evaluate.PackMatcher(pack)
        result = matcher.classify(R.Candidate(body, {}))
        self.assertEqual(result["h18"]["kind"], "candidates")
        self.assertIn(("_helper", "liba"), [tuple(i) for i in result["h18"]["identities"]])
        self.assertEqual(result["v1"]["kind"], "noMatch")
        both = matcher.classify(R.Candidate(solo, {}))
        self.assertEqual(both["h18"]["kind"], "candidates")
        self.assertEqual(both["h18"]["why"], "ambiguous")
        # The v1 rendering never contains candidate-only records.
        swift = generate.render_swift(pack).decode()
        self.assertIn('"_alone"', swift)
        self.assertNotIn('"_pub"', swift)
        self.assertNotIn('"_solo"', swift)

    def test_legacy_baseline_reproduces_per_library_rules(self):
        solo = words(12, 16)
        lib_a = write_archive(self.dir, "a", [("a2.o", "_solo", B.macho64_object(code=solo, symbols=[("_solo", N_SECT_EXT, 0)]))])
        lib_b = write_archive(self.dir, "b", [("b.o", "_other", B.macho64_object(code=solo, symbols=[("_other", N_SECT_EXT, 0)]))])
        pack = generate.build_pack([library_input(lib_a, "liba"), library_input(lib_b, "libb")], [],
                                   mask_loh=False, pack_id="x0", legacy=True)
        # Each library alone has no collision, so the existing rules emit both: a cross-library
        # equal predicate that the Swift matcher can only report as ambiguous.
        self.assertEqual(sorted(r["status"] for r in pack["records"]), ["accepted", "accepted"])
        result = evaluate.PackMatcher(pack).classify(R.Candidate(solo, {}))
        self.assertEqual(result["v1"]["kind"], "ambiguous")

    def test_negative_corpus_rejects_foreign_twins_and_marks_version_twins(self):
        shared, versioned = words(21, 16), words(22, 16)
        pack_lib = write_archive(self.dir, "p", [
            ("s.o", "_shared", B.macho64_object(code=shared, symbols=[("_shared", N_SECT_EXT, 0)])),
            ("v.o", "_inflate", B.macho64_object(code=versioned, symbols=[("_inflate", N_SECT_EXT, 0)]))])
        neg = write_archive(self.dir, "n", [
            ("x.o", "_unrelated", B.macho64_object(code=shared, symbols=[("_unrelated", N_SECT_EXT, 0)])),
            ("y.o", "_inflate", B.macho64_object(code=versioned, symbols=[("_inflate", N_SECT_EXT, 0)]))])
        pack = generate.build_pack([library_input(pack_lib, "zlib", version="1.3.1")],
                                   [library_input(neg, "zlib", role="dev-negative", version="1.2.13")],
                                   mask_loh=True, pack_id="t")
        names = {r["name"]: r for r in pack["records"]}
        self.assertNotIn("_shared", names)
        self.assertEqual([r["reason"] for r in pack["rejections"]], ["negative-corpus-collision"])
        self.assertEqual(names["_inflate"]["provenance"]["version_ambiguous_with"], ["zlib@1.2.13"])

    def test_pack_bytes_are_deterministic_under_input_reordering(self):
        objects = [(f"m{i}.o", f"_f{i}", B.macho64_object(code=words(30 + i, 12 + i), symbols=[(f"_f{i}", N_SECT_EXT, 0)]))
                   for i in range(6)]
        first = write_archive(self.dir, "a", objects)
        (self.dir / "r").mkdir()
        second = write_archive(self.dir / "r", "a", list(reversed(objects)))
        other = write_archive(self.dir, "b", [("b.o", "_g", B.macho64_object(code=words(99, 20), symbols=[("_g", N_SECT_EXT, 0)]))])
        p1 = generate.build_pack([library_input(first, "liba"), library_input(other, "libb")], [], mask_loh=True, pack_id="d")
        p2 = generate.build_pack([library_input(other, "libb"), library_input(second, "liba")], [], mask_loh=True, pack_id="d")
        strip = lambda p: {k: v for k, v in p.items() if k not in ("inputs", "generator_seconds")}
        self.assertEqual(generate.canonical_json(strip(p1)), generate.canonical_json(strip(p2)))
        self.assertEqual(generate.render_swift(p1), generate.render_swift(p2))

    def test_confidence_tiers_follow_the_preregistered_rules(self):
        sig = G.SignatureRecord("_f", "l", 128, G.MaskedPattern(b"\x01" * 32, b"\xff" * 32),
                                G.ChecksumSpan(32, 40, 0), (), ())
        record = generate.PackRecord(sig, None, None, {"p"}, dev_profile_support=2)
        self.assertEqual(generate.confidence_tier(record, 3), "high")  # 72 verified bytes, stable
        record.dev_profile_support = 1
        self.assertEqual(generate.confidence_tier(record, 3), "low")   # unstable, no references
        record.status = "candidate-only"
        self.assertEqual(generate.confidence_tier(record, 3), "candidate-only")

    def test_held_out_profiles_are_refused_as_generation_inputs(self):
        with self.assertRaises(generate.GenerationRefusal):
            generate.inputs_from_work_root(self.dir, ["z15-O2"], ("pack",))

    def test_oversized_archive_is_a_typed_refusal(self):
        path = write_archive(self.dir, "a", [("a.o", "_f", B.macho64_object(code=words(1, 16), symbols=[("_f", N_SECT_EXT, 0)]))])
        saved = generate.MAX_ARCHIVE_BYTES
        generate.MAX_ARCHIVE_BYTES = 16
        try:
            with self.assertRaises(generate.GenerationRefusal) as caught:
                generate.archive_atoms(library_input(path), mask_loh=True)
            self.assertEqual(caught.exception.reason, "archive-too-large")
        finally:
            generate.MAX_ARCHIVE_BYTES = saved

    def test_unparsable_member_is_retained_as_a_rejection_not_an_abort(self):
        good = B.macho64_object(code=words(5, 16), symbols=[("_f", N_SECT_EXT, 0)])
        path = write_archive(self.dir, "a", [("a.o", "_f", good), ("bad.o", "_g", b"\xcf\xfa\xed\xfe" + b"\0" * 8)])
        pack = generate.build_pack([library_input(path)], [], mask_loh=True, pack_id="t")
        self.assertEqual([r["name"] for r in pack["records"]], ["_f"])
        self.assertEqual([r["reason"] for r in pack["rejections"]], ["object-parse-error"])


class ReviewRegressionTests(unittest.TestCase):
    """Defects confirmed by the independent correctness review before the held-out run."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_twin_calling_a_locally_defined_function_still_collides(self):
        code = words(41, 16)
        call = B.relocation(8, symbol_index=1, pcrel=True, length=2, external=True, kind=2)
        f = B.macho64_object(code=code, symbols=[("_f", N_SECT_EXT, 0), ("_bar", N_UNDF_EXT, 0, 0)], relocations=call)
        # libb: static _g has _f's bytes; its call targets _bar defined in the same object.
        g = B.macho64_object(code=code + words(42, 4),
                             symbols=[("_g", N_SECT_LOCAL, 0), ("_bar", N_SECT_EXT, 64), ("_h", N_SECT_EXT, 64)],
                             relocations=call)
        lib_a = write_archive(self.dir, "a", [("f.o", "_f", f)])
        lib_b = write_archive(self.dir, "b", [("g.o", "_bar", g)])
        pack = generate.build_pack([library_input(lib_a, "liba"), library_input(lib_b, "libb")], [],
                                   mask_loh=True, pack_id="t")
        record = next(r for r in pack["records"] if r["name"] == "_f")
        self.assertEqual(record["status"], "candidate-only")
        self.assertIn(["_g", "libb"], record["collision_identities"])
        result = evaluate.PackMatcher(pack).classify(R.Candidate(code, {8: "_bar"}))
        self.assertNotEqual(result["h18"]["kind"], "name")
        self.assertEqual(result["v1"]["kind"], "noMatch")

    def test_pack_bytes_do_not_depend_on_profile_order(self):
        first = write_archive(self.dir, "a", [("m.o", "_f", B.macho64_object(code=words(51, 16), symbols=[("_f", N_SECT_EXT, 0)]))])
        (self.dir / "o").mkdir()
        second = write_archive(self.dir / "o", "a", [("m.o", "_f", B.macho64_object(code=words(51, 16), symbols=[("_f", N_SECT_EXT, 0)])),
                                                   ("n.o", "_g", B.macho64_object(code=words(51, 16), symbols=[("_g", N_SECT_EXT, 0)]))])
        a = [library_input(first, "liba", profile="z13-O1"), library_input(second, "liba", profile="z13-O2")]
        p1 = generate.build_pack(a, [], mask_loh=True, pack_id="d")
        p2 = generate.build_pack(list(reversed(a)), [], mask_loh=True, pack_id="d")
        self.assertEqual(generate.canonical_json(p1), generate.canonical_json(p2))

    def test_low_tier_records_stay_out_of_the_default_v1_rendering(self):
        lib = write_archive(self.dir, "a", [("t.o", "_tiny", B.macho64_object(code=words(61, 5), symbols=[("_tiny", N_SECT_EXT, 0)]))])
        pack = generate.build_pack([library_input(lib)], [], mask_loh=True, pack_id="t",
                                   support_inputs=[library_input(lib, profile="z13-Os")])
        record = pack["records"][0]
        self.assertEqual((record["status"], record["confidence"]), ("accepted", "low"))
        self.assertNotIn('"_tiny"', generate.render_swift(pack).decode())
        self.assertIn('"_tiny"', generate.render_swift(pack, min_tier="low").decode())

    def test_names_swift_would_quarantine_are_rejected(self):
        lib = write_archive(self.dir, "a", [("z.o", "_a\u200bb", B.macho64_object(code=words(71, 16), symbols=[("_a\u200bb", N_SECT_EXT, 0)]))])
        pack = generate.build_pack([library_input(lib)], [], mask_loh=True, pack_id="t")
        self.assertEqual(pack["records"], [])
        self.assertEqual([r["reason"] for r in pack["rejections"]], ["invalid-function-name"])

    def test_unparsable_member_caps_its_library_at_low(self):
        good = B.macho64_object(code=words(81, 32), symbols=[("_f", N_SECT_EXT, 0)])
        path = write_archive(self.dir, "a", [("a.o", "_f", good), ("bad.o", "_g", b"\xcf\xfa\xed\xfe" + b"\0" * 8)])
        pack = generate.build_pack([library_input(path)], [], mask_loh=True, pack_id="t",
                                   support_inputs=[library_input(path, profile="z13-Os")])
        self.assertEqual([r["confidence"] for r in pack["records"]], ["low"])

    def test_disagreeing_annotations_hide_no_evidence_across_tiers(self):
        state = project.NamingState({0x10: project.Function(0x10)})
        project.annotate(state, 0x10, {"kind": "name", "identity": ["_x", "a"], "tier": "high", "record": "r1"},
                         {"pack_id": "p1", "records": [{"id": "r1", "provenance": {"library_version": "1"}}]})
        project.annotate(state, 0x10, {"kind": "name", "identity": ["_y", "b"], "tier": "low", "record": "r2"},
                         {"pack_id": "p2", "records": [{"id": "r2", "provenance": {"library_version": "1"}}]})
        self.assertEqual(project.effective_name(state, 0x10), ("sub_10", "fallback"))
        self.assertEqual(project.candidates(state, 0x10), [("_x", "a"), ("_y", "b")])
        state2 = project.NamingState({0x10: project.Function(0x10)})
        project.annotate(state2, 0x10, {"kind": "name", "identity": ["_x", "a"], "tier": "high", "record": "r1"},
                         {"pack_id": "p1", "records": [{"id": "r1", "provenance": {"library_version": "1"}}]})
        project.annotate(state2, 0x10, {"kind": "candidates", "identities": [["_x", "a"], ["_y", "b"]], "why": "ambiguous"},
                         {"pack_id": "p2", "records": []})
        self.assertEqual(project.effective_name(state2, 0x10), ("sub_10", "fallback"))


class ImageRefusalTests(unittest.TestCase):
    def test_malformed_images_refuse_with_typed_reasons(self):
        for data, reason in [(b"", "truncated-header"), (b"\0" * 64, "not-arm64-macho64")]:
            with self.assertRaises(image.ImageRefusal) as caught:
                image.parse_image(data)
            self.assertEqual(caught.exception.reason, reason)
        header = struct.pack("<IIIIIIII", image.MH_MAGIC_64, image.CPU_TYPE_ARM64, 0, 2, 1, 4096, 0, 0)
        with self.assertRaises(image.ImageRefusal) as caught:
            image.parse_image(header)
        self.assertEqual(caught.exception.reason, "load-commands-out-of-bounds")

    def test_candidate_refuses_misaligned_or_oversized_ranges(self):
        img = image.Image(0, image.Section("__TEXT", "__text", 0x1000, 64, 0, 0, 0, 0), b"\0" * 64, 0x1000,
                          [], {}, {})
        self.assertIsNone(image.candidate_for(img, 0x1002, 0x1010, {}))
        self.assertIsNone(image.candidate_for(img, 0x1000, 0x1000, {}))
        self.assertIsNone(image.candidate_for(img, 0x1000, 0x1000 + 2_000_000, {}))
        self.assertEqual(len(image.candidate_for(img, 0x1000, 0x1040, {}).bytes), 64)

    def test_branch_to_stub_becomes_imported_reference(self):
        bl = struct.pack("<I", 0x94000000 | 4)  # bl +16
        text = bl + b"\0" * 28
        img = image.Image(0, image.Section("__TEXT", "__text", 0x1000, 32, 0, 0, 0, 0), text, 0x1000, [0x1000],
                          {0x1010: "_memcpy"}, {})
        cand = image.candidate_for(img, 0x1000, 0x1020, image.reference_names(img))
        self.assertEqual(cand.imported_references, {0: "_memcpy"})


class ExportTrieTests(unittest.TestCase):
    def test_export_trie_addresses_become_authoritative(self):
        # root: no terminal, 2 children "_a" -> node A, "_b" -> node B; A at 0x100, B re-export.
        node_a = bytes([3, 0]) + _uleb(0x100) + bytes([0])
        node_b = bytes([2, 0x08, 0]) + bytes([0])
        root_len = 1 + 1 + 3 + 1 + 3 + 1
        root = bytes([0, 2]) + b"_a\0" + bytes([root_len]) + b"_b\0" + bytes([root_len + len(node_a)])
        trie = root + node_a + node_b
        data = b"\0" * 16 + trie
        exports = image._parse_export_trie(data, (16, len(trie)), 0x100000000)
        self.assertEqual(exports, {0x100000100: ["_a"]})
        with self.assertRaises(image.ImageRefusal):
            image._parse_export_trie(data, (16, len(trie) + 64), 0)
        looping = bytes([0, 1]) + b"_x\0" + bytes([0])  # child points back to the root
        with self.assertRaises(image.ImageRefusal):
            image._parse_export_trie(looping, (0, len(looping)), 0)


class ReversibleNameContractTests(unittest.TestCase):
    PACK = {"pack_id": "p1", "records": [
        {"id": "r1", "provenance": {"library_version": "1.3.1"}},
        {"id": "r2", "provenance": {"library_version": "1.3.1"}}]}

    def state(self):
        return project.NamingState({
            0x10: project.Function(0x10),
            0x20: project.Function(0x20, "_exported", "export"),
            0x30: project.Function(0x30),
            0x40: project.Function(0x40)})

    def name(self, identity, tier="high", record="r1"):
        return {"kind": "name", "identity": identity, "tier": tier, "record": record}

    def test_authoritative_names_are_never_overwritten(self):
        state = self.state()
        project.annotate(state, 0x20, self.name(["_inflate", "zlib"]), self.PACK)
        self.assertEqual(project.effective_name(state, 0x20), ("_exported", "export"))
        project.rename(state, 0x20, "_analyst")
        self.assertEqual(project.effective_name(state, 0x20), ("_exported", "export"))

    def test_apply_revert_and_pack_removal_restore_the_exact_prior_name(self):
        state = self.state()
        before = project.snapshot(state, state.functions)
        project.annotate(state, 0x10, self.name(["_inflate", "zlib"]), self.PACK)
        project.annotate(state, 0x30, self.name(["_deflate", "zlib"], record="r2"), self.PACK)
        self.assertEqual(project.effective_name(state, 0x10), ("_inflate", "library-signature"))
        self.assertEqual(project.revert(state, 0x10), 1)
        self.assertEqual(project.effective_name(state, 0x10), before[0x10])
        self.assertEqual(project.remove_pack(state, "p1"), 2)
        self.assertEqual(project.snapshot(state, state.functions), before)

    def test_analyst_rename_wins_and_clearing_it_restores_the_library_name(self):
        state = self.state()
        project.annotate(state, 0x10, self.name(["_inflate", "zlib"]), self.PACK)
        project.rename(state, 0x10, "_my_inflate")
        self.assertEqual(project.effective_name(state, 0x10), ("_my_inflate", "analyst"))
        project.rename(state, 0x10, None)
        self.assertEqual(project.effective_name(state, 0x10), ("_inflate", "library-signature"))

    def test_candidates_and_below_threshold_matches_never_name_a_function(self):
        state = self.state()
        project.annotate(state, 0x10, {"kind": "candidates", "identities": [["_a", "x"], ["_b", "y"]],
                                       "why": "ambiguous"}, self.PACK)
        project.annotate(state, 0x30, self.name(["_low", "x"], tier="low"), self.PACK)
        self.assertEqual(project.effective_name(state, 0x10), ("sub_10", "fallback"))
        self.assertEqual(project.candidates(state, 0x10), [("_a", "x"), ("_b", "y")])
        self.assertEqual(project.effective_name(state, 0x30), ("sub_30", "fallback"))
        self.assertEqual(project.candidates(state, 0x30), [("_low", "x")])

    def test_disagreeing_packs_yield_candidates_not_a_choice(self):
        state = self.state()
        project.annotate(state, 0x40, self.name(["_x", "liba"]), self.PACK)
        project.annotate(state, 0x40, self.name(["_y", "libb"], record="r2"), {**self.PACK, "pack_id": "p2"})
        self.assertEqual(project.effective_name(state, 0x40), ("sub_40", "fallback"))
        self.assertEqual(project.candidates(state, 0x40), [("_x", "liba"), ("_y", "libb")])


class SwiftDifferentialTests(unittest.TestCase):
    """Runs the real product Swift matcher against refmatch when a Swift toolchain is given:
    H18_SWIFT_TOOLCHAIN=<root containing usr/libexec/swift/bin/swiftc> (Linux swiftlang layout)."""

    def test_product_swift_matcher_agrees_with_the_port(self):
        import os
        from h18_known_library import swiftdiff

        root = os.environ.get("H18_SWIFT_TOOLCHAIN")
        if not root or not swiftdiff.swiftc(Path(root)).exists():
            self.skipTest("H18_SWIFT_TOOLCHAIN not set")
        with tempfile.TemporaryDirectory() as tmp:
            code = swiftdiff.main(["run", "--toolchain", root, "--work-root", tmp, "--suites", "shipped", "fuzz",
                                   "--fuzz-count", "500"])
        self.assertEqual(code, 0)


if __name__ == "__main__":
    unittest.main()
