"""Pure in-memory record-bitfield parity definitions.

No extraction, compiler, libclang loading, corpus, fixture files or publication.
"""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location(
    "record_bitfield_extractor", ROOT / "Scripts/types/extract_clang_types.py")
extractor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(extractor)


def known(size):
    return {"status": "known", "sizeBytes": size, "alignmentBytes": 1}


def node(identity, kind, layout, **facts):
    return {"id": identity, "kind": kind, "spelling": identity,
            "layout": layout, "fields": [], "enumValues": [], "qualifiers": [], **facts}


def archive(width=8, name="flags", carrier_size=1, record_size=8, offset=0):
    field = {"id": "record/field:0", "name": name, "typeID": "byte",
             "bitWidth": width, "bitOffset": offset, "flexibleArray": False,
             "anonymous": False}
    # Record first also exercises validation before the carrier's own loop turn.
    record = node("record", "record", known(record_size), recordKind="struct", fields=[field])
    carrier = node("byte", "scalar", known(carrier_size), signed=False)
    return {"schema": "macscope.sdk-type-archive", "schemaMajor": 1, "schemaMinor": 0,
            "configurationID": "a" * 64,
            "provenance": {"compiler": "fixture", "compilerVersion": "fixture",
                           "libclangVersion": "fixture", "sdkIdentity": "synthetic",
                           "targetTriple": "arm64-apple-macosx14.0", "language": "c",
                           "extractorVersion": "fixture", "input": "authored.h",
                           "inputSHA256": "b" * 64, "arguments": []},
            "diagnostics": [], "types": [record, carrier]}


class RecordBitfieldValidationTests(unittest.TestCase):
    def accepts_unchanged(self, document):
        before = copy.deepcopy(document)
        extractor.validate_archive(document)
        self.assertEqual(document, before)

    def refuses_unchanged(self, document, reason):
        before = copy.deepcopy(document)
        with self.assertRaisesRegex(extractor.ExtractionError, reason):
            extractor.validate_archive(document)
        self.assertEqual(document, before)

    def test_exact_carrier_width_is_accepted(self):
        self.accepts_unchanged(archive(width=8))

    def test_one_over_carrier_width_refuses_inside_large_record(self):
        self.refuses_unchanged(archive(width=9), "invalid bit width")

    def test_sixteen_bits_do_not_borrow_enclosing_storage(self):
        self.refuses_unchanged(archive(width=16), "invalid bit width")

    def test_named_zero_width_is_refused(self):
        self.refuses_unchanged(archive(width=0), "invalid bit width")

    def test_unnamed_zero_width_separator_at_record_end_is_preserved(self):
        self.accepts_unchanged(archive(width=0, name="", offset=64))

    def test_typedef_retained_layout_is_accepted(self):
        document = archive()
        document["types"][0]["fields"][0]["typeID"] = "alias"
        document["types"].append(node("alias", "typedef", known(1), underlyingTypeID="byte"))
        self.accepts_unchanged(document)

    def test_typedef_missing_retained_size_cannot_borrow_root_size(self):
        document = archive()
        document["types"][0]["fields"][0]["typeID"] = "alias"
        document["types"].append(node("alias", "typedef", {"status": "unknown", "reason": "unavailable"},
                                      underlyingTypeID="byte"))
        self.refuses_unchanged(document, "invalid bit width")

    def test_typedef_layout_mismatch_is_still_refused(self):
        document = archive(width=16)
        document["types"][0]["fields"][0]["typeID"] = "alias"
        document["types"].append(node("alias", "typedef", known(2), underlyingTypeID="byte"))
        self.refuses_unchanged(document, "underlying layout mismatch")

    def test_noninteger_carrier_is_still_refused(self):
        document = archive()
        del document["types"][1]["signed"]
        self.refuses_unchanged(document, "noninteger bitfield")

    def test_unknown_record_does_not_gain_known_layout_width_or_name_rules(self):
        for width in (0, 16):
            with self.subTest(width=width):
                document = archive(width=width)
                document["types"][0]["layout"] = {"status": "unknown", "reason": "unavailable"}
                self.accepts_unchanged(document)

    def test_unknown_record_still_requires_integer_carrier(self):
        document = archive()
        document["types"][0]["layout"] = {"status": "unknown", "reason": "unavailable"}
        del document["types"][1]["signed"]
        self.refuses_unchanged(document, "noninteger bitfield")

    def test_union_offset_refusal_and_zero_offset_positive_are_preserved(self):
        document = archive(offset=1)
        document["types"][0]["recordKind"] = "union"
        self.refuses_unchanged(document, "invalid field bit extent")
        document["types"][0]["fields"][0]["bitOffset"] = 0
        self.accepts_unchanged(document)

    def test_enclosing_extent_refusal_is_preserved(self):
        self.refuses_unchanged(archive(width=8, record_size=1, offset=1), "invalid field bit extent")

    def test_invalid_known_width_numeric_domain_is_refused(self):
        for width in (True, False, -1, 1 << 64, 1.0, "1", None):
            with self.subTest(width=width):
                self.refuses_unchanged(archive(width=width), "invalid bit width")

    def test_invalid_selected_carrier_size_is_refused_before_multiplication(self):
        for size in (True, False, -1, 1 << 61, 1.0, "1", None):
            with self.subTest(size=size):
                self.refuses_unchanged(archive(carrier_size=size), "invalid bit width")

    def test_missing_selected_carrier_size_is_refused(self):
        document = archive()
        del document["types"][1]["layout"]["sizeBytes"]
        self.refuses_unchanged(document, "invalid bit width")

    def test_largest_safe_retained_size_and_bit_extent(self):
        maximum_bytes = ((1 << 64) - 1) // 8
        self.accepts_unchanged(archive(width=maximum_bytes * 8,
                                      carrier_size=maximum_bytes, record_size=maximum_bytes))
        self.refuses_unchanged(archive(width=maximum_bytes * 8 + 1,
                                      carrier_size=maximum_bytes, record_size=maximum_bytes),
                               "invalid bit width")

    def test_invalid_offset_domain_and_addition_extent_still_refuse(self):
        for offset in (True, -1, 1 << 64, (1 << 64) - 1):
            with self.subTest(offset=offset):
                self.refuses_unchanged(archive(offset=offset), "invalid field bit extent")

    def test_flexible_array_bitfield_already_refuses_as_noninteger(self):
        document = archive()
        document["types"][0]["fields"][0].update(typeID="tail", flexibleArray=True)
        document["types"].append(node("tail", "array", {"status": "unknown", "reason": "incomplete"},
                                      elementTypeID="byte"))
        self.refuses_unchanged(document, "noninteger bitfield")

    def test_ordinary_field_behavior_is_unchanged(self):
        document = archive(record_size=1)
        del document["types"][0]["fields"][0]["bitWidth"]
        self.accepts_unchanged(document)
