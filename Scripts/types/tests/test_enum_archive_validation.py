"""NEW pure in-memory producer validation definitions; no extraction fixtures.

Loading this module does not construct Clang or run the extractor. Synthetic
configuration/provenance strings are placeholders, not verification receipts.
"""
import copy
import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[3]
SPEC = importlib.util.spec_from_file_location("enum_validation_extractor", ROOT / "Scripts/types/extract_clang_types.py")
extractor = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(extractor)


def known(size=1):
    return {"status": "known", "sizeBytes": size, "alignmentBytes": 1}


def unknown():
    return {"status": "unknown", "reason": "synthetic unavailable layout"}


def node(identity, kind, layout, **properties):
    return dict(id=identity, kind=kind, spelling=identity, layout=layout,
                fields=[], enumValues=[], qualifiers=[], **properties)


def archive(signed=True, size=1, values=("0",)):
    base = node("integer", "scalar", known(size), signed=signed)
    enum = node("enum", "enumeration", known(size), underlyingTypeID="integer")
    enum["enumValues"] = [{"name": "value" + str(index), "value": value}
                          for index, value in enumerate(values)]
    return {"schema": "macscope.sdk-type-archive", "schemaMajor": 1, "schemaMinor": 0,
            "types": [base, enum]}


class EnumArchiveValidationTests(unittest.TestCase):
    def accept(self, doc):
        before = copy.deepcopy(doc)
        extractor.validate_archive(doc)
        self.assertEqual(doc, before, "validation must not normalize recorded facts")

    def refuse(self, doc):
        before = copy.deepcopy(doc)
        with self.assertRaises(extractor.ExtractionError):
            extractor.validate_archive(doc)
        self.assertEqual(doc, before, "refusal must not clamp or remove recorded facts")

    def test_signed_eight_bit_exact_edges_and_neighbors(self):
        self.accept(archive(values=("-128", "127")))
        for value in ("-129", "128"):
            self.refuse(archive(values=(value,)))

    def test_unsigned_eight_bit_exact_edges_and_neighbors(self):
        self.accept(archive(False, values=("0", "255")))
        for value in ("-1", "256"):
            self.refuse(archive(False, values=(value,)))

    def test_signed_64_bit_exact_edges_and_neighbors(self):
        self.accept(archive(True, 8, (str(-(1 << 63)), str((1 << 63) - 1))))
        for value in (-(1 << 63) - 1, 1 << 63):
            self.refuse(archive(True, 8, (str(value),)))

    def test_unsigned_64_bit_maximum_and_neighbors(self):
        self.accept(archive(False, 8, ("0", "18446744073709551615")))
        for value in ("-1", "18446744073709551616"):
            self.refuse(archive(False, 8, (value,)))

    def test_all_intermediate_known_width_edges(self):
        for size in range(2, 8):
            for signed in (True, False):
                low = -(1 << (size * 8 - 1)) if signed else 0
                high = (1 << (size * 8 - int(signed))) - 1
                self.accept(archive(signed, size, (str(low), str(high))))
                self.refuse(archive(signed, size, (str(low - 1),)))
                self.refuse(archive(signed, size, (str(high + 1),)))

    def test_noncanonical_strings_and_json_types_refused(self):
        for value in (True, False, 0, 1.0, None, [], {}, "", "+1", "01", "-01", "-0",
                      " 1", "1 ", "1\n", "0x10", "1e1", "1_0", "１２", "١", "9" * 100):
            with self.subTest(value=value):
                self.refuse(archive(values=(value,)))

    def test_duplicate_names_refused_but_numeric_aliases_preserved(self):
        doc = archive(values=("1", "1"))
        self.accept(doc)
        doc["types"][1]["enumValues"][1]["name"] = "value0"
        self.refuse(doc)

    def test_names_require_nonempty_bounded_text(self):
        for name in ("", None, 1, "x\0y", "x" * 16385):
            doc = archive()
            doc["types"][1]["enumValues"][0]["name"] = name
            self.refuse(doc)
        doc = archive()
        doc["types"][1]["enumValues"][0]["name"] = "x" * 16384
        self.accept(doc)

    def test_canonically_equivalent_names_refused_without_rewriting(self):
        doc = archive(values=("1", "2"))
        doc["types"][1]["enumValues"][0]["name"] = "caf\u00e9"
        doc["types"][1]["enumValues"][1]["name"] = "cafe\u0301"
        self.refuse(doc)

    def test_known_enum_requires_supported_integer_carrier(self):
        for size in (0, 9, 16):
            self.refuse(archive(True, size))
        for signed in (None, 0, 1, "true"):
            self.refuse(archive(signed))
        doc = archive()
        del doc["types"][0]["signed"]
        self.refuse(doc)

    def test_unknown_noninteger_base_accepts_only_64_bit_union(self):
        doc = archive(values=(str(-(1 << 63)), str((1 << 64) - 1)))
        doc["types"][0] = node("integer", "opaque", unknown())
        doc["types"][1]["layout"] = unknown()
        self.accept(doc)
        for value in (str(-(1 << 63) - 1), str(1 << 64), "-0", "+1"):
            bad = copy.deepcopy(doc)
            bad["types"][1]["enumValues"][0]["value"] = value
            self.refuse(bad)
        doc["types"][1]["layout"] = known()
        self.refuse(doc)

    def test_unknown_layout_preserves_available_signedness_without_width(self):
        for signed, invalid in ((True, str(1 << 63)), (False, "-1")):
            doc = archive(signed, 8, ("0",))
            for item in doc["types"]:
                item["layout"] = unknown()
            self.accept(doc)
            doc["types"][1]["enumValues"][0]["value"] = invalid
            self.refuse(doc)

    def test_unknown_enum_still_respects_known_narrow_carrier(self):
        doc = archive(False, 1, ("255",))
        doc["types"][1]["layout"] = unknown()
        self.accept(doc)
        doc["types"][1]["enumValues"][0]["value"] = "256"
        self.refuse(doc)

    def test_typedef_and_enumeration_carrier_links(self):
        doc = archive(False, 8, (str((1 << 64) - 1),))
        doc["types"].append(node("alias", "typedef", known(8), underlyingTypeID="integer"))
        doc["types"].append(node("inner", "enumeration", known(8), underlyingTypeID="alias"))
        doc["types"][1]["underlyingTypeID"] = "inner"
        self.accept(doc)

    def test_known_cycle_and_dangling_chain_refused(self):
        doc = archive()
        doc["types"].append(node("alias", "typedef", known(), underlyingTypeID="enum"))
        doc["types"][1]["underlyingTypeID"] = "alias"
        self.refuse(doc)
        doc["types"][2]["underlyingTypeID"] = "absent"
        self.refuse(doc)

    def test_unknown_cycle_remains_unknown_consumer_compatible(self):
        doc = archive(values=(str((1 << 64) - 1),))
        doc["types"][1]["layout"] = unknown()
        doc["types"].append(node("alias", "typedef", unknown(), underlyingTypeID="enum"))
        doc["types"][1]["underlyingTypeID"] = "alias"
        self.accept(doc)
        doc["types"][2]["underlyingTypeID"] = "absent"
        self.refuse(doc)

    def test_long_shared_carrier_chain_has_bounded_memoized_work(self):
        doc = archive()
        previous = "integer"
        for index in range(512):
            identity = "alias" + str(index)
            doc["types"].append(node(identity, "typedef", known(), underlyingTypeID=previous))
            previous = identity
        doc["types"][1]["underlyingTypeID"] = previous
        for index in range(256):
            doc["types"].append(node("enum" + str(index), "enumeration", known(), underlyingTypeID=previous))
        self.accept(doc)

    def test_enum_count_4096_and_4097(self):
        doc = archive()
        doc["types"][1]["enumValues"] = [{"name": "n" + str(i), "value": "0"} for i in range(4096)]
        self.accept(doc)
        doc["types"][1]["enumValues"].append({"name": "overflow", "value": "0"})
        self.refuse(doc)

    def test_pointer_dependency_remains_non_by_value(self):
        doc = archive()
        doc["types"].append(node("opaque", "opaque", unknown()))
        doc["types"].append(node("pointer", "pointer", known(8), pointeeTypeID="opaque"))
        self.accept(doc)

    def test_by_value_completeness_and_matching_layout_preserved(self):
        doc = archive()
        doc["types"][0]["layout"] = unknown()
        self.refuse(doc)
        doc = archive()
        doc["types"][1]["layout"] = known(2)
        self.refuse(doc)

    def test_bitfield_integer_resolution_preserved(self):
        doc = archive()
        record = node("record", "record", known(), recordKind="struct")
        record["fields"] = [{"id": "field", "name": "bits", "typeID": "enum", "bitOffset": 0,
                             "bitWidth": 1, "flexibleArray": False, "anonymous": False}]
        doc["types"].append(record)
        self.accept(doc)
        doc["types"][0].pop("signed")
        doc["types"][1]["layout"] = unknown()
        self.refuse(doc)

    def test_aggregate_node_bound_preserved(self):
        doc = archive()
        doc["types"].extend(node("extra" + str(i), "opaque", unknown()) for i in range(extractor.MAX_NODES))
        self.refuse(doc)

    def test_invalid_value_shape_refused(self):
        for values in ({}, [None], ["0"]):
            doc = archive()
            doc["types"][1]["enumValues"] = values
            self.refuse(doc)
