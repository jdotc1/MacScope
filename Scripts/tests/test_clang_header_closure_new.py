"""NEW Lane D definitions, NOT RUN. No real libclang/SDK/tool access.

Future fixture execution requires a parent-selected ordinary Developer directory.
"""
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "types"))
import clang_import_configuration as configuration
import extract_clang_types as extractor


def profile(language="objective-c++", sdk="driverkit"):
    return {"target": "arm64-apple-"+sdk+"25.0", "architecture": "arm64",
            "deployment_target": "25.0", "language": language, "dialect": "c++17",
            "objc_runtime": "macosx-25.0", "arc": False, "blocks": False,
            "modules": "disabled", "include_roots": [], "framework_roots": [],
            "defines": [], "undefines": [], "sdk": sdk}


class HeaderClosureDefinitions(unittest.TestCase):
    def setUp(self):
        parent = Path(os.environ["LANE_D_FIXTURE_PARENT"])
        self.directory = tempfile.TemporaryDirectory(prefix="laneD-synthetic-", dir=parent)
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def header(self, name, text):
        path = self.root/name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)
        return path

    def test_literal_framework_include_is_explicit_unsaved_input(self):
        root = self.header("entry.hpp", '#include <DriverKit/Types.h>\nstruct Outer { int x; };\n')
        member = self.header("Types.h", 'struct Inner { int y; };\n')
        original, rewritten, names = extractor.prepare_header_closure(root, {"DriverKit/Types.h": member})
        self.assertIn(('#include "'+str(member)+'"').encode(), rewritten[root])
        self.assertEqual(names[member], "DriverKit/Types.h")
        self.assertEqual(original[member], b'struct Inner { int y; };\n')

    def test_unlisted_and_macro_include_refuse_before_parse(self):
        for text in ('#include <Missing.h>\n', '#include SELECTED\n', '#include_next "Types.h"\n', '#include <Types.h"\n'):
            root = self.header("entry.hpp", text)
            with self.assertRaises(extractor.ExtractionError): extractor.prepare_header_closure(root, {})

    def test_default_include_free_mode_stays_closed(self):
        root = self.header("entry.h", '#include "Types.h"\n')
        with self.assertRaises(extractor.ExtractionError): extractor.prepare_header_closure(root)

    def test_mapping_alias_and_escape_refuse(self):
        root = self.header("entry.h", 'struct A { int a; };\n')
        with self.assertRaises(extractor.ExtractionError): extractor.prepare_header_closure(root, {"../bad.h": root})
        with self.assertRaises(extractor.ExtractionError): extractor.prepare_header_closure(root, {"alias.h": root})

    def test_alternative_module_preprocessing_refuses(self):
        for text in ('%:include <Types.h>\n', '@import DriverKit;\n', 'import DriverKit;\n'):
            with self.assertRaises(extractor.ExtractionError):
                extractor.prepare_header_closure(self.header("entry.hpp", text), {})

    def test_objcpp_profile_and_wrong_sdk_target(self):
        self.assertEqual(configuration.validate_profile(profile())["language"], "objective-c++")
        wrong = profile(); wrong["target"] = "arm64-apple-macosx25.0"
        with self.assertRaises(configuration.ConfigurationError): configuration.validate_profile(wrong)
        wrong = profile(); wrong["dialect"] = "c17"
        with self.assertRaises(configuration.ConfigurationError): configuration.validate_profile(wrong)

    def test_namespace_and_nested_record_traversal_without_libclang(self):
        leaf = SimpleNamespace(kind=4)
        namespace = SimpleNamespace(kind=22)
        root = SimpleNamespace(kind=300)
        class Fake:
            def children(self, cursor):
                return [namespace] if cursor is root else [leaf] if cursor is namespace else []
        self.assertEqual(list(extractor.declaration_seeds(Fake(), root)), [leaf])

    def test_cpp_nonpod_layout_remains_unknown(self):
        self.assertEqual(extractor.record_layout(8, 8, [6])["status"], "known")
        self.assertEqual(extractor.record_layout(16, 8, [44, 6])["status"], "unknown")
        self.assertEqual(extractor.record_layout(16, 8, [21, 6])["status"], "unknown")

    def test_unknown_layout_propagates_by_value_not_pointer(self):
        nodes = {"r": {"kind": "record", "layout": {"status": "unknown", "reason": "base"}, "fields": []},
                 "t": {"kind": "typedef", "underlyingTypeID": "r", "layout": {"status": "known"}},
                 "p": {"kind": "pointer", "pointeeTypeID": "r", "layout": {"status": "known"}}}
        extractor.propagate_unknown_layouts(nodes)
        self.assertEqual(nodes["t"]["layout"]["status"], "unknown")
        self.assertEqual(nodes["p"]["layout"]["status"], "known")

    def test_selected_iorpc_enum_preserves_numeric_alias_unknown(self):
        doc = {"provenance": {"sdkRelease": "25.0", "sdkBuild": "synthetic-build", "architecture": "arm64"},
               "types": [{"id": "enum:Messages", "kind": "enumeration", "origin": {"header": "Messages.h", "line": 1, "column": 1},
                          "enumValues": [{"name": "Start", "value": "100"}, {"name": "Alias", "value": "100"}]}]}
        facts = extractor.iorpc_constant_candidates(doc, ["enum:Messages"])
        self.assertEqual(facts["sdkBuild"], "synthetic-build")
        self.assertTrue(all(item["status"] == "ambiguous-numeric-alias" for item in facts["constants"]))
        with self.assertRaises(extractor.ExtractionError): extractor.iorpc_constant_candidates(doc, ["missing"])


class PreprocessingAdmissionDefinitions(unittest.TestCase):
    """NEW D1 changed-boundary definitions; NOT RUN, no libclang."""
    setUp = HeaderClosureDefinitions.setUp
    header = HeaderClosureDefinitions.header
    def test_ff_vt_and_cr_directive_forms_refuse_before_parse(self):
        for text in ('\f#include "/unlisted/path.h"\n', '#\finclude "/unlisted/path.h"\n',
                     '\v#include "/unlisted/path.h"\n', '#\vinclude "/unlisted/path.h"\n',
                     '#include "Types.h"\r#include "/unlisted/path.h"\r'):
            with self.assertRaises(extractor.ExtractionError):
                extractor.prepare_header_closure(self.header("entry.hpp", text), {})

    def test_unlisted_include_probes_and_indirect_pragmas_refuse(self):
        for text in ('#if __has_include("/unlisted/path.h")\n#endif\n',
                     '#if __has_include_next(<Other.h>)\n#endif\n',
                     '#if __has_embed("unlisted.bin")\n#endif\n',
                     '_Pragma("clang module import Other")\n',
                     '#pragma clang module import Other\n',
                     '#pragma GCC dependency "/unlisted/path.h"\n'):
            with self.assertRaises(extractor.ExtractionError):
                extractor.prepare_header_closure(self.header("entry.hpp", text), {})

    def test_supported_whitespace_and_pack_preserve_literal_closure(self):
        root = self.header("entry.hpp", '\t# \tinclude <DriverKit/Types.h>\n#pragma pack(push, 1)\nstruct P { int x; };\n#pragma pack(pop)\n')
        member = self.header("Types.h", '#pragma once\nstruct Q { int y; };\n')
        _, rewritten, _ = extractor.prepare_header_closure(root, {"DriverKit/Types.h": member})
        self.assertIn(('#include "'+str(member)+'"').encode(), rewritten[root])
        self.assertIn(b'#pragma pack(push, 1)', rewritten[root])
