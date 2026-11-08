import json
from pathlib import Path
import tempfile
import unittest

from driverkit_catalog import CatalogError, canonicalize, create, verify, canonical_bytes, digest


def sample():
    return {
        "schemaVersion": 1, "release": 25, "architecture": "arm64",
        "sdkBuildIdentifier": "Xcode27.synthetic",
        "classes": [
            {"name": "IOService", "parentName": None, "sizeBytes": 16, "fields": []},
            {"name": "ExampleDriver", "parentName": "IOService", "sizeBytes": 32,
             "fields": [{"name": "queue", "typeName": "IOQueue*", "offsetBytes": 16, "sizeBytes": 8}]},
        ],
        "messages": [{"id": 100, "name": "IOService_Start_ID"}],
    }


class DriverKitCatalogTests(unittest.TestCase):
    def test_canonical_roundtrip(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            source = directory / "source.json"
            source.write_text(json.dumps(sample()), encoding="utf-8")
            catalog = directory / "catalog.json"
            manifest = directory / "manifest.json"
            create(source, catalog, manifest)
            verify(catalog, manifest)
            self.assertIn('"architecture":"arm64"', catalog.read_text())

    def test_sdk_release_19_is_rejected_for_arm64(self):
        bad = sample()
        bad["release"] = 19
        with self.assertRaises(CatalogError):
            canonicalize(bad)

    def test_duplicate_class_rejected(self):
        bad = sample()
        bad["classes"].append(bad["classes"][0])
        with self.assertRaises(CatalogError):
            canonicalize(bad)

    def test_oversize_field_rejected(self):
        bad = sample()
        bad["classes"][1]["fields"][0]["offsetBytes"] = 31
        with self.assertRaises(CatalogError):
            canonicalize(bad)

    def test_duplicate_message_id_rejected(self):
        bad = sample()
        bad["messages"].append({"id": 100, "name": "DifferentName"})
        with self.assertRaises(CatalogError):
            canonicalize(bad)

    def test_bool_not_an_integer(self):
        bad = sample()
        bad["release"] = True
        with self.assertRaises(CatalogError):
            canonicalize(bad)

    def test_manifest_tamper_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            source = directory / "source.json"
            source.write_text(json.dumps(sample()), encoding="utf-8")
            catalog = directory / "catalog.json"
            manifest = directory / "manifest.json"
            create(source, catalog, manifest)
            doc = json.loads(manifest.read_text())
            doc["catalogSHA256"] = "0" * 64
            manifest.write_text(json.dumps(doc), encoding="utf-8")
            with self.assertRaises(CatalogError):
                verify(catalog, manifest)

    def test_cannot_overwrite_old_catalog(self):
        with tempfile.TemporaryDirectory() as root:
            directory = Path(root)
            source = directory / "source.json"
            source.write_text(json.dumps(sample()), encoding="utf-8")
            catalog = directory / "catalog.json"
            manifest = directory / "manifest.json"
            create(source, catalog, manifest)
            with self.assertRaises(CatalogError):
                create(source, catalog, manifest)

    def test_inheritance_cycle_rejected(self):
        bad = sample()
        bad["classes"][0]["parentName"] = "ExampleDriver"
        with self.assertRaises(CatalogError):
            canonicalize(bad)

    def test_inherited_and_sibling_overlap_rejected(self):
        bad = sample()
        bad["classes"][1]["fields"][0]["offsetBytes"] = 8
        with self.assertRaises(CatalogError):
            canonicalize(bad)
        sibling = sample()
        sibling["classes"][1]["fields"].append({
            "name": "alias", "typeName": "UInt64", "offsetBytes": 20, "sizeBytes": 8
        })
        with self.assertRaises(CatalogError):
            canonicalize(sibling)

    def test_python_canonical_golden_wire(self):
        fixture = (
            Path(__file__).resolve().parents[2]
            / "Packages/NEWFEATURESCore/Tests/NEWFEATURESCoreTests/Fixtures/python-golden-catalog.json"
        )
        wire = fixture.read_bytes()
        self.assertEqual(
            digest(wire), "b673965fa3d93a4f481d45bf8dc9016d7397e2ccf5a0a9a12ec13e0b78dca834"
        )
        self.assertEqual(wire, canonical_bytes(canonicalize(json.loads(wire))))


if __name__ == "__main__":
    unittest.main()
