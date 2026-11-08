import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("corpus_run", ROOT / "corpus_run.py")
corpus_run = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(corpus_run)
FIXTURE = ROOT / "tests" / "fixtures" / "corpus_manifest.json"


class CorpusRunTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.corpus = Path(self.directory.name) / "corpus"
        self.run_dir = Path(self.directory.name) / "run_dir"
        self.corpus.mkdir()
        self.run_dir.mkdir()
        text = FIXTURE.read_text().replace("@CORPUS@", str(self.corpus))
        self.manifest = json.loads(text)

    def tearDown(self):
        self.directory.cleanup()

    def test_selection_and_skip_lists(self):
        images, skipped = corpus_run.select_images(self.manifest, self.corpus)
        self.assertEqual([(i["image"], i["opt"], i["product"]) for i in images], [
            ("maccy", "O", "Maccy"), ("maccy", "Osize", "Maccy"), ("stats", "O", "Stats"),
            ("stats", "O", "Kit"), ("stats", "O-resilient", "Kit")])
        self.assertEqual([(s["product"], s["reason"]) for s in skipped], [
            ("Autoupdate", "Sparkle helper executable"),
            ("Sparkle", "Sparkle framework, not corpus application code"),
            ("Net.framework_Versions_A_Net", "packaging copy of a framework product"),
            ("WidgetsExtension", "widget extension")])

    def test_framework_source_prefers_retained_bundle_then_build_products(self):
        images, _ = corpus_run.select_images(self.manifest, self.corpus)
        maccy = images[0]
        self.assertEqual(corpus_run.child_environment(maccy, self.run_dir, self.corpus),
                         ({}, {"source": None, "variable": "DYLD_FRAMEWORK_PATH", "missing": True}))
        fallback = self.corpus / corpus_run.RETAINED_TREX[1]
        fallback.mkdir(parents=True)
        environment, record = corpus_run.child_environment(maccy, self.run_dir, self.corpus)
        self.assertEqual(record["source"], corpus_run.RETAINED_TREX[1])
        bundle = self.corpus / corpus_run.RETAINED_TREX[0]
        bundle.mkdir(parents=True)
        environment, record = corpus_run.child_environment(maccy, self.run_dir, self.corpus)
        self.assertEqual(environment, {"DYLD_FRAMEWORK_PATH": str(bundle)})
        self.assertEqual(record["source"], corpus_run.RETAINED_TREX[0])

    def test_stats_uses_symlink_farm_except_for_the_resilient_build(self):
        images, _ = corpus_run.select_images(self.manifest, self.corpus)
        farm = corpus_run.build_stats_farm(self.run_dir, self.corpus)
        link = farm / "Kit.framework" / "Versions" / "A" / "Kit"
        self.assertTrue(link.is_symlink())
        self.assertEqual(link.resolve(), (self.corpus / "inputs" / "stats" / "O" / "Kit").resolve())
        self.assertEqual((farm / "Kit.framework" / "Versions" / "Current").readlink().name, "A")
        environment, record = corpus_run.child_environment(images[2], self.run_dir, self.corpus)
        self.assertEqual(environment, {"DYLD_FRAMEWORK_PATH": str(farm)})
        self.assertEqual(corpus_run.child_environment(images[4], self.run_dir, self.corpus)[0], {})

    def test_run_image_requests_isolation_and_retains_existing_receipt(self):
        images, _ = corpus_run.select_images(self.manifest, self.corpus)
        done = mock.Mock(returncode=1, stderr="loader failure", stdout="")
        with mock.patch.object(corpus_run.subprocess, "run", return_value=done) as run:
            record = corpus_run.run_image(images[0], self.run_dir, self.corpus, Path("/host"), "digest")
        self.assertIn("--isolate", run.call_args.args[0])
        self.assertEqual(record["host_sha256"], "digest")
        receipt = Path(record["receipt"])
        receipt.write_text("retained")
        with mock.patch.object(corpus_run.subprocess, "run") as run:
            with self.assertRaises(FileExistsError):
                corpus_run.run_image(images[0], self.run_dir, self.corpus, Path("/host"), "digest")
            run.assert_not_called()
        self.assertEqual(receipt.read_text(), "retained")

    def test_sha_256_is_computed_from_file_contents(self):
        path = self.corpus / "data"
        path.write_bytes(b"abc")
        self.assertEqual(corpus_run.sha256_of(path),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")


if __name__ == "__main__":
    unittest.main()
