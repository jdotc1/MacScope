import hashlib
import json
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
STATUS_PATH = ROOT / "docs/qualification/oracles/PACKAGE_INTEGRATION_STATUS.json"
N9A_EVIDENCE_ROOT = ROOT / "docs/qualification/oracles/DCP05C-N9A"
SHA256 = re.compile(r"^[0-9a-f]{64}$")

EXPECTED_TASKS = {
    "DCP05C-A1A",
    "DCP05C-B1A",
    "DCP05C-C1A",
    "DCP05C-D1A",
    "DCP05C-E1A",
    "DCP05C-E3A",
    "DCP05C-F1A",
    "DCP05C-N8A",
    "DCP05C-N9A",
    "RECON-R1-T6A",
    "RECON-R1-T6B-INPUT",
    "RECON-R1-T10A-INPUT",
    "RECON-R1-T11A-INPUT",
    "MULTI-RETURN-HANDOFF",
}

ALLOWED_DISPOSITIONS = {
    "integrated_product_contract",
    "integrated_product_contract_with_remediation",
    "integrated_product_contract_with_repaired_evidence",
    "input_only_not_return_evidence",
    "coordination_input",
}


class OraclePackageIntegrationStatusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = STATUS_PATH.read_bytes()
        cls.document = json.loads(cls.raw)

    def test_schema_and_exact_archive_inventory(self):
        self.assertEqual(self.document["schema_version"], 1)
        packages = self.document["packages"]
        self.assertEqual({entry["task_id"] for entry in packages}, EXPECTED_TASKS)
        self.assertEqual(len(packages), len(EXPECTED_TASKS))
        self.assertEqual(len({entry["archive_filename"] for entry in packages}), len(packages))
        self.assertEqual(len({entry["archive_sha256"] for entry in packages}), len(packages))

    def test_every_entry_is_hash_bound_and_has_closed_disposition(self):
        for entry in self.document["packages"]:
            with self.subTest(task_id=entry["task_id"]):
                self.assertRegex(entry["archive_sha256"], SHA256)
                self.assertIn(entry["disposition"], ALLOWED_DISPOSITIONS)
                self.assertIsInstance(entry["product_pull_requests"], list)
                self.assertTrue(entry["archive_filename"].endswith(".zip"))

    def test_input_bundles_cannot_masquerade_as_completed_returns(self):
        for entry in self.document["packages"]:
            if entry["disposition"] == "input_only_not_return_evidence":
                with self.subTest(task_id=entry["task_id"]):
                    self.assertEqual(entry["return_status"], "input_only")
                    self.assertIn("INPUT", entry["task_id"])
                    self.assertIsNotNone(entry["remaining_action"])

    def test_repaired_n9a_return_names_hash_bound_evidence_path(self):
        repaired = [
            entry for entry in self.document["packages"]
            if entry["disposition"] == "integrated_product_contract_with_repaired_evidence"
        ]
        self.assertEqual([entry["task_id"] for entry in repaired], ["DCP05C-N9A"])
        self.assertEqual(
            repaired[0]["return_status"],
            "complete-with-reconstructed-closure",
        )
        self.assertEqual(
            repaired[0]["evidence_path"],
            "docs/qualification/oracles/DCP05C-N9A/",
        )
        self.assertIsNone(repaired[0]["remaining_action"])

    def test_repaired_n9a_sidecar_is_self_closed_and_matches_ledger(self):
        entry = next(
            item for item in self.document["packages"]
            if item["task_id"] == "DCP05C-N9A"
        )
        manifest = json.loads(
            (N9A_EVIDENCE_ROOT / "DCP05C_N9A_RETURN.json").read_text()
        )
        self.assertEqual(manifest["task_id"], "DCP05C-N9A")
        self.assertEqual(
            manifest["status"],
            "complete-with-reconstructed-closure",
        )
        self.assertEqual(
            manifest["original_archive"]["sha256"],
            entry["archive_sha256"],
        )
        self.assertFalse(
            manifest["decision"]["production_memory_ssa_enabled"]
        )
        self.assertTrue(
            manifest["standalone"]["patch_replay_all_tree_hashes_match"]
        )
        self.assertTrue(manifest["standalone"]["patch_replay_clean"])

        expected_files = {
            path.name for path in N9A_EVIDENCE_ROOT.iterdir()
            if path.is_file() and path.name != "bundle.sha256"
        }
        observed_files = set()
        mismatches = {}
        for line in (N9A_EVIDENCE_ROOT / "bundle.sha256").read_text().splitlines():
            digest, name = line.split("  ", 1)
            self.assertRegex(digest, SHA256)
            self.assertEqual(Path(name).name, name)
            target = N9A_EVIDENCE_ROOT / name
            self.assertTrue(target.is_file(), name)
            actual = hashlib.sha256(target.read_bytes()).hexdigest()
            if actual != digest:
                mismatches[name] = {"expected": digest, "actual": actual}
            observed_files.add(name)
        self.assertEqual(observed_files, expected_files)
        self.assertEqual(mismatches, {}, json.dumps(mismatches, sort_keys=True))

    def test_n9a_patch_replay_preserves_all_recorded_trees(self):
        replay = json.loads(
            (N9A_EVIDENCE_ROOT / "PATCH_REPLAY.json").read_text()
        )
        self.assertEqual(replay["patch_count"], 8)
        self.assertTrue(replay["all_tree_hashes_match"])
        self.assertTrue(replay["replay_worktree_clean"])
        self.assertEqual(
            [item["tree"] for item in replay["expected_series"]],
            [item["tree"] for item in replay["replayed_series"]],
        )
        self.assertEqual(
            replay["expected_final_tree"],
            replay["replayed_final_tree"],
        )
        archive_line = (
            N9A_EVIDENCE_ROOT / "ORIGINAL_ARCHIVE.sha256"
        ).read_text().strip()
        archive_digest, archive_name = archive_line.split("  ", 1)
        self.assertRegex(archive_digest, SHA256)
        self.assertEqual(
            archive_name,
            "oracle-package.zip",
        )

    def test_integrated_entries_name_product_pull_requests(self):
        for entry in self.document["packages"]:
            if entry["disposition"].startswith("integrated_product_contract"):
                with self.subTest(task_id=entry["task_id"]):
                    self.assertTrue(entry["product_pull_requests"])
                    self.assertTrue(all(isinstance(number, int) and number > 0
                                        for number in entry["product_pull_requests"]))

    def test_canonical_json_is_stable_and_utf8(self):
        decoded = self.raw.decode("utf-8")
        self.assertTrue(decoded.endswith("\n"))
        reparsed = json.loads(decoded)
        canonical = json.dumps(reparsed, sort_keys=True, separators=(",", ":"))
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        self.assertRegex(digest, SHA256)


if __name__ == "__main__":
    unittest.main()
