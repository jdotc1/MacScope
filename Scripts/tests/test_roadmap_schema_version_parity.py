#!/usr/bin/env python3

from __future__ import annotations

from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
DATABASE = ROOT / "MacScope" / "Stores" / "WorkspaceDatabase.swift"
ROADMAP = ROOT / "docs" / "ROADMAP.md"


class RoadmapSchemaVersionParityTests(unittest.TestCase):
    def test_gate_f_schema_version_matches_workspace_database(self) -> None:
        swift = DATABASE.read_text(encoding="utf-8")
        database_match = re.search(
            r"final class WorkspaceDatabase\s*\{.*?"
            r"^\s*static let schemaVersion\s*=\s*(\d+)\s*$",
            swift,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(database_match, "outer WorkspaceDatabase schemaVersion not found")
        schema_version = int(database_match.group(1))

        roadmap = ROADMAP.read_text(encoding="utf-8")
        gate_start = roadmap.index("### Gate F")
        heading_end = roadmap.index("\n", gate_start) + 1
        next_heading = re.search(r"^##\s", roadmap[heading_end:], re.MULTILINE)
        gate_end = (
            heading_end + next_heading.start()
            if next_heading is not None
            else len(roadmap)
        )
        gate_f = roadmap[gate_start:gate_end]
        gate_match = re.search(r"Schema v(\d+)/package v3", gate_f)
        self.assertIsNotNone(gate_match, "docs/ROADMAP.md Gate F schema token not found")
        self.assertEqual(
            int(gate_match.group(1)),
            schema_version,
            f"docs/ROADMAP.md Gate F must name WorkspaceDatabase schema v{schema_version}",
        )
        self.assertIn(f"PRAGMA user_version = {schema_version};", swift)
        migration = re.search(
            r"private func migrateVersion38To39\(\) throws \{.*?^    \}",
            swift,
            re.MULTILINE | re.DOTALL,
        )
        self.assertIsNotNone(migration, "v38-to-v39 migration not found")
        self.assertIn("PRAGMA user_version = 39;", migration.group(0))


if __name__ == "__main__":
    unittest.main()
