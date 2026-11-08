#!/usr/bin/env python3

from __future__ import annotations

import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
ROADMAP = ROOT / "docs" / "ROADMAP.md"
CONTRACT = ROOT / "MacScope" / "PARITY_CONTRACT.md"
DCP05C_DOCUMENTS = (
    "docs/superpowers/specs/2026-08-12-dcp05c-native-product-convergence-design.md",
    "docs/superpowers/plans/2026-08-12-dcp05c-product-convergence-master.md",
    "docs/superpowers/plans/2026-08-12-dcp05c-native-wire.md",
    "docs/superpowers/plans/2026-08-12-dcp05c-runtime-admission.md",
    "docs/superpowers/plans/2026-08-12-dcp05c-authored-drive.md",
    "docs/superpowers/plans/2026-08-12-dcp05c-presentation-reconstruction.md",
)


class RoadmapGateStatusTests(unittest.TestCase):
    def test_live_gate_statuses_match_program_record_and_contract(self) -> None:
        roadmap = ROADMAP.read_text(encoding="utf-8")
        status = json.loads((ROOT / "docs/roadmap/PROGRAM_STATUS.yaml").read_text(encoding="utf-8"))
        contract = CONTRACT.read_text(encoding="utf-8")
        allowed = set(re.findall(r"(?m)^\d+\. `(PASSED|BLOCKED|GATED)` — ", contract))
        self.assertEqual(allowed, {"PASSED", "BLOCKED", "GATED"})
        for name in "EF":
            with self.subTest(gate=name):
                match = re.search(
                    rf"^### Gate {name}\b[^\n]*\n(?P<body>.*?)(?=^## |^### Gate |\Z)",
                    roadmap, re.MULTILINE | re.DOTALL,
                )
                self.assertIsNotNone(match, f"Gate {name} heading missing")
                verdict = status["gates"][f"gate_{name.lower()}"]["status"].upper()
                self.assertIn(verdict, allowed)
                stated = re.search(
                    rf"Gate {name} (?:is|remains) `?(PASSED|BLOCKED|GATED)`?\b",
                    match.group("body"), re.IGNORECASE,
                )
                self.assertIsNotNone(stated, f"Gate {name} lacks an explicit verdict")
                self.assertEqual(stated.group(1).upper(), verdict)

    def test_current_next_five_plan_is_linked_and_exists(self) -> None:
        roadmap = ROADMAP.read_text(encoding="utf-8")
        relative = "superpowers/plans/2026-09-01-next-five-program-execution.md"
        self.assertIn(f"]({relative})", roadmap)
        self.assertTrue((ROADMAP.parent / relative).is_file())
        self.assertIn("docs/roadmap/NEXT5_SOURCE_ADMISSION.json", roadmap)
        self.assertTrue((ROOT / "docs/roadmap/NEXT5_SOURCE_ADMISSION.json").is_file())

    def test_historical_dcp05c_spec_and_lane_plans_are_retained(self) -> None:
        for relative in DCP05C_DOCUMENTS:
            with self.subTest(path=relative):
                self.assertTrue((ROOT / relative).is_file(), f"historical DCP-05C document missing: {relative}")


if __name__ == "__main__":
    unittest.main()
