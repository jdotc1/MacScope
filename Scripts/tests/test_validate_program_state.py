#!/usr/bin/env python3
"""Tests for the live MacScope program-state validator."""

from __future__ import annotations

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
VALIDATOR = ROOT / "Scripts/validate_program_state.py"


def load_validator():
    specification = importlib.util.spec_from_file_location("validate_program_state", VALIDATOR)
    if specification is None or specification.loader is None:
        raise AssertionError("could not load program-state validator")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def run_git(repository: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", "-C", str(repository), *arguments],
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


class ProgramStateValidatorTests(unittest.TestCase):
    def setUp(self) -> None:
        self.module = load_validator()
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name)
        run_git(self.repository.parent, "init", "--initial-branch=main", str(self.repository))
        run_git(self.repository, "config", "user.email", "validator@example.invalid")
        run_git(self.repository, "config", "user.name", "Program Validator")
        (self.repository / "base.txt").write_text("base\n", encoding="utf-8")
        run_git(self.repository, "add", "base.txt")
        run_git(self.repository, "commit", "-m", "base")
        self.base_sha = run_git(self.repository, "rev-parse", "HEAD")
        self.base_tree = run_git(self.repository, "show", "-s", "--format=%T", "HEAD")
        run_git(self.repository, "remote", "add", "origin", str(self.repository))
        run_git(
            self.repository,
            "update-ref",
            "refs/remotes/origin/main",
            self.base_sha,
        )
        run_git(self.repository, "switch", "-c", "topic/test-lane")
        roadmap = self.repository / "docs" / "ROADMAP.md"
        roadmap.parent.mkdir(parents=True)
        roadmap.write_text(
            "### Gate E — fixture\n\n"
            "presentation convergence is not integrated\n\n"
            "### Gate F — fixture\n",
            encoding="utf-8",
        )
        run_git(self.repository, "add", "docs/ROADMAP.md")
        run_git(self.repository, "commit", "-m", "roadmap")
        self.base_sha = run_git(self.repository, "rev-parse", "HEAD")
        self.base_tree = run_git(self.repository, "show", "-s", "--format=%T", "HEAD")
        run_git(self.repository, "update-ref", "refs/heads/main", self.base_sha)
        run_git(
            self.repository,
            "update-ref",
            "refs/remotes/origin/main",
            self.base_sha,
        )
        (self.repository / "owned.txt").write_text("owned\n", encoding="utf-8")
        run_git(self.repository, "add", "owned.txt")
        run_git(self.repository, "commit", "-m", "owned")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def status(self) -> dict:
        return {
            "schema_version": 1,
            "as_of_utc": "2026-08-16T00:00:00Z",
            "canonical_main": {"sha": self.base_sha, "tree": self.base_tree},
            "active_initiative": "DCP-05C",
            "gates": {
                "gate_e": {
                    "status": "blocked",
                    "blockers": ["DCP05C-E-NOT-INTEGRATED"],
                },
                "reconstruction_task_6": {"status": "gated"},
                "reconstruction_task_10": {"status": "gated"},
            },
            "lanes": [{
                "id": "lane",
                "status": "active",
                "base_sha": self.base_sha,
                "head_branch": "topic/test-lane",
                "owns": ["owned.txt"],
                "excludes": ["forbidden/**"],
            }],
        }

    def authoritative_status(self) -> dict:
        status = self.status()
        correction = self.repository / "correction.txt"
        correction.write_text("bounded correction\n", encoding="utf-8")
        run_git(self.repository, "add", "correction.txt")
        run_git(self.repository, "commit", "-m", "bounded correction")
        run_git(
            self.repository,
            "update-ref",
            "refs/remotes/gitfox-local/topic/test-lane",
            "HEAD",
        )
        status["local_authority"] = {
            "delivery_remote": "gitfox-local",
            "head_branch": "topic/test-lane",
            "integration_branch": "topic/test-lane",
            "integration_ref": "refs/remotes/gitfox-local/topic/test-lane",
        }
        status["lanes"][0]["integrated_claims"] = ["bounded-correction"]
        status["lanes"].append({
            "id": "bounded-correction",
            "status": self.module.INTEGRATED_CLAIM_STATUS,
            "base_sha": self.base_sha,
            "head_branch": "topic/test-lane",
            "owns": ["correction.txt"],
            "excludes": [],
        })
        return status

    def test_accepts_exact_base_and_complete_active_claim(self) -> None:
        self.module.validate(self.status(), self.repository)

    def test_rejects_canonical_commit_or_tree_drift(self) -> None:
        status = self.status()
        status["canonical_main"]["sha"] = "0" * 40
        with self.assertRaisesRegex(self.module.ProgramStateError, "canonical_main.sha"):
            self.module.validate(status, self.repository)
        status = self.status()
        status["canonical_main"]["tree"] = "f" * 40
        with self.assertRaisesRegex(self.module.ProgramStateError, "canonical_main.tree"):
            self.module.validate(status, self.repository)

    def test_integrated_main_accepts_recorded_base_and_rejects_descendant(self) -> None:
        status = self.status()
        self.module.validate_integrated_canonical_main(status, self.repository)

        descendant = run_git(self.repository, "rev-parse", "HEAD")
        status["canonical_main"] = {
            "sha": descendant,
            "tree": run_git(self.repository, "show", "-s", "--format=%T", descendant),
        }
        with self.assertRaisesRegex(
            self.module.ProgramStateError,
            "is not an ancestor of main",
        ):
            self.module.validate_integrated_canonical_main(status, self.repository)

    def canonical_remote_status(self) -> dict:
        status = self.status()
        status["canonical_main"].update({
            "ref": "refs/remotes/github/main",
            "repository": "https://github.com/jdotc1/MacScope.git",
        })
        return status

    def test_integrated_canonical_accepts_verified_local_and_ci_aliases(self) -> None:
        for remote, url in (
            ("github", "https://github.com/jdotc1/MacScope.git"),
            ("origin", "git@github.com:jdotc1/MacScope.git"),
            ("upstream", "ssh://git@github.com/jdotc1/MacScope.git"),
        ):
            with self.subTest(remote=remote):
                if remote != "origin":
                    run_git(self.repository, "remote", "rename", "origin", remote)
                run_git(self.repository, "remote", "set-url", remote, url)
                run_git(self.repository, "update-ref", f"refs/remotes/{remote}/main", "HEAD")
                self.module.validate_integrated_canonical_main(self.canonical_remote_status(), self.repository)
                if remote != "origin":
                    run_git(self.repository, "remote", "rename", remote, "origin")

    def test_integrated_canonical_does_not_trust_remote_name(self) -> None:
        status = self.canonical_remote_status()
        run_git(self.repository, "remote", "set-url", "origin", status["canonical_main"]["repository"])
        run_git(self.repository, "remote", "add", "github", "https://github.com/other/MacScope.git")
        unrelated = run_git(self.repository, "commit-tree", self.base_tree, "-m", "unrelated root")
        run_git(self.repository, "update-ref", "refs/remotes/github/main", unrelated)
        self.module.validate_integrated_canonical_main(status, self.repository)

    def test_integrated_canonical_rejects_disagreeing_verified_aliases(self) -> None:
        status = self.canonical_remote_status()
        url = status["canonical_main"]["repository"]
        run_git(self.repository, "remote", "set-url", "origin", url)
        run_git(self.repository, "remote", "add", "github", url)
        run_git(self.repository, "update-ref", "refs/remotes/github/main", "HEAD")
        with self.assertRaisesRegex(self.module.ProgramStateError, "aliases disagree"):
            self.module.validate_integrated_canonical_main(status, self.repository)

    def test_integrated_canonical_rejects_wrong_repository_and_absent_ref(self) -> None:
        status = self.canonical_remote_status()
        run_git(self.repository, "remote", "rename", "origin", "github")
        run_git(self.repository, "remote", "set-url", "github", "https://github.com/other/MacScope.git")
        with self.assertRaisesRegex(self.module.ProgramStateError, "no canonical remote-tracking ref"):
            self.module.validate_integrated_canonical_main(status, self.repository)
        run_git(self.repository, "remote", "set-url", "github", status["canonical_main"]["repository"])
        run_git(self.repository, "update-ref", "-d", "refs/remotes/github/main")
        with self.assertRaisesRegex(self.module.ProgramStateError, "no canonical remote-tracking ref"):
            self.module.validate_integrated_canonical_main(status, self.repository)

    def test_integrated_canonical_rejects_divergent_lineage_and_frozen_tree_drift(self) -> None:
        status = self.canonical_remote_status()
        run_git(self.repository, "remote", "set-url", "origin", status["canonical_main"]["repository"])
        unrelated = run_git(self.repository, "commit-tree", self.base_tree, "-m", "unrelated root")
        run_git(self.repository, "update-ref", "refs/remotes/origin/main", unrelated)
        with self.assertRaisesRegex(self.module.ProgramStateError, "is not an ancestor"):
            self.module.validate_integrated_canonical_main(status, self.repository)
        run_git(self.repository, "update-ref", "refs/remotes/origin/main", "HEAD")
        status["canonical_main"]["tree"] = "f" * 40
        with self.assertRaisesRegex(self.module.ProgramStateError, "canonical_main.tree"):
            self.module.validate_integrated_canonical_main(status, self.repository)

    def test_strict_canonical_validation_does_not_substitute_ci_alias(self) -> None:
        status = self.canonical_remote_status()
        run_git(self.repository, "remote", "set-url", "origin", status["canonical_main"]["repository"])
        with self.assertRaises(self.module.ProgramStateError):
            self.module.validate_canonical_main(status, self.repository)
        run_git(self.repository, "remote", "rename", "origin", "github")
        run_git(self.repository, "update-ref", "refs/remotes/github/main", "HEAD")
        with self.assertRaisesRegex(self.module.ProgramStateError, "canonical_main.sha"):
            self.module.validate_canonical_main(status, self.repository)

    def test_local_validation_ignores_remote_drift_and_rejects_local_main_drift(self) -> None:
        status = self.status()
        descendant = run_git(self.repository, "rev-parse", "HEAD")
        run_git(
            self.repository,
            "update-ref",
            "refs/remotes/origin/main",
            descendant,
        )
        self.module.validate_canonical_main(status, self.repository)

        run_git(self.repository, "update-ref", "refs/heads/main", descendant)
        with self.assertRaisesRegex(
            self.module.ProgramStateError,
            "canonical_main.sha",
        ):
            self.module.validate_canonical_main(status, self.repository)

    def test_rejects_unowned_or_excluded_changed_paths(self) -> None:
        status = self.status()
        status["lanes"][0]["owns"] = ["different.txt"]
        with self.assertRaisesRegex(self.module.ProgramStateError, "does not own changed paths"):
            self.module.validate(status, self.repository)
        forbidden = self.repository / "forbidden"
        forbidden.mkdir()
        (forbidden / "state.txt").write_text("no\n", encoding="utf-8")
        run_git(self.repository, "add", "forbidden/state.txt")
        run_git(self.repository, "commit", "-m", "forbidden")
        status = self.status()
        status["lanes"][0]["owns"].append("forbidden/**")
        with self.assertRaisesRegex(self.module.ProgramStateError, "changed excluded paths"):
            self.module.validate(status, self.repository)

    def test_rejects_duplicate_lane_claims_and_unknown_dependencies(self) -> None:
        status = self.status()
        status["lanes"].append({
            "id": "second",
            "status": "queued",
            "owns": ["owned.txt"],
        })
        with self.assertRaisesRegex(self.module.ProgramStateError, "both claim owned.txt"):
            self.module.validate(status, self.repository)
        status = self.status()
        status["lanes"][0]["depends_on"] = ["missing"]
        with self.assertRaisesRegex(self.module.ProgramStateError, "unknown lane"):
            self.module.validate(status, self.repository)

    def test_authoritative_local_integration_accepts_active_and_closed_claims(self) -> None:
        status = self.authoritative_status()
        self.module.validate_shape(status)
        self.module.validate_authoritative_local_integration_claim(
            status, self.repository
        )

    def test_authoritative_local_integration_rejects_stale_or_incomplete_claims(self) -> None:
        status = self.authoritative_status()
        stale_status = copy.deepcopy(status)
        stale_status["lanes"][0]["head_branch"] = "topic/stale-task11-branch"
        with self.assertRaisesRegex(
            self.module.ProgramStateError,
            "must have exactly one active lane claim",
        ):
            self.module.validate_authoritative_local_integration_claim(
                stale_status, self.repository
            )

        unowned_status = copy.deepcopy(status)
        unowned_status["lanes"][0]["owns"] = []
        with self.assertRaisesRegex(
            self.module.ProgramStateError,
            "does not own changed paths: owned.txt",
        ):
            self.module.validate_authoritative_local_integration_claim(
                unowned_status, self.repository
            )

    def test_authoritative_local_integration_rejects_ambiguous_ownership(self) -> None:
        status = self.authoritative_status()
        status["lanes"][1]["owns"].append("owned.txt")
        with self.assertRaisesRegex(
            self.module.ProgramStateError,
            "multiply owned changed paths: owned.txt",
        ):
            self.module.validate_authoritative_local_integration_claim(
                status, self.repository
            )

    def test_rejects_ungated_reconstruction_and_missing_qualification_receipt(self) -> None:
        status = self.status()
        status["gates"]["reconstruction_task_6"]["status"] = "active"
        with self.assertRaisesRegex(self.module.ProgramStateError, "must remain gated"):
            self.module.validate(status, self.repository)
        status = self.status()
        status["lanes"][0]["qualification"] = {
            "status": "qualified",
            "exact_head": run_git(self.repository, "rev-parse", "HEAD"),
            "receipt": "missing.json",
        }
        with self.assertRaisesRegex(self.module.ProgramStateError, "receipt is missing"):
            self.module.validate(status, self.repository)

    def test_github_state_rejects_ready_blocked_pr_and_head_drift(self) -> None:
        status = self.status()
        status["pull_requests"] = [{
            "number": 204,
            "state": "open",
            "is_draft": True,
            "disposition": "blocked-source-only",
            "head_sha": "a" * 40,
        }]
        status["lanes"][0]["source_prs"] = [204]

        def ready_pr(_repository: Path, _number: int) -> dict:
            return {
                "number": 204,
                "state": "OPEN",
                "isDraft": False,
                "headRefName": "topic/source",
                "headRefOid": "a" * 40,
                "body": "complete",
            }

        with self.assertRaisesRegex(self.module.ProgramStateError, "draft state"):
            self.module.validate_pull_requests(status, self.repository, ready_pr)

        def drifted_pr(_repository: Path, _number: int) -> dict:
            value = ready_pr(_repository, _number)
            value["isDraft"] = True
            value["headRefOid"] = "b" * 40
            return value

        with self.assertRaisesRegex(self.module.ProgramStateError, "head SHA"):
            self.module.validate_pull_requests(status, self.repository, drifted_pr)

    def test_rejects_gate_e_blocker_missing_from_roadmap_section(self) -> None:
        status = self.status()
        status["gates"]["gate_e"]["blockers"] = [
            "DCP05C-INSTALLED-QUALIFICATION-NOT-RUN"
        ]
        with self.assertRaisesRegex(
            self.module.ProgramStateError,
            "DCP05C-INSTALLED-QUALIFICATION-NOT-RUN",
        ):
            self.module.validate_gate_blockers_are_documented(status, self.repository)

    def test_live_program_status_matches_repository_and_gate_e_roadmap(self) -> None:
        status = self.module.load_status(ROOT / "docs/roadmap/PROGRAM_STATUS.yaml")
        self.module.validate_shape(status)
        self.module.validate_integrated_canonical_main(status, ROOT)
        # The local-authority lane claim (local_authority / lanes) is
        # historical since D6 (2026-10-12): the lead owns integration and
        # the per-tranche claim ledger was retired, so the live record is no
        # longer checked against a local workbranch. Hermetic claim-set tests
        # above still cover the validator itself.
        self.assertEqual(status["program_20261012"]["ownership"], "lead")
        self.module.validate_gate_blockers_are_documented(status, ROOT)

    def test_backup_local_materialization_is_not_treated_as_authority(self) -> None:
        status = self.status()
        status["local_authority"] = {
            "status": "backup-only-full-byte-materialization",
        }
        self.module.validate_authoritative_local_integration_claim(
            status, self.repository
        )


if __name__ == "__main__":
    unittest.main()
