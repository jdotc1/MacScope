#!/usr/bin/env python3
"""Per-check developer bootstrap receipts; never Release qualification authority.

Identity uses Git object metadata and clean governed paths, not payload hashes.
Receipts survive a later interrupted bootstrap. Missing history, interrupted or
failed checks fail closed; unchanged inputs cannot silently execute again.
First locally observed history requires an explicit operator reason, not bootstrap.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

SCHEMA = 1
POLICY = ("Scripts/dependencies/validate_policy_consistency.py",
          "Scripts/qualification/qualification_manifest_inheritance.py",
          "MacScope/PARITY_CONTRACT.md", "THIRD_PARTY_COMPONENTS.yml",
          "THIRD_PARTY_NOTICES.md", "docs/dependencies/LicenseDecision.md",
          "Scripts/ghostty-vt-source.contract", "Scripts/ghostty-surface-source.contract",
          "ThirdParty/MachOKit")
STAGES = {
    "policy": ("Scripts/dependencies/validate_policy_consistency.py", POLICY),
    "inventory": ("Scripts/dependencies/validate_third_party_components.py", (
        # Bind inventory implementation/schema, not unrelated dependency tooling.
        # In particular an offline-scanner edit must not repeat license/source
        # verification that the inventory already passed.
        "Scripts/dependencies/validate_third_party_components.py",
        "Scripts/dependencies/first_party_components.py",
        "Scripts/dependencies/third_party_components.schema.json",
        "Scripts/source_export_provenance.py",
        "Scripts/qualification/qualification_manifest_inheritance.py",
        ".gitignore", "THIRD_PARTY_COMPONENTS.yml", "THIRD_PARTY_NOTICES.md",
        "FIRST_PARTY_COMPONENTS.json", ".gitmodules", "docs/dependencies",
        "ThirdParty", "Vendor", "Dependencies", "Scripts/function-signatures")),
    # The scanner consumes ordinary build source recursively; binding that surface
    # is intentionally broader than policy/inventory and excludes product Swift.
    "offline": ("Scripts/dependencies/validate_offline_build_surface.py", (".",)),
    "xcodegen": ("Scripts/dependencies/materialize_xcodegen.py", (
        "Scripts/dependencies/materialize_xcodegen.py", "ThirdParty/XcodeGen")),
    "signing": ("Scripts/check_local_signing_policy.py", (
        "Scripts/check_local_signing_policy.py", "Scripts/xcode_project_json.py",
        "Scripts/project_freshness.py", "Scripts/reconstruction_gate_f",
        "Scripts/reconstruction", "Scripts/generate_release_build_provenance.py",
        "Scripts/qualification/generated_project_evidence.py",
        "Scripts/qualify_local_private_build.sh",
        "MacScope/project.yml", "MacScope/SigningIdentity.xcconfig", "MacScope/DependencyRoots.xcconfig",
        "MacScope/Resources", "MacScope/Tests/MacScopeInstalledAppUITests/InstalledAppUITests.entitlements",
        ".github/workflows/ci.yml")),
}
MARKERS = {
    "policy": "    Policy, inventory, licenses/notices, pins, and offline surface — OK",
    "inventory": "    Policy, inventory, licenses/notices, pins, and offline surface — OK",
    "offline": "    Policy, inventory, licenses/notices, pins, and offline surface — OK",
    "xcodegen": "    xcodegen 2.46.0 satisfies minimum 2.45.4 — OK",
    "signing": "    Signing-policy source + isolated-CI override — OK",
}


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def git(root, *arguments):
    return subprocess.check_output(["git", "-C", str(root), *arguments],
                                   env=dict(os.environ, GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1"))


def scopes(root, stage, revision):
    return sorted(set(STAGES[stage][1]))


def offline_input(path):
    # Mirror the scanner's ordinary-source surface; its own code is also bound.
    if path.startswith(("ThirdParty/", ".git/", ".build/", "MacScope/DerivedData")):
        return False
    if path.startswith(("Scripts/tests/", "Scripts/reconstruction_gate_f/tests/", ".github/workflows/")):
        return False
    return (path == ".gitignore"
            or path.startswith("Scripts/") and Path(path).suffix in {".sh", ".bash", ".zsh", ".py", ".cmake", ".mk"}
            or Path(path).name in {"CMakeLists.txt", "Package.swift", "Package.resolved",
                                  "project.yml", "project.yaml", "Makefile",
                                  "THIRD_PARTY_COMPONENTS.yml", "FIRST_PARTY_COMPONENTS.json"})


def tool_version(root, revision):
    metadata = json.loads(git(root, "show", f"{revision}:ThirdParty/XcodeGen/MATERIALIZATION.json"))
    version = metadata["binaryVersion"]
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("invalid admitted XcodeGen version")
    return version


def identity(root, stage, revision="HEAD", clean=True):
    paths = scopes(root, stage, revision)
    if clean:
        changes = git(root, "status", "--porcelain=v1", "-z", "--untracked-files=all",
                      "--ignored=matching", "--ignore-submodules=none", "--", *paths).decode().split("\0")
        # Renames are conservatively dirty. Ignored build debris is excluded only
        # for the offline scanner's declared skipped roots, never dependency tools.
        changes = [c for c in changes if c and (stage != "offline" or offline_input(c[3:]))]
        # Ignored Finder view metadata is never a build input; only the exact
        # basename of an ignored entry is skipped (tracked/untracked stay dirty).
        changes = [c for c in changes if not (c.startswith("!! ") and Path(c[3:]).name == ".DS_Store")]
        if changes:
            raise ValueError(f"{stage}: governed inputs are dirty; cannot admit retained evidence: {changes[0]}")
    if clean:
        flags = git(root, "ls-files", "-v", "-z", "--", *paths).decode().split("\0")
        if any(row and (row[0].islower() or row[0] == "S") for row in flags):
            raise ValueError(f"{stage}: Git skip-worktree/assume-unchanged flags cannot admit evidence")
    rows = git(root, "ls-tree", "-r", "-z", revision, "--", *paths).decode().split("\0")
    rows = [row for row in rows if row and (stage != "offline" or offline_input(row.split("\t", 1)[1]))]
    if not rows:
        raise ValueError(f"{stage}: no governed input records")
    # Gitlink IDs participate; clean status also checks their working trees.
    return {"stage": stage, "scopes": paths, "git_records": rows,
            "python": [sys.version_info.major, sys.version_info.minor, sys.version_info.micro],
            "platform": [sys.platform, os.uname().machine], "schema_version": SCHEMA,
            "python_environment": {k: os.environ.get(k, "") for k in ("PYTHONPATH", "PYTHONHOME", "PYTHONOPTIMIZE")}}


def receipt_key(value):
    # Hash only the metadata document, never dependency/source payload bytes.
    return hashlib.sha256(canonical(value)).hexdigest()


def save(path, value):
    temporary = path.with_name(path.name + f".{os.getpid()}.tmp")
    temporary.write_bytes(canonical(value))
    temporary.chmod(0o600)
    os.replace(temporary, path)


def read(path):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o022:
        raise ValueError("bootstrap receipt is not owner-controlled")
    value = json.loads(path.read_bytes())
    if value.get("schema_version") != SCHEMA:
        raise ValueError("unsupported bootstrap receipt")
    return value


def imported(value):
    # Includes pre-onboarding schema-1 imports whose runtime fields incorrectly
    # described the importer. They must not take the current-key reuse path.
    return value.get("evidence", {}).get("kind") == "observed-prior-bootstrap"


def governed_identity(value):
    return {k: v for k, v in value.items()
            if k not in {"python", "platform", "python_environment"}}


def consume(root, directory, stage, *, first_history_reason=None):
    if first_history_reason is not None:
        first_history_reason = first_history_reason.strip()
        if not first_history_reason:
            raise ValueError("first-history requires the owner's explicit reason")
    before = identity(root, stage)
    path = directory / (receipt_key(before) + ".json")
    if path.exists():
        value = read(path)
        if value.get("identity") != before or value.get("outcome") != "passed":
            raise ValueError(f"{stage}: prior check failed/interrupted or receipt differs; no automatic retry")
        if imported(value):
            raise ValueError(f"{stage}: legacy import runtime is unattested; preserve the receipt; no automatic re-verification")
        print(f"    Reusing unchanged developer bootstrap {stage} evidence", file=sys.stderr)
        return value.get("output", "")
    # New inputs can run once only after this stage has an explicitly recorded
    # history. Missing history is not evidence that the check has never run.
    history = [read(p) for p in directory.glob("*.json")]
    stage_history = [v for v in history if v.get("identity", {}).get("stage") == stage]
    if first_history_reason is not None:
        # One first locally observed attempt per stage/directory. Imported logs
        # are history, not observations of the runtime used for this attempt.
        if any(not imported(v) or v.get("outcome") != "passed" for v in stage_history):
            raise ValueError(f"{stage}: local history already exists; first-history cannot retry it")
        reason = {"kind": "operator-authorized-first-history", "reason": first_history_reason}
    else:
        if not any(v.get("outcome") == "passed" for v in stage_history):
            raise ValueError(f"{stage}: retained bootstrap history is missing; refusing implicit re-verification; owner may authorize first-history --reason")
        matching = [v for v in stage_history
                    if governed_identity(v.get("identity", {})) == governed_identity(before)]
        # Unknown-runtime imports alone cannot justify repeating equal source.
        # A locally observed passed baseline restores the normal runtime-change
        # path without requiring deletion of the preserved imported history.
        if any(imported(v) for v in matching) and not any(
                not imported(v) and v.get("outcome") == "passed" for v in matching):
            raise ValueError(f"{stage}: imported runtime is unattested for unchanged governed inputs; owner must authorize first-history --reason")
        reason = {"kind": "changed-inputs", "reason": "current admitted identity differs from retained history"}
    value = {"schema_version": SCHEMA, "identity": before, "outcome": "started", "evidence": reason}
    save(path, value)
    command = ["/usr/bin/python3", "-B", str(root / STAGES[stage][0])]
    if stage == "xcodegen":
        command += ["verify-tool", "--binary", str(root / "ThirdParty/XcodeGen/bin/xcodegen")]
    result = subprocess.run(command, cwd=root, stdout=subprocess.PIPE, text=True)
    value.update(outcome="failed", output=result.stdout, returncode=result.returncode)
    if result.returncode == 0 and identity(root, stage) == before:
        value["outcome"] = "passed"
        if stage == "xcodegen":
            value["output"] = tool_version(root, "HEAD")
    save(path, value)
    if value["outcome"] != "passed":
        raise ValueError(f"{stage}: check failed or inputs changed; result retained, no automatic retry")
    return value["output"]


def import_prior(root, directory, commit, log):
    # Explicit migration of observed local evidence, never called by bootstrap.
    # The operator supplies the recorded run commit; markers alone are not a
    # source binding. Both commit and full log are retained for audit/readback.
    if not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise ValueError("prior run needs its exact recorded commit")
    transcript = log.read_text()
    root_prefix = "    Repo root: "
    root_lines = [line[len(root_prefix):] for line in transcript.splitlines()
                  if line.startswith(root_prefix)]
    try:
        expected_root = root.resolve(strict=True)
        roots_match = bool(root_lines) and all(
            Path(recorded).is_absolute() and Path(recorded).resolve(strict=True) == expected_root
            for recorded in root_lines)
    except (OSError, RuntimeError, ValueError):
        roots_match = False
    if not roots_match:
        raise ValueError("prior bootstrap log belongs to a different checkout")
    for stage, marker in MARKERS.items():
        if marker not in transcript.splitlines():
            raise ValueError(f"prior bootstrap log has no successful {stage} completion")
    for stage in STAGES:
        prior = identity(root, stage, commit, clean=False)
        # The log attests no runtime. Never label its run with the importer's
        # Python, platform or environment, and never admit it as current reuse.
        for field in ("python", "platform", "python_environment"):
            prior[field] = None
        value = {"schema_version": SCHEMA, "identity": prior, "outcome": "passed",
                 "output": tool_version(root, commit) if stage == "xcodegen" else "",
                 "evidence": {"kind": "observed-prior-bootstrap", "runtime_attestation": "unattested",
                              "source_commit": commit,
                              "log": str(log), "transcript": transcript, "marker": MARKERS[stage]}}
        path = directory / (receipt_key(prior) + ".json")
        if path.exists():
            if read(path) != value:
                raise ValueError("refusing to replace existing bootstrap evidence")
        else:
            save(path, value)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--receipts", type=Path, required=True)
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run")
    run.add_argument("stage", choices=STAGES)
    first = sub.add_parser("first-history", help="owner-authorized first local observation; never called by bootstrap")
    first.add_argument("stage", choices=STAGES)
    first.add_argument("--reason", required=True, help="specific owner-accepted reason for this first attempt")
    prior = sub.add_parser("import-prior")
    prior.add_argument("--commit", required=True)
    prior.add_argument("--log", type=Path, required=True)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    directory = args.receipts.resolve()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = directory.stat()
    if metadata.st_uid != os.getuid() or metadata.st_mode & 0o022:
        raise ValueError("bootstrap receipt directory is not owner-controlled")
    with (directory / ".lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if args.command == "import-prior":
            import_prior(root, directory, args.commit, args.log.resolve(strict=True))
        else:
            if os.environ.get("MACSCOPE_XCODEGEN", str(root / "ThirdParty/XcodeGen/bin/xcodegen")) != str(root / "ThirdParty/XcodeGen/bin/xcodegen"):
                raise ValueError("developer receipt refuses an alternate XcodeGen binary")
            print(consume(root, directory, args.stage,
                          first_history_reason=args.reason if args.command == "first-history" else None))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)
