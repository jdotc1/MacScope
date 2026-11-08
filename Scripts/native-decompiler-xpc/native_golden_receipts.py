#!/usr/bin/env python3
"""Digest and staged-package receipt reuse for developer native goldens only.

Shared-view mode requires metadata-bound receipts. Normal standalone/Release
execution keeps stable full hashing and the existing strict package verifier.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
FIELDS = ("st_dev", "st_ino", "st_mode", "st_nlink", "st_size", "st_mtime_ns", "st_ctime_ns")
TRANSPORT_ONLY = {"Scripts/native-decompiler-xpc/native_golden_receipts.py",
                  "Scripts/native-decompiler-xpc/run_native_bridge_golden.sh"}
RUNNER = "Scripts/native-decompiler-xpc/run_native_bridge_golden.sh"
# Only this reviewed runner edit adds receipt admission/capture without changing
# test commands or assertions. Later runner edits remain identity-bearing.
REVIEWED_RUNNER = "836ff76aa12ebec6ad63e906d09e30323e7693a8"
REVIEWED_GOLDEN_SOURCE = "3adb0382ea5b08ff41ec045b1b604c69ce370a1ee2140808494a2dc75b229ad3"


def owned_receipt(path):
    before = ordinary(path)
    if before.st_uid != os.getuid() or before.st_mode & 0o222:
        raise ValueError("retained receipt must be immutable and owner controlled")
    value = json.loads(path.read_bytes())
    if fields(ordinary(path)) != fields(before):
        raise ValueError("retained receipt changed while reading")
    return value


def prior_root():
    raw = os.environ.get("MACSCOPE_NATIVE_PRIOR_RECEIPT_ROOT")
    if not raw:
        return None
    root = Path(raw)
    value = root.lstat()
    if (root.resolve(strict=True) != root or not root.is_dir()
            or value.st_uid != os.getuid() or value.st_mode & 0o077):
        raise ValueError("prior receipt root must be private and canonical")
    return root


def retain_document(path, value):
    if path.exists():
        if owned_receipt(path) != value:
            raise ValueError("refusing to replace retained evidence")
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, "w") as output:
        json.dump(value, output, sort_keys=True, separators=(",", ":"))
        output.write("\n")


def retiring():
    """dev_loop.sh opts in (the #364 switch); every other caller keeps the strict refusals."""
    return os.environ.get("MACSCOPE_NATIVE_RETIRE_STALE_RECEIPTS") == "1"


def retire_receipt(root, receipt, kind):
    """Move one retained receipt aside inside the private receipt root; never deletes."""
    base = root / "NativePhaseReuseRetired"
    if receipt.parent != root or not receipt.name.startswith("golden-") or ".." in receipt.parts:
        raise ValueError(f"native-retire-failed: path-outside-receipt-root: {receipt}")
    if os.lstat(receipt).st_dev != os.lstat(root).st_dev:
        raise ValueError(f"native-retire-failed: cross-device: {receipt}")
    destination = base / (time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()) + f"-{kind}-" + uuid.uuid4().hex[:8])
    base.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.mkdir(destination, 0o700)
    target = destination / receipt.name
    retain_document(destination / "manifest.json", {"schema": 1, "kind": kind, "moved": [{"from": str(receipt), "to": str(target)}]})
    os.rename(receipt, target)
    print(f"note: retired {kind} receipt to {destination}", file=sys.stderr)


def bridge_digest(path):
    raw = os.environ.get("MACSCOPE_NATIVE_DECOMPILER_BUILD_ROOT")
    if not raw:
        return None
    root = Path(raw)
    if not path.is_relative_to(root):
        return None
    relative = path.relative_to(root).as_posix()
    if relative not in ("libmacscope_native_decompiler_contract.a",
                        "generated/MacScopeNativeDecompiler/GhidraBuildIdentity.hpp"):
        return None
    repository = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repository / "Scripts/qualification"))
    import dev_dependency_cache as cache
    admission = cache.admitted_native_bridge(repository, Path(os.environ["MACSCOPE_SLEIGH_MATERIALIZATION_ROOT"]))
    stage_path = root / "NativeBridgeStage.json"
    before = fields(ordinary(stage_path))
    stage = json.loads(stage_path.read_text())
    observed = ordinary(path)
    # The staging receipt uses a different, explicitly ordered stat tuple.
    staged_fields = [observed.st_dev, observed.st_ino, observed.st_mode, observed.st_size,
                     observed.st_mtime_ns, observed.st_ctime_ns, observed.st_nlink]
    if stage.get("admission") != admission or stage.get("files", {}).get(relative) != staged_fields:
        raise ValueError("native golden input differs from its admitted staging receipt")
    cache_root, _ = cache.roots(argparse.Namespace(cache_root=None, view_root=None))
    entry = cache.CACHE.load_entry_receipt(cache_root / "artifacts/v1/native-bridge" / admission["key"],
                                          "native-bridge", admission["key"])
    row = next((row for row in entry["payload_records"] if row["path"] == relative), None)
    if row is None or row.get("kind") != "file" or row.get("size") != observed.st_size:
        raise ValueError("native entry lacks the staged golden input")
    if fields(ordinary(stage_path)) != before or fields(ordinary(path)) != fields(observed):
        raise ValueError("native golden input changed during receipt admission")
    return row["sha256"]


def fields(metadata):
    return [getattr(metadata, name) for name in FIELDS]


def ordinary(path):
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise ValueError("golden digest requires an ordinary singly linked file")
    return metadata


def receipt_root():
    root = Path(os.environ["MACSCOPE_NATIVE_SOURCE_IDENTITY_RECEIPT_ROOT"])
    metadata = root.lstat()
    if (not root.is_absolute() or root.resolve(strict=True) != root
            or not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077):
        raise ValueError("golden digest receipts require a private canonical directory")
    return root


def package_snapshot(root):
    # This reader anchors an existing staged receipt or the shared source view,
    # validates its closed metadata snapshot, and never rehashes admitted files.
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import stage_verified_package as stage
    canonical, descriptor, root_fields, snapshot, identity = stage._open_verified_materialization(root, "native golden package")
    try:
        stage._revalidate_anchored_materialization(canonical, descriptor, root_fields, snapshot, "native golden package")
        return canonical, snapshot, identity
    finally:
        os.close(descriptor)


def stable_hash(path):
    before = ordinary(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        if fields(os.fstat(descriptor)) != fields(before):
            raise ValueError("golden file moved before hashing")
        digest = hashlib.sha256()
        while block := os.read(descriptor, 1024 * 1024):
            digest.update(block)
        if fields(os.fstat(descriptor)) != fields(before) or fields(ordinary(path)) != fields(before):
            raise ValueError("golden file moved while hashing")
        return digest.hexdigest(), fields(before)
    finally:
        os.close(descriptor)


def digest(path, materialization=None, *, allow_new=True):
    mode = os.environ.get("MACSCOPE_NATIVE_VERIFICATION_RECEIPT_MODE", "")
    if not mode:
        return stable_hash(path)[0]
    if mode != "shared-view":
        raise ValueError("unsupported native golden verification receipt mode")
    if path.resolve(strict=True) != path:
        raise ValueError("golden digest path must be canonical")
    observed = fields(ordinary(path))
    retained = bridge_digest(path)
    if retained is not None:
        return retained
    if materialization is not None and path.is_relative_to(materialization):
        canonical, snapshot, _ = package_snapshot(materialization)
        relative = path.relative_to(canonical).as_posix()
        row = next((item for item in snapshot if item[0] == relative), None)
        if row is None or row[1] != "file" or list(row[2]) != observed or row[3] is None:
            raise ValueError("golden package leaf differs from staged receipt")
        return row[3]
    root = receipt_root()
    key = hashlib.sha256(str(path).encode()).hexdigest()
    receipt = root / ("golden-digest-" + key + ".json")
    prior = prior_root()
    if not receipt.exists() and prior is not None and (prior / receipt.name).exists():
        receipt = prior / receipt.name
    regenerated = False
    if receipt.exists() or receipt.is_symlink():
        before = ordinary(receipt)
        if before.st_uid != os.getuid() or before.st_mode & 0o222:
            raise ValueError("golden digest receipt must be immutable and owner controlled")
        value = json.loads(receipt.read_bytes())
        well_formed = (isinstance(value, dict) and set(value) == {"version", "path", "metadata", "sha256"}
                       and value["version"] == 1 and value["path"] == str(path)
                       and isinstance(value["metadata"], list) and len(value["metadata"]) == len(FIELDS)
                       and isinstance(value["sha256"], str) and len(value["sha256"]) == 64
                       and all(character in "0123456789abcdef" for character in value["sha256"])
                       and fields(ordinary(receipt)) == fields(before))
        if well_formed and fields(ordinary(path)) == observed and value["metadata"] != observed and retiring():
            # The file was regenerated (new inode): its bytes are a first hash of a new input, not a repeat.
            if receipt.parent == root:
                retire_receipt(root, receipt, "golden-digest")
            regenerated = True
            receipt = root / receipt.name  # a prior-root receipt stays untouched; the new one is written here
        elif (not well_formed or value["metadata"] != observed or fields(ordinary(path)) != observed):
            raise ValueError("golden digest receipt is stale or malformed; refusing repeat hashing")
        else:
            return value["sha256"]
    if not allow_new and not regenerated:
        # A regenerated input retired just above is a first hash of a new input; the caller compares it.
        raise ValueError("completed golden input lacks retained digest evidence; refusing repeat hashing")
    value, metadata = stable_hash(path)
    document = {"version": 1, "path": str(path), "metadata": metadata, "sha256": value}
    descriptor = os.open(receipt, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, "w") as handle:
        json.dump(document, handle, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
    return value


def completed_path(root, result):
    return root / ("golden-completed-" + hashlib.sha256(str(result).encode()).hexdigest() + ".json")


def semantic_sources(repository, rows):
    sys.path.insert(0, str(repository / "Scripts/qualification"))
    import dev_dependency_cache as cache
    prefixes = tuple(row[0] for row in rows if row[0] not in TRANSPORT_ONLY)
    cache.require_clean(repository, prefixes)
    return [list(row) for row in cache.tree_listing(repository, prefixes)]


def runner_blob(repository):
    sys.path.insert(0, str(repository / "Scripts/qualification"))
    import dev_dependency_cache as cache
    cache.require_clean(repository, (RUNNER,))
    return cache.tree_listing(repository, (RUNNER,))[0][2]


def toolchain_inputs(arguments):
    developer = arguments.developer_dir.resolve(strict=True)
    sdk = arguments.sdk_root.resolve(strict=True)
    if not developer.is_dir() or not sdk.is_dir() or not arguments.sdk_name:
        raise ValueError("golden toolchain arguments are incomplete")
    return {"developer": str(developer), "sdk": str(sdk), "sdkName": arguments.sdk_name}


def tool_identity(developer, sdk):
    repository = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(repository / "Scripts/qualification"))
    import dev_dependency_cache as cache
    view_root = cache.roots(argparse.Namespace(cache_root=None, view_root=None))[1]
    tools = developer / "Toolchains/XcodeDefault.xctoolchain/usr/bin"
    files = [("clang", str(tools / "clang++")),
             ("swiftc", str(tools / "swiftc")),
             ("lipo", str(tools / "lipo")),
             ("xcode-version", str(developer.parent / "version.plist")),
             ("sdk-settings", str(sdk / "SDKSettings.plist"))]
    return cache.external_identity(files, view_root)


TOOLCHAIN_PROBES = ("xcodeVersion", "xcodeBuild", "sdkVersion", "sdkBuild",
                    "swiftCompilerVersion", "swiftTargetTriple")


def probe_toolchain(developer, sdk):
    """Mirror the shell's command substitutions and sed, preserving spaces/tabs."""
    environment = dict(os.environ, DEVELOPER_DIR=str(developer))

    def output(arguments):
        # Shell command substitution removes trailing newlines, not whitespace.
        return subprocess.run(arguments, env=environment, check=True,
                              stdout=subprocess.PIPE).stdout.decode("utf-8").rstrip("\n")

    xcodebuild = str(developer / "usr/bin/xcodebuild")
    xcode = output([xcodebuild, "-version"]).split("\n")
    sdk_version = output([xcodebuild, "-version", "-sdk", str(sdk), "SDKVersion"])
    sdk_build = output([xcodebuild, "-version", "-sdk", str(sdk), "ProductBuildVersion"])
    swift = output([str(developer / "Toolchains/XcodeDefault.xctoolchain/usr/bin/swiftc"),
                    "--version"]).split("\n")
    compiler = re.match(r".*Apple Swift version ([^ ]*).*", swift[0])
    return {"xcodeVersion": xcode[0][6:] if xcode[0].startswith("Xcode ") else "",
            "xcodeBuild": xcode[1][14:] if len(xcode) > 1 and xcode[1].startswith("Build version ") else "",
            "sdkVersion": sdk_version, "sdkBuild": sdk_build,
            "swiftCompilerVersion": compiler.group(1) if compiler is not None else "",
            "swiftTargetTriple": "\n".join(line[8:] for line in swift if line.startswith("Target: ")).rstrip("\n")}


def toolbind_path(root, result):
    return root / completed_path(root, result).name.replace("golden-completed-", "golden-toolbind-", 1)


def receipt_bytes(path, document):
    before = fields(ordinary(path))
    encoded = path.read_bytes()
    if fields(ordinary(path)) != before or json.loads(encoded) != document:
        raise ValueError("retained receipt changed while reading its bytes")
    return encoded


def retain_toolbind_bytes(path, encoded):
    """Copy an already-admitted sidecar without changing its bound bytes."""
    if path.exists() or path.is_symlink():
        document = owned_receipt(path)
        if receipt_bytes(path, document) != encoded:
            raise ValueError("refusing to replace retained evidence")
        return
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(descriptor, "wb") as output:
        output.write(encoded)


def capture_completed(result, repository, toolchain):
    """Record existing passing evidence; no artifact/source hashing or execution."""
    root = receipt_root()
    result_before = fields(ordinary(result))
    value = json.loads(result.read_text())
    if value.get("passed") is not True or value.get("schemaVersion") != 1:
        raise ValueError("golden result is not completed passing evidence")
    key = hashlib.sha256((str(repository) + "\0golden").encode()).hexdigest()
    source = owned_receipt(root / (key + ".json"))
    if (source.get("profile") != "golden" or source.get("repository") != str(repository)
            or source.get("sha256") != value.get("goldenSourceSHA256")):
        raise ValueError("completed result is not bound to the recorded source identity")
    if fields(ordinary(result)) != result_before:
        raise ValueError("completed result changed during capture")
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import native_decompiler_source_identity as identity
    current = identity._profile_snapshot(repository, identity.profile_paths(repository, "golden"))
    semantic = lambda rows: [row for row in rows if row[0] not in TRANSPORT_ONLY]
    if semantic(current) != semantic(source["files"]):
        raise ValueError("completed evidence source snapshot changed before capture")
    runner = runner_blob(repository)
    old_runner = next(row for row in source["files"] if row[0] == RUNNER)
    current_runner = next(row for row in current if row[0] == RUNNER)
    if (old_runner != current_runner
            and (runner != REVIEWED_RUNNER or source["sha256"] != REVIEWED_GOLDEN_SOURCE)):
        raise ValueError("completed evidence does not cover the changed golden runner")
    if toolchain["sdkName"] != value.get("sdkName"):
        raise ValueError("capture SDK differs from completed golden result")
    retain_document(completed_path(root, result), {"version": 1, "resultPath": str(result),
                    "resultMetadata": result_before, "result": value, "source": source,
                    "sourceGitRecords": semantic_sources(repository, current), "toolchain": toolchain,
                    "runnerBlob": runner, "tools": tool_identity(Path(toolchain["developer"]), Path(toolchain["sdk"]))})


def reuse_completed(result, repository, materialization, stage_stamp, toolchain):
    root = receipt_root()
    candidates = [root] + ([prior_root()] if prior_root() is not None else [])
    record = next((completed_path(candidate, result) for candidate in candidates
                   if completed_path(candidate, result).exists()), None)
    if record is None:
        if result.exists():
            raise ValueError(
                "existing golden result lacks retained completion evidence (golden-completed-*); "
                "a result stageStampSHA256 and golden-digest-* receipts do not establish the "
                "original source, runner, toolchain and stage-stamp binding; refusing repeat. "
                "Preserve the result and receipts; a fresh golden run requires the owner's explicit authorization")
        return False
    if not result.exists() and not result.is_symlink():
        if retiring():
            if record.parent == root:
                # The fresh run's capture writes this path; move the stale record aside first.
                retire_receipt(root, record, "golden-completed")
            return False
        raise ValueError(
            "golden completion evidence exists but its result is missing; refusing repeat. "
            "A fresh golden run requires the owner's explicit authorization")
    saved = owned_receipt(record)
    if saved.get("toolchain") != toolchain:
        raise ValueError("requested golden toolchain differs from completed evidence")
    developer, sdk = Path(toolchain["developer"]), Path(toolchain["sdk"])
    tools = tool_identity(developer, sdk)
    sidecar = None
    sidecar_bytes = None
    refreshed = None
    if "tools" in saved:
        saved_tools = saved["tools"]
    else:
        record_sha256 = hashlib.sha256(receipt_bytes(record, saved)).hexdigest()
        sidecar = next((toolbind_path(candidate, result) for candidate in candidates
                        if toolbind_path(candidate, result).exists()
                        or toolbind_path(candidate, result).is_symlink()), None)
        if sidecar is not None:
            binding = owned_receipt(sidecar)
            sidecar_bytes = receipt_bytes(sidecar, binding)
            if (binding.get("version") != 1 or binding.get("recordSHA256") != record_sha256
                    or "tools" not in binding):
                raise ValueError("retained golden tool binding differs from completion record")
            saved_tools = binding["tools"]
        else:
            probes = probe_toolchain(developer, sdk)
            if any(not probes.get(name) or name not in saved["result"]
                   or probes[name] != saved["result"][name] for name in TOOLCHAIN_PROBES):
                return False
            binding = {"version": 1, "recordSHA256": record_sha256, "tools": tools,
                       "probes": {name: probes[name] for name in TOOLCHAIN_PROBES}}
            sidecar = toolbind_path(root, result)
            retain_document(sidecar, binding)
            sidecar_bytes = receipt_bytes(sidecar, binding)
            saved_tools = tools
    if saved_tools != tools:
        return False
    if runner_blob(repository) != saved["runnerBlob"]:
        return False  # new runner assertions are new test inputs
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import native_decompiler_source_identity as identity
    current = identity._profile_snapshot(repository, identity.profile_paths(repository, "golden"))
    semantic = lambda rows: [row for row in rows if row[0] not in TRANSPORT_ONLY]
    if semantic(current) != semantic(saved["source"]["files"]):
        if semantic_sources(repository, current) != saved["sourceGitRecords"]:
            return False  # changed tested sources need their first golden execution
        if not retiring():
            raise ValueError("unchanged golden sources have changed metadata; refusing repeat")
        # dev_loop only: git rewrote the checkout with equal git records, so the bytes are unchanged.
        # Reuse the retained result and carry the current metadata in a refreshed record (as #364 does).
        refreshed = dict(saved, source=dict(saved["source"], files=current), tools=saved_tools)
    value = saved["result"]
    if (fields(ordinary(result)) != saved["resultMetadata"] or json.loads(result.read_text()) != value
            or value.get("passed") is not True):
        raise ValueError("retained completed golden result changed; refusing repeat")
    archive = Path(os.environ["MACSCOPE_NATIVE_DECOMPILER_BUILD_ROOT"])
    inputs = {"contractArchiveSHA256": archive / "libmacscope_native_decompiler_contract.a",
              "contractBuildIdentitySHA256": archive / "generated/MacScopeNativeDecompiler/GhidraBuildIdentity.hpp",
              "materializationManifestSHA256": materialization / "MATERIALIZATION.json",
              "decompilerArchiveSHA256": materialization / "package/lib/libdecomp.a",
              "sleighArchiveSHA256": materialization / "package/lib/libsla.a",
              "stageStampSHA256": stage_stamp}
    for name, path in inputs.items():
        if digest(path, materialization, allow_new=False) != value[name]:
            raise ValueError("completed golden inputs differ; refusing unchanged-source repeat")
    if refreshed is not None:
        target = completed_path(root, result)
        if record == target:
            retire_receipt(root, target, "golden-completed")
        retain_document(target, refreshed)
        return True
    retain_document(completed_path(root, result), saved)
    if sidecar is not None and sidecar.parent != root:
        retain_toolbind_bytes(toolbind_path(root, result), sidecar_bytes)
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("digest", "verify-package", "capture-completed", "reuse-completed"))
    parser.add_argument("--path", type=Path)
    parser.add_argument("--materialization-root", type=Path)
    parser.add_argument("--result", type=Path)
    parser.add_argument("--repository-root", type=Path)
    parser.add_argument("--stage-stamp", type=Path)
    parser.add_argument("--developer-dir", type=Path)
    parser.add_argument("--sdk-root", type=Path)
    parser.add_argument("--sdk-name")
    arguments = parser.parse_args()
    try:
        if arguments.command == "capture-completed":
            capture_completed(arguments.result, arguments.repository_root, toolchain_inputs(arguments))
        elif arguments.command == "reuse-completed":
            return 0 if reuse_completed(arguments.result, arguments.repository_root,
                                         arguments.materialization_root, arguments.stage_stamp, toolchain_inputs(arguments)) else 3
        elif arguments.command == "verify-package":
            if os.environ.get("MACSCOPE_NATIVE_VERIFICATION_RECEIPT_MODE") != "shared-view":
                raise ValueError("receipt package admission requires shared-view mode")
            package_snapshot(arguments.materialization_root)
        else:
            if arguments.path is None:
                raise ValueError("digest requires --path")
            print(digest(arguments.path, arguments.materialization_root))
        return 0
    except (OSError, ValueError, KeyError, RuntimeError) as error:
        print(f"native golden receipt error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
