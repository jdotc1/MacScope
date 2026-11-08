#!/usr/bin/env python3
"""Developer-loop consumer of the shared verified dependency cache.

The qualifier content-addresses the Ghostty VT build, the Ghostty surface
package and the source-built SLEIGH materialization in one shared cache
(``Scripts/qualification/dependency_cache.py``). Before this helper existed,
bootstrap and the Xcode Ghostty VT phase ignored that cache and rebuilt every
component from scratch for each new worktree, DerivedData root or purged
``$TMPDIR`` slot (about ten minutes for SLEIGH plus the surface, and about a
minute of Zig per DerivedData for VT).

This helper gives the developer loop the qualifier's exact cache contract:

* the cache key is computed by ``dependency_cache.py key`` from the same
  component prefixes, values and platform/toolchain identity the qualifier
  uses (``COMPONENTS`` and ``platform_identity`` mirror
  the qualification entrypoint; a governance test compares the
  two). Source records come from the canonical Git blobs of ``HEAD`` for those
  prefixes, exactly as the sealed export records them, and only when the
  prefixes are clean in the index and work tree (otherwise the component is
  *unavailable* and the caller keeps its legacy local build);
* a miss builds once with the qualifier's builders, verifies, strips the same
  transient state and publishes an immutable entry through
  ``dependency_cache.py publish`` under the shared per-key lock;
* consumers receive a read-only view that ``dependency_cache.py materialize``
  fully re-hashed against the entry, that the component's domain verifier then
  accepted, and that is bound by a view receipt. The receipt binds the entry
  receipt digest and consumer descriptors; its read-only stamp sidecar binds
  current per-file metadata to that receipt. An unchanged view is reused without
  re-hashing (R9.3); a stamp change refuses reuse, never authorizes re-verification.

The ``native-bridge`` component is developer-loop only (the qualifier does not
key it): it caches the path-free native decompiler bridge archive keyed by the
wrapper sources, the SLEIGH key and the toolchain, and is served only when the
consumer's SLEIGH materialization is the shared view that key binds.

Iteration only: views are never qualification, Release or Gate F evidence. The
qualifier keeps its own run-owned views, verification receipts and provenance.

Exit status: 0 resolved (contract lines on stdout), 3 unavailable (disabled,
no cache root, or dirty governed sources; the caller builds locally), 1 error
(fail closed: a cache entry or view failed verification).
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from work_root import work_root as macscope_work_root  # noqa: E402

sys.dont_write_bytecode = True

SCRIPT_PATH = Path(__file__).resolve()
SCRIPTS = SCRIPT_PATH.parents[1]
VIEW_SCHEMA_VERSION = 1
MEMO_SCHEMA_VERSION = 1
UNAVAILABLE_STATUS = 3
# The owner's shared verified cache: the same root CI passes to the qualifier
# (.github/workflows/ci.yml MACSCOPE_DEPENDENCY_CACHE_ROOT).
DEFAULT_CACHE_ROOT = macscope_work_root() / "MacScopeQualificationCache-20260920"
DEFAULT_VIEW_ROOT = macscope_work_root() / "MacScopeDevLoop.noindex/dependency-views"
LFS_HEADER = b"version https://git-lfs.github.com/spec/v1"
LFS_POINTER = re.compile(
    rb"version https://git-lfs.github.com/spec/v1\noid sha256:([0-9a-f]{64})\nsize ([1-9][0-9]*)\n"
)
MAX_LFS_POINTER_BYTES = 1024
LOCK_TIMEOUT_SECONDS = int(os.environ.get("MACSCOPE_DEPENDENCY_CACHE_LOCK_TIMEOUT_SECONDS", "900"))
LOCK_OWNER_GRACE_SECONDS = 60
LOCK_WAIT_LOG_INTERVAL_SECONDS = 30

# Mirrors the qualification entrypoint's platform identity.
PLATFORM_FILES = (
    ("xcode-version", "@XCODE_VERSION_PLIST@"),
    ("macos-sdk-settings", "@SDK_SETTINGS@"),
    ("clang", "@CLANG@"),
    ("system-version", "/System/Library/CoreServices/SystemVersion.plist"),
    ("xcrun", "/usr/bin/xcrun"),
    ("ar", "/usr/bin/ar"),
    ("strip", "/usr/bin/strip"),
    ("lipo", "/usr/bin/lipo"),
    ("codesign", "/usr/bin/codesign"),
    ("otool", "/usr/bin/otool"),
    ("nm", "/usr/bin/nm"),
    ("git", "/usr/bin/git"),
    ("python", "/usr/bin/python3"),
    ("plist-buddy", "/usr/libexec/PlistBuddy"),
)
NATIVE_TOOL_FILES = (
    ("cmake", "@CMAKE@"),
    ("ninja", "@NINJA@"),
    ("rsync", "/usr/bin/rsync"),
    ("git", "/usr/bin/git"),
    ("python", "/usr/bin/python3"),
)

# Mirrors the GHOSTTY_VT/GHOSTTY_SURFACE/SLEIGH cache keys of the qualifier.
# "@NAME@" values are substituted at key time.
COMPONENTS: dict[str, dict[str, Any]] = {
    "ghostty-vt": {
        "prefixes": (
            "ThirdParty/GhosttyVT",
            "ThirdParty/Zig",
            "Scripts/build_ghostty_vt.sh",
            "Scripts/ghostty-vt-source.contract",
            "Scripts/prepare_zig_macos_sdk_overlay.py",
            "Scripts/dependencies/zig_toolchain_receipt.py",
        ),
        "values": (
            ("architecture", "arm64"),
            ("payload-layout", "vt-artifacts-no-transient-v1"),
            ("simd", "@SIMD@"),
            ("platform-toolchain", "@PLATFORM@"),
        ),
        "view_name": "ghostty-vt",
    },
    "ghostty-surface": {
        "prefixes": (
            "ThirdParty/GhosttySurface",
            "ThirdParty/Zig",
            "Scripts/dependencies/build_vendored_ghostty_surface.sh",
            "Scripts/dependencies/build_ghostty_surface.sh",
            "Scripts/dependencies/zig_toolchain_receipt.py",
            "Scripts/ghostty-surface-source.contract",
            "Scripts/ghostty-vt-source.contract",
        ),
        "values": (
            ("architecture", "arm64"),
            ("configuration", "ReleaseFast"),
            ("payload-layout", "surface-source-package-artifact-no-zig-state-v1"),
            ("platform-toolchain", "@PLATFORM@"),
        ),
        "view_name": "GhosttySurface",
    },
    "sleigh-native-source": {
        "prefixes": (
            "ThirdParty/SleighNative",
            "Scripts/dependencies/build_vendored_sleigh_native_source.sh",
            "Scripts/dependencies/verify_vendored_sleigh_source.py",
            "Scripts/native-decompiler-direct/sleigh_package.py",
            "Scripts/native-decompiler-direct/verify_sleigh_package.py",
        ),
        "values": (
            ("architecture", "arm64"),
            ("configuration", "Release"),
            ("deployment-target", "27.0"),
            ("jobs", "@JOBS@"),
            ("payload-layout", "sleigh-materialization-and-source-receipt-v1"),
            ("platform-toolchain", "@PLATFORM@"),
            ("native-tools", "@NATIVE_TOOLS@"),
        ),
        "view_name": "SleighNativeSource",
    },
    # Developer-loop only (R11.2): the qualifier, Release and Gate F build the
    # bridge from source and never consume this entry. The key binds the native
    # wrapper source identity (native_decompiler_source_identity.py --profile
    # wrapper covers exactly these prefixes), the SLEIGH cache key it compiled
    # against, and the platform/native toolchain. The payload is path-free:
    # CMakeCache.txt and the link-inputs list are regenerated per consumer by
    # native_bridge_cache_payload.py and never enter the key or the entry.
    "native-bridge": {
        "prefixes": (
            "Tools/NativeDecompilerBridge",
            "Scripts/native-decompiler-xpc/build_native_bridge.sh",
            "Scripts/native-decompiler-xpc/native_decompiler_source_identity.py",
            "Scripts/native-decompiler-xpc/native_bridge_cache_payload.py",
            "Scripts/qualification/dev_dependency_cache.py",
            "Scripts/qualification/dependency_cache.py",
            "Scripts/native-decompiler-direct/verify_sleigh_package.py",
            "Scripts/native-decompiler-direct/sleigh_package.py",
        ),
        "values": (
            ("architecture", "arm64"),
            ("configuration", "Release"),
            ("deployment-target", "27.0"),
            ("payload-layout", "native-bridge-contract-archive-path-free-v1"),
            ("sleigh-native-source", "@SLEIGH_KEY@"),
            ("platform-toolchain", "@PLATFORM@"),
            ("native-tools", "@NATIVE_TOOLS@"),
        ),
        "view_name": "NativeDecompilerBridge",
        "qualifier": False,
    },
}
# Components whose key the qualifier also computes (governance parity test).
QUALIFIER_COMPONENTS = tuple(name for name, spec in COMPONENTS.items() if spec.get("qualifier", True))
SURFACE_TOOL_ENVIRONMENT = {
    "MACSCOPE_GIT": "/usr/bin/git",
    "MACSCOPE_LIPO": "/usr/bin/lipo",
    "MACSCOPE_NM": "/usr/bin/nm",
    "MACSCOPE_PLIST_BUDDY": "/usr/libexec/PlistBuddy",
    "MACSCOPE_PYTHON": "/usr/bin/python3",
}


class Unavailable(RuntimeError):
    """The shared cache cannot serve this component; build locally instead."""


class DevCacheError(RuntimeError):
    """A cache entry, view or input violated its contract; fail closed."""


def log(message: str) -> None:
    print(f"==> dev dependency cache: {message}", file=sys.stderr, flush=True)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise DevCacheError(f"{path.name} is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CACHE = load_module("macscope_dependency_cache", SCRIPTS / "qualification" / "dependency_cache.py")


def canonical_json(value: object) -> bytes:
    return CACHE.canonical_json(value)


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def admit_owner_directory(path: Path, label: str, *, create: bool) -> Path:
    if not path.is_absolute():
        raise DevCacheError(f"{label} must be absolute")
    if create and not path.exists() and not path.is_symlink():
        path.mkdir(mode=0o700, parents=True)
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except FileNotFoundError as error:
        raise Unavailable(f"{label} does not exist: {path}") from error
    if (
        resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.getuid()
        or metadata.st_mode & 0o022
    ):
        raise DevCacheError(f"{label} must be a canonical, owner-controlled directory: {path}")
    return path


def roots(arguments: argparse.Namespace) -> tuple[Path, Path]:
    if os.environ.get("MACSCOPE_DEV_DEPENDENCY_CACHE", "1") == "0":
        raise Unavailable("disabled by MACSCOPE_DEV_DEPENDENCY_CACHE=0")
    cache_value = arguments.cache_root or os.environ.get("MACSCOPE_DEPENDENCY_CACHE_ROOT")
    cache_root = Path(cache_value) if cache_value else DEFAULT_CACHE_ROOT
    if not cache_value and not cache_root.is_dir():
        raise Unavailable(f"no shared dependency cache at {cache_root}")
    cache_root = admit_owner_directory(cache_root, "dependency cache root", create=False)
    view_value = arguments.view_root or os.environ.get("MACSCOPE_DEPENDENCY_VIEW_ROOT")
    view_root = Path(view_value) if view_value else DEFAULT_VIEW_ROOT
    if not any(part.endswith(".noindex") for part in view_root.parts):
        raise DevCacheError("dependency view root must lie under a .noindex directory")
    view_root = admit_owner_directory(view_root, "dependency view root", create=True)
    if cache_root == view_root or cache_root in view_root.parents or view_root in cache_root.parents:
        raise DevCacheError("dependency view root and cache root must be disjoint")
    return cache_root, view_root


# ── Key computation ──────────────────────────────────────────────────────────


def git(repository: Path, *arguments: str, stdin: bytes | None = None) -> bytes:
    environment = dict(os.environ)
    environment.update(
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_NO_LAZY_FETCH="1",
        GIT_OPTIONAL_LOCKS="0",
        GIT_TERMINAL_PROMPT="0",
    )
    result = subprocess.run(
        ["/usr/bin/git", "-C", str(repository), *arguments],
        input=stdin,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
    )
    if result.returncode != 0:
        raise DevCacheError(
            f"git {' '.join(arguments[:2])} failed: {result.stderr.decode(errors='replace').strip()}"
        )
    return result.stdout


def require_git_checkout(repository: Path) -> None:
    # The qualifier builds Debug from a Git-less sealed source export (with
    # MACSCOPE_DEBUG_SOURCE_IDENTITY=runtime-only); there is no HEAD to key
    # against, so the consumer must keep its local build path (status 3).
    if not (repository / ".git").exists():
        raise Unavailable("repository root is not a Git checkout (sealed source export)")


def require_clean(repository: Path, prefixes: tuple[str, ...]) -> None:
    status = git(
        repository,
        "status",
        "--porcelain=v1",
        "-z",
        "--untracked-files=all",
        "--ignored=matching",
        "--ignore-submodules=none",
        "--",
        *prefixes,
    )
    # Ignored Finder view metadata is never a build input; only the exact
    # basename of an ignored entry is skipped (tracked/untracked stay dirty).
    records = [
        record for record in status.split(b"\0")
        if record and not (record.startswith(b"!! ") and Path(os.fsdecode(record[3:])).name == ".DS_Store")
    ]
    if records:
        first = records[0].decode(errors="replace")
        raise Unavailable(f"governed inputs differ from HEAD (first: {first!r})")
    flags = git(repository, "ls-files", "-v", "-z", "--", *prefixes)
    for row in flags.split(b"\0"):
        tag = row[:1]
        if tag.islower() or tag == b"S":
            kinds = []
            if tag.islower():
                kinds.append("assume-unchanged")
            if tag.upper() == b"S":
                kinds.append("skip-worktree")
            path = row[2:].decode(errors="replace")
            remedies = " and ".join(f"git update-index --no-{kind}" for kind in kinds)
            raise Unavailable(
                f"governed input has Git {'/'.join(kinds)} flag "
                f"(first: {path!r}); clear the flag with {remedies}"
            )


def tree_listing(repository: Path, prefixes: tuple[str, ...]) -> list[tuple[str, str, str]]:
    output = git(repository, "ls-tree", "-r", "-z", "--full-tree", "HEAD", "--", *prefixes)
    entries: list[tuple[str, str, str]] = []
    for raw in output.split(b"\0"):
        if not raw:
            continue
        metadata, _, path = raw.partition(b"\t")
        mode, kind, object_id = metadata.decode("ascii").split(" ")
        relative = path.decode("utf-8")
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise Unavailable(f"governed input is not an ordinary blob: {relative}")
        entries.append((relative, mode, object_id))
    return entries


def blob_records(repository: Path, entries: list[tuple[str, str, str]]) -> list[dict[str, object]]:
    """Canonical SOURCE_FILES records for the selected blobs (LFS-aware)."""
    process = subprocess.Popen(
        ["/usr/bin/git", "-C", str(repository), "cat-file", "--batch"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=dict(os.environ, GIT_NO_REPLACE_OBJECTS="1", GIT_NO_LAZY_FETCH="1"),
    )
    assert process.stdin is not None and process.stdout is not None
    records: list[dict[str, object]] = []
    try:
        for relative, mode, object_id in entries:
            process.stdin.write(object_id.encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline(512).rstrip(b"\n").split(b" ")
            if len(header) != 3 or header[0].decode() != object_id or header[1] != b"blob":
                raise DevCacheError(f"git cat-file returned an unexpected object for {relative}")
            size = int(header[2])
            digest = hashlib.sha256()
            blob = hashlib.sha1(f"blob {size}\0".encode("ascii"))
            prefix = b""
            remaining = size
            while remaining:
                block = process.stdout.read(min(1024 * 1024, remaining))
                if not block:
                    raise DevCacheError("git cat-file truncated a blob")
                remaining -= len(block)
                if len(prefix) < MAX_LFS_POINTER_BYTES:
                    prefix += block[: MAX_LFS_POINTER_BYTES - len(prefix)]
                digest.update(block)
                blob.update(block)
            if process.stdout.read(1) != b"\n" or blob.hexdigest() != object_id:
                raise DevCacheError(f"canonical blob bytes do not match {object_id}")
            physical_digest, physical_size = digest.hexdigest(), size
            if prefix.startswith(LFS_HEADER):
                match = LFS_POINTER.fullmatch(prefix)
                if match is None or len(prefix) != size:
                    raise Unavailable(f"noncanonical LFS pointer: {relative}")
                physical_digest, physical_size = match.group(1).decode("ascii"), int(match.group(2))
            records.append(
                {
                    "blob_oid": object_id,
                    "mode": mode,
                    "path": relative,
                    "sha256": physical_digest,
                    "size": physical_size,
                }
            )
    finally:
        process.stdin.close()
        process.wait()
    records.sort(key=lambda record: os.fsencode(str(record["path"])))
    return records


def memo_path(view_root: Path, name: str) -> Path:
    directory = view_root / ".memo"
    directory.mkdir(mode=0o700, exist_ok=True)
    return directory / name


def read_memo(path: Path) -> Any:
    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid() or metadata.st_mode & 0o022:
            return None
        return json.loads(path.read_bytes())
    except (OSError, ValueError):
        return None


def write_memo(path: Path, value: object) -> None:
    temporary = path.with_name(f".{path.name}.{os.getpid()}")
    temporary.write_bytes(canonical_json(value))
    temporary.chmod(0o600)
    os.replace(temporary, path)


def source_records(repository: Path, prefixes: tuple[str, ...], view_root: Path) -> list[dict[str, object]]:
    require_clean(repository, prefixes)
    entries = tree_listing(repository, prefixes)
    for prefix in prefixes:
        if not any(path == prefix or path.startswith(prefix + "/") for path, _, _ in entries):
            raise Unavailable(f"governed prefix has no tracked input: {prefix}")
    # Records are a pure function of the blob identities: memoize by listing.
    listing_digest = sha256_bytes(canonical_json([list(entry) for entry in entries]))
    memo = memo_path(view_root, f"records-{listing_digest}.json")
    cached = read_memo(memo)
    if (
        isinstance(cached, dict)
        and cached.get("schema_version") == MEMO_SCHEMA_VERSION
        and isinstance(cached.get("records"), list)
        and [(r.get("path"), r.get("mode"), r.get("blob_oid")) for r in cached["records"]]
        == sorted(entries, key=lambda entry: os.fsencode(entry[0]))
    ):
        return cached["records"]
    # A changed transport script must not rehash unchanged native/dependency
    # blobs. Reuse their already recorded identities across listing revisions.
    known = {}
    wanted = set(entries)
    for prior_path in memo.parent.glob("records-*.json"):
        prior = read_memo(prior_path)
        if not isinstance(prior, dict) or prior.get("schema_version") != MEMO_SCHEMA_VERSION:
            continue
        for record in prior.get("records", []):
            identity = (record.get("path"), record.get("mode"), record.get("blob_oid"))
            if identity in wanted:
                known[identity] = record
    missing = [entry for entry in entries if entry not in known]
    records = list(known.values()) + blob_records(repository, missing) if missing else list(known.values())
    records.sort(key=lambda record: os.fsencode(str(record["path"])))
    write_memo(memo, {"records": records, "schema_version": MEMO_SCHEMA_VERSION})
    return records


def developer_dir() -> Path:
    value = os.environ.get("DEVELOPER_DIR") or subprocess.run(
        ["/usr/bin/xcode-select", "-p"], stdout=subprocess.PIPE, check=True, text=True
    ).stdout.strip()
    path = Path(value).resolve(strict=True)
    if not path.is_dir():
        raise DevCacheError("selected Xcode developer authority is not a directory")
    return path


def external_identity(files: list[tuple[str, str]], view_root: Path) -> str:
    """dependency_cache.py external-identity, memoized by each file's lstat identity."""
    observed = []
    for name, raw in files:
        resolved = Path(raw).resolve(strict=True)
        metadata = resolved.stat()
        observed.append(
            [name, str(resolved), metadata.st_dev, metadata.st_ino, metadata.st_size,
             metadata.st_mtime_ns, metadata.st_ctime_ns]
        )
    memo = memo_path(view_root, f"identity-{sha256_bytes(canonical_json(observed))}.json")
    cached = read_memo(memo)
    if isinstance(cached, dict) and cached.get("observed") == observed and isinstance(cached.get("identity"), str):
        return cached["identity"]
    external = [CACHE.external_file_identity(f"{name}={raw}") for name, raw in files]
    external.sort(key=lambda item: str(item["name"]))
    identity = sha256_bytes(canonical_json(external))
    write_memo(memo, {"identity": identity, "observed": observed})
    return identity


def which(tool: str) -> str:
    found = shutil.which(tool)
    if not found:
        raise Unavailable(f"{tool} is required for this component's cache identity")
    return found


def native_identity_tool(tool: str) -> str:
    """Identify the guarded tool, without changing PATH or its execution route.

    Storage-guard adapters enforce allocation policy but do not produce native
    artifacts. Match their underlying-tool search so installing an adapter does
    not invalidate an already verified compiler-tool identity. Other wrappers
    remain identity-bearing. This path is used only by external_identity.
    """
    def guard_adapter(candidate: Path) -> bool:
        with candidate.open("rb") as handle:
            prefix = handle.read(256)
        return (b"# storage-guard tool shim" in prefix or
                (candidate.resolve().name == "storage-guard" and
                 b"storage_guard.py --shim" in prefix))

    found = which(tool)
    if not guard_adapter(Path(found)):
        return found
    # Same ordered search and minimal-PATH fallbacks as storage-guard.real_tool.
    directories = os.environ.get("PATH", "").split(os.pathsep)
    directories += ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"]
    for directory in directories:
        candidate = Path(directory or os.curdir) / tool
        if candidate.is_file() and os.access(candidate, os.X_OK) and not guard_adapter(candidate):
            return str(candidate)
    raise Unavailable(f"underlying guarded {tool} is unavailable for cache identity")


def native_tool_selection(tool: str) -> tuple[str, str]:
    """Return identity and invocation paths without changing the caller's PATH.

    Preserve the legacy PATH/guard identity first when there is no override.
    The producer receives the invocation path explicitly, so a fallback cannot
    be re-resolved differently by build_native_bridge.sh. Guard invocations
    remain guarded; only their identity is transparent.
    """
    def guard_adapter(candidate: Path) -> bool:
        with candidate.open("rb") as handle:
            prefix = handle.read(256)
        return (b"# storage-guard tool shim" in prefix or
                (candidate.resolve().name == "storage-guard" and
                 b"storage_guard.py --shim" in prefix))

    override_name = "MACSCOPE_" + tool.upper()
    override = os.environ.get(override_name)
    if override:
        candidate = Path(override).absolute()
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            raise Unavailable(f"{override_name} override is not an executable file: {override}")
        invocation = str(candidate)
        if not guard_adapter(candidate):
            return invocation, invocation
        # Match the same underlying-tool search used by native_identity_tool.
        directories = os.environ.get("PATH", "").split(os.pathsep)
        directories += ["/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/bin"]
        for directory in directories:
            real = Path(directory or os.curdir) / tool
            if real.is_file() and os.access(real, os.X_OK) and not guard_adapter(real):
                return str(real.absolute()), invocation
        raise Unavailable(f"underlying guarded {tool} is unavailable for {override_name} override")

    try:
        identity = native_identity_tool(tool)
    except Unavailable:
        # Same default and empty-value behavior as the bridge shell resolver.
        search = os.environ.get("MACSCOPE_TOOL_SEARCH_PATH") or "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin"
        for directory in search.split(os.pathsep):
            candidate = Path(directory or os.curdir) / tool
            if candidate.is_file() and os.access(candidate, os.X_OK) and not guard_adapter(candidate):
                selected = str(candidate.absolute())
                return selected, selected
        raise Unavailable(f"{tool} is unavailable; searched PATH and MACSCOPE_TOOL_SEARCH_PATH={search}")
    return identity, which(tool)


def native_build_tool_environment() -> dict[str, str]:
    return {"MACSCOPE_" + tool.upper(): native_tool_selection(tool)[1]
            for tool in ("cmake", "ninja")}


def platform_identity(view_root: Path) -> str:
    developer = developer_dir()
    substitutions = {
        "@XCODE_VERSION_PLIST@": str(developer.parent / "version.plist"),
        "@SDK_SETTINGS@": str(
            developer / "Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk/SDKSettings.plist"
        ),
        "@CLANG@": str(developer / "Toolchains/XcodeDefault.xctoolchain/usr/bin/clang++"),
    }
    files = [(name, substitutions.get(raw, raw)) for name, raw in PLATFORM_FILES]
    return external_identity(files, view_root)


def native_tools_identity(view_root: Path) -> str:
    substitutions = {"@CMAKE@": native_tool_selection("cmake")[0], "@NINJA@": native_tool_selection("ninja")[0]}
    files = [(name, substitutions.get(raw, raw)) for name, raw in NATIVE_TOOL_FILES]
    return external_identity(files, view_root)


# Reviewed producer-only transition: _tool_identity now probes through the
# invocation path. Production verify (without sanitizer evidence) is unchanged.
# Keep both complete records: no wildcard, ignored verifier, or receipt rewrite.
SLEIGH_TOOL_PROBE_RECORD = {
    "path": "Scripts/native-decompiler-direct/verify_sleigh_package.py",
    "mode": "100755", "blob_oid": "97787329c56e32492869c3cc1d9881196fad7350",
    "sha256": "faea4ead7cb704cf816d05ef4e28cbad934aa6f46fe42e65fcfac76f78daa016", "size": 8407,
}
SLEIGH_PRIOR_TOOL_PROBE_RECORD = {
    "path": "Scripts/native-decompiler-direct/verify_sleigh_package.py",
    "mode": "100755", "blob_oid": "262aeefbf9bfe7af7e7b1d28dc4e369562bd0aa6",
    "sha256": "ed29c20df957fae7c27d2318d0e2f932d9c4c0acd45b022a37922975de9ccf9a", "size": 7582,
}


def sleigh_prior_records(records: list[dict[str, object]]) -> list[dict[str, object]] | None:
    matches = [record for record in records if record["path"] == SLEIGH_TOOL_PROBE_RECORD["path"]]
    if matches != [SLEIGH_TOOL_PROBE_RECORD]:
        return None
    return [dict(SLEIGH_PRIOR_TOOL_PROBE_RECORD) if record == SLEIGH_TOOL_PROBE_RECORD
            else dict(record) for record in records]


def component_key(component: str, repository: Path, view_root: Path) -> str:
    return component_keys(component, repository, view_root)[0]


def component_keys(component: str, repository: Path, view_root: Path) -> list[str]:
    spec = COMPONENTS[component]
    records = source_records(repository, spec["prefixes"], view_root)
    substitutions: dict[str, Callable[[], str]] = {
        "@PLATFORM@": lambda: platform_identity(view_root),
        "@NATIVE_TOOLS@": lambda: native_tools_identity(view_root),
        "@SIMD@": lambda: os.environ.get("MACSCOPE_GHOSTTY_SIMD") or "false",
        "@JOBS@": lambda: os.environ.get("MACSCOPE_NATIVE_SOURCE_JOBS") or "8",
        "@SLEIGH_KEY@": lambda: component_key("sleigh-native-source", repository, view_root),
    }
    values = [
        f"{name}={substitutions[value]() if value in substitutions else value}"
        for name, value in spec["values"]
    ]
    candidates = [records]
    if component == "sleigh-native-source":
        prior = sleigh_prior_records(records)
        if prior is not None:
            candidates.append(prior)
    keys = []
    with tempfile.TemporaryDirectory(prefix=".key-", dir=memo_path(view_root, "x").parent) as scratch:
        manifest = Path(scratch) / "SOURCE_FILES.json"
        manifest.write_bytes(canonical_json({"files": records, "schema_version": 2}))
        arguments = argparse.Namespace(
            source_files=manifest,
            component=component,
            prefix=list(spec["prefixes"]),
            value=values,
            external_file=[],
        )
        # Not key_command under redirect_stdout: that swaps the process-wide
        # sys.stdout, and the native stager admits source and staged copy in
        # two threads, so concurrent keys were lost ("key is malformed").
        for candidate in candidates:
            manifest.write_bytes(canonical_json({"files": candidate, "schema_version": 2}))
            key = CACHE.compute_key(arguments)
            if CACHE.HEX64.fullmatch(key) is None:
                raise DevCacheError("dependency cache key is malformed")
            keys.append(key)
    return keys


def retained_component_key(component: str, repository: Path, cache_root: Path, view_root: Path) -> tuple[str, bool]:
    keys = component_keys(component, repository, view_root)
    current = keys[0]
    if (cache_root / "artifacts/v1" / component / current).exists():
        return current, False
    if component == "native-bridge":
        retained = native_bridge_retained_key(repository, cache_root, view_root)
        if retained is not None:
            log(f"native-bridge {current[:12]}: retaining reviewed artifact/receipt {retained}")
            return retained, True
    if len(keys) == 1:
        return current, False
    prior = keys[1]
    entry = cache_root / "artifacts/v1" / component / prior
    directory = view_root / component / prior
    # Compatibility only consumes an existing domain-verified view. It never
    # builds, copies, relabels or repairs the predecessor entry/receipt.
    if entry.is_dir() and (directory / "VIEW.json").is_file():
        log(f"{component} {current[:12]}: reviewed tool-probe transition; retaining receipt key {prior}")
        return prior, True
    raise DevCacheError(
        f"{component} {current}: reviewed tool-probe transition requires retained "
        f"entry and VIEW receipt {prior}; refusing unchanged dependency rebuild")


# Narrow retained-artifact exception: only exact reviewed transport records
# may reuse this historical artifact and its embedded wrapper identity. These
# files also feed ordinary wrapper identity, so their changes can alter fresh
# production identity; this exception does not override the ordinary route.
# Engine, producer, type-rule and unreviewed transport changes still refuse.
NATIVE_TRANSPORT_INPUTS = frozenset({
    "Scripts/qualification/dependency_cache.py",
    "Scripts/qualification/dev_dependency_cache.py",
    "Scripts/native-decompiler-xpc/native_bridge_cache_payload.py",
    "Scripts/native-decompiler-xpc/native_decompiler_source_identity.py",
})


def native_bridge_retained_key(repository: Path, cache_root: Path, view_root: Path) -> str | None:
    contract = json.loads((SCRIPTS / "qualification/native_bridge_reuse_contract.json").read_text())
    if contract.get("schema_version") != 2:
        raise DevCacheError("unsupported native bridge reuse contract")
    reviewed = contract.get("reviewed_transport_records")
    malformed = "native bridge reuse contract reviewed transport records are missing or malformed"
    if not isinstance(reviewed, dict) or set(reviewed) != NATIVE_TRANSPORT_INPUTS:
        raise DevCacheError(malformed)
    fields = {"blob_oid", "mode", "path", "sha256", "size"}
    for path, records in reviewed.items():
        if not isinstance(records, list):
            raise DevCacheError(malformed)
        seen = []
        for record in records:
            if (not isinstance(record, dict) or set(record) != fields
                    or record["path"] != path
                    or record["mode"] not in ("100644", "100755")
                    or not isinstance(record["blob_oid"], str)
                    or CACHE.HEX40.fullmatch(record["blob_oid"]) is None
                    or not isinstance(record["sha256"], str)
                    or CACHE.HEX64.fullmatch(record["sha256"]) is None
                    or isinstance(record["size"], bool)
                    or not isinstance(record["size"], int) or record["size"] < 0
                    or record in seen):
                raise DevCacheError(malformed)
            seen.append(record)
    prior = contract["source_records"]
    payload = {"component": "native-bridge", "external_files": [], "schema_version": 1,
               "source_records": prior, "values": contract["values"]}
    if sha256_bytes(canonical_json(payload)) != contract["entry_key"]:
        raise DevCacheError("native bridge reuse contract does not reconstruct its original entry key")
    current = source_records(repository, COMPONENTS["native-bridge"]["prefixes"], view_root)
    prior_transport = {record["path"]: record for record in prior
                       if record["path"] in NATIVE_TRANSPORT_INPUTS}
    def implementation(records):
        result = []
        seen = set()
        for record in records:
            path = record["path"]
            if path in NATIVE_TRANSPORT_INPUTS:
                if (path in seen or (record != prior_transport.get(path)
                                     and record not in reviewed[path])):
                    return None
                seen.add(path)
                continue
            if record == SLEIGH_TOOL_PROBE_RECORD:
                record = SLEIGH_PRIOR_TOOL_PROBE_RECORD
            result.append(record)
        return result if seen == NATIVE_TRANSPORT_INPUTS else None
    current_implementation = implementation(current)
    if current_implementation is None or current_implementation != implementation(prior):
        return None
    sleigh, _ = retained_component_key("sleigh-native-source", repository, cache_root, view_root)
    substitutions = {"@SLEIGH_KEY@": sleigh, "@PLATFORM@": platform_identity(view_root),
                     "@NATIVE_TOOLS@": native_tools_identity(view_root)}
    expected = {name: substitutions.get(value, value) for name, value in COMPONENTS["native-bridge"]["values"]}
    if expected != contract["values"]:
        return None
    key = contract["entry_key"]
    entry = cache_root / "artifacts/v1/native-bridge" / key
    receipt = view_root / "native-bridge" / key / "VIEW.json"
    if not entry.is_dir() or not receipt.is_file():
        raise DevCacheError("reviewed native bridge entry/view receipt is absent; refusing implicit rebuild")
    return key


def admitted_native_bridge(repository: Path, materialization: Path, requested_view: Path | None = None) -> dict[str, Any]:
    cache_root, view_root = roots(argparse.Namespace(cache_root=None, view_root=None))
    resolved = resolve("native-bridge", repository, cache_root, view_root, build=False,
                       requested_materialization=str(materialization))
    view = resolved["view"]
    if requested_view is not None and requested_view.resolve(strict=True) != view:
        raise DevCacheError("native bridge stage does not name the admitted view")
    configuration = json.loads((view / "CONFIGURATION.json").read_text())
    sleigh = reused_sleigh_materialization(repository, materialization, cache_root, view_root)
    if configuration.get("materialization_manifest_sha256") != sleigh["manifest_sha256"]:
        raise DevCacheError("native bridge retained artifact names a different SLEIGH materialization")
    if not CACHE.HEX64.fullmatch(configuration.get("wrapper_revision", "")):
        raise DevCacheError("retained native wrapper identity is malformed")
    contract = json.loads((SCRIPTS / "qualification/native_bridge_reuse_contract.json").read_text())
    if resolved["key"] == contract["entry_key"] and configuration["wrapper_revision"] != contract["wrapper_revision"]:
        raise DevCacheError("retained native wrapper identity differs from its reviewed artifact")
    return {"configuration": configuration, "key": resolved["key"], "view": str(view),
            "entry_receipt_sha256": resolved["receipt"]["entry_receipt_sha256"]}


# ── Builders and domain verifiers (mirroring the qualifier callbacks) ────────


class ProducerCancelled(DevCacheError):
    pass


def process_identity(pid: str) -> str:
    if not pid.isdecimal() or int(pid) <= 1:
        return ""
    result = subprocess.run(["/bin/ps", "-p", pid, "-o", "lstart=", "-o", "stat="],
                            stdout=subprocess.PIPE, text=True, check=False,
                            env=dict(os.environ, LC_ALL="C", TZ="UTC"))
    value = result.stdout.strip()
    return value[:24] if result.returncode == 0 and value and not value[24:].strip().startswith("Z") else ""


def run_tool(command: list[str], *, extra_environment: dict[str, str] | None = None) -> str:
    environment = dict(os.environ)
    environment.update(extra_environment or {})
    owner = environment.get("MACSCOPE_DEV_OWNER_PID")
    birth = environment.get("MACSCOPE_DEV_OWNER_START")
    if owner and (not birth or process_identity(owner) != birth):
        raise ProducerCancelled("dev-loop owner is absent; refusing to start native work")
    interrupted = []
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGTERM, signal.SIGINT)}
    for sig in handlers:
        signal.signal(sig, lambda number, frame: interrupted.append(number))
    process = None
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, env=environment, text=True,
                                   start_new_session=True)
        while True:
            if interrupted or (owner and process_identity(owner) != birth):
                # Xcode starts script phases in another process group. Own the
                # producer group explicitly, including CMake/Ninja/CTest children.
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                try:
                    output, _ = process.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    output = ""
                finally:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                tail, _ = process.communicate()
                print(output or tail, end="", file=sys.stderr)
                raise ProducerCancelled("native producer cancelled with its dev-loop owner; partial results retained")
            try:
                output, _ = process.communicate(timeout=0.25)
                if interrupted or (owner and process_identity(owner) != birth):
                    continue
                break
            except subprocess.TimeoutExpired:
                continue
    finally:
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
    if process.returncode != 0:
        # A failed producer stays diagnosable: show its captured stdout (the
        # build and CTest log). Its stderr is not captured and already streamed.
        if output:
            print(output, end="" if output.endswith("\n") else "\n", file=sys.stderr)
        raise DevCacheError(f"{Path(command[0]).name} failed with exit {process.returncode}")
    return output


def remove_tree(path: Path) -> None:
    if path.is_symlink():
        path.unlink()
        return
    if not path.exists():
        return
    for item in [path, *path.rglob("*")]:
        try:
            if not item.is_symlink():
                item.chmod(0o700 if item.is_dir() else 0o600)
        except OSError:
            pass
    shutil.rmtree(path)


def native_bridge_payload_tool(repository: Path, *arguments: str) -> None:
    run_tool(["/usr/bin/python3", "-B",
              str(repository / "Scripts/native-decompiler-xpc/native_bridge_cache_payload.py"), *arguments])


def verify_view(component: str, repository: Path, view: Path, materialization: Path | None = None) -> None:
    scripts = repository / "Scripts"
    if component == "native-bridge":
        if materialization is None:
            raise DevCacheError("native-bridge verification requires the SLEIGH materialization root")
        native_bridge_payload_tool(repository, "verify", "--repository-root", str(repository),
                                   "--materialization-root", str(materialization), "--payload", str(view))
        return
    if component == "ghostty-vt":
        output = run_tool([str(scripts / "build_ghostty_vt.sh"), "--work-root", str(view), "--verify-only"])
        print(output, end="", file=sys.stderr)
        return
    if component == "ghostty-surface":
        # The cache view is a frozen copy of the producer output. Its .git
        # directory retains only the vendored-input identity, so the producer's
        # --verify-only mode (which needs Git HEAD) cannot verify this view.
        # materialize_command checks every copied byte against the immutable
        # entry; descriptors() then admits the actual consumed artifact leaves
        # and binds their digest to VIEW.json before this view is published.
        return
    output = run_tool(
        [str(scripts / "dependencies/build_vendored_sleigh_native_source.sh"),
         "--work-root", str(view.parent)]
    )
    expected = (
        f"MACSCOPE_SLEIGH_SOURCE_BUILD_ROOT={view}\n"
        f"MACSCOPE_SLEIGH_MATERIALIZATION_ROOT={view}/materialization\n"
    )
    if output != expected:
        raise DevCacheError(f"{component} verifier returned an unexpected output contract")


def build_payload(component: str, repository: Path, temporary: Path, materialization: Path | None = None) -> Path:
    scripts = repository / "Scripts"
    if component == "native-bridge":
        if materialization is None:
            raise DevCacheError("native-bridge build requires the SLEIGH materialization root")
        build_root = temporary / "build"
        revision = run_tool(
            ["/usr/bin/python3", "-B", str(scripts / "native-decompiler-xpc/native_decompiler_source_identity.py"),
             "--repository-root", str(repository), "--profile", "wrapper"]
        ).strip()
        output = run_tool(
            [str(scripts / "native-decompiler-xpc/build_native_bridge.sh"),
             "--source-root", str(repository / "Tools/NativeDecompilerBridge"),
             "--build-root", str(build_root),
             "--materialization-root", str(materialization),
             "--wrapper-revision", revision,
             "--configuration", "Release"],
            extra_environment=native_build_tool_environment(),
        )
        print(output, end="", file=sys.stderr)
        payload = temporary / "payload"
        native_bridge_payload_tool(repository, "extract", "--repository-root", str(repository),
                                   "--materialization-root", str(materialization),
                                   "--build-root", str(build_root), "--payload", str(payload))
        # The payload omits the build root, so carry the CTest log out before
        # it is removed; resolve() keeps it beside the published entry.
        test_log = build_root / "Testing/Temporary/LastTest.log"
        if test_log.is_file():
            (temporary / "test-log").mkdir()
            shutil.copy2(test_log, temporary / "test-log/LastTest.log")
        remove_tree(build_root)
        return payload
    if component == "ghostty-vt":
        payload = temporary / "payload"
        payload.mkdir()
        output = run_tool([str(scripts / "build_ghostty_vt.sh"), "--work-root", str(payload)])
        print(output, end="", file=sys.stderr)
        verify_view(component, repository, payload)
        for transient in ("cache", "global-cache", "sdk-compatibility"):
            if (payload / transient).is_dir() and not (payload / transient).is_symlink():
                remove_tree(payload / transient)
        (payload / "cache").mkdir()
        (payload / "global-cache").mkdir()
        return payload
    work = temporary / "work"
    work.mkdir()
    if component == "ghostty-surface":
        payload = work / "GhosttySurface"
        output = run_tool(
            [str(scripts / "dependencies/build_vendored_ghostty_surface.sh"), "--work-root", str(work)],
            extra_environment=SURFACE_TOOL_ENVIRONMENT,
        )
        expected = (
            f"GHOSTTY_SURFACE_SOURCE_DIR={payload}\n"
            f"GHOSTTY_SURFACE_ARTIFACT_ROOT={payload}/macos/GhosttyKit.xcframework\n"
        )
        if output != expected:
            raise DevCacheError("Ghostty surface producer returned an unexpected output contract")
        verify_view(component, repository, payload)
        transients = (".zig-cache", "zig-out")
    else:
        payload = work / "SleighNativeSource"
        output = run_tool(
            [str(scripts / "dependencies/build_vendored_sleigh_native_source.sh"), "--work-root", str(work)]
        )
        expected = (
            f"MACSCOPE_SLEIGH_SOURCE_BUILD_ROOT={payload}\n"
            f"MACSCOPE_SLEIGH_MATERIALIZATION_ROOT={payload}/materialization\n"
        )
        if output != expected:
            raise DevCacheError("native SLEIGH producer returned an unexpected output contract")
        verify_view(component, repository, payload)
        transients = ("source", "build")
    for transient in transients:
        if (payload / transient).is_dir() and not (payload / transient).is_symlink():
            remove_tree(payload / transient)
    return payload


# Metadata publication/reclaim/release share a stable kernel lock. Never unlink
# these guard files: replacing one would split contenders between two inodes.
@contextlib.contextmanager
def entry_lock_guard(path: Path, *, blocking: bool = False):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise DevCacheError(f"dependency cache lock guard is not a regular file: {path}")
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | (0 if blocking else fcntl.LOCK_NB))
        except BlockingIOError:
            yield False
            return
        try:
            yield True
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def process_start_identity(pid: int) -> str | None:
    """Darwin's ps lstart field, in a fixed locale; uncertainty is not death."""
    try:
        result = subprocess.run(
            ["/bin/ps", "-p", str(pid), "-o", "lstart="],
            env={**os.environ, "LC_ALL": "C", "TZ": "UTC"}, capture_output=True, text=True, timeout=5,
        )
        lines = result.stdout.strip().splitlines()
        if result.returncode != 0 or len(lines) != 1:
            return None
        identity = " ".join(lines[0].split())
        datetime.strptime(identity, "%a %b %d %H:%M:%S %Y")
        return identity
    except (OSError, ValueError, subprocess.SubprocessError):
        return None


def read_lock_owner(lock: Path) -> dict[str, str] | None:
    """None means unreadable/ambiguous; {} means absent, empty or partial."""
    try:
        descriptor = os.open(lock / "owner", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "r", encoding="utf-8") as stream:
            metadata = os.fstat(stream.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > 4096:
                return None
            text = stream.read(4097)
            if len(text) > 4096:
                return None
    except FileNotFoundError:
        return {}
    except (OSError, UnicodeError):
        return None
    fields = {}
    for line in text.splitlines():
        if "=" not in line:
            return None
        name, value = line.split("=", 1)
        if name in fields or name not in {"pid", "hostname", "start", "token", "component", "key"}:
            return None
        fields[name] = value
    return fields


def describe_lock_owner(lock: Path, hostname: str | None = None) -> str:
    """Read-only observation, never authority to reclaim; reject racing snapshots."""
    def snapshot():
        directory = lock.lstat()
        if not stat.S_ISDIR(directory.st_mode):
            raise ValueError("lock is not an ordinary directory")
        try:
            owner_metadata = (lock / "owner").lstat()
        except FileNotFoundError:
            owner_metadata = None
        fields = ("st_dev", "st_ino", "st_mode", "st_size", "st_mtime_ns", "st_ctime_ns")
        return (tuple(getattr(directory, name) for name in fields),
                None if owner_metadata is None else tuple(getattr(owner_metadata, name) for name in fields)), directory

    try:
        before, metadata = snapshot()
    except FileNotFoundError:
        return "lock not present; owner unknown"
    except (OSError, ValueError):
        return "owner unknown; lock unreadable or not an ordinary directory"
    owner = read_lock_owner(lock)
    fields = "" if owner is None else "; ".join(
        f"{label}={owner[name]!r}" for name, label in
        (("pid", "pid"), ("hostname", "host"), ("start", "recorded start")) if name in owner
    )
    try:
        current_host = socket.gethostname() if hostname is None else hostname
        if owner is None:
            verdict = "owner unknown; unreadable or malformed record"
        elif not current_host:
            verdict = "owner unknown; current hostname unavailable"
        elif owner.get("hostname") not in (None, current_host):
            verdict = f"foreign host; recorded host={owner['hostname']!r}; current host={current_host!r}; liveness unknown"
        elif "pid" not in owner:
            remaining = max(0.0, LOCK_OWNER_GRACE_SECONDS - (time.time() - metadata.st_mtime))
            verdict = (f"owner-less or partial record; liveness unknown; grace remaining={remaining:.1f}s"
                       if remaining else "owner-less or partial record; liveness unknown; grace elapsed")
        elif not owner["pid"].isdecimal() or int(owner["pid"]) <= 0:
            verdict = "owner unknown; malformed pid"
        else:
            pid = int(owner["pid"])
            try:
                os.kill(pid, 0)
            except ProcessLookupError:
                legacy = "hostname" not in owner and set(owner) <= {"pid", "component", "key"}
                reason = ("observation only; reclaim requires guarded decision"
                          if owner.get("hostname") == current_host or legacy
                          else "not reclaimable: partial record is not a legacy local owner")
                verdict = f"owner process not running; {reason}"
            except (OSError, OverflowError):
                verdict = "owner unknown; signal-0 probe failed"
            else:
                start = process_start_identity(pid)
                verdict = ("owner unknown; process start probe failed" if start is None else
                           "live pid; recorded start matches" if start == owner.get("start") else
                           "live pid; recorded start differs or is absent; refusing pid-reuse reclaim")
        after, _ = snapshot()
        if before != after:
            return "owner unknown; lock or owner record changed during inspection"
    except (OSError, ValueError, OverflowError):
        return "owner unknown; inspection failed or lock changed"
    return f"{fields}; {verdict}" if fields else verdict


def lock_reclaim_reason(lock: Path, hostname: str) -> str | None:
    """Called only with the stable guard held; never infer death from an error."""
    try:
        metadata = lock.lstat()
    except OSError:
        return None
    if not stat.S_ISDIR(metadata.st_mode):
        return None
    owner = read_lock_owner(lock)
    if owner is None:
        return None
    # A named foreign host vetoes even an old, partial or dead-pid record.
    if owner.get("hostname") not in (None, hostname):
        return None
    raw_pid = owner.get("pid")
    if raw_pid is None:
        # 60 seconds is much longer than an owner-file write. Publication is
        # additionally fenced by the guard, so even a paused writer is safe.
        if time.time() - metadata.st_mtime >= LOCK_OWNER_GRACE_SECONDS:
            return "owner-less lock past grace period"
        return None
    if not raw_pid.isdecimal() or int(raw_pid) <= 0:
        return None
    pid = int(raw_pid)
    # Ruling 350: legacy pid/component/key records belong to this host because
    # the admitted cache is a per-user LOCAL root, never a network/shared root.
    # Filesystem admission enforces ownership/canonicality, not locality itself.
    legacy = "hostname" not in owner and set(owner) <= {"pid", "component", "key"}
    if owner.get("hostname") != hostname and not legacy:
        return None
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return f"dead pid {pid}"
    except (OSError, OverflowError):
        return None
    current_start = process_start_identity(pid)
    if current_start is None or current_start != owner.get("start"):
        # A reused pid is distinguishable, but still live: conservatively wait.
        return None
    return None


def release_entry_lock(lock: Path, guard: Path, token: str, identity: tuple[int, int]) -> None:
    """A former owner cannot unlink a replacement, even after an ABA rename."""
    waited = 0
    while True:
        try:
            with entry_lock_guard(guard) as guarded:
                if guarded:
                    try:
                        metadata = lock.lstat()
                    except FileNotFoundError:
                        return
                    if (metadata.st_dev, metadata.st_ino) != identity or not stat.S_ISDIR(metadata.st_mode):
                        return
                    owner = read_lock_owner(lock)
                    if owner is None or owner.get("token") != token:
                        return
                    (lock / "owner").unlink()
                    lock.rmdir()
                    return
        except (OSError, DevCacheError) as error:
            # Never hide a build failure or remove a lock without its fence.
            log(f"leaving dependency cache lock {lock}: release failed: {error}")
            return
        if waited >= LOCK_TIMEOUT_SECONDS:
            log(f"leaving dependency cache lock {lock}: release guard timed out")
            return
        time.sleep(1)
        waited += 1


def ensure_entry(
    component: str, key: str, repository: Path, cache_root: Path, build: bool, materialization: Path | None = None
) -> tuple[Path, str]:
    entry = cache_root / "artifacts/v1" / component / key
    if entry.exists() or entry.is_symlink():
        return entry, "verified-hit"
    if not build:
        raise Unavailable(f"{component} {key} is not in the shared cache")
    cache_root = admit_owner_directory(cache_root, "dependency cache root", create=False)
    lock_parent = cache_root / "locks/v1" / component
    lock_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    lock = lock_parent / f"{key}.lock"
    guard = cache_root / "lock-guards/v1" / component / f"{key}.guard"
    token = uuid.uuid4().hex
    hostname = socket.gethostname()
    waited = 0
    wait_started = time.monotonic()
    last_wait_log = None
    while True:
        acquired = False
        owner_summary = "guard busy, owner not inspected"
        start_identity = process_start_identity(os.getpid())
        if start_identity is None:
            raise DevCacheError(
                f"/bin/ps failed to establish the current process start identity (pid {os.getpid()}); "
                "cannot safely acquire a dependency cache lock"
            )
        owner_text = (f"pid={os.getpid()}\nhostname={hostname}\nstart={start_identity}\n"
                      f"token={token}\ncomponent={component}\nkey={key}\n")
        with entry_lock_guard(guard) as guarded:
            if guarded and hostname:
                try:
                    lock.mkdir()
                except FileExistsError:
                    if entry.exists() or entry.is_symlink():
                        return entry, "verified-after-wait"
                    reason = lock_reclaim_reason(lock, hostname)
                    if reason is not None:
                        reclaimed_owner_summary = describe_lock_owner(lock, hostname)
                        retired = lock_parent / f"{key}.retired-{uuid.uuid4().hex}"
                        lock.rename(retired)
                        log(f"reclaiming dependency cache lock {lock}: {reason}; {reclaimed_owner_summary}")
                        remove_tree(retired)
                        try:
                            lock.mkdir()
                        except FileExistsError:
                            # Older checkouts do not take the guard and can win
                            # this gap. Their lock is not ours: wait, never remove it.
                            pass
                        else:
                            acquired = True
                    else:
                        # Keep the existing polling/timeout contract below.
                        pass
                else:
                    acquired = True
                if acquired:
                    metadata = lock.stat()
                    identity = (metadata.st_dev, metadata.st_ino)
                    try:
                        (lock / "owner").write_text(owner_text, encoding="utf-8")
                    except BaseException:
                        # No successor can enter while this guard is held.
                        (lock / "owner").unlink(missing_ok=True)
                        lock.rmdir()
                        raise
            if guarded and not acquired:
                owner_summary = describe_lock_owner(lock, hostname)
        if acquired:
            break
        if entry.exists() or entry.is_symlink():
            return entry, "verified-after-wait"
        now = time.monotonic()
        elapsed = max(0.0, now - wait_started)
        if last_wait_log is None or now - last_wait_log >= LOCK_WAIT_LOG_INTERVAL_SECONDS:
            log(f"waiting for dependency cache lock {lock}: {owner_summary}; "
                f"waited {elapsed:.1f}s / timeout {LOCK_TIMEOUT_SECONDS}s")
            last_wait_log = now
        if waited >= LOCK_TIMEOUT_SECONDS:
            raise DevCacheError(
                f"timed out waiting for dependency cache lock: {lock}; {owner_summary}; "
                f"waited {elapsed:.1f}s / timeout {LOCK_TIMEOUT_SECONDS}s; "
                "nothing was removed from the observed lock by diagnostics"
            )
        time.sleep(1)
        waited += 1
    temporary = None
    try:
        if entry.exists() or entry.is_symlink():
            return entry, "verified-after-wait"
        temporary_parent = cache_root / "temporary/v1" / component
        temporary_parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        temporary = Path(tempfile.mkdtemp(prefix=f"{key}.", dir=temporary_parent))
        log(f"{component} {key[:12]}: miss; building once from the governed sources")
        started = time.monotonic()
        payload = (build_payload(component, repository, temporary) if materialization is None
                   else build_payload(component, repository, temporary, materialization))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            CACHE.publish_command(
                argparse.Namespace(entry=entry, component=component, key=key, payload=payload)
            )
        log(f"{component} {key[:12]}: published in {time.monotonic() - started:.1f}s")
        # Keep the passing build's test log; only the newest per component key.
        if (temporary / "test-log").is_dir():
            kept = cache_root / "test-logs/v1" / component / key
            kept.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if kept.exists() or kept.is_symlink():
                remove_tree(kept)
            (temporary / "test-log").rename(kept)
            log(f"{component} {key[:12]}: test log kept at {kept}")
        return entry, "published-miss"
    except ProducerCancelled:
        if temporary is not None:
            log(f"{component}: cancelled producer retained in place at {temporary}")
            temporary = None
        raise
    except Exception:
        # Keep the failed build root (e.g. Testing/Temporary/LastTest.log) for
        # diagnosis; only the newest failure per component key is retained.
        if temporary is not None and temporary.exists():
            kept = cache_root / "failed/v1" / component / key
            kept.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            if kept.exists() or kept.is_symlink():
                remove_tree(kept)
            temporary.rename(kept)
            temporary = None
            log(f"{component} {key[:12]}: failed build kept at {kept}")
        raise
    finally:
        if temporary is not None and temporary.exists():
            remove_tree(temporary)
        release_entry_lock(lock, guard, token, identity)


# ── Views ─────────────────────────────────────────────────────────────────────


def descriptors(component: str, repository: Path, view: Path, directory: Path) -> dict[str, dict[str, str]]:
    scripts = repository / "Scripts"
    if component == "ghostty-vt":
        path = directory / "ghostty-vt-staging.json"
        digest = run_tool(
            ["/usr/bin/python3", "-B", str(scripts / "dependencies/stage_verified_ghostty_vt.py"),
             "--describe", "--artifact-root", str(view / "artifacts"), "--descriptor", str(path)]
        ).strip()
    elif component == "ghostty-surface":
        path = directory / "ghostty-surface-admission.json"
        digest = run_tool(
            ["/usr/bin/python3", "-B", str(scripts / "dependencies/verified_ghostty_surface_admission.py"),
             "--describe", "--source-root", str(view), "--descriptor", str(path)]
        ).strip()
    else:
        return {}
    if CACHE.HEX64.fullmatch(digest) is None or sha256_bytes(path.read_bytes()) != digest:
        raise DevCacheError(f"{component} consumer descriptor identity is malformed")
    return {"consumer": {"path": str(path), "sha256": digest}}


def view_receipt_structure_valid(receipt: Path, entry: Path, view: Path, component: str, key: str) -> dict[str, Any] | None:
    """Run the existing receipt and structural checks before stamp admission.

    The receipt binds the ENTRY.json SHA-256 (every payload path, kind, size
    and content digest) and the consumer descriptor digests. Across runs the
    read-only view is compared structurally (paths, kinds, sizes, executable
    bits, symlink targets; no rehash) with ENTRY.json. The recorded
    entry/view metadata digests remain historical and are never compared.
    Stamp admission is a separate, subsequent check.
    """
    value = read_memo(receipt)
    if not isinstance(value, dict) or value.get("schema_version") != VIEW_SCHEMA_VERSION:
        return None
    try:
        manifest = CACHE.read_canonical_json(entry / "ENTRY.json", "cache entry receipt")
        expected = [
            {name: field for name, field in record.items() if name != "sha256"}
            for record in manifest["payload_records"]
        ]
        observed, observed_bytes = CACHE.payload_records(view, hash_files=False, allow_hardlinks=True)
        checks = (
            value.get("component") == component,
            value.get("key") == key,
            value.get("entry") == str(entry),
            value.get("view") == str(view),
            value.get("entry_receipt_sha256") == CACHE.sha256(entry / "ENTRY.json"),
            observed == expected,
            observed_bytes == manifest["total_bytes"],
            all(path.lstat().st_mode & 0o222 == 0
                for path in [view, *view.rglob("*")] if not path.is_symlink()),
            all(
                isinstance(item, dict) and CACHE.sha256(Path(item["path"])) == item["sha256"]
                for item in value.get("descriptors", {}).values()
            ),
            receipt.stat().st_mode & 0o222 == 0,
        )
    except (OSError, KeyError, TypeError, ValueError, CACHE.CacheError):
        return None
    return value if all(checks) else None


def view_file_stamps(view: Path) -> list[dict[str, Any]]:
    """Inventory regular-file metadata only; never open payload bytes."""
    records = []
    for path in sorted(view.rglob("*"), key=lambda item: os.fsencode(item.relative_to(view))):
        metadata = path.lstat()
        if stat.S_ISREG(metadata.st_mode):
            records.append({"path": path.relative_to(view).as_posix(),
                            "st_ino": metadata.st_ino, "st_size": metadata.st_size,
                            "st_mtime_ns": metadata.st_mtime_ns, "st_ctime_ns": metadata.st_ctime_ns})
    return records


def view_stamp_state(receipt: Path, view: Path) -> str:
    """Return missing, valid or invalid; absence alone permits locked TOFU."""
    sidecar = receipt.with_name("VIEW-STAMPS.json")
    try:
        metadata = sidecar.lstat()
    except FileNotFoundError:
        return "missing"
    except OSError:
        return "invalid"
    try:
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o222):
            return "invalid"
        value = CACHE.read_canonical_json(sidecar, "view stamps")
        if (set(value) != {"schema_version", "view_receipt_sha256", "files"}
                or type(value["schema_version"]) is not int or value["schema_version"] != 1
                or value["view_receipt_sha256"] != sha256_bytes(receipt.read_bytes())
                or not isinstance(value["files"], list)):
            return "invalid"
        fields = {"path", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns"}
        for record in value["files"]:
            if (not isinstance(record, dict) or set(record) != fields
                    or not isinstance(record["path"], str)
                    or any(type(record[name]) is not int for name in fields - {"path"})):
                return "invalid"
        return "valid" if value["files"] == view_file_stamps(view) else "invalid"
    except (OSError, KeyError, TypeError, ValueError, CACHE.CacheError):
        return "invalid"


def write_view_stamps(receipt: Path, view: Path) -> None:
    """Create stamps only under resolve's component lock; never repair them.

    Legacy adoption trusts the structurally valid current view on first use.
    Owner receipt replacement/deletion and concurrent owner mutation are
    outside the bounded stamp guarantee.
    """
    sidecar = receipt.with_name("VIEW-STAMPS.json")
    try:
        sidecar.lstat()
    except FileNotFoundError:
        pass
    else:
        raise DevCacheError("view stamps already exist; refusing repair or re-verification")
    value = {"schema_version": 1, "view_receipt_sha256": sha256_bytes(receipt.read_bytes()),
             "files": view_file_stamps(view)}
    temporary = sidecar.with_name(f".{sidecar.name}.{os.getpid()}")
    temporary.write_bytes(canonical_json(value))
    temporary.chmod(0o444)
    os.replace(temporary, sidecar)


def view_receipt_valid(receipt: Path, entry: Path, view: Path, component: str, key: str) -> dict[str, Any] | None:
    """Admit an authentic persisted receipt and unchanged per-file stamps.

    After the existing receipt and structural checks pass, only device-number-only
    changes preserve stamp admission; changes to recorded inode/size/mtime/ctime
    refuse stamp admission even when bytes are unchanged. A stamp-admission
    failure does not authorize re-verification. Existing receipt or structural
    failures retain the pre-existing rebuild/refusal behavior described in ruling 4.
    """
    value = view_receipt_structure_valid(receipt, entry, view, component, key)
    if value is None:
        return None
    return value if view_stamp_state(receipt, view) == "valid" else None


def native_bridge_materialization(
    repository: Path, cache_root: Path, view_root: Path, requested: str | None
) -> Path:
    """The SLEIGH view the bridge key binds; it must be the consumer's materialization."""
    if not requested:
        raise Unavailable("native-bridge needs --materialization-root (the consumer's SLEIGH materialization)")
    materialization = Path(requested).resolve(strict=True)
    reused_sleigh_materialization(repository, materialization, cache_root, view_root)
    return materialization


def reused_sleigh_materialization(
    repository: Path, requested: Path, cache_root: Path | None = None, view_root: Path | None = None,
) -> dict[str, Any]:
    """Admit only an already domain-verified SLEIGH view; never repair or rehash it.

    ENTRY supplies the content digests. VIEW binds that exact ENTRY digest and
    the consumer descriptors observed when the domain verifier passed; the view
    must still match ENTRY structurally and its per-file stamps across runs.
    An unstamped legacy view must first be adopted by the explicit locked
    resolve(sleigh-native-source) migration; this lock-free caller never writes.
    A missing receipt or changed identity is an error, not permission to verify
    the unchanged dependency again or silently fall back to a weaker path.
    """
    if cache_root is None or view_root is None:
        cache_root, view_root = roots(argparse.Namespace(cache_root=None, view_root=None))
    component = "sleigh-native-source"
    key, _ = retained_component_key(component, repository, cache_root, view_root)
    entry = cache_root / "artifacts/v1" / component / key
    directory = view_root / component / key
    view = directory / COMPONENTS[component]["view_name"]
    materialization = view / "materialization"
    if Path(requested) != materialization or materialization.resolve(strict=True) != materialization:
        raise DevCacheError("SLEIGH consumer does not name the receipt-bound shared view")
    receipt = directory / "VIEW.json"
    accepted = view_receipt_valid(receipt, entry, view, component, key)
    if accepted is None:
        raise DevCacheError(
            "SLEIGH verification receipt is missing, stale or unstamped; reuse is required. "
            "Run resolve(sleigh-native-source) to migrate a structurally valid legacy view; "
            "stamp refusal does not authorize re-verification")
    manifest = CACHE.load_entry_receipt(entry, component, key)
    files = {}
    for record in manifest["payload_records"]:
        relative = record.get("path", "")
        if not relative.startswith("materialization/") or record.get("kind") == "directory":
            continue
        if (record.get("kind") != "file" or not isinstance(record.get("size"), int)
                or record["size"] < 0 or not isinstance(record.get("sha256"), str)
                or CACHE.HEX64.fullmatch(record["sha256"]) is None):
            raise DevCacheError("SLEIGH entry contains an invalid materialization file identity")
        relative = relative.removeprefix("materialization/")
        if relative in files:
            raise DevCacheError("SLEIGH entry contains duplicate materialization files")
        files[relative] = (record["size"], record["sha256"])
    if "MATERIALIZATION.json" not in files or not any(name.startswith("package/") for name in files):
        raise DevCacheError("SLEIGH entry omits the materialization identity")
    identity = json.loads((materialization / "MATERIALIZATION.json").read_text(encoding="utf-8"))
    if view_receipt_valid(receipt, entry, view, component, key) != accepted:
        raise DevCacheError("SLEIGH view changed while admitting its verified identity")
    log(f"sleigh-native-source {key[:12]}: verification receipt reused")
    return {"key": key, "identity": identity, "files": files, "receipt": str(receipt),
            "manifest_sha256": files["MATERIALIZATION.json"][1]}


def admit_retained_build_sources(repository: Path, completed_commit: str) -> str:
    if not CACHE.HEX64.fullmatch(completed_commit) and not re.fullmatch(r"[0-9a-f]{40}", completed_commit):
        raise DevCacheError("completed build commit must be a full Git object identity")
    resolved = git(repository, "rev-parse", "--verify", completed_commit + "^{commit}").decode().strip()
    changed = git(repository, "diff", "--name-only", "-z", resolved, "HEAD", "--",
                  *COMPONENTS["sleigh-native-source"]["prefixes"]).decode().split("\0")
    if set(filter(None, changed)) - {"Scripts/native-decompiler-direct/verify_sleigh_package.py"}:
        raise DevCacheError("completed SLEIGH build source, resources or build recipe changed")
    return resolved


def adopt_retained_sleigh(
    repository: Path, cache_root: Path, view_root: Path, accepted_entry: Path,
    verification_receipt: Path, retained_root: Path, completed_commit: str,
) -> dict[str, Any]:
    """Adopt identical accepted content for a developer view, retaining its provenance."""
    component = "sleigh-native-source"
    completed_commit = admit_retained_build_sources(repository, completed_commit)
    old_key = accepted_entry.name
    if accepted_entry != cache_root / "artifacts/v1" / component / old_key:
        raise DevCacheError("accepted SLEIGH entry is outside the selected cache layout")
    manifest = CACHE.load_entry_receipt(accepted_entry, component, old_key)
    CACHE.reject_indirect_ancestors(verification_receipt, "accepted verification receipt")
    authority = CACHE.read_canonical_json(verification_receipt, "accepted verification receipt")
    if authority.get("key") != old_key or authority.get("component") != component:
        raise DevCacheError("accepted verification receipt names another artifact")
    bindings = authority.get("bindings")
    if not isinstance(bindings, dict) or bindings.get("domain-verifier") != "verify_sleigh_view":
        raise DevCacheError("accepted receipt lacks SLEIGH domain authority")
    arguments = argparse.Namespace(
        entry=accepted_entry, component=component, key=old_key,
        verification_root=cache_root / "verification.noindex",
        binding=[f"{name}={value}" for name, value in sorted(bindings.items())],
    )
    _, expected_receipt, _ = CACHE.verification_identity(arguments)
    if verification_receipt != expected_receipt:
        raise DevCacheError("accepted verification receipt is not its canonical bound location")
    accepted, authority_digest = CACHE.load_verification_receipt(arguments)
    if accepted != authority:
        raise DevCacheError("accepted verification authority changed during admission")
    admit_owner_directory(retained_root, "retained SLEIGH root", create=False)
    retained_path = retained_root / "SOURCE_BUILD_MATERIALIZATION.json"
    if retained_path.is_symlink():
        raise DevCacheError("retained package receipt is indirect")
    retained = json.loads(retained_path.read_text(encoding="utf-8"))
    old_payload = accepted_entry / "payload"
    completed = json.loads((old_payload / "SOURCE_BUILD_MATERIALIZATION.json").read_text(encoding="utf-8"))
    if retained != completed:
        raise DevCacheError("retained SLEIGH package differs from accepted content")
    identity = json.loads((old_payload / "materialization/MATERIALIZATION.json").read_text(encoding="utf-8"))
    source = json.loads((repository / "ThirdParty/SleighNative/Source/MATERIALIZATION.json").read_text(encoding="utf-8"))
    sys.path.insert(0, str(SCRIPTS / "native-decompiler-direct"))
    from sleigh_package import FIRST_PARTY_MULTISTAGE_PATCH
    required_patches = source["patches"] + [{
        "path": FIRST_PARTY_MULTISTAGE_PATCH[0],
        "sha256": FIRST_PARTY_MULTISTAGE_PATCH[1],
    }]
    if (source["componentId"] != identity["componentId"]
            or required_patches != identity["sourceBuild"]["patches"]
            or any(source[name][field] != identity["sourceBuild"][name + suffix]
                   for name in ("sleigh", "ghidra")
                   for field, suffix in (("gitTree", "GitTree"), ("treeSha256", "TreeSha256")))
            or any(source[name]["revision"] != identity[name + "GitRevision"]
                   for name in ("sleigh", "ghidra"))):
        raise DevCacheError("current SLEIGH source manifest differs from accepted provenance")
    key = component_key(component, repository, view_root)
    entry = cache_root / "artifacts/v1" / component / key
    directory = view_root / component / key
    view = directory / COMPONENTS[component]["view_name"]
    lock = cache_root / "locks/v1" / component / f"{key}.lock"
    admit_owner_directory(lock.parent, "SLEIGH adoption lock directory", create=True)
    guard = cache_root / "lock-guards/v1" / component / f"{key}.guard"
    with entry_lock_guard(guard) as guarded:
        if not guarded:
            raise DevCacheError("SLEIGH adoption cache key is busy; refusing concurrent adoption")
        try:
            lock.mkdir()  # Existing ownership is a hard stop; adoption never builds or waits.
        except FileExistsError as error:
            raise FileExistsError(
                error.errno, f"SLEIGH adoption lock occupied; refusing reclaim; {describe_lock_owner(lock)}; "
                "nothing was removed", str(lock)
            ) from error
        staging = None
        staged_view = None
        descriptor = None
        try:
            admit_owner_directory(directory.parent, "SLEIGH adoption view directory", create=True)
            descriptor = os.open(directory.parent / f".{key}.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            if entry.exists() or entry.is_symlink() or directory.exists() or directory.is_symlink():
                raise DevCacheError("SLEIGH adoption destination already exists; refusing replacement")
            entry.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            staging = Path(tempfile.mkdtemp(prefix=f".{key}.adopt-", dir=entry.parent))
            staged_view = Path(tempfile.mkdtemp(prefix=f".{key}.adopt-", dir=directory.parent))
            expected = [{name: value for name, value in row.items() if name != "sha256"}
                        for row in manifest["payload_records"]]
            for destination in (staging / "payload", staged_view / COMPONENTS[component]["view_name"]):
                CACHE.clonefile_tree(old_payload, destination)
                if CACHE.entry_metadata_digest(accepted_entry) != arguments._reused_entry_metadata:
                    raise DevCacheError("accepted SLEIGH entry changed while cloning")
                records, total = CACHE.payload_records(destination, hash_files=False)
                if records != expected or total != manifest["total_bytes"]:
                    raise DevCacheError("adopted SLEIGH clone differs structurally from accepted receipt")
                CACHE.freeze_tree(destination)
            new_manifest = dict(manifest, key=key)
            CACHE.write_new_canonical(staging / "ENTRY.json", new_manifest)
            CACHE.freeze_tree(staging)
            provenance = {
                "accepted_entry": str(accepted_entry), "accepted_key": old_key,
                "verification_receipt": str(verification_receipt),
                "verification_receipt_sha256": authority_digest,
                "bindings": bindings, "retained_root": str(retained_root),
                "completed_source_commit": completed_commit,
                "retained_package_receipt": retained,
                "adopted_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            }
            value = {
                "component": component, "descriptors": {}, "entry": str(entry),
                "entry_metadata_sha256": CACHE.entry_metadata_digest(staging),
                "entry_receipt_sha256": CACHE.sha256(staging / "ENTRY.json"),
                "entry_status": "receipt-adopted", "key": key, "schema_version": VIEW_SCHEMA_VERSION,
                "verification": "historical domain receipt reused; developer artifact adoption",
                "verified_at": authority["verified_at"], "view": str(view),
                "view_metadata_sha256": CACHE.entry_metadata_digest(staged_view / COMPONENTS[component]["view_name"]),
                "adoption": provenance,
            }
            # Validate against staging paths before either immutable result is published.
            staged_receipt = dict(value, entry=str(staging), view=str(staged_view / COMPONENTS[component]["view_name"]))
            CACHE.write_new_canonical(staged_view / "VIEW.json", staged_receipt)
            (staged_view / "VIEW.json").chmod(0o444)
            if view_receipt_structure_valid(staged_view / "VIEW.json", staging,
                                  staged_view / COMPONENTS[component]["view_name"], component, key) is None:
                raise DevCacheError("staged SLEIGH adoption receipt failed structural admission")
            (staged_view / "VIEW.json").unlink()
            CACHE.write_new_canonical(staged_view / "VIEW.json", value)
            (staged_view / "VIEW.json").chmod(0o444)
            # Bind final receipt bytes to frozen descendants before their ancestor rename.
            write_view_stamps(staged_view / "VIEW.json", staged_view / COMPONENTS[component]["view_name"])
            staging.rename(entry)
            staging = None
            staged_view.rename(directory)
            staged_view = None
            return {"key": key, "status": "receipt-adopted", "view": view, "receipt": value}
        finally:
            for temporary in (staging, staged_view):
                if temporary is not None:
                    remove_tree(temporary)
            if descriptor is not None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            lock.rmdir()



def sleigh_occupied_view(cache_root: Path, view_root: Path, key: str) -> dict[str, Any]:
    """Observe an occupied destination without acquiring orphan ownership.

    Existing lock domains only, ordered G -> reject L -> F. An authentic VIEW
    admits developer reuse independently of strict ENTRY stamps. Entry-only
    publication cannot be distinguished from an ordinary first-view request;
    both refuse, preserving the destinations without verification or repair.
    """
    component = "sleigh-native-source"
    entry = cache_root / "artifacts/v1" / component / key
    directory = view_root / component / key
    view = directory / COMPONENTS[component]["view_name"]
    receipt = directory / "VIEW.json"
    guard = cache_root / "lock-guards/v1" / component / f"{key}.guard"
    lock = cache_root / "locks/v1" / component / f"{key}.lock"
    view_lock = view_root / component / f".{key}.lock"
    descriptors = []

    def refuse(reason: str) -> None:
        raise DevCacheError(
            f"SLEIGH {reason}: partial adoption preserved; ownership unknown; "
            f"entry={entry}; view={directory}; guard={guard}; lock={lock}; view_lock={view_lock}; "
            "no repair, materialization or re-verification is authorized")

    def snapshot() -> list[tuple[Any, ...]]:
        observed = []
        for destination in (entry, directory, guard, view_lock, receipt,
                            directory / "VIEW-STAMPS.json", entry / "ENTRY.json"):
            for ancestor in destination.parents:
                metadata = ancestor.lstat()
                if not stat.S_ISDIR(metadata.st_mode):
                    refuse("REFUSED_UNSAFE_OR_UNKNOWN")
            try:
                metadata = destination.lstat()
            except FileNotFoundError:
                observed.append((str(destination), None))
                continue
            if (stat.S_ISLNK(metadata.st_mode) or metadata.st_uid != os.getuid()
                    or not (stat.S_ISREG(metadata.st_mode) or stat.S_ISDIR(metadata.st_mode))):
                refuse("REFUSED_UNSAFE_OR_UNKNOWN")
            observed.append((str(destination), metadata.st_dev, metadata.st_ino, metadata.st_mode,
                             metadata.st_size, metadata.st_mtime_ns, metadata.st_ctime_ns))
        return observed

    try:
        for path in (guard, view_lock):
            # Validate ancestors before opening; O_NOFOLLOW also protects the leaf.
            for ancestor in path.parents:
                if not stat.S_ISDIR(ancestor.lstat().st_mode):
                    refuse("REFUSED_UNSAFE_OR_UNKNOWN")
            descriptor = os.open(path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
            descriptors.append(descriptor)
            metadata = os.fstat(descriptor)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid():
                refuse("REFUSED_UNSAFE_OR_UNKNOWN")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                refuse("REFUSED_BUSY_OR_LOCK_OWNER_UNKNOWN")
            if path == guard:
                for ancestor in lock.parents:
                    try:
                        ancestor_metadata = ancestor.lstat()
                    except FileNotFoundError:
                        continue
                    if not stat.S_ISDIR(ancestor_metadata.st_mode):
                        refuse("REFUSED_UNSAFE_OR_UNKNOWN")
                try:
                    lock.lstat()
                except FileNotFoundError:
                    pass
                else:
                    refuse("REFUSED_BUSY_OR_LOCK_OWNER_UNKNOWN")
        before = snapshot()
        for path, descriptor in zip((guard, view_lock), descriptors):
            named, held = path.lstat(), os.fstat(descriptor)
            if (named.st_dev, named.st_ino) != (held.st_dev, held.st_ino):
                refuse("REFUSED_CHANGED_DURING_OBSERVATION")
        if not entry.is_dir() or not directory.is_dir():
            refuse("REFUSED_OCCUPIED_OR_UNADMITTED")
        value = view_receipt_valid(receipt, entry, view, component, key)
        if value is None:
            refuse("REFUSED_OCCUPIED_OR_UNADMITTED")
        if view_receipt_valid(receipt, entry, view, component, key) != value or snapshot() != before:
            refuse("REFUSED_CHANGED_DURING_OBSERVATION")
        return {"key": key, "status": "view-reused", "view": view, "receipt": value}
    except OSError as error:
        raise DevCacheError(
            f"SLEIGH REFUSED_LOCK_DOMAIN_OR_OBSERVATION_UNAVAILABLE: entry={entry}; "
            f"view={directory}; preserved without repair: {error}") from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def sleigh_destination_occupied(cache_root: Path, view_root: Path, key: str) -> bool:
    for path in (cache_root / "artifacts/v1/sleigh-native-source" / key,
                 view_root / "sleigh-native-source" / key):
        try:
            path.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise DevCacheError(f"SLEIGH destination observation failed; preserving {path}: {error}") from error
        return True
    return False


def fresh_sleigh_view(repository: Path, cache_root: Path, view_root: Path, key: str) -> dict[str, Any]:
    """Publish the first view only from this invocation's successful producer.

    Proposal for crash-import packaging: unlike occupied observation, this owns
    G -> L -> F continuously. It never adopts or repairs an existing destination.
    """
    component = "sleigh-native-source"
    entry = cache_root / "artifacts/v1" / component / key
    directory = view_root / component / key
    view = directory / COMPONENTS[component]["view_name"]
    guard = cache_root / "lock-guards/v1" / component / f"{key}.guard"
    lock = cache_root / "locks/v1" / component / f"{key}.lock"
    descriptor = None
    temporary = staged = None
    owns_lock = False

    def vacant() -> None:
        if sleigh_destination_occupied(cache_root, view_root, key):
            raise DevCacheError("fresh SLEIGH destination occupied; preserving without repair")

    vacant()
    admit_owner_directory(cache_root, "dependency cache root", create=False)
    with entry_lock_guard(guard) as guarded:
        if not guarded:
            raise DevCacheError("fresh SLEIGH key is busy; refusing producer")
        try:
            admit_owner_directory(lock.parent, "SLEIGH producer lock directory", create=True)
            try:
                lock.mkdir()
            except FileExistsError:
                raise DevCacheError(
                    f"fresh SLEIGH producer lock occupied; refusing reclaim: {lock}; "
                    f"{describe_lock_owner(lock)}; nothing was removed"
                )
            owns_lock = True
            admit_owner_directory(directory.parent, "SLEIGH view directory", create=True)
            view_lock = directory.parent / f".{key}.lock"
            descriptor = os.open(view_lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
            metadata = os.fstat(descriptor)
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                    or metadata.st_nlink != 1 or metadata.st_mode & 0o022):
                raise DevCacheError("fresh SLEIGH view lock is unsafe")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise DevCacheError("fresh SLEIGH view lock is busy")
            vacant()
            parent = cache_root / "temporary/v1" / component
            admit_owner_directory(parent, "SLEIGH producer temporary directory", create=True)
            temporary = Path(tempfile.mkdtemp(prefix=f"{key}.fresh-", dir=parent))
            payload = build_payload(component, repository, temporary)
            # A source/tool metadata change or concurrent destination is not a
            # license to publish under the identity computed before production.
            if component_key(component, repository, view_root) != key:
                raise DevCacheError("fresh SLEIGH producer key changed; refusing publication")
            vacant()
            with contextlib.redirect_stdout(io.StringIO()):
                CACHE.publish_command(argparse.Namespace(entry=entry, component=component, key=key, payload=payload))
            before = CACHE.entry_metadata_digest(entry)
            staged = Path(tempfile.mkdtemp(prefix=f".{key}.fresh-", dir=directory.parent))
            staged_view = staged / COMPONENTS[component]["view_name"]
            with contextlib.redirect_stdout(io.StringIO()):
                CACHE.materialize_command(argparse.Namespace(entry=entry, component=component, key=key,
                                                            destination=staged_view, snapshot_output=None))
            verify_view(component, repository, staged_view)
            if CACHE.entry_metadata_digest(entry) != before:
                raise DevCacheError("fresh SLEIGH entry changed during first-view admission")
            value = {
                "component": component, "descriptors": {}, "entry": str(entry),
                "entry_metadata_sha256": before,
                "entry_receipt_sha256": CACHE.sha256(entry / "ENTRY.json"),
                "entry_status": "published-miss", "key": key, "schema_version": VIEW_SCHEMA_VERSION,
                "verification": "dependency_cache.py materialize (full SHA-256 of entry and view) + domain verifier",
                "verified_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "view": str(view), "view_metadata_sha256": CACHE.entry_metadata_digest(staged_view),
            }
            candidate = dict(value, view=str(staged_view))
            CACHE.write_new_canonical(staged / "VIEW.json", candidate)
            (staged / "VIEW.json").chmod(0o444)
            if view_receipt_structure_valid(staged / "VIEW.json", entry, staged_view, component, key) is None:
                raise DevCacheError("fresh SLEIGH view failed structural receipt admission")
            (staged / "VIEW.json").unlink()
            CACHE.write_new_canonical(staged / "VIEW.json", value)
            (staged / "VIEW.json").chmod(0o444)
            write_view_stamps(staged / "VIEW.json", staged_view)
            if directory.exists() or directory.is_symlink():
                raise DevCacheError("fresh SLEIGH view destination occupied at publication; preserving")
            if CACHE.entry_metadata_digest(entry) != before:
                raise DevCacheError("fresh SLEIGH entry changed before view publication")
            staged.rename(directory)
            staged = None
            return {"key": key, "status": "published-miss", "view": view, "receipt": value}
        finally:
            # Never remove published ENTRY or an occupied destination on failure.
            for scratch in (temporary, staged):
                if scratch is not None:
                    remove_tree(scratch)
            if descriptor is not None:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            if owns_lock:
                lock.rmdir()


def resolve(
    component: str, repository: Path, cache_root: Path, view_root: Path, build: bool,
    requested_materialization: str | None = None, *, fresh_sleigh: bool = False,
) -> dict[str, Any]:
    started = time.monotonic()
    materialization = None
    if component == "native-bridge":
        materialization = native_bridge_materialization(repository, cache_root, view_root, requested_materialization)
    key, compatibility_reuse = retained_component_key(component, repository, cache_root, view_root)
    if component == "sleigh-native-source":
        if sleigh_destination_occupied(cache_root, view_root, key):
            return sleigh_occupied_view(cache_root, view_root, key)
        if not build or compatibility_reuse or not fresh_sleigh:
            raise Unavailable(f"{component} {key} requires explicit fresh producer first-view admission")
        return fresh_sleigh_view(repository, cache_root, view_root, key)
    entry, entry_status = ensure_entry(component, key, repository, cache_root, build and not compatibility_reuse, materialization)
    component_root = view_root / component
    component_root.mkdir(mode=0o700, exist_ok=True)
    directory = component_root / key
    view = directory / COMPONENTS[component]["view_name"]
    receipt = directory / "VIEW.json"
    lock_descriptor = os.open(component_root / f".{key}.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        fcntl.flock(lock_descriptor, fcntl.LOCK_EX)
        value = view_receipt_structure_valid(receipt, entry, view, component, key)
        if value is not None:
            stamp_state = view_stamp_state(receipt, view)
            if stamp_state == "invalid":
                raise DevCacheError("view stamp admission failed; refusing repair or re-verification")
            if stamp_state == "missing":
                write_view_stamps(receipt, view)
                log(f"{component} {key[:12]}: legacy view was stamped under the component lock")
            status = "view-reused"
        else:
            if compatibility_reuse or (component == "native-bridge" and not build):
                raise DevCacheError("retained dependency receipt is invalid; refusing repair or re-verification")
            if directory.exists() or directory.is_symlink():
                remove_tree(directory)
            directory.mkdir(mode=0o700)
            before = CACHE.entry_metadata_digest(entry)
            # Full SHA-256 of the immutable entry and of the new read-only view.
            CACHE.materialize_command(
                argparse.Namespace(entry=entry, component=component, key=key,
                                   destination=view, snapshot_output=None)
            )
            if materialization is None:
                verify_view(component, repository, view)
            else:
                verify_view(component, repository, view, materialization)
            described = descriptors(component, repository, view, directory)
            if CACHE.entry_metadata_digest(entry) != before:
                raise DevCacheError("cache entry metadata changed during view verification")
            value = {
                "component": component,
                "descriptors": described,
                "entry": str(entry),
                "entry_metadata_sha256": before,
                "entry_receipt_sha256": CACHE.sha256(entry / "ENTRY.json"),
                "entry_status": entry_status,
                "key": key,
                "schema_version": VIEW_SCHEMA_VERSION,
                "verification": "dependency_cache.py materialize (full SHA-256 of entry and view) + domain verifier",
                "verified_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "view": str(view),
                "view_metadata_sha256": CACHE.entry_metadata_digest(view),
            }
            temporary = directory / f".VIEW.json.{os.getpid()}"
            temporary.write_bytes(canonical_json(value))
            temporary.chmod(0o444)
            os.replace(temporary, receipt)
            write_view_stamps(receipt, view)
            status = "view-verified" if entry_status == "verified-hit" else entry_status
    finally:
        fcntl.flock(lock_descriptor, fcntl.LOCK_UN)
        os.close(lock_descriptor)
    log(f"{component} {key[:12]}: {status} in {time.monotonic() - started:.1f}s ({view})")
    return {"key": key, "status": status, "view": view, "receipt": value}


def contract(component: str, resolved: dict[str, Any]) -> list[str]:
    view: Path = resolved["view"]
    lines = [f"MACSCOPE_DEV_DEPENDENCY_KEY={resolved['key']}"]
    consumer = resolved["receipt"].get("descriptors", {}).get("consumer")
    if component == "ghostty-vt":
        lines += [
            f"MACSCOPE_GHOSTTY_VT_VERIFIED_ARTIFACT_ROOT={view}/artifacts",
            f"MACSCOPE_GHOSTTY_VT_VERIFIED_DESCRIPTOR={consumer['path']}",
            f"MACSCOPE_GHOSTTY_VT_VERIFIED_DESCRIPTOR_SHA256={consumer['sha256']}",
        ]
    elif component == "native-bridge":
        lines += [f"MACSCOPE_NATIVE_DECOMPILER_CACHED_VIEW={view}"]
    elif component == "ghostty-surface":
        lines += [
            f"MACSCOPE_GHOSTTY_SURFACE_WORK_ROOT={view.parent}",
            f"MACSCOPE_GHOSTTY_SURFACE_VERIFIED_DESCRIPTOR={consumer['path']}",
            f"MACSCOPE_GHOSTTY_SURFACE_VERIFIED_DESCRIPTOR_SHA256={consumer['sha256']}",
        ]
    else:
        lines += [
            f"MACSCOPE_SLEIGH_SOURCE_BUILD_ROOT={view}",
            f"MACSCOPE_SLEIGH_MATERIALIZATION_ROOT={view}/materialization",
        ]
    for line in lines:
        if any(character in line for character in '"$\n') or "//" in line.partition("=")[2]:
            raise DevCacheError(f"dependency view path is not representable: {line}")
    return lines


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("key", "resolve"):
        command = commands.add_parser(name)
        command.add_argument("--component", choices=sorted(COMPONENTS), required=True)
        command.add_argument("--repository-root", type=Path, default=SCRIPTS.parent)
        command.add_argument("--cache-root")
        command.add_argument("--view-root")
        if name == "resolve":
            command.add_argument("--fresh-sleigh-first-view", action="store_true",
                                 help="explicit producer-owned first SLEIGH view; never repairs occupied keys")
            command.add_argument("--no-build", action="store_true",
                                 help="report unavailable on a cache miss instead of building once")
            command.add_argument("--materialization-root",
                                 help="native-bridge only: the consumer's SLEIGH materialization root")
    reuse = commands.add_parser("reuse-sleigh")
    reuse.add_argument("--repository-root", type=Path, default=SCRIPTS.parent)
    reuse.add_argument("--cache-root")
    reuse.add_argument("--view-root")
    reuse.add_argument("--materialization-root", type=Path, required=True)
    reuse.add_argument("--expected-sanitizer", choices=("none",), default="none")
    reuse.add_argument("--output-json", action="store_true")
    reuse.set_defaults(component="sleigh-native-source")
    adopt = commands.add_parser("adopt-retained-sleigh")
    adopt.add_argument("--repository-root", type=Path, default=SCRIPTS.parent)
    adopt.add_argument("--cache-root")
    adopt.add_argument("--view-root")
    adopt.add_argument("--accepted-entry", type=Path, required=True)
    adopt.add_argument("--verification-receipt", type=Path, required=True)
    adopt.add_argument("--retained-root", type=Path, required=True)
    adopt.add_argument("--completed-source-commit", required=True)
    adopt.set_defaults(component="sleigh-native-source")
    arguments = parser.parse_args()
    repository = arguments.repository_root.resolve(strict=True)
    try:
        require_git_checkout(repository)
        cache_root, view_root = roots(arguments)
        if arguments.command == "adopt-retained-sleigh":
            resolved = adopt_retained_sleigh(repository, cache_root, view_root, arguments.accepted_entry,
                                             arguments.verification_receipt, arguments.retained_root,
                                             arguments.completed_source_commit)
            print("\n".join(contract(arguments.component, resolved)))
            return 0
        if arguments.command == "reuse-sleigh":
            accepted = reused_sleigh_materialization(repository, arguments.materialization_root, cache_root, view_root)
            if arguments.output_json:
                print(json.dumps({"identity": accepted["identity"], "manifest_sha256": accepted["manifest_sha256"]},
                                 sort_keys=True, separators=(",", ":")))
            return 0
        if arguments.command == "key":
            print(component_key(arguments.component, repository, view_root))
            return 0
        # A focused native Debug iteration uses its retained CMake products on
        # a miss. Never launch the cache producer's cold build/full CTest here.
        build_on_miss = not arguments.no_build
        if arguments.component == "native-bridge" and os.environ.get("MACSCOPE_NATIVE_DEV_BUILD_ONLY") == "1":
            build_on_miss = False
        resolved = resolve(arguments.component, repository, cache_root, view_root, build_on_miss,
                           arguments.materialization_root, fresh_sleigh=arguments.fresh_sleigh_first_view)
        print("\n".join(contract(arguments.component, resolved)))
        return 0
    except Unavailable as error:
        if arguments.command == "adopt-retained-sleigh":
            print(f"ERROR: SLEIGH adoption unavailable: {error}", file=sys.stderr)
            return 1
        log(f"{arguments.component} unavailable ({error}); no artifact returned")
        return UNAVAILABLE_STATUS
    except (DevCacheError, CACHE.CacheError, OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as error:
        print(f"ERROR: dev dependency cache: {arguments.component}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
