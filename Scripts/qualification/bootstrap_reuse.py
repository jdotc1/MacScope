#!/usr/bin/env python3
"""Tree-keyed reuse of a verified ``Scripts/bootstrap.sh`` result.

A full bootstrap leaves exactly three outputs inside a run's source copy: the
generated ``MacScope.xcodeproj`` (five files), the machine-local
``DependencyRoots.local.xcconfig`` and the ``LocalPackages`` link. The project
bytes do not depend on the run root; the other two name run-owned roots only.

``record`` stores a byte-hashed copy of the project plus run-root-relative
templates of the xcconfig and link after a full bootstrap succeeded. ``reuse``
replays them into a fresh run when every key input is identical: it re-hashes
the stored project, clones it, restores the recorded modes, re-hashes the clone,
writes the xcconfig/link for this run root and re-runs the cheap checks
(freshness stamp against the current inputs, source inclusion). Exit status 3
means "not reusable; run the full bootstrap".
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import secrets
import shlex
import socket
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any


SCHEMA_VERSION = 1
NOT_REUSABLE_STATUS = 3
HEX64 = re.compile(r"[0-9a-f]{64}")
NAME = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}")
RUN_ROOT_TOKEN = "@MACSCOPE_RUN_ROOT@"
PROJECT = "MacScope/MacScope.xcodeproj"
XCCONFIG = "MacScope/DependencyRoots.local.xcconfig"
LOCAL_PACKAGES = "MacScope/LocalPackages"
FRESHNESS_STAMP = ".macscope-project-generation.sha256"
# Scripts/bootstrap.sh step 8; bootstrap.sh is itself a key input.
SOURCE_INCLUSION = ("WorkspaceDatabase.swift", "AnalysisEngine.swift")
MAX_XCCONFIG_BYTES = 64 * 1024
RECEIPT_FIELDS = {
    "key",
    "key_inputs",
    "local_packages_target",
    "project_identity",
    "project_manifest",
    "schema_version",
    "verification",
    "verified_at",
    "xcconfig_mode",
    "xcconfig_template",
}


class ReuseError(RuntimeError):
    """A bootstrap reuse path or record violated its closed contract."""


class NotReusableError(ReuseError):
    """The stored bootstrap cannot be reused; run the full bootstrap."""


def _restore_module():
    path = Path(__file__).resolve().with_name("restore_build_source.py")
    spec = importlib.util.spec_from_file_location("macscope_restore_build_source", path)
    if spec is None or spec.loader is None:
        raise ReuseError("restore_build_source.py is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def read_canonical_json(path: Path, label: str) -> dict[str, Any]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise NotReusableError(f"{label} must be one ordinary single-link file")
    payload = path.read_bytes()
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise NotReusableError(f"{label} is malformed") from error
    if not isinstance(value, dict) or canonical_json(value) != payload:
        raise NotReusableError(f"{label} is not canonical JSON")
    return value


def sha256_bytes(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            digest.update(block)
    return digest.hexdigest()


def named_value(raw: str, label: str) -> tuple[str, str]:
    name, separator, value = raw.partition("=")
    if not separator or NAME.fullmatch(name) is None or "\x00" in value:
        raise ReuseError(f"{label} must be NAME=VALUE")
    return name, value


def canonical_run(run_root: Path, source_root: Path) -> tuple[Path, Path]:
    run = run_root.resolve(strict=True)
    source = source_root.resolve(strict=True)
    if run != run_root or source != source_root or source.parent != run:
        raise ReuseError("run and source roots must be canonical and source must be <run>/source")
    if not run.name.startswith("run.") or run.parent.name != "runs":
        raise ReuseError("run root does not have the qualification run layout")
    return run, source


def normalize(value: str, run: Path) -> str:
    if RUN_ROOT_TOKEN in value:
        raise ReuseError("key input contains the reserved run-root token")
    return value.replace(str(run), RUN_ROOT_TOKEN)


def render(template: str, run: Path) -> str:
    return template.replace(RUN_ROOT_TOKEN, str(run))


# ── key ──────────────────────────────────────────────────────────────────────


def key_command(arguments: argparse.Namespace) -> int:
    run, _source = canonical_run(arguments.run_root, arguments.source_root)
    inherited = None
    source_digests = {}
    admission_path = os.environ.get("MACSCOPE_RETAINED_TOOLCHAIN_ADMISSION")
    if admission_path:
        helper_path = Path(__file__).with_name("retained_toolchain_admission.py")
        spec = importlib.util.spec_from_file_location("bootstrap_retained_tools", helper_path)
        helper = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(helper)
        inherited = json.loads(Path(admission_path).read_text())
        helper.revalidate(inherited)
        if inherited.get("source") != str(_source):
            raise ReuseError("retained toolchain admission source changed")
        source_digests = {r["path"]: r["sha256"] for r in
                          json.loads((_source / "SOURCE_FILES.json").read_text())["files"]}
    bindings: dict[str, str] = {}
    for raw in arguments.binding:
        name, value = named_value(raw, "binding")
        if name in bindings:
            raise ReuseError(f"duplicate binding: {name}")
        bindings[name] = normalize(value, run)
    files: dict[str, dict[str, object]] = {}
    for raw in arguments.hash_file:
        name, value = named_value(raw, "hash file")
        if name in files:
            raise ReuseError(f"duplicate hashed file: {name}")
        path = Path(value)
        if not path.is_absolute():
            raise ReuseError(f"hashed file {name} must be absolute")
        record: dict[str, object] = {"path": normalize(str(path), run)}
        if inherited is not None:
            try:
                relative = path.relative_to(_source).as_posix()
                record["sha256"] = source_digests[relative]
            except (ValueError, KeyError) as error:
                raise ReuseError("bootstrap key requests an unadmitted source digest") from error
        elif path.is_file():
            record["sha256"] = sha256_file(path)
        else:
            record["absent"] = True
        files[name] = record
    # Run-owned descriptors name their run root; bind their run-relative bytes.
    for raw in arguments.normalized_file:
        name, value = named_value(raw, "normalized file")
        if name in files:
            raise ReuseError(f"duplicate hashed file: {name}")
        path = Path(value)
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise ReuseError(f"normalized file {name} is unreadable") from error
        files[name] = {
            "normalized_sha256": sha256_bytes(normalize(text, run).encode("utf-8")),
            "path": normalize(str(path), run),
        }
    tools: dict[str, str] = {}
    for raw in arguments.tool_version:
        name, value = named_value(raw, "tool version")
        if inherited is not None:
            prior = inherited["prior_bootstrap"]
            if name != "xcodegen" or files.get(name, {}).get("sha256") != prior["files"][name]["sha256"]:
                raise ReuseError("bootstrap tool differs from retained canonical tool")
            tools[name] = prior["tool_versions"][name]
            continue
        try:
            completed = subprocess.run(
                [value, "version"], check=False, capture_output=True, timeout=60
            )
            observed = f"{completed.returncode}:{completed.stdout.decode('utf-8', 'replace').strip()}"
        except OSError as error:
            observed = f"unavailable:{error.__class__.__name__}"
        tools[name] = normalize(observed, run)
    environment = {
        name: normalize(value, run)
        for name, value in sorted(os.environ.items())
        if any(name.startswith(prefix) for prefix in arguments.environment_prefix)
        and name not in arguments.environment_exclude
    }
    which = {}
    for name in arguments.which:
        resolved = shutil.which(name)
        if inherited is not None:
            previous = inherited["prior_bootstrap"]["which"].get(name)
            if not previous or previous.get("path") != resolved:
                raise ReuseError("bootstrap tool lookup differs from admitted consumer")
            which[name] = previous
        else:
            which[name] = (
                {"path": resolved, "sha256": sha256_file(Path(resolved))} if resolved else {"absent": True}
            )
    system_version = Path("/System/Library/CoreServices/SystemVersion.plist")
    inputs = {
        "bindings": bindings,
        "environment": environment,
        "files": files,
        "python": {"executable": sys.executable, "version": sys.version},
        "schema_version": SCHEMA_VERSION,
        "system": {
            "machine": platform.machine(),
            "system_version_sha256": (inherited["inherited_system_version_sha256"] if inherited is not None
                                      else sha256_file(system_version) if system_version.is_file() else None),
        },
        "tool_versions": tools,
        "which": which,
    }
    if inherited is not None:
        helper.revalidate(inherited)
    payload = canonical_json(inputs)
    if arguments.output.exists() or arguments.output.is_symlink():
        raise ReuseError("bootstrap key-input output already exists")
    descriptor = os.open(
        arguments.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600
    )
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(payload)
    print(sha256_bytes(payload))
    return 0


# ── shared validation ────────────────────────────────────────────────────────


def load_key_inputs(path: Path, key: str) -> dict[str, Any]:
    if HEX64.fullmatch(key) is None:
        raise ReuseError("bootstrap key is malformed")
    try:
        value = read_canonical_json(path, "bootstrap key inputs")
    except NotReusableError as error:
        raise ReuseError(str(error)) from error
    if sha256_bytes(path.read_bytes()) != key or value.get("schema_version") != SCHEMA_VERSION:
        raise ReuseError("bootstrap key does not match its key inputs")
    return value


def store_paths(root: Path, key: str) -> dict[str, Path]:
    if not root.is_absolute():
        raise ReuseError("verification cache root must be absolute")
    base = root.resolve(strict=True) / "bootstraps" / f"v{SCHEMA_VERSION}"
    return {
        "base": base,
        "entry": base / "entries" / key,
        "lock": base / "locks" / f"{key}.lock",
        "quarantine": base / "quarantine",
        "temporary": base / "tmp",
    }


def project_manifest(project: Path) -> list[dict[str, object]]:
    records: list[dict[str, object]] = []
    for path in sorted([project, *project.rglob("*")], key=lambda item: os.fsencode(str(item))):
        metadata = path.lstat()
        relative = "." if path == project else path.relative_to(project).as_posix()
        if stat.S_ISDIR(metadata.st_mode):
            records.append({"kind": "directory", "mode": stat.S_IMODE(metadata.st_mode), "path": relative})
        elif stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1:
            records.append(
                {
                    "kind": "file",
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "path": relative,
                    "sha256": sha256_file(path),
                    "size": metadata.st_size,
                }
            )
        else:
            raise NotReusableError(f"generated project member is not an ordinary single-link entry: {relative}")
    return records


def content_manifest(records: list[dict[str, object]]) -> list[dict[str, object]]:
    return [{name: value for name, value in record.items() if name != "mode"} for record in records]


def _freshness_module():
    path = Path(__file__).resolve().parents[1] / "project_freshness.py"
    spec = importlib.util.spec_from_file_location("macscope_project_freshness", path)
    if spec is None or spec.loader is None:
        raise NotReusableError("project_freshness.py is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_freshness_stamp(source: Path, project: Path) -> None:
    """Re-run the canonical freshness comparison: the stamp must name the current inputs.

    Delegates to Scripts/project_freshness.py (the contract bootstrap records), which knows
    every label (file inputs inside and outside MacScope/, and the folder-source path list).
    A private re-implementation here only understood MacScope/ file labels and rejected the
    `MacScope/source-paths` label, so no qualifier run could reuse a bootstrap."""
    if project != source / PROJECT:
        raise NotReusableError("generated project is not at the source's MacScope.xcodeproj")
    errors = _freshness_module().validate_generated_project_freshness(source / "MacScope/project.yml")
    if errors:
        raise NotReusableError("project-generation freshness: " + "; ".join(errors))


def check_source_inclusion(project: Path) -> None:
    payload = (project / "project.xcproj").read_bytes()
    missing = [name for name in SOURCE_INCLUSION if name.encode("utf-8") not in payload]
    if missing:
        raise NotReusableError("generated project omits expected sources: " + ", ".join(missing))


def read_xcconfig(path: Path) -> tuple[bytes, int]:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
        raise NotReusableError("dependency-roots xcconfig must be one ordinary single-link file")
    if metadata.st_size <= 0 or metadata.st_size > MAX_XCCONFIG_BYTES:
        raise NotReusableError("dependency-roots xcconfig exceeds its bound")
    return path.read_bytes(), stat.S_IMODE(metadata.st_mode)


# ── record ───────────────────────────────────────────────────────────────────


def freeze(root: Path) -> None:
    for path in sorted([root, *root.rglob("*")], key=lambda item: len(item.parts), reverse=True):
        if not path.is_symlink():
            path.chmod(0o555 if path.is_dir() else 0o444)


def thaw_and_remove(root: Path) -> None:
    if not (root.exists() or root.is_symlink()):
        return
    for path in [root, *root.rglob("*")]:
        try:
            if not path.is_symlink():
                path.chmod(0o700 if path.is_dir() else 0o600)
        except OSError:
            pass
    shutil.rmtree(root, ignore_errors=True)


def clonefile_tree(source: Path, destination: Path) -> None:
    import ctypes
    import errno

    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    function = library.clonefile
    function.argtypes = (ctypes.c_char_p, ctypes.c_char_p, ctypes.c_uint32)
    function.restype = ctypes.c_int
    clone_nofollow, clone_noownercopy = 0x0001, 0x0002
    if function(os.fsencode(source), os.fsencode(destination), clone_nofollow | clone_noownercopy) != 0:
        code = ctypes.get_errno()
        if code in {errno.ENOTSUP, errno.EXDEV, errno.EOPNOTSUPP}:
            raise NotReusableError(f"clonefile unsupported: {os.strerror(code)}")
        raise OSError(code, os.strerror(code), str(destination))


def _publication_identity(metadata):
    return metadata.st_dev, metadata.st_ino


def _publication_snapshot(parent: int, name: str):
    """Read one anchored, bounded record; never follow a lock or owner link."""
    directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        metadata = os.fstat(directory)
        identity = _publication_identity(metadata)
        age = max(0.0, time.time() - metadata.st_mtime)
        try:
            owner_fd = os.open("owner", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,
                               dir_fd=directory)
        except FileNotFoundError:
            return identity, None, None, age, "missing"
        try:
            owner_stat = os.fstat(owner_fd)
            if not stat.S_ISREG(owner_stat.st_mode) or owner_stat.st_nlink != 1 or owner_stat.st_size > 4096:
                raise ValueError("owner is not a bounded ordinary file")
            payload = os.read(owner_fd, 4097)
            if len(payload) > 4096:
                raise ValueError("owner exceeds bound")
            owner_identity = _publication_identity(owner_stat)
        finally:
            os.close(owner_fd)
        text = payload.decode("ascii")
        if not text.endswith("\n"):
            raise ValueError("unterminated owner record")
        fields = {}
        for line in text[:-1].split("\n"):
            field, separator, value = line.partition("=")
            if (not separator or field not in {"pid", "hostname", "start", "token", "key"}
                    or field in fields or not value or any(ord(c) < 32 or ord(c) > 126 for c in value)):
                raise ValueError("malformed owner")
            fields[field] = value
        if (set(fields) != {"pid", "hostname", "start", "token", "key"}
                or re.fullmatch(r"[0-9]+", fields["pid"]) is None
                or not 0 < int(fields["pid"]) <= 2147483647
                or len(fields["hostname"]) > 255 or any(c.isspace() for c in fields["hostname"])
                or len(fields["start"]) > 128 or " ".join(fields["start"].split()) != fields["start"]
                or HEX64.fullmatch(fields["token"]) is None
                or HEX64.fullmatch(fields["key"]) is None or name != fields["key"] + ".lock"):
            raise ValueError("incomplete or malformed owner")
        return identity, (owner_identity, payload), fields, age, "complete"
    finally:
        os.close(directory)


def _publication_verdict(owner):
    if owner["hostname"] != socket.gethostname():
        return False, "foreign host"
    try:
        os.kill(int(owner["pid"]), 0)
    except ProcessLookupError:
        return True, "not running; stale tmp directory may exist (left untouched)"
    except PermissionError:
        return False, "not running but not reclaimable (permission denied; liveness unknown)"
    except OSError:
        return False, "not running but not reclaimable (probe failed; liveness unknown)"
    return False, "running"


def _publication_description(snapshot):
    _identity, _record, owner, age, state = snapshot
    if state == "missing":
        return f"no owner record, age={int(age)}s" + ("; stale by age (manual retirement only)" if age > 60 else "; owner record not written yet")
    _dead, verdict = _publication_verdict(owner)
    return f"pid={owner['pid']} host={owner['hostname'][:100]} start={owner['start'][:100]}; {verdict}"


def describe_publication_lock(lock: Path) -> str:
    """Return a single bounded diagnostic; no writes, removals or printing."""
    try:
        parent = os.open(lock.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            summary = _publication_description(_publication_snapshot(parent, lock.name))
        finally:
            os.close(parent)
    except (OSError, ValueError, UnicodeError):
        summary = "unreadable"
    return " ".join(summary.split())[:400]


def _publication_busy(lock: Path, key: str) -> None:
    summary = describe_publication_lock(lock)
    print(f"publication of {key} is busy; not publishing; owner: {summary}")
    if "stale by age (manual retirement only)" in summary:
        print("manual retirement command: mv " + shlex.quote(str(lock)) + " "
              + shlex.quote(str(lock) + ".retired-manual"))


def _publication_start() -> str:
    try:
        result = subprocess.run(["/bin/ps", "-p", str(os.getpid()), "-o", "lstart="],
                                capture_output=True, text=True, timeout=5,
                                env={**os.environ, "LC_ALL": "C", "TZ": "UTC"}, check=False)
        value = " ".join(result.stdout.split())
        if result.returncode == 0 and value and len(value) <= 128 and value.isascii() and value.isprintable():
            return value
    except (OSError, subprocess.SubprocessError, UnicodeError):
        pass
    return "unknown"


def _write_publication_owner(parent: int, lock: Path, key: str, token: str) -> None:
    directory = os.open(lock.name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    created = None
    identity = _publication_identity(os.fstat(directory))
    try:
        descriptor = os.open("owner", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=directory)
        created = _publication_identity(os.fstat(descriptor))
        with os.fdopen(descriptor, "w", encoding="ascii") as stream:
            stream.write(f"pid={os.getpid()}\nhostname={socket.gethostname()}\n"
                         f"start={_publication_start()}\ntoken={token}\nkey={key}\n")
    except BaseException:
        # A partial write cannot be parsed for its token. Only the inode created
        # above may be removed, anchored to the directory opened after our mkdir.
        if created is not None:
            try:
                if _publication_identity(os.stat("owner", dir_fd=directory, follow_symlinks=False)) == created:
                    os.unlink("owner", dir_fd=directory)
            except OSError:
                pass
        try:
            if _publication_identity(os.stat(lock.name, dir_fd=parent, follow_symlinks=False)) == identity:
                os.rmdir(lock.name, dir_fd=parent)
        except OSError:
            pass
        raise
    finally:
        os.close(directory)


# Retain the acquired directory descriptor until release. Other helper users
# cannot retire that inode while it is held; unrelated keys never contend.
_PUBLICATION_LOCKS: dict[tuple[str, str], tuple[int, int]] = {}
# Cooperating publishers are excluded; observed replacements are detected and refused.
# Replacement after the final identity check is outside this private single-user trust boundary.
def _publication_directory(parent: int, name: str) -> int | None:
    descriptor = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(descriptor)
        return None
    return descriptor


def acquire_publication_lock(lock: Path, key: str) -> str | None:
    """Acquire, or retire one strictly proven dead owner and retry once."""
    if HEX64.fullmatch(key) is None or lock.name != key + ".lock":
        raise ReuseError("publication lock name does not match its key")
    token = secrets.token_hex(32)
    parent = os.open(lock.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    directory = None
    retained = False
    try:
        try:
            os.mkdir(lock.name, mode=0o700, dir_fd=parent)
        except FileExistsError:
            try:
                directory = _publication_directory(parent, lock.name)
                if directory is None:
                    _publication_busy(lock, key)
                    return None
                snapshot = _publication_snapshot(parent, lock.name)
                owner = snapshot[2]
                dead = owner is not None and _publication_verdict(owner)[0]
                # The observed inode must be the one whose advisory lock we
                # hold, with the same owner inode and bytes at the final read.
                if (dead and snapshot[0] == _publication_identity(os.fstat(directory))
                        and _publication_snapshot(parent, lock.name)[:3] == snapshot[:3]):
                    retired = lock.name + ".retired-" + secrets.token_hex(32)
                    try:
                        os.stat(retired, dir_fd=parent, follow_symlinks=False)
                    except FileNotFoundError:
                        pass
                    else:
                        _publication_busy(lock, key)
                        return None
                    os.rename(lock.name, retired, src_dir_fd=parent, dst_dir_fd=parent)
                    print(f"reclaimed stale publication lock for {key}: owner pid {owner['pid']} "
                          f"not running (moved to {retired})")
                    print("stale tmp directory may exist for the dead owner pid (left untouched)")
                    os.close(directory)
                    directory = None
                    try:
                        os.mkdir(lock.name, mode=0o700, dir_fd=parent)
                    except FileExistsError:
                        _publication_busy(lock, key)
                        return None
                else:
                    _publication_busy(lock, key)
                    return None
            except (OSError, ValueError, UnicodeError):
                _publication_busy(lock, key)
                return None
        created_identity = _publication_identity(os.stat(lock.name, dir_fd=parent, follow_symlinks=False))
        try:
            directory = _publication_directory(parent, lock.name)
            if directory is None:
                raise ReuseError("publication lock directory coordination unavailable")
        except BaseException:
            try:
                if _publication_identity(os.stat(lock.name, dir_fd=parent, follow_symlinks=False)) == created_identity:
                    os.rmdir(lock.name, dir_fd=parent)
            except OSError:
                pass
            raise
        _write_publication_owner(parent, lock, key, token)
        _PUBLICATION_LOCKS[(str(lock), token)] = parent, directory
        retained = True
        return token
    finally:
        if not retained:
            if directory is not None:
                os.close(directory)
            os.close(parent)


def release_publication_lock(lock: Path, token: str) -> None:
    """Only remove our retained directory and its still-matching owner token."""
    descriptors = _PUBLICATION_LOCKS.pop((str(lock), token), None)
    if descriptors is None:
        return
    parent, directory = descriptors
    try:
        snapshot = _publication_snapshot(parent, lock.name)
        if (snapshot[0] != _publication_identity(os.fstat(directory))
                or snapshot[2] is None or snapshot[2]["token"] != token
                or int(snapshot[2]["pid"]) != os.getpid()
                or snapshot[2]["hostname"] != socket.gethostname()):
            return
        if _publication_snapshot(parent, lock.name)[:3] != snapshot[:3]:
            return
        os.unlink("owner", dir_fd=directory)
        if _publication_identity(os.stat(lock.name, dir_fd=parent, follow_symlinks=False)) == snapshot[0]:
            os.rmdir(lock.name, dir_fd=parent)
    except (OSError, ValueError, UnicodeError):
        return
    finally:
        os.close(directory)
        os.close(parent)


def record_command(arguments: argparse.Namespace) -> int:
    run, source = canonical_run(arguments.run_root, arguments.source_root)
    key_inputs = load_key_inputs(arguments.key_inputs, arguments.key)
    restore = _restore_module()
    project = source / PROJECT
    identity = restore.generated_project_identity(source, run / "private-machokit-input")
    manifest = project_manifest(project)
    run_bytes = os.fsencode(str(run))
    for record in manifest:
        if record["kind"] == "file" and run_bytes in (project / str(record["path"])).read_bytes():
            raise NotReusableError(f"generated project embeds the run root: {record['path']}")
    check_freshness_stamp(source, project)
    check_source_inclusion(project)
    xcconfig, xcconfig_mode = read_xcconfig(source / XCCONFIG)
    try:
        xcconfig_text = xcconfig.decode("utf-8")
    except UnicodeDecodeError as error:
        raise NotReusableError("dependency-roots xcconfig is not UTF-8") from error
    link = source / LOCAL_PACKAGES
    if not link.is_symlink():
        raise NotReusableError("LocalPackages is not the generated link")
    value = {
        "key": arguments.key,
        "key_inputs": key_inputs,
        "local_packages_target": normalize(os.readlink(link), run),
        "project_identity": identity,
        "project_manifest": manifest,
        "schema_version": SCHEMA_VERSION,
        "verification": arguments.verification,
        "verified_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "xcconfig_mode": xcconfig_mode,
        "xcconfig_template": normalize(xcconfig_text, run),
    }
    paths = store_paths(arguments.verification_root, arguments.key)
    if paths["entry"].exists():
        print(f"already published {paths['entry'].name}")
        return 0
    for name in ("temporary", "quarantine"):
        paths[name].mkdir(mode=0o700, parents=True, exist_ok=True)
    paths["entry"].parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    paths["lock"].parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    owner_token = acquire_publication_lock(paths["lock"], arguments.key)
    if owner_token is None:
        return 0
    temporary = paths["temporary"] / f"{arguments.key}.{os.getpid()}"
    temporary_created = False
    try:
        temporary.mkdir(mode=0o700)
        temporary_created = True
        clonefile_tree(project, temporary / "project")
        if content_manifest(project_manifest(temporary / "project")) != content_manifest(manifest):
            raise NotReusableError("stored project copy differs from the verified project")
        receipt = temporary / "RECEIPT.json"
        receipt.write_bytes(canonical_json(value))
        freeze(temporary)
        # Moving a directory between parents rewrites its "..": keep only the
        # entry root writable for the rename, then close it.
        temporary.chmod(0o700)
        os.rename(temporary, paths["entry"])
        paths["entry"].chmod(0o555)
    except BaseException:
        if temporary_created:
            thaw_and_remove(temporary)
        raise
    finally:
        release_publication_lock(paths["lock"], owner_token)
    print(sha256_file(paths["entry"] / "RECEIPT.json"))
    return 0


# ── reuse ────────────────────────────────────────────────────────────────────


def load_entry(arguments: argparse.Namespace) -> tuple[dict[str, Any], Path, str]:
    key_inputs = load_key_inputs(arguments.key_inputs, arguments.key)
    paths = store_paths(arguments.verification_root, arguments.key)
    entry = paths["entry"]
    if not entry.exists() and not entry.is_symlink():
        raise NotReusableError("no verified bootstrap for this key")
    if entry.is_symlink() or not entry.is_dir():
        raise NotReusableError("stored bootstrap entry is indirect")
    receipt_path = entry / "RECEIPT.json"
    value = read_canonical_json(receipt_path, "bootstrap receipt")
    if set(value) != RECEIPT_FIELDS or value.get("schema_version") != SCHEMA_VERSION:
        raise NotReusableError("stored bootstrap receipt schema is unsupported")
    if value.get("key") != arguments.key or sha256_bytes(canonical_json(value["key_inputs"])) != arguments.key:
        raise NotReusableError("stored bootstrap receipt key differs")
    if value["key_inputs"] != key_inputs:
        raise NotReusableError("stored bootstrap key inputs differ")
    if HEX64.fullmatch(str(value.get("project_identity"))) is None:
        raise NotReusableError("stored project identity is malformed")
    for path in [entry, receipt_path, *(entry / "project").rglob("*")]:
        if path.lstat().st_mode & 0o222:
            raise NotReusableError(f"stored bootstrap entry is writable: {path.name}")
    return value, entry, sha256_file(receipt_path)


def quarantine(entry: Path, arguments: argparse.Namespace, reason: str) -> None:
    paths = store_paths(arguments.verification_root, arguments.key)
    paths["quarantine"].mkdir(mode=0o700, parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    destination = paths["quarantine"] / f"{entry.name}.{stamp}"
    try:
        # Moving a directory between parents rewrites its "..".
        entry.chmod(0o700)
        os.rename(entry, destination)
        destination.chmod(0o555)
    except OSError:
        thaw_and_remove(entry)
        raise NotReusableError(f"{reason}; removed {entry.name}")
    raise NotReusableError(f"{reason}; quarantined to {destination}")


def reuse_check_command(arguments: argparse.Namespace) -> int:
    try:
        _value, _entry, digest = load_entry(arguments)
    except NotReusableError as error:
        print(str(error))
        return NOT_REUSABLE_STATUS
    print(digest)
    return 0


def reuse_command(arguments: argparse.Namespace) -> int:
    run, source = canonical_run(arguments.run_root, arguments.source_root)
    project = source / PROJECT
    xcconfig = source / XCCONFIG
    link = source / LOCAL_PACKAGES
    created: list[Path] = []
    try:
        value, entry, digest = load_entry(arguments)
        stored = entry / "project"
        manifest = value["project_manifest"]
        restore = _restore_module()
        # Full byte check of the stored project (a few hundred KiB).
        if (
            content_manifest(project_manifest(stored)) != content_manifest(manifest)
            or restore._generated_project_identity(stored, require_complete=True)
            != value["project_identity"]
        ):
            quarantine(entry, arguments, "stored bootstrap project bytes differ from its receipt")
        for path in (project, xcconfig, link):
            if path.exists() or path.is_symlink():
                raise ReuseError(f"run source already contains generated output: {path.name}")
        clonefile_tree(stored, project)
        created.append(project)
        modes = {str(record["path"]): int(record["mode"]) for record in manifest}
        for path in sorted([project, *project.rglob("*")], key=lambda item: len(item.parts), reverse=True):
            relative = "." if path == project else path.relative_to(project).as_posix()
            if relative not in modes:
                raise NotReusableError(f"cloned project has an unrecorded member: {relative}")
            path.chmod(modes[relative])
        if project_manifest(project) != manifest:
            raise NotReusableError("cloned project differs from the verified project")
        if restore.generated_project_identity(source, run / "private-machokit-input") != value["project_identity"]:
            raise NotReusableError("cloned project identity differs from the verified project")
        payload = render(value["xcconfig_template"], run).encode("utf-8")
        mode = int(value["xcconfig_mode"])
        descriptor = os.open(
            xcconfig, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), mode
        )
        created.append(xcconfig)
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), mode)
            stream.write(payload)
        if read_xcconfig(xcconfig) != (payload, mode):
            raise NotReusableError("written dependency-roots xcconfig differs")
        target = render(value["local_packages_target"], run)
        if not Path(target).is_dir():
            raise NotReusableError("LocalPackages target is missing for this run")
        os.symlink(target, link, target_is_directory=True)
        created.append(link)
        check_freshness_stamp(source, project)
        check_source_inclusion(project)
    except NotReusableError as error:
        remove_created(created)
        print(str(error))
        return NOT_REUSABLE_STATUS
    except BaseException:
        remove_created(created)
        raise
    print(digest)
    return 0


def remove_created(created: list[Path]) -> None:
    for path in reversed(created):
        if path.is_symlink() or path.is_file():
            path.unlink(missing_ok=True)
        elif path.is_dir():
            thaw_and_remove(path)


def parser() -> argparse.ArgumentParser:
    value = argparse.ArgumentParser(description=__doc__)
    commands = value.add_subparsers(dest="command", required=True)

    key = commands.add_parser("key")
    key.add_argument("--run-root", type=Path, required=True)
    key.add_argument("--source-root", type=Path, required=True)
    key.add_argument("--binding", action="append", default=[])
    key.add_argument("--hash-file", action="append", default=[])
    key.add_argument("--tool-version", action="append", default=[])
    key.add_argument("--environment-prefix", action="append", default=[])
    key.add_argument("--environment-exclude", action="append", default=[])
    key.add_argument("--normalized-file", action="append", default=[])
    key.add_argument("--which", action="append", default=[])
    key.add_argument("--output", type=Path, required=True)
    key.set_defaults(action=key_command)

    for name, action in (
        ("reuse-check", reuse_check_command),
        ("reuse", reuse_command),
        ("record", record_command),
    ):
        command = commands.add_parser(name)
        command.add_argument("--verification-root", type=Path, required=True)
        command.add_argument("--key", required=True)
        command.add_argument("--key-inputs", type=Path, required=True)
        if name != "reuse-check":
            command.add_argument("--run-root", type=Path, required=True)
            command.add_argument("--source-root", type=Path, required=True)
        if name == "record":
            command.add_argument("--verification", required=True)
        command.set_defaults(action=action)
    return value


def main() -> int:
    arguments = parser().parse_args()
    try:
        return arguments.action(arguments)
    except NotReusableError as error:
        print(str(error))
        return NOT_REUSABLE_STATUS
    except (ReuseError, OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
