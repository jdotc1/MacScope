#!/usr/bin/env python3
"""Owned-process host for one selector against an existing xctestrun. No build path."""
from __future__ import annotations

import argparse
import errno
from datetime import datetime, timezone
from contextlib import contextmanager
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess
import sys
import time
import uuid


SCRIPTS = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS / "lib"))
from work_root import work_root as macscope_work_root  # noqa: E402
POST_KILL_DRAIN_SECONDS = 0.25


def named_environment(developer_dir: Path, assignments: list[str]) -> dict[str, str]:
    """No ambient environment is copied, including toolchain or receipt overrides."""
    environment = {"DEVELOPER_DIR": str(developer_dir)}
    for assignment in assignments:
        name, separator, value = assignment.partition("=")
        if not separator or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError("environment entries must be NAME=VALUE")
        if name in environment:
            raise ValueError(f"duplicate environment name: {name}")
        environment[name] = value
    return environment


def selector_command(xctestrun: Path, selector: str, result: Path,
                     test_execution_allowance: int | None = None) -> list[str]:
    if not re.fullmatch(r"(?:CoreTests|Phase2Tests)/[A-Za-z0-9_]+(?:/[A-Za-z0-9_]+)?", selector):
        raise ValueError("provide exactly one CoreTests or Phase2Tests class/method selector")
    command = ["/usr/bin/nice", "-n", "5", "/usr/bin/xcodebuild",
            "test-without-building", "-xctestrun", str(xctestrun),
            "-destination", "platform=macOS,arch=arm64",
            f"-only-testing:{selector}", "-resultBundlePath", str(result),
            "-parallel-testing-enabled", "NO"]
    if test_execution_allowance is not None:
        if isinstance(test_execution_allowance, bool) or not isinstance(test_execution_allowance, int) or test_execution_allowance <= 0:
            raise ValueError("XCTest execution allowance must be a positive integer")
        command += ["-test-timeouts-enabled", "YES",
                    "-default-test-execution-time-allowance", str(test_execution_allowance),
                    "-maximum-test-execution-time-allowance", str(test_execution_allowance)]
    return command


def system_default_developer_dir() -> str:
    """Return the system default Xcode (xcode-select), the only one installed."""
    return subprocess.run(["/usr/bin/xcode-select", "-p"], capture_output=True,
                          text=True, check=False).stdout.strip()


def load_profile(path: Path, name: str) -> dict:
    """Read source configuration only; pending owner decisions remain explicit."""
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("schema_version") != 1 or not isinstance(document.get("profiles"), dict):
        raise ValueError("unsupported selector profile schema")
    if name not in document["profiles"]:
        raise ValueError(f"unknown selector profile: {name}")
    if not isinstance(document["profiles"][name], dict):
        raise ValueError("selector profile must be an object")
    profile = dict(document["profiles"][name])
    for field in ("work_root", "retained_root", "developer_dir"):
        if isinstance(profile.get(field), str):
            profile[field] = (profile[field].replace("{work_root}", str(macscope_work_root()))
                              .replace("{home}", str(Path.home())))
            if "{system_xcode}" in profile[field]:
                # The system default Xcode (xcode-select), the only one installed.
                profile[field] = profile[field].replace("{system_xcode}", system_default_developer_dir())
    for field in ("work_root", "retained_root", "developer_dir"):
        if not isinstance(profile.get(field), str) or not Path(profile[field]).is_absolute():
            raise ValueError(f"profile {field} must be an absolute path")
    pattern = profile.get("xctestrun_pattern")
    if (not isinstance(pattern, str) or Path(pattern).is_absolute()
            or ".." in Path(pattern).parts or "**" in pattern
            or not pattern.endswith(".xctestrun")):
        raise ValueError("profile requires a confined nonrecursive xctestrun pattern")
    if profile.get("result_path") != "{run_root}/result.xcresult":
        raise ValueError("profile result path must stay inside its run root")
    if not isinstance(profile.get("environment"), dict) or not all(
            isinstance(key, str) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
            and isinstance(value, str)
            for key, value in profile["environment"].items()):
        raise ValueError("profile environment must contain explicit string assignments")
    named_environment(Path(profile["developer_dir"]),
                      [f"{key}={value}" for key, value in profile["environment"].items()])
    for field in ("timeout", "grace"):
        value = profile.get(field)
        if value is not None and (isinstance(value, bool) or not isinstance(value, (int, float))
                                  or not math.isfinite(value) or value <= 0):
            raise ValueError(f"profile {field} must be positive or explicitly pending")
    allowance = profile.get("test_execution_allowance")
    if allowance is not None and (isinstance(allowance, bool) or not isinstance(allowance, int) or allowance <= 0):
        raise ValueError("profile XCTest allowance must be a positive integer")
    if profile.get("selector") is not None:
        if not isinstance(profile["selector"], str):
            raise ValueError("profile selector must be a string or explicitly pending")
        selector_command(Path("/retained/profile.xctestrun"), profile["selector"], Path("/run/result.xcresult"))
    profile["name"] = name
    return profile


def resolve_profile(profile: dict, run_root: Path, candidate_sha: str | None = None) -> dict:
    # Refuse incomplete decisions before looking at any retained build product.
    pending = [field for field in ("selector", "timeout", "grace") if profile.get(field) is None]
    if pending:
        raise ValueError("profile requires Plan decisions: " + ", ".join(pending))
    environment = []
    for key, value in profile["environment"].items():
        if "{candidate_sha}" in value and candidate_sha is None:
            raise ValueError("profile requires a candidate SHA for environment binding")
        try:
            expanded = value.format(run_root=run_root, candidate_sha=candidate_sha)
        except (KeyError, ValueError) as error:
            raise ValueError("unsupported profile environment placeholder") from error
        environment.append(f"{key}={expanded}")
    root = Path(profile["retained_root"])
    matches = list(root.glob(profile["xctestrun_pattern"]))
    if len(matches) != 1 or not matches[0].is_file():
        raise ValueError("profile pattern must select exactly one existing retained xctestrun")
    if not matches[0].resolve().is_relative_to(root.resolve()):
        raise ValueError("profile xctestrun escaped its retained root")
    return dict(work_root=Path(profile["work_root"]), retained_root=root,
                developer_dir=Path(profile["developer_dir"]), xctestrun=matches[0],
                selector=profile["selector"], timeout=profile["timeout"], grace=profile["grace"],
                env=environment, test_execution_allowance=profile.get("test_execution_allowance"),
                result=Path(profile["result_path"].format(run_root=run_root)))


@contextmanager
def heavy_gate(lock: Path, work_root: Path, run_root: Path, candidate: str, timeout: int):
    """Reuse dev_loop's helper and descriptor lifetime (its one-slot exclusive mode)."""
    specification = importlib.util.spec_from_file_location(
        "child_host_heavy_gate", SCRIPTS / "qualification/heavy_gate_lock.py")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    lock.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(lock, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o644)
    arguments = argparse.Namespace(
        lock=lock, fd=descriptor, pid=os.getpid(), work_root=str(work_root),
        run_root=str(run_root), integration_ref=candidate, mode="child-selector-host",
        timeout=timeout, shared=False, slot_fds=[])
    try:
        status = module.acquire_command(arguments)
        if status:
            raise RuntimeError(f"heavy-gate acquisition failed: {status}")
        yield
    finally:
        module.release_command(arguments)
        os.close(descriptor)


def signal_owned_group(process, sent_signal: int, record: dict, save) -> None:
    """An attempted signal is evidence only of its syscall outcome, never exit."""
    if process.returncode is not None:
        raise RuntimeError("refusing to signal a reaped child group")
    name = signal.Signals(sent_signal).name
    attempt = {"signal": name, "pgid": process.pid,
               "monotonic": time.monotonic(), "outcome": "attempting", "errno": None}
    record["signals_sent"].append(name)
    record["signal_attempts"].append(attempt)
    save()
    try:
        os.killpg(process.pid, sent_signal)
    except OSError as error:
        attempt.update(outcome="unsignalable", errno=error.errno, error=str(error))
        save()
        if error.errno not in (errno.EPERM, errno.ESRCH):
            raise
    else:
        attempt["outcome"] = "sent"
        save()


def wait_after_final_signal(process, record: dict, save, timeout: float) -> int:
    """Bound normal completion; quarantine retains this parent and its gate."""
    try:
        return process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        record.update(owner_quarantined=True, owner_state="owner_quarantined",
                      quarantine_monotonic=time.monotonic())
        save()
        print(f"OWNER QUARANTINED pid={process.pid} pgid={process.pid}: "
              "exit unconfirmed; retaining sole waiter and heavy gate; no more group signals",
              file=sys.stderr, flush=True)
        while True:
            try:
                status = process.wait()
                record["owner_state"] = "exited_after_quarantine"
                save()
                return status
            except KeyboardInterrupt:
                # Interrupting this intentional quarantine cannot safely abandon
                # a live child or release its gate. No further signal is issued.
                record["quarantine_interrupts"] = record.get("quarantine_interrupts", 0) + 1
                save()
                print(f"OWNER QUARANTINED pid={process.pid}: exit still unconfirmed",
                      file=sys.stderr, flush=True)


def supervise(command: list[str], *, environment: dict[str, str], work_root: Path,
              run_root: Path, candidate: str, selector: str, result: Path,
              timeout: float, grace: float, profile_evidence: dict | None = None) -> dict:
    """Only this parent waits its Popen; readers never reap or signal."""
    if not all(math.isfinite(value) and value > 0 for value in (timeout, grace)):
        raise ValueError("timeout and grace must be finite positive seconds")
    run_root.mkdir(parents=True, exist_ok=False)
    record = {"nonce": uuid.uuid4().hex, "candidate_sha": candidate,
              "selector": selector, "parent_pid": os.getpid(), "parent_pgid": os.getpgrp(),
              "xcresult_path": str(result), "command": command,
              "environment_names": sorted(environment),
              "phases": dict.fromkeys(("spawn", "first-output", "test-start", "test-end", "exit")),
              "timed_out": False, "returncode": None, "exit_code": None,
              "signal": None, "signals_sent": [], "signal_attempts": [], "output_complete": True,
              "unresolved_output_channels": [], "owner_quarantined": False,
              "owner_state": "not_spawned", "final_signal_boundary": False,
              "profile": profile_evidence, "host_timeout_seconds": timeout,
              "termination_grace_seconds": grace}
    record_path = run_root / "run.json"

    def save():
        temporary = run_root / "run.json.tmp"
        temporary.write_text(json.dumps(record, indent=2) + "\n", encoding="utf-8")
        os.replace(temporary, record_path)

    def phase(name):
        if record["phases"][name] is None:
            record["phases"][name] = time.monotonic()
            save()

    record["parent_start_utc"] = datetime.now(timezone.utc).isoformat()
    record["parent_start_monotonic"] = time.monotonic()
    save()  # nonce and parent identity exist before spawning.
    process = None
    with (run_root / "stdout.log").open("wb") as stdout, (run_root / "stderr.log").open("wb") as stderr:
        try:
            process = subprocess.Popen(command, cwd=work_root, env=environment,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                       start_new_session=True)
            # start_new_session makes the child session/group leader. Record before
            # consuming any output; never discover targets by process-name search.
            record.update(pid=process.pid, pgid=process.pid, owner_state="running")
            phase("spawn")
            deadline = record["phases"]["spawn"] + timeout
            kill_deadline = None
            drain_deadline = None
            buffers = {"stdout": b"", "stderr": b""}
            with selectors.DefaultSelector() as reader:
                for name, pipe, output in (("stdout", process.stdout, stdout),
                                           ("stderr", process.stderr, stderr)):
                    os.set_blocking(pipe.fileno(), False)
                    reader.register(pipe, selectors.EVENT_READ, (name, output))
                # Never poll/reap while another group signal remains possible.
                # Even an exited leader stays a zombie, reserving its PID/PGID.
                while reader.get_map():
                    now = time.monotonic()
                    if now >= deadline and not record["timed_out"]:
                        record["timed_out"] = True
                        signal_owned_group(process, signal.SIGTERM, record, save)
                        kill_deadline = now + grace
                    if kill_deadline is not None and now >= kill_deadline:
                        signal_owned_group(process, signal.SIGKILL, record, save)
                        kill_deadline = None
                        drain_deadline = now + POST_KILL_DRAIN_SECONDS
                    if drain_deadline is not None and now >= drain_deadline:
                        record["output_complete"] = False
                        record["unresolved_output_channels"] = [
                            key.data[0] for key in reader.get_map().values()]
                        save()
                        for key in list(reader.get_map().values()):
                            reader.unregister(key.fileobj)
                            key.fileobj.close()
                        break
                    for key, _ in reader.select(0.05):
                        name, output = key.data
                        chunk = os.read(key.fileobj.fileno(), 65536)
                        if not chunk:
                            reader.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        phase("first-output")
                        output.write(chunk)
                        output.flush()
                        buffers[name] += chunk
                        while b"\n" in buffers[name]:
                            line, buffers[name] = buffers[name].split(b"\n", 1)
                            text = line.decode("utf-8", errors="replace")
                            if re.match(r"Test (?:Suite|Case) .+ started", text):
                                phase("test-start")
                            if re.match(r"Test (?:Suite|Case) .+ (?:passed|failed|finished)", text):
                                record["phases"]["test-end"] = time.monotonic()
                                save()
                # Pipes are closed/drained; a child may have closed them before
                # exiting. A successful wait is the irreversible no-more-signals
                # boundary; TimeoutExpired has not reaped it, so signaling is safe.
                if "SIGKILL" not in record["signals_sent"]:
                    remaining = ((kill_deadline if record["timed_out"] else deadline)
                                 - time.monotonic())
                    try:
                        status = process.wait(timeout=max(0, remaining))
                    except subprocess.TimeoutExpired:
                        if not record["timed_out"]:
                            record["timed_out"] = True
                            signal_owned_group(process, signal.SIGTERM, record, save)
                            try:
                                status = process.wait(timeout=grace)
                            except subprocess.TimeoutExpired:
                                status = None
                        else:
                            status = None
                        if status is None:
                            signal_owned_group(process, signal.SIGKILL, record, save)
                            record["final_signal_boundary"] = True
                            save()
                            status = wait_after_final_signal(process, record, save, grace)
                else:
                    record["final_signal_boundary"] = True
                    save()
                    status = wait_after_final_signal(process, record, save, grace)
            if not record["owner_quarantined"]:
                record["owner_state"] = "exited"
            record.update(returncode=status, exit_code=status if status >= 0 else None,
                          signal=-status if status < 0 else None)
            phase("exit")
            return record
        except BaseException as error:
            record["host_error"] = f"{type(error).__name__}: {error}"
            if process is not None and process.returncode is None:
                if not record["final_signal_boundary"]:
                    signal_owned_group(process, signal.SIGKILL, record, save)
                    record["final_signal_boundary"] = True
                    save()
                status = wait_after_final_signal(process, record, save, grace)
                record.update(returncode=status, exit_code=status if status >= 0 else None,
                              signal=-status if status < 0 else None)
                phase("exit")
            save()
            raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile")
    parser.add_argument("--profiles-file", type=Path, default=SCRIPTS / "child_selector_profiles.json")
    for name in ("work-root", "retained-root", "xctestrun", "developer-dir"):
        parser.add_argument(f"--{name}", type=Path)
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--candidate-sha", required=True)
    parser.add_argument("--selector")
    parser.add_argument("--env", action="append", default=[], metavar="NAME=VALUE")
    parser.add_argument("--timeout", type=float)
    parser.add_argument("--grace", type=float)
    parser.add_argument("--gate-timeout", type=int, default=1800)
    args = parser.parse_args()
    profile = None
    args.test_execution_allowance = None
    result = args.run_root / "result.xcresult"
    if args.profile:
        overrides = (args.work_root, args.retained_root, args.xctestrun, args.developer_dir,
                     args.selector, args.timeout, args.grace, args.env)
        if any(value is not None and value != [] for value in overrides):
            parser.error("profile settings cannot be overridden by direct arguments")
        try:
            profile = load_profile(args.profiles_file, args.profile)
            settings = resolve_profile(profile, args.run_root, args.candidate_sha)
        except (OSError, ValueError, TypeError) as error:
            parser.error(str(error))
        result = settings.pop("result")
        for name, value in settings.items():
            setattr(args, name, value)
    else:
        if any(getattr(args, field) is None for field in
               ("work_root", "retained_root", "xctestrun", "developer_dir", "selector", "timeout")):
            parser.error("direct mode requires roots, xctestrun, developer-dir, selector and timeout")
        if args.grace is None:
            args.grace = 5
    for name in ("work_root", "retained_root", "xctestrun", "run_root", "developer_dir"):
        if not getattr(args, name).is_absolute():
            parser.error(f"{name} must be absolute")
    if not args.work_root.is_dir() or not args.retained_root.is_dir() or not args.developer_dir.is_dir():
        parser.error("work root, retained root and developer directory must already exist")
    if not args.xctestrun.is_file() or args.xctestrun.suffix != ".xctestrun":
        parser.error("xctestrun must name an existing retained .xctestrun")
    if not args.xctestrun.resolve().is_relative_to(args.retained_root.resolve()):
        parser.error("xctestrun must be inside retained root")
    if not re.fullmatch(r"[0-9a-f]{40}", args.candidate_sha):
        parser.error("candidate SHA must be a full commit ID (caller-supplied provenance)")
    if args.run_root.exists():
        parser.error("run root must not exist; write host logs outside the run root")
    if args.gate_timeout < 0:
        parser.error("gate timeout must be nonnegative")
    if not all(math.isfinite(value) and value > 0 for value in (args.timeout, args.grace)):
        parser.error("timeout and grace must be finite positive seconds")
    try:
        command = selector_command(args.xctestrun, args.selector, result, args.test_execution_allowance)
        environment = named_environment(args.developer_dir, args.env)
    except ValueError as error:
        parser.error(str(error))
    lock = Path.home() / ".macscope-heavy-gate.lock"
    with heavy_gate(lock, args.work_root, args.retained_root, args.candidate_sha, args.gate_timeout):
        record = supervise(command, environment=environment, work_root=args.work_root,
                           run_root=args.run_root, candidate=args.candidate_sha,
                           selector=args.selector, result=result,
                           timeout=args.timeout, grace=args.grace,
                           profile_evidence=({"name": profile["name"],
                                              "evidence": profile.get("evidence", {}),
                                              "configuration": str(args.profiles_file)}
                                             if profile else None))
    if record["owner_quarantined"]:
        return 125  # Quarantine is failure even if the child eventually exits zero.
    return 124 if record["timed_out"] else (record["returncode"] if record["returncode"] >= 0 else 128 + record["signal"])


if __name__ == "__main__":
    raise SystemExit(main())
