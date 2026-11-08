#!/usr/bin/env python3
"""Reuse completed Debug native phases without executing or rehashing their inputs.

A missing receipt with existing outputs is an error, never permission to rerun.
Historical adoption records the original execution and its existing digests; it
does not create a new native-test result. Source/output changes fail closed.
"""
from __future__ import annotations

import argparse
import copy
import gzip
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import time
import uuid

sys.dont_write_bytecode = True
FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
ENV_KEYS = ('CONFIGURATION', 'MACSCOPE_DEBUG_SOURCE_IDENTITY', 'DEVELOPER_DIR', 'SDKROOT',
            'SDK_NAME', 'SDK_VERSION', 'SDK_PRODUCT_BUILD_VERSION', 'ARCHS', 'MACOSX_DEPLOYMENT_TARGET',
            'MACSCOPE_SLEIGH_MATERIALIZATION_ROOT', 'MACSCOPE_NATIVE_DECOMPILER_BUILD_ROOT',
            'MACSCOPE_NATIVE_DECOMPILER_GOLDEN_BUILD_ROOT', 'TARGET_BUILD_DIR', 'PROJECT_TEMP_DIR',
            'TARGET_TEMP_DIR', 'UNLOCALIZED_RESOURCES_FOLDER_PATH')
OPTION_KEYS = ('MACSCOPE_CMAKE', 'MACSCOPE_CTEST', 'MACSCOPE_NINJA', 'MACSCOPE_FILE',
               'MACSCOPE_STRINGS', 'MACSCOPE_PYTHON3', 'MACSCOPE_TOOL_SEARCH_PATH')
DENIED_OVERRIDES = ('MACSCOPE_NATIVE_DEV_BUILD_ONLY', 'MACSCOPE_NATIVE_DEBUG_CONTINUATION_RECEIPT')
MAX_BYTES = 16 * 1024 * 1024


class ReuseError(RuntimeError):
    pass


class StaleInputsError(ReuseError):
    """The routine receipt's inputs changed; carries the receipt and the mapping for the retire decision."""

    def __init__(self, message, value, mapping):
        super().__init__(message)
        self.value = value
        self.mapping = mapping


def metadata(path: Path, *, owner=True) -> list[int]:
    value = path.lstat()
    if (not stat.S_ISREG(value.st_mode) or value.st_nlink != 1 or (owner and value.st_uid != os.getuid())
            or path.resolve(strict=True) != path):
        raise ReuseError(f'unsafe-file: {path}')
    return [getattr(value, field) for field in FIELDS]


def read_bytes(path: Path) -> bytes:
    before = metadata(path)
    if before[4] > MAX_BYTES:
        raise ReuseError(f'oversized-evidence: {path}')
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, 'rb') as stream:
        if [getattr(os.fstat(stream.fileno()), field) for field in FIELDS] != before:
            raise ReuseError('evidence-changed-before-read')
        data = stream.read(MAX_BYTES + 1)
    if metadata(path) != before:
        raise ReuseError('evidence-changed-during-read')
    return data


def read_json(path: Path) -> dict:
    def closed(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ReuseError('duplicate-json-key')
            result[key] = value
        return result
    result = json.loads(read_bytes(path), object_pairs_hook=closed)
    if not isinstance(result, dict):
        raise ReuseError('invalid-json-evidence')
    return result


def write_once(path: Path, value: dict) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    parent = path.parent.lstat()
    if path.parent.resolve(strict=True) != path.parent or parent.st_uid != os.getuid() or parent.st_mode & 0o077:
        raise ReuseError('receipt-directory-not-private')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
    with os.fdopen(fd, 'w') as stream:
        json.dump(value, stream, sort_keys=True, separators=(',', ':'))
        stream.write('\n')
        stream.flush()
        os.fsync(stream.fileno())


def environment(raw: dict) -> dict:
    if raw.get('CONFIGURATION') != 'Debug' or raw.get('MACSCOPE_DEBUG_SOURCE_IDENTITY') != 'runtime-only':
        raise ReuseError('not-routine-debug')
    if any(raw.get(key, '') not in ('', '0') for key in DENIED_OVERRIDES):
        raise ReuseError('conflicting-native-execution-mode')
    result = {}
    for key in ENV_KEYS:
        if not raw.get(key):
            raise ReuseError(f'missing-environment: {key}')
        result[key] = raw[key]
    result.update({key: raw.get(key, '') for key in OPTION_KEYS})
    return result


def profile_paths(repository: Path, phase: str) -> tuple[str, ...]:
    path = repository / 'Scripts/native-decompiler-xpc/native_decompiler_source_identity.py'
    spec = importlib.util.spec_from_file_location('native_reuse_source_profile', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    # Enumerate the existing closed profile, but never call its hashing entry point.
    return module.profile_paths(repository, 'wrapper' if phase == 'bridge' else 'golden')


def tree_snapshot(root: Path) -> dict:
    if root.resolve(strict=True) != root or not root.is_dir():
        raise ReuseError(f'unsafe-tree: {root}')
    result = {}
    pending = [root]
    while pending:
        for path in sorted(pending.pop().iterdir()):
            value = path.lstat()
            if stat.S_ISLNK(value.st_mode):
                raise ReuseError(f'tree-symlink: {path}')
            if stat.S_ISDIR(value.st_mode):
                pending.append(path)
            else:
                result[str(path.relative_to(root))] = metadata(path)
            if len(result) > 4096:
                raise ReuseError('native-tree-size-limit')
    return result


def paths(env: dict) -> dict[str, Path]:
    bridge = Path(env['MACSCOPE_NATIVE_DECOMPILER_BUILD_ROOT'])
    resources = Path(env['TARGET_BUILD_DIR']) / env['UNLOCALIZED_RESOURCES_FOLDER_PATH']
    return {'archive': bridge / 'libmacscope_native_decompiler_contract.a',
            'cmake': bridge / 'CMakeCache.txt',
            'identity': bridge / 'generated/MacScopeNativeDecompiler/GhidraBuildIdentity.hpp',
            'linkInputs': bridge / 'macscope-native-decompiler-link-inputs.xcfilelist',
            'linkProbe': bridge / 'macscope-native-decompiler-link-probe-inspection.txt',
            'ctest': bridge / 'Testing/Temporary/LastTest.log',
            'golden': resources / 'NativeDecompilerBridgeGolden.json',
            'stage': Path(env['TARGET_TEMP_DIR']) / 'NativeDecompilerPackageStage/NativeDecompilerPackage.stage.json',
            'package': resources / 'NativeDecompilerPackage'}


def toolchain_snapshot(env: dict) -> dict:
    toolchain = {}
    for relative in ('Toolchains/XcodeDefault.xctoolchain/usr/bin/clang',
                     'Toolchains/XcodeDefault.xctoolchain/usr/bin/swift-frontend'):
        path = (Path(env['DEVELOPER_DIR']) / relative).resolve(strict=True)
        toolchain[str(path)] = metadata(path, owner=False)
    for relative in ('SDKSettings.plist', 'usr/lib/libz.tbd', 'usr/lib/libc++.tbd'):
        path = (Path(env['SDKROOT']) / relative).resolve(strict=True)
        toolchain[str(path)] = metadata(path, owner=False)
    return toolchain


def input_snapshot(repository: Path, phase: str, env: dict) -> dict:
    sources = {relative: metadata(repository / relative) for relative in profile_paths(repository, phase)}
    return {'environment': normalized_tools(env), 'sources': sources, 'toolchain': toolchain_snapshot(env),
            'consumer': metadata(Path(__file__).resolve()),
            'materialization': tree_snapshot(Path(env['MACSCOPE_SLEIGH_MATERIALIZATION_ROOT']))}


def output_snapshot(phase: str, env: dict) -> dict:
    selected = paths(env)
    keys = ('archive', 'cmake', 'identity', 'linkInputs', 'linkProbe')
    if not cache_staged(selected['cmake']):
        keys += ('ctest',)
    if phase == 'golden':
        keys += ('golden', 'stage')
    result = {str(selected[key]): metadata(selected[key]) for key in keys}
    if phase == 'golden':
        result['stagedPackage'] = tree_snapshot(selected['package'])
    return result


def identities(phase: str, env: dict) -> dict:
    selected = paths(env)
    cache = read_bytes(selected['cmake']).decode()
    def cache_value(key):
        match = re.search(r'^' + re.escape(key) + r':[^=]+=(.+)$', cache, re.M)
        if not match:
            raise ReuseError(f'missing-cmake-key: {key}')
        return match[1]
    wrapper = cache_value('MACSCOPE_NATIVE_DECOMPILER_WRAPPER_GIT_REVISION')
    if not re.fullmatch('[0-9a-f]{64}', wrapper):
        raise ReuseError('invalid-wrapper-source-identity')
    if cache.startswith(CACHE_PROJECTION_MARKER):
        # A dependency-cache staged bridge carries no sysroot and ran no local CTest; the
        # verified cache entry, not this build tree, is its native evidence.
        if cache_value('CMAKE_OSX_ARCHITECTURES') != env['ARCHS']:
            raise ReuseError('cmake-toolchain-mismatch')
        result = {'wrapperSourceSHA256': wrapper, 'bridgeOrigin': 'dependency-cache-projection'}
    else:
        if cache_value('CMAKE_OSX_ARCHITECTURES') != env['ARCHS'] or cache_value('CMAKE_OSX_SYSROOT') != env['SDKROOT']:
            raise ReuseError('cmake-toolchain-mismatch')
        tests = read_bytes(selected['ctest']).decode()
        if len(re.findall(r'^Test Passed\.$', tests, re.M)) != 28 or 'End testing:' not in tests or 'Test Failed.' in tests:
            raise ReuseError('no-complete-28-test-receipt')
        result = {'wrapperSourceSHA256': wrapper, 'nativeTests': 28}
    if phase == 'golden':
        golden = read_json(selected['golden'])
        if golden.get('passed') is not True or golden.get('wrapperGitRevision') != wrapper:
            raise ReuseError('golden-wrapper-mismatch-or-failure')
        if golden.get('sdkName') != env['SDK_NAME'] or golden.get('sdkVersion') != env['SDK_VERSION'] or golden.get('sdkBuild') != env['SDK_PRODUCT_BUILD_VERSION']:
            raise ReuseError('golden-sdk-mismatch')
        stage = read_json(selected['stage'])
        if stage.get('materialization', {}).get('package', {}).get('treeSha256') != golden.get('materializationTreeSHA256'):
            raise ReuseError('golden-package-identity-mismatch')
        result.update({key: value for key, value in golden.items() if key.endswith('SHA256')})
    return result


CACHE_PROJECTION_MARKER = '# MacScope dev dependency cache projection: not a CMake build tree.'


def cache_staged(cache_path: Path) -> bool:
    return cache_path.exists() and read_bytes(cache_path).decode().startswith(CACHE_PROJECTION_MARKER)


def normalized_tools(env: dict) -> dict:
    result = dict(env)
    cache_path = paths(env)['cmake']
    if not cache_path.exists():
        return result
    cache = read_bytes(cache_path).decode()
    if cache.startswith(CACHE_PROJECTION_MARKER):
        # A dependency-cache staged bridge ran no local CMake or Ninja.
        return result
    for option, key in (('MACSCOPE_CMAKE', 'CMAKE_COMMAND'), ('MACSCOPE_NINJA', 'CMAKE_MAKE_PROGRAM')):
        match = re.search(r'^' + key + r':[^=]+=(.+)$', cache, re.M)
        if not match:
            raise ReuseError(f'missing-effective-tool: {key}')
        selected = Path(match[1])
        if not selected.is_absolute():
            raise ReuseError(f'nonabsolute-effective-tool: {key}')
        canonical = str(selected.resolve(strict=True))
        override = result.get(option, '')
        if override:
            explicit = Path(override)
            if not explicit.is_absolute() or str(explicit.resolve(strict=True)) != canonical:
                raise ReuseError(f'native-tool-override-differs: {option}')
        result[option] = canonical
    return result


def legacy_receipt_path(phase: str, env: dict) -> Path:
    return Path(env['PROJECT_TEMP_DIR']) / 'NativePhaseReuse' / (phase + '.json')


def receipt_path(phase: str, env: dict, pending=False) -> Path:
    staged = legacy_receipt_path(phase, env).with_name('package-admission.v5.json')
    if not pending and (staged.exists() or staged.is_symlink()):
        return staged
    restored = legacy_receipt_path(phase, env).with_name('source-admission.v4.json')
    if not pending and (restored.exists() or restored.is_symlink()):
        return restored
    admitted = legacy_receipt_path(phase, env).with_name('materialization-admission.v3.json')
    if not pending and (admitted.exists() or admitted.is_symlink()):
        return admitted
    upgraded = legacy_receipt_path(phase, env).with_name(phase + '.v2.json')
    if not pending and (upgraded.exists() or upgraded.is_symlink()):
        return upgraded
    return Path(env['PROJECT_TEMP_DIR']) / 'NativePhaseReuse' / (phase + ('.pending' if pending else '') + '.json')


def check_package_file_lists(repository: Path, raw: dict) -> None:
    for key, name in (('MACSCOPE_NATIVE_PACKAGE_INPUT_FILE_LIST', 'NativeDecompilerPackageInputs.xcfilelist'),
                      ('MACSCOPE_NATIVE_PACKAGE_OUTPUT_FILE_LIST', 'NativeDecompilerPackageOutputs.xcfilelist')):
        if not raw.get(key) or Path(raw[key]).resolve(strict=True) != repository / 'Scripts/native-decompiler-xpc' / name:
            raise ReuseError('package-file-list-setting-mismatch')


def content_digests(repository: Path, inputs: dict) -> dict:
    """SHA-256 of the repository-resident native inputs (profile sources and this consumer).

    Stat rows of these files change whenever git rewrites them; the digests let a receipt tell a
    rewrite with identical bytes from a real change. Only these inputs are digested.
    """
    result = {'sources': {name: hashlib.sha256(read_bytes(repository / name)).hexdigest()
                          for name in inputs['sources']}}
    if 'consumer' in inputs:
        result['consumer'] = hashlib.sha256(read_bytes(Path(__file__).resolve())).hexdigest()
    return result


def content_equal(repository: Path, value: dict, current: dict, mapping: dict) -> bool:
    """True when only the stat rows of sources/consumer differ and every digest still matches.

    A receipt without recorded digests, or any added, removed or changed input, is never admitted.
    """
    recorded = value.get('inputs')
    digests = value.get('contentDigests')
    if (not isinstance(recorded, dict) or not isinstance(digests, dict) or not isinstance(digests.get('sources'), dict)
            or not isinstance(recorded.get('sources'), dict) or not isinstance(current.get('sources'), dict)
            or set(digests['sources']) != set(recorded['sources']) or set(digests['sources']) != set(current['sources'])
            or ('consumer' in recorded) != ('consumer' in current) or ('consumer' in current) != ('consumer' in digests)):
        return False
    try:
        observed = content_digests(repository, current)
    except (OSError, ReuseError):
        return False
    if observed != {key: digests[key] for key in observed}:
        return False
    skipped = ('sources', 'consumer')
    return persisted_equal({k: v for k, v in recorded.items() if k not in skipped},
                           {k: v for k, v in current.items() if k not in skipped}, mapping=mapping)


def refresh_receipt(path: Path, value: dict, current: dict) -> None:
    """Replace a receipt atomically with its source/consumer stat rows refreshed (digests unchanged)."""
    refreshed = copy.deepcopy(value)
    for key in ('sources', 'consumer'):
        if key in current:
            refreshed['inputs'][key] = current[key]
    temporary = path.with_name(f'.{path.name}.{uuid.uuid4().hex}.tmp')
    write_once(temporary, refreshed)
    os.replace(temporary, path)


def check_recorded(repository: Path, phase: str, env: dict, receipt: Path, current: dict) -> dict:
    mapping = {}
    if metadata(receipt)[2] & 0o222:
        raise ReuseError('reuse-receipt-is-mutable')
    value = read_json(receipt)
    if value.get('schema') not in (1, 2) or value.get('phase') != phase or value.get('repository') != str(repository):
        raise ReuseError('reuse-receipt-scope-mismatch')
    refresh = False
    if not persisted_equal(value.get('inputs'), current, mapping=mapping):
        # Stat rows differ (git rewrote the files); admit only if every input's bytes are unchanged.
        if not content_equal(repository, value, current, mapping):
            raise StaleInputsError('native-inputs-changed-owner-qualification-required', value, mapping)
        refresh = True
    if not persisted_equal(value.get('outputs'), output_snapshot(phase, env), mapping=mapping):
        raise ReuseError('native-outputs-changed-owner-qualification-required')
    if refresh:
        refresh_receipt(receipt, value, current)
    return value


def retired_directory_name(phase: str) -> str:
    return time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + f'-{phase}-' + uuid.uuid4().hex[:8]


def routine_state(phase: str, env: dict) -> list[Path]:
    base = legacy_receipt_path(phase, env).parent
    return [base / (phase + '.v2.json'), base / (phase + '.json'), base / (phase + '.pending.json')]


def retire_targets(phase: str, env: dict) -> list[Path]:
    """Ordered paths a stale routine receipt retires (see the native-retire-stale brief)."""
    selected = paths(env)
    golden_build = Path(env['MACSCOPE_NATIVE_DECOMPILER_GOLDEN_BUILD_ROOT'])
    if phase == 'bridge':
        # The admitted names are shared by every phase, so check() takes the admitted branch first and this is unreachable today.
        if receipt_path('golden', env).name not in ('golden.v2.json', 'golden.json'):
            raise ReuseError('native-inputs-changed-owner-qualification-required')
        return (routine_state('bridge', env) + [Path(env['MACSCOPE_NATIVE_DECOMPILER_BUILD_ROOT'])]
                + routine_state('golden', env)
                + [selected['golden'], selected['package'], selected['stage'].parent, golden_build])
    if phase == 'package':
        return routine_state('golden', env) + [selected['golden'], selected['package'], selected['stage'].parent, golden_build]
    return routine_state('golden', env) + [selected['golden'], golden_build]


def retire_preflight(targets: list[Path], env: dict) -> None:
    anchors = [os.path.realpath(env[key]) for key in ('PROJECT_TEMP_DIR', 'TARGET_BUILD_DIR', 'TARGET_TEMP_DIR')]
    project_dev = os.lstat(anchors[0]).st_dev
    for target in targets:
        if not target.is_absolute() or '..' in target.parts:
            raise ReuseError(f'native-retire-failed: path-outside-derived-data: {target}')
        parent = os.path.realpath(target.parent)
        resolved = os.path.join(parent, target.name)
        if not any(os.path.commonpath([anchor, parent]) == anchor for anchor in anchors):
            raise ReuseError(f'native-retire-failed: path-outside-derived-data: {target}')
        if any(resolved == anchor or os.path.commonpath([resolved, anchor]) == resolved for anchor in anchors):
            raise ReuseError(f'native-retire-failed: path-outside-derived-data: {target}')
        if os.path.lexists(target) and os.lstat(target).st_dev != project_dev:
            raise ReuseError(f'native-retire-failed: cross-device: {target}')


def changed_input_rows(recorded, current: dict) -> tuple[list[str], list[str]]:
    recorded = recorded if isinstance(recorded, dict) else {}
    keys = sorted(key for key in set(recorded) | set(current)
                  if key not in recorded or key not in current or not persisted_equal(recorded[key], current[key], mapping={}))
    old = recorded.get('sources') if isinstance(recorded.get('sources'), dict) else {}
    new = current.get('sources') if isinstance(current.get('sources'), dict) else {}
    sources = sorted(name for name in set(old) | set(new)
                     if name not in old or name not in new or not persisted_equal(old[name], new[name], mapping={}))
    return keys, sources[:50]


def retire_stale(repository: Path, phase: str, receipt_phase: str, env: dict, error: StaleInputsError, current: dict) -> None:
    """Move a stale routine receipt and the native state bound to it aside; the caller continues as a fresh build would."""
    try:
        outputs_equal = persisted_equal(error.value.get('outputs'), output_snapshot(receipt_phase, env), mapping=error.mapping)
    except (OSError, ReuseError):
        raise error
    if not outputs_equal:
        raise ReuseError('native-outputs-changed-owner-qualification-required')
    keys, sources = changed_input_rows(error.value.get('inputs'), current)
    retire_move(phase, env, 'native-inputs-changed', keys, sources)
    print(f'note: {phase}: retired stale native receipt (inputs changed: {",".join(keys)}); '
          'continuing as a fresh DerivedData would', file=sys.stderr)


def stale_pending_rows(pending_phase: str, env: dict, current: dict):
    """Changed (keys, sources) when a pending receipt records inputs other than the current ones, else None.

    Equal inputs are a true repeat of an unfinished run and a malformed pending file is not understood; both stay refusals.
    """
    pending = receipt_path(pending_phase, env, pending=True)
    if not pending.is_file() or pending.is_symlink():
        return None
    try:
        recorded = copy.deepcopy(read_json(pending).get('inputs'))
    except (OSError, ReuseError, ValueError, AttributeError):
        return None
    if not isinstance(recorded, dict):
        return None
    if 'environment' in recorded:
        recorded['environment'] = normalized_tools(recorded['environment'])
    keys, sources = changed_input_rows(recorded, current)
    return (keys, sources) if keys else None


def retire_failed_pending(phase: str, env: dict, keys: list[str], sources: list[str]) -> None:
    """Retire the pending receipt and retained outputs of a failed execution of older inputs."""
    retire_move(phase, env, 'failed-execution-inputs-changed', keys, sources)
    print(f'note: {phase}: retired failed native execution of older inputs (inputs changed: {",".join(keys)}); '
          'continuing as a fresh DerivedData would', file=sys.stderr)


def retire_move(phase: str, env: dict, reason: str, keys: list[str], sources: list[str]) -> None:
    targets = retire_targets(phase, env)
    retire_preflight(targets, env)
    existing = [target for target in targets if os.path.lexists(target)]
    base = Path(env['PROJECT_TEMP_DIR']) / 'NativePhaseReuseRetired'
    destination = base / retired_directory_name(phase)
    moves = [(target, destination / f'{index}-{target.name}') for index, target in enumerate(existing)]
    try:
        base.mkdir(mode=0o700, parents=True, exist_ok=True)
        os.mkdir(destination, 0o700)
        write_once(destination / 'manifest.json', {
            'schema': 1, 'phase': phase, 'reason': reason, 'changedInputKeys': keys,
            'changedSources': sources, 'moved': [{'from': str(old), 'to': str(new)} for old, new in moves]})
    except (OSError, ReuseError) as failure:
        raise ReuseError(f'native-retire-failed: {failure}') from failure
    done = []
    try:
        for old, new in moves:
            os.rename(old, new)
            done.append((old, new))
    except OSError as failure:
        for old, new in reversed(done):
            os.rename(new, old)
        raise ReuseError(f'native-retire-failed: {failure}') from failure


def check(repository: Path, phase: str, raw: dict) -> int:
    env = environment(raw)
    retiring = raw.get('MACSCOPE_NATIVE_RETIRE_STALE_RECEIPTS') == '1'
    receipt = receipt_path('golden' if phase == 'package' else phase, env)
    if phase == 'package' and receipt.name in ('golden.json', 'golden.v2.json') and (receipt.exists() or receipt.is_symlink()):
        # A routine golden receipt is recorded after this stage on the same build and
        # binds the stage record (with its file-list digests), the result and every
        # staged package file. Unchanged golden inputs and outputs mean the stage is
        # unchanged; any difference remains the explicit-admission refusal.
        check_package_file_lists(repository, raw)
        stage = paths(env)['stage'].parent
        try:
            current = input_snapshot(repository, 'golden', env)
            try:
                value = check_recorded(repository, 'golden', env, receipt, current)
            except StaleInputsError as stale:
                if not retiring:
                    raise
                retire_stale(repository, 'package', 'golden', env, stale, current)
                return 3
            for name in ('NativeDecompilerPackage.inputs.xcfilelist', 'NativeDecompilerPackage.outputs.xcfilelist'):
                metadata(stage / name)
        except (OSError, ReuseError) as error:
            raise ReuseError(f'package-stage-needs-explicit-output-admission: {error}') from error
        print(f'note: package: reusing staged package bound by golden receipt; origin={value["origin"]["kind"]}')
        return 0
    if phase == 'package' and receipt.name != 'package-admission.v5.json':
        selected = paths(env)
        retained = [receipt, selected['package'], selected['stage'],
                    selected['stage'].parent / 'NativeDecompilerPackage.inputs.xcfilelist',
                    selected['stage'].parent / 'NativeDecompilerPackage.outputs.xcfilelist',
                    receipt_path('golden', env, pending=True)]
        if any(path.exists() or path.is_symlink() for path in retained):
            rows = None
            if retiring and not (receipt.exists() or receipt.is_symlink()):
                try:
                    rows = stale_pending_rows('golden', env, input_snapshot(repository, 'golden', env))
                except (OSError, ReuseError):
                    rows = None
            if rows is None:
                raise ReuseError('package-stage-needs-explicit-output-admission')
            retire_failed_pending('package', env, *rows)
        return 3
    if phase == 'package':
        check_package_file_lists(repository, raw)
    if receipt.name in ('materialization-admission.v3.json', 'source-admission.v4.json', 'package-admission.v5.json'):
        return check_admitted(repository, phase, env, receipt)
    current = input_snapshot(repository, phase, env)
    if receipt.exists() or receipt.is_symlink():
        try:
            value = check_recorded(repository, phase, env, receipt, current)
        except StaleInputsError as stale:
            if not retiring:
                raise
            retire_stale(repository, phase, phase, env, stale, current)
            value = None
        if value is not None:
            print(f'note: {phase}: reusing completed native execution; origin={value["origin"]["kind"]}')
            return 0
    selected = paths(env)
    candidates = ('archive', 'cmake') if phase == 'bridge' else ('golden',)
    pending = receipt_path(phase, env, pending=True)
    if retiring and (pending.exists() or pending.is_symlink()) and not (receipt.exists() or receipt.is_symlink()):
        rows = stale_pending_rows(phase, env, current)
        if rows is not None:
            retire_failed_pending(phase, env, *rows)
    if any(selected[key].exists() or selected[key].is_symlink() for key in candidates):
        raise ReuseError('existing-native-output-needs-explicit-adoption')
    if pending.exists():
        raise ReuseError('unfinished-native-execution-owner-action-required')
    write_once(pending, {'schema': 1, 'inputs': current})
    # The caller may execute its original phase once only for genuinely new inputs.
    return 3


def record(repository: Path, phase: str, raw: dict) -> None:
    mapping = {}
    env = environment(raw)
    pending = read_json(receipt_path(phase, env, pending=True))
    inputs = input_snapshot(repository, phase, env)
    expected = copy.deepcopy(pending.get('inputs'))
    if isinstance(expected, dict) and 'environment' in expected:
        expected['environment'] = normalized_tools(expected['environment'])
    if not persisted_equal(expected, inputs, mapping=mapping):
        raise ReuseError('inputs-changed-during-first-native-execution')
    value = {'schema': 1, 'repository': str(repository), 'phase': phase, 'inputs': inputs,
             'outputs': output_snapshot(phase, env), 'identities': identities(phase, env),
             'contentDigests': content_digests(repository, inputs),
             'origin': {'kind': 'completed-original-phase'}}
    write_once(receipt_path(phase, env), value)


def abandon(repository: Path, phase: str, raw: dict) -> None:
    """Drop the pending receipt of a bridge execution that never produced any output.

    A shared-cache miss stops the bridge phase after check() wrote the pending receipt and
    before any stage ran; the pending file would then refuse every later build. It is removed
    only when no bridge output exists and its inputs equal the current ones. Anything else is
    a genuinely interrupted execution and keeps refusing.
    """
    if phase != 'bridge':
        raise ReuseError('abandon-supports-bridge-only')
    env = environment(raw)
    pending = receipt_path(phase, env, pending=True)
    if not (pending.exists() or pending.is_symlink()):
        print(f'note: {phase}: no pending native execution to abandon')
        return
    selected = paths(env)
    present = [str(selected[key]) for key in ('archive', 'cmake', 'identity', 'linkInputs', 'linkProbe', 'ctest')
               if selected[key].exists() or selected[key].is_symlink()]
    if present:
        raise ReuseError(f'abandon-refused-native-output-exists: {present[0]}')
    expected = copy.deepcopy(read_json(pending).get('inputs'))
    if isinstance(expected, dict) and 'environment' in expected:
        expected['environment'] = normalized_tools(expected['environment'])
    if not persisted_equal(expected, input_snapshot(repository, phase, env), mapping={}):
        raise ReuseError('abandon-refused-inputs-changed')
    pending.unlink()
    print(f'note: {phase}: abandoned pending native execution (no bridge output exists, inputs unchanged)')


def activity_environment(text: str) -> dict:
    candidates = []
    for block in text.split('export ACTION\\=')[1:]:
        block = 'export ACTION\\=' + block
        values = {}
        for match in re.finditer(r'export ([A-Z_0-9]+)\\=([^\r\n]*)', block):
            words = shlex.split(match[2])
            values[match[1]] = ' '.join(words)
        if values.get('TARGET_NAME') == 'NativeDecompilerXPCService':
            candidates.append(environment(values))
    if not candidates or any(item != candidates[0] for item in candidates):
        raise ReuseError('ambiguous-or-missing-native-activity-environment')
    return candidates[0]


def metadata_rows(value):
    if isinstance(value, list) and len(value) == len(FIELDS) and all(isinstance(item, int) for item in value):
        yield value
    elif isinstance(value, dict):
        for item in value.values():
            yield from metadata_rows(item)


# st_dev is compared through one coherent mapping: a volume's device number is not stable across reboots on APFS (see receipt_device_transition.declaration for the Release audit).
def persisted_equal(recorded, observed, mapping=None) -> bool:
    candidate = dict(mapping) if mapping is not None else {}
    if len(set(candidate.values())) != len(candidate):
        return False

    def equal(old, new):
        if isinstance(old, dict) and isinstance(new, dict):
            return old.keys() == new.keys() and all(equal(old[key], new[key]) for key in old)
        old_row = isinstance(old, list) and len(old) == len(FIELDS) and all(isinstance(item, int) for item in old)
        new_row = isinstance(new, list) and len(new) == len(FIELDS) and all(isinstance(item, int) for item in new)
        if old_row and new_row:
            if old[1:] != new[1:]:
                return False
            before, after = old[0], new[0]
            if before in candidate and candidate[before] != after:
                return False
            if any(device != before and target == after for device, target in candidate.items()):
                return False
            candidate[before] = after
            return True
        return old == new

    if not equal(recorded, observed):
        return False
    if mapping is not None:
        mapping.update(candidate)
    return True


def adopt(repository: Path, activity: Path, run_log: Path, head: str, successful_exit: int) -> None:
    if successful_exit != 0 or not re.fullmatch('[0-9a-f]{40}', head):
        raise ReuseError('historical-run-not-successful')
    raw = read_bytes(activity)
    text = gzip.decompress(raw).decode('utf-8', 'replace')
    if len(text) > 64 * 1024 * 1024:
        raise ReuseError('activity-expansion-limit')
    log = read_bytes(run_log).decode()
    if ('100% tests passed out of 28' not in text or 'PASS: native bridge golden runner' not in text
            or '==> dev loop timings:' not in log or '** TEST FAILED **' in log or '** BUILD FAILED **' in log):
        raise ReuseError('historical-execution-evidence-incomplete')
    env = activity_environment(text)
    if f'{repository}/Tools/NativeDecompilerBridge' not in read_bytes(paths(env)['cmake']).decode():
        raise ReuseError('historical-repository-mismatch')
    origin = {'kind': 'adopted-historical-execution', 'successfulHead': head, 'exitCode': successful_exit,
              'activityLog': {'path': str(activity), 'metadata': metadata(activity)},
              'runLog': {'path': str(run_log), 'metadata': metadata(run_log)},
              'note': 'Existing completion and digest evidence reused; no native execution or content hashing performed.'}
    values = []
    for phase in ('bridge', 'golden'):
        if receipt_path(phase, env).exists():
            raise ReuseError('historical-adoption-already-recorded')
        inputs = input_snapshot(repository, phase, env)
        outputs = output_snapshot(phase, env)
        identity = identities(phase, env)
        cutoff = metadata(paths(env)['archive' if phase == 'bridge' else 'golden'])[5]
        completion = metadata(activity)[5]
        if cutoff > completion:
            raise ReuseError('outputs-postdate-historical-run')
        if any(row[6] > cutoff for row in inputs['sources'].values()):
            raise ReuseError('source-changed-after-historical-execution')
        if any(row[6] > completion for row in metadata_rows(outputs)):
            raise ReuseError('output-changed-after-historical-execution')
        if any(row[6] > cutoff for key in ('toolchain', 'materialization')
               for row in metadata_rows(inputs.get(key, {}))):
            raise ReuseError('dependency-changed-after-historical-execution')
        git = subprocess.run(['git', '-C', str(repository), 'ls-tree', '-r', head, '--', *inputs['sources']],
                             check=True, capture_output=True, text=True, timeout=30)
        blobs = {line.split('\t', 1)[1]: line.split('\t', 1)[0].split()[2] for line in git.stdout.splitlines()}
        if set(blobs) != set(inputs['sources']):
            raise ReuseError('historical-source-membership-mismatch')
        values.append((receipt_path(phase, env), {'schema': 1, 'repository': str(repository), 'phase': phase,
                      'inputs': inputs, 'outputs': outputs, 'identities': identity,
                      'historicalSourceBlobs': blobs, 'origin': origin}))
    for destination, value in values:
        write_once(destination, value)
    print('Adopted retained native CTest and golden execution; no native work ran.')


def upgrade(repository: Path, receipt_directory: Path) -> None:
    values = []
    for phase in ('bridge', 'golden'):
        mapping = {}
        old_path = receipt_directory / (phase + '.json')
        old_metadata = metadata(old_path)
        if old_metadata[2] & 0o222:
            raise ReuseError('upgrade-original-receipt-is-mutable')
        old = read_json(old_path)
        if old.get('schema') != 1 or old.get('phase') != phase or old.get('repository') != str(repository):
            raise ReuseError('upgrade-original-scope-mismatch')
        env = environment(old['inputs']['environment'])
        if legacy_receipt_path(phase, env) != old_path:
            raise ReuseError('upgrade-original-location-mismatch')
        destination = old_path.with_name(phase + '.v2.json')
        if destination.exists() or destination.is_symlink():
            raise ReuseError('consumer-upgrade-already-recorded')
        # The original CMake cache must be unchanged before its selected tool
        # paths can establish equivalence between omitted and explicit options.
        outputs = output_snapshot(phase, env)
        if not persisted_equal(old['outputs'], outputs, mapping=mapping):
            raise ReuseError('upgrade-native-outputs-changed')
        current = input_snapshot(repository, phase, env)
        expected = copy.deepcopy(old['inputs'])
        expected['environment'] = normalized_tools(expected['environment'])
        if 'consumer' not in expected or 'consumer' not in current:
            raise ReuseError('upgrade-consumer-binding-missing')
        expected['consumer'] = current['consumer']
        if not persisted_equal({k: v for k, v in expected.items() if k != 'consumer'},
                               {k: v for k, v in current.items() if k != 'consumer'}, mapping=mapping):
            raise ReuseError('upgrade-native-inputs-changed')
        if metadata(old_path) != old_metadata:
            raise ReuseError('upgrade-original-receipt-changed')
        value = copy.deepcopy(old)
        value.update(schema=2, inputs=current, outputs=outputs,
                     origin={'kind': 'consumer-upgrade', 'previousOrigin': old['origin'],
                             'previousReceipt': {'path': str(old_path), 'metadata': old_metadata},
                             'note': 'Only helper identity and equivalent cached CMake/Ninja selections changed; native evidence reused.'})
        values.append((destination, value))
    for destination, value in values:
        write_once(destination, value)
    print('Upgraded receipt consumers; original receipts preserved; no native work or hashing ran.')



ADMITTED_LEAVES = {
    ('sourceBuild', 'toolchain', 'cmake', 'path'),
    ('sourceBuild', 'toolchain', 'cmake', 'sha256'),
    ('sourceBuild', 'toolchain', 'ninja', 'path'),
    ('sourceBuild', 'toolchain', 'ninja', 'sha256'),
    ('sourceBuild', 'toolchain', 'compiler', 'path'),
}


def manifest_changes(before, after, prefix=()):
    if type(before) is not type(after):
        raise ReuseError('admission-manifest-type-change')
    if isinstance(before, dict):
        if before.keys() != after.keys():
            raise ReuseError('admission-manifest-membership-change')
        result = []
        for key in before:
            result.extend(manifest_changes(before[key], after[key], prefix + (key,)))
        return result
    if before == after:
        return []
    if prefix not in ADMITTED_LEAVES or not isinstance(before, str):
        raise ReuseError('admission-manifest-change-not-permitted: ' + '.'.join(prefix))
    return [{'field': '.'.join(prefix), 'before': before, 'after': after}]


def directory_metadata(path):
    value = path.lstat()
    if (not stat.S_ISDIR(value.st_mode) or path.resolve(strict=True) != path
            or value.st_uid != os.getuid()):
        raise ReuseError(f'admission-unsafe-directory: {path}')
    return [getattr(value, field) for field in FIELDS]


def recorded_metadata(root, rows):
    """Inspect only previously enumerated files; never enumerate or hash a tree."""
    if root.resolve(strict=True) != root:
        raise ReuseError('admission-unsafe-root')
    result = {}
    for relative in rows:
        path = Path(relative)
        if path.is_absolute() or str(path) != relative or '..' in path.parts or relative == '.':
            raise ReuseError('admission-unsafe-recorded-path')
        result[relative] = metadata(root / path)
    return result


def cache_binding(view_path):
    view_metadata = metadata(view_path)
    if view_metadata[2] & 0o222:
        raise ReuseError('admission-view-mutable')
    view = read_json(view_path)
    if metadata(view_path) != view_metadata:
        raise ReuseError('admission-view-changed')
    key = view.get('key', '')
    if (view.get('schema_version') != 1 or view.get('component') != 'sleigh-native-source'
            or not re.fullmatch('[0-9a-f]{64}', key) or not view.get('verified_at')
            or not re.fullmatch('[0-9a-f]{64}', view.get('entry_receipt_sha256', ''))
            or view_path.name != 'VIEW.json' or view_path.parent.name != key):
        raise ReuseError('admission-invalid-view-binding')
    root = Path(view['view'])
    entry_root = Path(view['entry'])
    if (root != view_path.parent / 'SleighNativeSource' or entry_root.name != key
            or entry_root.parent.name != 'sleigh-native-source'):
        raise ReuseError('admission-invalid-cache-location')
    entry_path = entry_root / 'ENTRY.json'
    entry_metadata = metadata(entry_path)
    if entry_metadata[2] & 0o222:
        raise ReuseError('admission-entry-mutable')
    entry = read_json(entry_path)
    if metadata(entry_path) != entry_metadata:
        raise ReuseError('admission-entry-changed')
    if (entry.get('schema_version') != 1 or entry.get('key') != key
            or entry.get('component') != view['component']):
        raise ReuseError('admission-invalid-entry-binding')
    records = {}
    files = {}
    directories = {str(root): directory_metadata(root)}
    for row in entry['payload_records']:
        relative = row['path']
        part = Path(relative)
        if (part.is_absolute() or str(part) != relative or '..' in part.parts
                or relative == '.' or relative in records):
            raise ReuseError('admission-invalid-payload-path')
        records[relative] = row
        target = root / part
        if row['kind'] == 'directory':
            directories[str(target)] = directory_metadata(target)
        elif row['kind'] == 'file':
            value = metadata(target)
            if (value[2] & 0o222 or value[4] != row['size']
                    or bool(value[2] & 0o111) != row['executable']):
                raise ReuseError('admission-payload-metadata-mismatch')
            if not re.fullmatch('[0-9a-f]{64}', row.get('sha256', '')):
                raise ReuseError('admission-invalid-existing-digest')
            files[relative] = value
        else:
            raise ReuseError('admission-unsupported-payload-kind')
    if any(value[2] & 0o222 for value in directories.values()):
        raise ReuseError('admission-payload-directory-mutable')
    if (entry.get('file_count') != len(files)
            or entry.get('total_bytes') != sum(value[4] for value in files.values())):
        raise ReuseError('admission-entry-count-mismatch')
    # Existing VIEW/ENTRY receipts establish membership and content digests.
    # This operation checks metadata of their recorded paths, not fresh bytes.
    return {'view': str(view_path), 'entry': str(entry_path), 'key': key,
            'root': str(root), 'records': records, 'files': files,
            'existingEntryReceiptSHA256': view['entry_receipt_sha256'],
            'directories': directories,
            'evidence': {str(view_path): view_metadata, str(entry_path): entry_metadata},
            'manifest': read_json(root / 'materialization/MATERIALIZATION.json')}


def admitted_outputs(phase, env, previous):
    result = {}
    for path, old in previous.items():
        if path == 'stagedPackage':
            result[path] = recorded_metadata(paths(env)['package'], old)
        else:
            result[path] = metadata(Path(path))
    return result


def check_admitted(repository, phase, env, receipt):
    mapping = {}
    if metadata(receipt)[2] & 0o222:
        raise ReuseError('reuse-receipt-is-mutable')
    bundle = read_json(receipt)
    if (bundle.get('schema') != {'materialization-admission.v3.json': 3, 'source-admission.v4.json': 4, 'package-admission.v5.json': 5}[receipt.name]
            or bundle.get('repository') != str(repository)):
        raise ReuseError('admitted-receipt-scope-mismatch')
    if phase == 'package':
        phase = 'golden'
    value = bundle['phases'][phase]
    expected = value['inputs']
    current = copy.deepcopy(expected)
    current['environment'] = normalized_tools(env)
    current['consumer'] = metadata(Path(__file__).resolve())
    current['sources'] = {name: metadata(repository / name) for name in expected['sources']}
    if set(profile_paths(repository, phase)) != set(expected['sources']):
        raise ReuseError('admitted-source-membership-changed')
    current['toolchain'] = toolchain_snapshot(env)
    current['materialization'] = recorded_metadata(Path(env['MACSCOPE_SLEIGH_MATERIALIZATION_ROOT']),
                                                   expected['materialization'])
    if not persisted_equal(expected, current, mapping=mapping):
        raise ReuseError('native-inputs-changed-owner-qualification-required')
    if not persisted_equal(value['outputs'], admitted_outputs(phase, env, value['outputs']), mapping=mapping):
        raise ReuseError('native-outputs-changed-owner-qualification-required')
    for path, old in bundle['evidence'].items():
        if not persisted_equal(old, metadata(Path(path)), mapping=mapping):
            raise ReuseError('admitted-evidence-changed')
    for path, old in bundle['directories'].items():
        if not persisted_equal(old, directory_metadata(Path(path)), mapping=mapping):
            raise ReuseError('admitted-directory-membership-changed')
    print(f'note: {phase}: reusing completed native execution; origin={value["origin"]["kind"]}')
    return 0


def admit_materialization(repository, receipt_directory, old_view, new_view):
    mapping = {}
    destination = receipt_directory / 'materialization-admission.v3.json'
    if destination.exists() or destination.is_symlink():
        raise ReuseError('materialization-admission-already-recorded')
    before, after = cache_binding(old_view), cache_binding(new_view)
    if before['key'] == after['key'] or before['records'].keys() != after['records'].keys():
        raise ReuseError('admission-cache-membership-mismatch')
    changed = [name for name in before['records'] if before['records'][name] != after['records'][name]]
    if changed != ['materialization/MATERIALIZATION.json']:
        raise ReuseError('admission-package-records-not-identical')
    old_record = before['records'][changed[0]]
    new_record = after['records'][changed[0]]
    if (old_record.keys() != new_record.keys()
            or {key: value for key, value in old_record.items() if key not in ('size', 'sha256')}
            != {key: value for key, value in new_record.items() if key not in ('size', 'sha256')}):
        raise ReuseError('admission-manifest-record-structure-changed')
    changes = manifest_changes(before['manifest'], after['manifest'])
    if not changes:
        raise ReuseError('admission-missing-manifest-change')
    evidence = {**before['evidence'], **after['evidence']}
    directories = {**before['directories'], **after['directories']}
    phases = {}
    unresolved = {}
    old_root = Path(before['root']) / 'materialization'
    new_root = Path(after['root']) / 'materialization'
    for phase in ('bridge', 'golden'):
        previous = receipt_directory / (phase + '.v2.json')
        prior_metadata = metadata(previous)
        if prior_metadata[2] & 0o222:
            raise ReuseError('admission-previous-receipt-mutable')
        old = read_json(previous)
        if (old.get('schema') != 2 or old.get('repository') != str(repository)
                or old.get('phase') != phase):
            raise ReuseError('admission-previous-scope-mismatch')
        env = environment(old['inputs']['environment'])
        if (legacy_receipt_path(phase, env).parent != receipt_directory
                or env['MACSCOPE_SLEIGH_MATERIALIZATION_ROOT'] != str(old_root)):
            raise ReuseError('admission-previous-location-mismatch')
        if not persisted_equal(old['outputs'], admitted_outputs(phase, env, old['outputs']), mapping=mapping):
            raise ReuseError('admission-retained-outputs-changed')
        old_files = {name.removeprefix('materialization/'): value for name, value in before['files'].items()
                     if name.startswith('materialization/')}
        if not persisted_equal(old['inputs']['materialization'], old_files, mapping=mapping):
            raise ReuseError('admission-old-materialization-changed')
        # Do not refresh unrelated source or toolchain bindings. Any mismatch
        # remains a refusal at check time, pending separately authorized work.
        unresolved[phase] = [name for name, old_meta in old['inputs']['sources'].items()
                             if not persisted_equal(old_meta, metadata(repository / name), mapping=mapping)]
        value = copy.deepcopy(old)
        value['schema'] = 3
        value['inputs']['environment']['MACSCOPE_SLEIGH_MATERIALIZATION_ROOT'] = str(new_root)
        value['inputs']['consumer'] = metadata(Path(__file__).resolve())
        value['inputs']['materialization'] = {
            name.removeprefix('materialization/'): row for name, row in after['files'].items()
            if name.startswith('materialization/')}
        value['origin'] = {'kind': 'materialization-admission', 'previousOrigin': old['origin'],
                           'previousReceipt': str(previous), 'oldRoot': str(old_root), 'newRoot': str(new_root),
                           'changes': changes, 'previousConsumer': old['inputs']['consumer'],
                           'note': 'Existing recorded package digests and execution evidence reused; no content hashing or native execution.'}
        evidence[str(previous)] = prior_metadata
        phases[phase] = value
        if phase == 'golden':
            package = paths(env)['package']
            directories[str(package)] = directory_metadata(package)
            for name in old['outputs']['stagedPackage']:
                for parent in (package / name).parents:
                    if parent == package:
                        break
                    directories[str(parent)] = directory_metadata(parent)
    # One immutable bundle publishes both phase bindings atomically. Original
    # receipts, execution identities and retained output paths remain intact.
    for binding in (before, after):
        if recorded_metadata(Path(binding['root']), binding['files']) != binding['files']:
            raise ReuseError('admission-payload-changed-during-admission')
    for path, old_meta in evidence.items():
        if metadata(Path(path)) != old_meta:
            raise ReuseError('admission-evidence-changed-during-admission')
    for path, old_meta in directories.items():
        if directory_metadata(Path(path)) != old_meta:
            raise ReuseError('admission-directory-changed-during-admission')
    bundle = {'schema': 3, 'repository': str(repository), 'phases': phases,
              'evidence': evidence, 'directories': directories,
              'reusedEntryReceiptSHA256': {item['entry']: item['existingEntryReceiptSHA256']
                                         for item in (before, after)},
              'unresolvedSourceMetadata': unresolved,
              'membershipAuthority': 'Existing verified VIEW/ENTRY records; no fresh tree enumeration or byte verification.'}
    temporary = destination.with_name('.admission-' + uuid.uuid4().hex + '.json')
    try:
        write_once(temporary, bundle)
        os.link(temporary, destination, follow_symlinks=False)
    finally:
        if temporary.exists():
            temporary.unlink()
    print(json.dumps({'admission': str(destination), 'materializationBinding': 'reconciled',
                      'unresolvedSourceMetadata': unresolved, 'testsRun': 0,
                      'verificationRun': False}, sort_keys=True))


def admit_restored_source(repository, receipt_directory):
    """Compare exactly the restored script once; preserve every other binding."""
    mapping = {}
    relative = 'Scripts/qualification/dev_dependency_cache.py'
    previous = receipt_directory / 'materialization-admission.v3.json'
    destination = receipt_directory / 'source-admission.v4.json'
    if destination.exists() or destination.is_symlink():
        raise ReuseError('restored-source-admission-already-recorded')
    previous_metadata = metadata(previous)
    if previous_metadata[2] & 0o222:
        raise ReuseError('restored-source-prior-receipt-mutable')
    bundle = read_json(previous)
    if (bundle.get('schema') != 3 or bundle.get('repository') != str(repository)
            or set(bundle.get('phases', {})) != {'bridge', 'golden'}
            or bundle.get('unresolvedSourceMetadata') != {
                'bridge': [relative], 'golden': [relative]}):
        raise ReuseError('restored-source-prior-scope-mismatch')
    blob_ids = set()
    original_metadata = []
    for phase, value in bundle['phases'].items():
        env = environment(value['inputs']['environment'])
        if (value.get('schema') != 3 or value.get('phase') != phase
                or value.get('repository') != str(repository)
                or legacy_receipt_path(phase, env).parent != receipt_directory):
            raise ReuseError('restored-source-phase-scope-mismatch')
        blob = value['historicalSourceBlobs'][relative]
        if not re.fullmatch('[0-9a-f]{40}', blob):
            raise ReuseError('restored-source-invalid-recorded-blob')
        blob_ids.add(blob)
        original_metadata.append(value['inputs']['sources'][relative])
    if len(blob_ids) != 1 or original_metadata[0] != original_metadata[1]:
        raise ReuseError('restored-source-phase-identity-disagreement')
    source = repository / relative
    current_metadata = metadata(source)
    # A restoration may change inode and timestamps; mode, links and length
    # remain exact. Byte equivalence below is the sole new content check.
    def proj(row):
        return [row[0], 0, row[2], row[3], row[4], 0, 0]
    if not persisted_equal(proj(original_metadata[0]), proj(current_metadata), mapping=mapping):
        raise ReuseError('restored-source-nonrestoration-metadata-change')
    blob = next(iter(blob_ids))
    recorded_size = subprocess.run(['git', '-C', str(repository), 'cat-file', '-s', blob],
                                   check=True, capture_output=True, text=True, timeout=30)
    if int(recorded_size.stdout.strip()) != current_metadata[4] or current_metadata[4] > MAX_BYTES:
        raise ReuseError('restored-source-recorded-size-mismatch')
    historical = subprocess.run(['git', '-C', str(repository), 'cat-file', 'blob', blob],
                                check=True, capture_output=True, timeout=30).stdout
    actual = read_bytes(source)
    if actual != historical:
        raise ReuseError('restored-source-bytes-differ-from-recorded-blob')
    consumer = metadata(Path(__file__).resolve())
    for phase, value in bundle['phases'].items():
        value['schema'] = 4
        value['origin'] = {
            'kind': 'restored-source-admission', 'previousOrigin': value['origin'],
            'previousReceipt': str(previous), 'source': relative,
            'historicalGitBlob': blob, 'comparison': 'exact-byte-equality',
            'comparedBytes': len(actual),
            'previousSourceMetadata': value['inputs']['sources'][relative],
            'previousConsumer': value['inputs']['consumer'],
            'note': 'Only restored source metadata and admission consumer renewed; native execution evidence reused.'}
        value['inputs']['sources'][relative] = current_metadata
        value['inputs']['consumer'] = consumer
    bundle['schema'] = 4
    bundle['evidence'][str(previous)] = previous_metadata
    bundle['unresolvedSourceMetadata'] = {'bridge': [], 'golden': []}
    bundle['sourceAdmission'] = {'path': relative, 'historicalGitBlob': blob,
                               'comparison': 'exact-byte-equality', 'comparedBytes': len(actual)}
    if (metadata(source) != current_metadata or metadata(previous) != previous_metadata
            or metadata(Path(__file__).resolve()) != consumer):
        raise ReuseError('restored-source-evidence-changed-during-admission')
    # No native check, package scan, source profile walk or test is invoked.
    temporary = destination.with_name('.source-admission-' + uuid.uuid4().hex + '.json')
    try:
        write_once(temporary, bundle)
        os.link(temporary, destination, follow_symlinks=False)
    finally:
        if temporary.exists():
            temporary.unlink()
    print(json.dumps({'admission': str(destination), 'sourceBinding': 'reconciled',
                      'source': relative, 'historicalGitBlob': blob, 'comparedBytes': len(actual),
                      'comparison': 'exact-byte-equality', 'unresolvedSourceMetadata': bundle['unresolvedSourceMetadata'],
                      'buildsRun': 0, 'testsRun': 0, 'corpusRun': False}, sort_keys=True))



def admit_staged_package(repository, receipt_directory):
    """Admit the existing staging publication; do not run a native verifier."""
    mapping = {}
    previous = receipt_directory / 'source-admission.v4.json'
    destination = receipt_directory / 'package-admission.v5.json'
    if destination.exists() or destination.is_symlink():
        raise ReuseError('package-admission-already-recorded')
    previous_metadata = metadata(previous)
    if previous_metadata[2] & 0o222:
        raise ReuseError('package-admission-previous-mutable')
    bundle = read_json(previous)
    if (bundle.get('schema') != 4 or bundle.get('repository') != str(repository)
            or set(bundle.get('phases', {})) != {'bridge', 'golden'}
            or bundle.get('unresolvedSourceMetadata') != {'bridge': [], 'golden': []}):
        raise ReuseError('package-admission-previous-scope-mismatch')
    golden = bundle['phases']['golden']
    env = environment(golden['inputs']['environment'])
    if legacy_receipt_path('golden', env).parent != receipt_directory:
        raise ReuseError('package-admission-location-mismatch')
    selected = paths(env)
    materialization = Path(env['MACSCOPE_SLEIGH_MATERIALIZATION_ROOT'])
    view_path = materialization.parent.parent / 'VIEW.json'
    # The earlier immutable admission already bound this VIEW and ENTRY.
    if not persisted_equal(bundle['evidence'][str(view_path)], metadata(view_path), mapping=mapping):
        raise ReuseError('package-admission-view-changed')
    view = read_json(view_path)
    if Path(view['view']) / 'materialization' != materialization:
        raise ReuseError('package-admission-view-root-mismatch')
    entry_path = Path(view['entry']) / 'ENTRY.json'
    if not persisted_equal(bundle['evidence'][str(entry_path)], metadata(entry_path), mapping=mapping):
        raise ReuseError('package-admission-entry-changed')
    entry = read_json(entry_path)
    if entry.get('key') != view.get('key') or entry.get('component') != 'sleigh-native-source':
        raise ReuseError('package-admission-cache-scope-mismatch')
    stage_path = selected['stage']
    stage_metadata = metadata(stage_path)
    stage = read_json(stage_path)
    source_manifest = materialization / 'MATERIALIZATION.json'
    if not persisted_equal(golden['inputs']['materialization']['MATERIALIZATION.json'], metadata(source_manifest), mapping=mapping):
        raise ReuseError('package-admission-source-manifest-changed')
    manifest = read_json(source_manifest)
    if (set(stage) != {'schemaVersion', 'destinationName', 'materialization', 'linkInputs',
                      'inputFileListSHA256', 'outputFileListSHA256'}
            or stage['schemaVersion'] != 2 or stage['destinationName'] != 'NativeDecompilerPackage'
            or stage['materialization'] != manifest
            or manifest['package']['treeSha256'] != golden['identities']['materializationTreeSHA256']):
        raise ReuseError('package-admission-staging-provenance-mismatch')
    expected_links = [
        {'relativePath': 'package/lib/libdecomp.a', 'sha256': golden['identities']['decompilerArchiveSHA256']},
        {'relativePath': 'package/lib/libsla.a', 'sha256': golden['identities']['sleighArchiveSHA256']}]
    if stage['linkInputs'] != expected_links:
        raise ReuseError('package-admission-link-identities-mismatch')
    for key in ('inputFileListSHA256', 'outputFileListSHA256'):
        if not re.fullmatch('[0-9a-f]{64}', stage[key]):
            raise ReuseError('package-admission-invalid-recorded-file-list-digest')
    package = selected['package']
    files, directories = {}, {str(package): directory_metadata(package)}
    rows = {}
    for row in entry['payload_records']:
        name = row['path']
        if not name.startswith('materialization/'):
            continue
        relative = name.removeprefix('materialization/')
        part = Path(relative)
        if part.is_absolute() or str(part) != relative or '..' in part.parts or relative == '.' or relative in rows:
            raise ReuseError('package-admission-invalid-recorded-path')
        rows[relative] = row
        if row['kind'] == 'directory':
            directories[str(package / relative)] = directory_metadata(package / relative)
        elif row['kind'] == 'file':
            observed = metadata(package / relative)
            if observed[4] != row['size'] or bool(observed[2] & 0o111) != row['executable']:
                raise ReuseError('package-admission-staged-file-metadata-mismatch')
            files[relative] = observed
        else:
            raise ReuseError('package-admission-invalid-record-kind')
    for link in expected_links:
        if (rows[link['relativePath']]['kind'] != 'file'
                or rows[link['relativePath']]['sha256'] != link['sha256']):
            raise ReuseError('package-admission-entry-link-identity-mismatch')
    if set(files) != set(golden['outputs']['stagedPackage']):
        raise ReuseError('package-admission-staged-membership-mismatch')
    if read_json(package / 'MATERIALIZATION.json') != stage['materialization']:
        raise ReuseError('package-admission-staged-manifest-mismatch')
    extra_evidence = {}
    for suffix, prefix in (('inputs', materialization), ('outputs', package)):
        file_list = stage_path.parent / ('NativeDecompilerPackage.' + suffix + '.xcfilelist')
        captured = metadata(file_list)
        values = read_bytes(file_list).decode().splitlines()
        expected_paths = {str(prefix / name) for name in files}
        if len(values) != len(expected_paths) or set(values) != expected_paths:
            raise ReuseError('package-admission-file-list-membership-mismatch')
        extra_evidence[str(file_list)] = captured
    for name in ('NativeDecompilerPackageInputs.xcfilelist', 'NativeDecompilerPackageOutputs.xcfilelist'):
        path = repository / 'Scripts/native-decompiler-xpc' / name
        extra_evidence[str(path)] = metadata(path)
    # Execution artifacts and source/toolchain bindings are never renewed here.
    for phase, value in bundle['phases'].items():
        for path, old in value['outputs'].items():
            if phase == 'golden' and path in (str(stage_path), 'stagedPackage'):
                continue
            if not persisted_equal(old, metadata(Path(path)), mapping=mapping):
                raise ReuseError('package-admission-native-output-changed')
        value['schema'] = 5
        value['origin'] = {'kind': 'package-output-admission', 'previousOrigin': value['origin'],
                           'previousReceipt': str(previous), 'stageReceipt': str(stage_path),
                           'previousConsumer': value['inputs']['consumer'],
                           'note': 'Existing stage publication and admitted package identities reused; no native verification or execution.'}
        value['inputs']['consumer'] = metadata(Path(__file__).resolve())
    golden['origin']['previousStageMetadata'] = golden['outputs'][str(stage_path)]
    golden['origin']['previousStagedPackageMetadata'] = golden['outputs']['stagedPackage']
    golden['outputs'][str(stage_path)] = stage_metadata
    golden['outputs']['stagedPackage'] = files
    # Replace only the staged subtree's directory bindings; old values remain
    # in the immutable previous receipt. Source-view directories stay intact.
    bundle['directories'] = {name: row for name, row in bundle['directories'].items()
                             if not Path(name).is_relative_to(package)}
    bundle['directories'].update(directories)
    bundle['evidence'].update(extra_evidence)
    bundle['evidence'][str(previous)] = previous_metadata
    bundle['schema'] = 5
    bundle['packageAdmission'] = {'stageReceipt': str(stage_path), 'sourceEntry': str(entry_path),
        'materializationTreeSHA256': manifest['package']['treeSha256'],
        'fileCount': len(files),
        'historicalGoldenManifestSHA256': golden['identities']['materializationManifestSHA256'],
        'admittedManifestRecordSHA256': rows['MATERIALIZATION.json']['sha256'],
        'recordedFileListDigests': {key: stage[key] for key in
            ('inputFileListSHA256', 'outputFileListSHA256')},
        'authority': 'Existing completed staging record and previously admitted cache ENTRY; metadata only for payload files.'}
    if (metadata(previous) != previous_metadata or metadata(stage_path) != stage_metadata
            or not persisted_equal(golden['inputs']['materialization']['MATERIALIZATION.json'], metadata(source_manifest), mapping=mapping)
            or metadata(Path(__file__).resolve()) != golden['inputs']['consumer']
            or recorded_metadata(package, files) != files):
        raise ReuseError('package-admission-publication-changed')
    for path in (str(view_path), str(entry_path)):
        if not persisted_equal(bundle['evidence'][path], metadata(Path(path)), mapping=mapping):
            raise ReuseError('package-admission-evidence-changed')
    for path, row in extra_evidence.items():
        if metadata(Path(path)) != row:
            raise ReuseError('package-admission-evidence-changed')
    for path, row in directories.items():
        if directory_metadata(Path(path)) != row:
            raise ReuseError('package-admission-directory-changed')
    temporary = destination.with_name('.package-admission-' + uuid.uuid4().hex + '.json')
    try:
        write_once(temporary, bundle)
        os.link(temporary, destination, follow_symlinks=False)
    finally:
        if temporary.exists():
            temporary.unlink()
    print(json.dumps({'admission': str(destination), 'packageBinding': 'reconciled',
                      'recordedFiles': len(files), 'nativeVerificationRun': False,
                      'buildsRun': 0, 'testsRun': 0, 'corpusRun': False}, sort_keys=True))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=('check', 'record', 'adopt', 'upgrade', 'admit-materialization', 'admit-restored-source', 'admit-staged-package', 'abandon'))
    parser.add_argument('--repository-root', type=Path, required=True)
    parser.add_argument('--phase', choices=('bridge', 'golden', 'package'))
    parser.add_argument('--activity-log', type=Path)
    parser.add_argument('--run-log', type=Path)
    parser.add_argument('--successful-head')
    parser.add_argument('--successful-exit-code', type=int)
    parser.add_argument('--receipt-directory', type=Path)
    parser.add_argument('--old-view', type=Path)
    parser.add_argument('--new-view', type=Path)
    args = parser.parse_args(argv)
    try:
        repository = args.repository_root.resolve(strict=True)
        if args.command == 'admit-staged-package':
            if args.receipt_directory is None:
                raise ReuseError('package-admission-requires-receipt-directory')
            admit_staged_package(repository, args.receipt_directory.resolve(strict=True))
        elif args.command == 'admit-restored-source':
            if args.receipt_directory is None:
                raise ReuseError('restored-source-admission-requires-receipt-directory')
            admit_restored_source(repository, args.receipt_directory.resolve(strict=True))
        elif args.command == 'admit-materialization':
            if None in (args.receipt_directory, args.old_view, args.new_view):
                raise ReuseError('admission-requires-directory-and-both-views')
            admit_materialization(repository, args.receipt_directory.resolve(strict=True),
                                  args.old_view.absolute(), args.new_view.absolute())
        elif args.command == 'adopt':
            if None in (args.activity_log, args.run_log, args.successful_head, args.successful_exit_code):
                raise ReuseError('adoption-requires-explicit-successful-evidence')
            adopt(repository, args.activity_log, args.run_log, args.successful_head, args.successful_exit_code)
        elif args.command == 'upgrade':
            if args.receipt_directory is None:
                raise ReuseError('upgrade-requires-receipt-directory')
            upgrade(repository, args.receipt_directory.resolve(strict=True))
        elif not args.phase:
            raise ReuseError('phase-required')
        elif args.command == 'check':
            return check(repository, args.phase, dict(os.environ))
        elif args.command == 'abandon':
            abandon(repository, args.phase, dict(os.environ))
        else:
            record(repository, args.phase, dict(os.environ))
        return 0
    except (OSError, ValueError, KeyError, TypeError, ReuseError, subprocess.SubprocessError) as error:
        print(f'ERROR: native phase reuse: {error}; no automatic rerun allowed', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
