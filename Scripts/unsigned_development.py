#!/usr/bin/env python3
"""Explicit unsigned Debug builds using already accepted local preparation.

This path is never a release, archive, signing or qualification entry point.
It reuses recorded dependencies; it cannot produce or requalify a dependency.
"""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import importlib.util
import json
import os
import plistlib
from pathlib import Path
import shutil
import stat
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / 'lib'))
from work_root import work_root as macscope_work_root  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'Scripts'))

PHASES = {
    'Verify certificate-backed signing environment': 'guard',
    'Stage verified Ghostty surface build inputs': 'surface',
    'Build repository-owned Ghostty VT': 'vt',
    'Stage cached parser engines': 'parsers',
    'Verify canonical embedded REA resource': 'rea',
    'Verify exact MachOKit source materialization': 'machokit',
    'Build verified native decompiler bridge': 'bridge',
    'Stage verified native decompiler package': 'package',
    'Validate native decompiler bridge golden': 'golden',
    'Generate sealed Release build provenance': 'development-record',
}
# Dependency and verifier declarations must match the accepted donor. App/UI
# source is deliberately excluded: it is compiled freshly by the real target.
CONTRACT_PATHS = ('ThirdParty', 'Tools/NativeDecompilerBridge',
                  'Scripts/dependencies', 'Scripts/native-decompiler-xpc',
                  'Scripts/native-decompiler-direct', 'Scripts/machokit_source_identity.py',
                  'MacScope/DependencyRoots.xcconfig', 'MacScope/SigningIdentity.xcconfig',
                  'MacScope/project.yml', 'MacScope/ParserEngines')


def git(root, *args):
    return subprocess.check_output(['/usr/bin/git', '-C', str(root), *args], text=True).strip()


def specification(text):
    """Replace only development consumers; the authored release spec is untouched."""
    lines = text.splitlines(keepends=True)
    result, name, index = [], '', 0
    while index < len(lines):
        line = lines[index]
        if line.startswith('      - name: '):
            name = line.split(': ', 1)[1].strip()
        # Unsigned products have no CodeResources. This input belongs only to
        # the replaced sealed-provenance phase, never to release generation.
        if '/Contents/_CodeSignature/CodeResources' in line:
            index += 1
            continue
        if line == '        script: |\n' and name in PHASES:
            result.append(line)
            phase = PHASES[name]
            result.append('          /usr/bin/python3 -B "$SRCROOT/../Scripts/unsigned_development.py" phase --phase ' + phase + '\n')
            index += 1
            while index < len(lines) and (lines[index].startswith('          ') or not lines[index].strip()):
                index += 1
            continue
        result.append(line)
        index += 1
    return ''.join(result)


def load(path):
    return json.loads(Path(path).read_text())


def guard(environment):
    import check_local_signing_policy as policy
    errors = policy.validate_build_environment(environment)
    if environment.get('MACSCOPE_DEV_UNSIGNED') != 'YES':
        errors.append('development-generated project requires explicit unsigned opt-in')
    if errors:
        raise ValueError('; '.join(errors))
    admission_path = environment.get('MACSCOPE_DEV_UNSIGNED_ADMISSION')
    if not admission_path:
        raise ValueError('development admission is missing')
    admission = load(admission_path)
    if admission.get('repository') != str(ROOT):
        raise ValueError('development admission belongs to another checkout')
    validate_development_generation(ROOT / 'MacScope', admission['generation'])


def copy(source, destination):
    """Copy admitted bytes while keeping only build-owned directories writable."""
    source, destination = Path(source), Path(destination)
    if not source.exists() or destination.is_symlink():
        raise ValueError(f'missing retained input or indirect output: {source} -> {destination}')
    admission_path = os.environ.get('MACSCOPE_DEV_UNSIGNED_ADMISSION')
    if admission_path:
        allowed = Path(admission_path).resolve().parent
        if allowed not in destination.resolve().parents:
            raise ValueError('development copy must remain in its admitted output root')
    if source.is_dir():
        destination.mkdir(parents=True, exist_ok=True)
        destination.chmod(0o700)
        for child in source.iterdir():
            copy(child, destination / child.name)
    else:
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.parent.chmod(0o700)
        if destination.exists():
            destination.unlink()
        shutil.copy2(source, destination, follow_symlinks=True)


def select_retained_tool_identity(observed, candidates):
    """Reuse a recorded identity across a coherent device-number transition only.

    Every canonical path, inode, size and timestamp remains exact. This consumes
    existing identity evidence; it neither proves payload bytes again nor admits
    a compiler/SDK change. Partial transitions and conflicting identities refuse.
    """
    def valid(rows):
        return (isinstance(rows, list) and bool(rows)
                and all(isinstance(row, list) and len(row) == 7
                        and all(isinstance(v, str) and v for v in row[:2])
                        and all(type(v) is int for v in row[2:]) for row in rows)
                and len({row[0] for row in rows}) == len(rows))

    if not valid(observed):
        raise ValueError('invalid current tool metadata')
    admitted = []
    for candidate in candidates:
        before, identity = candidate.get('observed'), candidate.get('identity')
        if (not valid(before) or len(before) != len(observed)
                or not isinstance(identity, str) or len(identity) != 64
                or any(c not in '0123456789abcdef' for c in identity)):
            continue
        if any(a[:2] != b[:2] or a[3:] != b[3:] for a, b in zip(before, observed)):
            continue
        changed = before != observed
        if changed:
            pairs = {(a[2], b[2]) for a, b in zip(before, observed)}
            if len(pairs) != 1 or next(iter(pairs))[0] == next(iter(pairs))[1]:
                continue
        admitted.append(dict(identity=identity, source_memo=candidate['source_memo'],
                             prior_observed=before, current_observed=observed,
                             device_transition=changed))
    if not admitted or len({row['identity'] for row in admitted}) != 1:
        raise ValueError('retained exact or coherent-device-only tool identity required; no verification fallback')
    return admitted[0]


def retained_external_identity(cache, files, view_root, receipts):
    observed = []
    for name, raw in files:
        path = Path(raw).resolve(strict=True)
        item = path.stat()
        observed.append([name, str(path), item.st_dev, item.st_ino, item.st_size,
                         item.st_mtime_ns, item.st_ctime_ns])
    for prior in receipts:
        if prior['current_observed'] == observed:
            return prior['identity']
    # Read only bounded, owner-controlled memo declarations through the existing
    # cache reader. No global memo is rewritten or manufactured for the new device.
    paths = sorted((view_root / '.memo').glob('identity-*.json'))
    if len(paths) > 4_096:
        raise ValueError('tool identity memo limit exceeded')
    candidates = []
    for path in paths:
        if path.lstat().st_size > 256 * 1024:
            continue
        value = cache.read_memo(path)
        if isinstance(value, dict):
            candidates.append(dict(value, source_memo=str(path)))
    selected = select_retained_tool_identity(observed, candidates)
    receipts.append(selected)
    return selected['identity']


def admit_retained_view(cache, receipt, entry, view, component, key):
    """Use the existing locked legacy-stamp migration, with no rebuild branch."""
    if component == 'sleigh-native-source':
        # Occupied SLEIGH has its own G/L/F ownership protocol and forbids
        # creating missing stamps through the generic legacy-view migration.
        occupied = cache.sleigh_occupied_view(entry.parents[3], receipt.parents[2], key)
        return occupied['receipt'], False
    component_root = receipt.parent.parent
    descriptor = os.open(component_root / ('.' + key + '.lock'),
                         os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        value = cache.view_receipt_structure_valid(receipt, entry, view, component, key)
        if value is None:
            raise ValueError('accepted unchanged dependency view required: ' + component)
        state = cache.view_stamp_state(receipt, view)
        if state not in ('valid', 'missing'):
            raise ValueError('dependency stamps changed; no repair or verification fallback: ' + component)
        if state == 'missing':
            cache.write_view_stamps(receipt, view)
        return value, state == 'missing'
    finally:
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def machokit_device_transition(saved, current, rows, prior_device):
    """Compare captured metadata only; never read or modify dependency content."""
    if (type(prior_device) is not int or prior_device <= 0 or not rows
            or any(not isinstance(row, list) or len(row) != 7
                   or not isinstance(row[0], str)
                   or any(type(value) is not int for value in row[1:]) for row in rows)):
        raise ValueError('invalid captured MachOKit device metadata')
    paths = [row[0] for row in rows]
    devices = {row[1] for row in rows}
    if (paths[0] != '.' or len(set(paths)) != len(paths) or len(devices) != 1
            or prior_device in devices
            or any(Path(path).is_absolute() or '..' in Path(path).parts for path in paths)):
        raise ValueError('MachOKit device transition is not uniform and closed')
    fingerprint = lambda value: hashlib.sha256(json.dumps(value, separators=(',', ':')).encode()).hexdigest()
    previous = [[row[0], prior_device, *row[2:]] for row in rows]
    if (fingerprint(rows) != current.get('metadata_sha256')
            or dict(current, metadata_sha256=fingerprint(previous)) != saved):
        raise ValueError('MachOKit metadata differs beyond the recorded device transition')
    return {'prior_device': prior_device, 'current_device': next(iter(devices)),
            'prior_metadata_sha256': saved['metadata_sha256'],
            'current_metadata_sha256': current['metadata_sha256'], 'rows': len(rows)}


def stable_file_metadata(value):
    return tuple(getattr(value, name) for name in
                 ('st_dev', 'st_ino', 'st_mode', 'st_nlink', 'st_size',
                  'st_mtime_ns', 'st_ctime_ns', 'st_uid'))


def retained_machokit_transition(path, root, saved, current):
    original = root.parent / ('.' + root.name + '.admission.json')
    before = original.lstat()
    if (original.resolve(strict=True) != original or not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid() or before.st_nlink != 1 or before.st_mode & 0o222
            or before.st_size > 65536 or load(original) != saved
            or stable_file_metadata(original.lstat()) != stable_file_metadata(before)):
        raise ValueError('original MachOKit admission must remain immutable and unchanged')
    metadata = path.lstat()
    if (path.resolve(strict=True) != path or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != os.getuid() or metadata.st_nlink != 1
            or metadata.st_mode & 0o222 or metadata.st_size > 1024 * 1024):
        raise ValueError('captured MachOKit transition must be an immutable owner-controlled record')
    captured = load(path)
    if stable_file_metadata(path.lstat()) != stable_file_metadata(metadata):
        raise ValueError('captured MachOKit transition changed while reading')
    if (captured.get('completed') is not True or captured.get('prior_match') is not True
            or captured.get('root') != str(root) or captured.get('current_identity') != current):
        raise ValueError('captured MachOKit metadata does not cover the current view')
    historical = load(Path(captured['historical_tool_memo']))
    observed = historical.get('observed')
    if (not isinstance(observed, list) or not observed
            or any(not isinstance(row, list) or len(row) != 7 for row in observed)
            or {row[2] for row in observed} != {captured['prior_device']}):
        raise ValueError('MachOKit prior device lacks its historical tool memo')
    return machokit_device_transition(saved, current, captured['rows'], captured['prior_device'])


def completed_golden(path, repository, helper, identity, current_tools):
    """Consume an existing completed runner record without executing validation."""
    if path.resolve(strict=True) != path:
        raise ValueError('completed golden receipt must be canonical')
    saved = helper.owned_receipt(path)
    result = Path(saved['resultPath'])
    result_metadata = helper.ordinary(result)
    before = helper.fields(result_metadata)
    value = load(result)
    source = saved.get('source', {})
    if (path != helper.completed_path(path.parent, result)
            or result.resolve(strict=True) != result
            or result_metadata.st_uid != os.getuid()
            or saved.get('version') != 1 or before != saved.get('resultMetadata')
            or value != saved.get('result') or value.get('passed') is not True
            or value.get('schemaVersion') != 1
            or source.get('repository') != str(repository) or source.get('profile') != 'golden'
            or source.get('sha256') != value.get('goldenSourceSHA256')
            or source.get('files') != identity._profile_snapshot(repository, identity.profile_paths(repository, 'golden'))
            or saved.get('tools') != current_tools
            or stable_file_metadata(helper.ordinary(result)) != stable_file_metadata(result_metadata)):
        raise ValueError('completed golden result/source/tool receipt differs')
    return value


def prepare(donor, donor_derived, output):
    donor, donor_derived = donor.resolve(strict=True), donor_derived.resolve(strict=True)
    workspace = str(donor / 'MacScope/MacScope.xcodeproj')
    if plistlib.loads((donor_derived / 'info.plist').read_bytes()).get('WorkspacePath') != workspace:
        raise ValueError('retained DerivedData belongs to another checkout')
    requests = [load(path) for path in (donor_derived / 'Build/Intermediates.noindex/XCBuildData').glob('*.xcbuilddata/build-request.json')]
    if not any(request.get('containerPath') == workspace and
               request.get('parameters', {}).get('configurationName') == 'Debug' and
               request.get('parameters', {}).get('activeArchitecture') == 'arm64' and
               request.get('parameters', {}).get('arenaInfo', {}).get('derivedDataPath') == str(donor_derived)
               for request in requests):
        raise ValueError('retained Debug/arm64 build request is missing')
    identities = {}
    for relative in CONTRACT_PATHS:
        old, new = git(donor, 'rev-parse', 'HEAD:' + relative), git(ROOT, 'rev-parse', 'HEAD:' + relative)
        if old != new:
            raise ValueError('retained development contract differs: ' + relative)
        if git(donor, 'status', '--porcelain', '--untracked-files=no', '--', relative) or git(ROOT, 'status', '--porcelain', '--untracked-files=no', '--', relative):
            raise ValueError('dependency contract has local changes: ' + relative)
        identities[relative] = old
    config = donor / 'MacScope/DependencyRoots.local.xcconfig'
    if not (donor / 'MacScope/MacScope.xcodeproj/.macscope-project-generation.sha256').is_file():
        raise ValueError('donor has no successful preparation receipt')
    settings = {}
    for line in config.read_text().splitlines():
        if line and not line.startswith('//'):
            key, value = line.split(' = ', 1)
            settings[key] = value
    # Consume the existing read-only VIEW receipts, not cache producers.
    helper = ROOT / 'Scripts/qualification/dev_dependency_cache.py'
    spec = importlib.util.spec_from_file_location('unsigned_dependency_cache', helper)
    cache = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(cache)
    # A memo miss must never re-read/re-hash unchanged governed inputs.
    def no_reverification(*_args, **_kwargs):
        raise ValueError('retained source/tool identity memo required; no verification fallback')
    cache.blob_records = no_reverification
    cache.CACHE.external_file_identity = no_reverification
    tool_receipts = []
    cache.external_identity = lambda files, root: retained_external_identity(cache, files, root, tool_receipts)
    view_root = macscope_work_root() / 'MacScopeDevLoop.noindex/dependency-views'
    views, entries, adopted_stamps = {}, {}, []
    for component in ('ghostty-surface', 'ghostty-vt', 'sleigh-native-source', 'native-bridge'):
        key = cache.component_key(component, ROOT, view_root)
        directory = view_root / component / key
        receipt_path = directory / 'VIEW.json'
        receipt = load(receipt_path)
        view = Path(receipt['view'])
        _accepted, adopted = admit_retained_view(cache, receipt_path, Path(receipt['entry']), view, component, key)
        if adopted:
            adopted_stamps.append(dict(component=component, key=key, receipt=str(receipt_path)))
        views[component] = str(view)
        entries[component] = load(Path(receipt['entry']) / 'ENTRY.json')
    # The existing MachOKit admission uses metadata identity and falls closed
    # here rather than falling back to payload verification.
    import machokit_source_identity as machokit
    macho_root = Path(settings['MACSCOPE_MACHOKIT_MATERIALIZATION_ROOT'])
    macho_saved = load(machokit._admission_receipt(macho_root))
    macho_current = machokit._admission_identity(macho_root)
    # Retain the actual use-time outcome even if a later preparation gate fails.
    print('Unsigned MachOKit use-time metadata: ' + json.dumps(macho_current, sort_keys=True), flush=True)
    macho_transition = None
    if macho_saved != macho_current:
        captured = os.environ.get('MACSCOPE_UNSIGNED_MACHOKIT_DEVICE_RECORD')
        if not captured:
            raise ValueError('unchanged MachOKit admission required')
        macho_transition = retained_machokit_transition(Path(captured), macho_root, macho_saved, macho_current)
    donor_build = donor_derived / 'Build/Intermediates.noindex/MacScope.build'
    for target, phase in (('AnalysisWorkerXPCService', 'rea-resource'),
                          ('AnalysisWorkerXPCService', 'machokit-source'),
                          ('NativeDecompilerXPCService', 'native-package-stage')):
        receipt = load(donor_build / 'Debug' / (target + '.build') / 'DerivedSources/MacScopePhaseStamps' / (phase + '.json'))
        if receipt.get('schema') != 1 or receipt.get('phase') != phase or not receipt.get('inputs'):
            raise ValueError('retained successful phase required: ' + phase)
    # Reuse the recorded golden only when its semantic input identities match
    # the accepted immutable bridge/materialization records and donor app record.
    donor_resources = donor_derived / 'Build/Products/Debug/NativeDecompilerXPCService.xpc/Contents/Resources'
    golden_origin = os.environ.get('MACSCOPE_UNSIGNED_GOLDEN_COMPLETION')
    if golden_origin:
        sys.path.insert(0, str(ROOT / 'Scripts/native-decompiler-xpc'))
        import native_golden_receipts as golden_receipts
        import native_decompiler_source_identity as native_identity
        record = Path(golden_origin)
        developer = cache.developer_dir()
        sdk = (developer / 'Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk').resolve(strict=True)
        tools = developer / 'Toolchains/XcodeDefault.xctoolchain/usr/bin'
        files = [('clang', str(tools / 'clang++')), ('swiftc', str(tools / 'swiftc')),
                 ('lipo', str(tools / 'lipo')), ('xcode-version', str(developer.parent / 'version.plist')),
                 ('sdk-settings', str(sdk / 'SDKSettings.plist'))]
        tool_identity = retained_external_identity(cache, files, view_root, tool_receipts)
        golden = completed_golden(record, ROOT, golden_receipts, native_identity, tool_identity)
        donor_golden_bound = True  # completed runner evidence replaces donor provenance only
    else:
        golden = load(donor_resources / 'NativeDecompilerBridgeGolden.json')
        provenance = load(donor_derived / 'Build/Products/Debug/MacScope.app/Contents/Resources/MacScopeBuildProvenance.json')
        donor_golden_bound = provenance.get('native_decompiler_golden_result') == golden
    configuration = load(Path(views['native-bridge']) / 'CONFIGURATION.json')
    bridge_records = {row['path']: row for row in entries['native-bridge']['payload_records']}
    materialization = load(Path(views['sleigh-native-source']) / 'materialization/MATERIALIZATION.json')
    if not (golden.get('passed') is True and donor_golden_bound and
            golden.get('wrapperGitRevision') == configuration['wrapper_revision'] and
            golden.get('materializationManifestSHA256') == configuration['materialization_manifest_sha256'] and
            golden.get('materializationTreeSHA256') == materialization['package']['treeSha256'] and
            golden.get('contractArchiveSHA256') == bridge_records['libmacscope_native_decompiler_contract.a']['sha256']):
        raise ValueError('retained golden does not cover the admitted native inputs')
    # The parser stage receipt names immutable published entries; use those
    # directly instead of trusting mutable donor staging directories.
    parsers = load(donor_build / 'MacScopeParserEngines/STAGED.json')
    parser_roots = {}
    for component, key in parsers['keys'].items():
        entry = Path(parsers['cache_root']) / 'artifacts/v1' / component / key
        manifest = load(entry / 'ENTRY.json')
        payload = entry / 'payload'
        observed, _size = cache.CACHE.payload_records(payload, hash_files=False, allow_hardlinks=True)
        expected = [{k: v for k, v in row.items() if k != 'sha256'} for row in manifest['payload_records']]
        if manifest['component'] != component or manifest['key'] != key or observed != expected:
            raise ValueError('retained parser entry differs: ' + component)
        if any(path.stat().st_mode & 0o222 for path in [payload, *payload.rglob('*')] if not path.is_symlink()):
            raise ValueError('retained parser entry is not read-only')
        parser_roots[component] = str(payload)
    output.parent.mkdir(parents=True, exist_ok=True)
    value = {'schema': 1, 'repository': str(ROOT), 'donor': str(donor),
             'donor_derived': str(donor_derived), 'source_ids': identities, 'views': views,
             'entries': entries, 'golden': golden, 'golden_completion': golden_origin,
             'parser_roots': parser_roots, 'parser_stage': parsers,
             'retained_tool_identity_receipts': tool_receipts,
             'machokit_device_transition': macho_transition,
             'legacy_view_stamp_adoptions': adopted_stamps}
    output.write_text(json.dumps(value, indent=2) + '\n')
    settings['MACSCOPE_SLEIGH_COMPONENT_ROOT'] = str(ROOT / 'ThirdParty/SleighNative')
    (ROOT / 'MacScope/DependencyRoots.local.xcconfig').write_text(''.join(f'{k} = {v}\n' for k, v in settings.items()))
    local = ROOT / 'MacScope/LocalPackages'
    if local.is_symlink():
        if local.resolve() != macho_root:
            raise ValueError('existing LocalPackages points at a different input')
    elif not local.exists():
        local.symlink_to(macho_root, target_is_directory=True)
    else:
        raise ValueError('LocalPackages already exists without the accepted link')
    value['generation'] = generate_development_project(ROOT / 'MacScope')
    output.write_text(json.dumps(value, indent=2) + '\n')
    print('Reused accepted dependency and source-phase receipts; generated unsigned-development project.')


def file_identity(path, *, symlink=False):
    value = path.lstat()
    if symlink:
        if not stat.S_ISLNK(value.st_mode):
            raise ValueError('expected admitted package symlink: ' + str(path))
    elif not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
        raise ValueError('expected ordinary generation input: ' + str(path))
    fields = [value.st_dev, value.st_ino, value.st_mode, value.st_uid,
              value.st_gid, getattr(value, 'st_flags', 0), value.st_nlink,
              value.st_size, value.st_mtime_ns, value.st_ctime_ns]
    if symlink:
        target = path.resolve(strict=True).stat()
        return {'link': fields, 'target': os.readlink(path),
                'target_identity': [target.st_dev, target.st_ino, target.st_mode, target.st_uid, target.st_gid]}
    return fields


def generation_inputs(source):
    relatives = ('project.yml', 'DependencyRoots.xcconfig', 'SigningIdentity.xcconfig',
                 'DependencyRoots.local.xcconfig', '../ThirdParty/SleighNative/PATCHED_RESOURCES.json',
                 '../Scripts/unsigned_development.py', '../Scripts/generate_xcode_json_project.py')
    return {relative: file_identity(source / relative) for relative in relatives}


def generate_development_project(source):
    from generate_xcode_json_project import generate
    from project_freshness import generated_project_source_paths
    project = source / 'project.yml'
    before, paths = generation_inputs(source), generated_project_source_paths(project)
    link = file_identity(source / 'LocalPackages', symlink=True)
    generate(source, unsigned_development=True)
    if before != generation_inputs(source) or paths != generated_project_source_paths(project) or link != file_identity(source / 'LocalPackages', symlink=True):
        raise ValueError('development generation inputs changed during generation')
    return {'inputs': before, 'source_paths': paths, 'packages': link,
            'project': file_identity(source / 'MacScope.xcodeproj/project.xcproj'),
            'marker': file_identity(source / 'MacScope.xcodeproj/.unsigned-development')}


def validate_development_generation(source, receipt):
    from project_freshness import generated_project_source_paths
    observed = {'inputs': generation_inputs(source),
                'source_paths': generated_project_source_paths(source / 'project.yml'),
                'packages': file_identity(source / 'LocalPackages', symlink=True),
                'project': file_identity(source / 'MacScope.xcodeproj/project.xcproj'),
                'marker': file_identity(source / 'MacScope.xcodeproj/.unsigned-development')}
    if observed != receipt:
        raise ValueError('development generated project, source membership or input metadata changed; regenerate explicitly')


def phase(name):
    env = dict(os.environ)
    guard(env)
    if name == 'guard':
        return
    admission = load(env['MACSCOPE_DEV_UNSIGNED_ADMISSION'])
    if admission['repository'] != str(ROOT):
        raise ValueError('development admission belongs to another checkout')
    for relative, identity in admission['source_ids'].items():
        if git(ROOT, 'rev-parse', 'HEAD:' + relative) != identity:
            raise ValueError('development source contract changed: ' + relative)
    donor_derived = Path(admission['donor_derived'])
    donor_temp = donor_derived / 'Build/Intermediates.noindex/MacScope.build'
    donor_products = donor_derived / 'Build/Products/Debug'
    views = {k: Path(v) for k, v in admission['views'].items()}
    resources = Path(env['TARGET_BUILD_DIR']) / env['UNLOCALIZED_RESOURCES_FOLDER_PATH']
    if name in ('rea', 'machokit'):
        print('Reusing accepted unchanged ' + name + ' source evidence')
    elif name == 'surface':
        surface = views['ghostty-surface']
        artifact = surface / 'macos/GhosttyKit.xcframework/macos-arm64'
        destination = Path(env['MACSCOPE_GHOSTTY_SURFACE_STAGED_ROOT'])
        descriptor = {'schema_version': 1, 'leaves': []}
        records = {row['path']: row for row in admission['entries']['ghostty-surface']['payload_records']}
        descriptor['source_manifest_sha256'] = records['macos/.macscope-ghostty-surface-manifest']['sha256']
        for role, relative in (('archive', 'libghostty-internal.a'), ('header', 'Headers/ghostty.h'), ('module_map', 'Headers/module.modulemap')):
            source = artifact / relative
            copy(source, destination / relative)
            descriptor['leaves'].append({'role': role, 'relative_path': relative, 'sha256': records[source.relative_to(surface).as_posix()]['sha256']})
        (destination / 'STAGED_GHOSTTY_SURFACE.json').write_text(json.dumps(descriptor, sort_keys=True) + '\n')
    elif name == 'vt':
        copy(views['ghostty-vt'] / 'artifacts', Path(env['MACSCOPE_GHOSTTY_VT_BUILD_ROOT']) / 'artifacts')
        copy(views['ghostty-vt'] / 'artifacts/lib/libghostty-vt.dylib', Path(env['TARGET_BUILD_DIR']) / env['FRAMEWORKS_FOLDER_PATH'] / 'libghostty-vt.dylib')
    elif name == 'parsers':
        destination = Path(env['MACSCOPE_PARSER_ENGINES_ROOT'])
        for component, source in admission['parser_roots'].items():
            copy(source, destination / component)
        (destination / 'STAGED.json').write_text(json.dumps(admission['parser_stage'], sort_keys=True) + '\n')
    elif name == 'bridge':
        destination = Path(env['MACSCOPE_NATIVE_DECOMPILER_BUILD_ROOT'])
        copy(views['native-bridge'], destination)
        links = destination / 'macscope-native-decompiler-link-inputs.xcfilelist'
        links.write_text(str(destination / 'libmacscope_native_decompiler_contract.a') + '\n')
    elif name in ('package', 'golden'):
        donor_resources = donor_products / 'NativeDecompilerXPCService.xpc/Contents/Resources'
        if name == 'package':
            copy(views['sleigh-native-source'] / 'materialization', resources / 'NativeDecompilerPackage')
            copy(donor_temp / 'Debug/NativeDecompilerXPCService.build/NativeDecompilerPackageStage', Path(env['TARGET_TEMP_DIR']) / 'NativeDecompilerPackageStage')
        else:
            resources.mkdir(parents=True, exist_ok=True)
            (resources / 'NativeDecompilerBridgeGolden.json').write_text(json.dumps(admission['golden'], sort_keys=True, separators=(',', ':')) + '\n')
    elif name == 'development-record':
        resources.mkdir(parents=True, exist_ok=True)
        (resources / 'MacScopeBuildProvenance.json').write_text(json.dumps({'kind': 'unsigned-development', 'qualification': 'not-performed', 'source_commit': git(ROOT, 'rev-parse', 'HEAD')}) + '\n')
    else:
        raise ValueError('unknown development phase')
    print('Unsigned development phase: ' + name + '; no signing or dependency verification')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    prep = sub.add_parser('prepare')
    prep.add_argument('--prepared-repository', type=Path, required=True)
    prep.add_argument('--prepared-derived-data', type=Path, required=True)
    prep.add_argument('--admission', type=Path, required=True)
    consumer = sub.add_parser('phase')
    consumer.add_argument('--phase', choices=tuple(PHASES.values()), required=True)
    args = parser.parse_args()
    if args.command == 'prepare':
        prepare(args.prepared_repository, args.prepared_derived_data, args.admission)
    else:
        phase(args.phase)

if __name__ == '__main__':
    main()
