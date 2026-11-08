#!/usr/bin/env python3
"""Synthetic-only tests for completed native execution reuse."""
import gzip
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


def real_temporary_directory(prefix):
    """TemporaryDirectory under the resolved temp root (macOS /var -> /private/var)."""
    return tempfile.TemporaryDirectory(prefix=prefix, dir=os.path.realpath(tempfile.gettempdir()))

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location('native_phase_reuse', ROOT / 'Scripts/native-decompiler-xpc/native_phase_reuse.py')
reuse = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(reuse)


class PersistedEqualTests(unittest.TestCase):
    def testEqualValues(self):
        self.assertTrue(reuse.persisted_equal({'a': [1, 11, 12, 13, 14, 15, 16], 'b': 'same'},
                                             {'a': [1, 11, 12, 13, 14, 15, 16], 'b': 'same'}))

    def testDeviceOnlyDifference(self):
        self.assertTrue(reuse.persisted_equal([1, 11, 12, 13, 14, 15, 16], [2, 11, 12, 13, 14, 15, 16]))

    def testEveryNondeviceFieldRemainsExact(self):
        for index, field in enumerate(reuse.FIELDS[1:], 1):
            with self.subTest(field=field):
                observed = [2, 11, 12, 13, 14, 15, 16]
                observed[index] += 1
                self.assertFalse(reuse.persisted_equal([1, 11, 12, 13, 14, 15, 16], observed))

    def testTwoOldDevicesCannotShareNewDevice(self):
        self.assertFalse(reuse.persisted_equal(
            {'a': [1, 11, 12, 13, 14, 15, 16], 'b': [3, 11, 12, 13, 14, 15, 16]},
            {'a': [2, 11, 12, 13, 14, 15, 16], 'b': [2, 11, 12, 13, 14, 15, 16]}))

    def testOneOldDeviceCannotSplit(self):
        self.assertFalse(reuse.persisted_equal(
            {'a': [1, 11, 12, 13, 14, 15, 16], 'b': [1, 11, 12, 13, 14, 15, 16]},
            {'a': [2, 11, 12, 13, 14, 15, 16], 'b': [3, 11, 12, 13, 14, 15, 16]}))

    def testIdentityPairCannotSplit(self):
        self.assertFalse(reuse.persisted_equal(
            {'a': [5, 11, 12, 13, 14, 15, 16], 'b': [5, 11, 12, 13, 14, 15, 16]},
            {'a': [5, 11, 12, 13, 14, 15, 16], 'b': [6, 11, 12, 13, 14, 15, 16]}))

    def testIdentityPairReservesItsTarget(self):
        self.assertFalse(reuse.persisted_equal(
            {'a': [5, 11, 12, 13, 14, 15, 16], 'b': [7, 11, 12, 13, 14, 15, 16]},
            {'a': [5, 11, 12, 13, 14, 15, 16], 'b': [5, 11, 12, 13, 14, 15, 16]}))

    def testKeySetsRemainExact(self):
        self.assertFalse(reuse.persisted_equal({'a': 1}, {'b': 1}))

    def testNonmetadataListsAreNotTraversed(self):
        self.assertFalse(reuse.persisted_equal([[1, 11, 12, 13, 14, 15, 16]],
                                              [[2, 11, 12, 13, 14, 15, 16]]))
        self.assertFalse(reuse.persisted_equal([1, 2], [2, 2]))

    def testSharedAccumulatorCommitsOnlySuccess(self):
        mapping = {}
        self.assertTrue(reuse.persisted_equal([1, 11, 12, 13, 14, 15, 16], [2, 11, 12, 13, 14, 15, 16], mapping=mapping))
        self.assertEqual(mapping, {1: 2})
        self.assertFalse(reuse.persisted_equal([1, 11, 12, 13, 14, 15, 16], [3, 11, 12, 13, 14, 15, 16], mapping=mapping))
        self.assertEqual(mapping, {1: 2})
        self.assertFalse(reuse.persisted_equal([4, 11, 12, 13, 14, 15, 16], [2, 11, 12, 13, 14, 15, 16], mapping=mapping))
        self.assertEqual(mapping, {1: 2})
        self.assertTrue(reuse.persisted_equal([1, 11, 12, 13, 14, 15, 16], [2, 11, 12, 13, 14, 15, 16], mapping=mapping))
        self.assertEqual(mapping, {1: 2})

    def testStructuralFailureRollsBackEarlierPairs(self):
        mapping = {8: 9}
        self.assertFalse(reuse.persisted_equal(
            {'a': [1, 11, 12, 13, 14, 15, 16], 'z': 'old'},
            {'a': [2, 11, 12, 13, 14, 15, 16], 'z': 'new'}, mapping=mapping))
        self.assertEqual(mapping, {8: 9})

    def testBoolHasMetadataShapeAndOneSidedShapeStaysUnequal(self):
        self.assertTrue(reuse.persisted_equal([True, 11, 12, 13, 14, 15, 16], [2, 11, 12, 13, 14, 15, 16]))
        self.assertFalse(reuse.persisted_equal([1, 11, 12, 13, 14, 15, 16], [2, 11, 12, 13, 14, 15, '16']))

    def testMultipleVolumesAndExistingInvalidMapping(self):
        mapping = {}
        self.assertTrue(reuse.persisted_equal(
            {'a': [1, 11, 12, 13, 14, 15, 16], 'b': [3, 11, 12, 13, 14, 15, 16]},
            {'a': [2, 11, 12, 13, 14, 15, 16], 'b': [4, 11, 12, 13, 14, 15, 16]}, mapping=mapping))
        self.assertEqual(mapping, {1: 2, 3: 4})
        invalid = {1: 2, 3: 2}
        self.assertFalse(reuse.persisted_equal({}, {}, mapping=invalid))
        self.assertEqual(invalid, {1: 2, 3: 2})


class NativePhaseReuseTests(unittest.TestCase):
    def setUp(self):
        self.temporary = real_temporary_directory('native-phase-reuse-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.env = {key: 'value' for key in reuse.ENV_KEYS}
        self.env.update(CONFIGURATION='Debug', MACSCOPE_DEBUG_SOURCE_IDENTITY='runtime-only',
                        PROJECT_TEMP_DIR=str(self.root), MACSCOPE_NATIVE_DECOMPILER_BUILD_ROOT=str(self.root / 'bridge'),
                        TARGET_BUILD_DIR=str(self.root / 'products'), UNLOCALIZED_RESOURCES_FOLDER_PATH='resources',
                        TARGET_TEMP_DIR=str(self.root / 'target'))
        self.source = self.root / 'source.cpp'
        self.source.write_text('original source')
        self.output = self.root / 'output.a'
        self.output.write_text('completed output')
        self.inputs = patch.object(reuse, 'input_snapshot', side_effect=lambda repository, phase, env:
                                  {'environment': env, 'sources': {'source.cpp': reuse.metadata(self.source)}})
        self.outputs = patch.object(reuse, 'output_snapshot', side_effect=lambda phase, env:
                                   {str(self.output): reuse.metadata(self.output)})
        self.ids = patch.object(reuse, 'identities', return_value={'wrapperSourceSHA256': 'a' * 64, 'nativeTests': 28})
        for item in (self.inputs, self.outputs, self.ids):
            item.start()
            self.addCleanup(item.stop)

    def receipt(self, phase='bridge'):
        env = reuse.environment(self.env)
        reuse.write_once(reuse.receipt_path(phase, env), {
            'schema': 1, 'repository': str(self.root), 'phase': phase,
            'inputs': reuse.input_snapshot(self.root, phase, env),
            'outputs': reuse.output_snapshot(phase, env),
            'origin': {'kind': 'adopted-historical-execution'}})

    def receipt_with_device(self, phase, device, output_device=None, size_delta=0):
        env = reuse.environment(self.env)
        document = {
            'schema': 1, 'repository': str(self.root), 'phase': phase,
            'inputs': reuse.input_snapshot(self.root, phase, env),
            'outputs': reuse.output_snapshot(phase, env),
            'origin': {'kind': 'adopted-historical-execution'}}
        for row in reuse.metadata_rows(document):
            row[0] = device
        if output_device is not None:
            document['outputs'][str(self.output)][0] = output_device
        if size_delta:
            document['inputs']['sources']['source.cpp'][4] += size_delta
        self.assertNotEqual(document['inputs'], reuse.input_snapshot(self.root, phase, env))
        reuse.write_once(reuse.receipt_path(phase, env), document)
        return document

    def testRebootDeviceChangeReusesBothPhasesWithoutRunner(self):
        device = reuse.metadata(self.source)[0] + 1
        for phase in ('bridge', 'golden'):
            with self.subTest(phase=phase):
                self.receipt_with_device(phase, device)
                with patch.object(subprocess, 'run', side_effect=AssertionError('must not execute')) as run:
                    self.assertEqual(reuse.check(self.root, phase, self.env), 0)
                    run.assert_not_called()

    def testRebootDeviceChangeDoesNotHideRecordedSizeChange(self):
        device = reuse.metadata(self.source)[0] + 1
        for phase in ('bridge', 'golden'):
            with self.subTest(phase=phase):
                self.receipt_with_device(phase, device, size_delta=1)
                with self.assertRaisesRegex(reuse.ReuseError, 'native-inputs-changed-owner-qualification-required'):
                    reuse.check(self.root, phase, self.env)

    def testRebootDeviceMappingIsSharedAcrossInputsAndOutputs(self):
        device = reuse.metadata(self.source)[0] + 1
        for phase in ('bridge', 'golden'):
            with self.subTest(phase=phase):
                self.receipt_with_device(phase, device, output_device=device + 1)
                with self.assertRaisesRegex(reuse.ReuseError, 'native-outputs-changed-owner-qualification-required'):
                    reuse.check(self.root, phase, self.env)

    def testReusesBothCompletedPhasesWithoutRunner(self):
        for phase in ('bridge', 'golden'):
            self.receipt(phase)
            with patch.object(subprocess, 'run', side_effect=AssertionError('must not execute')):
                self.assertEqual(reuse.check(self.root, phase, self.env), 0)

    def testAbandonRemovesPendingWhenNoOutputExistsThenCheckStartsAgain(self):
        self.output.unlink()
        env = dict(self.env)
        self.assertEqual(reuse.check(self.root, 'bridge', env), 3)
        pending = reuse.receipt_path('bridge', reuse.environment(env), pending=True)
        self.assertTrue(pending.exists())
        reuse.abandon(self.root, 'bridge', env)
        self.assertFalse(pending.exists())
        self.assertEqual(reuse.check(self.root, 'bridge', env), 3)
        self.assertTrue(pending.exists())

    def testAbandonRefusesAndKeepsPendingWhenBridgeOutputExists(self):
        self.output.unlink()
        self.assertEqual(reuse.check(self.root, 'bridge', self.env), 3)
        pending = reuse.receipt_path('bridge', reuse.environment(self.env), pending=True)
        bridge = self.root / 'bridge'
        bridge.mkdir()
        for name in ('libmacscope_native_decompiler_contract.a', 'CMakeCache.txt'):
            with self.subTest(output=name):
                (bridge / name).write_text('produced')
                with self.assertRaisesRegex(reuse.ReuseError, 'abandon-refused-native-output-exists'):
                    reuse.abandon(self.root, 'bridge', self.env)
                self.assertTrue(pending.exists())
                (bridge / name).unlink()

    def testAbandonRefusesAndKeepsPendingWhenInputsChanged(self):
        self.output.unlink()
        self.assertEqual(reuse.check(self.root, 'bridge', self.env), 3)
        pending = reuse.receipt_path('bridge', reuse.environment(self.env), pending=True)
        self.source.write_text('changed native source')
        with self.assertRaisesRegex(reuse.ReuseError, 'abandon-refused-inputs-changed'):
            reuse.abandon(self.root, 'bridge', self.env)
        self.assertTrue(pending.exists())

    def package_env(self):
        lists = self.root / 'Scripts/native-decompiler-xpc'
        lists.mkdir(parents=True)
        stage = reuse.paths(self.env)['stage'].parent
        stage.mkdir(parents=True)
        for name in ('NativeDecompilerPackageInputs.xcfilelist', 'NativeDecompilerPackageOutputs.xcfilelist'):
            (lists / name).write_text('list\n')
        for name in ('NativeDecompilerPackage.inputs.xcfilelist', 'NativeDecompilerPackage.outputs.xcfilelist'):
            (stage / name).write_text('staged\n')
        return dict(self.env,
                    MACSCOPE_NATIVE_PACKAGE_INPUT_FILE_LIST=str(lists / 'NativeDecompilerPackageInputs.xcfilelist'),
                    MACSCOPE_NATIVE_PACKAGE_OUTPUT_FILE_LIST=str(lists / 'NativeDecompilerPackageOutputs.xcfilelist'))

    def testPackageStageReusesUnchangedRoutineGoldenReceipt(self):
        env = self.package_env()
        self.assertEqual(reuse.check(self.root, 'golden', env), 3)
        reuse.record(self.root, 'golden', env)
        with patch.object(subprocess, 'run', side_effect=AssertionError('must not execute')):
            self.assertEqual(reuse.check(self.root, 'package', env), 0)
            self.assertEqual(reuse.check(self.root, 'golden', env), 0)

    def testPackageStageRefusesChangedInputBehindRoutineGoldenReceipt(self):
        env = self.package_env()
        self.assertEqual(reuse.check(self.root, 'golden', env), 3)
        reuse.record(self.root, 'golden', env)
        self.source.write_text('changed native source')
        with self.assertRaisesRegex(reuse.ReuseError,
                                    'package-stage-needs-explicit-output-admission: native-inputs-changed'):
            reuse.check(self.root, 'package', env)

    def testPackageStageRefusesChangedOutputOrMissingStageListBehindRoutineGoldenReceipt(self):
        env = self.package_env()
        self.assertEqual(reuse.check(self.root, 'golden', env), 3)
        reuse.record(self.root, 'golden', env)
        stage_list = reuse.paths(env)['stage'].parent / 'NativeDecompilerPackage.outputs.xcfilelist'
        stage_list.rename(stage_list.with_name('moved-aside.xcfilelist'))
        with self.assertRaisesRegex(reuse.ReuseError, 'package-stage-needs-explicit-output-admission'):
            reuse.check(self.root, 'package', env)
        self.output.write_text('changed output')
        with self.assertRaisesRegex(reuse.ReuseError,
                                    'package-stage-needs-explicit-output-admission: native-outputs-changed'):
            reuse.check(self.root, 'package', env)

    def testAdmittedSchemasResolveCurrentToolchainAliases(self):
        developer = self.root / 'selected-developer'
        sdk = self.root / 'selected-sdk'
        for installation in ('A', 'B'):
            for relative in ('Toolchains/XcodeDefault.xctoolchain/usr/bin/clang',
                             'Toolchains/XcodeDefault.xctoolchain/usr/bin/swift-frontend',
                             'SDKSettings.plist', 'usr/lib/libz.tbd', 'usr/lib/libc++.tbd'):
                target = self.root / installation / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text('synthetic tool')
        developer.symlink_to(self.root / 'A', target_is_directory=True)
        sdk.symlink_to(self.root / 'A', target_is_directory=True)
        env = dict(self.env, DEVELOPER_DIR=str(developer), SDKROOT=str(sdk),
                   MACSCOPE_SLEIGH_MATERIALIZATION_ROOT=str(self.root))
        original = reuse.toolchain_snapshot(env)
        self.assertEqual(len(original), 5)
        for schema, name in ((3, 'materialization-admission.v3.json'),
                             (4, 'source-admission.v4.json'), (5, 'package-admission.v5.json')):
            inputs = {'environment': env, 'consumer': {}, 'sources': {},
                      'toolchain': original, 'materialization': {}}
            bundle = {'schema': schema, 'repository': str(self.root),
                      'phases': {'bridge': {'inputs': inputs, 'outputs': {},
                                           'origin': {'kind': 'synthetic'}}},
                      'evidence': {}, 'directories': {}}
            receipt = self.root / name
            with patch.object(reuse, 'read_json', return_value=bundle), \
                 patch.object(reuse, 'normalized_tools', return_value=env), \
                 patch.object(reuse, 'metadata', side_effect=lambda path, **kwargs:
                              [0, 0, 0o400] if path == receipt else {}), \
                 patch.object(reuse, 'profile_paths', return_value=[]), \
                 patch.object(reuse, 'recorded_metadata', return_value={}), \
                 patch.object(reuse, 'admitted_outputs', return_value={}):
                # Keep real selected-path resolution while isolating metadata.
                inputs['toolchain'] = reuse.toolchain_snapshot(env)
                self.assertEqual(reuse.check_admitted(self.root, 'bridge', env, receipt), 0)
                developer.unlink()
                developer.symlink_to(self.root / 'B', target_is_directory=True)
                with self.assertRaisesRegex(reuse.ReuseError, 'native-inputs-changed'):
                    reuse.check_admitted(self.root, 'bridge', env, receipt)
                developer.unlink()
                developer.symlink_to(self.root / 'A', target_is_directory=True)

    def testUnrelatedSwiftSettingsAndSchedulerIDsDoNotInvalidate(self):
        self.receipt()
        changed = dict(self.env, SWIFT_ACTIVE_COMPILATION_CONDITIONS='CHANGED', LLBUILD_BUILD_ID='new', PROJECT_FILE_PATH='new')
        self.assertEqual(reuse.check(self.root, 'bridge', changed), 0)

    def testRelevantSDKChangeFailsClosed(self):
        self.receipt()
        with self.assertRaisesRegex(reuse.ReuseError, 'native-inputs-changed'):
            reuse.check(self.root, 'bridge', dict(self.env, SDKROOT='different'))

    def testChangedNativeSourceFailsWithoutAutomaticRerun(self):
        self.receipt()
        self.source.write_text('changed native source')
        with self.assertRaisesRegex(reuse.ReuseError, 'native-inputs-changed'):
            reuse.check(self.root, 'bridge', self.env)

    def recordedReceipt(self):
        self.assertEqual(reuse.check(self.root, 'bridge', self.env), 3)
        reuse.record(self.root, 'bridge', self.env)
        return reuse.receipt_path('bridge', reuse.environment(self.env))

    def rewriteSource(self, data=b'original source'):
        replacement = self.root / 'source.cpp.new'
        replacement.write_bytes(data)
        os.replace(replacement, self.source)

    def testStatOnlySourceChangeWithSameBytesIsAdmittedAndRefreshed(self):
        path = self.recordedReceipt()
        before = reuse.metadata(self.source)
        self.rewriteSource()
        after = reuse.metadata(self.source)
        self.assertNotEqual(before, after)
        with patch.object(subprocess, 'run', side_effect=AssertionError('must not execute')):
            self.assertEqual(reuse.check(self.root, 'bridge', self.env), 0)
        value = reuse.read_json(path)
        self.assertEqual(value['inputs']['sources']['source.cpp'], after)
        self.assertEqual(reuse.metadata(path)[2] & 0o777, 0o400)
        self.assertEqual(reuse.check(self.root, 'bridge', self.env), 0)

    def testOneByteSourceChangeKeepsRefusal(self):
        path = self.recordedReceipt()
        recorded = path.read_bytes()
        self.rewriteSource(b'original sourcf')
        with self.assertRaisesRegex(reuse.ReuseError, 'native-inputs-changed-owner-qualification-required'):
            reuse.check(self.root, 'bridge', self.env)
        self.assertEqual(path.read_bytes(), recorded)

    def testLegacyReceiptWithoutDigestsRefusesAfterStatChange(self):
        self.receipt()
        self.rewriteSource()
        with self.assertRaisesRegex(reuse.ReuseError, 'native-inputs-changed-owner-qualification-required'):
            reuse.check(self.root, 'bridge', self.env)

    def testAddedInputRefusesDespiteMatchingDigests(self):
        self.recordedReceipt()
        extra = self.root / 'extra.cpp'
        extra.write_text('new input')
        self.rewriteSource()
        with patch.object(reuse, 'input_snapshot', side_effect=lambda repository, phase, env:
                          {'environment': env, 'sources': {'source.cpp': reuse.metadata(self.source),
                                                           'extra.cpp': reuse.metadata(extra)}}):
            with self.assertRaisesRegex(reuse.ReuseError, 'native-inputs-changed-owner-qualification-required'):
                reuse.check(self.root, 'bridge', self.env)

    def testChangedNativeOutputFailsWithoutAutomaticRerun(self):
        self.receipt()
        self.output.write_text('changed output')
        with self.assertRaisesRegex(reuse.ReuseError, 'native-outputs-changed'):
            reuse.check(self.root, 'bridge', self.env)

    def testMissingReceiptWithExistingOutputsRequiresAdoption(self):
        archive = reuse.paths(self.env)['archive']
        archive.parent.mkdir()
        archive.write_text('old native output')
        with self.assertRaisesRegex(reuse.ReuseError, 'explicit-adoption'):
            reuse.check(self.root, 'bridge', self.env)

    def testFirstExecutionRecordsOnlyAfterSuccessfulOriginalPhase(self):
        self.assertEqual(reuse.check(self.root, 'bridge', self.env), 3)
        reuse.record(self.root, 'bridge', self.env)
        self.assertEqual(reuse.check(self.root, 'bridge', self.env), 0)
        value = reuse.read_json(reuse.receipt_path('bridge', self.env))
        self.assertEqual(value['origin']['kind'], 'completed-original-phase')

    def testUnfinishedExecutionCannotAutomaticallyRepeat(self):
        self.assertEqual(reuse.check(self.root, 'bridge', self.env), 3)
        with self.assertRaisesRegex(reuse.ReuseError, 'unfinished-native-execution'):
            reuse.check(self.root, 'bridge', self.env)

    def testChangingInputsDuringFirstRunCannotProduceReceipt(self):
        self.assertEqual(reuse.check(self.root, 'bridge', self.env), 3)
        self.source.write_text('changed during original run')
        with self.assertRaisesRegex(reuse.ReuseError, 'inputs-changed-during'):
            reuse.record(self.root, 'bridge', self.env)

    def testHistoricalAdoptionLabelsOriginalEvidenceAndUsesOnlyGitMetadata(self):
        env = reuse.environment(self.env)
        activity = self.root / 'successful.xcactivitylog'
        log = self.root / 'successful.log'
        cmake = reuse.paths(env)['cmake']
        cmake.parent.mkdir()
        cmake.write_text(str(self.root / 'Tools/NativeDecompilerBridge'))
        archive = reuse.paths(env)['archive']
        archive.write_text('completed native archive')
        golden = reuse.paths(env)['golden']
        golden.parent.mkdir(parents=True)
        golden.write_text('{}')
        activity.write_bytes(gzip.compress(b'100% tests passed out of 28\nPASS: native bridge golden runner'))
        log.write_text('==> dev loop timings: completed\n')
        result = subprocess.CompletedProcess([], 0, '100644 blob ' + 'b' * 40 + '\tsource.cpp\n', '')
        with patch.object(reuse, 'activity_environment', return_value=env), patch.object(subprocess, 'run', return_value=result) as run:
            reuse.adopt(self.root, activity, log, 'c' * 40, 0)
        self.assertEqual(run.call_count, 2)
        self.assertTrue(all(call.args[0][0] == 'git' for call in run.call_args_list))
        for phase in ('bridge', 'golden'):
            document = reuse.read_json(reuse.receipt_path(phase, env))
            self.assertEqual(document['origin']['kind'], 'adopted-historical-execution')
            self.assertEqual(document['identities']['wrapperSourceSHA256'], 'a' * 64)

    def testFailedHistoricalRunCannotBeAdopted(self):
        with self.assertRaisesRegex(reuse.ReuseError, 'not-successful'):
            reuse.adopt(self.root, self.root / 'absent', self.root / 'absent', 'c' * 40, 1)

    def testHistoricalAdoptionRejectsOutputChangeDespiteRestoredMtime(self):
        env = reuse.environment(self.env)
        activity = self.root / 'successful.xcactivitylog'
        log = self.root / 'successful.log'
        cmake = reuse.paths(env)['cmake']
        cmake.parent.mkdir()
        cmake.write_text(str(self.root / 'Tools/NativeDecompilerBridge'))
        reuse.paths(env)['archive'].write_text('old archive')
        activity.write_bytes(gzip.compress(b'100% tests passed out of 28\nPASS: native bridge golden runner'))
        log.write_text('==> dev loop timings: completed\n')
        prior = self.output.stat()
        self.output.write_text('modified output')
        os.utime(self.output, ns=(prior.st_atime_ns, prior.st_mtime_ns))
        with patch.object(reuse, 'activity_environment', return_value=env):
            with self.assertRaisesRegex(reuse.ReuseError, 'output-changed-after'):
                reuse.adopt(self.root, activity, log, 'c' * 40, 0)

    def testActivityEnvironmentRejectsAmbiguousNativeTargets(self):
        def block(env):
            return 'export ACTION\\=build\r' + ''.join(f'export {key}\\={value}\r' for key, value in env.items()) + 'export TARGET_NAME\\=NativeDecompilerXPCService\r'
        self.assertEqual(reuse.activity_environment(block(self.env)), reuse.environment(self.env))
        with self.assertRaisesRegex(reuse.ReuseError, 'ambiguous'):
            reuse.activity_environment(block(self.env) + block(dict(self.env, SDK_NAME='different')))

    # --- Retiring a stale routine receipt (MACSCOPE_NATIVE_RETIRE_STALE_RECEIPTS) ---
    FLAG = 'MACSCOPE_NATIVE_RETIRE_STALE_RECEIPTS'

    def retireSetup(self):
        self.env['MACSCOPE_NATIVE_DECOMPILER_GOLDEN_BUILD_ROOT'] = str(self.root / 'golden-build')

    def flagged(self, env=None, value='1'):
        return dict(self.env if env is None else env, **{self.FLAG: value})

    def makeDir(self, name, parent=None):
        directory = (parent or self.root) / name
        directory.mkdir(parents=True, exist_ok=True)
        (directory / 'file.txt').write_text(name)
        return directory

    def retiredDirectories(self):
        base = self.root / 'NativePhaseReuseRetired'
        return sorted(base.iterdir()) if base.exists() else []

    def retiredManifest(self):
        directories = self.retiredDirectories()
        self.assertEqual(len(directories), 1)
        return json.loads((directories[0] / 'manifest.json').read_text())

    def movedNames(self, manifest):
        return [Path(row['to']).name for row in manifest['moved']]

    def staleBridge(self):
        self.retireSetup()
        self.makeDir('bridge')
        path = self.recordedReceipt()
        before = path.read_bytes()
        self.rewriteSource(b'original sourcf')
        return path, before

    def testRetireStaleBridgeReceiptContinuesAsFresh(self):
        path, before = self.staleBridge()
        with patch.object(subprocess, 'run', side_effect=AssertionError('must not execute')):
            self.assertEqual(reuse.check(self.root, 'bridge', self.flagged()), 3)
        self.assertFalse(path.exists())
        self.assertTrue(reuse.receipt_path('bridge', reuse.environment(self.env), pending=True).exists())
        manifest = self.retiredManifest()
        self.assertEqual(self.movedNames(manifest), ['0-bridge.json', '1-bridge.pending.json', '2-bridge'])
        self.assertEqual(Path(manifest['moved'][0]['to']).read_bytes(), before)
        self.assertEqual(manifest['changedSources'], ['source.cpp'])
        self.assertIn('sources', manifest['changedInputKeys'])
        self.assertFalse((self.root / 'bridge').exists())

    def testRetireNeedsTheFlagToBeExactlyOne(self):
        path, before = self.staleBridge()
        for env in (self.env, self.flagged(value='0')):
            with self.assertRaisesRegex(reuse.ReuseError, 'native-inputs-changed-owner-qualification-required'):
                reuse.check(self.root, 'bridge', env)
            self.assertEqual(path.read_bytes(), before)
        self.assertFalse((self.root / 'NativePhaseReuseRetired').exists())

    def testRetireChangedOutputsStillRefuse(self):
        self.retireSetup()
        self.receipt()
        path = reuse.receipt_path('bridge', reuse.environment(self.env))
        self.source.write_text('changed native source')
        self.output.write_text('changed output')
        with self.assertRaisesRegex(reuse.ReuseError, 'native-outputs-changed-owner-qualification-required'):
            reuse.check(self.root, 'bridge', self.flagged())
        self.assertTrue(path.exists())
        self.assertFalse((self.root / 'NativePhaseReuseRetired').exists())

    def testRetireStalePackageGoldenReceipt(self):
        self.retireSetup()
        env = dict(self.package_env(), **{self.FLAG: '1'})
        self.assertEqual(reuse.check(self.root, 'golden', env), 3)
        reuse.record(self.root, 'golden', env)
        selected = reuse.paths(reuse.environment(env))
        selected['golden'].parent.mkdir(parents=True)
        selected['golden'].write_text('golden')
        self.makeDir('NativeDecompilerPackage', selected['package'].parent)
        self.makeDir('golden-build')
        self.source.write_text('changed native source')
        self.assertEqual(reuse.check(self.root, 'package', env), 3)
        self.assertEqual(self.movedNames(self.retiredManifest()), [
            '0-golden.json', '1-golden.pending.json', '2-NativeDecompilerBridgeGolden.json',
            '3-NativeDecompilerPackage', '4-NativeDecompilerPackageStage', '5-golden-build'])
        self.assertEqual(reuse.check(self.root, 'golden', env), 3)
        self.assertTrue(reuse.receipt_path('golden', reuse.environment(env), pending=True).exists())

    def testRetireStaleGoldenReceiptKeepsPackageAndStage(self):
        self.retireSetup()
        env = self.flagged()
        self.assertEqual(reuse.check(self.root, 'golden', env), 3)
        reuse.record(self.root, 'golden', env)
        selected = reuse.paths(reuse.environment(env))
        selected['golden'].parent.mkdir(parents=True)
        selected['golden'].write_text('golden')
        self.makeDir('NativeDecompilerPackage', selected['package'].parent)
        self.makeDir('NativeDecompilerPackageStage', selected['stage'].parent.parent)
        self.makeDir('golden-build')
        self.source.write_text('changed native source')
        self.assertEqual(reuse.check(self.root, 'golden', env), 3)
        self.assertEqual(self.movedNames(self.retiredManifest()), [
            '0-golden.json', '1-golden.pending.json', '2-NativeDecompilerBridgeGolden.json', '3-golden-build'])
        self.assertTrue(selected['package'].exists())
        self.assertTrue(selected['stage'].parent.exists())

    def failedGoldenRun(self, env):
        """A golden execution that wrote its pending receipt and staged outputs but never recorded a receipt."""
        self.assertEqual(reuse.check(self.root, 'golden', env), 3)
        selected = reuse.paths(reuse.environment(env))
        selected['golden'].parent.mkdir(parents=True, exist_ok=True)
        selected['golden'].write_text('golden')
        self.makeDir('NativeDecompilerPackage', selected['package'].parent)
        self.makeDir('golden-build')
        self.assertFalse(reuse.receipt_path('golden', reuse.environment(env)).exists())
        return selected

    def testRetireFailedPendingPackageMovesAsideAndContinuesFresh(self):
        self.retireSetup()
        env = dict(self.package_env(), **{self.FLAG: '1'})
        selected = self.failedGoldenRun(env)
        pending = reuse.receipt_path('golden', reuse.environment(env), pending=True)
        pendingBytes = pending.read_bytes()
        self.source.write_text('changed native source')
        self.assertEqual(reuse.check(self.root, 'package', env), 3)
        manifest = self.retiredManifest()
        self.assertEqual(manifest['reason'], 'failed-execution-inputs-changed')
        self.assertEqual(self.movedNames(manifest), [
            '0-golden.pending.json', '1-NativeDecompilerBridgeGolden.json',
            '2-NativeDecompilerPackage', '3-NativeDecompilerPackageStage', '4-golden-build'])
        # Nothing is deleted: every moved item exists at its destination.
        for row in manifest['moved']:
            self.assertTrue(os.path.lexists(row['to']))
            self.assertFalse(os.path.lexists(row['from']))
        self.assertEqual(Path(manifest['moved'][0]['to']).read_bytes(), pendingBytes)
        self.assertFalse(selected['package'].exists())
        self.assertEqual(reuse.check(self.root, 'golden', env), 3)
        self.assertTrue(pending.exists())

    def testRetireFailedPendingNeedsTheFlag(self):
        self.retireSetup()
        env = self.package_env()
        selected = self.failedGoldenRun(env)
        self.source.write_text('changed native source')
        with self.assertRaisesRegex(reuse.ReuseError, 'package-stage-needs-explicit-output-admission'):
            reuse.check(self.root, 'package', env)
        with self.assertRaisesRegex(reuse.ReuseError, 'package-stage-needs-explicit-output-admission'):
            reuse.check(self.root, 'package', dict(env, **{self.FLAG: '0'}))
        self.assertTrue(selected['package'].exists())
        self.assertFalse((self.root / 'NativePhaseReuseRetired').exists())

    def testRetireFailedPendingWithEqualInputsStillRefuses(self):
        self.retireSetup()
        env = dict(self.package_env(), **{self.FLAG: '1'})
        selected = self.failedGoldenRun(env)
        with self.assertRaisesRegex(reuse.ReuseError, 'package-stage-needs-explicit-output-admission'):
            reuse.check(self.root, 'package', env)
        with self.assertRaisesRegex(reuse.ReuseError, 'existing-native-output-needs-explicit-adoption'):
            reuse.check(self.root, 'golden', env)
        self.assertTrue(selected['package'].exists())
        self.assertFalse((self.root / 'NativePhaseReuseRetired').exists())

    def testRetireFailedPendingMalformedStillRefuses(self):
        self.retireSetup()
        env = dict(self.package_env(), **{self.FLAG: '1'})
        selected = self.failedGoldenRun(env)
        malformed = reuse.receipt_path('golden', reuse.environment(env), pending=True)
        malformed.unlink()
        malformed.write_text('not json')
        self.source.write_text('changed native source')
        with self.assertRaisesRegex(reuse.ReuseError, 'package-stage-needs-explicit-output-admission'):
            reuse.check(self.root, 'package', env)
        with self.assertRaisesRegex(reuse.ReuseError, 'existing-native-output-needs-explicit-adoption'):
            reuse.check(self.root, 'golden', env)
        self.assertTrue(selected['package'].exists())
        self.assertFalse((self.root / 'NativePhaseReuseRetired').exists())

    def testRetireFailedPendingGoldenPhaseWritesNewPending(self):
        self.retireSetup()
        env = self.flagged()
        selected = self.failedGoldenRun(env)
        pending = reuse.receipt_path('golden', reuse.environment(env), pending=True)
        old = pending.read_bytes()
        self.source.write_text('changed native source')
        self.assertEqual(reuse.check(self.root, 'golden', env), 3)
        manifest = self.retiredManifest()
        self.assertEqual(manifest['reason'], 'failed-execution-inputs-changed')
        self.assertEqual(self.movedNames(manifest), [
            '0-golden.pending.json', '1-NativeDecompilerBridgeGolden.json', '2-golden-build'])
        for row in manifest['moved']:
            self.assertTrue(os.path.lexists(row['to']))
        self.assertEqual(Path(manifest['moved'][0]['to']).read_bytes(), old)
        self.assertTrue(pending.exists())
        self.assertNotEqual(pending.read_bytes(), old)
        self.assertTrue(selected['package'].exists())

    def testRetireFailedPendingOutsideDerivedDataStillRefuses(self):
        self.retireSetup()
        env = dict(self.package_env(), **{self.FLAG: '1'})
        self.failedGoldenRun(env)
        self.source.write_text('changed native source')
        outside = real_temporary_directory('native-phase-outside-')
        self.addCleanup(outside.cleanup)
        env['MACSCOPE_NATIVE_DECOMPILER_GOLDEN_BUILD_ROOT'] = str(Path(outside.name) / 'golden-build')
        with self.assertRaisesRegex(reuse.ReuseError, 'native-retire-failed: path-outside-derived-data'):
            reuse.check(self.root, 'package', env)
        self.assertFalse((self.root / 'NativePhaseReuseRetired').exists())

    def testRetireNeverTouchesAdmittedReceipts(self):
        self.retireSetup()
        admitted = self.root / 'NativePhaseReuse' / 'materialization-admission.v3.json'
        reuse.write_once(admitted, {})
        error = reuse.ReuseError('native-inputs-changed-owner-qualification-required')
        for env in (self.env, self.flagged()):
            with patch.object(reuse, 'check_admitted', side_effect=error) as admitting:
                with self.assertRaisesRegex(reuse.ReuseError, 'native-inputs-changed-owner-qualification-required'):
                    reuse.check(self.root, 'bridge', env)
            admitting.assert_called_once()
        package = self.package_env()
        staged = self.root / 'NativePhaseReuse' / 'package-admission.v5.json'
        reuse.write_once(staged, {})
        before = staged.read_bytes()
        for env in (package, self.flagged(package)):
            with patch.object(reuse, 'check_admitted', side_effect=error) as admitting:
                with self.assertRaisesRegex(reuse.ReuseError, 'native-inputs-changed-owner-qualification-required'):
                    reuse.check(self.root, 'package', env)
            admitting.assert_called_once()
        self.assertEqual(staged.read_bytes(), before)
        self.assertEqual(admitted.read_bytes(), b'{}\n')
        self.assertFalse((self.root / 'NativePhaseReuseRetired').exists())

    def testRetireStatOnlyChangeStillReusesWithFlag(self):
        self.retireSetup()
        self.recordedReceipt()
        self.rewriteSource()
        with patch.object(subprocess, 'run', side_effect=AssertionError('must not execute')):
            self.assertEqual(reuse.check(self.root, 'bridge', self.flagged()), 0)
        self.assertFalse((self.root / 'NativePhaseReuseRetired').exists())

    def testRetireDirectoryCollisionFailsBeforeMoving(self):
        path, _ = self.staleBridge()
        collision = self.root / 'NativePhaseReuseRetired' / 'fixed'
        collision.mkdir(parents=True)
        with patch.object(reuse, 'retired_directory_name', return_value='fixed'):
            with self.assertRaisesRegex(reuse.ReuseError, 'native-retire-failed'):
                reuse.check(self.root, 'bridge', self.flagged())
        self.assertTrue(path.exists())
        self.assertTrue((self.root / 'bridge').exists())

    def testRetireBridgeCascadesToGolden(self):
        self.retireSetup()
        env = self.flagged()
        self.makeDir('bridge')
        self.recordedReceipt()
        self.assertEqual(reuse.check(self.root, 'golden', env), 3)
        reuse.record(self.root, 'golden', env)
        self.makeDir('golden-build')
        self.rewriteSource(b'original sourcf')
        self.assertEqual(reuse.check(self.root, 'bridge', env), 3)
        self.assertEqual(self.movedNames(self.retiredManifest()), [
            '0-bridge.json', '1-bridge.pending.json', '2-bridge', '3-golden.json', '4-golden.pending.json',
            '5-golden-build'])
        self.assertEqual(reuse.check(self.root, 'package', env), 3)
        self.assertEqual(reuse.check(self.root, 'golden', env), 3)

    def testRetireMovesEveryRoutineName(self):
        self.retireSetup()
        self.makeDir('bridge')
        path = self.recordedReceipt()
        reuse.write_once(path.with_name('bridge.v2.json'), reuse.read_json(path))
        self.rewriteSource(b'original sourcf')
        env = self.flagged()
        self.assertEqual(reuse.check(self.root, 'bridge', env), 3)
        self.assertEqual(self.movedNames(self.retiredManifest()), [
            '0-bridge.v2.json', '1-bridge.json', '2-bridge.pending.json', '3-bridge'])
        reuse.record(self.root, 'bridge', env)

    def testRetireRefusesBuildRootOutsideDerivedData(self):
        outside = real_temporary_directory('native-phase-reuse-outside-')
        self.addCleanup(outside.cleanup)
        self.retireSetup()
        self.env['MACSCOPE_NATIVE_DECOMPILER_BUILD_ROOT'] = str(self.makeDir('bridge', Path(outside.name)))
        path = self.recordedReceipt()
        self.rewriteSource(b'original sourcf')
        with patch.object(os, 'rename', side_effect=AssertionError('must not rename')):
            with self.assertRaisesRegex(reuse.ReuseError, 'native-retire-failed: path-outside-derived-data'):
                reuse.check(self.root, 'bridge', self.flagged())
        self.assertTrue(path.exists())
        self.assertTrue((Path(outside.name) / 'bridge').exists())
        self.assertFalse((self.root / 'NativePhaseReuseRetired').exists())

    def testRetireRefusesDotDotBuildRoot(self):
        self.retireSetup()
        (self.root / 'target').mkdir()
        self.makeDir('bridge')
        self.env['MACSCOPE_NATIVE_DECOMPILER_BUILD_ROOT'] = str(self.root / 'target' / '..' / 'bridge')
        path = self.recordedReceipt()
        self.rewriteSource(b'original sourcf')
        with self.assertRaisesRegex(reuse.ReuseError, 'native-retire-failed: path-outside-derived-data'):
            reuse.check(self.root, 'bridge', self.flagged())
        self.assertTrue(path.exists())
        self.assertTrue((self.root / 'bridge').exists())

    def testRetireRefusesSymlinkedParentOutsideDerivedData(self):
        outside = real_temporary_directory('native-phase-reuse-outside-')
        self.addCleanup(outside.cleanup)
        self.makeDir('b', Path(outside.name))
        os.symlink(outside.name, self.root / 'link')
        self.retireSetup()
        self.env['MACSCOPE_NATIVE_DECOMPILER_BUILD_ROOT'] = str(self.root / 'link' / 'b')
        path = self.recordedReceipt()
        self.rewriteSource(b'original sourcf')
        with self.assertRaisesRegex(reuse.ReuseError, 'native-retire-failed: path-outside-derived-data'):
            reuse.check(self.root, 'bridge', self.flagged())
        self.assertTrue(path.exists())
        self.assertTrue((Path(outside.name) / 'b').exists())

    def testRetireBridgeGuardRefusesAdmittedGoldenReceipt(self):
        path, before = self.staleBridge()
        admitted = self.root / 'admitted' / 'package-admission.v5.json'
        reuse.write_once(admitted, {})
        original = reuse.receipt_path

        def wrapper(phase, env, pending=False):
            return admitted if phase == 'golden' and not pending else original(phase, env, pending=pending)

        with patch.object(reuse, 'receipt_path', side_effect=wrapper):
            with self.assertRaisesRegex(reuse.ReuseError, 'native-inputs-changed-owner-qualification-required'):
                reuse.check(self.root, 'bridge', self.flagged())
        self.assertEqual(path.read_bytes(), before)
        self.assertFalse((self.root / 'NativePhaseReuseRetired').exists())


class NativePhaseConsumerUpgradeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = real_temporary_directory('native-consumer-upgrade-')
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.env = {key: 'value' for key in reuse.ENV_KEYS}
        self.env.update(CONFIGURATION='Debug', MACSCOPE_DEBUG_SOURCE_IDENTITY='runtime-only',
                        PROJECT_TEMP_DIR=str(self.root), MACSCOPE_NATIVE_DECOMPILER_BUILD_ROOT=str(self.root / 'bridge'))
        self.env = reuse.environment(self.env)
        self.cmake = self.root / 'cmake'
        self.ninja = self.root / 'ninja'
        self.cmake.write_text('synthetic cmake')
        self.ninja.write_text('synthetic ninja')
        self.alias = self.root / 'cmake-alias'
        self.alias.symlink_to(self.cmake)
        self.cache = reuse.paths(self.env)['cmake']
        self.cache.parent.mkdir()
        self.cache.write_text(f'CMAKE_COMMAND:INTERNAL={self.cmake}\nCMAKE_MAKE_PROGRAM:FILEPATH={self.ninja}\n')
        self.source = self.root / 'source.cpp'
        self.output = self.root / 'output.a'
        self.consumer = self.root / 'consumer.py'
        self.source.write_text('unchanged source')
        self.output.write_text('unchanged output')
        self.consumer.write_text('old consumer')
        self.directory = self.root / 'NativePhaseReuse'
        for phase in ('bridge', 'golden'):
            reuse.write_once(reuse.legacy_receipt_path(phase, self.env), {
                'schema': 1, 'repository': str(self.root), 'phase': phase,
                'inputs': self.snapshot(self.env, normalize=False), 'outputs': self.output_snapshot(),
                'identities': {'wrapperSourceSHA256': 'a' * 64},
                'origin': {'kind': 'adopted-historical-execution', 'successfulHead': 'b' * 40}})
        self.consumer.write_text('new consumer')
        for patcher in (
            patch.object(reuse, 'input_snapshot', side_effect=lambda repository, phase, env: self.snapshot(env)),
            patch.object(reuse, 'output_snapshot', side_effect=lambda phase, env: self.output_snapshot()),
            patch.object(subprocess, 'run', side_effect=AssertionError('no native process allowed')),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def snapshot(self, env, normalize=True):
        return {'environment': reuse.normalized_tools(env) if normalize else dict(env),
                'sources': {'source.cpp': reuse.metadata(self.source)},
                'consumer': reuse.metadata(self.consumer), 'toolchain': {}, 'materialization': {}}

    def output_snapshot(self):
        return {str(path): reuse.metadata(path) for path in (self.cache, self.output)}

    def testInheritedToolsMatchLoggedDefaultsAndCanonicalAliases(self):
        inherited = dict(self.env, MACSCOPE_CMAKE=str(self.alias), MACSCOPE_NINJA=str(self.ninja))
        self.assertEqual(reuse.normalized_tools(inherited), reuse.normalized_tools(self.env))
        self.assertEqual(reuse.normalized_tools(inherited)['MACSCOPE_CMAKE'], str(self.cmake))

    def testCacheStagedProjectionHasNoEffectiveTools(self):
        self.cache.write_text(reuse.CACHE_PROJECTION_MARKER + '\nCMAKE_OSX_ARCHITECTURES:STRING=arm64\n')
        self.assertEqual(reuse.normalized_tools(self.env), self.env)
        self.cache.write_text('CMAKE_OSX_ARCHITECTURES:STRING=arm64\n')
        with self.assertRaisesRegex(reuse.ReuseError, 'missing-effective-tool: CMAKE_COMMAND'):
            reuse.normalized_tools(self.env)

    def testDifferingOverridesAreRefusedAndOtherOptionsRemainBound(self):
        alternate = self.root / 'different-tool'
        alternate.write_text('different executable')
        for option in ('MACSCOPE_CMAKE', 'MACSCOPE_NINJA'):
            with self.subTest(option=option), self.assertRaisesRegex(reuse.ReuseError, 'native-tool-override-differs'):
                reuse.normalized_tools(dict(self.env, **{option: str(alternate)}))
        self.assertNotEqual(reuse.normalized_tools(dict(self.env, MACSCOPE_CTEST='different')),
                            reuse.normalized_tools(self.env))

    def testUpgradePreservesOriginalsAndReusesActualInheritedEnvironment(self):
        originals = {phase: (reuse.legacy_receipt_path(phase, self.env).read_bytes(),
                             reuse.metadata(reuse.legacy_receipt_path(phase, self.env)))
                     for phase in ('bridge', 'golden')}
        reuse.upgrade(self.root, self.directory)
        for phase in ('bridge', 'golden'):
            old_path = reuse.legacy_receipt_path(phase, self.env)
            self.assertEqual((old_path.read_bytes(), reuse.metadata(old_path)), originals[phase])
            value = reuse.read_json(reuse.receipt_path(phase, self.env))
            self.assertEqual(value['schema'], 2)
            self.assertEqual(value['origin']['previousReceipt']['metadata'], originals[phase][1])
            self.assertEqual(value['origin']['previousOrigin']['kind'], 'adopted-historical-execution')
            self.assertEqual(reuse.check(self.root, phase, dict(self.env, MACSCOPE_CMAKE=str(self.cmake), MACSCOPE_NINJA=str(self.ninja))), 0)

    def testUpgradeRefusesStaleSourceWithoutWritingReceipts(self):
        self.source.write_text('changed native source')
        with self.assertRaisesRegex(reuse.ReuseError, 'upgrade-native-inputs-changed'):
            reuse.upgrade(self.root, self.directory)
        self.assertFalse((self.directory / 'bridge.v2.json').exists())

    def testUpgradeRefusesStaleOutputWithoutWritingReceipts(self):
        self.output.write_text('changed native output')
        with self.assertRaisesRegex(reuse.ReuseError, 'upgrade-native-outputs-changed'):
            reuse.upgrade(self.root, self.directory)
        self.assertFalse((self.directory / 'bridge.v2.json').exists())

    def testUpgradeRefusesChangedCacheBeforeToolNormalization(self):
        self.cache.write_text(f'CMAKE_COMMAND:INTERNAL={self.ninja}\nCMAKE_MAKE_PROGRAM:FILEPATH={self.cmake}\n')
        with self.assertRaisesRegex(reuse.ReuseError, 'upgrade-native-outputs-changed'):
            reuse.upgrade(self.root, self.directory)
        self.assertFalse((self.directory / 'bridge.v2.json').exists())

    def testFirstRecordNormalizesToolsSelectedAfterPendingWasWritten(self):
        fresh = dict(self.env, PROJECT_TEMP_DIR=str(self.root / 'first-run'))
        pending = self.snapshot(fresh, normalize=False)
        reuse.write_once(reuse.receipt_path('bridge', fresh, pending=True), {'schema': 1, 'inputs': pending})
        with patch.object(reuse, 'identities', return_value={'wrapperSourceSHA256': 'a' * 64}):
            reuse.record(self.root, 'bridge', fresh)
        value = reuse.read_json(reuse.receipt_path('bridge', fresh))
        self.assertEqual(value['inputs']['environment'], reuse.normalized_tools(fresh))
        self.assertEqual(value['origin']['kind'], 'completed-original-phase')



class NativePhaseCacheStagedBridgeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix='native-cache-staged-',
                                                     dir=os.path.realpath(tempfile.gettempdir()))
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.env = {key: 'value' for key in reuse.ENV_KEYS}
        self.env.update(ARCHS='arm64', SDKROOT=str(self.root / 'sdk'),
                        MACSCOPE_NATIVE_DECOMPILER_BUILD_ROOT=str(self.root / 'bridge'))
        self.selected = reuse.paths(self.env)
        for key in ('archive', 'identity', 'linkInputs', 'linkProbe'):
            self.selected[key].parent.mkdir(parents=True, exist_ok=True)
            self.selected[key].write_text(key)

    def write_cache(self, *lines):
        self.selected['cmake'].write_text('\n'.join(lines) + '\n')

    def testProjectionNeedsNoLocalCTestEvidence(self):
        self.write_cache(reuse.CACHE_PROJECTION_MARKER, 'CMAKE_OSX_ARCHITECTURES:STRING=arm64',
                         'MACSCOPE_NATIVE_DECOMPILER_WRAPPER_GIT_REVISION:STRING=' + 'a' * 64)
        self.assertNotIn(str(self.selected['ctest']), reuse.output_snapshot('bridge', self.env))
        self.assertEqual(reuse.identities('bridge', self.env),
                         {'wrapperSourceSHA256': 'a' * 64, 'bridgeOrigin': 'dependency-cache-projection'})
        self.write_cache(reuse.CACHE_PROJECTION_MARKER, 'CMAKE_OSX_ARCHITECTURES:STRING=x86_64',
                         'MACSCOPE_NATIVE_DECOMPILER_WRAPPER_GIT_REVISION:STRING=' + 'a' * 64)
        with self.assertRaisesRegex(reuse.ReuseError, 'cmake-toolchain-mismatch'):
            reuse.identities('bridge', self.env)

    def testLocalBuildStillRequiresCompleteCTestEvidence(self):
        self.write_cache('CMAKE_OSX_ARCHITECTURES:STRING=arm64', 'CMAKE_OSX_SYSROOT:PATH=' + self.env['SDKROOT'],
                         'MACSCOPE_NATIVE_DECOMPILER_WRAPPER_GIT_REVISION:STRING=' + 'a' * 64)
        with self.assertRaises(FileNotFoundError):
            reuse.output_snapshot('bridge', self.env)
        self.selected['ctest'].parent.mkdir(parents=True)
        self.selected['ctest'].write_text('Test Passed.\nEnd testing: now\n')
        self.assertIn(str(self.selected['ctest']), reuse.output_snapshot('bridge', self.env))
        with self.assertRaisesRegex(reuse.ReuseError, 'no-complete-28-test-receipt'):
            reuse.identities('bridge', self.env)

if __name__ == '__main__':
    unittest.main()
