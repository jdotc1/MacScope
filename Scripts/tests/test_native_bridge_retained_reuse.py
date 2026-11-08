#!/usr/bin/env python3
"""Synthetic admission and cancellation regressions; never uses native inputs."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("bridge_reuse", ROOT / "Scripts/qualification/dev_dependency_cache.py")
DEV = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEV)


class RetainedBridgeTests(unittest.TestCase):
    def contract(self):
        contract = json.loads((DEV.SCRIPTS / "qualification/native_bridge_reuse_contract.json").read_text())
        # Fixed-code fixtures use schema 2. EXPECTED.md walks the equivalent
        # schema-1 fixtures at the base comparison gate; these tests are not run.
        contract["schema_version"] = 2
        contract["reviewed_transport_records"] = {path: [] for path in DEV.NATIVE_TRANSPORT_INPUTS}
        return contract

    def reviewed_record(self, contract):
        record = copy.deepcopy(next(record for record in contract["source_records"]
                                    if record["path"] in DEV.NATIVE_TRANSPORT_INPUTS))
        record.update(blob_oid="a" * 40, sha256="b" * 64, size=record["size"] + 1)
        contract["reviewed_transport_records"][record["path"]].append(record)
        return record

    def resolve_records(self, contract, records):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            (root / "cache/artifacts/v1/native-bridge" / contract["entry_key"]).mkdir(parents=True)
            receipt = root / "views/native-bridge" / contract["entry_key"] / "VIEW.json"
            receipt.parent.mkdir(parents=True)
            receipt.write_text("{}")
            values = contract["values"]
            with mock.patch.object(DEV.json, "loads", return_value=contract), \
                    mock.patch.object(DEV, "source_records", return_value=records), \
                    mock.patch.object(DEV, "retained_component_key", return_value=(values["sleigh-native-source"], True)), \
                    mock.patch.object(DEV, "platform_identity", return_value=values["platform-toolchain"]), \
                    mock.patch.object(DEV, "native_tools_identity", return_value=values["native-tools"]):
                return DEV.native_bridge_retained_key(root, root / "cache", root / "views")

    def test_compatible_transport_preserves_key_but_engine_and_configuration_changes_do_not(self):
        contract = self.contract()
        records = copy.deepcopy(contract["source_records"])
        self.assertEqual(self.resolve_records(contract, records), contract["entry_key"])  # T1
        for record in records:
            if record["path"] in DEV.NATIVE_TRANSPORT_INPUTS:
                record["blob_oid"] = "f" * 40
        self.assertIsNone(self.resolve_records(contract, records))  # T3
        records = copy.deepcopy(contract["source_records"])
        changed = copy.deepcopy(DEV.COMPONENTS["native-bridge"])
        changed["values"] = tuple((name, "99.0" if name == "deployment-target" else value)
                                  for name, value in changed["values"])
        with mock.patch.dict(DEV.COMPONENTS, {"native-bridge": changed}):
            self.assertIsNone(self.resolve_records(contract, records))
        records[-1]["blob_oid"] = "e" * 40
        self.assertIsNone(self.resolve_records(contract, records))  # T6

    def test_exact_reviewed_records_preserve_key_independent_of_key_order(self):
        contract = self.contract()
        reviewed = self.reviewed_record(contract)
        another = dict(reviewed, blob_oid="c" * 40)
        contract["reviewed_transport_records"][reviewed["path"]].append(another)
        for candidate in (reviewed, another):
            with self.subTest(blob_oid=candidate["blob_oid"]):
                records = [dict(reversed(list(candidate.items()))) if record["path"] == candidate["path"]
                           else dict(record) for record in contract["source_records"]]
                self.assertEqual(self.resolve_records(contract, records), contract["entry_key"])  # T2

    def test_missing_or_duplicate_current_transport_path_refuses_reuse(self):
        contract = self.contract()
        reviewed = self.reviewed_record(contract)
        records = copy.deepcopy(contract["source_records"])
        path = reviewed["path"]
        absent = [record for record in records if record["path"] != path]
        self.assertIsNone(self.resolve_records(contract, absent))  # T4
        prior = next(record for record in records if record["path"] == path)
        for duplicate in (prior, reviewed):
            with self.subTest(duplicate=duplicate):
                self.assertIsNone(self.resolve_records(contract, records + [dict(duplicate)]))  # T8

    def test_reviewed_blob_requires_whole_record_equality(self):
        contract = self.contract()
        reviewed = self.reviewed_record(contract)
        for field, value in (("sha256", "c" * 64), ("size", reviewed["size"] + 1),
                             ("mode", "100755" if reviewed["mode"] == "100644" else "100644")):
            with self.subTest(field=field):
                changed = dict(reviewed, **{field: value})
                records = [changed if record["path"] == reviewed["path"] else dict(record)
                           for record in contract["source_records"]]
                self.assertIsNone(self.resolve_records(contract, records))  # T5, plus mode

    def test_schema_one_is_rejected_by_its_own_error(self):
        contract = self.contract()
        contract["schema_version"] = 1
        with self.assertRaisesRegex(DEV.DevCacheError, "^unsupported native bridge reuse contract$"):
            self.resolve_records(contract, contract["source_records"])  # T7a

    def test_missing_reviewed_map_is_rejected_by_its_own_error(self):
        contract = self.contract()
        del contract["reviewed_transport_records"]
        with self.assertRaisesRegex(DEV.DevCacheError,
                                    "^native bridge reuse contract reviewed transport records are missing or malformed$"):
            self.resolve_records(contract, contract["source_records"])  # T7b

    def test_malformed_reviewed_maps_fail_closed(self):
        contract = self.contract()
        reviewed = self.reviewed_record(contract)
        path = reviewed["path"]
        valid = copy.deepcopy(contract["reviewed_transport_records"])
        malformed = [None, [], {}, {**valid, "Scripts/outside.py": []},
                     {**valid, path: {}}, {**valid, path: [reviewed, dict(reviewed)]}]
        for field, value in (("path", "Scripts/outside.py"), ("mode", "100600"), ("mode", []),
                             ("blob_oid", "F" * 40), ("blob_oid", 1),
                             ("sha256", "b" * 63), ("sha256", None),
                             ("size", True), ("size", -1), ("size", "1")):
            malformed.append({**valid, path: [dict(reviewed, **{field: value})]})
        malformed.extend(({**valid, path: [None]}, {**valid, path: [{**reviewed, "extra": 1}]},
                          {**valid, path: [{key: value for key, value in reviewed.items() if key != "size"}]}))
        for mapping in malformed:
            with self.subTest(mapping=mapping):
                contract["reviewed_transport_records"] = mapping
                with self.assertRaisesRegex(DEV.DevCacheError,
                                            "^native bridge reuse contract reviewed transport records are missing or malformed$"):
                    self.resolve_records(contract, contract["source_records"])

    def test_sleigh_probe_substitution_does_not_authorize_transport_alias(self):
        contract = self.contract()
        records = [dict(DEV.SLEIGH_TOOL_PROBE_RECORD) if record == DEV.SLEIGH_PRIOR_TOOL_PROBE_RECORD
                   else dict(record) for record in contract["source_records"]]
        self.assertEqual(self.resolve_records(contract, records), contract["entry_key"])
        path = next(iter(sorted(DEV.NATIVE_TRANSPORT_INPUTS)))
        records = [dict(DEV.SLEIGH_TOOL_PROBE_RECORD, path=path) if record["path"] == path else record
                   for record in records]
        self.assertIsNone(self.resolve_records(contract, records))

    def test_sleigh_admission_never_invokes_resolver_or_verifier(self):
        with tempfile.TemporaryDirectory() as temporary, \
                mock.patch.object(DEV, "resolve", side_effect=AssertionError("repair forbidden")), \
                mock.patch.object(DEV, "reused_sleigh_materialization", side_effect=DEV.DevCacheError("stale")):
            with self.assertRaisesRegex(DEV.DevCacheError, "stale"):
                DEV.native_bridge_materialization(Path(temporary), Path(temporary), Path(temporary), temporary)

    def test_dead_owner_prevents_start(self):
        with mock.patch.dict(os.environ, {"MACSCOPE_DEV_OWNER_PID": "123", "MACSCOPE_DEV_OWNER_START": "birth"}), \
                mock.patch.object(DEV, "process_identity", return_value=""), \
                mock.patch.object(DEV.subprocess, "Popen") as launch:
            with self.assertRaises(DEV.ProducerCancelled):
                DEV.run_tool(["synthetic-producer"])
            launch.assert_not_called()

    def test_owner_loss_terminates_then_kills_worker_group(self):
        worker = mock.Mock(pid=12345)
        worker.communicate.side_effect = [subprocess.TimeoutExpired("synthetic", .25), ("partial", None), ("partial", None)]
        with mock.patch.dict(os.environ, {"MACSCOPE_DEV_OWNER_PID": "123", "MACSCOPE_DEV_OWNER_START": "birth"}), \
                mock.patch.object(DEV, "process_identity", side_effect=["birth", "birth", ""]), \
                mock.patch.object(DEV.subprocess, "Popen", return_value=worker), \
                mock.patch.object(DEV.os, "killpg") as kill, \
                mock.patch.object(DEV.signal, "signal"), mock.patch.object(DEV.signal, "getsignal"):
            with self.assertRaises(DEV.ProducerCancelled):
                DEV.run_tool(["synthetic-producer"])
            self.assertEqual(kill.call_args_list, [mock.call(12345, signal.SIGTERM), mock.call(12345, signal.SIGKILL)])

    def test_owner_loss_during_successful_exit_still_cancels(self):
        worker = mock.Mock(pid=12345)
        worker.communicate.return_value = ("completed just as owner exited", None)
        with mock.patch.dict(os.environ, {"MACSCOPE_DEV_OWNER_PID": "123", "MACSCOPE_DEV_OWNER_START": "birth"}), \
                mock.patch.object(DEV, "process_identity", side_effect=["birth", "birth", "", ""]), \
                mock.patch.object(DEV.subprocess, "Popen", return_value=worker), \
                mock.patch.object(DEV.os, "killpg") as kill, \
                mock.patch.object(DEV.signal, "signal"), mock.patch.object(DEV.signal, "getsignal"):
            with self.assertRaises(DEV.ProducerCancelled):
                DEV.run_tool(["synthetic-producer"])
            self.assertEqual(kill.call_count, 2)

    def test_cancelled_producer_keeps_partial_results_in_place(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            partial = []
            def interrupted(component, repository, directory):
                partial.append(directory / "CTestCheckpoint.txt")
                partial[-1].write_text("18 completed cases")
                raise DEV.ProducerCancelled("owner lost")
            with mock.patch.object(DEV, "build_payload", side_effect=interrupted):
                with self.assertRaises(DEV.ProducerCancelled):
                    DEV.ensure_entry("native-bridge", "a" * 64, root, root, True)
            self.assertEqual(partial[0].read_text(), "18 completed cases")
            self.assertFalse((root / "artifacts/v1/native-bridge" / ("a" * 64)).exists())


if __name__ == "__main__":
    unittest.main()
