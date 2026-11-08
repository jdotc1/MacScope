#!/usr/bin/env python3
"""Item 360 synthetic tool selection cases; never invoke a build tool."""
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "item360_tool_resolution", ROOT / "Scripts/qualification/dev_dependency_cache.py")
DEV = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEV)


class NativeToolResolutionTests(unittest.TestCase):
    def tool(self, directory, name, *, guard=False):
        directory.mkdir(parents=True, exist_ok=True)
        path = directory / name
        path.write_text("#!/bin/sh\n" + ("# storage-guard tool shim\n" if guard else "") + "exit 0\n")
        path.chmod(0o755)
        return str(path)

    def test_path_miss_uses_ordered_non_guard_fallback_for_identity_and_build(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for name in ("cmake", "ninja"):
                self.tool(root / "shims", name, guard=True)
                self.tool(root / "first", name)
                self.tool(root / "later", name)
            search = os.pathsep.join(str(root / p) for p in ("shims", "first", "later"))
            environment = {"PATH": str(root / "empty"), "MACSCOPE_TOOL_SEARCH_PATH": search}
            with mock.patch.dict(os.environ, environment, clear=True), \
                    mock.patch.object(DEV, "external_identity", return_value="identity") as external:
                self.assertEqual(DEV.native_tools_identity(root), "identity")
                files = dict(external.call_args.args[0])
                selected = DEV.native_build_tool_environment()
                for name in ("cmake", "ninja"):
                    expected = str(root / "first" / name)
                    self.assertEqual(files[name], expected)
                    self.assertEqual(selected["MACSCOPE_" + name.upper()], expected)
                self.assertEqual(os.environ["PATH"], environment["PATH"])

    def test_path_hit_keeps_legacy_identity_and_guard_invocation(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            for name in ("cmake", "ninja"):
                self.tool(root / "real", name)
                self.tool(root / "shims", name, guard=True)
            environment = {"PATH": os.pathsep.join(str(root / p) for p in ("shims", "real"))}
            with mock.patch.dict(os.environ, environment, clear=True):
                for name in ("cmake", "ninja"):
                    identity, invocation = DEV.native_tool_selection(name)
                    self.assertEqual(identity, DEV.native_identity_tool(name))
                    self.assertEqual(identity, str(root / "real" / name))
                    self.assertEqual(invocation, str(root / "shims" / name))

    def test_override_wins_and_invalid_override_never_falls_back(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            real = self.tool(root / "real", "cmake")
            override = self.tool(root / "override", "cmake")
            shim = self.tool(root / "override-shim", "cmake", guard=True)
            with mock.patch.dict(os.environ, {"PATH": str(root / "real"), "MACSCOPE_CMAKE": override}, clear=True):
                self.assertEqual(DEV.native_tool_selection("cmake"), (override, override))
                with mock.patch.dict(os.environ, {"MACSCOPE_CMAKE": shim}):
                    self.assertEqual(DEV.native_tool_selection("cmake"), (real, shim))
                with mock.patch.dict(os.environ, {"MACSCOPE_CMAKE": str(root / "absent")}):
                    with self.assertRaisesRegex(DEV.Unavailable, "MACSCOPE_CMAKE override"):
                        DEV.native_tool_selection("cmake")

    def test_unavailable_names_the_complete_configured_search_list(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            search = os.pathsep.join(str(root / p) for p in ("one", "two"))
            with mock.patch.dict(os.environ, {"PATH": str(root / "empty"), "MACSCOPE_TOOL_SEARCH_PATH": search}, clear=True):
                with self.assertRaises(DEV.Unavailable) as error:
                    DEV.native_tool_selection("cmake")
                self.assertIn(search, str(error.exception))

    def test_bridge_producer_receives_the_selected_invocation_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            environment = {"MACSCOPE_CMAKE": "/synthetic/cmake", "MACSCOPE_NINJA": "/synthetic/ninja"}
            with mock.patch.object(DEV, "native_build_tool_environment", return_value=environment), \
                    mock.patch.object(DEV, "run_tool", side_effect=["a" * 64, "built"]) as run, \
                    mock.patch.object(DEV, "native_bridge_payload_tool"), \
                    mock.patch.object(DEV, "remove_tree"):
                DEV.build_payload("native-bridge", root, root / "temporary", root / "materialization")
                bridge_call = run.call_args_list[1]
                self.assertTrue(bridge_call.args[0][0].endswith("/build_native_bridge.sh"))
                self.assertEqual(bridge_call.kwargs["extra_environment"], environment)


if __name__ == "__main__":
    unittest.main()
