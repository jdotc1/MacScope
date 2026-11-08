#!/usr/bin/env python3
"""Item 362 hidden-index admission cases; authored, not run for this delivery."""
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
    "item362_hidden_git_flags", ROOT / "Scripts/qualification/dev_dependency_cache.py")
DEV = importlib.util.module_from_spec(SPEC)
with mock.patch.dict(os.environ, {"MACSCOPE_WORK_ROOT": tempfile.gettempdir()}):
    SPEC.loader.exec_module(DEV)


class HiddenGitFlagTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.repository = Path(temporary.name).resolve()
        self.prefixes = ("governed",)
        self.governed = "governed/input with space\nand newline.txt"
        self.outside = "outside/input.txt"
        for relative in (self.governed, self.outside):
            path = self.repository / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("committed input\n")
        self.git("init", "-q")
        self.git("add", "--", self.governed, self.outside)
        self.git("-c", "user.name=Item 362 Test", "-c", "user.email=item362@invalid.local",
                 "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null",
                 "commit", "-qm", "base")

    def git(self, *arguments):
        return DEV.git(self.repository, *arguments)

    def assert_flag_refused(self, kind):
        with self.assertRaises(DEV.Unavailable) as raised:
            DEV.require_clean(self.repository, self.prefixes)
        message = str(raised.exception)
        self.assertIn(kind, message)
        self.assertIn(repr(self.governed), message)
        self.assertIn("git update-index --no-" + kind, message)

    def test_s1_clean_governed_tree_without_flags_is_admitted(self):
        self.assertIsNone(DEV.require_clean(self.repository, self.prefixes))

    def test_s2_assume_unchanged_hides_edit_but_does_not_admit_it(self):
        # EXPECTED FAIL ON BASE — NOT RUN: status-only require_clean does not raise.
        self.git("update-index", "--assume-unchanged", "--", self.governed)
        (self.repository / self.governed).write_text("hidden changed input\n")
        self.assertEqual(self.git("status", "--porcelain=v1", "-z", "--", *self.prefixes), b"")
        self.assert_flag_refused("assume-unchanged")

    def test_s3_skip_worktree_is_refused_even_without_an_edit(self):
        # EXPECTED FAIL ON BASE — NOT RUN: status-only require_clean does not raise.
        self.git("update-index", "--skip-worktree", "--", self.governed)
        self.assert_flag_refused("skip-worktree")

    def test_s4_flags_only_outside_nonempty_prefixes_are_not_refused(self):
        for kind in ("assume-unchanged", "skip-worktree"):
            with self.subTest(kind=kind):
                self.git("update-index", "--" + kind, "--", self.outside)
                (self.repository / self.outside).write_text("outside changed input\n")
                self.assertIsNone(DEV.require_clean(self.repository, self.prefixes))
                self.git("update-index", "--no-" + kind, "--", self.outside)

    def test_s5_dirty_governed_input_raises_before_flag_inspection(self):
        (self.repository / self.governed).write_text("visible changed input\n")
        with mock.patch.object(DEV, "git", wraps=DEV.git) as observed:
            with self.assertRaisesRegex(DEV.Unavailable, "governed inputs differ from HEAD"):
                DEV.require_clean(self.repository, self.prefixes)
        self.assertEqual(observed.call_count, 1)
        self.assertEqual(observed.call_args.args[1], "status")

    def exclude_ds_store(self):
        exclude = self.repository / ".git/info/exclude"
        exclude.write_text(exclude.read_text() + "**/.DS_Store\nignored.log\n")

    def test_s6_ignored_ds_store_is_admitted(self):
        self.exclude_ds_store()
        (self.repository / "governed/.DS_Store").write_bytes(b"finder")
        self.assertIn(b"!! governed/.DS_Store",
                      self.git("status", "--porcelain=v1", "-z", "--ignored=matching", "--", *self.prefixes))
        self.assertIsNone(DEV.require_clean(self.repository, self.prefixes))

    def test_s7_untracked_unignored_ds_store_is_refused(self):
        (self.repository / "governed/.DS_Store").write_bytes(b"finder")
        with self.assertRaisesRegex(DEV.Unavailable, r"governed inputs differ from HEAD.*\?\? governed/\.DS_Store"):
            DEV.require_clean(self.repository, self.prefixes)

    def test_s8_other_ignored_file_is_refused_even_beside_ds_store(self):
        self.exclude_ds_store()
        (self.repository / "governed/.DS_Store").write_bytes(b"finder")
        (self.repository / "governed/ignored.log").write_text("debris\n")
        with self.assertRaisesRegex(DEV.Unavailable, r"governed inputs differ from HEAD.*!! governed/ignored\.log"):
            DEV.require_clean(self.repository, self.prefixes)


if __name__ == "__main__":
    unittest.main()
