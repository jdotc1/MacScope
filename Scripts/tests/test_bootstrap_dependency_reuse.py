from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]


class BootstrapDependencyReuseTests(unittest.TestCase):
    def test_cache_miss_refuses_fallback_and_never_authorizes_build(self):
        source = (ROOT / "Scripts/bootstrap.sh").read_text()
        start = source.index("dev_dependency_resolve() {")
        stop = source.index("\n}\n", start) + 3
        function = source[start:stop]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            resolver = root / "resolver.py"
            arguments = root / "arguments.json"
            resolver.write_text("import json, pathlib, sys\n"
                                "pathlib.Path(__file__).with_name('arguments.json').write_text(json.dumps(sys.argv[1:]))\n"
                                "raise SystemExit(3 if '--no-build' in sys.argv else 99)\n")
            script = function + "\ndev_dependency_resolve sleigh-native-source\n"
            env = dict(os.environ, DEV_DEPENDENCY_CACHE=str(resolver), REPO_ROOT=str(root),
                       MACSCOPE_DEV_DEPENDENCY_REUSE_ONLY="1")
            result = subprocess.run(["/bin/bash", "-c", script], env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn("status 3", result.stderr)
            self.assertIn("no build fallback is authorized", result.stderr)
            self.assertIn("--no-build", json.loads(arguments.read_text()))
        dev_loop = (ROOT / "Scripts/dev_loop.sh").read_text()
        self.assertLess(dev_loop.index("export MACSCOPE_DEV_DEPENDENCY_REUSE_ONLY=1"),
                        dev_loop.index('"${ROOT_DIR}/script/build_and_run.sh" --prepare'))


if __name__ == "__main__":
    unittest.main()
