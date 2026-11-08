#!/usr/bin/env python3
"""Run the value witness oracle over the selected images of a corpus manifest.

Usage: corpus_run.py <manifest.json> <run-folder> [--only NAME] [--host PATH]

Images are the manifest products flagged as main executables, the dylib
products listed in EXTRA_DYLIBS, and the fixture projects. Every selected image
is checked against its recorded sha256, then loaded by the host in its own
child process with only the dependency search paths it needs. Receipts go to
<run>/receipts/oracle/ and the run record to <run>/receipts/run.json.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time


STATS_MODULES = ("Battery", "Bluetooth", "CPU", "Clock", "Disk", "GPU", "Net",
                 "RAM", "Remote", "Sensors", "Kit")
EXTRA_DYLIBS = {
    ("stats", "O"): STATS_MODULES,
    ("stats", "O-resilient"): ("Kit",),
    ("backyard-birds", "O"): ("BackyardBirdsData", "BackyardBirdsUI",
                              "LayeredArtworkLibrary"),
}
FIXTURE_PROJECTS = ("fixture-sample", "fixture-resilient")

# One row per image group: where DYLD_FRAMEWORK_PATH comes from. A source is a
# path relative to the corpus root, tried in order; "farm:<project>" is the
# symlink farm built under the run_dir folder. The first existing source is used
# and recorded. "library" rows set DYLD_LIBRARY_PATH instead.
RETAINED_TREX = ["bundles/trex/O/TRex.app/Contents/Frameworks",
                 "tmp/trex-O/Build/Products/Release/TRex.app/Contents/Frameworks"]
FRAMEWORK_TABLE = {
    "alt-tab": {"framework": [
        "bundles/alt-tab/O/AltTab.app/Contents/Frameworks",
        "tmp/alt-tab-O/Build/Products/Release/AltTab.app/Contents/Frameworks"]},
    "amethyst": {"framework": RETAINED_TREX},
    "backyard-birds": {"framework": [
        "bundles/backyard-birds/O/Backyard Birds.app/Contents/Frameworks"]},
    "keyboard-cowboy": {"framework": RETAINED_TREX},
    "maccy": {"framework": RETAINED_TREX},
    "monitorcontrol": {"framework": [
        "bundles/monitorcontrol/O/MonitorControl.app/Contents/Frameworks"]},
    "rectangle": {"framework": RETAINED_TREX},
    "stats": {"framework": ["farm:stats"], "except_opt": ["O-resilient"]},
    "trex": {"framework": RETAINED_TREX},
    "fixture-resilient": {"library": ["inputs/fixture-resilient/O"],
                          "only_products": ["clientg"]},
}

SKIP_RULES = (
    ("Sparkle", "Sparkle framework, not corpus application code"),
    ("Autoupdate", "Sparkle helper executable"),
    ("Downloader", "Sparkle helper executable"),
    ("Installer", "Sparkle helper executable"),
    ("Updater", "Sparkle helper executable"),
    ("LoopUpdaterHelper", "updater helper"),
    ("LoopDockTile", "MH_BUNDLE plug-in"),
    ("IceCubes", "Ice Cubes extension"),
    ("Widgets", "widget extension"),
    ("smc", "privileged helper"),
    ("eu.exelban.Stats.SMC.Helper", "privileged helper"),
    (".framework_Versions_A_", "packaging copy of a framework product"),
    (".app_Contents_MacOS_", "packaging copy of an app executable"),
)


def sha256_of(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def opt_of(product, project, corpus):
    relative = Path(product["path"]).relative_to(Path(corpus) / "inputs" / project)
    return relative.parts[0]


def skip_reason(product):
    for needle, reason in SKIP_RULES:
        if needle in product["name"]:
            return reason
    return "not a main executable, listed dylib or fixture product"


def select_images(manifest, corpus):
    """Return (images, skipped) from the manifest list, in manifest order."""
    images, skipped = [], []
    for project in manifest:
        for product in project.get("products", []):
            opt = opt_of(product, project["name"], corpus)
            row = {"image": project["name"], "opt": opt, "product": product["name"],
                   "path": product["path"],
                   "unstripped_path": product["unstripped_path"],
                   "sha256": product["sha256"],
                   "unstripped_sha256": product["unstripped_sha256"]}
            wanted = (product.get("main_executable") is True
                      or product["name"] in EXTRA_DYLIBS.get((project["name"], opt), ())
                      or project["name"] in FIXTURE_PROJECTS)
            if wanted:
                images.append(row)
            else:
                row["reason"] = skip_reason(product)
                skipped.append(row)
    return images, skipped


def build_stats_farm(run_dir, corpus):
    """Symlink farm: <Module>.framework/Versions/A/<Module> -> corpus input."""
    root = Path(run_dir) / "frameworks" / "stats"
    for module in STATS_MODULES:
        folder = root / (module + ".framework") / "Versions"
        folder.mkdir(parents=True, exist_ok=True)
        link = folder / "A"
        link.mkdir(exist_ok=True)
        target = Path(corpus) / "inputs" / "stats" / "O" / module
        entry = link / module
        if entry.is_symlink():
            entry.unlink()
        entry.symlink_to(target)
        current = folder / "Current"
        if not current.is_symlink():
            current.symlink_to("A")
    return root


def child_environment(image, run_dir, corpus):
    """Return (environment additions, record) for one image."""
    row = FRAMEWORK_TABLE.get(image["image"])
    if row is None:
        return {}, {"source": None}
    if image["opt"] in row.get("except_opt", ()):
        return {}, {"source": None}
    if "only_products" in row and image["product"] not in row["only_products"]:
        return {}, {"source": None}
    variable = "DYLD_LIBRARY_PATH" if "library" in row else "DYLD_FRAMEWORK_PATH"
    for candidate in row.get("library", row.get("framework")):
        if candidate.startswith("farm:"):
            path = Path(run_dir) / "frameworks" / candidate[5:]
        else:
            path = Path(corpus) / candidate
        if path.is_dir():
            return {variable: str(path)}, {"source": candidate, "variable": variable,
                                           "path": str(path)}
    return {}, {"source": None, "variable": variable, "missing": True}


def summarise(document):
    unanswered = {}
    for row in document.get("unanswered", []):
        reason = row.get("reason", "unknown")
        unanswered[reason] = unanswered.get(reason, 0) + int(row.get("count", 1))
    summary = document.get("summary", {})
    return {"status": document.get("status"),
            "answered": summary.get("answered"), "askable": summary.get("askable"),
            "dependent": summary.get("dependent"), "rate": summary.get("rate"),
            "unanswered": unanswered}


def run_image(image, run_dir, corpus, host, host_sha):
    name = "{}-{}-{}".format(image["image"], image["opt"], image["product"])
    out = Path(run_dir) / "receipts" / "oracle" / (name + ".json")
    out.parent.mkdir(parents=True, exist_ok=True)
    additions, source = child_environment(image, run_dir, corpus)
    command = [str(host), image["path"], "--fields", "--isolate", "--timeout", "120", "--out", str(out)]
    record = {"name": name, **{k: image[k] for k in ("image", "opt", "product", "path")},
              "command": command, "environment": additions, "framework_source": source,
              "host_sha256": host_sha, "receipt": str(out)}
    if out.exists():
        raise FileExistsError("refusing to overwrite oracle receipt: " + str(out))
    started = time.time()
    try:
        done = subprocess.run(command, env={**os.environ, **additions}, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=240)
        record["exit_status"] = done.returncode
        record["stderr_tail"] = done.stderr[-600:]
        record["stdout_tail"] = done.stdout[-300:]
    except subprocess.TimeoutExpired:
        record["exit_status"] = "outer-timeout"
    record["wall_seconds"] = round(time.time() - started, 2)
    if out.exists():
        document = json.loads(out.read_text())
        record["oracle"] = summarise(document)
        status = document.get("status")
        record["outcome"] = "answered" if status == "ok" else str(status)
        if status != "ok":
            details = [row.get("detail") or row.get("reason")
                       for row in document.get("unanswered", [])]
            record["reason"] = "; ".join(str(d) for d in details[:2] if d)[:600]
    else:
        text = (record.get("stderr_tail", "") + record.get("stdout_tail", "")).strip()
        record["outcome"] = "timeout" if record["exit_status"] == "outer-timeout" else "failed"
        record["reason"] = text[-300:] or "no receipt written"
    return record


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--only", help="project name to run")
    parser.add_argument("--host", type=Path, help="host binary (default <run>/build/vwo)")
    args = parser.parse_args(argv)
    corpus = args.manifest.resolve().parent
    manifest = json.loads(args.manifest.read_text())
    images, skipped = select_images(manifest, corpus)
    host = args.host or args.run_dir / "build" / "vwo"
    host_sha = sha256_of(host)
    # Check every selected image before running any.
    bad = []
    for image in images:
        for key, path in (("sha256", "path"), ("unstripped_sha256", "unstripped_path")):
            actual = sha256_of(image[path])
            if actual != image[key]:
                bad.append({"image": image["image"], "opt": image["opt"],
                            "file": image[path], "expected": image[key], "actual": actual})
    if bad:
        print(json.dumps(bad, indent=2))
        print("STOP: image sha256 differs from the manifest", file=sys.stderr)
        return 2
    build_stats_farm(args.run_dir, corpus)
    selected = [i for i in images if args.only in (None, i["image"])]
    runs = []
    for image in selected:
        record = run_image(image, args.run_dir, corpus, host, host_sha)
        runs.append(record)
        print("{} {} {}s {}".format(record["name"], record["outcome"],
                                    record["wall_seconds"], record.get("oracle", {}).get("rate")),
              flush=True)
        document = {"manifest": str(args.manifest), "host": str(host),
                    "host_sha256": host_sha, "selected": len(selected),
                    "sha256_checked": len(images), "runs": runs, "skipped": skipped}
        target = args.run_dir / "receipts" / "run.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
