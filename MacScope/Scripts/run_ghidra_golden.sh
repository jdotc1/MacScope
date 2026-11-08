#!/usr/bin/env bash
# Run Ghidra headlessly over a binary and emit MacScope's GoldenOutput JSON as the
# MacScope-vs-Ghidra differential reference (GoldenFixtures/<basename>/ghidra.json).
#
# Pipeline: bootstrap a pinned, OFFLINE PyGhidra venv (from Ghidra's bundled wheels) ->
# lipo-thin the target to the slice MacScope analyzes -> run ghidra_golden_export.py ->
# drop ghidra.json into the fixtures tree. The reference is not committed.
#
# Usage:   Scripts/run_ghidra_golden.sh [BINARY]            # default: /bin/ls
# Env:     GHIDRA_INSTALL_DIR   override Ghidra location (default: brew --prefix ghidra/libexec)
#          GHIDRA_GOLDEN_ARCH   slice to analyze        (default: arm64e, MacScope's choice)
#          MACSCOPE_GHIDRA_VENV venv location           (default: ~/.cache/macscope_ghidra/venv)
set -euo pipefail

BINARY="${1:-/bin/ls}"
[ -f "$BINARY" ] || { echo "error: binary not found: $BINARY" >&2; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MACSCOPE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FIXTURES="$MACSCOPE_DIR/Tests/CoreTests/GoldenFixtures"
BASENAME="$(basename "$BINARY")"
TARGET_ARCH="${GHIDRA_GOLDEN_ARCH:-arm64e}"

# --- locate Ghidra -----------------------------------------------------------------
if [ -z "${GHIDRA_INSTALL_DIR:-}" ]; then
    if command -v brew >/dev/null 2>&1 && brew --prefix ghidra >/dev/null 2>&1; then
        GHIDRA_INSTALL_DIR="$(brew --prefix ghidra)/libexec"
    fi
fi
[ -n "${GHIDRA_INSTALL_DIR:-}" ] && [ -d "$GHIDRA_INSTALL_DIR/Ghidra" ] || {
    echo "error: GHIDRA_INSTALL_DIR not found (set it to .../ghidra/<ver>/libexec)" >&2; exit 1; }
export GHIDRA_INSTALL_DIR
GHIDRA_VER="$(sed -n 's/^application.version=//p' "$GHIDRA_INSTALL_DIR/Ghidra/application.properties" | head -1)"
PYPKG_DIST="$GHIDRA_INSTALL_DIR/Ghidra/Features/PyGhidra/pypkg/dist"
echo "Ghidra $GHIDRA_VER  ($GHIDRA_INSTALL_DIR)"

# --- bootstrap a pinned, offline PyGhidra venv (idempotent; rebuilt on Ghidra upgrade) ---
command -v uv >/dev/null 2>&1 || { echo "error: uv not on PATH" >&2; exit 1; }
VENV_DIR="${MACSCOPE_GHIDRA_VENV:-$HOME/.cache/macscope_ghidra/venv}"
STAMP="$VENV_DIR/.ghidra_version"
if [ ! -x "$VENV_DIR/bin/python" ] || [ "$(cat "$STAMP" 2>/dev/null || true)" != "$GHIDRA_VER" ]; then
    echo "Bootstrapping PyGhidra venv (Python 3.13, offline) -> $VENV_DIR"
    rm -rf "$VENV_DIR"
    uv venv --python 3.13 "$VENV_DIR"
    # --no-index + --find-links keeps this OFFLINE and matched to THIS Ghidra build's wheels.
    uv pip install --python "$VENV_DIR/bin/python" --no-index --find-links "$PYPKG_DIST" pyghidra jpype1
    echo "$GHIDRA_VER" > "$STAMP"
fi
VENV_PY="$VENV_DIR/bin/python"

# --- thin to the slice MacScope analyzes -------------------------------------------
WORK="$(mktemp -d -t macscope_ghidra)"
trap 'rm -rf "$WORK"' EXIT
THIN="$WORK/$BASENAME"   # name the thin file after the basename so pathBasename == MacScope's
ARCHS="$(lipo -archs "$BINARY" 2>/dev/null || true)"
if echo "$ARCHS" | grep -qw "$TARGET_ARCH" && [ "$(echo "$ARCHS" | wc -w)" -gt 1 ]; then
    echo "lipo: thinning $BASENAME ($ARCHS) -> $TARGET_ARCH"
    lipo "$BINARY" -thin "$TARGET_ARCH" -output "$THIN"
else
    echo "lipo: using $BASENAME as-is (archs: ${ARCHS:-unknown})"
    cp "$BINARY" "$THIN"
fi

# --- run the exporter --------------------------------------------------------------
OUT_DIR="$FIXTURES/$BASENAME"
mkdir -p "$OUT_DIR"
OUT_JSON="$OUT_DIR/ghidra.json"
echo "Analyzing in Ghidra (this runs full auto-analysis)..."
"$VENV_PY" "$SCRIPT_DIR/ghidra_golden_export.py" \
    "$THIN" "$OUT_JSON" \
    --basename "$BASENAME" \
    --project-dir "$WORK/proj"

echo
echo "Reference written: $OUT_JSON"
echo "Run the differential:"
echo "  xcrun xcodebuild test -project MacScope.xcodeproj -scheme MacScopeApp \\"
echo "    -destination 'platform=macOS,arch=arm64' \\"
echo "    -only-testing:CoreTests/GoldenDifferentialTests/testGhidraReferenceDifferential"
