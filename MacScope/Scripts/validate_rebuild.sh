#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

source "${SCRIPT_DIR}/../../Scripts/xcode27_env.sh"

DERIVED_DATA="${MACSCOPE_DERIVED_DATA:-$PROJECT_DIR/DerivedDataValidation}"
PROJECT_FILE="$PROJECT_DIR/MacScope.xcodeproj"
SCHEME="${MACSCOPE_SCHEME:-MacScopeApp}"
CONFIGURATION="${MACSCOPE_CONFIGURATION:-Debug}"
APP_BUNDLE="$DERIVED_DATA/Build/Products/$CONFIGURATION/MacScope.app"

cd "$PROJECT_DIR"

echo "[1/6] Build for testing"
xcrun xcodebuild build-for-testing \
  -project "$PROJECT_FILE" \
  -scheme "$SCHEME" \
  -configuration "$CONFIGURATION" \
  -destination 'platform=macOS,arch=arm64' \
  -derivedDataPath "$DERIVED_DATA"

echo "[2/6] CoreTests"
xcrun xcodebuild test \
  -project "$PROJECT_FILE" \
  -scheme "$SCHEME" \
  -configuration "$CONFIGURATION" \
  -destination 'platform=macOS,arch=arm64' \
  -derivedDataPath "$DERIVED_DATA" \
  -only-testing:CoreTests

echo "[3/6] Xcode 27 signed-build proof"
# Machine-local helper: run when available, skip on clean checkouts/CI.
XCODE27_PROOF="$HOME/.local/bin/xcode27-proof"
if [[ -x "$XCODE27_PROOF" ]]; then
  "$XCODE27_PROOF" proof \
    --project "$PROJECT_FILE" \
    --scheme "$SCHEME" \
    --destination 'platform=macOS,arch=arm64' \
    --code-signing-allowed
else
  echo "Skipping Xcode 27 proof ($XCODE27_PROOF not present on this machine)."
fi

echo "[4/6] Artifact signing policy"
/usr/bin/python3 "$PROJECT_DIR/../Scripts/check_local_signing_policy.py" --app-bundle "$APP_BUNDLE" \
  --configuration "$CONFIGURATION"

echo "[5/6] Artifact signing policy passed"

echo "[6/6] Screenshots"
echo "Skipping GUI screenshot capture. Automation must not launch MacScope windows without explicit display-placement approval."

echo "MacScope rebuild validation passed."
