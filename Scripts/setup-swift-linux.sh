#!/usr/bin/env bash
# MacScope's explicit Linux-only Swift setup. This is NOT the macOS app bootstrap.
# Usage: bash Scripts/setup-swift-linux.sh [--verify-only]
# No effect on MacScope's Xcode, signing, CI, or qualification workflows.
set -euo pipefail

readonly SWIFT_VERSION="6.4.2"
readonly SWIFT_ARCHIVE_ROOT="swift-6.4.2-RELEASE-ubuntu24.04"
readonly SWIFT_DOWNLOAD_BASE="https://download.swift.org/swift-6.4.2-release/ubuntu2404/swift-6.4.2-RELEASE"
readonly UBUNTU_NCURSES_BASE="https://archive.ubuntu.com/ubuntu/pool/main/n/ncurses"

log() { printf '[MacScope Swift Linux] %s\n' "$*" >&2; }
fail() { log "ERROR: $*"; exit 1; }
help() {
  printf '%s\n' \
    'Usage: bash Scripts/setup-swift-linux.sh [--verify-only]' \
    'Explicit Ubuntu 24.04 x86_64 Swift 6.4.2 bootstrap, independent of MacScope builds.' \
    'Installs a PGP-verified official tarball to the current user home.' \
    'If necessary, extracts a SHA-256-pinned Ubuntu libncurses6 into that toolchain.' \
    '--verify-only: run version/compile/package smoke tests without downloading.'
}
verify_only=0
case "${1:-}" in
  "") ;;
  --verify-only) verify_only=1 ;;
  --help|-h) help; exit 0 ;;
  *) help >&2; exit 2 ;;
esac
[[ $# -le 1 ]] || fail "Unexpected extra arguments"

[[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] ||
  fail "This bootstrap supports Linux x86_64 only"
[[ -r /etc/os-release ]] || fail "Missing /etc/os-release"
# shellcheck disable=SC1091
. /etc/os-release
[[ "${ID:-}" == ubuntu && "${VERSION_ID:-}" == 24.04 ]] ||
  fail "This pinned toolchain/dependency pair requires Ubuntu 24.04"
[[ -n "${HOME:-}" && -d "$HOME" ]] || fail "An existing user home directory is required"

readonly INSTALL_ROOT="${MACSCOPE_SWIFT_LINUX_ROOT:-${XDG_DATA_HOME:-$HOME/.local/share}/swift/toolchains}"
readonly TARGET="$INSTALL_ROOT/$SWIFT_ARCHIVE_ROOT"
readonly TARGET_BIN="$TARGET/usr/bin"
work=""

# Cleanup is limited to this run's exact mktemp-created directory. It never
# removes an installed toolchain, an existing directory, or an arbitrary path.
cleanup() {
  if [[ -n "$work" && -d "$work" &&
        "$work" == "$INSTALL_ROOT"/.macscope-swift-6.4.2.* ]]; then
    command rm -r -- "$work"
  fi
}
trap cleanup EXIT

check_version() {
  local bin="$1" output
  [[ -x "$bin/swift" && -x "$bin/swiftc" ]] || return 1
  output=$("$bin/swift" --version 2>&1) || {
    log "Swift exists but cannot execute: $output"
    return 1
  }
  [[ "$output" == *"Swift version $SWIFT_VERSION "* ]] || {
    log "Swift version does not match pinned $SWIFT_VERSION: $output"
    return 1
  }
  "$bin/swiftc" --version >/dev/null 2>&1 || return 1
}

smoke_test() {
  local bin="$1" test_dir output
  test_dir="$(mktemp -d "${TMPDIR:-/tmp}/macscope-swift-smoke.XXXXXXXX")" ||
    fail "Cannot create a smoke-test directory"
  printf 'print("Swift compilation successful")\n' > "$test_dir/Hello.swift"
  "$bin/swiftc" "$test_dir/Hello.swift" -o "$test_dir/Hello" ||
    fail "swiftc direct compilation failed; files retained at $test_dir"
  output=$("$test_dir/Hello") ||
    fail "Compiled Swift executable failed; files retained at $test_dir"
  [[ "$output" == "Swift compilation successful" ]] ||
    fail "Unexpected direct executable output; files retained at $test_dir"
  mkdir "$test_dir/package"
  (
    cd "$test_dir/package"
    "$bin/swift" package init --name MacScopeSwiftBootstrapCheck --type executable
    "$bin/swift" build
    "$bin/swift" run
  ) > "$test_dir/package.log" 2>&1 ||
    fail "SwiftPM init/build/run failed; see $test_dir/package.log"
  grep -Fq 'Hello, world!' "$test_dir/package.log" ||
    fail "SwiftPM executable did not produce expected output; see $test_dir/package.log"
  log "PASS: swiftc compile/run and SwiftPM init/build/run"
  if [[ "$test_dir" == "${TMPDIR:-/tmp}"/macscope-swift-smoke.* ]]; then
    command rm -r -- "$test_dir"
  fi
}

persist_path() {
  local bin="$1" profile line escaped_bin
  # PATH in this process cannot change its parent. Record it for later Bash shells.
  printf -v escaped_bin "%q" "$bin"
  line="export PATH=$escaped_bin:\$PATH"
  for profile in "$HOME/.bashrc" "$HOME/.bash_profile"; do
    if [[ -e "$profile" && ! -w "$profile" ]]; then
      log "Cannot update $profile; use: export PATH=\"$bin:\$PATH\""
      continue
    fi
    if [[ ! -e "$profile" && ! -w "$HOME" ]]; then
      log "Cannot create $profile; use: export PATH=\"$bin:\$PATH\""
      continue
    fi
    if ! [[ -e "$profile" ]] || ! grep -Fqx "$line" "$profile"; then
      if ! printf '\n# MacScope explicit Swift-for-Linux toolchain\n%s\n' "$line" >> "$profile"; then
        log "Could not persist PATH in $profile; use: export PATH=\"$bin:\$PATH\""
      fi
    fi
  done
}

existing_bin=""
if [[ -d "$TARGET" || -L "$TARGET" ]]; then
  check_version "$TARGET_BIN" ||
    fail "Existing $TARGET is not usable. Inspect permissions/dependencies; refusing to overwrite it."
  existing_bin="$TARGET_BIN"
elif command -v swift >/dev/null 2>&1; then
  candidate="$(command -v swift)"
  if check_version "$(dirname "$candidate")"; then
    existing_bin="$(dirname "$candidate")"
  fi
fi

if [[ -n "$existing_bin" ]]; then
  log "Reusing working Swift $SWIFT_VERSION at $existing_bin"
  "$existing_bin/swift" --version
  if [[ "$verify_only" == 1 ]]; then smoke_test "$existing_bin"; fi
  if [[ "$verify_only" == 0 ]]; then persist_path "$existing_bin"; fi
  log "To use Swift in this already-running shell: export PATH=\"$existing_bin:\$PATH\""
  exit 0
fi

[[ "$verify_only" == 0 ]] || fail "Swift $SWIFT_VERSION is absent; --verify-only never installs"
for tool in curl gpg tar sha256sum dpkg-deb dpkg-query mktemp df awk grep ldd; do
  command -v "$tool" >/dev/null 2>&1 || fail "Required command unavailable: $tool"
done
mkdir -p "$INSTALL_ROOT" || fail "Cannot create $INSTALL_ROOT (possibly read-only sandbox)"
[[ -w "$INSTALL_ROOT" ]] ||
  fail "Install destination is not writable: $INSTALL_ROOT"
available_kb="$(df -Pk "$INSTALL_ROOT" | awk 'END {print $4}')"
[[ "$available_kb" =~ ^[0-9]+$ && "$available_kb" -ge 5242880 ]] ||
  fail "At least 5 GiB free space is required for archive + extraction"
work="$(mktemp -d "$INSTALL_ROOT/.macscope-swift-6.4.2.XXXXXXXX")" ||
  fail "Cannot create an isolated installation workspace"
mkdir -m 700 "$work/gnupg"

download() {
  curl --fail --location --silent --show-error --retry 3 \
    --connect-timeout 15 --max-time 1800 --output "$2" "$1" ||
    fail "Download failed: $1"
}
log "Downloading Swift $SWIFT_VERSION and PGP signature"
download "$SWIFT_DOWNLOAD_BASE/$SWIFT_ARCHIVE_ROOT.tar.gz" "$work/swift.tar.gz"
download "$SWIFT_DOWNLOAD_BASE/$SWIFT_ARCHIVE_ROOT.tar.gz.sig" "$work/swift.tar.gz.sig"
download "https://www.swift.org/keys/all-keys.asc" "$work/swift-keys.asc"
gpg --homedir "$work/gnupg" --batch --quiet --import "$work/swift-keys.asc" ||
  fail "Could not import official Swift public keys"
gpg --homedir "$work/gnupg" --batch --verify \
  "$work/swift.tar.gz.sig" "$work/swift.tar.gz" ||
  fail "Swift release signature verification failed"
log "Official Swift release signature verified"

# A signed archive is still restricted to one expected top-level directory.
tar -tzf "$work/swift.tar.gz" | awk -v root="$SWIFT_ARCHIVE_ROOT" '
  $0 == root || $0 == root "/" {next}
  index($0, root "/") != 1 || $0 ~ /(^|\/)\.\.(\/|$)/ {bad=1; exit}
  END {exit bad}
' || fail "Archive contains an unexpected or traversal path"
tar -xzf "$work/swift.tar.gz" -C "$work" ||
  fail "Swift archive extraction failed"
staged="$work/$SWIFT_ARCHIVE_ROOT"
[[ -x "$staged/usr/bin/swift" && -x "$staged/usr/bin/swiftc" ]] ||
  fail "Signed archive did not contain expected Swift executables"

# Ubuntu's minimal containers can lack libncurses.so.6. apt-get is intentionally
# not used: its setgroups operation may be blocked. Do not mix incompatible
# libncurses6/libtinfo6 package versions.
if ldd "$staged/usr/bin/swift-driver" | grep -Fq 'libncurses.so.6 => not found'; then
  tinfo_version="$(dpkg-query -W -f='${Version}' libtinfo6 2>/dev/null || true)"
  case "$tinfo_version" in
    '6.4+20240113-1ubuntu2')
      ncurses_revision='6.4+20240113-1ubuntu2'
      ncurses_sha256='f2b8efe3a3e2f622c5266d5a1301048306441885d2bbebc02685cb8c2d097537'
      ;;
    '6.4+20240113-1ubuntu2.2')
      ncurses_revision='6.4+20240113-1ubuntu2.2'
      ncurses_sha256='59e8527dfd14473393960bfb7c69566f1ad9d576423421dcb8b8dcdbb3e7fca1'
      ;;
    *)
      fail "Missing libncurses6; unsupported libtinfo6 version '$tinfo_version'. No package-version guessing."
      ;;
  esac
  log "Installing locally verified Ubuntu libncurses6 $ncurses_revision"
  deb="libncurses6_${ncurses_revision}_amd64.deb"
  encoded_deb="${deb/+/%2B}"
  download "$UBUNTU_NCURSES_BASE/$encoded_deb" "$work/libncurses6.deb"
  printf '%s  %s\n' "$ncurses_sha256" "$work/libncurses6.deb" | sha256sum -c - ||
    fail "Ubuntu package SHA-256 mismatch"
  [[ "$(dpkg-deb --field "$work/libncurses6.deb" Architecture)" == amd64 ]] ||
    fail "Unexpected Ubuntu package architecture"
  [[ "$(dpkg-deb --field "$work/libncurses6.deb" Version)" == "$ncurses_revision" ]] ||
    fail "Unexpected Ubuntu package version"
  dpkg-deb -x "$work/libncurses6.deb" "$work/ncurses"
  lib_source=""
  for p in "$work/ncurses/usr/lib/x86_64-linux-gnu/libncurses.so.6.4" \
           "$work/ncurses/lib/x86_64-linux-gnu/libncurses.so.6.4"; do
    if [[ -f "$p" ]]; then lib_source="$p"; break; fi
  done
  [[ -n "$lib_source" ]] || fail "Verified package lacks expected libncurses.so.6.4"
  cp "$lib_source" "$staged/usr/lib/swift/linux/libncurses.so.6.4"
  ln -s libncurses.so.6.4 "$staged/usr/lib/swift/linux/libncurses.so.6"
  mkdir -p "$staged/usr/share/doc/libncurses6"
  for p in "$work/ncurses/usr/share/doc/libncurses6/copyright" \
           "$work/ncurses/share/doc/libncurses6/copyright"; do
    if [[ -f "$p" ]]; then
      cp "$p" "$staged/usr/share/doc/libncurses6/copyright"
      break
    fi
  done
fi

if ldd "$staged/usr/bin/swift-driver" | grep -Fq 'not found'; then
  fail "Swift still has unresolved shared-library dependencies"
fi
check_version "$staged/usr/bin" ||
  fail "Staged Swift cannot execute. Do not install a nonfunctional toolchain."
log "Running compilation and package-manager smoke tests before installation"
smoke_test "$staged/usr/bin"
[[ ! -e "$TARGET" && ! -L "$TARGET" ]] ||
  fail "Target appeared while staging: $TARGET; refusing overwrite"
mv "$staged" "$TARGET"
persist_path "$TARGET_BIN"
log "Installed PGP-verified Swift $SWIFT_VERSION at $TARGET_BIN"
log "PASS: direct compilation, execution, SwiftPM build, SwiftPM run"
log "For the current shell: export PATH=\"$TARGET_BIN:\$PATH\""
log "No MacScope macOS app build or qualification was performed."
