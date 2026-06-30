#!/usr/bin/env bash
set -euo pipefail

die() {
  echo "error: $*" >&2
  exit 1
}

require_command() {
  local cmd
  for cmd in "$@"; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
      die "required command not found: $cmd"
    fi
  done
}

usage() {
  echo "usage: $0 [--notarize]" >&2
}

NOTARIZE=0
if [[ "${1:-}" == "--notarize" ]]; then
  NOTARIZE=1
  shift
fi
if [[ $# -ne 0 ]]; then
  usage
  exit 2
fi

require_command uname
if [[ "$(uname -s)" != "Darwin" ]]; then
  die "macOS packaging must run on Darwin"
fi

require_command awk cargo codesign dirname find install mkdir plutil rm sed shasum strip tar uname

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PROFILE="${PROFILE:-release}"
TARGET_DIR="${CARGO_TARGET_DIR:-"$ROOT_DIR/target"}"
DIST_DIR="${DIST_DIR:-"$ROOT_DIR/packaging/dist"}"
if [[ "$DIST_DIR" != /* ]]; then
  DIST_DIR="$ROOT_DIR/$DIST_DIR"
fi
DIST_BASENAME="$(basename "$DIST_DIR")"
ARCH="$(uname -m)"
# This packaging path targets macOS arm64 only. Universal/Intel builds are out
# of scope for now; fail loudly rather than emit a mislabeled x86_64 artifact.
if [[ "$ARCH" != "arm64" ]]; then
  die "this packaging script targets macOS arm64 only (detected: $ARCH); universal/Intel is out of scope"
fi
APP_NAME="Cleanton"
APP_EXECUTABLE="Cleanton"
APP_BUNDLE="$DIST_DIR/$APP_NAME.app"
APP_CONTENTS="$APP_BUNDLE/Contents"
APP_RESOURCES="$APP_CONTENTS/Resources"
APP_VERSION="${APP_VERSION:-$(awk -F '"' '/^version = / { print $2; exit }' "$ROOT_DIR/Cargo.toml")}"
BUNDLE_IDENTIFIER="${BUNDLE_IDENTIFIER:-ai.olib.cleanton}"
MIN_SYSTEM_VERSION="${MIN_SYSTEM_VERSION:-13.0}"
ICON_FILE="Cleanton.icns"

case "$DIST_DIR" in
  "/" | "$ROOT_DIR" | "$ROOT_DIR/" | "$ROOT_DIR/packaging" | "$ROOT_DIR/packaging/")
    die "refusing to clean unsafe DIST_DIR: $DIST_DIR"
    ;;
  *"/../"* | *"/.." | *"/./"* | *"/.")
    die "refusing to clean non-normal DIST_DIR: $DIST_DIR"
    ;;
esac
if [[ "$DIST_BASENAME" == "." || "$DIST_BASENAME" == ".." ]]; then
  die "refusing to clean non-normal DIST_DIR: $DIST_DIR"
fi

if [[ -z "$APP_VERSION" ]]; then
  die "could not determine APP_VERSION from Cargo.toml"
fi
if [[ -z "$BUNDLE_IDENTIFIER" ]]; then
  die "BUNDLE_IDENTIFIER must not be empty"
fi
if [[ "$NOTARIZE" == "1" && ! -x "$ROOT_DIR/packaging/notarize-macos.sh" ]]; then
  die "notarization script is missing or not executable: packaging/notarize-macos.sh"
fi

# Remap developer-local absolute paths out of embedded panic/location strings
# (file!() metadata from first-party and registry crates) so release artifacts
# never leak the build machine's home directory or username. Any RUSTFLAGS the
# caller already set is preserved. The broad $HOME remap is the guarantee that
# no username survives; the $CARGO_HOME and workspace remaps keep remaining
# paths tidy.
if [[ -n "${HOME:-}" ]]; then
  CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
  REMAP_FLAGS="--remap-path-prefix=$HOME=/build"
  REMAP_FLAGS+=" --remap-path-prefix=$ROOT_DIR=/cleanton"
  REMAP_FLAGS+=" --remap-path-prefix=$CARGO_HOME_DIR=/cargo"
  export RUSTFLAGS="${RUSTFLAGS:-} $REMAP_FLAGS"
fi

case "$PROFILE" in
  release)
    BUILD_DIR="$TARGET_DIR/release"
    cargo build --release -p cleanton-cli -p cleanton-app
    ;;
  *)
    BUILD_DIR="$TARGET_DIR/$PROFILE"
    cargo build --profile "$PROFILE" -p cleanton-cli -p cleanton-app
    ;;
esac

for binary in "$BUILD_DIR/cleanton" "$BUILD_DIR/cleanton-app"; do
  if [[ ! -x "$binary" ]]; then
    die "expected built executable missing: $binary"
  fi
done
if [[ ! -f "$ROOT_DIR/packaging/macos/$ICON_FILE" ]]; then
  die "required app icon missing: packaging/macos/$ICON_FILE"
fi

rm -rf "$DIST_DIR"
mkdir -p "$DIST_DIR/cli" "$APP_CONTENTS/MacOS" "$APP_RESOURCES"

install -m 0755 "$BUILD_DIR/cleanton" "$DIST_DIR/cli/cleanton"
install -m 0755 "$BUILD_DIR/cleanton-app" "$APP_CONTENTS/MacOS/$APP_EXECUTABLE"
install -m 0644 "$ROOT_DIR/packaging/macos/$ICON_FILE" "$APP_RESOURCES/$ICON_FILE"
sed \
  -e "s/@APP_VERSION@/$APP_VERSION/g" \
  -e "s/@BUNDLE_IDENTIFIER@/$BUNDLE_IDENTIFIER/g" \
  -e "s/@APP_EXECUTABLE@/$APP_EXECUTABLE/g" \
  -e "s/@ICON_FILE@/$ICON_FILE/g" \
  -e "s/@MIN_SYSTEM_VERSION@/$MIN_SYSTEM_VERSION/g" \
  "$ROOT_DIR/packaging/macos/Info.plist.in" > "$APP_CONTENTS/Info.plist"
printf "APPL????" > "$APP_CONTENTS/PkgInfo"
plutil -lint "$APP_CONTENTS/Info.plist" >/dev/null

junk_path="$(find "$DIST_DIR" \( -name '.DS_Store' -o -name '._*' \) -print -quit)"
if [[ -n "$junk_path" ]]; then
  die "refusing to package local Finder metadata: $junk_path"
fi

# Strip local symbols to shrink the shipped binaries and avoid leaking
# developer-local symbol paths into artifacts. Stripping rewrites the Mach-O and
# invalidates the implicit ad-hoc "linker-signed" signature, so every binary is
# (re-)signed afterward.
CLI_BIN="$DIST_DIR/cli/cleanton"
APP_BIN="$APP_CONTENTS/MacOS/$APP_EXECUTABLE"
strip -x "$CLI_BIN" "$APP_BIN"

# The CLI binary is always ad-hoc signed so the stripped Mach-O has a valid
# signature and launches on arm64. (Developer ID signing of the CLI is a
# separate Homebrew-channel concern and is intentionally not required here.)
codesign --force --sign - "$CLI_BIN"
codesign --verify --strict "$CLI_BIN"

if [[ "$NOTARIZE" == "1" ]]; then
  # Real Developer ID signature + notarization for the app bundle. This path is
  # gated on Apple secrets and is left fully intact.
  "$ROOT_DIR/packaging/notarize-macos.sh" "$APP_BUNDLE"
else
  # Ad-hoc sign the app bundle so it at least launches locally. Gatekeeper will
  # still reject it (no Developer ID, not notarized) — that is expected for
  # UNSIGNED builds; the signed path above is gated on Apple secrets.
  codesign --force --deep --sign - "$APP_BUNDLE"
  codesign --verify --deep --strict --verbose=2 "$APP_BUNDLE"
fi

CLI_ARCHIVE="cleanton-cli-macos-$ARCH.tar.gz"
APP_ARCHIVE="cleanton-app-macos-$ARCH.tar.gz"
export COPYFILE_DISABLE=1
tar -C "$DIST_DIR/cli" -czf "$DIST_DIR/$CLI_ARCHIVE" cleanton
tar -C "$DIST_DIR" -czf "$DIST_DIR/$APP_ARCHIVE" "$APP_NAME.app"
(
  cd "$DIST_DIR"
  shasum -a 256 "$CLI_ARCHIVE" "$APP_ARCHIVE" > SHA256SUMS
)

if [[ "$NOTARIZE" == "1" ]]; then
  BUILD_KIND="Signed and notarized"
  RELEASE_HINT="Public direct-download macOS releases should be published from these artifacts."
else
  BUILD_KIND="Unsigned"
  RELEASE_HINT="Unsigned builds are for CI and local smoke testing only. Public direct-download macOS releases must be produced with: ./packaging/build-macos.sh --notarize"
fi
cat <<EOF
${BUILD_KIND} macOS artifacts are in $DIST_DIR.

App bundle: $APP_BUNDLE

$RELEASE_HINT
EOF
