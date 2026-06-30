#!/usr/bin/env sh
# =============================================================================
# Cleanton CLI installer
#   curl -fsSL https://raw.githubusercontent.com/Olib-AI/cleanton/main/scripts/install.sh | sh
# =============================================================================
# Downloads the latest Cleanton command-line tarball from GitHub Releases,
# installs it to ~/.cleanton/, clears the macOS quarantine flag, and adds a
# shim to ~/.local/bin/cleanton. POSIX sh, macOS arm64 only.
#
# To install the Cleanton app instead, download cleanton-app-macos-arm64.tar.gz
# from the releases page and move Cleanton.app to /Applications. The app is
# notarized and needs no extra steps.
# =============================================================================
set -eu

REPO="${CLEANTON_REPO:-Olib-AI/cleanton}"
INSTALL_DIR="${CLEANTON_HOME:-$HOME/.cleanton}"
BIN_DIR="${CLEANTON_BIN_DIR:-$HOME/.local/bin}"
VERSION="${CLEANTON_VERSION:-latest}"

if [ -t 1 ]; then
  G='\033[0;32m'; R='\033[0;31m'; Y='\033[1;33m'; N='\033[0m'
else
  G=''; R=''; Y=''; N=''
fi
say()  { printf "${G}==>${N} %s\n" "$1"; }
warn() { printf "${Y}!! ${N} %s\n" "$1"; }
die()  { printf "${R}xx ${N} %s\n" "$1" >&2; exit 1; }

# ----- platform check ---------------------------------------------------------
uname_s="$(uname -s)"
uname_m="$(uname -m)"
[ "$uname_s" = "Darwin" ] || die "Cleanton is macOS only. Your OS is $uname_s."
case "$uname_m" in
  arm64|aarch64) PLATFORM="macos-arm64" ;;
  *) die "Cleanton ships an Apple Silicon build only. Your CPU is $uname_m." ;;
esac
say "detected $PLATFORM"

need() { command -v "$1" >/dev/null 2>&1 || die "missing required tool: $1"; }
need curl; need tar; need uname

# ----- resolve version --------------------------------------------------------
if [ "$VERSION" = "latest" ]; then
  say "resolving latest release"
  TAG="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
          | sed -nE 's/.*"tag_name": *"([^"]+)".*/\1/p' | head -1)"
  [ -n "${TAG:-}" ] || die "could not resolve the latest tag from the GitHub API"
else
  TAG="$VERSION"
fi
say "installing $TAG"

# ----- download + extract -----------------------------------------------------
TARBALL="cleanton-cli-${PLATFORM}.tar.gz"
URL="https://github.com/${REPO}/releases/download/${TAG}/${TARBALL}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

say "downloading ${URL}"
curl -fL --progress-bar -o "${TMP}/${TARBALL}" "$URL" \
  || die "download failed. check https://github.com/${REPO}/releases"

mkdir -p "$INSTALL_DIR"
say "extracting to $INSTALL_DIR"
tar -xzf "${TMP}/${TARBALL}" -C "$INSTALL_DIR"

BINARY="${INSTALL_DIR}/cleanton"
[ -f "$BINARY" ] || die "expected binary not found at $BINARY"
chmod +x "$BINARY"

# Clear the quarantine flag so the first launch is not blocked by Gatekeeper.
if command -v xattr >/dev/null 2>&1; then
  xattr -d com.apple.quarantine "$BINARY" >/dev/null 2>&1 || true
fi

# ----- shim -------------------------------------------------------------------
mkdir -p "$BIN_DIR"
SHIM="${BIN_DIR}/cleanton"
cat > "$SHIM" <<EOF
#!/usr/bin/env sh
exec "$BINARY" "\$@"
EOF
chmod +x "$SHIM"
say "installed shim: $SHIM"

# ----- PATH guidance ----------------------------------------------------------
case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    warn "$BIN_DIR is not on your PATH"
    echo "    add this to your shell profile (~/.zshrc or ~/.bashrc):"
    echo
    echo "        export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ;;
esac

# ----- smoke test -------------------------------------------------------------
if "$BINARY" --version 2>/dev/null | head -1; then
  say "Cleanton $TAG installed"
else
  say "binary installed at $BINARY"
fi

cat <<'POST'

  Try it (nothing is removed until you confirm):

    cleanton plan

  Then, after reviewing the plan, send removed items to the Trash:

    cleanton plan --apply

  Docs: https://github.com/Olib-AI/cleanton/tree/main/docs

POST
