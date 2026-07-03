#!/usr/bin/env bash
# Sign, notarize, and staple Cleanton.app.
#
# This mirrors the Apple release credential flow used by olib-browser/light:
# import a Developer ID Application .p12 into a temporary keychain, sign with
# hardened runtime, submit with notarytool, then staple and verify.
#
# Required env vars:
#   APPLE_CERTIFICATE_B64         base64-encoded Developer ID Application .p12
#   APPLE_CERTIFICATE_PASSWORD    .p12 import password
#   APPLE_ID                      Apple developer email
#   APPLE_APP_PASSWORD            app-specific password from appleid.apple.com
#   APPLE_TEAM_ID                 10-character team id
#
# Optional:
#   APPLE_KEYCHAIN_NAME           default: cleanton-build.keychain
#   APPLE_KEYCHAIN_PASS           default: random

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

if [[ $# -ne 1 ]]; then
  echo "usage: $0 <path-to-Cleanton.app>" >&2
  exit 2
fi

BUNDLE="$1"

require_var() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    die "$name env var is not set"
  fi
}

# ---------------------------------------------------------------------------
# Interactive fallback: prompt for any missing credential.
# Passwords are hidden (read -rs). The .p12 is read from a file path and
# base64-encoded here so you never have to paste a large blob.
#
# NOTE: uses printf -v to assign values — this is the only safe way to
# store passwords with special chars ($, !, #, `, etc.) into variables
# without the shell interpreting them.
# ---------------------------------------------------------------------------
_prompt_var() {
  local var_name="$1"
  local prompt_text="$2"
  local sensitive="${3:-false}"
  if [[ -z "${!var_name:-}" ]]; then
    if [[ "$sensitive" == "true" ]]; then
      local val
      IFS= read -rs -p "  $prompt_text: " val </dev/tty
      echo ""
      printf -v "$var_name" '%s' "$val"   # safe: no shell interpretation of val
      export "$var_name"
    else
      local val
      IFS= read -r -p "  $prompt_text: " val </dev/tty
      printf -v "$var_name" '%s' "$val"
      export "$var_name"
    fi
  fi
}

if [[ -z "${APPLE_CERTIFICATE_B64:-}" ]]; then
  echo ""
  echo "==> Credentials not set — prompting interactively."
  echo "    (Press Enter to accept defaults shown in brackets)"
  echo ""
  p12_default="$HOME/.ssh/ovc-devid.p12"
  IFS= read -r -p "  Path to Developer ID .p12 [$p12_default]: " p12_path </dev/tty
  p12_path="${p12_path:-$p12_default}"
  if [[ ! -f "$p12_path" ]]; then
    die "File not found: $p12_path"
  fi

  # Prompt for password and verify it against the .p12 immediately —
  # Uses /usr/bin/openssl (macOS LibreSSL) — the same engine as security import.
  # Homebrew OpenSSL 3.x requires -legacy to read its own legacy-format files,
  # so we avoid it here to match what security import actually does.
  while true; do
    cert_pass=""
    IFS= read -rs -p "  Password used to export the .p12: " cert_pass </dev/tty
    echo ""
    if /usr/bin/openssl pkcs12 -in "$p12_path" -noout -passin "pass:${cert_pass}" 2>/dev/null; then
      printf -v APPLE_CERTIFICATE_PASSWORD '%s' "$cert_pass"
      export APPLE_CERTIFICATE_PASSWORD
      echo "  ==> Password verified ✓"
      break
    else
      echo "  ❌  Wrong password — please try again."
    fi
  done

  APPLE_CERTIFICATE_B64="$(base64 -i "$p12_path")"
  export APPLE_CERTIFICATE_B64
fi

_prompt_var APPLE_ID          "Apple developer email"                      false
_prompt_var APPLE_APP_PASSWORD "App-specific password (appleid.apple.com)" true
_prompt_var APPLE_TEAM_ID     "Apple Team ID [FG2QS563CD]"                 false
APPLE_TEAM_ID="${APPLE_TEAM_ID:-FG2QS563CD}"
echo ""
# ---------------------------------------------------------------------------

require_var APPLE_CERTIFICATE_B64
require_var APPLE_CERTIFICATE_PASSWORD
require_var APPLE_ID
require_var APPLE_APP_PASSWORD
require_var APPLE_TEAM_ID

require_command uname
if [[ "$(uname -s)" != "Darwin" ]]; then
  die "macOS notarization must run on Darwin"
fi

require_command awk base64 codesign ditto mktemp openssl rm security spctl tr xcrun
if [[ ! -x /usr/libexec/PlistBuddy ]]; then
  die "required command not found: /usr/libexec/PlistBuddy"
fi

if [[ ! -d "$BUNDLE" ]]; then
  die "bundle missing at $BUNDLE"
fi
case "$BUNDLE" in
  *.app) ;;
  *) die "bundle path must end in .app: $BUNDLE" ;;
esac
if [[ ! -f "$BUNDLE/Contents/Info.plist" ]]; then
  die "bundle is missing Contents/Info.plist"
fi
if [[ ! -d "$BUNDLE/Contents/MacOS" ]]; then
  die "bundle is missing Contents/MacOS"
fi

if [[ ! "$APPLE_TEAM_ID" =~ ^[A-Z0-9]{10}$ ]]; then
  die "APPLE_TEAM_ID must be a 10-character Apple team id"
fi
if [[ "$APPLE_ID" != *@* ]]; then
  die "APPLE_ID must be the Apple developer account email"
fi

KEYCHAIN_NAME="${APPLE_KEYCHAIN_NAME:-cleanton-build.keychain}"
KEYCHAIN_PASS="${APPLE_KEYCHAIN_PASS:-$(openssl rand -base64 24)}"
if [[ -z "$KEYCHAIN_NAME" || "$KEYCHAIN_NAME" == */* ]]; then
  die "APPLE_KEYCHAIN_NAME must be a keychain filename, not a path"
fi

ORIGINAL_DEFAULT_KEYCHAIN="$(security default-keychain -d user 2>/dev/null | tr -d '"' || true)"
ORIGINAL_KEYCHAINS=()
while IFS= read -r keychain; do
  keychain="${keychain#\"}"
  keychain="${keychain%\"}"
  if [[ -n "$keychain" ]]; then
    ORIGINAL_KEYCHAINS+=("$keychain")
  fi
done < <(security list-keychains -d user 2>/dev/null || true)

WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cleanton-notary.XXXXXX")"
KEYCHAIN_PATH="$WORK_DIR/$KEYCHAIN_NAME"
KEYCHAIN_CREATED=0
ZIP=""

cleanup() {
  local status=$?
  set +e
  if [[ -n "$ZIP" ]]; then
    rm -f "$ZIP" >/dev/null 2>&1
  fi
  if [[ ${#ORIGINAL_KEYCHAINS[@]} -gt 0 ]]; then
    security list-keychains -d user -s "${ORIGINAL_KEYCHAINS[@]}" >/dev/null 2>&1
  fi
  if [[ -n "$ORIGINAL_DEFAULT_KEYCHAIN" ]]; then
    security default-keychain -d user -s "$ORIGINAL_DEFAULT_KEYCHAIN" >/dev/null 2>&1
  fi
  if [[ "$KEYCHAIN_CREATED" == "1" ]]; then
    security delete-keychain "$KEYCHAIN_PATH" >/dev/null 2>&1
  fi
  if [[ -n "$WORK_DIR" ]]; then
    rm -rf "$WORK_DIR" >/dev/null 2>&1
  fi
  exit "$status"
}
trap cleanup EXIT

echo "==> Creating temporary keychain '$KEYCHAIN_NAME'"
security create-keychain -p "$KEYCHAIN_PASS" "$KEYCHAIN_PATH"
KEYCHAIN_CREATED=1
security default-keychain -d user -s "$KEYCHAIN_PATH"
security unlock-keychain -p "$KEYCHAIN_PASS" "$KEYCHAIN_PATH"
security set-keychain-settings -lut 21600 "$KEYCHAIN_PATH"

CERT_PATH="$WORK_DIR/cert.p12"
if ! printf '%s' "$APPLE_CERTIFICATE_B64" | base64 -D > "$CERT_PATH" 2>/dev/null; then
  if ! printf '%s' "$APPLE_CERTIFICATE_B64" | base64 --decode > "$CERT_PATH" 2>/dev/null; then
    die "APPLE_CERTIFICATE_B64 is not valid base64"
  fi
fi
if [[ ! -s "$CERT_PATH" ]]; then
  die "decoded Apple certificate is empty"
fi
security import "$CERT_PATH" \
  -k "$KEYCHAIN_PATH" \
  -P "$APPLE_CERTIFICATE_PASSWORD" \
  -T /usr/bin/codesign \
  -T /usr/bin/security
rm -f "$CERT_PATH"
security set-key-partition-list -S apple-tool:,apple: -s -k "$KEYCHAIN_PASS" "$KEYCHAIN_PATH"
security list-keychains -d user -s "$KEYCHAIN_PATH" "${ORIGINAL_KEYCHAINS[@]}"

IDENTITY="$(security find-identity -v -p codesigning "$KEYCHAIN_PATH" \
            | awk -F'"' '/Developer ID Application/ {print $2; exit}' || true)"
if [[ -z "$IDENTITY" ]]; then
  die "no Developer ID Application identity found in temporary keychain"
fi
echo "==> Signing identity: $IDENTITY"

MAIN_INNER="$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$BUNDLE/Contents/Info.plist" 2>/dev/null || true)"
if [[ -z "$MAIN_INNER" || ! -f "$BUNDLE/Contents/MacOS/$MAIN_INNER" ]]; then
  die "CFBundleExecutable is missing or does not exist in Contents/MacOS"
fi

SIGN_FLAGS=( --force --options runtime --timestamp --sign "$IDENTITY" )

echo "==> Signing main executable"
codesign "${SIGN_FLAGS[@]}" "$BUNDLE/Contents/MacOS/$MAIN_INNER"

echo "==> Signing outer bundle"
codesign "${SIGN_FLAGS[@]}" "$BUNDLE"
codesign --verify --deep --strict --verbose=2 "$BUNDLE"

ZIP="${BUNDLE%.app}.zip"
rm -f "$ZIP"
echo "==> Submitting to Apple notary service"
export COPYFILE_DISABLE=1
ditto -c -k --keepParent "$BUNDLE" "$ZIP"
xcrun notarytool submit "$ZIP" \
  --apple-id "$APPLE_ID" \
  --team-id "$APPLE_TEAM_ID" \
  --password "$APPLE_APP_PASSWORD" \
  --wait
rm -f "$ZIP"

echo "==> Stapling notarization ticket"
xcrun stapler staple "$BUNDLE"
xcrun stapler validate "$BUNDLE"
spctl --assess --verbose=4 --type execute "$BUNDLE"

echo "==> $BUNDLE: signed, notarized, and stapled."
