#!/usr/bin/env bash
# Dependency security audit for cleanton.
#
#   scripts/audit.sh            # audit the committed lock file (fails on vulnerabilities)
#   scripts/audit.sh --deny-warnings  # also fail on unmaintained/unsound advisories
#
# Uses `.cargo/audit.toml` for the ignore list and output format, so a documented,
# unreachable advisory is the only thing an ignore can silence. Requires cargo-audit:
#   cargo install cargo-audit --locked
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if ! command -v cargo-audit >/dev/null 2>&1; then
  echo "cargo-audit not found. Install it with:" >&2
  echo "  cargo install cargo-audit --locked" >&2
  exit 2
fi

echo "== toolchain =="
cargo --version
rustc --version

echo
echo "== cargo audit (RustSec advisory database) =="
if [[ "${1:-}" == "--deny-warnings" ]]; then
  cargo audit --deny warnings
else
  cargo audit
fi

echo
echo "== reviewed triage =="
grep -E '^    "RUSTSEC-' .cargo/audit.toml \
  | sed -E 's/^ *"([^"]+)",?$/  ignored: \1/' \
  || echo "  (no ignored advisories)"
echo
echo "Done. Every ignored advisory must name an unreachable code path; see SECURITY.md."
