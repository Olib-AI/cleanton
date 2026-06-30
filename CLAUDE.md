# Working in the Cleanton source repo

Native macOS disk cleaner. Rust workspace, edition 2024, resolver 3, MSRV 1.96.
Closed source. See `README.md` for the crate map and build commands.

## Commits

- Do NOT add a `Co-Authored-By` trailer to commits. No co-author lines, ever.
- Keep commit messages plain and factual. No "Generated with" footers.
- Only commit or push when asked. If you are on the default branch, branch first.

## Lint policy (this is a deleter, so it is strict)

The workspace denies these in non-test code (see root `Cargo.toml` and
`clippy.toml`):

- `unwrap_used`, `expect_used`, `panic`, `indexing_slicing`, `todo`,
  `unimplemented`, `unused_must_use`.
- `unsafe_code` is denied except the one audited FFI module
  `crates/cleanton-scanner/src/capacity_ffi.rs`, which carries a scoped allow and
  a `// SAFETY:` comment on every `unsafe` block.

Write code that passes these by construction:

- Use `.get()` instead of indexing, `?` and `let ... else` instead of `unwrap`.
- Use `saturating_*` for arithmetic, `u64::try_from(x).unwrap_or(default)` for
  casts.
- Tests may use `unwrap`/`expect`/`panic` (allowed via `clippy.toml`).

Disallowed methods (routed through audited adapters only, never called directly):

- `std::fs::remove_file`, `std::fs::remove_dir`, `std::fs::remove_dir_all` go
  through the `cleanton-engine` executor.
- `std::process::Command::new` goes through the service/executor adapters that
  carry explicit safety review.

Match the surrounding code's idioms and comment density. Do not reformat
unrelated code.

## Safety boundaries (do not cross)

- Never run a destructive operation yourself. Cleanton moves items to the Trash
  by default; deletion happens only after explicit user confirmation in the UI.
- A scan must never remove anything. Suggestions (large folders, re-clonable
  repos) are review-only and must never be auto-removed.
- When changing the executor or planner, preserve the "review then confirm"
  flow and the Trash-by-default behavior.

## UI parity

The Slint app (`crates/cleanton-app`) is the source of truth for the product UI.
The ratatui TUI (`crates/cleanton-ui`, launched by `cleanton` with no
subcommand) mirrors it: same screens (Dashboard, Results, Packages, Services,
Settings), same logic (keep-set package removal, two-phase package load,
Suggestions and Docker review panels). If you change one, align the other or
call out the gap.

## Before declaring a change done

Run the CI gates and report real results. Do not claim a check passed that you
did not run.

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
```

## Distribution repo (separate)

The public distribution repo is `github.com/Olib-AI/cleanton` (binaries, docs,
website only, closed source). Two hard rules apply to anything written there:

- No em-dashes and no AI-fingerprint phrasing in docs or the website.
- No `Co-Authored-By` on commits (same as here).

Release artifacts come from `./packaging/build-macos.sh --notarize` in this repo
and are attached to a release in the distribution repo.
