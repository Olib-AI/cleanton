# Cleanton — Built-In Recipes Reference

> Each recipe is a TOML file that defines what to scan, how to match, and what action to take.
> Recipes are grouped by category. This document lists all planned built-in recipes.

The checked-in `recipes/*.toml` files are the implementation source of truth.

### Trash by default

**Every shipped recipe uses `action.type = "trash"`.** No built-in recipe ever permanently
deletes user data: a matched item is moved to the macOS Trash, where the user can review and
restore it. Space is reclaimed only when the Trash is emptied — and because the Trash lives on
the same volume as the original file, a trash action does **not** free disk space until the
Trash is emptied (macOS keeps the bytes in `~/.Trash` / the volume's `.Trashes` until then).

The safety contract still guards any future `delete` recipe: any recipe with
`action.type = "delete"` must also declare `recipe.safety_level = "aggressive"`; `safe` and
`cautious` recipes may only plan recoverable actions such as Trash. Release validation rejects
any TOML recipe that violates this rule. As an additional hard floor, the matcher refuses to
plan **any** action against a credential, auth-token, secret, or settings basename (e.g.
`.env`, `credentials.json`, `auth.json`, `.credentials.json`, `settings.json`, `mcp.json`),
regardless of how broad a recipe's glob is.

---

## Category: `rust`

### `rust-target-dirs`
| Field | Value |
|---|---|
| **Name** | Rust Build Artifacts (`target/`) |
| **Safety** | `safe` |
| **Match** | Directories named `target` whose parent contains `Cargo.toml` |
| **Exclude** | `target/release/*.app`, `target/release/*.dmg`, `target/release/<binary>` (heuristic) |
| **Min Size** | 10 MB |
| **Action** | Trash |
| **Notes** | Fully regenerable via `cargo build`. Single largest source of developer disk waste. |

### `rust-cargo-registry-cache`
| Field | Value |
|---|---|
| **Name** | Cargo Registry Cache |
| **Safety** | `safe` |
| **Match** | `~/.cargo/registry/cache/**` |
| **Min Age** | 30 days |
| **Action** | Trash |
| **Notes** | Downloaded `.crate` files; re-downloaded on demand. |

### `rust-cargo-registry-src`
| Field | Value |
|---|---|
| **Name** | Cargo Registry Source Checkouts |
| **Safety** | `safe` |
| **Match** | `~/.cargo/registry/src/**` |
| **Min Age** | 30 days |
| **Action** | Trash |

### `rust-incremental-cache`
| Field | Value |
|---|---|
| **Name** | Rust Incremental Compilation Cache |
| **Safety** | `safe` |
| **Match** | `**/target/*/incremental/**` |
| **Notes** | Speeds up recompilation but grows unbounded. |

### `rust-sccache`
| Field | Value |
|---|---|
| **Name** | sccache Shared Compilation Cache |
| **Safety** | `safe` |
| **Match** | `~/.cache/sccache/**` |
| **Min Size** | 100 MB |
| **Min Age** | 14 days |
| **Action** | Trash |
| **Notes** | Shared compiler cache for Rust, C, and C++. Safe to clear, will rebuild on next compile. |

---

## Category: `swift`

### `swift-derived-data`
| Field | Value |
|---|---|
| **Name** | Xcode DerivedData |
| **Safety** | `safe` |
| **Match** | `~/Library/Developer/Xcode/DerivedData/**` |
| **Min Size** | 50 MB |
| **Action** | Trash |
| **Notes** | Can grow to tens of GB. Fully regenerable. |

### `swift-build-dirs`
| Field | Value |
|---|---|
| **Name** | Swift Package Build Directories |
| **Safety** | `safe` |
| **Match** | Directories named `.build` whose parent contains `Package.swift` |
| **Min Size** | 10 MB |
| **Action** | Trash |

### `swift-archives`
| Field | Value |
|---|---|
| **Name** | Xcode Archives |
| **Safety** | `cautious` |
| **Match** | `~/Library/Developer/Xcode/Archives/**` |
| **Min Age** | 90 days |
| **Action** | Trash |
| **Notes** | Old archives may be needed for dSYM symbolication. Cautious because of crash report analysis. |

### `swift-simulators`
| Field | Value |
|---|---|
| **Name** | iOS/watchOS/tvOS Simulator Runtimes |
| **Safety** | `cautious` |
| **Match** | `~/Library/Developer/CoreSimulator/Devices/**` |
| **Min Age** | 60 days |
| **Action** | Trash |
| **Notes** | Can consume 10+ GB per runtime version. |

### `swift-device-support`
| Field | Value |
|---|---|
| **Name** | Xcode Device Support Files |
| **Safety** | `safe` |
| **Match** | `~/Library/Developer/Xcode/iOS DeviceSupport/**`, `~/Library/Developer/Xcode/watchOS DeviceSupport/**` |
| **Min Age** | 180 days |
| **Action** | Trash |

### `swift-xcode-device-logs`
| Field | Value |
|---|---|
| **Name** | Xcode Device Logs |
| **Safety** | `cautious` |
| **Match** | `~/Library/Developer/Xcode/iOS Device Logs/**` |
| **Min Age** | 30 days |
| **Action** | Trash |

---

## Category: `node`

### `node-modules`
| Field | Value |
|---|---|
| **Name** | Node Modules |
| **Safety** | `safe` |
| **Match** | Directories named `node_modules` whose parent contains `package.json` |
| **Min Size** | 50 MB |
| **Action** | Trash |
| **Notes** | Regenerable via `npm install`. Often 200MB-1GB per project. |

### `node-next-cache`
| Field | Value |
|---|---|
| **Name** | Next.js Build Cache |
| **Safety** | `safe` |
| **Match** | Directories named `.next` whose parent contains `next.config.*` or `package.json` |
| **Action** | Trash |

### `node-dist-build`
| Field | Value |
|---|---|
| **Name** | Node Build Output Directories |
| **Safety** | `cautious` |
| **Match** | `dist/`, `build/`, `.output/` in Node projects |
| **Parent Must Contain** | `package.json` |
| **Action** | Trash |
| **Notes** | Cautious because `dist/` might contain deployment artifacts the user needs. |

### `node-cache-dirs`
| Field | Value |
|---|---|
| **Name** | Node Tool Caches |
| **Safety** | `safe` |
| **Match** | Directories named `.parcel-cache` whose parent contains `package.json` |
| **Action** | Trash |

### `node-turbo-cache`
| Field | Value |
|---|---|
| **Name** | Turborepo Cache |
| **Safety** | `safe` |
| **Match** | Directories named `.turbo` whose parent contains `package.json` |
| **Min Size** | 10 MB |
| **Action** | Trash |

### `node-pnpm-store`
| Field | Value |
|---|---|
| **Name** | pnpm Global Store |
| **Safety** | `cautious` |
| **Match** | `~/Library/pnpm/store/**` (default on macOS; honor `store-dir` / `~/Library/Preferences/pnpm/config.yaml` and `PNPM_HOME` when set) |
| **Min Size** | 200 MB |
| **Action** | Trash |
| **Notes** | Content-addressable package store. Cautious because active projects **hardlink** into this store — deleting it breaks every project's `node_modules` and frees less than the logical size suggests (see [PLATFORM.md](./PLATFORM.md) §1.5). Prefer `pnpm store prune` semantics over blind deletion. |

### `node-bun-cache`
| Field | Value |
|---|---|
| **Name** | Bun Install Cache |
| **Safety** | `safe` |
| **Match** | `~/.bun/install/cache/**` |
| **Action** | Trash |
| **Notes** | Cached npm packages for Bun. |

### `node-deno-cache`
| Field | Value |
|---|---|
| **Name** | Deno Cache |
| **Safety** | `safe` |
| **Match** | `~/Library/Caches/deno/**` |
| **Action** | Trash |
| **Notes** | Downloaded dependencies and compilation cache for Deno. |

### `node-bundler-caches`
| Field | Value |
|---|---|
| **Name** | Node Bundler Caches |
| **Safety** | `safe` |
| **Match** | `**/node_modules/.cache/{babel-loader,swc,nx,storybook}/**` inside a directory containing `package.json` |
| **Action** | Trash |
| **Notes** | Each tool rebuilds its own subdirectory on the next run. |

---

## Category: `python`

### `python-pycache`
| Field | Value |
|---|---|
| **Name** | Python Bytecode Cache |
| **Safety** | `safe` |
| **Match** | `__pycache__/`, `*.pyc`, `*.pyo` |
| **Action** | Trash |

### `python-venvs`
| Field | Value |
|---|---|
| **Name** | Python Virtual Environments |
| **Safety** | `cautious` |
| **Match** | `.venv/`, `venv/`, `.virtualenv/` containing `pyvenv.cfg` |
| **Min Size** | 50 MB |
| **Min Age** | 30 days |
| **Action** | Trash |
| **Notes** | Cautious because user may have custom packages installed. |

### `python-tool-caches`
| Field | Value |
|---|---|
| **Name** | Python Tool Caches |
| **Safety** | `safe` |
| **Match** | `.tox/`, `.mypy_cache/`, `.pytest_cache/`, `.ruff_cache/`, `*.egg-info/` |
| **Action** | Trash |

### `python-uv-cache`
| Field | Value |
|---|---|
| **Name** | uv Cache |
| **Safety** | `safe` |
| **Match** | `~/.cache/uv/**` |
| **Min Size** | 100 MB |
| **Action** | Trash |
| **Notes** | Package resolution and download cache for uv. Growing rapidly in modern projects as of 2026. |

### `python-poetry-cache`
| Field | Value |
|---|---|
| **Name** | Poetry Cache |
| **Safety** | `safe` |
| **Match** | `~/Library/Caches/pypoetry/**` |
| **Min Size** | 50 MB |
| **Action** | Trash |

---

## Category: `ml`

### `ml-checkpoints`
| Field | Value |
|---|---|
| **Name** | ML Model Checkpoints |
| **Safety** | `cautious` |
| **Match** | `*.ckpt`, `*.ckpt.data-*`, `*.ckpt.index`, `checkpoint` files |
| **Min Size** | 100 MB |
| **Min Age** | 14 days |
| **Action** | Trash |
| **Notes** | Training checkpoints can be multi-GB. Cautious — user may want the latest checkpoint. |

### `ml-safetensors-cache`
| Field | Value |
|---|---|
| **Name** | Cached Model Weights |
| **Safety** | `cautious` |
| **Match** | `~/.cache/huggingface/hub/**/*.safetensors`, `~/.cache/huggingface/hub/**/*.bin` |
| **Min Age** | 30 days |
| **Action** | Trash |
| **Notes** | HuggingFace model cache. Can grow to 50+ GB. |

### `ml-wandb`
| Field | Value |
|---|---|
| **Name** | Weights & Biases Local Data |
| **Safety** | `cautious` |
| **Match** | `wandb/` directories, `wandb/run-*/**` |
| **Min Age** | 7 days |
| **Action** | Trash |
| **Notes** | Local run data is often synced, but offline runs and artifacts can be user-authored. Require review. |

### `ml-tensorboard`
| Field | Value |
|---|---|
| **Name** | TensorBoard Log Directories |
| **Safety** | `cautious` |
| **Match** | `runs/`, `logs/` containing `events.out.tfevents.*` files |
| **Min Age** | 14 days |
| **Action** | Trash |

### `ml-datasets-cache`
| Field | Value |
|---|---|
| **Name** | Cached Datasets |
| **Safety** | `cautious` |
| **Match** | `~/.cache/huggingface/datasets/**`, `~/.cache/torch/datasets/**` |
| **Min Age** | 30 days |
| **Action** | Trash |

### `ml-ollama-models`
| Field | Value |
|---|---|
| **Name** | Ollama Downloaded Models |
| **Safety** | `cautious` |
| **Match** | `~/.ollama/models/**` |
| **Min Size** | 500 MB |
| **Action** | Trash |
| **Notes** | LLM model files, often 4-70 GB each. Cautious — user may want specific models. |

### `ml-lmstudio-models`
| Field | Value |
|---|---|
| **Name** | LM Studio Downloaded Models |
| **Safety** | `cautious` |
| **Match** | `~/.lmstudio/models/**` (current default); `~/.cache/lm-studio/models/**` (legacy). Honor a user-set model directory. |
| **Min Size** | 500 MB |
| **Action** | Trash |
| **Notes** | GGUF/MLX weights, 4–70 GB each. Cautious — expensive to re-download and deliberately chosen. |

### `ml-vector-dbs`
| Field | Value |
|---|---|
| **Name** | Local Vector Databases |
| **Safety** | `cautious` |
| **Match** | `**/chroma/**/*.sqlite3`, `**/.qdrant/storage/**`, `**/.milvus/**` |
| **Min Size** | 100 MB |
| **Min Age** | 14 days |
| **Action** | Trash |
| **Notes** | Vector store storage databases generated during local RAG application development. |

### `ml-vllm-cache`
| Field | Value |
|---|---|
| **Name** | vLLM Model Cache |
| **Safety** | `cautious` |
| **Match** | `~/.cache/vllm/**` |
| **Min Size** | 1 GB |
| **Action** | Trash |

---

## Category: `docker`

Docker cleanup is implemented through `cleanton docker` commands and the Docker Engine API.
The checked-in Docker TOML recipe files are disabled for normal filesystem planning so scans do
not propose fake `docker-dummy-*` path actions.

### `docker-build-cache`
| Field | Value |
|---|---|
| **Name** | Docker Build Cache |
| **Safety** | `safe` |
| **Match** | Via Docker API — `docker system df` build cache |
| **Action** | Docker API prune |
| **Notes** | Uses `bollard` crate, not filesystem ops. |

### `docker-dangling-images`
| Field | Value |
|---|---|
| **Name** | Docker Dangling Images |
| **Safety** | `safe` |
| **Match** | Via Docker API — images with `<none>` tag |
| **Action** | Docker API remove |

### `docker-stopped-containers`
| Field | Value |
|---|---|
| **Name** | Docker Stopped Containers |
| **Safety** | `cautious` |
| **Match** | Via Docker API — containers with `Exited` status |
| **Min Age** | 7 days |
| **Action** | Docker API remove |

### `docker-unused-volumes`
| Field | Value |
|---|---|
| **Name** | Docker Unused Volumes |
| **Safety** | `aggressive` |
| **Match** | Via Docker API — volumes not attached to any container |
| **Action** | Docker API remove |
| **Notes** | Aggressive — volumes may contain database data. |

---

## Category: `ai-tools`

### `ai-codex-cache`
| Field | Value |
|---|---|
| **Name** | OpenAI Codex CLI Cache and Logs |
| **Safety** | `cautious` |
| **Match** | `~/.codex-cache/**` only — the dedicated cache dir. The active `~/.codex/` dir (auth, config, sessions, history) is **never** matched. |
| **Exclude** | by name `auth.json`, `config.toml`, `config.json`, `credentials.json`, `.credentials.json` |
| **Min Age** | 14 days |
| **Action** | Trash |
| **Notes** | Never delete the entire `~/.codex` directory. Agent state can contain auth, working memory, and conversation history. |

### `ai-codex-worktrees`
| Field | Value |
|---|---|
| **Name** | Codex Worktrees |
| **Safety** | `cautious` |
| **Match** | `~/.codex/worktrees/**` |
| **Min Age** | 14 days |
| **Action** | Trash |
| **Notes** | Keeps auth, config, sessions, and history outside the match scope. |

### `ai-claude-code-cache`
| Field | Value |
|---|---|
| **Name** | Claude Code Cache & Logs |
| **Safety** | `cautious` |
| **Match** | `~/.claude/statsig/**` only — the regenerable Statsig feature-flag cache. **Never** the whole `~/.claude` dir. |
| **Exclude** | `~/.claude/projects/**` (transcripts), `todos/`, `history/`, `sessions/`; and by name `.credentials.json`, `settings.json`, `settings.local.json`, `.claude.json`, `mcp.json`, `CLAUDE.md` |
| **Min Age** | 7 days |
| **Action** | Trash |
| **Notes** | Statsig is the only subtree we can clear with zero risk to credentials, settings, MCP config, transcripts, or memory. If a wider safe cache subdir is ever identified, extend the match then; do not broaden to the whole dir. |

### `ai-claude-code-worktrees`
| Field | Value |
|---|---|
| **Name** | Claude Code Worktrees |
| **Safety** | `cautious` |
| **Match** | `~/.claude/worktrees/**` |
| **Min Age** | 14 days |
| **Action** | Trash |
| **Notes** | Keeps settings, credentials, MCP config, and memory files outside the match scope. |

### `ai-cursor-cache`
| Field | Value |
|---|---|
| **Name** | Cursor Editor Cache |
| **Safety** | `safe` |
| **Match** | `~/Library/Application Support/Cursor/Cache/**`, `~/Library/Application Support/Cursor/CachedData/**` |
| **Action** | Trash |

### `ai-copilot-cache`
| Field | Value |
|---|---|
| **Name** | GitHub Copilot Cache |
| **Safety** | `cautious` |
| **Match** | Known Copilot/editor cache directories only; `~/Library/Caches/co.tabnine.*` belongs to Tabnine and must be a separate recipe |
| **Action** | Trash |

### `ai-gemini-cache`
| Field | Value |
|---|---|
| **Name** | Gemini / Antigravity Cache |
| **Safety** | `cautious` |
| **Match** | Known cache/log subdirectories under `~/.gemini/` |
| **Exclude** | config, credentials, auth tokens, project instructions, conversation history |
| **Min Age** | 14 days |
| **Action** | Trash |

---

## Category: `apps`

### `apps-orphaned-support`
| Field | Value |
|---|---|
| **Name** | Orphaned Application Support |
| **Safety** | `aggressive` |
| **Match** | `~/Library/Application Support/<app>` where `<app>.app` is not in `/Applications/` |
| **Min Age** | 30 days |
| **Action** | Trash |
| **Notes** | Aggressive — requires heuristic matching of app names. ML model can help here. |

### `apps-orphaned-caches`
| Field | Value |
|---|---|
| **Name** | Orphaned Application Caches |
| **Safety** | `cautious` |
| **Match** | `~/Library/Caches/<bundle-id>` where the bundle ID doesn't match any installed app |
| **Min Age** | 30 days |
| **Action** | Trash |

### `apps-orphaned-preferences`
| Field | Value |
|---|---|
| **Name** | Orphaned Preferences |
| **Safety** | `cautious` |
| **Match** | `~/Library/Preferences/<bundle-id>.plist` where bundle ID is orphaned |
| **Min Age** | 60 days |
| **Action** | Trash |

### `browser-edge-http-cache`
| Field | Value |
|---|---|
| **Name** | Edge HTTP Cache |
| **Safety** | `cautious` |
| **Match** | `~/Library/Application Support/Microsoft Edge/*/Cache/Cache_Data/**`, `~/.config/microsoft-edge/*/Cache/Cache_Data/**` |
| **Min Age** | 7 days |
| **Action** | Trash |
| **Notes** | Profile databases (History, Bookmarks, Login Data) are siblings and never match. |

### `browser-brave-http-cache`
| Field | Value |
|---|---|
| **Name** | Brave HTTP Cache |
| **Safety** | `cautious` |
| **Match** | `~/Library/Application Support/BraveSoftware/Brave-Browser/*/Cache/Cache_Data/**`, `~/.config/BraveSoftware/Brave-Browser/*/Cache/Cache_Data/**` |
| **Min Age** | 7 days |
| **Action** | Trash |
| **Notes** | Profile databases (History, Bookmarks, Login Data) are siblings and never match. |

### `browser-vivaldi-http-cache`
| Field | Value |
|---|---|
| **Name** | Vivaldi HTTP Cache |
| **Safety** | `cautious` |
| **Match** | `~/Library/Application Support/Vivaldi/*/Cache/Cache_Data/**`, `~/.config/vivaldi/*/Cache/Cache_Data/**` |
| **Min Age** | 7 days |
| **Action** | Trash |
| **Notes** | Profile databases (History, Bookmarks, Login Data) are siblings and never match. |

### `apps-discord-cache`
| Field | Value |
|---|---|
| **Name** | Discord Cache |
| **Safety** | `cautious` |
| **Match** | `~/Library/Application Support/discord/Cache/**`, `~/.config/discord/Cache/**` |
| **Min Age** | 14 days |
| **Action** | Trash |
| **Notes** | Only the Cache subtree; Local Storage, IndexedDB and settings hold your session and never match. |

---

## Category: `system`

### `system-xcode-caches`
| Field | Value |
|---|---|
| **Name** | Xcode Caches |
| **Safety** | `safe` |
| **Match** | `~/Library/Caches/com.apple.dt.Xcode/**` |
| **Action** | Trash |

### `system-time-machine-local-snapshots`
| Field | Value |
|---|---|
| **Name** | Time Machine Local Snapshots |
| **Safety** | `aggressive` |
| **Match** | `**/com.apple.TimeMachine.localsnapshots/**` |
| **Min Age** | 7 days |
| **Action** | Archive / advisory only |
| **Notes** | APFS local snapshots must be thinned through `tmutil`; Cleanton must not trash snapshot mount contents. This recipe is intentionally non-executable until a tmutil-backed executor is implemented. |

### `system-homebrew-cache`
| Field | Value |
|---|---|
| **Name** | Homebrew Download Cache |
| **Safety** | `safe` |
| **Match** | `~/Library/Caches/Homebrew/**` |
| **Min Age** | 30 days |
| **Action** | Trash |

### `system-cocoapods-cache`
| Field | Value |
|---|---|
| **Name** | CocoaPods Cache |
| **Safety** | `safe` |
| **Match** | `~/Library/Caches/CocoaPods/**` |
| **Min Age** | 30 days |
| **Action** | Trash |

### `system-old-logs`
| Field | Value |
|---|---|
| **Name** | Old User Log Files |
| **Safety** | `cautious` |
| **Match** | `~/Library/Logs/**` |
| **Min Age** | 30 days |
| **Action** | Trash |
| **Notes** | User logs can contain diagnostics needed for support or development. Never match `/Library/Logs` or `/var/log`. |

### `system-crash-reports`
| Field | Value |
|---|---|
| **Name** | Old Crash Reports |
| **Safety** | `cautious` |
| **Match** | `~/Library/Logs/DiagnosticReports/**` |
| **Min Age** | 14 days |
| **Action** | Trash |
| **Notes** | Crash reports may be needed for symbolication, bug reports, and app support. |

### `system-thumbnail-cache`
| Field | Value |
|---|---|
| **Name** | Thumbnail Caches |
| **Safety** | `safe` |
| **Match** | `~/.cache/thumbnails/**`, `~/Library/Caches/com.apple.iconservices/**` |
| **Min Age** | 14 days |
| **Action** | Trash |
| **Notes** | Derived image stores the desktop regenerates on demand; originals are untouched. |

### `system-security-scanner-caches`
| Field | Value |
|---|---|
| **Name** | Security Scanner Caches |
| **Safety** | `safe` |
| **Match** | `~/.cache/{trivy,grype,snyk}/**`, `~/Library/Caches/{trivy,grype}/**` |
| **Min Age** | 14 days |
| **Action** | Trash |
| **Notes** | Local copies of the vulnerability feeds; every scanner re-downloads them. |

### `system-package-manager-caches`
| Field | Value |
|---|---|
| **Name** | System Package Manager Caches |
| **Safety** | `safe` |
| **Match** | `~/.cache/{snapcraft,flatpak,packagekit}/**` |
| **Min Age** | 30 days |
| **Action** | Trash |
| **Notes** | `/var/cache/apt` is deliberately not matched because only root may clear it. |

### `helm-kubernetes-caches`
| Field | Value |
|---|---|
| **Name** | Helm Caches |
| **Safety** | `safe` |
| **Match** | `~/.cache/helm/**`, `~/Library/Caches/helm/**` |
| **Min Age** | 30 days |
| **Action** | Trash |
| **Notes** | Cached chart archives and repository indexes; `~/.kube` is never touched. |

### `firebase-emulator-cache`
| Field | Value |
|---|---|
| **Name** | Firebase Emulator Caches |
| **Safety** | `cautious` |
| **Match** | `~/.cache/firebase/emulators/**`, `~/Library/Caches/firebase/emulators/**` |
| **Min Age** | 30 days |
| **Action** | Trash |
| **Notes** | Downloaded emulator jars only; credentials and exported data are siblings. |

### `nim-cache`
| Field | Value |
|---|---|
| **Name** | Nim Cache |
| **Safety** | `safe` |
| **Match** | `~/.cache/nim/**`, `~/Library/Caches/nim/**` |
| **Min Age** | 30 days |
| **Action** | Trash |
| **Notes** | Generated C sources the compiler rewrites on every build. |

### `ocaml-dune-cache`
| Field | Value |
|---|---|
| **Name** | Dune Cache |
| **Safety** | `safe` |
| **Match** | `~/.cache/dune/**`, `~/Library/Caches/dune/**` |
| **Min Age** | 30 days |
| **Action** | Trash |
| **Notes** | Dune's shared build artefacts. |

---

## Category: `go`

### `go-build-cache`
| Field | Value |
|---|---|
| **Name** | Go Build Cache |
| **Safety** | `safe` |
| **Match** | `~/Library/Caches/go-build/**` |
| **Action** | Trash |

### `go-mod-cache`
| Field | Value |
|---|---|
| **Name** | Go Module Cache |
| **Safety** | `safe` |
| **Match** | `~/go/pkg/mod/cache/**` |
| **Min Age** | 30 days |
| **Action** | Trash |

---

## Additional 2026-Era Recipes

> These extend the categories above for the modern macOS developer stack. All follow the
> [Recipe Acceptance Rules](#recipe-acceptance-rules) and the normative match semantics in
> [CRATES.md](./CRATES.md) §3.4 (fields AND'd, lists OR'd, excludes win, `min_age` on the newest
> descendant mtime, size hardlink-deduped).

### Category: `rust` (additions)

| Recipe | Safety | Match | Age/Size | Notes |
|---|---|---|---|---|
| `rust-rustup-toolchains` | `cautious` | `~/.rustup/toolchains/<name>/**` | min age 90d | Skip the **active/default** toolchain (`rustup show active-toolchain`); old toolchains are GBs. Regenerate via `rustup toolchain install`. |
| `rust-cargo-git` | `safe` | `~/.cargo/git/checkouts/**`, `~/.cargo/git/db/**` | min age 30d | Git dependency checkouts; re-fetched on demand. |

### Category: `swift` (additions)

| Recipe | Safety | Match | Age/Size | Notes |
|---|---|---|---|---|
| `swift-spm-cache` | `safe` | `~/Library/Caches/org.swift.swiftpm/**`, `~/Library/org.swift.swiftpm/cache/**` | — | SwiftPM dependency cache; rebuilt on resolve. |
| `swift-simulator-unavailable` | `cautious` | CoreSimulator devices marked unavailable | — | Prefer driving `xcrun simctl delete unavailable` over raw deletion so Xcode's index stays consistent. |
| `swift-previews` | `safe` | `~/Library/Developer/Xcode/UserData/Previews/**` | — | SwiftUI preview build products; regenerable. |

### Category: `node` (additions)

| Recipe | Safety | Match | Age/Size | Notes |
|---|---|---|---|---|
| `node-framework-caches` | `safe` | dirs `.svelte-kit/`, `.astro/`, `.nuxt/`, `.vite/`, `.angular/cache/`, `.docusaurus/`, `.parcel-cache/` with `package.json` parent | — | Framework build/dev caches; regenerated on next build. |
| `node-deploy-caches` | `cautious` | `.vercel/`, `.netlify/`, `.wrangler/` with `package.json` parent | — | May hold linked-project + deploy metadata; cautious, not deleted blind. |
| `node-yarn-classic-cache` | `safe` | `~/Library/Caches/Yarn/**` | min age 30d | Yarn v1 global cache. |
| `node-yarn-berry-cache` | `cautious` | in-project `.yarn/cache/**`, `.yarn/unplugged/**` | — | **Zero-install** repos commit `.yarn/cache`; deleting breaks offline installs. Skip if `.yarnrc.yml` enables PnP zero-install. |

### Category: `python` (additions)

| Recipe | Safety | Match | Age/Size | Notes |
|---|---|---|---|---|
| `python-pip-cache` | `safe` | `~/Library/Caches/pip/**`, `~/.cache/pip/**` | min age 30d | pip wheel/http cache; `pip cache purge` equivalent. |
| `python-conda-pkgs` | `cautious` | `<conda-root>/pkgs/**` (`~/miniconda3`, `~/anaconda3`, `~/miniforge3`), `~/.conda/pkgs/**` | min age 30d | Prefer `conda clean -p`; pkgs are hardlinked into envs (PLATFORM §1.5). |
| `python-pixi-cache` | `safe` | `~/.cache/rattler/**`, `~/Library/Caches/rattler/**` | min size 100 MB | pixi/rattler package cache (growing in 2026). |

### Category: `jvm-android`

| Recipe | Safety | Match | Age/Size | Notes |
|---|---|---|---|---|
| `gradle-caches` | `safe` | `~/.gradle/caches/**` | min age 30d | Gradle build cache & downloaded artifacts; re-fetched. Skip `~/.gradle/wrapper` only if active. |
| `gradle-project-build` | `cautious` | dirs `build/` whose parent contains `build.gradle`/`build.gradle.kts`/`settings.gradle*` | min size 50 MB | Android/Kotlin/KMP build output; regenerable but cautious (may hold signed APKs/AABs). |
| `android-avd` | `cautious` | `~/.android/avd/**` | min size 500 MB | Emulator disk images & snapshots; deleting loses emulator state. |
| `android-system-images` | `cautious` | `~/Library/Android/sdk/system-images/**`, `~/Library/Android/sdk/sources/**` | min size 500 MB, age 90d | Re-installable via SDK manager; multi-GB each. |

### Category: `dart-flutter`

| Recipe | Safety | Match | Age/Size | Notes |
|---|---|---|---|---|
| `dart-pub-cache` | `cautious` | `~/.pub-cache/**`, `$PUB_CACHE/**` | min age 30d | Shared package cache; `dart pub cache clean` re-downloads. Cautious: may hold local path/git pkgs. |
| `flutter-project-build` | `safe` | dirs `build/`, `.dart_tool/` whose parent contains `pubspec.yaml` | min size 50 MB | Flutter/Dart build artifacts; regenerable. |

### Category: `editors`

| Recipe | Safety | Match | Age/Size | Notes |
|---|---|---|---|---|
| `jetbrains-caches` | `safe` | `~/Library/Caches/JetBrains/**` | — | IDE indices/system caches (IntelliJ, PyCharm, CLion, RustRover…); rebuilt on open. Never touch `~/Library/Application Support/JetBrains` (settings/plugins). |
| `vscode-caches` | `safe` | `~/Library/Application Support/Code/Cache/**`, `.../CachedData/**`, `.../Code Cache/**`, `.../GPUCache/**` | — | Electron caches. Never match `User/` (settings, keybindings, snippets) or `extensions/`. |
| `vscode-variants` | `safe` | same subpaths under `Code - Insiders/`, `VSCodium/`, `Cursor/`, `Windsurf/` | — | Mirror of the above for VS Code forks/variants. Distinct from AI agent state (see `ai-tools`). |

### Category: `ml` (additions)

| Recipe | Safety | Match | Age/Size | Notes |
|---|---|---|---|---|
| `ml-torch-hub` | `cautious` | `~/.cache/torch/hub/**`, `~/.cache/torch/checkpoints/**` | min age 30d | Downloaded model weights; re-downloaded on demand. |
| `ml-triton-cache` | `safe` | `~/.triton/cache/**` | min size 100 MB | GPU kernel compilation cache. |

> **MLX (Apple Silicon)** stores weights in the Hugging Face hub (`~/.cache/huggingface/hub`),
> already covered by `ml-safetensors-cache`. See [PLATFORM.md](./PLATFORM.md) §7.

### Container runtimes beyond Docker Desktop

Docker recipes are **API-driven** (`bollard`), not filesystem globs. In 2026 the active runtime may
be **OrbStack, Colima, Podman, or Rancher Desktop** — the engine connects to whichever Engine-API
socket exists (`DOCKER_HOST` first, then known socket paths) and is inert if none is present. After
any API prune, results state that space was freed **inside the VM** and the host-side disk image may
not shrink until the runtime compacts it. Full details and per-runtime paths: [PLATFORM.md](./PLATFORM.md) §5.

---

### Recently added (maintenance pass)

A set of caches added after the original registry, each scoped to a tool-owned
subtree so a generic dotfolder (`~/.sbt/global.sbt`, `~/.conan/profiles`, …)
is never matched.

| Recipe | Safety | Match | Age/Size | Notes |
|---|---|---|---|---|
| `c-cpp-ccache` | `safe` | `~/Library/Caches/ccache/**` or `~/.cache/ccache/**` | min size 50 MB, min age 30d | ccache object-file cache; rebuilt on the next compile. |
| `c-cpp-conan-cache` | `cautious` | `~/.conan/data/**` (Conan 1) or `~/.conan2/p/**` (Conan 2) | min size 50 MB, min age 30d | Downloaded packages; re-download on demand. Scopes away profiles/settings. |
| `go-module-cache` | `cautious` | `~/go/pkg/mod/**` excluding `~/go/pkg/mod/cache/**` | min age 30d | Extracted modules; the download cache is `go-mod-cache`. |
| `rust-cargo-registry-index` | `safe` | `~/.cargo/registry/index/**` | min age 30d | Sparse-index metadata; Cargo re-fetches on demand. |
| `jvm-sbt-cache` | `cautious` | `~/.sbt/boot/**` | min age 30d | sbt launcher boot jars; re-resolved on demand. Never `~/.sbt/global.sbt`/`plugins`. |
| `ai-opencode-cache` | `cautious` | `~/.cache/opencode/**` | min age 14d | OpenCode model/log cache; regenerable. |
| `apps-slack-cache` | `cautious` | `~/Library/Caches/com.tinyspeck.slackmacgap/**` | min age 14d | Slack desktop HTTP/media cache; re-fetched on demand. |
| `browser-safari-cache` | `cautious` | `~/Library/Caches/com.apple.Safari/**` | min age 7d | Safari WebKit content cache; re-fetched from the origin. |

> Docker recipes remain API-driven (`bollard`) and are intentionally not
> filesystem globs; the `docker-*` TOML entries are disabled placeholders.

## Recipe Priority Order

When multiple recipes match the same path, priority determines which recipe "owns" it:

| Priority Range | Category |
|---|---|
| 90-100 | `safe` filesystem recipes (target/, node_modules/) |
| 70-89 | `safe` cache recipes |
| 50-69 | `cautious` recipes |
| 30-49 | Docker recipes |
| 10-29 | `aggressive` recipes |
| 0-9 | ML-inferred (fallback) |

## Recipe Acceptance Rules

Every built-in recipe must satisfy these checks before it can ship:

1. It has at least one `should_match` and one `should_not_match` fixture.
2. It cannot match any protected path, credential file, shell history, keychain, user document/media folder, cloud root, external volume root, or Cleanton's own config/logs.
3. It includes context proof for generic names such as `build`, `dist`, `cache`, `logs`, `tmp`, `models`, `runs`, and `data`.
4. Its default action is `trash` unless the target is a small, tool-owned cache with no user-authored contents.
5. Its safety level is `cautious` or `aggressive` if the target can contain user-generated state, credentials, conversation history, datasets, database contents, deployment artifacts, or support diagnostics.
6. It documents what command regenerates the data when claiming `safe`.
7. It has a minimum age unless the target is provably pure build output.
8. It treats cloud-provider, File Provider, and external-volume paths as opt-in.

### `python-ruff-cache`
| Field | Value |
|---|---|
| **Name** | Ruff Cache |
| **Safety** | `safe` |
| **Match** | `~/.cache/ruff/**` or a project `.ruff_cache` beside a Python project marker |
| **Min Age** | 14 days |
| **Action** | Trash |
| **Notes** | Rebuilt automatically on the next ruff run. |

### `python-precommit-cache`
| Field | Value |
|---|---|
| **Name** | pre-commit Cache |
| **Safety** | `safe` |
| **Match** | `~/.cache/pre-commit/**` |
| **Min Age** | 30 days |
| **Action** | Trash |
| **Notes** | Hook environments are re-cloned and rebuilt on the next run. |

### `node-corepack-cache`
| Field | Value |
|---|---|
| **Name** | Corepack Cache |
| **Safety** | `safe` |
| **Match** | `~/.cache/node/corepack/**` or `~/Library/Caches/node/corepack/**` |
| **Min Age** | 30 days |
| **Action** | Trash |
| **Notes** | Downloaded pnpm/yarn shims are re-downloaded on demand. |
