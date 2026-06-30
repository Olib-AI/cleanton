# Cleanton — Documentation Index

> Architecture and design documentation for the Cleanton disk cleaning app.

---

## Documents

| Document | Description |
|---|---|
| [ARCHITECTURE.md](./ARCHITECTURE.md) | High-level architecture, crate structure, data flow pipeline, tech stack, development phases |
| [CRATES.md](./CRATES.md) | Detailed specification for each of the 9 crates — modules, rules, APIs, types |
| [ML_PIPELINE.md](./ML_PIPELINE.md) | Python training framework, dataset generation, neural net models, and ONNX export |
| [RECIPES.md](./RECIPES.md) | Full reference of 60+ built-in cleanup recipes by category (incl. 2026 stacks: MLX/Ollama/LM Studio, Android/Gradle, Flutter, modern JS frameworks, JetBrains/VS Code) |
| [ICONS.md](./ICONS.md) | FontAwesome Pro integration strategy — Nerd Font, Unicode, ASCII tiers + SVG hero icons |
| [UI_DESIGN.md](./UI_DESIGN.md) | Visual design spec — color palette, layouts, animations, keyboard shortcuts, responsive behavior |
| [SAFETY.md](./SAFETY.md) | Safety model — threat analysis, defense layers, execution logging, testing procedures |
| [PLATFORM.md](./PLATFORM.md) | macOS Tahoe 26 / APFS realities — freed-vs-reclaimable, snapshots, TCC & Full Disk Access, notarization, path-safety traps, container runtimes |
| [IMPLEMENTATION_PLAN.md](./IMPLEMENTATION_PLAN.md) | Milestones, release gates, risk register, and non-negotiable acceptance criteria |

---

## Quick Reference

### Crate Map

```
cleanton-cli          Binary entry point, CLI args, mode dispatch
cleanton-app          Native Slint GUI application
cleanton-ui           TUI (ratatui) — dashboard, results, services, execution screens
cleanton-engine       Core pipeline orchestrator: scan → analyze → plan → execute
cleanton-scanner      Parallel filesystem walker, project root detection
cleanton-recipes      TOML recipe parser, pattern matcher, recipe registry
cleanton-services     macOS services manager (launchd plists + Homebrew services)
cleanton-ml           Optional ONNX-based file classification (feature-gated)
cleanton-common       Shared types, errors, config, path safety utilities
```

### Pipeline

```
SCAN → ANALYZE → PLAN → CONFIRM → EXECUTE
 │        │        │        │         │
 FS walk  Recipes  Actions  Dry-run   Trash/Delete
 Metadata ML       Priority User OK   Log
```

### Safety Levels

| Level | Color | Description |
|---|---|---|
| `safe` | 🟢 | Regenerable artifacts with strong local proof — `target/`, `__pycache__/`, tool caches |
| `cautious` | 🟡 | Likely removable but user/project context matters — virtualenvs, checkpoints, stopped containers |
| `aggressive` | 🔴 | High data-loss risk — orphaned app data, Docker volumes, datasets |

### Non-Negotiable Rule

Cleanton must never convert a scan finding directly into a destructive operation. Every item must pass:

```
recipe/heuristic match -> safety validation -> protected path check -> plan review -> execution log
```

### Docker Cleanup

Docker cleanup is API-backed, not filesystem-recipe-backed:

```sh
cleanton docker analyze
cleanton docker clean --dangling-images --stopped-containers --build-cache
cleanton docker clean --unused-volumes --yes
```

`docker clean` is a dry run unless `--yes` is passed. Reported bytes are reclaimed inside the
Docker runtime/VM and must not be presented as guaranteed host APFS free space.
