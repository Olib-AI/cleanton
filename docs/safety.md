# Safety

Cleanton removes files. This page explains how it tries to keep that safe, and where your judgment is still required.

## What Cleanton does by default

- **Moves to the Trash, not permanent delete.** Anything Cleanton removes goes to the macOS Trash. You can restore it until you empty the Trash.
- **Shows the full plan first.** Every scan produces a reviewable list with per-item sizes. You confirm the final selection.
- **Targets rebuildable artifacts.** The built-in recipes aim at build caches and dependency folders that your tools recreate on demand: Rust `target` directories, `node_modules`, Swift DerivedData, Python virtual environments and caches, Docker dangling images and build cache, and machine learning model caches.

## What Cleanton will not do for you

- **It does not auto-remove large folders.** The Suggestions view lists large folders and re-clonable repositories for you to review. It never removes them on its own.
- **It does not touch source code or documents.** The recipes match known cache and artifact locations, not your working files. When in doubt, Cleanton leaves it alone and you can still select it manually if you know what it is.
- **It does not act without confirmation.** A scan never removes anything. Removal happens only after you confirm a selection.

## Where your judgment matters

- **Read the plan.** A clean machine can show tens of gigabytes. Confirm you understand each large item before you act.
- **Rebuild cost.** Removing a cache means the next build is slower while the tool repopulates it. That is the trade you are making.
- **Back up first.** Cleanton targets rebuildable data, but you confirm the final list. Keep backups of anything you cannot lose.
- **Empty the Trash deliberately.** Recovery is possible only until you empty the Trash.

## Reporting a safety issue

If Cleanton ever removes or flags something you did not select, email **security@olib.ai** with the details. Please do not open a public issue for data-loss reports. See [SECURITY.md](../SECURITY.md).
