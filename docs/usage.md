# Using Cleanton

Nothing is removed until you confirm. Read the plan, select what you want, then act.

## The app

1. **Pick a scan root.** The default is your home folder. You can point it anywhere you own.
2. **Scan.** Cleanton walks the tree and groups what it finds by category: Rust, Node, Swift, Python, Docker, machine learning, and more.
3. **Review.** Each category expands into groups, and each group expands into individual items with their sizes. Select or skip anything, down to a single folder.
4. **Act.** Confirm the selection. Removed items go to the Trash, where you can recover them until you empty it.

### Results and suggestions

- **Results** shows the reclaimable items, grouped and selectable.
- **Suggestions** is review only. It lists large folders worth a look and large git repositories that have a remote and no local changes, which you could re-clone instead of storing. Cleanton never removes these for you.

### Packages

The Packages tab reads your installed npm, pip, Homebrew, and MacPorts packages. You can update them, clean their caches, and remove ones you do not want. For Homebrew, Cleanton computes a dependency-aware removal plan: keep the packages you want, and it works out which dependencies are safe to drop. It also scans your codebases and warns when a package you are about to remove is referenced by one of them.

## The command-line tool

```sh
# show everything reclaimable, grouped, without removing anything
cleanton plan

# write the same view as JSON
cleanton plan --json

# run the plan after reviewing it (items go to the Trash)
cleanton plan --apply
```

Useful flags:

```sh
# scan a specific root
cleanton plan --root ~/work

# check Full Disk Access status and how to grant it
cleanton doctor
```

Run `cleanton --help` for the complete command and flag list.

## Full Disk Access

Some protected folders are hidden from any tool until you grant Full Disk Access. Cleanton works without it and reports the locations it had to skip. To scan everything, grant access in System Settings, Privacy and Security, Full Disk Access. The app and the command-line tool each have their own entry there.
