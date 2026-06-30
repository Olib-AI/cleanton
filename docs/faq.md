# FAQ

### Is Cleanton free?

Yes, it is free to download and use. It is closed source. See [LICENSE](../LICENSE).

### Does it work on Intel Macs?

The current release is built for Apple Silicon (arm64). If you need an Intel build, open an [issue](https://github.com/Olib-AI/cleanton/issues) and tell us.

### Can I get my files back after a cleanup?

Yes, as long as you have not emptied the Trash. Cleanton moves removed items to the Trash by default rather than deleting them.

### Why does the command-line tool get a Gatekeeper warning when the app does not?

The app is notarized by Apple, so it opens cleanly. The standalone CLI is signed but distributed on its own, so macOS quarantines it on direct download. The installer script clears that flag for you. If you install the CLI by hand, run `xattr -d com.apple.quarantine ./cleanton` once. See [installation](installation.md).

### What does Cleanton clean?

Build caches and dependency folders for Rust, Node, Swift, and Python, plus Docker images and build cache, and machine learning model caches. See [usage](usage.md) for the full picture.

### Will it delete my source code or documents?

No. The recipes match known cache and artifact locations, not your working files, and nothing is removed without your confirmation. See [safety](safety.md).

### What is the difference between Results and Suggestions?

Results are reclaimable items you can select and remove. Suggestions are review only: large folders and re-clonable git repositories that Cleanton points out but never removes for you.

### Does it need Full Disk Access?

No, but some protected folders stay hidden from any tool until you grant it. Cleanton runs without it and reports what it skipped. Run `cleanton doctor` or read the in-app prompt for how to grant it.

### Where do I report a bug or ask for a feature?

Open an [issue](https://github.com/Olib-AI/cleanton/issues). For anything involving data loss or security, email security@olib.ai instead.
