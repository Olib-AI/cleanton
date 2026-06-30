import os
import sys

# ---------------------------------------------------------------------------
# WARNING: This generator is NO LONGER the source of truth.
#
# The checked-in recipes/*.toml files are authoritative (see doc/RECIPES.md).
# They have since diverged from this script in ways this writer cannot express:
#   * per-recipe `priority` and `enabled = false` (e.g. the docker placeholders)
#   * `[match.exclude]` blocks (credentials/settings/transcript guards on the
#     ai-* recipes, release-artifact excludes on rust-target-dirs, etc.)
#   * trash-by-default actions and the narrowly-scoped AI cache matches
#
# Running this as-is would CLOBBER those safety properties (it hardcodes
# `enabled = true`, `priority = 50`, and emits no excludes). It is kept only as
# a scaffold for bulk-authoring brand-new recipes. To run it intentionally,
# set CLEANTON_ALLOW_RECIPE_REGEN=1 and then manually re-apply excludes,
# priorities, enabled flags, and AI-cache scoping before committing.
# ---------------------------------------------------------------------------
if os.environ.get("CLEANTON_ALLOW_RECIPE_REGEN") != "1":
    sys.exit(
        "refusing to regenerate: recipes/*.toml are the source of truth and this "
        "generator cannot emit excludes/priority/enabled. Set "
        "CLEANTON_ALLOW_RECIPE_REGEN=1 to override (see header comment)."
    )

recipes_data = [
    # Category: rust
    {
        "id": "rust-cargo-registry-cache",
        "name": "Cargo Registry Cache",
        "description": "Downloaded Cargo .crate files",
        "category": "rust",
        "safety_level": "aggressive",
        "match": {
            "path_glob": "~/.cargo/registry/cache/**",
            "min_age_days": 30
        },
        "action": {
            "type": "delete",
            "prompt": "Delete {size} of Cargo registry cache?",
            "group": True
        },
        "test": {
            "should_match": ["~/.cargo/registry/cache/foo.crate"],
            "should_not_match": ["~/.cargo/registry/src/foo"]
        }
    },
    {
        "id": "rust-cargo-registry-src",
        "name": "Cargo Registry Source Checkouts",
        "description": "Extracted Cargo registry source code checkouts",
        "category": "rust",
        "safety_level": "aggressive",
        "match": {
            "path_glob": "~/.cargo/registry/src/**",
            "min_age_days": 30
        },
        "action": {
            "type": "delete",
            "prompt": "Delete {size} of Cargo registry source checkouts?",
            "group": True
        },
        "test": {
            "should_match": ["~/.cargo/registry/src/foo/bar.rs"],
            "should_not_match": ["~/.cargo/registry/cache/foo.crate"]
        }
    },
    {
        "id": "rust-incremental-cache",
        "name": "Rust Incremental Compilation Cache",
        "description": "Incremental compilation cache for Rust projects",
        "category": "rust",
        "safety_level": "safe",
        "match": {
            "path_glob": "**/target/*/incremental/**"
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Rust incremental compile cache to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["projects/app/target/debug/incremental/foo"],
            "should_not_match": ["projects/app/src/main.rs"]
        }
    },
    {
        "id": "rust-sccache",
        "name": "sccache Shared Compilation Cache",
        "description": "Shared compiler cache for Rust, C, and C++",
        "category": "rust",
        "safety_level": "aggressive",
        "match": {
            "path_glob": "~/.cache/sccache/**",
            "min_size_mb": 100,
            "min_age_days": 14
        },
        "action": {
            "type": "delete",
            "prompt": "Delete {size} of sccache compiler cache?",
            "group": True
        },
        "test": {
            "should_match": ["~/.cache/sccache/foo"],
            "should_not_match": ["~/.cache/other/foo"]
        }
    },
    {
        "id": "rust-rustup-toolchains",
        "name": "Rustup Toolchains",
        "description": "Unused rustup toolchains",
        "category": "rust",
        "safety_level": "cautious",
        "match": {
            "path_glob": "~/.rustup/toolchains/**",
            "min_age_days": 90
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of old rustup toolchains to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/.rustup/toolchains/stable-x86_64-apple-darwin"],
            "should_not_match": ["~/.rustup/settings.toml"]
        }
    },
    {
        "id": "rust-cargo-git",
        "name": "Cargo Git Dependency Checkouts",
        "description": "Git dependency checkouts for Cargo",
        "category": "rust",
        "safety_level": "safe",
        "match": {
            "path_glob": "~/.cargo/git/checkouts/**",
            "min_age_days": 30
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Cargo git checkouts to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/.cargo/git/checkouts/foo"],
            "should_not_match": ["~/.cargo/registry"]
        }
    },

    # Category: swift
    {
        "id": "swift-derived-data",
        "name": "Xcode DerivedData",
        "description": "Xcode DerivedData build products",
        "category": "swift",
        "safety_level": "safe",
        "match": {
            "path_glob": "~/Library/Developer/Xcode/DerivedData/**",
            "min_size_mb": 50
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Xcode DerivedData to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Developer/Xcode/DerivedData/MyApp-abc/Build/Products"],
            "should_not_match": ["~/Library/Developer/Xcode/UserData"]
        }
    },
    {
        "id": "swift-build-dirs",
        "name": "Swift Package Build Directories",
        "description": "Swift Package Manager build directories",
        "category": "swift",
        "safety_level": "safe",
        "match": {
            "directory_name": ".build",
            "parent_must_contain": ["Package.swift"],
            "min_size_mb": 10
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Swift build directories to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["projects/app/.build"],
            "should_not_match": ["projects/app/src"]
        }
    },
    {
        "id": "swift-archives",
        "name": "Xcode Archives",
        "description": "Xcode archives of iOS/macOS apps",
        "category": "swift",
        "safety_level": "cautious",
        "match": {
            "path_glob": "~/Library/Developer/Xcode/Archives/**",
            "min_age_days": 90
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Xcode archives to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Developer/Xcode/Archives/2026-01-01/App.xcarchive"],
            "should_not_match": ["~/Library/Developer/Xcode/DerivedData"]
        }
    },
    {
        "id": "swift-simulators",
        "name": "Simulator Devices",
        "description": "iOS/watchOS/tvOS Simulator Devices runtime data",
        "category": "swift",
        "safety_level": "cautious",
        "match": {
            "path_glob": "~/Library/Developer/CoreSimulator/Devices/**",
            "min_age_days": 60
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Simulator device data to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Developer/CoreSimulator/Devices/device-id/data"],
            "should_not_match": ["~/Library/Developer/Xcode"]
        }
    },
    {
        "id": "swift-device-support",
        "name": "Xcode Device Support Files",
        "description": "Xcode support files for iOS/watchOS devices",
        "category": "swift",
        "safety_level": "aggressive",
        "match": {
            "path_glob": "~/Library/Developer/Xcode/iOS DeviceSupport/**",
            "min_age_days": 180
        },
        "action": {
            "type": "delete",
            "prompt": "Delete {size} of Xcode Device Support files?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Developer/Xcode/iOS DeviceSupport/15.0/Symbols"],
            "should_not_match": ["~/Library/Developer/Xcode/DerivedData"]
        }
    },
    {
        "id": "swift-spm-cache",
        "name": "SwiftPM Dependency Cache",
        "description": "Swift Package Manager dependencies cache",
        "category": "swift",
        "safety_level": "safe",
        "match": {
            "path_glob": "~/Library/Caches/org.swift.swiftpm/**"
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of SwiftPM cache to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Caches/org.swift.swiftpm/repositories"],
            "should_not_match": ["~/Library/Caches/com.apple.dt.Xcode"]
        }
    },
    {
        "id": "swift-simulator-unavailable",
        "name": "Unavailable Simulators",
        "description": "Unavailable Xcode Simulator runtimes",
        "category": "swift",
        "safety_level": "cautious",
        "match": {
            "path_glob": "~/Library/Developer/CoreSimulator/Devices/*/unavailable/**"
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of unavailable simulators to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Developer/CoreSimulator/Devices/dev-id/unavailable/runtime"],
            "should_not_match": ["~/Library/Developer/CoreSimulator/Devices/dev-id/data"]
        }
    },
    {
        "id": "swift-previews",
        "name": "SwiftUI Previews",
        "description": "SwiftUI preview build products",
        "category": "swift",
        "safety_level": "safe",
        "match": {
            "path_glob": "~/Library/Developer/Xcode/UserData/Previews/**"
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of SwiftUI Previews cache to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Developer/Xcode/UserData/Previews/Product/foo"],
            "should_not_match": ["~/Library/Developer/Xcode/DerivedData"]
        }
    },

    # Category: node
    {
        "id": "node-next-cache",
        "name": "Next.js Build Cache",
        "description": "Next.js cache directories",
        "category": "node",
        "safety_level": "safe",
        "match": {
            "directory_name": ".next",
            "parent_must_contain": ["package.json"]
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Next.js cache to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["projects/app/.next"],
            "should_not_match": ["projects/app/src"]
        }
    },
    {
        "id": "node-dist-build",
        "name": "Node Build Output Directories",
        "description": "Vite/dist output folders with package.json context",
        "category": "node",
        "safety_level": "cautious",
        "match": {
            "directory_name": "dist",
            "parent_must_contain": ["package.json"]
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Node build output to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["projects/app/dist"],
            "should_not_match": ["projects/app/src"]
        }
    },
    {
        "id": "node-cache-dirs",
        "name": "Node Tool Caches",
        "description": "Parcel, Turbo, and ESLint caches",
        "category": "node",
        "safety_level": "safe",
        "match": {
            "directory_name": ".parcel-cache",
            "parent_must_contain": ["package.json"]
        },
        "action": {
            "type": "delete",
            "prompt": "Delete {size} of Node tool caches?",
            "group": True
        },
        "test": {
            "should_match": ["projects/app/.parcel-cache"],
            "should_not_match": ["projects/app/src"]
        }
    },
    {
        "id": "node-pnpm-store",
        "name": "pnpm Global Store",
        "description": "Global pnpm store for dependencies",
        "category": "node",
        "safety_level": "cautious",
        "match": {
            "path_glob": "~/Library/pnpm/store/**",
            "min_size_mb": 200
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of pnpm global store to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/pnpm/store/v3/files/foo"],
            "should_not_match": ["~/.cargo"]
        }
    },
    {
        "id": "node-bun-cache",
        "name": "Bun Install Cache",
        "description": "Global package install cache for Bun",
        "category": "node",
        "safety_level": "safe",
        "match": {
            "path_glob": "~/.bun/install/cache/**"
        },
        "action": {
            "type": "delete",
            "prompt": "Delete {size} of Bun install cache?",
            "group": True
        },
        "test": {
            "should_match": ["~/.bun/install/cache/foo/package.json"],
            "should_not_match": ["~/.bun/bin"]
        }
    },
    {
        "id": "node-deno-cache",
        "name": "Deno Cache",
        "description": "Global download and compilation cache for Deno",
        "category": "node",
        "safety_level": "safe",
        "match": {
            "path_glob": "~/Library/Caches/deno/**"
        },
        "action": {
            "type": "delete",
            "prompt": "Delete {size} of Deno cache?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Caches/deno/deps/http/foo"],
            "should_not_match": ["~/Library/Caches/Homebrew"]
        }
    },
    {
        "id": "node-framework-caches",
        "name": "Node Framework Caches",
        "description": "Vite, Astro, SvelteKit, and Nuxt build caches",
        "category": "node",
        "safety_level": "safe",
        "match": {
            "directory_name": ".vite",
            "parent_must_contain": ["package.json"]
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of framework caches to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["projects/app/.vite"],
            "should_not_match": ["projects/app/src"]
        }
    },
    {
        "id": "node-deploy-caches",
        "name": "Node Deploy Caches",
        "description": "Vercel, Netlify, and Wrangler deploy caches",
        "category": "node",
        "safety_level": "cautious",
        "match": {
            "directory_name": ".vercel",
            "parent_must_contain": ["package.json"]
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of deploy caches to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["projects/app/.vercel"],
            "should_not_match": ["projects/app/src"]
        }
    },
    {
        "id": "node-yarn-classic-cache",
        "name": "Yarn v1 Cache",
        "description": "Yarn classic global cache",
        "category": "node",
        "safety_level": "safe",
        "match": {
            "path_glob": "~/Library/Caches/Yarn/**",
            "min_age_days": 30
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Yarn classic cache to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Caches/Yarn/v6/npm-foo"],
            "should_not_match": ["~/Library/Caches/Homebrew"]
        }
    },
    {
        "id": "node-yarn-berry-cache",
        "name": "Yarn Berry Cache",
        "description": "Yarn Berry local package cache",
        "category": "node",
        "safety_level": "cautious",
        "match": {
            "directory_name": ".yarn",
            "parent_must_contain": ["package.json"]
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Yarn Berry cache to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["projects/app/.yarn"],
            "should_not_match": ["projects/app/src"]
        }
    },

    # Category: python
    {
        "id": "python-venvs",
        "name": "Python Virtual Environments",
        "description": "Python .venv or venv directories",
        "category": "python",
        "safety_level": "cautious",
        "match": {
            "directory_name": ".venv",
            "parent_must_contain": ["pyproject.toml"],
            "min_size_mb": 50,
            "min_age_days": 30
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Python virtual environments to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["projects/app/.venv"],
            "should_not_match": ["projects/app/src"]
        }
    },
    {
        "id": "python-tool-caches",
        "name": "Python Tool Caches",
        "description": "tox, mypy, pytest, and ruff caches",
        "category": "python",
        "safety_level": "safe",
        "match": {
            "directory_name": ".mypy_cache",
            "parent_must_contain": ["pyproject.toml"]
        },
        "action": {
            "type": "delete",
            "prompt": "Delete {size} of Python tool caches?",
            "group": True
        },
        "test": {
            "should_match": ["projects/app/.mypy_cache"],
            "should_not_match": ["projects/app/src"]
        }
    },
    {
        "id": "python-uv-cache",
        "name": "uv Cache",
        "description": "Package resolution and download cache for uv",
        "category": "python",
        "safety_level": "safe",
        "match": {
            "path_glob": "~/.cache/uv/**",
            "min_size_mb": 100
        },
        "action": {
            "type": "delete",
            "prompt": "Delete {size} of uv cache?",
            "group": True
        },
        "test": {
            "should_match": ["~/.cache/uv/archive/foo"],
            "should_not_match": ["~/.cache/other"]
        }
    },
    {
        "id": "python-poetry-cache",
        "name": "Poetry Cache",
        "description": "Poetry dependency download cache",
        "category": "python",
        "safety_level": "safe",
        "match": {
            "path_glob": "~/Library/Caches/pypoetry/**",
            "min_size_mb": 50
        },
        "action": {
            "type": "delete",
            "prompt": "Delete {size} of Poetry cache?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Caches/pypoetry/artifacts/foo"],
            "should_not_match": ["~/Library/Caches/Homebrew"]
        }
    },
    {
        "id": "python-pip-cache",
        "name": "pip Cache",
        "description": "Global pip HTTP and wheel cache",
        "category": "python",
        "safety_level": "safe",
        "match": {
            "path_glob": "~/Library/Caches/pip/**",
            "min_age_days": 30
        },
        "action": {
            "type": "delete",
            "prompt": "Delete {size} of pip wheel/http cache?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Caches/pip/wheels/foo"],
            "should_not_match": ["~/Library/Caches/Homebrew"]
        }
    },
    {
        "id": "python-conda-pkgs",
        "name": "Conda Packages",
        "description": "Conda package cache directory",
        "category": "python",
        "safety_level": "cautious",
        "match": {
            "path_glob": "~/.conda/pkgs/**",
            "min_age_days": 30
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Conda packages to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/.conda/pkgs/python-3.10-foo"],
            "should_not_match": ["~/.conda/envs"]
        }
    },
    {
        "id": "python-pixi-cache",
        "name": "Pixi/Rattler Package Cache",
        "description": "Pixi rattler package cache",
        "category": "python",
        "safety_level": "safe",
        "match": {
            "path_glob": "~/.cache/rattler/**",
            "min_size_mb": 100
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Pixi/rattler package cache to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/.cache/rattler/pkgs/foo"],
            "should_not_match": ["~/.cache/other"]
        }
    },

    # Category: ml
    {
        "id": "ml-checkpoints",
        "name": "ML Model Checkpoints",
        "description": "ML model training checkpoint files",
        "category": "ml",
        "safety_level": "cautious",
        "match": {
            "path_glob": "**/*.ckpt",
            "min_size_mb": 100,
            "min_age_days": 14
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of training checkpoints to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["projects/ml/epoch-10.ckpt"],
            "should_not_match": ["projects/ml/train.py"]
        }
    },
    {
        "id": "ml-safetensors-cache",
        "name": "Cached Model Weights",
        "description": "Hugging Face model cache weights",
        "category": "ml",
        "safety_level": "cautious",
        "match": {
            "path_glob": "~/.cache/huggingface/hub/**/*.safetensors",
            "min_age_days": 30
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of HuggingFace safetensors to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/.cache/huggingface/hub/models--gpt2/model.safetensors"],
            "should_not_match": ["~/.cache/huggingface/hub/settings"]
        }
    },
    {
        "id": "ml-wandb",
        "name": "Weights & Biases Local Data",
        "description": "Local run data for Weights & Biases",
        "category": "ml",
        "safety_level": "cautious",
        "match": {
            "directory_name": "wandb",
            "parent_must_contain": ["train.py"],
            "min_age_days": 7
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of W&B logs to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["projects/ml/wandb"],
            "should_not_match": ["projects/ml/src"]
        }
    },
    {
        "id": "ml-tensorboard",
        "name": "TensorBoard Log Directories",
        "description": "TensorBoard logs directory",
        "category": "ml",
        "safety_level": "cautious",
        "match": {
            "directory_name": "runs",
            "parent_must_contain": ["train.py"],
            "min_age_days": 14
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of TensorBoard logs to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["projects/ml/runs"],
            "should_not_match": ["projects/ml/src"]
        }
    },
    {
        "id": "ml-datasets-cache",
        "name": "Cached Datasets",
        "description": "Hugging Face and PyTorch cached datasets",
        "category": "ml",
        "safety_level": "cautious",
        "match": {
            "path_glob": "~/.cache/huggingface/datasets/**",
            "min_age_days": 30
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of HF datasets cache to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/.cache/huggingface/datasets/imdb/plain_text/cache.arrow"],
            "should_not_match": ["~/.cache/other"]
        }
    },
    {
        "id": "ml-ollama-models",
        "name": "Ollama Downloaded Models",
        "description": "Ollama downloaded model weights",
        "category": "ml",
        "safety_level": "cautious",
        "match": {
            "path_glob": "~/.ollama/models/**",
            "min_size_mb": 500
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Ollama models to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/.ollama/models/blobs/sha256-foo"],
            "should_not_match": ["~/.ollama/config"]
        }
    },
    {
        "id": "ml-lmstudio-models",
        "name": "LM Studio Downloaded Models",
        "description": "LM Studio downloaded GGUF/MLX model weights",
        "category": "ml",
        "safety_level": "cautious",
        "match": {
            "path_glob": "~/.lmstudio/models/**",
            "min_size_mb": 500
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of LM Studio models to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/.lmstudio/models/publisher/model-gguf"],
            "should_not_match": ["~/.lmstudio/config"]
        }
    },
    {
        "id": "ml-vector-dbs",
        "name": "Local Vector Databases",
        "description": "Vector store database storage (Chroma, Qdrant, Milvus)",
        "category": "ml",
        "safety_level": "cautious",
        "match": {
            "file_name": "chroma.sqlite3",
            "min_size_mb": 100,
            "min_age_days": 14
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of vector databases to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["projects/app/chroma/chroma.sqlite3"],
            "should_not_match": ["projects/app/main.py"]
        }
    },
    {
        "id": "ml-vllm-cache",
        "name": "vLLM Model Cache",
        "description": "vLLM model cache directory",
        "category": "ml",
        "safety_level": "cautious",
        "match": {
            "path_glob": "~/.cache/vllm/**",
            "min_size_mb": 1000
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of vLLM model cache to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/.cache/vllm/foo"],
            "should_not_match": ["~/.cache/other"]
        }
    },
    {
        "id": "ml-torch-hub",
        "name": "PyTorch Hub Cache",
        "description": "Downloaded PyTorch model weights and checkpoints",
        "category": "ml",
        "safety_level": "cautious",
        "match": {
            "path_glob": "~/.cache/torch/hub/**",
            "min_age_days": 30
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of PyTorch Hub cache to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/.cache/torch/hub/checkpoints/resnet.pth"],
            "should_not_match": ["~/.cache/other"]
        }
    },
    {
        "id": "ml-triton-cache",
        "name": "vLLM Triton Kernel Cache",
        "description": "GPU kernel compilation cache for Triton",
        "category": "ml",
        "safety_level": "safe",
        "match": {
            "path_glob": "~/.triton/cache/**",
            "min_size_mb": 100
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Triton cache to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/.triton/cache/foo/bar.bin"],
            "should_not_match": ["~/.triton/config"]
        }
    },

    # Category: docker
    {
        "id": "docker-build-cache",
        "name": "Docker Build Cache",
        "description": "Docker build cache layers",
        "category": "docker",
        "safety_level": "safe",
        "match": {
            "path_glob": "**/docker-dummy-build-cache/**"
        },
        "action": {
            "type": "trash",
            "prompt": "Prune Docker build cache?",
            "group": True
        },
        "test": {
            "should_match": ["projects/docker-dummy-build-cache/layer"],
            "should_not_match": ["projects/src"]
        }
    },
    {
        "id": "docker-dangling-images",
        "name": "Docker Dangling Images",
        "description": "Docker images with no tag",
        "category": "docker",
        "safety_level": "safe",
        "match": {
            "path_glob": "**/docker-dummy-dangling-images/**"
        },
        "action": {
            "type": "trash",
            "prompt": "Delete dangling Docker images?",
            "group": True
        },
        "test": {
            "should_match": ["projects/docker-dummy-dangling-images/img"],
            "should_not_match": ["projects/src"]
        }
    },
    {
        "id": "docker-stopped-containers",
        "name": "Docker Stopped Containers",
        "description": "Docker containers with exited status",
        "category": "docker",
        "safety_level": "cautious",
        "match": {
            "path_glob": "**/docker-dummy-stopped-containers/**",
            "min_age_days": 7
        },
        "action": {
            "type": "trash",
            "prompt": "Delete stopped Docker containers?",
            "group": True
        },
        "test": {
            "should_match": ["projects/docker-dummy-stopped-containers/container"],
            "should_not_match": ["projects/src"]
        }
    },
    {
        "id": "docker-unused-volumes",
        "name": "Docker Unused Volumes",
        "description": "Docker volumes not attached to any container",
        "category": "docker",
        "safety_level": "aggressive",
        "match": {
            "path_glob": "**/docker-dummy-unused-volumes/**"
        },
        "action": {
            "type": "delete",
            "prompt": "Delete unused Docker volumes?",
            "group": True
        },
        "test": {
            "should_match": ["projects/docker-dummy-unused-volumes/volume"],
            "should_not_match": ["projects/src"]
        }
    },

    # Category: ai-tools
    {
        "id": "ai-codex-cache",
        "name": "Codex CLI Cache",
        "description": "OpenAI Codex CLI cache and logs",
        "category": "ai-tools",
        "safety_level": "cautious",
        "match": {
            "path_glob": "~/.codex-cache/**",
            "min_age_days": 14
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Codex cache to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/.codex-cache/log.txt"],
            "should_not_match": ["~/.codex/config"]
        }
    },
    {
        "id": "ai-claude-code-cache",
        "name": "Claude Code Cache",
        "description": "Claude Code CLI cache and logs",
        "category": "ai-tools",
        "safety_level": "cautious",
        "match": {
            "directory_name": ".claude",
            "parent_must_contain": ["package.json"],
            "min_age_days": 7
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Claude Code cache to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["projects/web/.claude"],
            "should_not_match": ["projects/web/src"]
        }
    },
    {
        "id": "ai-cursor-cache",
        "name": "Cursor Cache",
        "description": "Cursor editor Cache and CachedData",
        "category": "ai-tools",
        "safety_level": "safe",
        "match": {
            "path_glob": "~/Library/Application Support/Cursor/Cache/**"
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Cursor cache to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Application Support/Cursor/Cache/foo"],
            "should_not_match": ["~/Library/Application Support/Cursor/User"]
        }
    },
    {
        "id": "ai-copilot-cache",
        "name": "GitHub Copilot Cache",
        "description": "GitHub Copilot editor caches",
        "category": "ai-tools",
        "safety_level": "cautious",
        "match": {
            "path_glob": "~/Library/Caches/github-copilot/**"
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of GitHub Copilot cache to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Caches/github-copilot/foo"],
            "should_not_match": ["~/Library/Caches/Tabnine"]
        }
    },
    {
        "id": "ai-gemini-cache",
        "name": "Gemini / Antigravity Cache",
        "description": "Gemini and Antigravity log and cache files",
        "category": "ai-tools",
        "safety_level": "cautious",
        "match": {
            "path_glob": "~/.gemini/cache/**",
            "min_age_days": 14
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Antigravity cache to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/.gemini/cache/log.txt"],
            "should_not_match": ["~/.gemini/config"]
        }
    },

    # Category: apps
    {
        "id": "apps-orphaned-support",
        "name": "Orphaned Application Support",
        "description": "Orphaned Library Application Support folders",
        "category": "apps",
        "safety_level": "aggressive",
        "match": {
            "path_glob": "~/Library/Application Support/OrphanedApp/**",
            "min_age_days": 30
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of orphaned app support to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Application Support/OrphanedApp/data"],
            "should_not_match": ["~/Library/Application Support/Xcode"]
        }
    },
    {
        "id": "apps-orphaned-caches",
        "name": "Orphaned Application Caches",
        "description": "Orphaned Library Caches",
        "category": "apps",
        "safety_level": "cautious",
        "match": {
            "path_glob": "~/Library/Caches/com.orphaned.app/**",
            "min_age_days": 30
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of orphaned caches to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Caches/com.orphaned.app/cache"],
            "should_not_match": ["~/Library/Caches/com.apple.dt.Xcode"]
        }
    },
    {
        "id": "apps-orphaned-preferences",
        "name": "Orphaned Preferences",
        "description": "Orphaned Application plist files",
        "category": "apps",
        "safety_level": "cautious",
        "match": {
            "path_glob": "~/Library/Preferences/com.orphaned.app.plist",
            "min_age_days": 60
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of orphaned preferences to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Preferences/com.orphaned.app.plist"],
            "should_not_match": ["~/Library/Preferences/com.apple.Xcode.plist"]
        }
    },

    # Category: system
    {
        "id": "system-xcode-caches",
        "name": "Xcode Caches",
        "description": "Xcode DT.Xcode caches",
        "category": "system",
        "safety_level": "safe",
        "match": {
            "path_glob": "~/Library/Caches/com.apple.dt.Xcode/**"
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Xcode caches to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Caches/com.apple.dt.Xcode/downloads"],
            "should_not_match": ["~/Library/Caches/Yarn"]
        }
    },
    {
        "id": "system-homebrew-cache",
        "name": "Homebrew Download Cache",
        "description": "Cached Homebrew formula downloads",
        "category": "system",
        "safety_level": "safe",
        "match": {
            "path_glob": "~/Library/Caches/Homebrew/**",
            "min_age_days": 30
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Homebrew cache to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Caches/Homebrew/downloads/git-2.40.tar.gz"],
            "should_not_match": ["~/Library/Caches/Yarn"]
        }
    },
    {
        "id": "system-cocoapods-cache",
        "name": "CocoaPods Cache",
        "description": "Global CocoaPods download cache",
        "category": "system",
        "safety_level": "safe",
        "match": {
            "path_glob": "~/Library/Caches/CocoaPods/**",
            "min_age_days": 30
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of CocoaPods cache to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Caches/CocoaPods/Pods/Release/AFNetworking"],
            "should_not_match": ["~/Library/Caches/Yarn"]
        }
    },
    {
        "id": "system-old-logs",
        "name": "Old User Log Files",
        "description": "Old development and system user log files",
        "category": "system",
        "safety_level": "cautious",
        "match": {
            "path_glob": "~/Library/Logs/**",
            "min_age_days": 30
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of user logs to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Logs/console.log"],
            "should_not_match": ["projects/system.log"]
        }
    },
    {
        "id": "system-crash-reports",
        "name": "Old Crash Reports",
        "description": "Old diagnostic crash reports",
        "category": "system",
        "safety_level": "cautious",
        "match": {
            "path_glob": "~/Library/Logs/DiagnosticReports/**",
            "min_age_days": 14
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of crash reports to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Logs/DiagnosticReports/App_2026-01-01.crash"],
            "should_not_match": ["~/Library/Logs/console.log"]
        }
    },

    # Category: go
    {
        "id": "go-build-cache",
        "name": "Go Build Cache",
        "description": "Go build cache directory",
        "category": "go",
        "safety_level": "safe",
        "match": {
            "path_glob": "~/Library/Caches/go-build/**"
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Go build cache to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/Library/Caches/go-build/00/0000000000000000000000000000000000000000-d"],
            "should_not_match": ["~/Library/Caches/Yarn"]
        }
    },
    {
        "id": "go-mod-cache",
        "name": "Go Module Cache",
        "description": "Go module cache directory",
        "category": "go",
        "safety_level": "safe",
        "match": {
            "path_glob": "~/go/pkg/mod/cache/**",
            "min_age_days": 30
        },
        "action": {
            "type": "trash",
            "prompt": "Move {size} of Go module cache to Trash?",
            "group": True
        },
        "test": {
            "should_match": ["~/go/pkg/mod/cache/download/github.com/foo/@v/v1.0.0.zip"],
            "should_not_match": ["~/go/pkg/mod/foo"]
        }
    }
]

# Ensure the recipes folder exists
os.makedirs("recipes", exist_ok=True)

# Generate TOML files
generated_toml_files = []
for recipe in recipes_data:
    if recipe['action']['type'] == 'delete':
        recipe['safety_level'] = 'aggressive'
        
    filename = f"{recipe['id']}.toml"
    filepath = os.path.join("recipes", filename)
    generated_toml_files.append((filename, filepath))
    
    toml_content = f"""[recipe]
id = "{recipe['id']}"
name = "{recipe['name']}"
description = "{recipe['description']}"
category = "{recipe['category']}"
safety_level = "{recipe['safety_level']}"
enabled = true
priority = 50

[match]
"""
    if "directory_name" in recipe["match"]:
        toml_content += f'directory_name = "{recipe["match"]["directory_name"]}"\n'
    if "file_name" in recipe["match"]:
        toml_content += f'file_name = "{recipe["match"]["file_name"]}"\n'
    if "file_extension" in recipe["match"]:
        ext_list = ", ".join(f'"{ext}"' for ext in recipe["match"]["file_extension"])
        toml_content += f'file_extension = [{ext_list}]\n'
    if "path_glob" in recipe["match"]:
        toml_content += f'path_glob = "{recipe["match"]["path_glob"]}"\n'
    if "parent_must_contain" in recipe["match"]:
        pm_list = ", ".join(f'"{pm}"' for pm in recipe["match"]["parent_must_contain"])
        toml_content += f'parent_must_contain = [{pm_list}]\n'
    if "min_size_mb" in recipe["match"]:
        toml_content += f'min_size_mb = {recipe["match"]["min_size_mb"]}\n'
    if "min_age_days" in recipe["match"]:
        toml_content += f'min_age_days = {recipe["match"]["min_age_days"]}\n'
        
    toml_content += f"""
[action]
type = "{recipe['action']['type']}"
prompt = "{recipe['action']['prompt']}"
group = {str(recipe['action']['group']).lower()}

[test]
should_match = {str(recipe['test']['should_match']).replace("'", '"')}
should_not_match = {str(recipe['test']['should_not_match']).replace("'", '"')}
"""
    with open(filepath, "w") as f:
        f.write(toml_content)

print(f"Generated {len(generated_toml_files)} TOML files.")

# Generate builtin.rs content
builtin_entries = []
# include the 3 original ones too
original_recipes = [("recipes/rust.toml", "rust.toml"), ("recipes/node.toml", "node.toml"), ("recipes/python.toml", "python.toml")]
for original_path, original_file in original_recipes:
    builtin_entries.append(f'    (\n        "{original_path}",\n        include_str!("../../../{original_path}"),\n    ),')

for name, path in generated_toml_files:
    # avoid duplicates with original
    if name in ["rust.toml", "node.toml", "python.toml"]:
        continue
    builtin_entries.append(f'    (\n        "recipes/{name}",\n        include_str!("../../../recipes/{name}"),\n    ),')

builtin_content = f"""pub(crate) const BUILTIN_RECIPES: &[(&str, &str)] = &[
{"\n".join(builtin_entries)}
];
"""

with open("crates/cleanton-recipes/src/builtin.rs", "w") as f:
    f.write(builtin_content)

print("Updated builtin.rs successfully.")
