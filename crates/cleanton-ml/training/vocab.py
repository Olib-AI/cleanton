"""Baked-in name vocabularies for realistic synthetic tree generation.

Large lists of REAL package / project / application / file names so the
generator draws from plausible distributions instead of a handful of
hard-coded strings (the main realism flaw of the v1 dataset).

All data in this module is static; the generator samples from it with a
seeded RNG so generation stays deterministic.
"""

from __future__ import annotations

# --- Top npm packages (registry download leaders + common transitive deps) ---
NPM_PACKAGES: tuple[str, ...] = (
    "react", "react-dom", "lodash", "chalk", "axios", "express", "vite",
    "eslint", "typescript", "commander", "tslib", "prettier", "webpack",
    "next", "vue", "svelte", "jest", "vitest", "mocha", "chai", "sinon",
    "debug", "ms", "semver", "minimatch", "glob", "rimraf", "mkdirp",
    "yargs", "inquirer", "ora", "boxen", "figlet", "dotenv", "cross-env",
    "uuid", "nanoid", "dayjs", "moment", "date-fns", "zod", "yup", "joi",
    "ajv", "json5", "js-yaml", "toml", "ini", "cosmiconfig", "esbuild",
    "rollup", "terser", "babel-loader", "css-loader", "style-loader",
    "postcss", "autoprefixer", "tailwindcss", "sass", "less", "stylus",
    "styled-components", "emotion", "classnames", "clsx", "zustand",
    "redux", "react-redux", "mobx", "immer", "reselect", "rxjs", "ramda",
    "underscore", "async", "bluebird", "p-limit", "p-queue", "got",
    "node-fetch", "undici", "superagent", "form-data", "ws", "socket.io",
    "cors", "helmet", "morgan", "compression", "body-parser", "multer",
    "passport", "jsonwebtoken", "bcrypt", "argon2", "pg", "mysql2",
    "mongodb", "mongoose", "sequelize", "prisma", "knex", "typeorm",
    "redis", "ioredis", "sqlite3", "better-sqlite3", "graphql", "apollo-server",
    "fastify", "koa", "hapi", "nestjs", "electron", "playwright", "puppeteer",
    "cypress", "storybook", "react-router-dom", "react-query", "swr",
    "framer-motion", "three", "d3", "chart.js", "leaflet", "mapbox-gl",
    "pixi.js", "howler", "fuse.js", "marked", "remark", "rehype", "mdx",
    "highlight.js", "prismjs", "shiki", "sharp", "jimp", "canvas",
    "pdfkit", "jspdf", "exceljs", "xlsx", "csv-parse", "papaparse",
    "fast-glob", "chokidar", "nodemon", "ts-node", "tsx", "swc",
    "source-map", "source-map-support", "acorn", "espree", "esprima",
    "estraverse", "escodegen", "magic-string", "picocolors", "kleur",
    "supports-color", "strip-ansi", "ansi-regex", "wrap-ansi", "cliui",
    "string-width", "emoji-regex", "is-fullwidth-code-point", "yocto-queue",
    "queue-microtask", "run-parallel", "picomatch", "braces", "micromatch",
    "fill-range", "to-regex-range", "is-number", "readdirp", "anymatch",
    "normalize-path", "path-key", "shebang-command", "which", "isexe",
    "signal-exit", "onetime", "mimic-fn", "npm-run-path", "execa",
    "get-stream", "human-signals", "merge-stream", "pump", "end-of-stream",
    "once", "wrappy", "inherits", "safe-buffer", "buffer", "events",
    "process", "util", "assert", "punycode", "iconv-lite", "safer-buffer",
    "graceful-fs", "jsonfile", "universalify", "fs-extra", "tmp", "make-dir",
    "find-up", "locate-path", "p-locate", "path-exists", "pkg-dir",
)

# --- Top crates.io packages -------------------------------------------------
CRATES: tuple[str, ...] = (
    "serde", "serde_json", "serde_derive", "tokio", "syn", "quote",
    "proc-macro2", "rand", "libc", "log", "cfg-if", "itoa", "ryu",
    "anyhow", "thiserror", "clap", "regex", "regex-syntax", "memchr",
    "once_cell", "lazy_static", "bitflags", "hashbrown", "indexmap",
    "smallvec", "parking_lot", "crossbeam", "crossbeam-channel", "rayon",
    "num_cpus", "futures", "futures-util", "mio", "bytes", "http",
    "hyper", "reqwest", "url", "percent-encoding", "idna", "unicode-bidi",
    "unicode-normalization", "chrono", "time", "uuid", "base64", "hex",
    "sha2", "sha1", "md-5", "digest", "hmac", "rand_core", "getrandom",
    "ring", "rustls", "webpki", "native-tls", "openssl", "openssl-sys",
    "pkg-config", "cc", "bindgen", "autocfg", "version_check", "semver",
    "toml", "toml_edit", "serde_yaml", "csv", "flate2", "tar", "zip",
    "walkdir", "glob", "notify", "tempfile", "dirs", "home", "which",
    "env_logger", "tracing", "tracing-subscriber", "tracing-core",
    "slab", "pin-project", "pin-project-lite", "pin-utils", "async-trait",
    "tower", "tower-service", "axum", "actix-web", "warp", "rocket",
    "diesel", "sqlx", "rusqlite", "postgres", "redis", "mongodb",
    "crossterm", "ratatui", "termcolor", "atty", "is-terminal", "console",
    "indicatif", "dialoguer", "colored", "owo-colors", "strsim", "heck",
    "convert_case", "itertools", "either", "num-traits", "num-integer",
    "num-bigint", "ordered-float", "float-cmp", "approx", "nalgebra",
    "ndarray", "image", "png", "jpeg-decoder", "gif", "resvg", "tiny-skia",
    "wgpu", "winit", "raw-window-handle", "glam", "bevy", "egui", "iced",
    "criterion", "proptest", "quickcheck", "insta", "pretty_assertions",
    "mockall", "wiremock", "assert_cmd", "predicates", "rstest",
    "zerocopy", "bytemuck", "memmap2", "object", "gimli", "addr2line",
    "backtrace", "rustc-demangle", "unicode-ident", "unicode-width",
    "textwrap", "vte", "signal-hook", "nix", "errno", "socket2",
)

# --- Top PyPI packages --------------------------------------------------------
PYPI_PACKAGES: tuple[str, ...] = (
    "numpy", "pandas", "requests", "urllib3", "certifi", "charset_normalizer",
    "idna", "setuptools", "pip", "wheel", "packaging", "typing_extensions",
    "six", "python_dateutil", "pytz", "pyyaml", "attrs", "click", "jinja2",
    "markupsafe", "cryptography", "cffi", "pycparser", "rich", "pygments",
    "tqdm", "colorama", "filelock", "platformdirs", "virtualenv", "tomli",
    "pluggy", "iniconfig", "pytest", "coverage", "hypothesis", "mypy",
    "ruff", "black", "isort", "flake8", "pylint", "pydantic", "pydantic_core",
    "annotated_types", "fastapi", "starlette", "uvicorn", "httpx", "httpcore",
    "anyio", "sniffio", "h11", "websockets", "flask", "werkzeug",
    "itsdangerous", "blinker", "django", "sqlalchemy", "alembic", "psycopg2",
    "pymysql", "redis", "celery", "kombu", "billiard", "vine", "boto3",
    "botocore", "s3transfer", "jmespath", "awscli", "google_api_core",
    "google_auth", "grpcio", "protobuf", "googleapis_common_protos",
    "torch", "torchvision", "torchaudio", "tensorflow", "keras", "jax",
    "jaxlib", "flax", "optax", "transformers", "tokenizers", "datasets",
    "accelerate", "safetensors", "huggingface_hub", "sentencepiece",
    "scikit_learn", "scipy", "matplotlib", "seaborn", "plotly", "bokeh",
    "pillow", "opencv_python", "imageio", "scikit_image", "networkx",
    "sympy", "numba", "llvmlite", "cython", "pyarrow", "polars", "duckdb",
    "openpyxl", "xlrd", "lxml", "beautifulsoup4", "soupsieve", "html5lib",
    "selenium", "playwright", "scrapy", "nltk", "spacy", "gensim",
    "wandb", "mlflow", "tensorboard", "lightning", "pytorch_lightning",
    "onnx", "onnxruntime", "openai", "anthropic", "langchain", "tiktoken",
    "chromadb", "faiss_cpu", "pinecone", "jupyter", "notebook", "ipython",
    "ipykernel", "jupyterlab", "nbconvert", "nbformat", "traitlets",
    "jsonschema", "referencing", "rpds_py", "psutil", "watchdog", "paramiko",
    "fabric", "invoke", "gunicorn", "supervisor", "python_dotenv",
)

# --- Go modules (path tail used as dir names in pkg/mod) ----------------------
GO_MODULES: tuple[str, ...] = (
    "github.com/gin-gonic/gin", "github.com/gorilla/mux", "github.com/spf13/cobra",
    "github.com/spf13/viper", "github.com/stretchr/testify", "github.com/pkg/errors",
    "github.com/sirupsen/logrus", "go.uber.org/zap", "github.com/rs/zerolog",
    "google.golang.org/grpc", "google.golang.org/protobuf", "github.com/golang/protobuf",
    "golang.org/x/net", "golang.org/x/sync", "golang.org/x/text", "golang.org/x/crypto",
    "github.com/go-sql-driver/mysql", "github.com/lib/pq", "github.com/jmoiron/sqlx",
    "gorm.io/gorm", "github.com/redis/go-redis", "go.mongodb.org/mongo-driver",
    "github.com/aws/aws-sdk-go", "cloud.google.com/go", "github.com/urfave/cli",
    "github.com/mitchellh/mapstructure", "github.com/google/uuid", "github.com/fatih/color",
)

# --- Homebrew formulas / casks ------------------------------------------------
BREW_FORMULAS: tuple[str, ...] = (
    "node", "python@3.12", "python@3.11", "git", "go", "rust", "cmake",
    "ninja", "llvm", "gcc", "openssl@3", "readline", "sqlite", "xz", "zstd",
    "wget", "curl", "jq", "yq", "ripgrep", "fd", "fzf", "bat", "eza",
    "htop", "tmux", "neovim", "vim", "ffmpeg", "imagemagick", "graphviz",
    "postgresql@16", "mysql", "redis", "mongodb-community", "kubectl",
    "helm", "terraform", "awscli", "azure-cli", "gh", "docker", "colima",
    "openjdk", "maven", "gradle", "kotlin", "swiftlint", "cocoapods",
    "carthage", "fastlane", "watchman", "yarn", "pnpm", "deno", "bun",
)

# --- macOS application names + bundle ids ------------------------------------
# (app name, bundle id) pairs used for ~/Library structures.
MACOS_APPS: tuple[tuple[str, str], ...] = (
    ("Safari", "com.apple.Safari"),
    ("Mail", "com.apple.mail"),
    ("Messages", "com.apple.MobileSMS"),
    ("Notes", "com.apple.Notes"),
    ("Photos", "com.apple.Photos"),
    ("Music", "com.apple.Music"),
    ("Xcode", "com.apple.dt.Xcode"),
    ("Google Chrome", "com.google.Chrome"),
    ("Firefox", "org.mozilla.firefox"),
    ("Arc", "company.thebrowser.Browser"),
    ("Slack", "com.tinyspeck.slackmacgap"),
    ("Discord", "com.hnc.Discord"),
    ("zoom.us", "us.zoom.xos"),
    ("Spotify", "com.spotify.client"),
    ("VLC", "org.videolan.vlc"),
    ("Notion", "notion.id"),
    ("Obsidian", "md.obsidian"),
    ("Figma", "com.figma.Desktop"),
    ("Visual Studio Code", "com.microsoft.VSCode"),
    ("Cursor", "com.todesktop.230313mzl4w4u92"),
    ("Zed", "dev.zed.Zed"),
    ("iTerm2", "com.googlecode.iterm2"),
    ("Warp", "dev.warp.Warp-Stable"),
    ("Docker", "com.docker.docker"),
    ("Postman", "com.postmanlabs.mac"),
    ("TablePlus", "com.tinyapp.TablePlus"),
    ("1Password", "com.1password.1password"),
    ("Telegram", "ru.keepcoder.Telegram"),
    ("WhatsApp", "net.whatsapp.WhatsApp"),
    ("Steam", "com.valvesoftware.steam"),
    ("Adobe Photoshop 2025", "com.adobe.Photoshop"),
    ("Adobe Premiere Pro 2025", "com.adobe.PremierePro.25"),
    ("Final Cut Pro", "com.apple.FinalCut"),
    ("Sketch", "com.bohemiancoding.sketch3"),
    ("Raycast", "com.raycast.macos"),
    ("Rectangle", "com.knollsoft.Rectangle"),
    ("Alfred 5", "com.runningwithcrayons.Alfred"),
    ("CleanShot X", "pl.maketheweb.cleanshotx"),
    ("OBS", "com.obsproject.obs-studio"),
    ("Blender", "org.blenderfoundation.blender"),
)

# Electron-style apps whose Application Support dir carries Cache/Code Cache.
ELECTRON_APPS: tuple[str, ...] = (
    "Slack", "Discord", "Notion", "Figma", "Code", "Cursor", "Postman",
    "obsidian", "Signal", "WhatsApp", "Microsoft Teams", "linear",
)

# --- Hugging Face model repos (org--name form used in the hub cache) ----------
HF_MODELS: tuple[str, ...] = (
    "bert-base-uncased", "gpt2", "distilbert-base-uncased",
    "roberta-base", "t5-small", "t5-base", "facebook--bart-large",
    "openai--clip-vit-base-patch32", "openai--whisper-large-v3",
    "meta-llama--Llama-3.1-8B-Instruct", "mistralai--Mistral-7B-v0.1",
    "Qwen--Qwen2.5-7B-Instruct", "google--flan-t5-base",
    "sentence-transformers--all-MiniLM-L6-v2", "stabilityai--stable-diffusion-2-1",
    "runwayml--stable-diffusion-v1-5", "microsoft--phi-2",
    "TinyLlama--TinyLlama-1.1B-Chat-v1.0", "BAAI--bge-small-en-v1.5",
    "intfloat--e5-large-v2",
)

# --- Project name material -----------------------------------------------------
PROJECT_WORDS_A: tuple[str, ...] = (
    "acme", "atlas", "aurora", "beacon", "bento", "canvas", "cascade",
    "cedar", "cipher", "cobalt", "comet", "compass", "coral", "cosmos",
    "crane", "delta", "drift", "echo", "ember", "falcon", "fern", "flux",
    "forge", "fusion", "gantry", "glacier", "granite", "harbor", "helix",
    "horizon", "hydra", "indigo", "ion", "iris", "jade", "juniper",
    "keystone", "lattice", "ledger", "lumen", "lyra", "magma", "maple",
    "meridian", "mesa", "mosaic", "nebula", "nimbus", "nova", "nucleus",
    "onyx", "opal", "orbit", "origin", "osprey", "oxide", "pelican",
    "phoenix", "pixel", "prism", "pulse", "quartz", "quill", "raven",
    "reef", "relay", "ridge", "sable", "sage", "sentry", "sierra",
    "signal", "slate", "solstice", "sonar", "spark", "sprout", "summit",
    "tandem", "tango", "terra", "tidal", "titan", "topaz", "torch",
    "tundra", "umbra", "vector", "vertex", "vista", "vortex", "wavelet",
    "willow", "zenith", "zephyr",
)
PROJECT_WORDS_B: tuple[str, ...] = (
    "api", "app", "backend", "frontend", "service", "server", "client",
    "cli", "tool", "kit", "sdk", "core", "engine", "pipeline", "worker",
    "bot", "agent", "dashboard", "portal", "site", "web", "mobile", "ios",
    "android", "desktop", "sync", "gateway", "proxy", "cache", "store",
    "db", "etl", "ml", "ai", "labs", "playground", "demo", "poc",
    "prototype", "experiments", "utils", "scripts", "infra", "ops",
    "deploy", "monitor", "metrics", "auth", "billing", "search", "feed",
    "notifications", "scheduler", "parser", "renderer", "compiler",
)

# --- Human file-name material ---------------------------------------------------
DOCUMENT_NAMES: tuple[str, ...] = (
    "resume", "resume-2026", "cover-letter", "invoice-0042", "invoice-march",
    "taxes-2024", "taxes-2025", "tax-return-2025", "w2-2025", "1099-2025",
    "lease-agreement", "rental-contract", "mortgage-docs", "insurance-policy",
    "medical-records", "prescription", "lab-results", "passport-scan",
    "drivers-license", "birth-certificate", "marriage-certificate",
    "thesis", "thesis-final", "thesis-final-v2", "dissertation",
    "meeting-notes", "quarterly-report", "annual-review", "budget-2026",
    "expense-report", "travel-itinerary", "flight-confirmation",
    "hotel-booking", "recipe-collection", "shopping-list", "todo",
    "journal", "book-draft", "chapter-01", "presentation-q3",
    "offer-letter", "employment-contract", "nda-signed", "will-and-testament",
    "wedding-plan", "guest-list", "vacation-photos-list", "warranty-macbook",
)
DOCUMENT_EXTS: tuple[str, ...] = ("pdf", "docx", "xlsx", "pptx", "txt", "md", "pages", "numbers", "key", "csv")

MEDIA_NAMES: tuple[str, ...] = (
    "IMG_0231", "IMG_1044", "IMG_2207", "IMG_3350", "IMG_4470", "IMG_5921",
    "IMG_7238", "IMG_8804", "DSC_0042", "DSC_1187", "PXL_20250614_183021",
    "vacation-lisbon", "birthday-party", "wedding-ceremony", "graduation",
    "family-reunion", "hiking-yosemite", "beach-sunset", "new-year-2026",
    "concert-video", "kids-recital", "screen-recording-2026-03-14",
)
SCREENSHOT_NAMES: tuple[str, ...] = (
    "Screenshot 2026-01-14 at 09.32.11", "Screenshot 2026-02-03 at 14.05.48",
    "Screenshot 2026-03-22 at 18.44.02", "Screenshot 2026-05-09 at 11.21.36",
    "Screenshot 2026-06-30 at 20.15.55", "CleanShot 2026-04-11 at 16.02.33",
)
DOWNLOAD_NAMES: tuple[str, ...] = (
    "node-v22.12.0-darwin-arm64", "Docker", "Figma-124.5.4", "Slack-4.42.117",
    "googlechrome", "Firefox 133.0", "VSCode-darwin-universal", "iTerm2-3_5_10",
    "Obsidian-1.7.7", "zoomusInstallerFull", "Raycast", "dataset-dump-2026",
    "backup-photos-2024", "project-archive", "conference-slides", "ubuntu-24.04.1-live-server-arm64",
)

USERNAMES: tuple[str, ...] = (
    "maya", "alex", "jordan", "sam", "casey", "devin", "riley", "kai",
    "noah", "emma", "liam", "olivia", "ethan", "ava", "lucas", "mia",
)

SRC_BASENAMES: tuple[str, ...] = (
    "main", "lib", "app", "utils", "helpers", "handler", "handlers",
    "model", "models", "router", "routes", "index", "core", "view",
    "views", "controller", "service", "services", "config", "settings",
    "types", "schema", "client", "server", "worker", "queue", "cache",
    "auth", "middleware", "logger", "errors", "constants", "parser",
    "engine", "runtime", "store", "state", "actions", "reducers",
    "components", "hooks", "context", "api", "db", "migrations",
    "validators", "formatters", "encoders", "decoders", "session",
    "metrics", "tracing", "events", "tasks", "jobs", "cron", "mailer",
)

# Lockfiles the engine's FileContext recognizes (mirror of cleanton-engine LOCKFILES).
LOCKFILES: tuple[str, ...] = (
    "Cargo.lock", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
    "poetry.lock", "uv.lock", "Gemfile.lock", "go.sum", "composer.lock",
)

# Project manifests that mark an ecosystem root (used for the
# ancestor_has_project_marker context feature; must mirror the Rust port).
PROJECT_MARKERS: tuple[str, ...] = (
    "Cargo.toml", "package.json", "pyproject.toml", "setup.py", "go.mod",
    "build.gradle", "build.gradle.kts", "pom.xml", "Package.swift",
    "mix.exs", "pubspec.yaml", "Gemfile", "composer.json", "CMakeLists.txt",
    "stack.yaml", "build.zig", "Project.toml", "requirements.txt",
)
