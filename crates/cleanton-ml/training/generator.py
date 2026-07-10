"""Coherent macOS home-directory tree generation.

Each ``world`` is one simulated user's disk: N dev projects across
ecosystems with internally consistent structure (a Rust project really has
``Cargo.toml`` + ``Cargo.lock`` + ``src/*.rs`` + a populated ``target/``;
a node project's ``node_modules`` holds real npm package names with
transitive layouts), plus realistic non-dev life (documents, media,
downloads, ``~/Library`` app data with BOTH recipe-matched caches and
keep-shaped siblings), credentials dotfiles, and systematically constructed
near-miss decoys derived from recipe guard conditions.

Sizes are log-normal per file class; ages have project-level locality
(active / dormant / abandoned) so correlated metadata is consistent.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

from . import vocab as V
from .fstree import Node, build_root

KB = 1024
MB = 1024 * KB
GB = 1024 * MB


def _lognormal(rng: random.Random, median: float, sigma: float, lo: float = 1, hi: float = 64 * GB) -> int:
    value = median * math.exp(rng.gauss(0.0, sigma))
    return int(min(max(value, lo), hi))


@dataclass
class Activity:
    """Project-level age locality."""

    base_age: float       # age of the most recent activity
    spread: float         # how far back file ages scatter

    def src_age(self, rng: random.Random) -> float:
        return self.base_age + rng.uniform(0.0, self.spread)

    def artifact_age(self, rng: random.Random) -> float:
        # Build outputs cluster near the last activity.
        return self.base_age + rng.uniform(0.0, min(self.spread, 20.0))


def _activity(rng: random.Random) -> Activity:
    roll = rng.random()
    if roll < 0.4:    # active
        return Activity(base_age=rng.uniform(0.0, 20.0), spread=rng.uniform(30.0, 120.0))
    if roll < 0.75:   # dormant
        return Activity(base_age=rng.uniform(45.0, 200.0), spread=rng.uniform(60.0, 300.0))
    return Activity(base_age=rng.uniform(250.0, 900.0), spread=rng.uniform(90.0, 400.0))


def _project_name(rng: random.Random) -> str:
    a = rng.choice(V.PROJECT_WORDS_A)
    if rng.random() < 0.6:
        return f"{a}-{rng.choice(V.PROJECT_WORDS_B)}"
    return a


class WorldBuilder:
    def __init__(self, seed: int, scale: float = 1.0):
        self.rng = random.Random(seed)
        self.scale = scale
        self.root = build_root()
        self.user = self.rng.choice(V.USERNAMES)
        self.home = self.root.dir("Users").dir(self.user)
        self.home.age_days = 400.0

    def n(self, base: int, jitter: int = 0) -> int:
        """Scale a count (smoke mode shrinks trees)."""
        value = base + (self.rng.randint(0, jitter) if jitter else 0)
        return max(1, int(value * self.scale))

    def pick(self, population, base: int, jitter: int = 0) -> list:
        """Sample a scaled count from a vocabulary, clamped to its size."""
        population = list(population)
        return self.rng.sample(population, min(self.n(base, jitter), len(population)))

    def finder_droppings(self, node: Node, localized: bool = False) -> None:
        """Real macOS scans are littered with Finder metadata: ``.DS_Store``
        in most browsed directories and zero-byte ``.localized`` markers in
        the standard user folders. No recipe touches them, so they train the
        no-signal/uncertain shape at its true frequency."""
        rng = self.rng
        node.file(".DS_Store", rng.randint(6 * KB, 20 * KB), rng.uniform(0, 200))
        if localized:
            node.file(".localized", 0, rng.uniform(200, 900))

    # --- Dev projects ----------------------------------------------------------

    def add_git_dir(self, project: Node, act: Activity) -> None:
        rng = self.rng
        git = project.dir(".git", age_days=act.src_age(rng))
        git.file("HEAD", 23, act.base_age)
        git.file("config", rng.randint(200, 800), act.src_age(rng))
        git.file("index", _lognormal(rng, 40 * KB, 1.0), act.base_age)
        objects = git.dir("objects")
        pack = objects.dir("pack")
        pack.file(f"pack-{rng.getrandbits(80):020x}.pack", _lognormal(rng, 8 * MB, 1.5), act.src_age(rng))
        pack.file(f"pack-{rng.getrandbits(80):020x}.idx", _lognormal(rng, 500 * KB, 1.0), act.src_age(rng))
        refs = git.dir("refs").dir("heads")
        refs.file("main", 41, act.base_age)
        hooks = git.dir("hooks")
        hooks.file("pre-commit.sample", 1600, 700.0)

    def add_src_files(self, parent: Node, ext: str, count: int, act: Activity) -> None:
        rng = self.rng
        names = rng.sample(V.SRC_BASENAMES, min(count, len(V.SRC_BASENAMES)))
        for name in names:
            parent.file(f"{name}.{ext}", _lognormal(rng, 4 * KB, 1.2), act.src_age(rng))

    def rust_project(self, parent: Node, name: str) -> Node:
        rng = self.rng
        act = _activity(rng)
        project = parent.dir(name, age_days=act.base_age)
        project.file("Cargo.toml", rng.randint(300, 2000), act.src_age(rng))
        has_lock = rng.random() < 0.92
        if has_lock:
            project.file("Cargo.lock", _lognormal(rng, 60 * KB, 0.8), act.src_age(rng))
        if rng.random() < 0.9:
            project.file(".gitignore", rng.randint(20, 300), act.src_age(rng))
        project.file("README.md", _lognormal(rng, 3 * KB, 1.0), act.src_age(rng))
        self.add_git_dir(project, act)
        src = project.dir("src")
        self.add_src_files(src, "rs", self.n(8, 14), act)
        if rng.random() < 0.5:
            tests = project.dir("tests")
            self.add_src_files(tests, "rs", self.n(2, 3), act)
        if rng.random() < 0.85:  # built at least once
            target = project.dir("target", age_days=act.artifact_age(rng))
            target.file("CACHEDIR.TAG", 177, act.artifact_age(rng))
            for profile in (["debug"] + (["release"] if rng.random() < 0.5 else [])):
                prof = target.dir(profile, age_days=act.artifact_age(rng))
                deps = prof.dir("deps")
                for crate in self.pick(V.CRATES, 10, 25):
                    flat = crate.replace("-", "_")
                    suffix = f"{rng.getrandbits(64):016x}"
                    deps.file(f"lib{flat}-{suffix}.rlib", _lognormal(rng, 2 * MB, 1.4), act.artifact_age(rng))
                    deps.file(f"{flat}-{suffix}.d", rng.randint(200, 3000), act.artifact_age(rng))
                fingerprint = prof.dir(".fingerprint")
                for crate in self.pick(V.CRATES, 6, 10):
                    fdir = fingerprint.dir(f"{crate}-{rng.getrandbits(64):016x}")
                    fdir.file("lib-{}.json".format(crate.replace("-", "_")), rng.randint(300, 900), act.artifact_age(rng))
                incremental = prof.dir("incremental")
                inc = incremental.dir(f"{name.replace('-', '_')}-{rng.getrandbits(48):012x}")
                inc.file("s-gvvj0k5q-1x2y3z.lock", 0, act.artifact_age(rng))
                prof.file(name, _lognormal(rng, 12 * MB, 1.2), act.artifact_age(rng))
        return project

    def node_project(self, parent: Node, name: str) -> Node:
        rng = self.rng
        act = _activity(rng)
        project = parent.dir(name, age_days=act.base_age)
        project.file("package.json", rng.randint(400, 2500), act.src_age(rng))
        lock = rng.choice(["package-lock.json", "yarn.lock", "pnpm-lock.yaml"])
        if rng.random() < 0.9:
            project.file(lock, _lognormal(rng, 400 * KB, 1.0), act.src_age(rng))
        if rng.random() < 0.85:
            project.file(".gitignore", rng.randint(20, 200), act.src_age(rng))
        project.file("tsconfig.json", rng.randint(200, 900), act.src_age(rng))
        self.add_git_dir(project, act)
        src = project.dir("src")
        ext = rng.choice(["ts", "tsx", "js", "jsx"])
        self.add_src_files(src, ext, self.n(10, 20), act)
        if rng.random() < 0.4:
            comp = src.dir("components")
            self.add_src_files(comp, "tsx", self.n(5, 8), act)
        if rng.random() < 0.9:  # installed deps
            nm = project.dir("node_modules", age_days=act.artifact_age(rng))
            nm.file(".package-lock.json", _lognormal(rng, 300 * KB, 0.8), act.artifact_age(rng))
            if rng.random() < 0.3:  # pnpm layout: deep .pnpm store + nested node_modules
                pnpm = nm.dir(".pnpm")
                for pkg in self.pick(V.NPM_PACKAGES, 6, 10):
                    ver = f"{rng.randint(0, 18)}.{rng.randint(0, 20)}.{rng.randint(0, 9)}"
                    inner = pnpm.dir(f"{pkg}@{ver}").dir("node_modules").dir(pkg)
                    inner.file("package.json", rng.randint(300, 1500), act.artifact_age(rng))
                    inner.dir("dist").file("index.js", _lognormal(rng, 20 * KB, 1.3), act.artifact_age(rng))
            for pkg in self.pick(V.NPM_PACKAGES, 35, 80):
                pdir = nm.dir(pkg, age_days=act.artifact_age(rng))
                pdir.file("package.json", rng.randint(300, 2500), act.artifact_age(rng))
                pdir.file("README.md", _lognormal(rng, 4 * KB, 1.0), 200.0 + rng.uniform(0, 400))
                pdir.file("LICENSE", rng.randint(1000, 1500), 200.0 + rng.uniform(0, 400))
                inner = pdir.dir(rng.choice(["dist", "lib", "build"]))
                for i in range(self.n(3, 6)):
                    inner.file(f"index{'.min' if i % 2 else ''}.js", _lognormal(rng, 30 * KB, 1.5), act.artifact_age(rng))
                    if rng.random() < 0.5:
                        inner.file(f"index{'.min' if i % 2 else ''}.js.map", _lognormal(rng, 80 * KB, 1.2), act.artifact_age(rng))
                if rng.random() < 0.15:  # transitive nested node_modules
                    nested = pdir.dir("node_modules").dir(rng.choice(V.NPM_PACKAGES))
                    nested.file("package.json", rng.randint(300, 1200), act.artifact_age(rng))
                    nested.file("index.js", _lognormal(rng, 10 * KB, 1.2), act.artifact_age(rng))
        if rng.random() < 0.4:
            out = project.dir(rng.choice(["dist", "build", ".next"]), age_days=act.artifact_age(rng))
            for i in range(self.n(6, 12)):
                out.file(f"chunk-{rng.getrandbits(32):08x}.js", _lognormal(rng, 200 * KB, 1.3), act.artifact_age(rng))
                out.file(f"chunk-{rng.getrandbits(32):08x}.css", _lognormal(rng, 30 * KB, 1.0), act.artifact_age(rng))
        return project

    def python_project(self, parent: Node, name: str, ml: bool = False) -> Node:
        rng = self.rng
        act = _activity(rng)
        project = parent.dir(name, age_days=act.base_age)
        if rng.random() < 0.7:
            project.file("pyproject.toml", rng.randint(300, 2000), act.src_age(rng))
            if rng.random() < 0.5:
                project.file(rng.choice(["poetry.lock", "uv.lock"]), _lognormal(rng, 200 * KB, 0.8), act.src_age(rng))
        else:
            project.file("setup.py", rng.randint(300, 1500), act.src_age(rng))
            project.file("requirements.txt", rng.randint(100, 900), act.src_age(rng))
        if rng.random() < 0.85:
            project.file(".gitignore", rng.randint(20, 300), act.src_age(rng))
        self.add_git_dir(project, act)
        pkg = project.dir(name.replace("-", "_"))
        self.add_src_files(pkg, "py", self.n(8, 15), act)
        pkg.file("__init__.py", rng.randint(0, 400), act.src_age(rng))
        pyc = pkg.dir("__pycache__", age_days=act.artifact_age(rng))
        for child_name in list(pkg.children):
            if child_name.endswith(".py"):
                pyc.file(child_name[:-3] + ".cpython-312.pyc", _lognormal(rng, 6 * KB, 1.0), act.artifact_age(rng))
        if rng.random() < 0.7:
            venv = project.dir(".venv", age_days=act.artifact_age(rng))
            venv.file("pyvenv.cfg", 200, act.artifact_age(rng))
            bindir = venv.dir("bin")
            bindir.file("python", 60 * KB, act.artifact_age(rng))
            bindir.file("activate", 2000, act.artifact_age(rng))
            bindir.file("pip", 250, act.artifact_age(rng))
            site = venv.dirs("lib", "python3.12", "site-packages")
            for dep in self.pick(V.PYPI_PACKAGES, 15, 30):
                ddir = site.dir(dep)
                for i in range(self.n(4, 8)):
                    ddir.file(f"{rng.choice(V.SRC_BASENAMES)}.py", _lognormal(rng, 8 * KB, 1.3), act.artifact_age(rng))
                dpyc = ddir.dir("__pycache__")
                dpyc.file("__init__.cpython-312.pyc", _lognormal(rng, 4 * KB, 1.0), act.artifact_age(rng))
                site.dir(f"{dep}-{rng.randint(1, 9)}.{rng.randint(0, 30)}.{rng.randint(0, 9)}.dist-info").file(
                    "METADATA", rng.randint(1000, 20000), act.artifact_age(rng)
                )
        if rng.random() < 0.5:
            project.dir(".pytest_cache").file("CACHEDIR.TAG", 191, act.artifact_age(rng))
            cache_v = project.dir(".pytest_cache").dir("v").dir("cache")
            cache_v.file("lastfailed", rng.randint(2, 2000), act.artifact_age(rng))
            cache_v.file("nodeids", rng.randint(100, 40000), act.artifact_age(rng))
        if rng.random() < 0.35:
            mypy = project.dir(".mypy_cache").dir("3.12")
            for base in self.pick(V.SRC_BASENAMES, 4, 6):
                mypy.file(f"{base}.data.json", _lognormal(rng, 150 * KB, 1.0), act.artifact_age(rng))
                mypy.file(f"{base}.meta.json", _lognormal(rng, 2 * KB, 0.6), act.artifact_age(rng))
        if ml:
            self._ml_extras(project, act)
        if rng.random() < 0.3:
            project.file(f"{rng.choice(['analysis', 'exploration', 'scratch', 'train'])}.ipynb",
                         _lognormal(rng, 300 * KB, 1.4), act.src_age(rng))
        return project

    def _ml_extras(self, project: Node, act: Activity) -> None:
        rng = self.rng
        ckpts = project.dir("checkpoints", age_days=act.artifact_age(rng))
        for epoch in range(self.n(2, 5)):
            ckpts.file(f"epoch-{epoch:02d}.ckpt", _lognormal(rng, 800 * MB, 0.7),
                       act.base_age + 14.0 + rng.uniform(0, 200))
        if rng.random() < 0.6:
            weights = project.dir("weights")
            weights.file("model_final.pth", _lognormal(rng, 1200 * MB, 0.6), act.base_age + 30.0 + rng.uniform(0, 200))
            weights.file("best.pt", _lognormal(rng, 900 * MB, 0.6), act.base_age + 30.0 + rng.uniform(0, 150))
        if rng.random() < 0.6:
            out = project.dir("output")
            for step in (500, 1000):
                ck = out.dir(f"checkpoint-{step}", age_days=act.base_age + 14.0 + rng.uniform(0, 90))
                ck.file("trainer_state.json", rng.randint(2000, 60000))
                ck.file("model.safetensors", _lognormal(rng, 500 * MB, 0.5))
                ck.file("optimizer.pt", _lognormal(rng, 900 * MB, 0.5))
                ck.file("rng_state.pth", rng.randint(10000, 20000))
        if rng.random() < 0.7:
            wandb = project.dir("wandb")
            for _ in range(self.n(2, 4)):
                run = wandb.dir(f"run-2026{rng.randint(1, 6):02d}{rng.randint(1, 28):02d}_{rng.randint(100000, 999999)}-{rng.getrandbits(32):08x}")
                run.age_days = act.base_age + 30.0 + rng.uniform(0, 200)
                files = run.dir("files")
                files.file("output.log", _lognormal(rng, 2 * MB, 1.5), run.age_days)
                files.file("config.yaml", rng.randint(500, 4000), run.age_days)
                files.file("wandb-summary.json", rng.randint(200, 3000), run.age_days)
                run.dir("logs").file("debug.log", _lognormal(rng, 500 * KB, 1.2), run.age_days)
        if rng.random() < 0.5:
            data = project.dir("data")
            for i in range(self.n(2, 4)):
                data.file(f"shard-{i:04d}.parquet", _lognormal(rng, 200 * MB, 1.0), act.src_age(rng))
            data.file("labels.csv", _lognormal(rng, 5 * MB, 1.0), act.src_age(rng))
        if rng.random() < 0.4:
            ll = project.dir("lightning_logs").dir(f"version_{rng.randint(0, 8)}")
            ckdir = ll.dir("checkpoints")
            ckdir.file(f"epoch={rng.randint(1, 30)}-step={rng.randint(100, 9000)}.ckpt",
                       _lognormal(rng, 600 * MB, 0.6), act.base_age + 20.0 + rng.uniform(0, 120))
            ll.file("hparams.yaml", rng.randint(100, 2000), act.src_age(rng))

    def swift_project(self, parent: Node, name: str) -> Node:
        rng = self.rng
        act = _activity(rng)
        project = parent.dir(name, age_days=act.base_age)
        project.file("Package.swift", rng.randint(400, 2000), act.src_age(rng))
        project.file("Package.resolved", rng.randint(500, 5000), act.src_age(rng))
        if rng.random() < 0.8:
            project.file(".gitignore", rng.randint(20, 200), act.src_age(rng))
        self.add_git_dir(project, act)
        sources = project.dir("Sources").dir(name.title().replace("-", ""))
        self.add_src_files(sources, "swift", self.n(6, 12), act)
        if rng.random() < 0.7:
            build = project.dir(".build", age_days=act.artifact_age(rng))
            arm = build.dir("arm64-apple-macosx").dir(rng.choice(["debug", "release"]))
            for i in range(self.n(8, 15)):
                arm.file(f"{rng.choice(V.SRC_BASENAMES)}.swift.o", _lognormal(rng, 300 * KB, 1.2), act.artifact_age(rng))
            arm.file(f"{name}", _lognormal(rng, 8 * MB, 1.0), act.artifact_age(rng))
            build.dir("checkouts").dir("swift-argument-parser").file("Package.swift", 3000, 300.0)
        return project

    def jvm_project(self, parent: Node, name: str) -> Node:
        rng = self.rng
        act = _activity(rng)
        project = parent.dir(name, age_days=act.base_age)
        kotlin = rng.random() < 0.5
        project.file("build.gradle.kts" if kotlin else "build.gradle", rng.randint(400, 3000), act.src_age(rng))
        project.file("settings.gradle" + (".kts" if kotlin else ""), rng.randint(50, 400), act.src_age(rng))
        if rng.random() < 0.8:
            project.file(".gitignore", rng.randint(20, 200), act.src_age(rng))
        self.add_git_dir(project, act)
        src = project.dirs("src", "main", "kotlin" if kotlin else "java", "com", "example", name.replace("-", ""))
        self.add_src_files(src, "kt" if kotlin else "java", self.n(6, 12), act)
        if rng.random() < 0.75:
            build = project.dir("build", age_days=act.artifact_age(rng))
            classes = build.dirs("classes", "kotlin" if kotlin else "java", "main")
            for base in self.pick(V.SRC_BASENAMES, 5, 8):
                classes.file(f"{base.title()}.class", _lognormal(rng, 20 * KB, 1.0), act.artifact_age(rng))
            libs = build.dir("libs")
            libs.file(f"{name}-1.0.jar", _lognormal(rng, 15 * MB, 1.0), act.artifact_age(rng))
            build.dir("tmp").dir("compileKotlin").file("build-history.bin", _lognormal(rng, 100 * KB, 1.0), act.artifact_age(rng))
            project.dir(".gradle").dir("8.11").dir("executionHistory").file(
                "executionHistory.bin", _lognormal(rng, 30 * MB, 0.8), act.artifact_age(rng)
            )
        return project

    def go_project(self, parent: Node, name: str) -> Node:
        rng = self.rng
        act = _activity(rng)
        project = parent.dir(name, age_days=act.base_age)
        project.file("go.mod", rng.randint(100, 900), act.src_age(rng))
        project.file("go.sum", _lognormal(rng, 40 * KB, 0.9), act.src_age(rng))
        if rng.random() < 0.8:
            project.file(".gitignore", rng.randint(20, 150), act.src_age(rng))
        self.add_git_dir(project, act)
        self.add_src_files(project, "go", self.n(5, 8), act)
        cmd = project.dirs("cmd", name)
        cmd.file("main.go", _lognormal(rng, 3 * KB, 0.8), act.src_age(rng))
        internal = project.dir("internal")
        self.add_src_files(internal, "go", self.n(4, 8), act)
        return project

    def cpp_project(self, parent: Node, name: str) -> Node:
        rng = self.rng
        act = _activity(rng)
        project = parent.dir(name, age_days=act.base_age)
        project.file("CMakeLists.txt", rng.randint(300, 3000), act.src_age(rng))
        if rng.random() < 0.75:
            project.file(".gitignore", rng.randint(20, 150), act.src_age(rng))
        self.add_git_dir(project, act)
        src = project.dir("src")
        self.add_src_files(src, "cpp", self.n(6, 10), act)
        self.add_src_files(project.dir("include"), "hpp", self.n(3, 6), act)
        if rng.random() < 0.7:
            build = project.dir(rng.choice(["build", "cmake-build-debug"]), age_days=act.artifact_age(rng))
            build.file("CMakeCache.txt", rng.randint(10000, 60000), act.artifact_age(rng))
            build.file("Makefile", rng.randint(5000, 40000), act.artifact_age(rng))
            cmakefiles = build.dir("CMakeFiles")
            objdir = cmakefiles.dir(f"{name}.dir").dir("src")
            for child_name in list(src.children):
                objdir.file(child_name + ".o", _lognormal(rng, 400 * KB, 1.1), act.artifact_age(rng))
            build.file(name, _lognormal(rng, 5 * MB, 1.0), act.artifact_age(rng))
        return project

    def unity_project(self, parent: Node, name: str) -> Node:
        """Unity project: its Library dir is recipe territory (guarded)."""
        rng = self.rng
        act = _activity(rng)
        project = parent.dir(name, age_days=act.base_age)
        assets = project.dir("Assets")
        assets.dir("Scenes").file("Main.unity", _lognormal(rng, 300 * KB, 1.0), act.src_age(rng))
        assets.dir("Scripts").file("Player.cs", _lognormal(rng, 6 * KB, 0.8), act.src_age(rng))
        project.dir("ProjectSettings").file("ProjectVersion.txt", 100, act.src_age(rng))
        project.dir("Packages").file("manifest.json", rng.randint(500, 3000), act.src_age(rng))
        library = project.dir("Library", age_days=act.artifact_age(rng))
        library.dir("Artifacts").file(f"{rng.getrandbits(64):016x}", _lognormal(rng, 2 * MB, 1.5), act.artifact_age(rng))
        library.dir("ShaderCache").file("shaders.db", _lognormal(rng, 80 * MB, 0.8), act.artifact_age(rng))
        library.file("ArtifactDB", _lognormal(rng, 60 * MB, 0.8), act.artifact_age(rng))
        return project

    # --- Decoys: systematic near-misses from recipe guards ------------------------

    def decoys(self, parent: Node) -> None:
        rng = self.rng
        scratch = parent.dir("scratch", age_days=rng.uniform(30, 300))
        # target/ without Cargo.toml
        loose_target = scratch.dir("target", age_days=rng.uniform(20, 300))
        loose_target.file("results.csv", _lognormal(rng, 12 * MB, 1.0))
        loose_target.file("summary.txt", _lognormal(rng, 40 * KB, 1.0))
        # node_modules without package.json
        loose_nm = scratch.dir("node_modules", age_days=rng.uniform(20, 300))
        loose_nm.file("saved-snippet.js", _lognormal(rng, 30 * KB, 1.0))
        # build/ that is actually source (no CMakeCache, has sources)
        build_src = scratch.dir("build", age_days=rng.uniform(10, 200))
        build_src.file("deploy.sh", rng.randint(500, 4000))
        build_src.file("pipeline.yaml", rng.randint(300, 2000))
        # checkpoint-alpha dir without trainer_state.json
        photos = scratch.dir("checkpoint-alpha", age_days=rng.uniform(60, 400))
        photos.file("IMG_0001.jpg", _lognormal(rng, 3 * MB, 0.8))
        # a small .pt that is NOT a model weight (path hook size class)
        scratch.file("hook.pt", rng.randint(100, 4000), rng.uniform(60, 300))
        # a .ppt presentation (extension near-miss for **/*.pt)
        scratch.file("quarterly-review.ppt", _lognormal(rng, 8 * MB, 0.8), rng.uniform(60, 500))
        # fresh .venv (fails any age gate; pyvenv.cfg present = live)
        fresh = scratch.dir("fresh-experiment", age_days=rng.uniform(0, 3))
        venv = fresh.dir(".venv", age_days=rng.uniform(0, 3))
        venv.file("pyvenv.cfg", 200, rng.uniform(0, 3))
        venv.dirs("lib", "python3.12", "site-packages").file("six.py", 34 * KB, rng.uniform(0, 3))
        # non-Unity Library dir (a book-writing project)
        book = parent.dir("book-draft", age_days=rng.uniform(30, 400))
        library = book.dir("Library")
        library.file("references.bib", _lognormal(rng, 80 * KB, 0.8))
        book.file("chapter-01.md", _lognormal(rng, 40 * KB, 0.8))
        # tiny target WITH Cargo.toml (fails min_size_mb=10)
        tiny = parent.dir("hello-rust", age_days=rng.uniform(5, 60))
        tiny.file("Cargo.toml", 250)
        tiny.file("Cargo.lock", 1200)
        tiny.dir("src").file("main.rs", 800)
        tt = tiny.dir("target")
        tt.dir("debug").file("hello-rust", 900 * KB)

    # --- Non-dev life ---------------------------------------------------------------

    def user_data(self) -> None:
        rng = self.rng
        home = self.home
        docs = home.dir("Documents", age_days=300.0)
        self.finder_droppings(docs, localized=True)
        for name in self.pick(V.DOCUMENT_NAMES, 12, 20):
            docs.file(f"{name}.{rng.choice(V.DOCUMENT_EXTS)}", _lognormal(rng, 400 * KB, 1.6), rng.uniform(5, 1500))
        # a project someone dropped into Documents (floor keeps ALL of it)
        proj = docs.dir("old-website", age_days=rng.uniform(300, 900))
        proj.file("package.json", 600)
        nm = proj.dir("node_modules")
        for pkg in self.pick(V.NPM_PACKAGES, 6, 8):
            nm.dir(pkg).file("index.js", _lognormal(rng, 20 * KB, 1.2))
        desktop = home.dir("Desktop", age_days=100.0)
        self.finder_droppings(desktop, localized=True)
        for name in self.pick(V.SCREENSHOT_NAMES, 3, 3):
            desktop.file(f"{name}.png", _lognormal(rng, 2 * MB, 0.8), rng.uniform(1, 400))
        desktop.file("todo.md", rng.randint(100, 4000), rng.uniform(0, 60))
        downloads = home.dir("Downloads", age_days=200.0)
        self.finder_droppings(downloads, localized=True)
        for name in self.pick(V.DOWNLOAD_NAMES, 6, 8):
            ext = rng.choice(["dmg", "pkg", "zip", "tar.gz"])
            downloads.file(f"{name}.{ext}", _lognormal(rng, 150 * MB, 1.3), rng.uniform(2, 800))
        # iCloud Drive: real documents next to undownloaded .icloud placeholders
        # (tiny plist stubs the scanner sees as ordinary hidden files).
        cloud = home.dirs("Library", "Mobile Documents", "com~apple~CloudDocs")
        self.finder_droppings(cloud)
        for name in self.pick(V.DOCUMENT_NAMES, 3, 4):
            ext = rng.choice(V.DOCUMENT_EXTS)
            if rng.random() < 0.4:
                cloud.file(f".{name}.{ext}.icloud", rng.randint(150, 400), rng.uniform(5, 500))
            else:
                cloud.file(f"{name}.{ext}", _lognormal(rng, 500 * KB, 1.4), rng.uniform(5, 800))
        pictures = home.dir("Pictures", age_days=600.0)
        self.finder_droppings(pictures, localized=True)
        lib = pictures.dir("Photos Library.photoslibrary")
        originals = lib.dir("originals")
        for name in self.pick(V.MEDIA_NAMES, 10, 10):
            originals.file(f"{name}.{rng.choice(['heic', 'jpg', 'png'])}", _lognormal(rng, 3 * MB, 0.9), rng.uniform(30, 2000))
        movies = home.dir("Movies", age_days=700.0)
        movies.file("wedding-ceremony.mov", _lognormal(rng, 2 * GB, 0.8), rng.uniform(200, 2000))
        music = home.dir("Music", age_days=800.0)
        music.dir("Music").dir("Media").file("favorite-song.m4a", _lognormal(rng, 8 * MB, 0.6), rng.uniform(100, 1500))

    def credentials(self) -> None:
        rng = self.rng
        home = self.home
        ssh = home.dir(".ssh", age_days=500.0)
        ssh.file("id_ed25519", 411, rng.uniform(100, 900))
        ssh.file("id_ed25519.pub", 98, rng.uniform(100, 900))
        ssh.file("known_hosts", rng.randint(500, 8000), rng.uniform(0, 60))
        ssh.file("config", rng.randint(100, 2000), rng.uniform(30, 400))
        aws = home.dir(".aws", age_days=400.0)
        aws.file("credentials", rng.randint(100, 900), rng.uniform(10, 300))
        aws.file("config", rng.randint(50, 500), rng.uniform(10, 300))
        home.file(".netrc", rng.randint(50, 400), rng.uniform(30, 600))
        home.file(".npmrc", rng.randint(30, 300), rng.uniform(30, 600))
        home.file(".gitconfig", rng.randint(100, 1000), rng.uniform(5, 200))
        home.file(".zshrc", rng.randint(500, 8000), rng.uniform(0, 90))
        home.file(".zsh_history", _lognormal(rng, 300 * KB, 0.8), rng.uniform(0, 5))
        gnupg = home.dir(".gnupg", age_days=600.0)
        gnupg.file("pubring.kbx", _lognormal(rng, 30 * KB, 0.6), rng.uniform(100, 900))
        gnupg.file("trustdb.gpg", 1280, rng.uniform(100, 900))
        kube = home.dir(".kube", age_days=200.0)
        kube.file("config", rng.randint(1000, 8000), rng.uniform(10, 300))
        docker = home.dir(".docker", age_days=200.0)
        docker.file("config.json", rng.randint(100, 2000), rng.uniform(5, 200))
        gcloud = home.dirs(".config", "gcloud")
        gcloud.file("credentials.db", rng.randint(10000, 60000), rng.uniform(10, 300))
        gcloud.file("access_tokens.db", rng.randint(10000, 40000), rng.uniform(0, 30))
        claude = home.dir(".claude", age_days=100.0)
        claude.file(".credentials.json", rng.randint(300, 1200), rng.uniform(0, 30))
        claude.file("settings.json", rng.randint(100, 2000), rng.uniform(0, 90))
        projects = claude.dir("projects")
        for _ in range(self.n(2, 3)):
            pdir = projects.dir(f"-Users-{self.user}-code-{_project_name(rng)}")
            for _ in range(self.n(2, 4)):
                pdir.file(f"{rng.getrandbits(64):016x}.jsonl", _lognormal(rng, 800 * KB, 1.5), rng.uniform(0, 200))
        todos = claude.dir("todos")
        todos.file(f"{rng.getrandbits(64):016x}.json", rng.randint(200, 5000), rng.uniform(0, 60))
        statsig = claude.dir("statsig")
        statsig.file("statsig.cached.evaluations.2", _lognormal(rng, 200 * KB, 0.6), rng.uniform(8, 60))
        statsig.file("statsig.session_id.2", 150, rng.uniform(8, 60))
        statsig.file("statsig.stable_id.2", 60, rng.uniform(8, 60))

    def library(self) -> None:
        rng = self.rng
        home = self.home
        library = home.dir("Library", age_days=300.0)
        caches = library.dir("Caches")
        for app_name, bundle in self.pick(list(V.MACOS_APPS), 10, 15):
            cdir = caches.dir(bundle)
            for i in range(self.n(3, 6)):
                cdir.file(f"Cache.db-{i:03d}", _lognormal(rng, 4 * MB, 1.6), rng.uniform(1, 400))
            if rng.random() < 0.3:
                cdir.dir("fsCachedData").file(f"{rng.getrandbits(64):016X}", _lognormal(rng, 1 * MB, 1.4), rng.uniform(1, 200))
        # pip / homebrew / go-build style tool caches
        pip = caches.dir("pip").dir("wheels")
        for dep in self.pick(V.PYPI_PACKAGES, 6, 10):
            pip.dirs(f"{rng.getrandbits(8):02x}", f"{rng.getrandbits(8):02x}").file(
                f"{dep}-2.0.1-py3-none-any.whl", _lognormal(rng, 2 * MB, 1.5), rng.uniform(10, 500)
            )
        brew = caches.dir("Homebrew")
        for formula in self.pick(V.BREW_FORMULAS, 5, 10):
            brew.dir("downloads").file(
                f"{rng.getrandbits(64):016x}--{formula.replace('@', '-')}-{rng.randint(1, 20)}.{rng.randint(0, 9)}.{rng.randint(0, 9)}.bottle.tar.gz",
                _lognormal(rng, 12 * MB, 1.2), rng.uniform(10, 400),
            )
        go_build = caches.dir("go-build")
        for _ in range(self.n(6, 12)):
            shard = go_build.dir(f"{rng.getrandbits(8):02x}")
            shard.file(f"{rng.getrandbits(128):032x}-d", _lognormal(rng, 300 * KB, 1.5), rng.uniform(5, 200))
        # Application Support: electron apps get Cache/Code Cache (recipe
        # territory) NEXT TO real user data (keep territory).
        support = library.dir("Application Support")
        for app in self.pick(V.ELECTRON_APPS, 4, 6):
            adir = support.dir(app)
            cache = adir.dir("Cache").dir("Cache_Data")
            for i in range(self.n(4, 10)):
                cache.file(f"{rng.getrandbits(64):016x}_0", _lognormal(rng, 800 * KB, 1.6), rng.uniform(1, 200))
            code_cache = adir.dir("Code Cache").dir("js")
            code_cache.file(f"{rng.getrandbits(64):016x}_0", _lognormal(rng, 300 * KB, 1.3), rng.uniform(1, 200))
            adir.file("Preferences", rng.randint(1000, 60000), rng.uniform(0, 90))
            adir.dir("Local Storage").dir("leveldb").file("000003.log", _lognormal(rng, 200 * KB, 1.2), rng.uniform(0, 60))
            adir.dir("Session Storage").file("000004.ldb", _lognormal(rng, 100 * KB, 1.0), rng.uniform(0, 60))
        # Non-electron support data (keep shapes)
        support.dir("Firefox").dir("Profiles").dir(f"{rng.getrandbits(32):08x}.default-release").file(
            "places.sqlite", _lognormal(rng, 40 * MB, 0.6), rng.uniform(0, 60)
        )
        support.dir("MobileSync").dir("Backup").dir(f"{rng.getrandbits(120):030x}").file(
            "Manifest.db", _lognormal(rng, 500 * MB, 0.8), rng.uniform(60, 600)
        )
        # Logs (old → junk recipes; recent → uncertain)
        logs = library.dir("Logs")
        for app_name, bundle in self.pick(list(V.MACOS_APPS), 4, 6):
            ldir = logs.dir(app_name)
            for i in range(self.n(2, 4)):
                ldir.file(f"{app_name.replace(' ', '')}-{i}.log", _lognormal(rng, 800 * KB, 1.8), rng.uniform(10, 700))
        diag = logs.dir("DiagnosticReports")
        diag.file(f"Safari-2026-0{rng.randint(1, 6)}-{rng.randint(10, 28)}-{rng.randint(100000, 235959)}.ips",
                  _lognormal(rng, 100 * KB, 0.8), rng.uniform(10, 300))
        # Xcode DerivedData + device support
        xcode = library.dir("Developer").dir("Xcode")
        derived = xcode.dir("DerivedData")
        for _ in range(self.n(2, 3)):
            pname = _project_name(rng)
            ddir = derived.dir(f"{pname}-{rng.getrandbits(80):020x}"[:40])
            build_dir = ddir.dirs("Build", "Products", "Debug-iphonesimulator")
            build_dir.file(f"{pname}.app", _lognormal(rng, 40 * MB, 1.0), rng.uniform(2, 200))
            ddir.dirs("Build", "Intermediates.noindex").file("file-list", rng.randint(100, 4000), rng.uniform(2, 200))
            ddir.dir("Index.noindex").file("db.sqlite3", _lognormal(rng, 200 * MB, 0.8), rng.uniform(2, 200))
            ddir.file("info.plist", 400, rng.uniform(2, 200))
        ios = xcode.dir("iOS DeviceSupport")
        for _ in range(self.n(1, 2)):
            dsdir = ios.dir(f"1{rng.randint(6, 8)}.{rng.randint(0, 5)} ({rng.randint(20, 22)}{rng.choice('ABCDEF')}{rng.randint(100, 999)})")
            symbols = dsdir.dir("Symbols").dir("usr").dir("lib")
            symbols.file("libSystem.dylib", _lognormal(rng, 900 * MB, 0.5), rng.uniform(60, 700))
        # Containers (protected)
        containers = library.dir("Containers")
        mail = containers.dir("com.apple.mail").dir("Data")
        maildata = mail.dir("Library").dir("Mail Downloads")
        maildata.file("contract-signed.pdf", _lognormal(rng, 800 * KB, 0.8), rng.uniform(10, 500))
        mail.file("state.db", _lognormal(rng, 20 * MB, 0.8), rng.uniform(0, 60))
        news = containers.dir("com.apple.news").dir("Data").dir("Library").dir("Caches")
        news.file("cache.db", _lognormal(rng, 30 * MB, 0.8), rng.uniform(0, 200))
        group = library.dir("Group Containers")
        group.dir("group.com.apple.notes").file("NoteStore.sqlite", _lognormal(rng, 60 * MB, 0.8), rng.uniform(0, 90))
        # Mail / Messages / Keychains (protected)
        library.dir("Mail").dir("V10").dir("MailData").file("Envelope Index", _lognormal(rng, 150 * MB, 0.6), rng.uniform(0, 30))
        library.dir("Messages").file("chat.db", _lognormal(rng, 300 * MB, 0.6), rng.uniform(0, 10))
        library.dir("Keychains").file("login.keychain-db", _lognormal(rng, 2 * MB, 0.5), rng.uniform(0, 30))
        library.dir("Preferences").file(f"{rng.choice([b for _, b in V.MACOS_APPS])}.plist", rng.randint(200, 20000), rng.uniform(0, 200))
        library.dir("Saved Application State").dir("com.apple.Safari.savedState").file(
            "windows.plist", rng.randint(2000, 60000), rng.uniform(0, 90)
        )

    def global_dev_caches(self) -> None:
        rng = self.rng
        home = self.home
        # ~/.cache: huggingface, uv, torch, pip-tools style
        cache = home.dir(".cache", age_days=200.0)
        hf_hub = cache.dirs("huggingface", "hub")
        for model in self.pick(V.HF_MODELS, 3, 5):
            mdir = hf_hub.dir(f"models--{model.replace('/', '--')}")
            blobs = mdir.dir("blobs")
            blobs.file(f"{rng.getrandbits(256):064x}", _lognormal(rng, 2 * GB, 1.0), rng.uniform(10, 400))
            blobs.file(f"{rng.getrandbits(256):064x}", _lognormal(rng, 500 * KB, 1.0), rng.uniform(10, 400))
            snap = mdir.dirs("snapshots", f"{rng.getrandbits(160):040x}")
            snap.file("config.json", rng.randint(500, 3000), rng.uniform(10, 400))
            snap.file("model.safetensors", 60, rng.uniform(10, 400))  # symlink-sized stub
        cache.dir("uv").dir("wheels-v1").file(f"{rng.getrandbits(64):016x}.whl", _lognormal(rng, 3 * MB, 1.2), rng.uniform(5, 200))
        torch_hub = cache.dirs("torch", "hub", "checkpoints")
        torch_hub.file("resnet50-0676ba61.pth", _lognormal(rng, 100 * MB, 0.3), rng.uniform(30, 500))
        # ~/.npm cacache
        npm = home.dir(".npm", age_days=150.0)
        cacache = npm.dir("_cacache")
        content = cacache.dirs("content-v2", "sha512", f"{rng.getrandbits(8):02x}", f"{rng.getrandbits(8):02x}")
        for _ in range(self.n(5, 10)):
            content.file(f"{rng.getrandbits(240):060x}", _lognormal(rng, 300 * KB, 1.8), rng.uniform(5, 400))
        npm.dir("_logs").file(f"2026-0{rng.randint(1, 6)}-{rng.randint(10, 28)}T10_00_00_000Z-debug-0.log",
                              _lognormal(rng, 100 * KB, 1.0), rng.uniform(5, 300))
        # ~/.cargo registry + git
        cargo = home.dir(".cargo", age_days=250.0)
        registry = cargo.dir("registry")
        cache_dir = registry.dirs("cache", "index.crates.io-6f17d22bba15001f")
        for crate in self.pick(V.CRATES, 10, 20):
            cache_dir.file(f"{crate}-{rng.randint(0, 3)}.{rng.randint(0, 20)}.{rng.randint(0, 9)}.crate",
                           _lognormal(rng, 150 * KB, 1.4), rng.uniform(10, 500))
        src_dir = registry.dirs("src", "index.crates.io-6f17d22bba15001f")
        for crate in self.pick(V.CRATES, 6, 12):
            cdir = src_dir.dir(f"{crate}-{rng.randint(0, 3)}.{rng.randint(0, 20)}.{rng.randint(0, 9)}")
            cdir.file("Cargo.toml", rng.randint(300, 2000), rng.uniform(10, 500))
            self.add_src_files(cdir.dir("src"), "rs", self.n(3, 6), Activity(base_age=rng.uniform(10, 500), spread=10))
        cargo.dir("bin").file("cargo-nextest", _lognormal(rng, 15 * MB, 0.5), rng.uniform(30, 400))
        # ~/.rustup toolchains
        rustup = home.dir(".rustup", age_days=300.0)
        tc = rustup.dirs("toolchains", "stable-aarch64-apple-darwin", "lib", "rustlib")
        tc.file("components", 40, rng.uniform(30, 400))
        tcdir = tc.dir("aarch64-apple-darwin").dir("lib")
        for _ in range(self.n(4, 8)):
            tcdir.file(f"libstd-{rng.getrandbits(64):016x}.dylib", _lognormal(rng, 10 * MB, 0.6), rng.uniform(30, 400))
        # go module cache
        gopath = home.dir("go", age_days=250.0)
        gomod = gopath.dirs("pkg", "mod", "github.com")
        for module in self.pick(V.GO_MODULES, 4, 8):
            tail = module.split("/", 1)[1]
            parts = tail.split("/")
            mdir = gomod
            for part in parts[:-1]:
                mdir = mdir.dir(part)
            vdir = mdir.dir(f"{parts[-1]}@v{rng.randint(0, 2)}.{rng.randint(0, 20)}.{rng.randint(0, 9)}")
            self.add_src_files(vdir, "go", self.n(3, 6), Activity(base_age=rng.uniform(10, 500), spread=10))
        # poetry cache virtualenvs (recipe-safety learning: live envs!)
        poetry = home.dirs("Library", "Caches", "pypoetry", "virtualenvs")
        for _ in range(self.n(1, 2)):
            env = poetry.dir(f"{_project_name(rng)}-{rng.getrandbits(32):08x}-py3.12")
            env.file("pyvenv.cfg", 250, rng.uniform(0, 200))
            site = env.dirs("lib", "python3.12", "site-packages")
            for dep in self.pick(V.PYPI_PACKAGES, 4, 8):
                site.dir(dep).file("__init__.py", _lognormal(rng, 5 * KB, 1.0), rng.uniform(0, 200))

    def system_paths(self) -> None:
        rng = self.rng
        system = self.root.dir("System", age_days=900.0)
        fw = system.dirs("Library", "Frameworks", "Foundation.framework")
        fw.file("Foundation", _lognormal(rng, 8 * MB, 0.4), 900.0)
        self.root.dir("usr", age_days=900.0).dir("lib").file("libSystem.dylib", _lognormal(rng, 2 * MB, 0.3), 900.0)
        apps = self.root.dir("Applications", age_days=400.0)
        for app_name, bundle in self.pick(list(V.MACOS_APPS), 4, 6):
            adir = apps.dir(f"{app_name}.app").dir("Contents")
            adir.file("Info.plist", rng.randint(1000, 8000), rng.uniform(30, 600))
            adir.dir("MacOS").file(app_name.replace(" ", ""), _lognormal(rng, 60 * MB, 1.0), rng.uniform(30, 600))
        private = self.root.dir("private", age_days=900.0)
        private.dir("etc").file("hosts", 300, rng.uniform(100, 900))
        private.dirs("var", "folders", "zz").file("cleanton-scratch.tmp", _lognormal(rng, 100 * KB, 1.0), rng.uniform(0, 10))

    def projects(self) -> None:
        rng = self.rng
        code_dir = self.home.dir(rng.choice(["code", "Projects", "dev", "work"]), age_days=200.0)
        self.finder_droppings(code_dir)
        builders = [
            (self.rust_project, 2), (self.node_project, 2),
            (lambda p, n: self.python_project(p, n, ml=False), 2),
            (lambda p, n: self.python_project(p, n, ml=True), 1),
            (self.swift_project, 1), (self.jvm_project, 1),
            (self.go_project, 1), (self.cpp_project, 1),
            (self.unity_project, 1),
        ]
        count = self.n(6, 6)
        used_names: set[str] = set()
        weighted = [b for b, w in builders for _ in range(w)]
        for _ in range(count):
            builder = rng.choice(weighted)
            name = _project_name(rng)
            while name in used_names:
                name = _project_name(rng)
            used_names.add(name)
            project = builder(code_dir, name)
            if rng.random() < 0.35:  # Finder was here
                self.finder_droppings(project)
        self.decoys(code_dir)

    def build(self) -> Node:
        self.credentials()
        self.user_data()
        self.projects()
        self.library()
        self.global_dev_caches()
        self.system_paths()
        self.root.freeze()
        return self.root


def generate_world(seed: int, scale: float = 1.0) -> Node:
    return WorldBuilder(seed, scale=scale).build()
