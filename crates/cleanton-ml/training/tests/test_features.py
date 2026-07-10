"""Feature schema v2 unit tests (formulas, vocab stability, hashing)."""

import math

import numpy as np

from training import features as F
from training.features import FileSample, extract_features


def test_self_check_passes():
    F.self_check()


def test_v1_extension_ids_preserved():
    # v1 ids must stay stable so the vocab is append-only.
    assert F.EXTENSION_IDS["rs"] == 1
    assert F.EXTENSION_IDS["swift"] == 2
    assert F.EXTENSION_IDS["py"] == 7
    assert F.EXTENSION_IDS["lock"] == 29
    assert F.EXTENSION_IDS["pyc"] == 35 and F.EXTENSION_IDS["pyo"] == 35
    assert F.EXTENSION_IDS["ckpt"] == 59 and F.EXTENSION_IDS["pt"] == 59
    assert F.EXTENSION_IDS["onnx"] == 61


def test_v1_dir_ids_preserved():
    assert F.DIR_IDS["target"] == 1
    assert F.DIR_IDS["node_modules"] == 7
    assert F.DIR_IDS[".venv"] == 17 and F.DIR_IDS["venv"] == 17
    assert F.DIR_IDS["wandb"] == 23


def test_extension_mirrors_rust_path_extension():
    # Dotfiles have no extension; trailing dots have no extension.
    assert F.extension_id("/a/.gitignore") == 0
    assert F.extension_id("/a/name.") == 0
    assert F.extension_id("/a/archive.TAR") == F.EXTENSION_IDS["tar"]
    assert F.extension_id("/a/noext") == 0


def test_parent_and_grandparent_ids():
    path = "/Users/dev/proj/target/debug/app.o"
    assert F.parent_id(path) == F.DIR_IDS["debug"]
    assert F.grandparent_id(path) == F.DIR_IDS["target"]
    assert F.parent_id("/file") == 0
    assert F.grandparent_id("/a/file") == 0


def test_numeric_formulas():
    sample = FileSample(
        path="/Users/dev/x/data123.bin", size_bytes=999, age_days=9.0,
        depth=4, sibling_count=99, sibling_total_bytes=99_999,
    )
    got = extract_features(sample)
    assert got[3] == np.float32(3.0)                      # log10(1000)
    assert abs(got[4] - math.log10(10.0)) < 1e-6          # log10(9+1)
    assert got[5] == 4.0
    assert got[6] == np.float32(2.0)                      # log10(100)
    name = "data123.bin"
    assert abs(got[7] - math.log10(len(name) + 1)) < 1e-6
    assert abs(got[8] - 3.0 / len(name)) < 1e-6           # 3 digits
    assert abs(got[9] - (3.0 - 5.0)) < 1e-5               # log10 ratio


def test_depth_saturates_like_u16():
    sample = FileSample(path="/x", depth=1_000_000)
    assert extract_features(sample)[5] == 65535.0


def test_signal_path_convention():
    # Directory entries: components include the dir itself.
    d = FileSample(path="/p/node_modules", kind=F.KIND_DIRECTORY)
    f = FileSample(path="/p/node_modules/react/index.js")
    outside = FileSample(path="/p/node_modules-backup/file.js")
    assert extract_features(d)[19] == 1.0
    assert extract_features(f)[19] == 1.0
    assert extract_features(outside)[19] == 0.0


def test_library_pair_flags():
    caches = FileSample(path="/Users/m/Library/Caches/com.app.x/blob")
    support = FileSample(path="/Users/m/Library/Application Support/Slack/Cache/f")
    containers = FileSample(path="/Users/m/Library/Containers/com.apple.mail/Data/s.db")
    unity = FileSample(path="/Users/m/code/game/Library/ArtifactDB")
    got = extract_features(caches)
    assert got[22] == 1.0 and got[23] == 1.0
    got = extract_features(support)
    assert got[24] == 1.0 and got[23] == 0.0
    got = extract_features(containers)
    assert got[25] == 1.0
    got = extract_features(unity)
    assert got[22] == 1.0 and got[23] == 0.0 and got[25] == 0.0


def test_user_data_and_system_root():
    assert extract_features(FileSample(path="/Users/m/Documents/a.pdf"))[28] == 1.0
    assert extract_features(FileSample(path="/Users/m/code/a.pdf"))[28] == 0.0
    assert extract_features(FileSample(path="/System/Library/x"))[29] == 1.0
    assert extract_features(FileSample(path="/Users/m/x"))[29] == 0.0


def test_cmake_build_prefix_counts_as_build_dir():
    sample = FileSample(path="/Users/m/code/x/cmake-build-debug/CMakeCache.txt")
    assert extract_features(sample)[17] == 1.0


def test_hash_buckets_depend_only_on_basename_and_are_stable():
    a = F.name_hash_buckets("/x/y/statsig.cached.evaluations.2")
    b = F.name_hash_buckets("/other/statsig.cached.evaluations.2")
    assert a == b
    assert sum(a) >= 1.0
    # Pure-digit tokens are dropped.
    assert F.name_hash_buckets("/x/12345") == [0.0] * 16


def test_fnv1a32_reference_vector():
    # Known FNV-1a 32-bit test vectors.
    assert F.fnv1a32(b"") == 2166136261
    assert F.fnv1a32(b"a") == 0xE40C292C
    assert F.fnv1a32(b"foobar") == 0xBF9CF968


def test_schema_hash_is_deterministic():
    assert F.schema_hash() == F.schema_hash()
    assert len(F.schema_hash()) == 64


def test_normalization_is_identity_for_categorical():
    from training.train import compute_normalization

    x = np.random.default_rng(0).normal(5, 2, size=(64, F.FEATURE_COUNT)).astype(np.float32)
    mean, std = compute_normalization(x)
    assert (mean[: F.CATEGORICAL_COUNT] == 0.0).all()
    assert (std[: F.CATEGORICAL_COUNT] == 1.0).all()
    assert (mean[F.CATEGORICAL_COUNT:] != 0.0).any()
