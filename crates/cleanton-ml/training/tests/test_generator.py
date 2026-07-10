"""Generator invariants: determinism, coherence, correlated metadata."""

import pytest

from training.features import KIND_DIRECTORY
from training.fstree import node_to_sample
from training.generator import generate_world

MB = 1024 * 1024


@pytest.fixture(scope="module")
def world():
    return generate_world(seed=42, scale=0.3)


def tree_signature(root):
    return sorted((n.path, n.kind, n.size_bytes, round(n.age_days, 6)) for n in root.walk())


def test_deterministic_for_same_seed(world):
    again = generate_world(seed=42, scale=0.3)
    assert tree_signature(world) == tree_signature(again)


def test_different_seeds_differ(world):
    other = generate_world(seed=43, scale=0.3)
    assert tree_signature(world) != tree_signature(other)


def test_scale_shrinks_trees():
    small = sum(1 for _ in generate_world(seed=7, scale=0.15).walk())
    large = sum(1 for _ in generate_world(seed=7, scale=1.0).walk())
    assert small < large


def test_rust_targets_always_have_manifest_evidence(world):
    # Coherence: every generated target/ under a code dir has Cargo.toml
    # beside it EXCEPT the deliberate decoys (scratch/ and tiny project).
    for node in world.walk():
        if node.name == "target" and node.kind == KIND_DIRECTORY:
            parent = node.parent
            if parent is not None and parent.name in ("scratch",):
                assert "Cargo.toml" not in parent.children
            elif parent is not None:
                assert "Cargo.toml" in parent.children, node.path


def test_node_modules_have_package_json_except_decoys(world):
    for node in world.walk():
        if node.name == "node_modules" and node.kind == KIND_DIRECTORY:
            parent = node.parent
            grand = parent.parent if parent is not None else None
            in_nm_tree = any(a.name == "node_modules" for a in _ancestors(node))
            if parent is not None and parent.name == "scratch":
                assert "package.json" not in parent.children
            elif parent is not None and not in_nm_tree:
                assert "package.json" in parent.children, node.path
            del grand


def _ancestors(node):
    current = node.parent
    while current is not None:
        yield current
        current = current.parent


def test_context_flags_match_tree_reality(world):
    checked = 0
    for node in world.walk():
        if not node.name or node.parent is None:
            continue
        sample = node_to_sample(node)
        assert sample.has_gitignore == (".gitignore" in node.parent.children), node.path
        assert sample.sibling_count == len(node.parent.children), node.path
        checked += 1
        if checked > 2000:
            break
    assert checked > 100


def test_age_locality_build_artifacts_cluster_near_activity(world):
    # Within one project, target/ contents share age locality: the spread of
    # artifact ages must be far smaller than the global age range.
    for node in world.walk():
        if node.name == "target" and node.kind == KIND_DIRECTORY and node.children:
            ages = [child.age_days for child in node.walk() if child is not node]
            if len(ages) > 5:
                assert max(ages) - min(ages) <= 40.0, node.path


def test_world_contains_required_shapes(world):
    paths = {node.path for node in world.walk()}
    home = next(p for p in paths if p.startswith("/Users/") and p.count("/") == 2)
    assert any(p.startswith(f"{home}/Library/Caches/") for p in paths)
    assert any("/node_modules/" in p for p in paths)
    assert any(p.endswith("pyvenv.cfg") for p in paths)
    assert any("/.ssh/" in p for p in paths)
    assert any("/Documents/" in p for p in paths)
    assert any("/wandb/" in p or "/checkpoints/" in p for p in paths)
    assert any(p.startswith("/System/") for p in paths)


def test_finder_metadata_is_generated(world):
    # Real macOS scans always contain Finder droppings; the generator must
    # produce them so the model sees the no-signal shape at true frequency.
    paths = {node.path for node in world.walk()}
    ds_stores = [p for p in paths if p.endswith("/.DS_Store")]
    assert len(ds_stores) >= 4, ds_stores
    assert any(p.endswith("/.localized") for p in paths)
    zero_byte = [n for n in world.walk() if n.kind != KIND_DIRECTORY and n.size_bytes == 0]
    assert zero_byte, "expected zero-byte files (.localized at minimum)"


def test_icloud_placeholders_and_pnpm_store_across_worlds():
    # Probabilistic shapes: check across a few seeds rather than one world.
    found_icloud = found_pnpm = False
    for seed in range(60, 70):
        for node in generate_world(seed=seed, scale=0.3).walk():
            if node.path.endswith(".icloud"):
                found_icloud = True
            if "/node_modules/.pnpm/" in node.path:
                found_pnpm = True
        if found_icloud and found_pnpm:
            break
    assert found_icloud and found_pnpm


def test_directory_sizes_aggregate(world):
    for node in world.walk():
        if node.kind == KIND_DIRECTORY and node.children:
            total = sum(
                child.subtree_bytes() for child in node.children.values()
            )
            assert node.subtree_bytes() == total
            break
