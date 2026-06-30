//! Pure Homebrew keep-set analysis. No I/O, fully unit-tested.

use std::collections::{HashMap, HashSet};

use crate::types::{Inventory, RemovalPlan};

/// Computes which installed packages can be removed if `keep` (plus everything
/// it transitively depends on) is retained.
///
/// For Homebrew formulae the dependency graph drives a transitive closure and a
/// dependents-before-dependencies uninstall order. For managers without a graph
/// (casks, npm, pip, `MacPorts` have empty `deps`) this degenerates to
/// `installed - keep`, ordered alphabetically.
// The concrete `HashSet<String>` is part of the public, app/CLI-facing API
// contract, so a generic hasher parameter is intentionally not exposed.
#[allow(clippy::implicit_hasher)]
#[must_use]
pub fn plan_removal(inv: &Inventory, keep: &HashSet<String>) -> RemovalPlan {
    // Owned adjacency keeps lifetimes trivial; package graphs are tiny.
    let deps_map: HashMap<String, Vec<String>> = inv
        .packages
        .iter()
        .map(|pkg| (pkg.name.clone(), pkg.deps.clone()))
        .collect();
    let size_map: HashMap<&str, u64> = inv
        .packages
        .iter()
        .map(|pkg| (pkg.name.as_str(), pkg.size_bytes))
        .collect();
    let installed: HashSet<&str> = inv.packages.iter().map(|pkg| pkg.name.as_str()).collect();

    // closure(keep) = keep + all transitive deps (DFS, cycle-safe via visited).
    let mut closure: HashSet<String> = HashSet::new();
    let mut stack: Vec<String> = keep.iter().cloned().collect();
    while let Some(name) = stack.pop() {
        if !closure.insert(name.clone()) {
            continue;
        }
        if let Some(deps) = deps_map.get(&name) {
            for dep in deps {
                if !closure.contains(dep) {
                    stack.push(dep.clone());
                }
            }
        }
    }

    let mut removable: Vec<String> = installed
        .iter()
        .filter(|name| !closure.contains(**name))
        .map(|name| (*name).to_owned())
        .collect();
    removable.sort();

    let mut kept_as_dependency: Vec<String> = closure
        .iter()
        .filter(|name| !keep.contains(*name) && installed.contains(name.as_str()))
        .cloned()
        .collect();
    kept_as_dependency.sort();

    let reclaimable_bytes = removable.iter().fold(0_u64, |acc, name| {
        acc.saturating_add(size_map.get(name.as_str()).copied().unwrap_or(0))
    });

    let removable_set: HashSet<String> = removable.iter().cloned().collect();
    let uninstall_order = uninstall_order(&removable, &removable_set, &deps_map);

    let mut keep_sorted: Vec<String> = keep.iter().cloned().collect();
    keep_sorted.sort();

    RemovalPlan {
        keep: keep_sorted,
        removable,
        kept_as_dependency,
        reclaimable_bytes,
        uninstall_order,
    }
}

/// Reverse-topological order over the removable sub-graph: a package always
/// precedes the dependencies it pulls in, so `brew uninstall` never refuses on
/// "still required by". Deterministic and cycle-safe.
///
/// We DFS nodes in *descending* name order and push in post-order, then reverse
/// the whole vector. Post-order puts dependencies before dependents; reversing
/// flips that to dependents-first, and the descending visit makes independent
/// nodes come out in ascending name order.
fn uninstall_order(
    removable: &[String],
    set: &HashSet<String>,
    deps_map: &HashMap<String, Vec<String>>,
) -> Vec<String> {
    let mut nodes: Vec<String> = removable.to_vec();
    nodes.sort();
    nodes.reverse();

    let mut visited: HashSet<String> = HashSet::new();
    let mut on_stack: HashSet<String> = HashSet::new();
    let mut order: Vec<String> = Vec::with_capacity(removable.len());

    for node in &nodes {
        dfs_post(node, set, deps_map, &mut visited, &mut on_stack, &mut order);
    }
    order.reverse();
    order
}

fn dfs_post(
    node: &str,
    set: &HashSet<String>,
    deps_map: &HashMap<String, Vec<String>>,
    visited: &mut HashSet<String>,
    on_stack: &mut HashSet<String>,
    order: &mut Vec<String>,
) {
    if visited.contains(node) {
        return;
    }
    // Cycle guard: if `node` is already on the current DFS path, stop.
    if !on_stack.insert(node.to_owned()) {
        return;
    }
    if let Some(deps) = deps_map.get(node) {
        let mut children: Vec<&str> = deps
            .iter()
            .map(String::as_str)
            .filter(|dep| set.contains(*dep))
            .collect();
        children.sort_unstable();
        children.reverse();
        for child in children {
            dfs_post(child, set, deps_map, visited, on_stack, order);
        }
    }
    on_stack.remove(node);
    if visited.insert(node.to_owned()) {
        order.push(node.to_owned());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ManagerKind, Package};

    fn pkg(name: &str, deps: &[&str], size: u64) -> Package {
        Package {
            manager: ManagerKind::Homebrew,
            name: name.to_owned(),
            version: "1.0".to_owned(),
            size_bytes: size,
            is_leaf: true,
            explicitly_installed: true,
            outdated_to: None,
            deps: deps.iter().map(|d| (*d).to_owned()).collect(),
            used_by: Vec::new(),
        }
    }

    fn brew_inv(packages: Vec<Package>) -> Inventory {
        Inventory::ready(ManagerKind::Homebrew, packages, None)
    }

    fn keep(names: &[&str]) -> HashSet<String> {
        names.iter().map(|n| (*n).to_owned()).collect()
    }

    fn before(order: &[String], a: &str, b: &str) -> bool {
        let pa = order.iter().position(|x| x == a);
        let pb = order.iter().position(|x| x == b);
        matches!((pa, pb), (Some(ia), Some(ib)) if ia < ib)
    }

    #[test]
    fn chain_keep_root_keeps_all() {
        // a -> b -> c, keep {a} keeps everything.
        let inv = brew_inv(vec![
            pkg("a", &["b"], 10),
            pkg("b", &["c"], 20),
            pkg("c", &[], 40),
        ]);
        let plan = plan_removal(&inv, &keep(&["a"]));
        assert!(plan.removable.is_empty());
        assert_eq!(plan.reclaimable_bytes, 0);
        assert_eq!(
            plan.kept_as_dependency,
            vec!["b".to_owned(), "c".to_owned()]
        );
    }

    #[test]
    fn empty_keep_makes_leaves_removable() {
        let inv = brew_inv(vec![
            pkg("a", &["b"], 10),
            pkg("b", &["c"], 20),
            pkg("c", &[], 40),
        ]);
        let plan = plan_removal(&inv, &keep(&[]));
        assert_eq!(
            plan.removable,
            vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]
        );
        assert_eq!(plan.reclaimable_bytes, 70);
        // Dependents before dependencies.
        assert!(before(&plan.uninstall_order, "a", "b"));
        assert!(before(&plan.uninstall_order, "b", "c"));
    }

    #[test]
    fn diamond_keep_root_keeps_all() {
        // a -> b, a -> c, b -> d, c -> d
        let inv = brew_inv(vec![
            pkg("a", &["b", "c"], 1),
            pkg("b", &["d"], 1),
            pkg("c", &["d"], 1),
            pkg("d", &[], 1),
        ]);
        let plan = plan_removal(&inv, &keep(&["a"]));
        assert!(plan.removable.is_empty());
        let mut kept = plan.kept_as_dependency.clone();
        kept.sort();
        assert_eq!(kept, vec!["b".to_owned(), "c".to_owned(), "d".to_owned()]);
    }

    #[test]
    fn diamond_empty_keep_order_is_safe() {
        let inv = brew_inv(vec![
            pkg("a", &["b", "c"], 1),
            pkg("b", &["d"], 1),
            pkg("c", &["d"], 1),
            pkg("d", &[], 1),
        ]);
        let plan = plan_removal(&inv, &keep(&[]));
        // a before its deps; all before d.
        assert!(before(&plan.uninstall_order, "a", "b"));
        assert!(before(&plan.uninstall_order, "a", "c"));
        assert!(before(&plan.uninstall_order, "b", "d"));
        assert!(before(&plan.uninstall_order, "c", "d"));
    }

    #[test]
    fn cycle_is_handled() {
        // a -> b -> a (pathological); must terminate and list both.
        let inv = brew_inv(vec![pkg("a", &["b"], 5), pkg("b", &["a"], 5)]);
        let plan = plan_removal(&inv, &keep(&[]));
        assert_eq!(plan.removable, vec!["a".to_owned(), "b".to_owned()]);
        assert_eq!(plan.uninstall_order.len(), 2);
    }

    #[test]
    fn non_homebrew_degenerates_to_alpha() {
        // No deps anywhere => removable is installed - keep, ordered by name.
        let mut p1 = pkg("zlib", &[], 3);
        let mut p2 = pkg("curl", &[], 7);
        p1.manager = ManagerKind::Npm;
        p2.manager = ManagerKind::Npm;
        let inv = Inventory::ready(ManagerKind::Npm, vec![p1, p2], None);
        let plan = plan_removal(&inv, &keep(&["curl"]));
        assert_eq!(plan.removable, vec!["zlib".to_owned()]);
        assert_eq!(plan.uninstall_order, vec!["zlib".to_owned()]);
        assert!(plan.kept_as_dependency.is_empty());
    }
}
