use std::{
    path::{Component, Path, PathBuf},
    time::{Duration, SystemTime},
};

use cleanton_common::{
    ActionType, CleantonError, FileEntry, FileKind, ProtectedPaths, Result, SafetyLevel,
    paths::expand_tilde,
};
use glob::Pattern;

use crate::{MatchSpec, RecipeDocument, matcher::recipe_matches_entry_with_parent_lookup};

pub fn validate_recipe(path: &Path, document: &RecipeDocument) -> Result<()> {
    validate_id(path, &document.recipe.id)?;
    validate_action(path, document)?;
    validate_spec(path, &document.matcher)?;
    for alternative in &document.matcher.any_of {
        if !alternative.any_of.is_empty() {
            return Err(recipe_error(
                path,
                "any_of alternatives must not nest further any_of blocks",
            ));
        }
        validate_spec(path, alternative)?;
    }
    validate_tests(path, document)?;
    validate_protected_test_paths(path, document)?;
    validate_test_fixtures_match(path, document)?;
    Ok(())
}

/// Every match spec — the top-level one and each `[[match.any_of]]`
/// alternative — must independently satisfy the full matcher rules (target
/// selector, context requirements, glob validity).
fn validate_spec(path: &Path, matcher: &MatchSpec) -> Result<()> {
    validate_matcher(path, matcher)?;
    validate_glob(path, matcher.path_glob.as_deref())?;
    for pattern in &matcher.exclude.paths {
        validate_glob(path, Some(pattern))?;
    }
    Ok(())
}

fn validate_id(path: &Path, id: &str) -> Result<()> {
    let valid = !id.is_empty()
        && id
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-');
    if valid {
        Ok(())
    } else {
        Err(recipe_error(
            path,
            format!("invalid recipe id {id:?}; use kebab-case"),
        ))
    }
}

fn validate_matcher(path: &Path, matcher: &MatchSpec) -> Result<()> {
    let has_target_criterion = matcher.directory_name.is_some()
        || matcher.file_name.is_some()
        || matcher
            .file_extension
            .as_ref()
            .is_some_and(|items| !items.is_empty())
        || matcher.path_glob.is_some();

    if !has_target_criterion {
        return Err(recipe_error(
            path,
            "matcher must include a target selector such as directory_name, file_name, file_extension, or path_glob",
        ));
    }

    validate_directory_name(path, matcher.directory_name.as_deref())?;
    validate_file_name(path, matcher)?;
    validate_file_extensions(path, matcher.file_extension.as_deref())?;
    validate_path_glob_safety(path, matcher.path_glob.as_deref())?;
    validate_markers(
        path,
        "parent_must_contain",
        matcher.parent_must_contain.as_deref(),
    )?;
    validate_markers(
        path,
        "parent_must_contain_any",
        matcher.parent_must_contain_any.as_deref(),
    )?;
    validate_markers(
        path,
        "self_must_contain",
        matcher.self_must_contain.as_deref(),
    )?;
    validate_numeric_guards(path, matcher)?;

    if matcher.self_must_contain.is_some()
        && matcher.directory_name.is_none()
        && matcher.path_glob.is_none()
    {
        return Err(recipe_error(
            path,
            "self_must_contain requires directory_name or path_glob (it proves a directory target)",
        ));
    }

    if matcher.directory_name.is_some()
        && matcher.path_glob.is_none()
        && !has_parent_markers(matcher)
        && !has_self_markers(matcher)
    {
        return Err(recipe_error(
            path,
            "directory_name matchers require path_glob, parent_must_contain, parent_must_contain_any, or self_must_contain context",
        ));
    }

    if matcher.file_extension.is_some()
        && matcher.directory_name.is_none()
        && matcher.file_name.is_none()
        && matcher.path_glob.is_none()
        && !has_parent_markers(matcher)
    {
        return Err(recipe_error(
            path,
            "file_extension matchers require path_glob, file_name, directory_name, or parent_must_contain context",
        ));
    }

    Ok(())
}

fn validate_action(path: &Path, document: &RecipeDocument) -> Result<()> {
    if document.action.action_type == ActionType::Delete
        && document.recipe.safety_level != SafetyLevel::Aggressive
    {
        return Err(recipe_error(
            path,
            "delete actions must use safety_level = \"aggressive\"",
        ));
    }

    Ok(())
}

fn validate_directory_name(path: &Path, directory_name: Option<&str>) -> Result<()> {
    let Some(directory_name) = directory_name else {
        return Ok(());
    };

    if !is_plain_segment(directory_name) || contains_glob_meta(directory_name) {
        return Err(recipe_error(
            path,
            format!("directory_name must be a literal path segment: {directory_name:?}"),
        ));
    }

    Ok(())
}

fn validate_file_name(path: &Path, matcher: &MatchSpec) -> Result<()> {
    let Some(file_name) = matcher.file_name.as_deref() else {
        return Ok(());
    };

    if !is_plain_segment(file_name) {
        return Err(recipe_error(
            path,
            format!("file_name must be a single path segment: {file_name:?}"),
        ));
    }

    validate_glob(path, Some(file_name))?;

    if is_broad_pattern(file_name) {
        return Err(recipe_error(
            path,
            format!("broad file_name pattern is not allowed: {file_name:?}"),
        ));
    }

    if contains_glob_meta(file_name) && matcher.path_glob.is_none() && !has_parent_markers(matcher)
    {
        return Err(recipe_error(
            path,
            "wildcard file_name matchers require path_glob or parent_must_contain context",
        ));
    }

    Ok(())
}

fn validate_file_extensions(path: &Path, extensions: Option<&[String]>) -> Result<()> {
    let Some(extensions) = extensions else {
        return Ok(());
    };

    if extensions.is_empty() {
        return Err(recipe_error(path, "file_extension must not be empty"));
    }

    for extension in extensions {
        if extension.len() <= 1
            || !extension.starts_with('.')
            || extension[1..].contains('.')
            || extension.contains('/')
            || extension.contains('\\')
            || contains_glob_meta(extension)
            || extension.chars().any(char::is_whitespace)
        {
            return Err(recipe_error(
                path,
                format!("invalid file_extension: {extension:?}"),
            ));
        }
    }

    Ok(())
}

fn has_parent_markers(matcher: &MatchSpec) -> bool {
    matcher
        .parent_must_contain
        .as_ref()
        .is_some_and(|items| !items.is_empty())
        || matcher
            .parent_must_contain_any
            .as_ref()
            .is_some_and(|items| !items.is_empty())
}

fn has_self_markers(matcher: &MatchSpec) -> bool {
    matcher
        .self_must_contain
        .as_ref()
        .is_some_and(|items| !items.is_empty())
}

fn validate_path_glob_safety(path: &Path, path_glob: Option<&str>) -> Result<()> {
    let Some(path_glob) = path_glob else {
        return Ok(());
    };

    if path_glob.trim() != path_glob || path_glob.is_empty() {
        return Err(recipe_error(
            path,
            format!("invalid path_glob: {path_glob:?}"),
        ));
    }

    if Path::new(path_glob).is_absolute() {
        return Err(recipe_error(
            path,
            format!("absolute path_glob is not allowed: {path_glob:?}"),
        ));
    }

    if is_broad_pattern(path_glob) {
        return Err(recipe_error(
            path,
            format!("broad path_glob pattern is not allowed: {path_glob:?}"),
        ));
    }

    Ok(())
}

fn validate_markers(path: &Path, field: &str, markers: Option<&[String]>) -> Result<()> {
    let Some(markers) = markers else {
        return Ok(());
    };

    if markers.is_empty() {
        return Err(recipe_error(path, format!("{field} must not be empty")));
    }

    for marker in markers {
        if marker.trim() != marker
            || marker.is_empty()
            || Path::new(marker).is_absolute()
            || marker.contains('\\')
            || contains_glob_meta(marker)
            || !is_safe_relative_path(marker)
        {
            return Err(recipe_error(
                path,
                format!("invalid {field} marker: {marker:?}"),
            ));
        }
    }

    Ok(())
}

fn validate_numeric_guards(path: &Path, matcher: &MatchSpec) -> Result<()> {
    if matcher.min_size_mb == Some(0) {
        return Err(recipe_error(path, "min_size_mb must be greater than zero"));
    }

    if matcher.min_age_days == Some(0) {
        return Err(recipe_error(path, "min_age_days must be greater than zero"));
    }

    Ok(())
}

fn validate_glob(path: &Path, pattern: Option<&str>) -> Result<()> {
    if let Some(pattern) = pattern {
        Pattern::new(pattern)
            .map(|_| ())
            .map_err(|err| recipe_error(path, format!("invalid glob {pattern:?}: {err}")))?;
    }
    Ok(())
}

fn validate_tests(path: &Path, document: &RecipeDocument) -> Result<()> {
    if document.test.should_match.is_empty() || document.test.should_not_match.is_empty() {
        return Err(recipe_error(
            path,
            "recipe tests must include should_match and should_not_match fixtures",
        ));
    }
    Ok(())
}

fn validate_test_fixtures_match(path: &Path, document: &RecipeDocument) -> Result<()> {
    // `should_match` fixtures are evaluated optimistically: assume the parent
    // context markers are present (we cannot materialize them on disk here), so
    // a positive fixture proves the selector/size/age/exclude logic accepts it.
    for candidate in &document.test.should_match {
        let entry = synthetic_entry(document, candidate);
        if !recipe_matches_entry_with_parent_lookup(document, &entry, |_, _| true) {
            return Err(recipe_error(
                path,
                format!("should_match fixture did not match recipe: {candidate}"),
            ));
        }
    }

    // `should_not_match` fixtures are evaluated pessimistically: assume the
    // parent context markers are ABSENT. This lets a recipe assert a genuine
    // context-guard negative (e.g. a `target` dir whose parent has no
    // `Cargo.toml`) and proves a bare name/glob hit alone is never enough.
    for candidate in &document.test.should_not_match {
        let entry = synthetic_entry(document, candidate);
        if recipe_matches_entry_with_parent_lookup(document, &entry, |_, _| false) {
            return Err(recipe_error(
                path,
                format!("should_not_match fixture matched recipe: {candidate}"),
            ));
        }
    }

    Ok(())
}

fn validate_protected_test_paths(path: &Path, document: &RecipeDocument) -> Result<()> {
    let protected = ProtectedPaths::defaults();
    for candidate in document
        .test
        .should_match
        .iter()
        .chain(document.test.should_not_match.iter())
    {
        if protected.is_protected(Path::new(candidate)) {
            return Err(recipe_error(
                path,
                format!("recipe fixture references protected path: {candidate}"),
            ));
        }
    }
    Ok(())
}

fn recipe_error(path: &Path, message: impl Into<String>) -> CleantonError {
    CleantonError::Recipe {
        path: path.to_path_buf(),
        message: message.into(),
    }
}

fn synthetic_entry(document: &RecipeDocument, fixture: &str) -> FileEntry {
    let path = expand_tilde(&PathBuf::from(fixture));
    let specs = || std::iter::once(&document.matcher).chain(document.matcher.any_of.iter());

    // A fixture is synthesized as a directory when any spec targets directories
    // and selects this path: a literal `directory_name` matching the basename,
    // or a `self_must_contain` proof whose `path_glob` covers the fixture.
    let kind = if specs().any(|spec| spec_wants_directory(spec, &path)) {
        FileKind::Directory
    } else {
        FileKind::File
    };

    // Size/age floors: take the maximum across all specs so a fixture clears
    // every spec's gate. Larger/older can only ever match MORE specs, so this
    // stays the strict direction for should_not_match fixtures too.
    let min_bytes = specs()
        .map(|spec| spec.min_size_mb.unwrap_or(1))
        .max()
        .unwrap_or(1)
        .saturating_add(1)
        .saturating_mul(1_048_576);
    let min_age_days = specs()
        .map(|spec| spec.min_age_days.unwrap_or(30))
        .max()
        .unwrap_or(30)
        .saturating_add(1);

    FileEntry {
        depth: path.components().count(),
        path,
        kind,
        logical_bytes: min_bytes,
        allocated_bytes: min_bytes,
        modified: Some(
            SystemTime::now()
                .checked_sub(Duration::from_secs(
                    min_age_days.saturating_mul(24 * 60 * 60),
                ))
                .unwrap_or(SystemTime::UNIX_EPOCH),
        ),
        device_id: None,
        inode: None,
        hardlink_count: None,
        symlink_target: None,
        ignored_by_git: false,
    }
}

/// Whether `spec` selects `path` as a *directory* target for fixture synthesis:
/// either its literal `directory_name` equals the fixture's basename, or the
/// spec proves a directory via `self_must_contain` and its `path_glob` covers
/// the fixture path.
fn spec_wants_directory(spec: &MatchSpec, path: &Path) -> bool {
    if let Some(directory_name) = &spec.directory_name {
        return path
            .file_name()
            .is_some_and(|candidate| candidate == directory_name.as_str());
    }
    if spec.self_must_contain.is_none() {
        return false;
    }
    let Some(path_glob) = &spec.path_glob else {
        return false;
    };
    let expanded = if path_glob.starts_with('~') {
        expand_tilde(&PathBuf::from(path_glob))
            .to_string_lossy()
            .into_owned()
    } else {
        path_glob.clone()
    };
    Pattern::new(&expanded).is_ok_and(|pattern| pattern.matches_path(path))
}

fn is_plain_segment(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && !value.contains('/')
        && !value.contains('\\')
        && value != "."
        && value != ".."
}

fn is_safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_) | Component::CurDir
        )
    })
}

fn contains_glob_meta(value: &str) -> bool {
    value
        .chars()
        .any(|ch| matches!(ch, '*' | '?' | '[' | ']' | '{' | '}'))
}

fn is_broad_pattern(pattern: &str) -> bool {
    let normalized = pattern
        .trim_start_matches("./")
        .trim_matches('/')
        .replace('\\', "/");

    normalized.is_empty()
        || matches!(normalized.as_str(), "*" | "**" | "**/*" | "**/**" | "*/*")
        || !has_literal_signal(&normalized)
}

fn has_literal_signal(pattern: &str) -> bool {
    pattern.chars().any(|ch| {
        !matches!(
            ch,
            '*' | '?' | '[' | ']' | '{' | '}' | ',' | '!' | '/' | '\\' | '.'
        )
    })
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use cleanton_common::{ActionType, SafetyLevel};

    use crate::{ActionSpec, MatchSpec, Recipe, RecipeDocument, RecipeSet, RecipeTest};

    use super::*;

    #[test]
    fn builtin_recipe_self_tests_are_valid() {
        let recipes = RecipeSet::load_builtin().expect("built-in recipes should validate");

        assert_eq!(recipes.len(), 130);
    }

    #[test]
    fn rejects_context_only_matcher() {
        let recipe = test_recipe(MatchSpec {
            parent_must_contain: Some(vec!["Cargo.toml".to_owned()]),
            ..MatchSpec::default()
        });

        assert_recipe_error_contains(&recipe, "target selector");
    }

    #[test]
    fn rejects_directory_name_without_context() {
        let recipe = test_recipe(MatchSpec {
            directory_name: Some("target".to_owned()),
            ..MatchSpec::default()
        });

        assert_recipe_error_contains(&recipe, "directory_name matchers require");
    }

    #[test]
    fn rejects_broad_path_globs() {
        for pattern in ["*", "**", "**/*", "**/**", "*/**"] {
            let recipe = test_recipe(MatchSpec {
                path_glob: Some(pattern.to_owned()),
                ..MatchSpec::default()
            });

            assert_recipe_error_contains(&recipe, "broad path_glob");
        }
    }

    #[test]
    fn rejects_absolute_path_globs() {
        let recipe = test_recipe(MatchSpec {
            path_glob: Some("/Users/*/Downloads/**".to_owned()),
            ..MatchSpec::default()
        });

        assert_recipe_error_contains(&recipe, "absolute path_glob");
    }

    #[test]
    fn rejects_broad_file_names() {
        for pattern in ["*", ".*", "*.*"] {
            let recipe = test_recipe(MatchSpec {
                file_name: Some(pattern.to_owned()),
                parent_must_contain: Some(vec!["package.json".to_owned()]),
                ..MatchSpec::default()
            });

            assert_recipe_error_contains(&recipe, "broad file_name");
        }
    }

    #[test]
    fn rejects_wildcard_file_name_without_context() {
        let recipe = test_recipe(MatchSpec {
            file_name: Some("*.log".to_owned()),
            ..MatchSpec::default()
        });

        assert_recipe_error_contains(&recipe, "wildcard file_name");
    }

    #[test]
    fn rejects_invalid_file_name_glob() {
        let recipe = test_recipe(MatchSpec {
            file_name: Some("[".to_owned()),
            parent_must_contain: Some(vec!["package.json".to_owned()]),
            ..MatchSpec::default()
        });

        assert_recipe_error_contains(&recipe, "invalid glob");
    }

    #[test]
    fn rejects_extension_only_matcher() {
        let recipe = test_recipe(MatchSpec {
            file_extension: Some(vec![".log".to_owned()]),
            ..MatchSpec::default()
        });

        assert_recipe_error_contains(&recipe, "file_extension matchers require");
    }

    #[test]
    fn rejects_invalid_extension() {
        let recipe = test_recipe(MatchSpec {
            file_extension: Some(vec!["*".to_owned()]),
            path_glob: Some("**/cache/**".to_owned()),
            ..MatchSpec::default()
        });

        assert_recipe_error_contains(&recipe, "invalid file_extension");
    }

    #[test]
    fn rejects_invalid_parent_marker() {
        let recipe = test_recipe(MatchSpec {
            directory_name: Some("target".to_owned()),
            parent_must_contain: Some(vec!["../Cargo.toml".to_owned()]),
            ..MatchSpec::default()
        });

        assert_recipe_error_contains(&recipe, "invalid parent_must_contain");
    }

    #[test]
    fn rejects_invalid_any_of_parent_marker() {
        let recipe = test_recipe(MatchSpec {
            directory_name: Some("build".to_owned()),
            parent_must_contain_any: Some(vec!["/abs/build.gradle".to_owned()]),
            ..MatchSpec::default()
        });

        assert_recipe_error_contains(&recipe, "invalid parent_must_contain_any");
    }

    #[test]
    fn any_of_parent_markers_count_as_directory_context() {
        let recipe = test_recipe(MatchSpec {
            directory_name: Some("build".to_owned()),
            parent_must_contain_any: Some(vec![
                "build.gradle".to_owned(),
                "build.gradle.kts".to_owned(),
            ]),
            ..MatchSpec::default()
        })
        .with_tests(["projects/app/build"], ["loose/build"]);

        validate_recipe(Path::new("test.toml"), &recipe).expect("any-of context is valid");
    }

    #[test]
    fn rejects_self_must_contain_without_directory_target() {
        // Neither directory_name nor path_glob: nothing proves a directory.
        let recipe = test_recipe(MatchSpec {
            file_name: Some("cache.bin".to_owned()),
            parent_must_contain: Some(vec!["package.json".to_owned()]),
            self_must_contain: Some(vec!["CMakeCache.txt".to_owned()]),
            ..MatchSpec::default()
        });

        assert_recipe_error_contains(&recipe, "self_must_contain requires directory_name");
    }

    #[test]
    fn self_must_contain_with_path_glob_is_valid() {
        // A glob-selected directory proven by an internal marker (e.g. a
        // `checkpoint-*` dir containing `trainer_state.json`) is a valid spec;
        // the matcher enforces the directory kind at match time.
        let recipe = test_recipe(MatchSpec {
            path_glob: Some("**/checkpoint-*".to_owned()),
            self_must_contain: Some(vec!["trainer_state.json".to_owned()]),
            ..MatchSpec::default()
        })
        .with_tests(
            ["projects/ml/out/checkpoint-500"],
            ["loose/checkpoint-500", "projects/ml/train.py"],
        );

        validate_recipe(Path::new("test.toml"), &recipe).expect("glob directory proof is valid");
    }

    #[test]
    fn rejects_nested_any_of_alternatives() {
        let recipe = test_recipe(MatchSpec {
            path_glob: Some("**/cache/**".to_owned()),
            any_of: vec![MatchSpec {
                path_glob: Some("**/tmp-cache/**".to_owned()),
                any_of: vec![MatchSpec {
                    path_glob: Some("**/deep-cache/**".to_owned()),
                    ..MatchSpec::default()
                }],
                ..MatchSpec::default()
            }],
            ..MatchSpec::default()
        });

        assert_recipe_error_contains(&recipe, "must not nest");
    }

    #[test]
    fn any_of_alternatives_are_validated_like_the_primary_spec() {
        // An alternative with no target selector is rejected outright.
        let recipe = test_recipe(MatchSpec {
            path_glob: Some("**/cache/**".to_owned()),
            any_of: vec![MatchSpec {
                min_size_mb: Some(10),
                ..MatchSpec::default()
            }],
            ..MatchSpec::default()
        });

        assert_recipe_error_contains(&recipe, "target selector");
    }

    #[test]
    fn fixtures_may_match_via_an_any_of_alternative() {
        let recipe = test_recipe(MatchSpec {
            path_glob: Some("**/*.ckpt".to_owned()),
            any_of: vec![MatchSpec {
                path_glob: Some("**/checkpoint-*".to_owned()),
                self_must_contain: Some(vec!["trainer_state.json".to_owned()]),
                ..MatchSpec::default()
            }],
            ..MatchSpec::default()
        })
        .with_tests(
            ["projects/ml/last.ckpt", "projects/ml/out/checkpoint-500"],
            ["projects/ml/train.py", "loose/checkpoint-500"],
        );

        validate_recipe(Path::new("test.toml"), &recipe).expect("alternative fixtures are valid");
    }

    #[test]
    fn self_markers_count_as_directory_context() {
        let recipe = test_recipe(MatchSpec {
            directory_name: Some("build".to_owned()),
            self_must_contain: Some(vec!["CMakeCache.txt".to_owned()]),
            ..MatchSpec::default()
        })
        .with_tests(["projects/native/build"], ["loose/build"]);

        validate_recipe(Path::new("test.toml"), &recipe).expect("self-marker context is valid");
    }

    #[test]
    fn rejects_safe_delete_action() {
        let mut recipe = test_recipe(MatchSpec {
            path_glob: Some("**/cache/**".to_owned()),
            ..MatchSpec::default()
        });
        recipe.action.action_type = ActionType::Delete;

        assert_recipe_error_contains(&recipe, "delete actions");
    }

    #[test]
    fn allows_aggressive_delete_action() {
        let mut recipe = test_recipe(MatchSpec {
            path_glob: Some("**/cache/**".to_owned()),
            ..MatchSpec::default()
        });
        recipe.recipe.safety_level = SafetyLevel::Aggressive;
        recipe.action.action_type = ActionType::Delete;

        validate_recipe(Path::new("test.toml"), &recipe).expect("aggressive delete is valid");
    }

    #[test]
    fn rejects_mismatched_should_match_fixture() {
        let recipe = test_recipe(MatchSpec {
            file_name: Some(".DS_Store".to_owned()),
            ..MatchSpec::default()
        })
        .with_tests(["project/keep.txt"], ["project/app.log"]);

        assert_recipe_error_contains(&recipe, "should_match fixture did not match");
    }

    #[test]
    fn rejects_mismatched_should_not_match_fixture() {
        let recipe = test_recipe(MatchSpec {
            file_name: Some(".DS_Store".to_owned()),
            ..MatchSpec::default()
        })
        .with_tests(["project/.DS_Store"], ["other/.DS_Store"]);

        assert_recipe_error_contains(&recipe, "should_not_match fixture matched");
    }

    #[test]
    fn accepts_context_guard_negative_fixture() {
        // A `target` dir whose parent lacks `Cargo.toml` must be a valid
        // should_not_match fixture: the matcher rejects it because the context
        // guard fails, even though the directory name matches.
        let recipe = test_recipe(MatchSpec {
            directory_name: Some("target".to_owned()),
            parent_must_contain: Some(vec!["Cargo.toml".to_owned()]),
            ..MatchSpec::default()
        })
        .with_tests(["project/target"], ["loose/target"]);

        validate_recipe(Path::new("test.toml"), &recipe).expect("context-guard negative is valid");
    }

    #[test]
    fn rejects_sensitive_basename_should_match_fixture() {
        // A recipe can never legitimately match a credentials file, so listing
        // one as should_match must fail because the matcher's hard floor rejects
        // it regardless of the selector.
        let recipe = test_recipe(MatchSpec {
            path_glob: Some("~/.tool/cache/**".to_owned()),
            ..MatchSpec::default()
        })
        .with_tests(["~/.tool/cache/.credentials.json"], ["~/.tool/config"]);

        assert_recipe_error_contains(&recipe, "should_match fixture did not match");
    }

    fn assert_recipe_error_contains(recipe: &RecipeDocument, expected: &str) {
        let err = validate_recipe(Path::new("test.toml"), recipe).expect_err("invalid recipe");
        assert!(
            err.to_string().contains(expected),
            "expected {err:?} to contain {expected:?}",
        );
    }

    fn test_recipe(matcher: MatchSpec) -> RecipeDocument {
        RecipeDocument {
            recipe: Recipe {
                id: "test-recipe".to_owned(),
                name: "Test Recipe".to_owned(),
                description: "test".to_owned(),
                category: "test".to_owned(),
                icon: None,
                safety_level: SafetyLevel::Safe,
                enabled: true,
                priority: 50,
            },
            matcher,
            action: ActionSpec {
                action_type: ActionType::Trash,
                prompt: "Trash?".to_owned(),
            },
            test: RecipeTest {
                should_match: vec!["project/cache/item".to_owned()],
                should_not_match: vec!["project/src/item".to_owned()],
            },
        }
    }

    trait TestRecipeExt {
        fn with_tests(
            self,
            should_match: impl IntoIterator<Item = &'static str>,
            should_not_match: impl IntoIterator<Item = &'static str>,
        ) -> Self;
    }

    impl TestRecipeExt for RecipeDocument {
        fn with_tests(
            mut self,
            should_match: impl IntoIterator<Item = &'static str>,
            should_not_match: impl IntoIterator<Item = &'static str>,
        ) -> Self {
            self.test = RecipeTest {
                should_match: should_match.into_iter().map(str::to_owned).collect(),
                should_not_match: should_not_match.into_iter().map(str::to_owned).collect(),
            };
            self
        }
    }
}
