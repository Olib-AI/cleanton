use std::path::Path;

use cleanton_common::{ActionType, CleantonError, Result, SafetyLevel};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecipeDocument {
    pub recipe: Recipe,
    #[serde(rename = "match")]
    pub matcher: MatchSpec,
    pub action: ActionSpec,
    pub test: RecipeTest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Recipe {
    pub id: String,
    pub name: String,
    pub description: String,
    pub category: String,
    pub icon: Option<String>,
    pub safety_level: SafetyLevel,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
    #[serde(default = "default_priority")]
    pub priority: u8,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchSpec {
    pub directory_name: Option<String>,
    pub file_name: Option<String>,
    pub file_extension: Option<Vec<String>>,
    pub path_glob: Option<String>,
    pub parent_must_contain: Option<Vec<String>>,
    /// Any-of variant of `parent_must_contain`: at least one marker must exist
    /// in the parent directory. Lets one recipe cover ecosystems with several
    /// equivalent project manifests (e.g. `build.gradle` / `build.gradle.kts`).
    pub parent_must_contain_any: Option<Vec<String>>,
    /// Markers that must exist *inside* the matched directory itself (all of
    /// them). Proves a generically named directory really is the tool's output
    /// (e.g. a `build` dir containing `CMakeCache.txt`). Directory targets only.
    pub self_must_contain: Option<Vec<String>>,
    pub min_size_mb: Option<u64>,
    pub min_age_days: Option<u64>,
    #[serde(default)]
    pub exclude: MatchExclude,
    /// Alternative match specs (`[[match.any_of]]` in TOML): the entry matches
    /// the recipe when the top-level spec *or* any alternative matches. Lets one
    /// recipe cover several on-disk shapes of the same artifact (e.g. `.ckpt`
    /// files and `checkpoint-*` directories). Every alternative is validated
    /// under the same rules as the top-level spec, alternatives must not nest,
    /// and the matcher's safety floors apply to the recipe as a whole.
    #[serde(default)]
    pub any_of: Vec<MatchSpec>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MatchExclude {
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub names: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionSpec {
    #[serde(rename = "type")]
    pub action_type: ActionType,
    pub prompt: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeTest {
    #[serde(default)]
    pub should_match: Vec<String>,
    #[serde(default)]
    pub should_not_match: Vec<String>,
}

pub fn parse_recipe_str(path: &Path, source: &str) -> Result<RecipeDocument> {
    toml::from_str(source).map_err(|err| CleantonError::Recipe {
        path: path.to_path_buf(),
        message: err.to_string(),
    })
}

fn default_enabled() -> bool {
    true
}

fn default_priority() -> u8 {
    50
}
