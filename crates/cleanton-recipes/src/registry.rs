use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use cleanton_common::Result;

use crate::{RecipeDocument, builtin, parse_recipe_str, validate_recipe};

#[derive(Debug, Clone, Default, PartialEq)]
pub struct RecipeSet {
    recipes: BTreeMap<String, RecipeDocument>,
}

impl RecipeSet {
    pub fn load_builtin() -> Result<Self> {
        let mut set = Self::default();
        for (path, source) in builtin::BUILTIN_RECIPES {
            let path = Path::new(path);
            let recipe = parse_recipe_str(path, source)?;
            validate_recipe(path, &recipe)?;
            set.recipes.insert(recipe.recipe.id.clone(), recipe);
        }
        Ok(set)
    }

    pub fn load_all() -> Result<Self> {
        let mut set = Self::load_builtin()?;
        let user_dir =
            cleanton_common::paths::expand_tilde(&PathBuf::from("~/.config/cleanton/recipes"));
        set.load_from_dir(&user_dir)?;
        Ok(set)
    }

    pub fn load_from_dir(&mut self, dir: &Path) -> Result<()> {
        if dir.is_dir()
            && let Ok(entries) = std::fs::read_dir(dir)
        {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().is_some_and(|ext| ext == "toml")
                    && let Ok(source) = std::fs::read_to_string(&path)
                {
                    let recipe = parse_recipe_str(&path, &source)?;
                    validate_recipe(&path, &recipe)?;
                    self.recipes.insert(recipe.recipe.id.clone(), recipe);
                }
            }
        }
        Ok(())
    }

    pub fn iter(&self) -> impl Iterator<Item = &RecipeDocument> {
        self.recipes.values()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.recipes.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.recipes.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_load_from_dir_merges_and_overrides() {
        let mut set = RecipeSet::load_builtin().expect("load builtin");
        let original_len = set.len();

        let temp = tempfile::tempdir().expect("tempdir");
        let user_recipes_dir = temp.path().join("recipes");
        fs::create_dir(&user_recipes_dir).expect("create dir");

        // 1. Create a brand new user recipe
        let new_recipe_toml = user_recipes_dir.join("custom.toml");
        fs::write(
            &new_recipe_toml,
            r#"
[recipe]
id = "custom-recipe"
name = "Custom Recipe"
description = "A custom recipe"
category = "custom"
safety_level = "safe"
enabled = true
priority = 10

[match]
directory_name = "custom_cache"
parent_must_contain = ["custom.marker"]

[action]
type = "trash"
prompt = "Trash custom cache?"

[test]
should_match = ["projects/my-app/custom_cache"]
should_not_match = ["projects/my-app/src"]
"#,
        )
        .expect("write custom.toml");

        // 2. Create an overriding recipe for "rust-target-dirs" (a built-in recipe)
        let override_recipe_toml = user_recipes_dir.join("rust-target.toml");
        fs::write(
            &override_recipe_toml,
            r#"
[recipe]
id = "rust-target-dirs"
name = "Overridden Rust Build Artifacts"
description = "Overridden description"
category = "rust"
safety_level = "safe"
enabled = true
priority = 90

[match]
directory_name = "target"
parent_must_contain = ["Cargo.toml"]

[action]
type = "trash"
prompt = "Trash target?"

[test]
should_match = ["projects/my-app/target"]
should_not_match = ["projects/my-app/src"]
"#,
        )
        .expect("write rust-target.toml");

        set.load_from_dir(&user_recipes_dir).expect("load from dir");

        // Length should increase by 1 (since rust-target-dirs is overridden, not duplicated)
        assert_eq!(set.len(), original_len + 1);

        // Check that new recipe was loaded
        assert!(set.recipes.contains_key("custom-recipe"));

        // Check that rust-target-dirs was overridden
        let rust_recipe = set.recipes.get("rust-target-dirs").unwrap();
        assert_eq!(rust_recipe.recipe.name, "Overridden Rust Build Artifacts");
        assert_eq!(rust_recipe.recipe.description, "Overridden description");
    }
}
