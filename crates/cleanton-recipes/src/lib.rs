mod builtin;
mod matcher;
mod parser;
mod registry;
mod validator;

pub use matcher::{
    DirectoryGate, action_for_entry, action_for_entry_with_subtree_mtime, directory_gate,
    recipe_has_gates, recipe_matches_entry,
};
pub use parser::{
    ActionSpec, MatchExclude, MatchSpec, Recipe, RecipeDocument, RecipeTest, parse_recipe_str,
};
pub use registry::RecipeSet;
pub use validator::validate_recipe;
