mod builtin;
mod matcher;
mod parser;
mod registry;
mod validator;

pub use matcher::{action_for_entry, action_for_entry_with_subtree_mtime, recipe_matches_entry};
pub use parser::{
    ActionSpec, MatchExclude, MatchSpec, Recipe, RecipeDocument, RecipeTest, parse_recipe_str,
};
pub use registry::RecipeSet;
pub use validator::validate_recipe;
