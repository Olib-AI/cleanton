//! Detection engine implementations.
//!
//! Each sub-module defines one [`crate::engine::DetectionEngine`] struct.
//! `default_engines()` wires the full default set into the scanner pipeline.

pub mod binary_indicators;
pub mod entropy;
pub mod hashdb;
pub mod ioc;
pub mod mcp_descriptor;
pub mod rules;
pub mod script_behavior;
pub mod supply_chain;
pub mod typosquat;
pub mod worm_propagation;

pub use binary_indicators::BinaryIndicatorEngine;
pub use entropy::EntropyEngine;
pub use hashdb::HashSignatureEngine;
pub use ioc::IocEngine;
pub use mcp_descriptor::McpDescriptorEngine;
pub use rules::RuleEngine;
pub use script_behavior::ScriptBehaviorEngine;
pub use supply_chain::SupplyChainEngine;
pub use typosquat::TyposquatEngine;
pub use worm_propagation::WormPropagationEngine;

/// Build the default set of detection engines, one per engine family.
///
/// All engines implement [`Default`]; this constructs them in the canonical
/// evaluation order (signature first, heuristics last).
pub fn default_engines() -> Vec<Box<dyn crate::engine::DetectionEngine>> {
    vec![
        Box::new(HashSignatureEngine::default()),
        Box::new(RuleEngine),
        Box::new(McpDescriptorEngine),
        Box::new(WormPropagationEngine),
        Box::new(EntropyEngine),
        Box::new(IocEngine),
        Box::new(ScriptBehaviorEngine),
        Box::new(BinaryIndicatorEngine),
        Box::new(SupplyChainEngine),
        Box::new(TyposquatEngine),
    ]
}
