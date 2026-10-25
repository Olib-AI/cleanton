//! # rb-antivirus
//!
//! A general-purpose, multi-engine static malware and supply-chain scanner.
//!
//! It loads a target (a file, a directory tree, or an archive such as an npm
//! `.tgz` tarball) into an in-memory [`engine::FileUnit`] set, runs every
//! [`engine::DetectionEngine`] over it, and aggregates the [`types::Finding`]s
//! into a scored [`types::ScanReport`] / [`types::Verdict`].
//!
//! It is deliberately not tied to any one ecosystem: the same engines vet
//! native binaries, scripts in several languages, and archives. The npm
//! supply-chain analysis (malicious install scripts, dependency confusion,
//! typosquatting) is one engine family among many — it is simply the first
//! consumer, because MCP servers are distributed as npm packages.
//!
//! ## Architecture
//!
//! - [`types`] — findings, severity/confidence/category, the scan report.
//! - [`engine`] — the [`engine::DetectionEngine`] trait + the [`engine::FileUnit`]
//!   / [`engine::ScanContext`] inputs.
//! - [`config`] — scan limits and scoring thresholds.
//! - [`extract`] — the loader: directory walk + archive extraction + file-kind
//!   identification + zip-bomb / size / depth limits.
//! - [`engines`] — the detection engines (hashdb, rules, entropy, ioc,
//!   script_behavior, binary_indicators, supply_chain, typosquat, and the
//!   worm_propagation / persistence pair that look for live infection).
//! - [`scoring`] — the policy that turns findings into a score and verdict.
//! - [`scanner`] — the [`Scanner`] facade tying it all together.
//!
//! Engines depend ONLY on [`types`], [`engine`], and [`config`] — never on each
//! other — so they compose and test independently.

#![forbid(unsafe_code)]

pub mod config;
pub mod engine;
pub mod engines;
pub mod error;
pub mod extract;
pub mod scanner;
pub mod scoring;
pub mod types;

pub use config::ScanConfig;
pub use engine::{DetectionEngine, FileKind, FileUnit, ScanContext};
pub use error::{AvError, AvResult};
pub use scanner::Scanner;
pub use types::{
    Confidence, EngineStat, FileLocation, Finding, ScanReport, Severity, ThreatCategory, Verdict,
};
