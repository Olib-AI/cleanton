//! High-level scanner facade.
//!
//! [`Scanner`] ties together the loader ([`crate::extract::Loader`]),
//! the detection engines ([`crate::engine::DetectionEngine`]), and the
//! scoring policy ([`crate::scoring::ScoringPolicy`]) into a single entry
//! point that callers use for filesystem paths, raw bytes, or npm tarballs.

use std::path::Path;
use std::time::Instant;

use crate::config::ScanConfig;
use crate::engine::{DetectionEngine, ScanContext};
use crate::error::AvResult;
use crate::extract::Loader;
use crate::scoring::ScoringPolicy;
use crate::types::{EngineStat, ScanReport};

/// A configured scanner instance.
///
/// Construct with [`Scanner::new`] (no engines) or
/// [`Scanner::with_default_engines`] (all bundled engines).
/// Additional engines can be pushed via [`Scanner::add_engine`].
pub struct Scanner {
    engines: Vec<Box<dyn DetectionEngine>>,
    config: ScanConfig,
}

impl std::fmt::Debug for Scanner {
    // `DetectionEngine` is a trait object (no `Debug`), so summarise the engine
    // set by name — enough for a holder that derives `Debug` to be useful.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Scanner")
            .field("engines", &self.engine_names())
            .field("config", &self.config)
            .finish()
    }
}

impl Scanner {
    /// Create a scanner with no engines and the given config.
    pub fn new(config: ScanConfig) -> Self {
        Self {
            engines: Vec::new(),
            config,
        }
    }

    /// Create a scanner pre-loaded with the default engine set and the given config.
    pub fn with_default_engines(config: ScanConfig) -> Self {
        Self {
            engines: crate::engines::default_engines(),
            config,
        }
    }

    /// Append an engine to the evaluation pipeline.
    pub fn add_engine(&mut self, engine: Box<dyn DetectionEngine>) {
        self.engines.push(engine);
    }

    /// Return the names of all registered detection engines.
    pub fn engine_names(&self) -> Vec<String> {
        self.engines.iter().map(|e| e.name().to_owned()).collect()
    }

    // ── Core scan entry points ────────────────────────────────────────────────

    /// Scan a filesystem path (file, directory, or archive).
    pub fn scan_path(&self, path: &Path) -> AvResult<ScanReport> {
        let target_name = path.display().to_string();
        let wall = Instant::now();

        let loaded = Loader::load(path, &self.config)?;
        self.run_engines(target_name, loaded, wall)
    }

    /// Scan raw bytes under the given display name.
    pub fn scan_bytes(&self, name: &str, bytes: &[u8]) -> AvResult<ScanReport> {
        let wall = Instant::now();
        let loaded = Loader::load_bytes(name, bytes, &self.config)?;
        self.run_engines(name.to_owned(), loaded, wall)
    }

    /// Scan an npm `.tgz` package at the given path.
    ///
    /// This is an alias for [`scan_path`] — the loader already handles
    /// gzip/tar extraction and `package.json` parsing automatically.
    pub fn scan_npm_package(&self, path: &Path) -> AvResult<ScanReport> {
        self.scan_path(path)
    }

    /// Scan an MCP server's advertised tool list before registration.
    ///
    /// `server_name` is used as the display name in the report (e.g.
    /// `"my-mcp-server"`). `tools_schema_json` is the raw JSON bytes of the
    /// tool-list response as returned by the MCP server (the `tools/list`
    /// response body, or any serialisation of the server's tool descriptors).
    ///
    /// The schema is wrapped as a synthetic [`crate::engine::FileUnit`] with a
    /// path of `"<server_name>/mcp-tools.json"` and
    /// [`crate::engine::FileKind::Json`], then run through all engines. The
    /// [`crate::engines::McpDescriptorEngine`] fires on description-poisoning
    /// and injection patterns; other engines inspect the JSON for additional
    /// supply-chain signals.
    ///
    /// Returns a [`crate::types::ScanReport`] whose
    /// [`crate::types::Verdict`] the MCP gate should consult before allowing
    /// the server's tools to be registered.
    pub fn scan_mcp_tools(
        &self,
        server_name: &str,
        tools_schema_json: &[u8],
    ) -> AvResult<ScanReport> {
        let wall = std::time::Instant::now();
        let synthetic_name = format!("{server_name}/mcp-tools.json");
        let loaded = Loader::load_bytes(&synthetic_name, tools_schema_json, &self.config)?;
        self.run_engines(synthetic_name, loaded, wall)
    }

    // ── Internal ──────────────────────────────────────────────────────────────

    fn run_engines(
        &self,
        target_name: String,
        loaded: crate::extract::LoadedTarget,
        wall: Instant,
    ) -> AvResult<ScanReport> {
        let pkg_ref = loaded.package_json.as_ref();
        let target_ref = target_name.as_str();

        // For large standalone targets (archives, monorepos), run engines in
        // parallel on a bounded worker pool while preserving canonical engine
        // ordering. Small per-package scans stay inline to avoid thread-spawn
        // overhead when callers already parallelize across packages.
        let results: Vec<(EngineStat, Vec<crate::types::Finding>)> =
            if loaded.files.len() >= 64 && self.engines.len() >= 2 {
                let next = std::sync::atomic::AtomicUsize::new(0);
                let workers = std::thread::available_parallelism()
                    .map_or(2, std::num::NonZeroUsize::get)
                    .clamp(1, 4)
                    .min(self.engines.len());
                let slots: std::sync::Mutex<
                    Vec<Option<(EngineStat, Vec<crate::types::Finding>)>>,
                > = std::sync::Mutex::new((0..self.engines.len()).map(|_| None).collect());

                std::thread::scope(|scope| {
                    for _ in 0..workers {
                        scope.spawn(|| {
                            loop {
                                let idx =
                                    next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                let Some(engine) = self.engines.get(idx) else {
                                    break;
                                };
                                let ctx = ScanContext {
                                    target_name: target_ref.to_owned(),
                                    files: &loaded.files,
                                    package_json: pkg_ref,
                                    config: &self.config,
                                };
                                let t0 = Instant::now();
                                let findings = engine.scan(&ctx);
                                let stat = EngineStat {
                                    engine: engine.name().to_owned(),
                                    findings: findings.len(),
                                    duration_ms: t0.elapsed().as_millis() as u64,
                                };
                                let mut guard = match slots.lock() {
                                    Ok(g) => g,
                                    Err(p) => p.into_inner(),
                                };
                                if let Some(slot) = guard.get_mut(idx) {
                                    *slot = Some((stat, findings));
                                }
                            }
                        });
                    }
                });

                let completed = match slots.into_inner() {
                    Ok(v) => v,
                    Err(p) => p.into_inner(),
                };
                completed.into_iter().flatten().collect()
            } else {
                self.engines
                    .iter()
                    .map(|engine| {
                        let ctx = ScanContext {
                            target_name: target_ref.to_owned(),
                            files: &loaded.files,
                            package_json: pkg_ref,
                            config: &self.config,
                        };
                        let t0 = Instant::now();
                        let findings = engine.scan(&ctx);
                        let stat = EngineStat {
                            engine: engine.name().to_owned(),
                            findings: findings.len(),
                            duration_ms: t0.elapsed().as_millis() as u64,
                        };
                        (stat, findings)
                    })
                    .collect()
            };

        let mut all_findings = Vec::new();
        let mut engine_stats = Vec::with_capacity(results.len());
        for (stat, findings) in results {
            engine_stats.push(stat);
            all_findings.extend(findings);
        }

        let (score, verdict) = ScoringPolicy::evaluate(&all_findings, &self.config);

        Ok(ScanReport {
            target: target_name,
            verdict,
            score,
            findings: all_findings,
            files_scanned: loaded.files.len(),
            bytes_scanned: loaded.bytes_scanned,
            duration_ms: wall.elapsed().as_millis() as u64,
            engine_stats,
            errors: loaded.errors,
        })
    }
}
