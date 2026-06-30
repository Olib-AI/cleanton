use std::time::Instant;

use cleanton_common::{CleantonConfig, CleanupPlan, ExecutionResult, Result, ScanResult};
use cleanton_recipes::RecipeSet;
use cleanton_scanner::{ScanOptions, ScanProgress};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

use cleanton_ml::MlEngine;

use crate::{
    AnalyzedPlan, EngineEvent,
    analyzer::{analyze_scan, analyze_with},
    docker::{DockerAnalysis, DockerCleaner},
    executor::execute_plan,
    ml::DEFAULT_ML_CONFIDENCE_THRESHOLD,
    suggestions::{Suggestions, detect_suggestions},
};

/// The complete analysis surfaced in the Results view: the filesystem cleanup
/// plan, the Docker reclaimable accounting (independent of the scan root), and
/// the review-only suggestions (duplicate sets + large files/folders).
#[derive(Debug, Clone)]
pub struct AnalyzedFull {
    pub analyzed: AnalyzedPlan,
    pub docker: DockerAnalysis,
    pub suggestions: Suggestions,
}

#[derive(Debug)]
pub struct Orchestrator {
    config: CleantonConfig,
    recipes: RecipeSet,
}

impl Orchestrator {
    pub fn new(config: CleantonConfig) -> Result<Self> {
        Ok(Self {
            config,
            recipes: RecipeSet::load_all()?,
        })
    }

    pub async fn run(
        &self,
        options: ScanOptions,
        event_tx: mpsc::Sender<EngineEvent>,
    ) -> Result<PipelineResult> {
        let started = Instant::now();
        let scan = self.scan_only(options, event_tx.clone()).await?;
        let plan = self.plan_scan(&scan, &event_tx)?;
        let _ = event_tx.try_send(EngineEvent::PipelineCompleted {
            total_reclaimable: plan.total_reclaimable,
            duration: started.elapsed(),
        });
        Ok(PipelineResult { scan, plan })
    }

    pub async fn scan_only(
        &self,
        options: ScanOptions,
        event_tx: mpsc::Sender<EngineEvent>,
    ) -> Result<ScanResult> {
        for root in &options.roots {
            let _ = event_tx.try_send(EngineEvent::ScanStarted { root: root.clone() });
        }

        let (progress_tx, mut progress_rx) = mpsc::channel::<ScanProgress>(64);
        let progress_events = event_tx.clone();
        let progress_task = tokio::spawn(async move {
            while let Some(progress) = progress_rx.recv().await {
                let _ = progress_events.try_send(EngineEvent::ScanProgress {
                    files_scanned: progress.files_scanned,
                    dirs_entered: progress.dirs_entered,
                    bytes_seen: progress.bytes_seen,
                });
            }
        });

        let scan = cleanton_scanner::scan(options, progress_tx).await?;
        progress_task.abort();

        let _ = event_tx.try_send(EngineEvent::ScanCompleted {
            result: scan.clone(),
        });
        Ok(scan)
    }

    pub fn plan_scan(
        &self,
        scan: &ScanResult,
        event_tx: &mpsc::Sender<EngineEvent>,
    ) -> Result<CleanupPlan> {
        let _ = event_tx.try_send(EngineEvent::AnalysisStarted);
        let plan = analyze_scan(&self.config, scan, &self.recipes);
        let _ = event_tx.try_send(EngineEvent::AnalysisCompleted { plan: plan.clone() });
        Ok(plan)
    }

    /// Full analysis with ML annotations and held / orphan candidates exposed.
    ///
    /// The returned [`AnalyzedPlan::plan`] is identical in shape to what
    /// [`plan_scan`](Self::plan_scan) produces; the extra fields are advisory.
    #[must_use]
    pub fn analyze(&self, scan: &ScanResult) -> AnalyzedPlan {
        let classifier = MlEngine::embedded();
        // Only inspect ~/Library for orphaned app data when the scan actually
        // covered it (home / full-disk scan). Skips the expensive Library walk
        // entirely for project-scoped scans.
        let orphans = if crate::orphans::scan_reaches_home_library(scan) {
            crate::orphans::detect_orphans(&self.config)
        } else {
            Vec::new()
        };
        analyze_with(
            &self.config,
            scan,
            &self.recipes,
            &classifier,
            DEFAULT_ML_CONFIDENCE_THRESHOLD,
            orphans,
        )
    }

    /// Full Results analysis: the filesystem [`AnalyzedPlan`] plus Docker
    /// accounting (always evaluated, independent of the scan root) and the
    /// review-only [`Suggestions`]. Docker failures degrade gracefully to an
    /// empty analysis so a missing/absent daemon never breaks the Results view.
    pub async fn analyze_full(&self, scan: &ScanResult) -> AnalyzedFull {
        let analyzed = self.analyze(scan);
        let docker = analyze_docker().await;
        let suggestions = detect_suggestions(scan);
        AnalyzedFull {
            analyzed,
            docker,
            suggestions,
        }
    }

    pub fn execute_plan(
        &self,
        plan: &CleanupPlan,
        event_tx: &mpsc::Sender<EngineEvent>,
    ) -> Result<ExecutionResult> {
        execute_plan(&self.config, plan, event_tx)
    }
}

/// Run Docker reclaimable accounting, degrading to an empty analysis if the
/// runtime can't be constructed or queried (no daemon, permission, timeout).
async fn analyze_docker() -> DockerAnalysis {
    match DockerCleaner::new() {
        Ok(cleaner) => cleaner.analyze().await.unwrap_or_else(|_| empty_docker()),
        Err(_) => empty_docker(),
    }
}

fn empty_docker() -> DockerAnalysis {
    DockerAnalysis {
        dangling_images: Vec::new(),
        stopped_containers: Vec::new(),
        unused_volumes: Vec::new(),
        build_cache: crate::docker::BuildCacheInfo { size: 0 },
        total_reclaimable: 0,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineResult {
    pub scan: ScanResult,
    pub plan: CleanupPlan,
}
