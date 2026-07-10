//! Scoring policy: converts a slice of [`Finding`]s into a 0–100 risk score
//! and a [`Verdict`].
//!
//! ## Design goals
//!
//! 1. **Deterministic.** Given the same findings and config, the output never
//!    changes. No randomness, no external state.
//! 2. **Allowlist first.** Operator-suppressed rule IDs are dropped before any
//!    accumulation.
//! 3. **De-duplicate.** Multiple findings from the same `(engine, rule_id,
//!    file-path)` triple are collapsed to one; this prevents a rule that fires
//!    on every line from saturating the score alone.
//! 4. **Diminishing returns.** Additional lower-severity findings add
//!    progressively less to the score so that a cloud of low-confidence noise
//!    alone can never cross the Malicious threshold.
//! 5. **Escalation combos.** Certain co-occurring threat categories reliably
//!    indicate real attacks and override the numeric threshold — see
//!    [`CategoryFlags::forces_malicious`].

use std::collections::HashMap;

use crate::config::ScanConfig;
use crate::types::{Confidence, Finding, Severity, ThreatCategory, Verdict};

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Canonical de-duplication key for a finding.
///
/// Two findings are "near-identical" when they share the same engine, the same
/// rule_id (if any), and the same file path (if any).  Line and offset are
/// intentionally excluded — the same rule firing at line 1 and line 2 of the
/// same file is usually the same pattern repeated.
#[derive(Hash, PartialEq, Eq)]
struct DedupKey<'a> {
    engine: &'a str,
    /// `None` rule IDs are never collapsed with each other (every no-rule
    /// finding is distinct).
    rule_id: Option<&'a str>,
    path: Option<&'a str>,
}

impl<'a> DedupKey<'a> {
    fn from(f: &'a Finding) -> Option<Self> {
        // We only de-dup when both engine AND rule_id are present; an engine
        // without a rule_id may legitimately produce multiple distinct
        // findings of the same category on the same file.
        let rule_id = f.rule_id.as_deref()?;
        Some(Self {
            engine: f.engine.as_str(),
            rule_id: Some(rule_id),
            path: f.location.as_ref().map(|l| l.path.as_str()),
        })
    }
}

// ---------------------------------------------------------------------------
// Escalation combos
// ---------------------------------------------------------------------------

/// Category presence flags used to evaluate combo escalation rules.
struct CategoryFlags {
    has_critical_malware: bool,
    has_install_script_high: bool,
    has_exfiltration: bool,
    has_network: bool,
    has_obfuscation: bool,
    has_native_binary: bool,
    has_command_exec: bool,
    /// Any finding that is BOTH Critical severity AND High confidence.
    has_critical_high: bool,
}

impl CategoryFlags {
    fn from_findings(findings: &[&Finding]) -> Self {
        let mut f = Self {
            has_critical_malware: false,
            has_install_script_high: false,
            has_exfiltration: false,
            has_network: false,
            has_obfuscation: false,
            has_native_binary: false,
            has_command_exec: false,
            has_critical_high: false,
        };
        for finding in findings {
            if finding.severity == Severity::Critical && finding.confidence == Confidence::High {
                f.has_critical_high = true;
            }
            match finding.category {
                ThreatCategory::KnownMalware if finding.severity == Severity::Critical => {
                    f.has_critical_malware = true;
                }
                ThreatCategory::InstallScript if finding.severity >= Severity::High => {
                    f.has_install_script_high = true;
                }
                ThreatCategory::Exfiltration => f.has_exfiltration = true,
                ThreatCategory::Network => f.has_network = true,
                ThreatCategory::Obfuscation => f.has_obfuscation = true,
                ThreatCategory::NativeBinary => f.has_native_binary = true,
                ThreatCategory::CommandExecution => f.has_command_exec = true,
                _ => {}
            }
        }
        f
    }

    /// Returns `true` if any combo rule mandates a Malicious verdict
    /// regardless of the numeric score.
    ///
    /// Combo rules (grounded in real supply-chain attack patterns):
    ///
    /// A) Any Critical KnownMalware finding — a matched hash or signature with
    ///    Critical severity is, by definition, a confirmed active malware
    ///    indicator. We must not let noise dilution or a high allowlist
    ///    threshold clear it.
    ///
    /// B) High-severity install script AND (data exfiltration OR outbound
    ///    network OR obfuscation) — the classic npm post-install backdoor:
    ///    a lifecycle script that phones home, exfiltrates env vars, or hides
    ///    its payload behind encoding.
    ///
    /// C) Obfuscation AND Exfiltration (co-occurring) — encoding/packing used
    ///    to hide a data-theft payload; seen in credential stealers.
    ///
    /// D) Native binary AND (network OR command execution) — a compiled
    ///    payload dropped by a package that also makes network connections or
    ///    spawns processes; classic dropper / implant pattern.
    /// E) Any Critical-severity, High-confidence finding. `Severity::Critical`
    ///    is defined as a near-certain malware / active-compromise indicator and
    ///    `Confidence::High` means the engine is near-certain it is a true
    ///    positive; a fail-closed gate must block such a finding on its own. The
    ///    numeric path alone caps a single finding at 67 (< the 70 default
    ///    Malicious threshold), which would let a byte-exact known-C2 IOC or a
    ///    `curl | bash` dropper resolve to Suspicious and pass the block gate.
    fn forces_malicious(&self) -> bool {
        // Rule A
        if self.has_critical_malware {
            return true;
        }
        // Rule E
        if self.has_critical_high {
            return true;
        }
        // Rule B
        if self.has_install_script_high
            && (self.has_exfiltration || self.has_network || self.has_obfuscation)
        {
            return true;
        }
        // Rule C
        if self.has_obfuscation && self.has_exfiltration {
            return true;
        }
        // Rule D
        if self.has_native_binary && (self.has_network || self.has_command_exec) {
            return true;
        }
        false
    }
}

// ---------------------------------------------------------------------------
// Public interface
// ---------------------------------------------------------------------------

/// The scoring policy.
///
/// This is a pure-function struct with no state.  Construct once (it is `Copy`)
/// and call [`ScoringPolicy::evaluate`] as many times as needed.
#[derive(Debug, Clone, Copy, Default)]
pub struct ScoringPolicy;

impl ScoringPolicy {
    /// Evaluate a slice of raw findings (as emitted by all engines combined)
    /// and return `(score, verdict)`.
    ///
    /// ### Steps
    /// 1. Drop allowlisted rule IDs.
    /// 2. De-duplicate by `(engine, rule_id, file-path)`.
    /// 3. Compute a weighted, diminishing-returns score.
    /// 4. Evaluate escalation combos — if any fires, the verdict is Malicious
    ///    regardless of the numeric score.
    /// 5. Apply threshold-based verdict from the numeric score.
    pub fn evaluate(findings: &[Finding], cfg: &ScanConfig) -> (u32, Verdict) {
        // Step 1 — drop allowlisted rule IDs.
        let active: Vec<&Finding> = findings
            .iter()
            .filter(|f| {
                !f.rule_id
                    .as_deref()
                    .map(|id| cfg.is_allowlisted(id))
                    .unwrap_or(false)
            })
            .collect();

        if active.is_empty() {
            return (0, Verdict::Clean);
        }

        // Step 2 — de-duplicate near-identical findings.
        //
        // For findings that have a (engine, rule_id, path) key we keep only
        // the representative with the highest severity (then highest
        // confidence); for findings without a rule_id we keep all of them
        // (they are distinct by construction — the engine chose not to assign
        // one, so we cannot safely collapse them).
        let deduped: Vec<&Finding> = deduplicate(&active);

        // Step 3 — weighted accumulation with diminishing returns.
        let score = compute_score(&deduped);

        // Step 4 — escalation combos.
        let flags = CategoryFlags::from_findings(&deduped);
        if flags.forces_malicious() {
            // Clamp score to at least the Malicious threshold so the numeric
            // score is also consistent with the verdict in the report.
            let forced_score = score.max(cfg.min_score_malicious);
            return (forced_score, Verdict::Malicious);
        }

        // Step 5 — threshold verdict.
        let verdict = if score >= cfg.min_score_malicious {
            Verdict::Malicious
        } else if score >= cfg.min_score_suspicious {
            Verdict::Suspicious
        } else {
            Verdict::Clean
        };

        (score, verdict)
    }
}

// ---------------------------------------------------------------------------
// De-duplication
// ---------------------------------------------------------------------------

fn deduplicate<'a>(findings: &[&'a Finding]) -> Vec<&'a Finding> {
    // For each dedup key keep the "worst" representative (highest severity;
    // tie-break on highest confidence).
    let mut keyed: HashMap<DedupKey<'_>, &Finding> = HashMap::new();
    let mut unkeyed: Vec<&Finding> = Vec::new();

    for &f in findings {
        match DedupKey::from(f) {
            None => {
                // No rule_id — cannot safely collapse.
                unkeyed.push(f);
            }
            Some(key) => {
                let entry = keyed.entry(key).or_insert(f);
                // Replace if this finding is worse (higher severity, or same
                // severity but higher confidence).
                if f.severity > entry.severity
                    || (f.severity == entry.severity && f.confidence > entry.confidence)
                {
                    *entry = f;
                }
            }
        }
    }

    let mut result: Vec<&Finding> = keyed.into_values().collect();
    result.extend(unkeyed);
    // Sort for determinism (severity desc, confidence desc) so tests are stable.
    result.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.confidence.cmp(&a.confidence))
            .then(a.engine.cmp(&b.engine))
            .then(a.rule_id.cmp(&b.rule_id))
    });
    result
}

// ---------------------------------------------------------------------------
// Score accumulation
// ---------------------------------------------------------------------------

/// Compute a 0–100 score from the de-duplicated finding list.
///
/// ### Weighting model
///
/// Each finding contributes `raw = severity.weight() * confidence.factor()`.
/// Raw contributions are collected per-category and then subject to
/// diminishing returns within that category: each additional finding in the
/// same category contributes only a fraction of its raw value.
///
/// Diminishing-returns coefficient for the N-th finding (0-indexed) in a
/// category:
/// ```text
///   coefficient(n) = 1.0 / (n as f64 + 1.0)
/// ```
/// So the 1st finding contributes 100 %, the 2nd 50 %, the 3rd 33 %, etc.
///
/// The accumulated float total is then soft-clamped to 0–100 via a
/// logistic-like formula:
/// ```text
///   score = raw_total * 100 / (raw_total + 50)
/// ```
/// This ensures that even an enormous number of low-severity findings
/// asymptotically approaches 100 but never reaches it through noise alone.
/// A single Critical/High finding contributes enough raw value to push past
/// the Malicious threshold through the numeric path when the combo rules
/// don't apply.
fn compute_score(findings: &[&Finding]) -> u32 {
    // Tally raw contributions per category with diminishing returns.
    let mut per_category: HashMap<u8, Vec<f64>> = HashMap::new();

    for &f in findings {
        let raw = f64::from(f.severity.weight()) * f64::from(f.confidence.factor());
        // Use the discriminant as a cheap category key (ThreatCategory is Copy).
        let cat_key = category_key(f.category);
        per_category.entry(cat_key).or_default().push(raw);
    }

    // Sort each category bucket descending so the highest-value findings
    // get the least-diminished coefficients.
    let mut raw_total: f64 = 0.0;
    for values in per_category.values_mut() {
        values.sort_by(|a, b| b.partial_cmp(a).unwrap_or(std::cmp::Ordering::Equal));
        for (n, &v) in values.iter().enumerate() {
            let coeff = 1.0_f64 / (n as f64 + 1.0);
            raw_total += v * coeff;
        }
    }

    // Soft-clamp via logistic compression: maps [0, ∞) to [0, 100).
    // raw_total = 100 maps to score 67; raw_total = 200 maps to 80.
    // A single Critical/High finding (raw ≈ 100×1.0 = 100) maps to score 67,
    // comfortably above the default Malicious threshold of 70 only with the
    // combo rule; but two independent Critical findings (≈ 100 + 50 = 150)
    // push the pure score to 75, clearing the threshold numerically.
    let score_f = raw_total * 100.0 / (raw_total + 50.0);

    // Floor at 0, ceiling at 100 (paranoia clamp).
    score_f.clamp(0.0, 100.0).round() as u32
}

/// Map a `ThreatCategory` to a compact u8 key for the per-category map.
/// We cannot derive `Hash` on the enum because it has no data, but matching
/// is just as fast and avoids a derived impl dependency.
fn category_key(c: ThreatCategory) -> u8 {
    match c {
        ThreatCategory::KnownMalware => 0,
        ThreatCategory::SupplyChain => 1,
        ThreatCategory::InstallScript => 2,
        ThreatCategory::Obfuscation => 3,
        ThreatCategory::Exfiltration => 4,
        ThreatCategory::CommandExecution => 5,
        ThreatCategory::Network => 6,
        ThreatCategory::FilesystemAbuse => 7,
        ThreatCategory::CredentialAccess => 8,
        ThreatCategory::CryptoStealer => 9,
        ThreatCategory::Typosquatting => 10,
        ThreatCategory::DependencyConfusion => 11,
        ThreatCategory::Ioc => 12,
        ThreatCategory::Packer => 13,
        ThreatCategory::NativeBinary => 14,
        ThreatCategory::Other => 15,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{Confidence, Finding, Severity, ThreatCategory, Verdict};

    fn cfg() -> ScanConfig {
        ScanConfig::default() // min_score_suspicious=25, min_score_malicious=70
    }

    fn make_finding(
        category: ThreatCategory,
        severity: Severity,
        confidence: Confidence,
        rule_id: Option<&str>,
    ) -> Finding {
        let mut f = Finding::new(
            "test_engine",
            category,
            severity,
            confidence,
            "test title",
            "test description",
        );
        if let Some(id) = rule_id {
            f = f.with_rule_id(id);
        }
        f
    }

    // -----------------------------------------------------------------------
    // Empty input
    // -----------------------------------------------------------------------

    #[test]
    fn empty_findings_clean_zero() {
        let (score, verdict) = ScoringPolicy::evaluate(&[], &cfg());
        assert_eq!(score, 0);
        assert_eq!(verdict, Verdict::Clean);
    }

    // -----------------------------------------------------------------------
    // Single Critical KnownMalware => Malicious (combo rule A)
    // -----------------------------------------------------------------------

    #[test]
    fn single_critical_known_malware_forces_malicious() {
        let findings = vec![make_finding(
            ThreatCategory::KnownMalware,
            Severity::Critical,
            Confidence::High,
            Some("HASH_KNOWN_RAT"),
        )];
        let (score, verdict) = ScoringPolicy::evaluate(&findings, &cfg());
        assert_eq!(verdict, Verdict::Malicious);
        // Score must be at least the malicious threshold.
        assert!(score >= cfg().min_score_malicious, "score={score}");
    }

    // -----------------------------------------------------------------------
    // Combo rule E: a single Critical + High-confidence finding forces Malicious
    // -----------------------------------------------------------------------

    #[test]
    fn single_critical_high_non_malware_forces_malicious() {
        // A byte-exact known-C2 IOC (Critical/High, category Network — NOT
        // KnownMalware so combo A does not apply). The numeric path alone caps
        // this at 67; rule E must still block it.
        let findings = vec![make_finding(
            ThreatCategory::Network,
            Severity::Critical,
            Confidence::High,
            Some("IOC_KNOWN_C2"),
        )];
        let (score, verdict) = ScoringPolicy::evaluate(&findings, &cfg());
        assert_eq!(verdict, Verdict::Malicious, "score={score}");
        assert!(score >= cfg().min_score_malicious, "score={score}");
    }

    // Rule E is confidence-gated: a Critical finding at only Medium confidence
    // does NOT force Malicious (it may still be Suspicious by score).
    #[test]
    fn single_critical_medium_confidence_not_forced() {
        let findings = vec![make_finding(
            ThreatCategory::Network,
            Severity::Critical,
            Confidence::Medium,
            Some("IOC_MAYBE_C2"),
        )];
        let (score, verdict) = ScoringPolicy::evaluate(&findings, &cfg());
        assert_ne!(verdict, Verdict::Malicious, "score={score}");
    }

    // Rule E is severity-gated: a High/High finding is not Critical, so it does
    // not force Malicious on its own.
    #[test]
    fn single_high_high_not_forced() {
        let findings = vec![make_finding(
            ThreatCategory::Network,
            Severity::High,
            Confidence::High,
            Some("IOC_HIGH"),
        )];
        let (_, verdict) = ScoringPolicy::evaluate(&findings, &cfg());
        assert_ne!(verdict, Verdict::Malicious);
    }

    // -----------------------------------------------------------------------
    // A single Medium finding — result depends on thresholds
    // -----------------------------------------------------------------------

    #[test]
    fn single_medium_high_confidence_is_suspicious() {
        // raw = 25 * 1.0 = 25.0; soft-clamped: 25*100/(25+50) ≈ 33 → Suspicious
        let findings = vec![make_finding(
            ThreatCategory::Ioc,
            Severity::Medium,
            Confidence::High,
            Some("IOC_SUSPICIOUS_DOMAIN"),
        )];
        let (score, verdict) = ScoringPolicy::evaluate(&findings, &cfg());
        // Must be Suspicious (not Malicious, not Clean).
        assert_eq!(verdict, Verdict::Suspicious, "score={score}");
        assert!(score >= cfg().min_score_suspicious, "score={score}");
        assert!(score < cfg().min_score_malicious, "score={score}");
    }

    #[test]
    fn single_medium_low_confidence_may_be_clean() {
        // raw = 25 * 0.4 = 10; soft-clamped: 10*100/(10+50) ≈ 17 → Clean
        let findings = vec![make_finding(
            ThreatCategory::Ioc,
            Severity::Medium,
            Confidence::Low,
            Some("IOC_WEAK"),
        )];
        let (score, verdict) = ScoringPolicy::evaluate(&findings, &cfg());
        assert_eq!(verdict, Verdict::Clean, "score={score}");
        assert!(score < cfg().min_score_suspicious, "score={score}");
    }

    // -----------------------------------------------------------------------
    // Install-script (High) + Exfiltration => Malicious (combo rule B)
    // -----------------------------------------------------------------------

    #[test]
    fn install_script_plus_exfil_forces_malicious() {
        let findings = vec![
            make_finding(
                ThreatCategory::InstallScript,
                Severity::High,
                Confidence::High,
                Some("NPM_POSTINSTALL_CURL"),
            ),
            make_finding(
                ThreatCategory::Exfiltration,
                Severity::Medium,
                Confidence::Medium,
                Some("EXFIL_ENV_SEND"),
            ),
        ];
        let (_, verdict) = ScoringPolicy::evaluate(&findings, &cfg());
        assert_eq!(verdict, Verdict::Malicious);
    }

    #[test]
    fn install_script_plus_network_forces_malicious() {
        let findings = vec![
            make_finding(
                ThreatCategory::InstallScript,
                Severity::High,
                Confidence::High,
                Some("NPM_POSTINSTALL_WGET"),
            ),
            make_finding(
                ThreatCategory::Network,
                Severity::Medium,
                Confidence::Medium,
                Some("NET_C2_BEACON"),
            ),
        ];
        let (_, verdict) = ScoringPolicy::evaluate(&findings, &cfg());
        assert_eq!(verdict, Verdict::Malicious);
    }

    #[test]
    fn install_script_plus_obfuscation_forces_malicious() {
        let findings = vec![
            make_finding(
                ThreatCategory::InstallScript,
                Severity::High,
                Confidence::Medium,
                Some("NPM_PREINSTALL_EVAL"),
            ),
            make_finding(
                ThreatCategory::Obfuscation,
                Severity::High,
                Confidence::High,
                Some("OBF_BASE64_CHAIN"),
            ),
        ];
        let (_, verdict) = ScoringPolicy::evaluate(&findings, &cfg());
        assert_eq!(verdict, Verdict::Malicious);
    }

    // Install script at merely Medium severity does NOT trigger combo rule B.
    #[test]
    fn install_script_medium_plus_network_not_forced_malicious() {
        let findings = vec![
            make_finding(
                ThreatCategory::InstallScript,
                Severity::Medium,
                Confidence::Medium,
                Some("NPM_POSTINSTALL_MINOR"),
            ),
            make_finding(
                ThreatCategory::Network,
                Severity::Low,
                Confidence::Low,
                Some("NET_MINOR"),
            ),
        ];
        let (score, verdict) = ScoringPolicy::evaluate(&findings, &cfg());
        // No combo rule fires; verdict is score-driven (should be Suspicious at most).
        assert_ne!(verdict, Verdict::Malicious, "score={score}");
    }

    // -----------------------------------------------------------------------
    // Obfuscation + Exfiltration => Malicious (combo rule C)
    // -----------------------------------------------------------------------

    #[test]
    fn obfuscation_plus_exfil_forces_malicious() {
        let findings = vec![
            make_finding(
                ThreatCategory::Obfuscation,
                Severity::Medium,
                Confidence::Medium,
                Some("OBF_HEX_ENCODED"),
            ),
            make_finding(
                ThreatCategory::Exfiltration,
                Severity::Low,
                Confidence::Low,
                Some("EXFIL_WEAK"),
            ),
        ];
        let (_, verdict) = ScoringPolicy::evaluate(&findings, &cfg());
        assert_eq!(verdict, Verdict::Malicious);
    }

    // -----------------------------------------------------------------------
    // Native binary + network => Malicious (combo rule D)
    // -----------------------------------------------------------------------

    #[test]
    fn native_binary_plus_network_forces_malicious() {
        let findings = vec![
            make_finding(
                ThreatCategory::NativeBinary,
                Severity::Medium,
                Confidence::Medium,
                Some("BIN_ELF_DROPPED"),
            ),
            make_finding(
                ThreatCategory::Network,
                Severity::Medium,
                Confidence::Medium,
                Some("NET_CONNECT"),
            ),
        ];
        let (_, verdict) = ScoringPolicy::evaluate(&findings, &cfg());
        assert_eq!(verdict, Verdict::Malicious);
    }

    #[test]
    fn native_binary_plus_cmd_exec_forces_malicious() {
        let findings = vec![
            make_finding(
                ThreatCategory::NativeBinary,
                Severity::High,
                Confidence::High,
                Some("BIN_PE_DROPPER"),
            ),
            make_finding(
                ThreatCategory::CommandExecution,
                Severity::High,
                Confidence::High,
                Some("EXEC_SHELL_SPAWN"),
            ),
        ];
        let (_, verdict) = ScoringPolicy::evaluate(&findings, &cfg());
        assert_eq!(verdict, Verdict::Malicious);
    }

    // Native binary alone (no network/exec) — no combo.
    #[test]
    fn native_binary_alone_not_forced_malicious() {
        let findings = vec![make_finding(
            ThreatCategory::NativeBinary,
            Severity::Medium,
            Confidence::Medium,
            Some("BIN_ELF_PRESENT"),
        )];
        let (score, verdict) = ScoringPolicy::evaluate(&findings, &cfg());
        // May be Suspicious by score but not forced Malicious.
        assert_ne!(verdict, Verdict::Malicious, "score={score}");
    }

    // -----------------------------------------------------------------------
    // Allowlisting
    // -----------------------------------------------------------------------

    #[test]
    fn allowlisted_critical_finding_suppressed() {
        let mut cfg = cfg();
        cfg.allowlisted_rule_ids.push("HASH_KNOWN_RAT".to_string());

        let findings = vec![make_finding(
            ThreatCategory::KnownMalware,
            Severity::Critical,
            Confidence::High,
            Some("HASH_KNOWN_RAT"),
        )];
        let (score, verdict) = ScoringPolicy::evaluate(&findings, &cfg);
        // Allowlisted — must not trigger combo rule A.
        assert_ne!(verdict, Verdict::Malicious, "score={score}");
        assert_eq!(score, 0);
        assert_eq!(verdict, Verdict::Clean);
    }

    #[test]
    fn allowlist_only_suppresses_matching_rule_id() {
        let mut cfg = cfg();
        cfg.allowlisted_rule_ids.push("HASH_KNOWN_RAT".to_string());

        let findings = vec![
            // Allowlisted — dropped.
            make_finding(
                ThreatCategory::KnownMalware,
                Severity::Critical,
                Confidence::High,
                Some("HASH_KNOWN_RAT"),
            ),
            // NOT allowlisted — survives.
            make_finding(
                ThreatCategory::Obfuscation,
                Severity::High,
                Confidence::High,
                Some("OBF_DIFFERENT"),
            ),
            make_finding(
                ThreatCategory::Exfiltration,
                Severity::High,
                Confidence::High,
                Some("EXFIL_DIFFERENT"),
            ),
        ];
        let (_, verdict) = ScoringPolicy::evaluate(&findings, &cfg);
        // OBF + EXFIL still triggers combo rule C.
        assert_eq!(verdict, Verdict::Malicious);
    }

    // -----------------------------------------------------------------------
    // De-duplication
    // -----------------------------------------------------------------------

    #[test]
    fn same_rule_same_file_deduped_to_one() {
        // Simulate a rule firing on 100 lines of the same file.
        let findings: Vec<Finding> = (0..100)
            .map(|line| {
                make_finding(
                    ThreatCategory::Obfuscation,
                    Severity::Medium,
                    Confidence::Medium,
                    Some("OBF_HEX"),
                )
                .with_location(crate::types::FileLocation::at_line("index.js", line + 1))
            })
            .collect();

        // Without de-dup 100 × (25×0.7) = 1750 raw, which with our formula
        // gives (1750×100)/(1750+50) ≈ 97 — well above Malicious.
        // With de-dup it collapses to 1, raw ≈ 17.5 → score ≈ 26 → Suspicious.
        let (score, verdict) = ScoringPolicy::evaluate(&findings, &cfg());
        assert_eq!(verdict, Verdict::Suspicious, "score={score}");
        assert!(score < cfg().min_score_malicious, "score={score}");
    }

    #[test]
    fn different_rule_ids_same_category_not_deduped() {
        // Two different rules on the same file should both count.
        let findings = vec![
            make_finding(
                ThreatCategory::Obfuscation,
                Severity::High,
                Confidence::High,
                Some("OBF_RULE_1"),
            ),
            make_finding(
                ThreatCategory::Obfuscation,
                Severity::High,
                Confidence::High,
                Some("OBF_RULE_2"),
            ),
        ];
        let (score, _verdict) = ScoringPolicy::evaluate(&findings, &cfg());
        // Two High/High obfuscation findings: raw ≈ 60 + 30 = 90,
        // score ≈ 90*100/140 ≈ 64 → Suspicious (< malicious 70).
        assert!(score >= cfg().min_score_suspicious, "score={score}");
    }

    // -----------------------------------------------------------------------
    // Diminishing returns: many low findings don't saturate
    // -----------------------------------------------------------------------

    #[test]
    fn many_low_findings_do_not_saturate_without_combo() {
        // 50 distinct Low/Low IOC findings (different rule IDs so they survive
        // de-dup; no combo category pair).
        let findings: Vec<Finding> = (0..50)
            .map(|i| {
                make_finding(
                    ThreatCategory::Ioc,
                    Severity::Low,
                    Confidence::Low,
                    Some(&format!("IOC_{i}")),
                )
            })
            .collect();

        let (score, verdict) = ScoringPolicy::evaluate(&findings, &cfg());
        // Even 50 Low/Low findings should not reach Malicious.
        assert!(
            score < cfg().min_score_malicious,
            "diminishing returns failed; score={score}, verdict={verdict:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Score boundary: two Critical/High findings cross Malicious numerically
    // -----------------------------------------------------------------------

    #[test]
    fn two_independent_critical_high_exceed_malicious_threshold() {
        // Two independent Critical/High findings from different categories
        // with different rule IDs (no combo needed — pure numeric path).
        // raw ≈ 100 + 50 = 150; score ≈ 150*100/200 = 75 → Malicious.
        let findings = vec![
            make_finding(
                ThreatCategory::SupplyChain,
                Severity::Critical,
                Confidence::High,
                Some("SC_CRITICAL_1"),
            ),
            make_finding(
                ThreatCategory::CredentialAccess,
                Severity::Critical,
                Confidence::High,
                Some("CRED_CRITICAL_2"),
            ),
        ];
        let (score, verdict) = ScoringPolicy::evaluate(&findings, &cfg());
        assert_eq!(verdict, Verdict::Malicious, "score={score}");
    }

    // -----------------------------------------------------------------------
    // No false positives on benign input
    // -----------------------------------------------------------------------

    #[test]
    fn only_info_findings_clean() {
        let findings: Vec<Finding> = (0..20)
            .map(|i| {
                make_finding(
                    ThreatCategory::Other,
                    Severity::Info,
                    Confidence::High,
                    Some(&format!("INFO_{i}")),
                )
            })
            .collect();
        let (score, verdict) = ScoringPolicy::evaluate(&findings, &cfg());
        // Info weight = 0, so score must be 0 and verdict Clean.
        assert_eq!(score, 0, "info findings must not contribute to score");
        assert_eq!(verdict, Verdict::Clean);
    }

    #[test]
    fn only_low_severity_single_finding_clean() {
        // Low/Low: raw = 8 * 0.4 = 3.2; score ≈ 3.2*100/53.2 ≈ 6 → Clean.
        let findings = vec![make_finding(
            ThreatCategory::Ioc,
            Severity::Low,
            Confidence::Low,
            Some("IOC_LOW_BENIGN"),
        )];
        let (score, verdict) = ScoringPolicy::evaluate(&findings, &cfg());
        assert_eq!(verdict, Verdict::Clean, "score={score}");
        assert!(score < cfg().min_score_suspicious, "score={score}");
    }

    // -----------------------------------------------------------------------
    // Allowlisted finding without rule_id (no-op — cannot match)
    // -----------------------------------------------------------------------

    #[test]
    fn no_rule_id_finding_not_allowlisted() {
        let mut cfg = cfg();
        cfg.allowlisted_rule_ids.push("ANYTHING".to_string());

        // Finding without rule_id — allowlist cannot match it.
        let findings = vec![make_finding(
            ThreatCategory::Obfuscation,
            Severity::Medium,
            Confidence::High,
            None, // no rule_id
        )];
        let (score, verdict) = ScoringPolicy::evaluate(&findings, &cfg);
        // Not suppressed → Suspicious.
        assert_eq!(verdict, Verdict::Suspicious, "score={score}");
    }

    // -----------------------------------------------------------------------
    // Score monotonicity: more findings → higher or equal score
    // -----------------------------------------------------------------------

    #[test]
    fn additional_non_combo_finding_does_not_reduce_score() {
        let base = vec![make_finding(
            ThreatCategory::Ioc,
            Severity::Medium,
            Confidence::Medium,
            Some("IOC_BASE"),
        )];
        let (score_base, _) = ScoringPolicy::evaluate(&base, &cfg());

        let mut extended = base.clone();
        extended.push(make_finding(
            ThreatCategory::Network,
            Severity::Low,
            Confidence::Low,
            Some("NET_EXTRA"),
        ));
        let (score_ext, _) = ScoringPolicy::evaluate(&extended, &cfg());

        assert!(
            score_ext >= score_base,
            "adding a finding reduced score: {score_base} -> {score_ext}"
        );
    }
}
