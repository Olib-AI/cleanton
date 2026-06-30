//! Per-manager adapters: read-only inventory plus gated mutating actions.

pub(crate) mod homebrew;
pub(crate) mod macports;
pub(crate) mod npm;
pub(crate) mod pip;

use crate::process::CmdOutput;
use crate::types::ActionOutcome;

/// Caps an action message so a chatty tool cannot bloat the UI/JSON payload.
const MAX_MESSAGE_LEN: usize = 600;

/// Builds an [`ActionOutcome`] from an optional command result.
pub(crate) fn outcome(result: Option<CmdOutput>, freed_bytes: u64) -> ActionOutcome {
    match result {
        Some(out) => {
            let freed = if out.status_ok { freed_bytes } else { 0 };
            ActionOutcome {
                ok: out.status_ok,
                message: summarize(&out),
                freed_bytes: freed,
            }
        }
        None => ActionOutcome::failed("command timed out or could not be launched"),
    }
}

/// Prefers stderr on failure, stdout on success; trimmed and length-capped.
fn summarize(out: &CmdOutput) -> String {
    let primary = if out.status_ok {
        out.stdout.trim()
    } else {
        let err = out.stderr.trim();
        if err.is_empty() {
            out.stdout.trim()
        } else {
            err
        }
    };
    let trimmed = if primary.is_empty() {
        if out.status_ok {
            "completed"
        } else {
            "command exited with a non-zero status"
        }
    } else {
        primary
    };
    truncate(trimmed, MAX_MESSAGE_LEN)
}

fn truncate(value: &str, max: usize) -> String {
    if value.len() <= max {
        return value.to_owned();
    }
    let mut end = max;
    while end > 0 && !value.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let head = value.get(..end).unwrap_or("");
    format!("{head}…")
}

/// Parses a Homebrew "freed approximately <size>" notice into bytes.
pub(crate) fn parse_freed(text: &str) -> u64 {
    for marker in ["freed approximately ", "freed "] {
        let Some(idx) = text.find(marker) else {
            continue;
        };
        let Some(rest) = text.get(idx.saturating_add(marker.len())..) else {
            continue;
        };
        if let Some(token) = rest.split_whitespace().next()
            && let Some(bytes) = parse_size_token(token)
        {
            return bytes;
        }
    }
    0
}

/// Parses a human size token such as `1.2GB`, `523.4MB`, `12KB`, `4096B`.
/// Integer-only math (no float casts) keeps the strict lint set happy.
fn parse_size_token(token: &str) -> Option<u64> {
    let split = token.find(|c: char| c.is_ascii_alphabetic())?;
    let (number, unit) = token.split_at(split);
    let multiplier: u64 = match unit.to_ascii_uppercase().as_str() {
        "B" => 1,
        "K" | "KB" | "KIB" => 1024,
        "M" | "MB" | "MIB" => 1024 * 1024,
        "G" | "GB" | "GIB" => 1024 * 1024 * 1024,
        "T" | "TB" | "TIB" => 1024_u64 * 1024 * 1024 * 1024,
        _ => return None,
    };

    let (int_part, frac_part) = number.split_once('.').unwrap_or((number, ""));
    let int_val: u64 = int_part.parse().ok()?;
    let mut bytes = int_val.saturating_mul(multiplier);

    if !frac_part.is_empty() {
        // Bound fractional precision so 10^digits cannot overflow.
        let capped = frac_part.get(..frac_part.len().min(6)).unwrap_or("");
        if let Ok(frac_val) = capped.parse::<u64>() {
            let digits = u32::try_from(capped.len()).unwrap_or(0);
            let denom = 10_u64.checked_pow(digits).unwrap_or(1);
            if let Some(contribution) = frac_val.saturating_mul(multiplier).checked_div(denom) {
                bytes = bytes.saturating_add(contribution);
            }
        }
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_size_tokens() {
        assert_eq!(parse_size_token("1KB"), Some(1024));
        assert_eq!(parse_size_token("1.5KB"), Some(1024 + 512));
        assert_eq!(parse_size_token("2GB"), Some(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_size_token("4096B"), Some(4096));
        assert_eq!(parse_size_token("garbage"), None);
    }

    #[test]
    fn parses_brew_cleanup_notice() {
        let text = "Removing: /Users/x/Library/Caches/Homebrew/foo... (1.2MB)\n\
                    ==> This operation has freed approximately 1.2GB of disk space.";
        assert_eq!(parse_freed(text), 1_288_490_188);
    }

    #[test]
    fn truncates_on_char_boundary() {
        let s = "héllo wörld this is long";
        let out = truncate(s, 4);
        assert!(out.ends_with('…'));
    }
}
