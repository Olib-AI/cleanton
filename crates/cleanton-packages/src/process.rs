//! Timeout-bounded external-tool runner and the admin-prompt helper.
//!
//! Mirrors `cleanton-services::reviewed_process`: every external command goes
//! through a single audited adapter. We use `tokio::process::Command` with
//! `tokio::time::timeout` plus `kill_on_drop(true)` so a wedged tool can never
//! hang the UI — on timeout the future is dropped and the child is reaped.
//!
//! `tokio::process::Command::new` is intentionally distinct from the
//! workspace-disallowed `std::process::Command::new`; subprocess execution
//! still lives only in this adapter.

use std::ffi::OsStr;
use std::path::PathBuf;
use std::time::Duration;

use tokio::process::Command;
use tokio::time::timeout;

/// Wall clock for read-only inventory probes.
pub(crate) const READ_TIMEOUT: Duration = Duration::from_secs(20);
/// Wall clock for read-only probes that hit the network for every package
/// (e.g. `pip list --outdated`, `brew outdated`, `npm outdated`). These query a
/// remote index per package and routinely run well past `READ_TIMEOUT` on large
/// installs — a too-short budget silently reports zero updates available.
pub(crate) const NETWORK_READ_TIMEOUT: Duration = Duration::from_mins(2);
/// Wall clock for mutating actions (downloads/compiles can be slow). Finite so
/// a stuck tool still cannot hang forever.
pub(crate) const ACTION_TIMEOUT: Duration = Duration::from_mins(10);
/// Wall clock for the admin (osascript) prompt — leaves room for the user to
/// type a password before the GUI dialog is force-dismissed.
pub(crate) const ADMIN_TIMEOUT: Duration = Duration::from_mins(10);

/// Captured, UTF-8-lossy result of a finished command.
#[derive(Debug, Clone)]
pub(crate) struct CmdOutput {
    pub status_ok: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Runs `program args`, returning `None` on spawn failure or timeout.
///
/// stdin is closed so a tool can never block waiting for input.
pub(crate) async fn run<I, S>(program: &str, args: I, dur: Duration) -> Option<CmdOutput>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut cmd = Command::new(program);
    cmd.args(args);
    cmd.stdin(std::process::Stdio::null());
    // A Finder/launchd-launched `.app` inherits only a minimal PATH, so bare
    // program names (`brew`, `npm`, `pip3`) and the tools they in turn invoke
    // (npm → node, brew → git) fail to resolve. Hand the child a PATH augmented
    // with the usual developer-tool locations so resolution matches a terminal.
    cmd.env("PATH", cleanton_common::paths::augmented_path());
    cmd.kill_on_drop(true);
    match timeout(dur, cmd.output()).await {
        Ok(Ok(out)) => Some(CmdOutput {
            status_ok: out.status.success(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        }),
        Ok(Err(_)) | Err(_) => None,
    }
}

/// Runs `program args` under `osascript ... with administrator privileges`,
/// the same elevation path used by `cleanton-services`. The command runs as
/// root via the GUI prompt; callers must NOT prefix `sudo`.
pub(crate) async fn run_admin(program: &str, args: &[&str], dur: Duration) -> Option<CmdOutput> {
    // `do shell script` runs under a bare `/bin/sh` whose PATH does not include
    // the developer-tool locations, so resolve the program to an absolute path
    // (falling back to the bare name) before quoting it into the script.
    let resolved = which(program).map_or_else(
        || program.to_owned(),
        |path| path.to_string_lossy().into_owned(),
    );
    let mut words = Vec::with_capacity(args.len().saturating_add(1));
    words.push(shell_quote(&resolved));
    for arg in args {
        words.push(shell_quote(arg));
    }
    let shell_command = words.join(" ");
    let script = format!(
        "do shell script {} with administrator privileges",
        applescript_quote(&shell_command)
    );
    run("osascript", ["-e", script.as_str()], dur).await
}

/// First executable match for `bin`, searching the developer-tool-augmented
/// `PATH` so a GUI-launched app finds the same binaries as the user's terminal.
pub(crate) fn which(bin: &str) -> Option<PathBuf> {
    cleanton_common::paths::find_executable(bin)
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn applescript_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}
