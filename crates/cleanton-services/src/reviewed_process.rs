use std::ffi::OsStr;
use std::process::{Command, ExitStatus, Output};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReviewedCommand {
    pub program: String,
    pub args: Vec<String>,
}

/// Reviewed subprocess adapter for service inspection and launchd/brew mutations.
#[allow(clippy::disallowed_methods)]
fn service_command(program: &str) -> Command {
    Command::new(program)
}

pub fn output<I, S>(program: &str, args: I) -> std::io::Result<Output>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = service_command(program);
    command.args(args);
    command.output()
}

pub fn status<I, S>(program: &str, args: I) -> std::io::Result<ExitStatus>
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut command = service_command(program);
    command.args(args);
    command.status()
}

pub(crate) fn elevated_launchctl_command(args: &[String]) -> ReviewedCommand {
    administrator_command("/bin/launchctl", args)
}

pub(crate) fn elevated_plutil_command(args: &[String]) -> ReviewedCommand {
    administrator_command("/usr/bin/plutil", args)
}

pub(crate) fn elevated_rm_command(path: &str) -> ReviewedCommand {
    administrator_command("/bin/rm", &["-f".to_string(), path.to_string()])
}

pub(crate) fn reviewed_status(command: &ReviewedCommand) -> std::io::Result<ExitStatus> {
    status(
        command.program.as_str(),
        command.args.iter().map(String::as_str),
    )
}

fn administrator_command(program: &str, args: &[String]) -> ReviewedCommand {
    let mut shell_words = Vec::with_capacity(args.len() + 1);
    shell_words.push(shell_quote(program));
    shell_words.extend(args.iter().map(|arg| shell_quote(arg)));

    let shell_command = shell_words.join(" ");
    let script = format!(
        "do shell script {} with administrator privileges",
        applescript_quote(&shell_command)
    );

    ReviewedCommand {
        program: "osascript".to_string(),
        args: vec!["-e".to_string(), script],
    }
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn applescript_quote(value: &str) -> String {
    format!("\"{}\"", value.replace('\\', "\\\\").replace('"', "\\\""))
}
