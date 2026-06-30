use std::path::Path;

use crate::reviewed_process;

/// Reviewed deletion adapter for service plist cleanup after safety and backup checks.
#[allow(clippy::disallowed_methods)]
pub fn remove_service_plist(path: &Path) -> std::io::Result<()> {
    std::fs::remove_file(path)
}

pub fn remove_service_plist_elevated(path: &Path) -> std::io::Result<()> {
    let command = reviewed_process::elevated_rm_command(&path.to_string_lossy());
    let status = reviewed_process::reviewed_status(&command)?;
    if status.success() {
        Ok(())
    } else {
        Err(std::io::Error::other(format!(
            "elevated service plist removal exited with status {status}"
        )))
    }
}
