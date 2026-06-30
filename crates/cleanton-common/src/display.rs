use humansize::{BINARY, format_size};

#[must_use]
pub fn human_bytes(bytes: u64) -> String {
    format_size(bytes, BINARY)
}
