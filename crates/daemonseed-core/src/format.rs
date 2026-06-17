//! Display-only formatting helpers shared across the daemonseed clients.
//!
//! These produce human-facing strings for the TUI and GUI. They are **not** for
//! protocol, storage, or any path where an exact value matters — those use the
//! raw integer byte counts directly.

/// Format a byte count as a compact, human-readable size string.
///
/// Binary (1024-based) units, one decimal place above bytes: `B`, `KB`, `MB`,
/// `GB`. Display-only — used by the TUI and GUI share browsers. The canonical
/// home for this helper (the TUI and GUI both delegate here rather than carrying
/// their own copy).
///
/// ```
/// use daemonseed_core::format::human_bytes;
/// assert_eq!(human_bytes(0), "0 B");
/// assert_eq!(human_bytes(1024), "1.0 KB");
/// assert_eq!(human_bytes(1_572_864), "1.5 MB");
/// ```
#[must_use]
pub fn human_bytes(n: u64) -> String {
    const KB: f64 = 1024.0;
    let f = n as f64;
    if f < KB {
        format!("{n} B")
    } else if f < KB * KB {
        format!("{:.1} KB", f / KB)
    } else if f < KB * KB * KB {
        format!("{:.1} MB", f / (KB * KB))
    } else {
        format!("{:.1} GB", f / (KB * KB * KB))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn human_bytes_thresholds() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(512), "512 B");
        assert_eq!(human_bytes(1024), "1.0 KB");
        assert_eq!(human_bytes(1_572_864), "1.5 MB");
        assert_eq!(human_bytes(3 * 1024 * 1024 * 1024), "3.0 GB");
    }
}
