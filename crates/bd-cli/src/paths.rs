//! Per-user directories.

use std::path::PathBuf;

/// `$XDG_CONFIG_HOME` on every OS, else the platform's per-user config dir:
/// `~/.config`, or `%APPDATA%` on Windows.
pub fn user_config_dir() -> Option<PathBuf> {
    let var = |name: &str| std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from);
    var("XDG_CONFIG_HOME").or_else(
        || {
            if cfg!(windows) { var("APPDATA") } else { var("HOME").map(|h| h.join(".config")) }
        },
    )
}
