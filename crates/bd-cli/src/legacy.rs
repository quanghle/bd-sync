//! Legacy fallback: when the nearest workspace is a Go-beads `.beads/`
//! directory (and not a `.bd/` one), forward the whole command line to the
//! legacy `beads` binary so existing hooks (`bd prime`) and repositories keep
//! working. Disable with `BD_LEGACY_FALLBACK=0`; point at a specific binary
//! with `BD_LEGACY_BIN`.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Commands that always run natively.
const NATIVE_ONLY: &[&str] = &["init", "help", "version", "bench", "bench-worker"];

/// Global flags (ours and beads') that take a separate value.
const VALUE_FLAGS: &[&str] = &[
    "-C",
    "--directory",
    "--db",
    "--actor",
    "--log-format",
    "--slow-ms",
    "--busy-timeout-ms",
    "--database",
    "--dolt-auto-commit",
    "--mem-profile",
];

const MAX_DEPTH: u32 = 3;

#[derive(Debug, PartialEq, Eq)]
pub enum Workspace {
    Native(PathBuf),
    Legacy(PathBuf),
    None,
}

/// The nearest workspace walking up from `start`; at the same level a native
/// `.bd/bd.db` wins over a legacy `.beads/`.
pub fn nearest_workspace(start: &Path) -> Workspace {
    for dir in start.ancestors() {
        let native = dir.join(".bd").join("bd.db");
        if native.is_file() {
            return Workspace::Native(native);
        }
        let legacy = dir.join(".beads");
        if legacy.is_dir() {
            return Workspace::Legacy(legacy);
        }
    }
    Workspace::None
}

struct Scan {
    directory: Option<PathBuf>,
    subcommand: Option<String>,
    explicit_db: bool,
}

fn scan(args: &[OsString]) -> Scan {
    let mut s = Scan { directory: None, subcommand: None, explicit_db: false };
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].to_string_lossy().to_string();
        if arg == "--" {
            break;
        }
        if let Some(v) = arg.strip_prefix("--db=") {
            s.explicit_db = !v.is_empty();
        } else if let Some(v) = arg.strip_prefix("--directory=") {
            s.directory = Some(PathBuf::from(v));
        } else if VALUE_FLAGS.contains(&arg.as_str()) {
            let value = args.get(i + 1).map(PathBuf::from);
            match arg.as_str() {
                "--db" => s.explicit_db = true,
                "-C" | "--directory" => s.directory = value,
                _ => {}
            }
            i += 2;
            continue;
        } else if !arg.starts_with('-') && s.subcommand.is_none() {
            s.subcommand = Some(arg);
        }
        i += 1;
    }
    s
}

fn disabled() -> bool {
    std::env::var("BD_LEGACY_FALLBACK")
        .map(|v| matches!(v.trim().to_ascii_lowercase().as_str(), "0" | "false" | "off" | "no"))
        .unwrap_or(false)
}

fn legacy_binary() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("BD_LEGACY_BIN").filter(|p| !p.is_empty()) {
        return Some(PathBuf::from(p));
    }
    let me = std::env::current_exe().ok().and_then(|p| p.canonicalize().ok());
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path)
        .map(|dir| dir.join(if cfg!(windows) { "beads.exe" } else { "beads" }))
        .find(|cand| cand.is_file() && cand.canonicalize().ok() != me)
}

/// Decide whether to forward; returns the exit code if the command ran in
/// the legacy binary.
pub fn maybe_delegate(args: &[OsString]) -> Option<i32> {
    if disabled() || std::env::var_os("BD_DB").is_some() {
        return None;
    }
    let depth: u32 = std::env::var("BD_DELEGATION_DEPTH").ok().and_then(|v| v.parse().ok()).unwrap_or(0);
    if depth >= MAX_DEPTH {
        return None;
    }
    let scan = scan(args.get(1..).unwrap_or_default());
    let sub = scan.subcommand.as_deref()?;
    if scan.explicit_db || NATIVE_ONLY.contains(&sub) {
        return None;
    }
    let cwd = std::env::current_dir().ok()?;
    let start = match &scan.directory {
        Some(d) if d.is_absolute() => d.clone(),
        Some(d) => cwd.join(d),
        None => cwd,
    };
    match nearest_workspace(&start) {
        Workspace::Legacy(_) => {}
        Workspace::None if std::env::var_os("BEADS_DIR").is_some() => {}
        _ => return None,
    }
    let Some(bin) = legacy_binary() else {
        eprintln!(
            "bd: {} uses a Go-beads workspace (.beads/) but the legacy `beads` binary is not on PATH; \
             set BD_LEGACY_BIN, or BD_LEGACY_FALLBACK=0 to silence this",
            start.display()
        );
        return None;
    };
    let mut cmd = Command::new(&bin);
    cmd.args(&args[1..]).env("BD_DELEGATION_DEPTH", (depth + 1).to_string());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        eprintln!("bd: failed to run legacy {}: {err}", bin.display());
        Some(127)
    }
    #[cfg(not(unix))]
    {
        Some(cmd.status().map(|s| s.code().unwrap_or(1)).unwrap_or(127))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn scan_finds_subcommand_past_value_flags() {
        let s = scan(&os(&["--actor", "x", "-C", "/tmp/w", "--json", "ready", "--limit", "3"]));
        assert_eq!(s.subcommand.as_deref(), Some("ready"));
        assert_eq!(s.directory, Some(PathBuf::from("/tmp/w")));
        assert!(!s.explicit_db);
        assert!(scan(&os(&["--db=/x.db", "list"])).explicit_db);
        assert!(scan(&os(&["--db", "/x.db", "list"])).explicit_db);
        assert_eq!(scan(&os(&["--json"])).subcommand, None);
    }

    #[test]
    fn nearest_workspace_prefers_closest_and_native() {
        let root = std::env::temp_dir().join(format!("bd-legacy-test-{}", std::process::id()));
        let inner = root.join("a").join("b");
        std::fs::create_dir_all(&inner).unwrap();
        std::fs::create_dir_all(root.join(".beads")).unwrap();
        assert_eq!(nearest_workspace(&inner), Workspace::Legacy(root.join(".beads")));
        std::fs::create_dir_all(root.join("a").join(".bd")).unwrap();
        std::fs::write(root.join("a").join(".bd").join("bd.db"), b"").unwrap();
        assert_eq!(nearest_workspace(&inner), Workspace::Native(root.join("a").join(".bd").join("bd.db")));
        std::fs::create_dir_all(root.join(".bd")).unwrap();
        std::fs::write(root.join(".bd").join("bd.db"), b"").unwrap();
        assert_eq!(nearest_workspace(&root), Workspace::Native(root.join(".bd").join("bd.db")));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
