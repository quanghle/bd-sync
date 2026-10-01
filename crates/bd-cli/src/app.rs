//! Per-invocation context: global options, actor, the open store, output.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use bd_core::{Error, OpenOptions, ReadCtx, Result, Store, TxStats, WriteCtx};
use serde::Serialize;
use serde_json::Value;

use crate::cli::Global;

/// What a command produced, rendered according to --json / --quiet.
pub struct Out {
    pub json: Value,
    pub text: Vec<String>,
    pub ids: Vec<String>,
}

impl Out {
    pub fn new(json: impl Serialize) -> Out {
        Out { json: serde_json::to_value(json).unwrap_or(Value::Null), text: Vec::new(), ids: Vec::new() }
    }

    pub fn line(mut self, s: impl Into<String>) -> Out {
        self.text.push(s.into());
        self
    }

    pub fn lines(mut self, lines: impl IntoIterator<Item = String>) -> Out {
        self.text.extend(lines);
        self
    }

    pub fn id(mut self, id: impl Into<String>) -> Out {
        self.ids.push(id.into());
        self
    }
}

pub struct App {
    pub g: Global,
    pub cwd: PathBuf,
    pub started: Instant,
    actor: Option<String>,
    store: Option<Store>,
    pub open_time: Duration,
    pub tx: Vec<TxStats>,
}

impl App {
    pub fn new(g: Global) -> Result<App> {
        let cwd = match &g.directory {
            Some(d) => resolve_dir(d).map_err(|e| Error::invalid(format!("-C {}: {e}", d.display())))?,
            None => std::env::current_dir()?,
        };
        Ok(App { g, cwd, started: Instant::now(), actor: None, store: None, open_time: Duration::ZERO, tx: Vec::new() })
    }

    pub fn actor(&mut self) -> String {
        if self.actor.is_none() {
            self.actor = Some(resolve_actor(self.g.actor.clone()));
        }
        self.actor.clone().expect("set above")
    }

    pub fn open_options(&self) -> OpenOptions {
        OpenOptions {
            busy_timeout: Duration::from_millis(self.g.busy_timeout_ms),
            slow_threshold: Duration::from_millis(self.g.slow_ms),
            ..Default::default()
        }
    }

    pub fn db_path(&self) -> Result<PathBuf> {
        match &self.g.db {
            Some(p) if p.is_absolute() => Ok(p.clone()),
            Some(p) => Ok(self.cwd.join(p)),
            None => find_workspace(&self.cwd).ok_or_else(|| {
                Error::NoWorkspace(format!(
                    "no bd workspace found in {} or its parents (run `bd init`, or pass --db)",
                    self.cwd.display()
                ))
            }),
        }
    }

    pub fn store(&mut self) -> Result<&mut Store> {
        if self.store.is_none() {
            let t = Instant::now();
            let path = self.db_path()?;
            let store = Store::open(&path, self.open_options())?;
            self.open_time = t.elapsed();
            tracing::debug!(target: "bd::cli", path = %path.display(), open_us = self.open_time.as_micros() as u64, "opened store");
            self.store = Some(store);
        }
        Ok(self.store.as_mut().expect("opened above"))
    }

    pub fn set_store(&mut self, store: Store) {
        self.store = Some(store);
    }

    pub fn write<T>(&mut self, op: &'static str, f: impl FnOnce(&mut WriteCtx<'_>) -> Result<T>) -> Result<T> {
        let actor = self.actor();
        let store = self.store()?;
        let out = store.write(op, &actor, f);
        if let Some(stats) = store.last_tx_stats().cloned() {
            if out.is_ok() {
                self.tx.push(stats);
            }
        }
        out
    }

    pub fn read<T>(&mut self, f: impl FnOnce(&ReadCtx<'_>) -> Result<T>) -> Result<T> {
        self.store()?.read(f)
    }

    pub fn print(&self, out: Out) {
        if self.g.json {
            println!("{}", serde_json::to_string_pretty(&out.json).unwrap_or_default());
        } else if self.g.quiet {
            for id in out.ids {
                println!("{id}");
            }
        } else {
            for line in out.text {
                println!("{line}");
            }
        }
    }

    pub fn print_json(&self, v: &impl Serialize) {
        println!("{}", serde_json::to_string_pretty(v).unwrap_or_default());
    }
}

/// The absolute form of an existing directory given with `-C`.
fn resolve_dir(d: &Path) -> std::io::Result<PathBuf> {
    // canonicalize returns a verbatim `\\?\C:\...` path on Windows, which
    // cmd.exe (and so a `.cmd` BD_GH) refuses as a working directory.
    #[cfg(windows)]
    {
        let p = std::path::absolute(d)?;
        std::fs::metadata(&p)?;
        Ok(p)
    }
    #[cfg(not(windows))]
    {
        std::fs::canonicalize(d)
    }
}

/// Nearest `.bd/bd.db` walking up from `start`.
pub fn find_workspace(start: &Path) -> Option<PathBuf> {
    start.ancestors().map(|d| d.join(".bd").join("bd.db")).find(|p| p.is_file())
}

/// `--actor`, then $BD_ACTOR, $BEADS_ACTOR, `git config user.name`, $USER.
pub fn resolve_actor(flag: Option<String>) -> String {
    let clean = |s: String| {
        let t = s.trim().to_string();
        (!t.is_empty()).then_some(t)
    };
    flag.and_then(clean)
        .or_else(|| std::env::var("BD_ACTOR").ok().and_then(clean))
        .or_else(|| std::env::var("BEADS_ACTOR").ok().and_then(clean))
        .or_else(|| {
            Command::new("git")
                .args(["config", "user.name"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .and_then(|o| String::from_utf8(o.stdout).ok())
                .and_then(clean)
        })
        .or_else(|| std::env::var("USER").ok().and_then(clean))
        .or_else(|| std::env::var("USERNAME").ok().and_then(clean))
        .unwrap_or_else(|| "unknown".into())
}
