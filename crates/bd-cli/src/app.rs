//! Per-invocation context: global options, actor, the open store, output.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use bd_core::{Error, OpenOptions, ReadCtx, Result, Store, TxStats, WriteCtx};
use serde::Serialize;
use serde_json::Value;

use crate::actor;
use crate::cli::Global;
use crate::io;

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

/// The idempotency key of a request served by `bd serve`.
#[derive(Clone, Debug)]
pub struct RequestKey {
    pub id: String,
    /// The access token that sent it.
    pub principal: String,
    /// Set once a committed write transaction recorded the key.
    pub recorded: bool,
}

pub struct App {
    pub g: Global,
    pub cwd: PathBuf,
    pub started: Instant,
    actor: Option<actor::Resolved>,
    store: Option<Store>,
    pub open_time: Duration,
    pub tx: Vec<TxStats>,
    /// Shown instead of the database path (the workspace URL under `bd serve`).
    pub location: Option<String>,
    /// Recorded in the first write transaction, so a retried request applies once.
    pub request: Option<RequestKey>,
}

impl App {
    pub fn new(g: Global) -> Result<App> {
        let cwd = match &g.directory {
            Some(d) => resolve_dir(d).map_err(|e| Error::invalid(format!("-C {}: {e}", d.display())))?,
            None => std::env::current_dir()?,
        };
        Ok(App {
            g,
            cwd,
            started: Instant::now(),
            actor: None,
            store: None,
            open_time: Duration::ZERO,
            tx: Vec::new(),
            location: None,
            request: None,
        })
    }

    pub fn actor(&mut self) -> String {
        self.resolved_actor().actor
    }

    /// The actor, and where it came from (see [`crate::actor`]).
    pub fn resolved_actor(&mut self) -> actor::Resolved {
        if self.actor.is_none() {
            self.actor = Some(actor::resolve(self.g.actor.as_deref()));
        }
        self.actor.clone().expect("set above")
    }

    /// The actor, if a command resolved it already.
    pub fn known_actor(&self) -> Option<&actor::Resolved> {
        self.actor.as_ref()
    }

    /// Run as `actor` (`bd serve` sets each request's).
    pub fn set_actor(&mut self, actor: actor::Resolved) {
        self.g.actor = Some(actor.actor.clone());
        self.actor = Some(actor);
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

    /// Hand back the open store (`bd serve` pools them).
    pub fn take_store(&mut self) -> Option<Store> {
        self.store.take()
    }

    /// Where the workspace lives, for display: the database path, or the
    /// workspace URL when the command runs under `bd serve`.
    pub fn workspace_label(&self) -> Result<String> {
        match &self.location {
            Some(l) => Ok(l.clone()),
            None => Ok(self.db_path()?.display().to_string()),
        }
    }

    pub fn write<T>(&mut self, op: &'static str, f: impl FnOnce(&mut WriteCtx<'_>) -> Result<T>) -> Result<T> {
        let actor = self.actor();
        let key = self.request.as_ref().filter(|k| !k.recorded).map(|k| (k.id.clone(), k.principal.clone()));
        let mut recorded = false;
        // Under bd serve, the engine limits what the request's token may override.
        let policy = io::policy();
        let store = self.store()?;
        let out = store.write(op, &actor, |tx| {
            tx.set_policy(policy);
            let out = f(tx)?;
            if let Some((id, principal)) = &key {
                if !tx.is_rollback_only() {
                    tx.record_request(id, principal, op)?;
                    recorded = true;
                }
            }
            Ok(out)
        });
        if let Some(stats) = store.last_tx_stats().cloned() {
            if out.is_ok() {
                self.tx.push(stats);
            }
        }
        if out.is_ok() && recorded {
            if let Some(k) = self.request.as_mut() {
                k.recorded = true;
            }
        }
        out
    }

    pub fn read<T>(&mut self, f: impl FnOnce(&ReadCtx<'_>) -> Result<T>) -> Result<T> {
        self.store()?.read(f)
    }

    pub fn print(&self, out: Out) {
        if self.g.json {
            io::outln(serde_json::to_string_pretty(&out.json).unwrap_or_default());
        } else if self.g.quiet {
            for id in out.ids {
                io::outln(id);
            }
        } else {
            for line in out.text {
                io::outln(line);
            }
        }
    }

    pub fn print_json(&self, v: &impl Serialize) {
        io::outln(serde_json::to_string_pretty(v).unwrap_or_default());
    }
}

/// The absolute form of an existing directory given with `-C` or
/// `bd serve --root`: canonical on Unix, plain absolute on Windows.
pub fn resolve_dir(d: &Path) -> std::io::Result<PathBuf> {
    // canonicalize returns a verbatim `\\?\C:\...` path on Windows, which
    // cmd.exe (and so a `.cmd` BD_GH) refuses as a working directory, and
    // workspace dirs under `bd serve --root` are the cwd of its gh probes.
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
