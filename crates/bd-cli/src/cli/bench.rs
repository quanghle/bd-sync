//! `bd bench`.

use std::path::PathBuf;

use clap::{Args, ValueEnum};

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum BenchMode {
    /// Worker threads in this process, one connection each (embedded library)
    Threads,
    /// One long-lived worker process each (cross-process locking)
    Processes,
    /// A fresh `bd` process per claim and close (what CLI agents experience)
    Cli,
    /// Like `cli`, but every command goes through a scratch `bd serve` (HTTP, access token, server)
    Remote,
}

#[derive(Args, Debug, Clone)]
pub struct BenchArgs {
    /// Concurrent workers
    #[arg(short, long, default_value_t = 8)]
    pub workers: usize,
    #[arg(long, value_enum, default_value = "threads")]
    pub mode: BenchMode,
    /// Issues to seed
    #[arg(short = 'n', long, default_value_t = 2000)]
    pub issues: usize,
    /// Average blocking dependencies per issue (random DAG)
    #[arg(long, default_value_t = 1.0)]
    pub deps: f64,
    /// Simulated work per claim
    #[arg(long, default_value_t = 0, value_name = "MS")]
    pub work_ms: u64,
    /// Heartbeat once per claim before closing
    #[arg(long)]
    pub heartbeat: bool,
    /// Durability (off | normal | full)
    #[arg(long, default_value = "normal")]
    pub durability: String,
    /// Keep the scratch database at this path instead of a temp dir (remote mode: <root>/<name>/.bd/bd.db)
    #[arg(long)]
    pub keep: Option<PathBuf>,
    /// RNG seed for the generated graph
    #[arg(long, default_value_t = 42)]
    pub seed: u64,
}

#[derive(Args, Debug, Clone)]
pub struct BenchWorkerArgs {
    #[arg(long)]
    pub path: PathBuf,
    #[arg(long)]
    pub name: String,
    #[arg(long, default_value_t = 0)]
    pub work_ms: u64,
    #[arg(long)]
    pub heartbeat: bool,
    #[arg(long, default_value = "normal")]
    pub durability: String,
}
