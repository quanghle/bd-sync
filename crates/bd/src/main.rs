//! The `bd` binary: `bd-cli`'s commands, with `bd serve` from `bd-server`
//! and `bd bench`, which drives both.

mod bench;

use bd_cli::app::App;
use bd_cli::cli::{Cli, Command};
use bd_core::{Error, Result};
use clap::Parser;

fn main() {
    let cli = Cli::parse();
    // A server logs one line per request unless BD_LOG says otherwise.
    let default_filter = if matches!(cli.command, Command::Serve(_)) { "warn,bd::serve=info" } else { "warn" };
    bd_cli::logging::init(cli.global.log_format, default_filter);
    bd_cli::set_handler(handle);
    std::process::exit(bd_cli::run(cli));
}

/// The commands `bd-cli` hands back to the binary.
fn handle(app: &mut App, cmd: &Command) -> Result<i32> {
    match cmd {
        Command::Serve(a) => bd_server::serve::cmd_serve(app, a).map(|_| 0),
        Command::Bench(a) => bench::cmd_bench(app, a).map(|_| 0),
        Command::BenchWorker(a) => bench::cmd_bench_worker(a).map(|_| 0),
        _ => Err(Error::invalid(format!("bd {} is not handled by the binary", bd_cli::command_name(cmd)))),
    }
}
