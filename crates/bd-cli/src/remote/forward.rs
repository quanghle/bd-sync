//! Forwarding a command line to the server, with the stdin and input files
//! it reads; `bd prime` in session hooks.

use std::io::Write;
use std::path::{Path, PathBuf};

use bd_core::{Error, Result};

use super::delivery::{Delivery, OutputFile};
use super::events::{follow_events, wait_for_events};
use super::{Remote, identity, response_error, without_session_flag};
use crate::app::App;
use crate::cli::*;
use crate::io;
use crate::playbooks;
use crate::protocol::{ExecRequest, ExecResponse};
use crate::tokens::random_hex;

/// `bd prime` in text mode, or with `--hook`: session hooks run it, so it
/// gives up within the hook's budget (even against a server that accepts
/// the connection and never answers) and reports an unavailable workspace as context instead
/// of failing the hook.
pub fn is_hook(cli: &Cli) -> bool {
    matches!(&cli.command, Command::Prime(a) if a.hook.is_some() || !cli.global.json)
}

/// What `bd prime` prints in place of workspace context when the remote
/// workspace cannot be used, in the format of the hook running it
/// (`--hook`). Exits 0, so the session hook still succeeds.
pub fn unavailable(cli: &Cli, e: &Error) -> i32 {
    let harness = match &cli.command {
        Command::Prime(a) => a.hook,
        _ => None,
    };
    let text = format!(
        "# bd workflow context\nThe remote bd workspace is unavailable: {}\nbd commands fail until this is fixed; `bd \
         remote show` checks the connection and the access token (BD_TOKEN or `bd remote login`).",
        crate::agents::show::printable(&e.to_string())
    );
    crate::hook::print_context(harness, crate::hook::Event::SessionStart, &text);
    0
}

/// Run the command on the server; returns the process exit code.
pub fn run(app: &mut App, remote: Remote, cli: &Cli) -> i32 {
    let hook = is_hook(cli);
    let remote = if hook { remote.quick().within(crate::agents::hook::server_budget(app)) } else { remote };
    match forward(app, &remote, cli, hook) {
        Ok(response) if hook && response.exit_code != 0 => unavailable(cli, &response_error(&response, &remote.url)),
        Ok(response) => {
            io::out(&response.stdout);
            let _ = std::io::stderr().write_all(io::printable(&response.stderr).as_bytes());
            response.exit_code
        }
        Err(e) if hook => unavailable(cli, &e),
        Err(e) => crate::report(&e, app.g.json),
    }
}

/// Run the command remotely. Output files are written as they arrive, and
/// stdout printed if it is long; the result holds the rest, to print.
fn forward(app: &App, remote: &Remote, cli: &Cli, hook: bool) -> Result<ExecResponse> {
    match &cli.command {
        Command::Init(_) => {
            return Err(Error::Refused(format!(
                "this workspace is remote ({}); bd init creates a local one, so run it elsewhere or remove the remote \
                 configuration (`bd remote unset`)",
                remote.url
            )));
        }
        Command::Events(a) if a.follow => {
            let code = follow_events(app, remote, a)?;
            return Ok(ExecResponse { exit_code: code, ..Default::default() });
        }
        Command::Events(a @ EventsArgs { action: None, since: Some(since), wait: Some(wait), .. }) => {
            let code = wait_for_events(app, remote, a, *since, *wait)?;
            return Ok(ExecResponse { exit_code: code, ..Default::default() });
        }
        Command::Playbook(cmd) => {
            if let Some(code) = playbooks::client_command(app, remote, cmd)? {
                return Ok(ExecResponse { exit_code: code, ..Default::default() });
            }
        }
        Command::Agents(cmd) => {
            if let Some(code) = crate::agents::client_command(app, remote, cmd)? {
                return Ok(ExecResponse { exit_code: code, ..Default::default() });
            }
        }
        _ => {}
    }
    let mut argv = std::env::args_os()
        .skip(1)
        .map(|a| a.into_string().map_err(|a| Error::invalid(format!("argument {a:?} is not valid UTF-8"))))
        .collect::<Result<Vec<_>>>()?;
    if app.g.session.is_some() {
        argv = without_session_flag(argv);
    }
    let (actor, session) = identity();
    let mut request = ExecRequest {
        argv,
        actor,
        session,
        request_id: Some(random_hex(16)?),
        location: Some(remote.url.clone()),
        ..Default::default()
    };
    attach_inputs(&cli.command, &mut request)?;
    playbooks::attach_bundle(app, &cli.command, &mut request)?;
    playbooks::attach_listing(app, &cli.command, &mut request);
    check_outputs(app, &cli.command)?;
    // A session hook prints `bd prime` only once it knows the command worked.
    let write = crate::cli::access(&cli.command) == crate::cli::Access::Write;
    remote.exec_into(&request, &mut Delivery::new(output_files(app, &cli.command), hook, write))
}

/// Send the stdin and input files the command reads; the server never reads its own files for a client.
fn attach_inputs(cmd: &Command, request: &mut ExecRequest) -> Result<()> {
    fn attach(request: &mut ExecRequest, path: &str) -> Result<()> {
        if path == "-" {
            request.stdin = Some(io::read_stdin()?);
        } else {
            request.files.insert(path.to_string(), io::read_file(Path::new(path))?);
        }
        Ok(())
    }
    match cmd {
        Command::Import(a) => attach(request, &a.file),
        Command::Batch(a) => match &a.file {
            Some(f) => {
                request.files.insert(f.to_string_lossy().into_owned(), io::read_file(f)?);
                Ok(())
            }
            None => attach(request, "-"),
        },
        Command::Comment(CommentCommand::Add(a)) if a.stdin => attach(request, "-"),
        Command::Comment(CommentCommand::Add(a)) => match &a.file {
            Some(f) => attach(request, &f.to_string_lossy()),
            None => Ok(()),
        },
        _ => Ok(()),
    }
}

fn extract_target(app: &App, path: &Path) -> PathBuf {
    if path.is_relative() { app.cwd.join(path) } else { path.to_path_buf() }
}

fn check_outputs(app: &App, cmd: &Command) -> Result<()> {
    if let Command::Playbook(PlaybookCommand::Extract(ExtractArgs { output: Some(p), force: false, .. })) = cmd {
        let target = extract_target(app, p);
        if target.exists() {
            return Err(Error::Refused(format!("{} exists; pass --force to overwrite", target.display())));
        }
    }
    Ok(())
}

/// The output files the command asked for, written where the local CLI would.
fn output_files(app: &App, cmd: &Command) -> Vec<OutputFile> {
    match cmd {
        Command::Export(ExportArgs { output: Some(path), .. }) => vec![OutputFile::new(path, path.clone(), false)],
        Command::Playbook(PlaybookCommand::Extract(ExtractArgs { output: Some(path), .. })) => {
            vec![OutputFile::new(path, extract_target(app, path), true)]
        }
        _ => Vec::new(),
    }
}
