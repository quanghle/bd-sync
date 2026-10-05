//! `bd remote`: set, show, unset, login and logout.

use std::path::{Path, PathBuf};
use std::time::Duration;

use bd_core::{Error, Result};
use serde_json::{Value, json};

use super::config::{RemoteFile, Token, check_url, missing_token, remote_file, token_for};
use super::renew::{Revocation, revoke_saved, trust_for};
use super::{Configured, Remote, Source, Trust, configured, env, identity, response_error};
use crate::app::{App, Out};
use crate::cli::*;
use crate::credentials::{self, Renewal, Scope};
use crate::io;
use crate::playbooks;
use crate::protocol::ExecRequest;

pub fn cmd_remote(app: &mut App, cmd: &RemoteCommand) -> Result<i32> {
    io::require_local("bd remote")?;
    match cmd {
        RemoteCommand::Set(a) => set(app, a).map(|_| 0),
        RemoteCommand::Show => show(app),
        RemoteCommand::Unset => unset(app).map(|_| 0),
        RemoteCommand::Login(a) => login(app, a).map(|_| 0),
        RemoteCommand::Logout(a) => logout(app, a).map(|_| 0),
    }
}

/// The `.bd` directory `bd remote set` writes to: the nearest one, else `./.bd`.
fn config_dir(start: &Path) -> PathBuf {
    start.ancestors().map(|d| d.join(".bd")).find(|d| d.is_dir()).unwrap_or_else(|| start.join(".bd"))
}

fn set(app: &mut App, a: &RemoteSetArgs) -> Result<()> {
    no_extra_args("set", &a.extra)?;
    let url = check_url(url_arg(&a.url, "https://host[:port]/w/<workspace>")?)?;
    let dir = config_dir(&app.cwd);
    let db = dir.join("bd.db");
    if db.is_file() && !a.force {
        return Err(Error::Refused(format!(
            "{0} is a local workspace, which a remote.toml next to it would hide. Move its issues to the server first \
             (`bd --db {0} export -o issues.jsonl`, then `bd import issues.jsonl` with an admin token), then pass \
             --force",
            db.display()
        )));
    }
    let pem = match &a.ca_cert {
        Some(src) => {
            let src = if src.is_relative() { app.cwd.join(src) } else { src.clone() };
            let pem = std::fs::read(&src).map_err(|e| Error::invalid(format!("--ca-cert {}: {e}", src.display())))?;
            if !ureq::tls::parse_pem(&pem).any(|item| matches!(item, Ok(ureq::tls::PemItem::Certificate(_)))) {
                return Err(Error::invalid(format!("--ca-cert {}: no PEM certificate in the file", src.display())));
            }
            Some(pem)
        }
        None => None,
    };
    std::fs::create_dir_all(&dir)?;
    crate::commands::write_bd_gitignore(&dir)?;
    // The CA certificate is public: it goes next to remote.toml, so the checkout can commit both.
    let ca_cert = match pem {
        Some(pem) => {
            std::fs::write(dir.join("ca.pem"), pem)?;
            Some(PathBuf::from("ca.pem"))
        }
        None => None,
    };
    let path = dir.join("remote.toml");
    let body = toml::to_string(&RemoteFile { url: url.clone(), ca_cert: ca_cert.clone() })
        .map_err(|e| Error::invalid(format!("remote.toml: {e}")))?;
    std::fs::write(
        &path,
        format!(
            "# Commands in this checkout run on a bd server; `bd remote show` checks the connection.\n\
             # The access token comes from `bd remote login` ($BD_TOKEN goes only to $BD_REMOTE): never commit it.\n{body}"
        ),
    )?;
    let checkout = dir.parent().unwrap_or(&dir).display().to_string();
    let mut out = Out::new(json!({ "path": path, "url": url, "ca_cert": ca_cert.as_ref().map(|c| dir.join(c)) }))
        .line(format!("✓ Commands under {checkout} now run on {url}"))
        .line(format!("  wrote {}{}", path.display(), if ca_cert.is_some() { " and ca.pem" } else { "" }));
    if app.g.remote.is_some() {
        out = out.line("  note: --remote or $BD_REMOTE is set, and takes precedence over this file");
    }
    let ca_path = ca_cert.as_ref().map(|c| dir.join(c));
    let trust = Trust::load(ca_path.as_deref()).ok();
    let token = trust.as_ref().and_then(|t| token_for(&url, t, &Source::File(path.clone())).ok().flatten());
    out = out.line(if token.is_some() {
        "  check the connection: bd remote show"
    } else {
        "  next: `bd remote login --provider <name>` to sign in, or `bd remote login` with a token \
         (or set BD_TOKEN with BD_REMOTE); then `bd remote show` checks the connection"
    });
    if let (Some(trust), Some(token), None) = (trust, token, &app.g.remote) {
        let c = Configured { url: url.clone(), source: Source::File(path.clone()), ca_cert: ca_path };
        if let Some(hint) = agents_hint(app, Remote::new(c, trust, token.secret())) {
            out = out.line(hint);
        }
    }
    app.print(out.id(url));
    Ok(())
}

/// How long `bd remote set` and `bd remote login` wait for the server's agent manifests.
const HINT_BUDGET: Duration = Duration::from_secs(3);

/// The line `bd remote set` and `bd remote login` add when the workspace
/// serves agent assets: for which harnesses, and the pull that places them
/// in the checkout before the first agent session (no harness is known
/// yet, so nothing is pulled). `None` when nothing is served, or no usable
/// answer came within [`HINT_BUDGET`].
fn agents_hint(app: &App, remote: Remote) -> Option<String> {
    use bd_core::agents::{Harness, Manifest};
    let remote = remote.quick().within(HINT_BUDGET);
    let argv = ["--json", "agents", "manifest"].map(String::from).to_vec();
    let response = playbooks::server_read(app, &remote, argv).ok().filter(|r| r.exit_code == 0)?;
    let manifests: std::collections::BTreeMap<Harness, Manifest> = serde_json::from_str(&response.stdout).ok()?;
    let served: Vec<&str> = manifests
        .iter()
        .filter(|(h, m)| m.harness == **h && m.check().is_ok() && !m.is_empty())
        .map(|(h, _)| h.name())
        .collect();
    let harness = match served[..] {
        [] => return None,
        [one] => one.to_string(),
        _ => format!("<{}>", served.join("|")),
    };
    Some(format!(
        "  agent assets are served for {}: `bd agents pull --harness {harness}` (for each harness used here) places \
         them in this checkout before the first agent session",
        served.join(", ")
    ))
}

fn show(app: &mut App) -> Result<i32> {
    let Some(c) = configured(app)? else {
        let local = app.db_path().ok();
        let line = match &local {
            Some(p) => format!("No remote workspace: commands here use the local database {}", p.display()),
            None => "No workspace here: `bd remote set <url>` uses a bd server, `bd init` creates a local one".into(),
        };
        app.print(Out::new(json!({ "remote": null, "local": local })).line(line));
        return Ok(0);
    };
    let token = Trust::load(c.ca_cert.as_deref()).and_then(|trust| Ok((token_for(&c.url, &trust, &c.source)?, trust)));
    let source = match &c.source {
        Source::Flag => "--remote or $BD_REMOTE".to_string(),
        Source::File(p) => p.display().to_string(),
    };
    let mut view = json!({
        "url": c.url,
        "source": source,
        "ca_cert": c.ca_cert,
        "token_set": matches!(token, Ok((Some(_), _))),
        "token_from": null,
        "credentials": null,
    });
    let mut lines = vec![format!("remote      {}", c.url), format!("from        {source}")];
    if let Some(ca) = &c.ca_cert {
        lines.push(format!("ca cert     {}", ca.display()));
    }
    lines.push(match &token {
        Ok((Some(Token::Env(_)), _)) => {
            view["token_from"] = json!("env");
            "token       $BD_TOKEN".to_string()
        }
        Ok((Some(Token::Saved(s)), _)) => {
            view["token_from"] = json!("credentials");
            let renewal =
                s.renewal.as_ref().map(|r| json!({ "refresh_after": r.refresh_after, "expires_at": r.expires_at }));
            view["credentials"] =
                json!({ "path": s.path, "key": s.key, "scope": s.scope.as_str(), "renewal": renewal });
            let renewed = match &s.renewal {
                Some(r) => format!(" (renewed automatically, next after {})", r.refresh_after),
                None => String::new(),
            };
            format!("token       saved for {} in {}{renewed}", s.key, s.path.display())
        }
        Ok((None, _)) => "token       none: run `bd remote login`, or set BD_TOKEN with BD_REMOTE".to_string(),
        Err(_) => "token       not usable".to_string(),
    });
    if let (Some(_), Source::File(_), Ok((Some(Token::Saved(_)), _))) = (env("BD_TOKEN"), &c.source, &token) {
        lines.push("note        $BD_TOKEN is set, and goes only to a server named by --remote or $BD_REMOTE".into());
    }
    let checked = match token {
        Ok((Some(t), trust)) => check(t.remote(c.clone(), trust).quick(), identity()),
        Ok((None, trust)) => Err(missing_token(&c.url, trust.path.as_deref())),
        Err(e) => Err(e),
    };
    let code = match checked {
        Ok(info) => {
            let s = |k: &str| info[k].as_str().map(String::from).unwrap_or_else(|| info[k].to_string());
            lines.push(format!("server      bd {}, schema v{}", s("version"), s("schema_version")));
            lines.push(format!(
                "workspace   prefix {}, {} issues, events head {}",
                s("prefix"),
                s("issues"),
                s("events_head")
            ));
            lines.push(format!("actor       {}", s("actor")));
            if info["token"].is_object() {
                lines.push(format!("access      {}", crate::tokens::access_line(&info["token"])));
            }
            lines.push("✓ connected".into());
            view["connected"] = json!(true);
            view["server"] = info;
            0
        }
        Err(e) => {
            lines.push(format!("✗ {e}"));
            view["connected"] = json!(false);
            view["error"] = json!({ "code": e.code(), "message": e.to_string(), "exit_code": e.exit_code() });
            e.exit_code()
        }
    };
    // The server's info and errors are its own text: escaped, as anything a server sends.
    app.print(Out::new(view).lines(lines.iter().map(|l| crate::agents::show::printable(l))));
    Ok(code)
}

/// `bd info` on the server: proves that the URL, certificate, token and actor all work.
fn check(remote: Remote, (actor, session): (Option<String>, Option<String>)) -> Result<Value> {
    let request = ExecRequest {
        argv: vec!["info".into(), "--json".into()],
        actor,
        session,
        location: Some(remote.url.clone()),
        ..Default::default()
    };
    let response = remote.exec(&request)?;
    if response.exit_code != 0 {
        return Err(response_error(&response, &remote.url));
    }
    Ok(serde_json::from_str(&response.stdout)?)
}

fn unset(app: &mut App) -> Result<()> {
    let mut out = match remote_file(&app.cwd) {
        Some(path) => {
            std::fs::remove_file(&path)?;
            let mut out = Out::new(json!({ "removed": path })).line(format!("✓ Removed {}", path.display()));
            if let Some(db) = path.parent().map(|d| d.join("bd.db")).filter(|db| db.is_file()) {
                out = out.line(format!("  commands here use the local database {} again", db.display()));
            }
            out
        }
        None => Out::new(json!({ "removed": null })).line("= No .bd/remote.toml applies here"),
    };
    if app.g.remote.is_some() {
        out = out.line("  note: --remote or $BD_REMOTE is still set, and keeps commands remote");
    }
    app.print(out);
    Ok(())
}

fn no_remote_here(command: &str) -> Error {
    Error::invalid(format!(
        "no remote workspace here: pass its URL (`bd remote {command} https://bd.example.com/w/proj`), or run `bd \
         remote set <url>` first"
    ))
}

/// The workspace `bd remote login` checks a token against: `url`, else the configured one.
fn login_target(app: &App, url: Option<&str>) -> Result<Configured> {
    let configured = configured(app);
    let Some(raw) = url else { return configured?.ok_or_else(|| no_remote_here("login")) };
    let url = check_url(url_arg(raw, "https://host[:port]/w/<workspace>")?)?;
    let same = |c: &Configured| credentials::keys(&c.url).ok() == credentials::keys(&url).ok();
    let ca_cert = match configured {
        Ok(Some(c)) if same(&c) => c.ca_cert,
        _ => env("BD_CA_CERT").map(PathBuf::from),
    };
    Ok(Configured { url, source: Source::Flag, ca_cert })
}

/// A URL argument of `bd remote login/logout`. Anything but a plain URL is
/// refused without repeating it: it may be a token pasted in the wrong place.
fn url_arg<'a>(raw: &'a str, expected: &str) -> Result<&'a str> {
    let arg = raw.trim();
    if looks_like_token(arg) {
        return Err(Error::invalid(format!(
            "that argument looks like an access token: never pass one on the command line, where shell history \
             keeps it (consider revoking it); {}",
            how_to_pipe()
        )));
    }
    if !arg.contains("://") || arg.chars().any(char::is_whitespace) {
        return Err(Error::invalid(format!("the URL argument is not a URL; expected {expected}")));
    }
    Ok(arg)
}

/// Refuse arguments after the URL without repeating them: clap would echo
/// a token pasted there.
fn no_extra_args(command: &str, extra: &[String]) -> Result<()> {
    if extra.is_empty() {
        return Ok(());
    }
    Err(Error::invalid(format!(
        "bd remote {command} takes one URL and never a token on the command line, where shell history keeps it (if \
         you passed one, consider revoking it); {}",
        how_to_pipe()
    )))
}

/// `bdt_<hex>`, the secrets `bd serve token create` prints.
fn looks_like_token(arg: &str) -> bool {
    arg.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("bdt_"))
}

fn login(app: &mut App, a: &RemoteLoginArgs) -> Result<()> {
    no_extra_args("login", &a.extra)?;
    let c = login_target(app, a.url.as_deref())?;
    let scope = if a.workspace_only { Scope::Workspace } else { Scope::Server };
    let keys = credentials::keys(&c.url)?;
    let path = credentials::default_path()?;
    let trust = Trust::load(c.ca_cert.as_deref())?;
    let (token, signed_in) = if let Some(provider) = a.provider.clone() {
        let workspace = c.url.rsplit_once("/w/").map_or("", |(_, w)| w);
        let remote = Remote::new(c.clone(), trust.clone(), String::new());
        let issued = super::sign_in::sign_in(&remote, workspace, &keys.server, &provider)?;
        credentials::check_token(&issued.token)
            .map_err(|_| Error::Remote(format!("{}: unexpected sign-in answer: not an access token", keys.server)))?;
        (issued.token.clone(), Some(issued))
    } else {
        let label = match scope {
            Scope::Server => keys.server.clone(),
            Scope::Workspace => c.url.clone(),
        };
        let label = match &trust.path {
            Some(ca) => format!("{label}, trusting the CA certificate {}", ca.display()),
            None => label,
        };
        let token = read_token(&label)?;
        credentials::check_token(&token)?;
        (token, None)
    };
    let actor = match &signed_in {
        Some(issued) => Some(issued.actor.clone()),
        None if a.no_verify => None,
        None => {
            // The token alone: $BD_ACTOR is checked per command, not saved.
            let info = check(Remote::new(c.clone(), trust.clone(), token.clone()).quick(), (None, None)).map_err(
                |e| match e {
                    Error::Unauthorized(m) => Error::Unauthorized(format!("{m}; nothing was saved")),
                    Error::Remote(m) => Error::Remote(format!(
                        "{m}; nothing was saved (--no-verify saves the token without checking it)"
                    )),
                    e => e,
                },
            )?;
            info["actor"].as_str().map(String::from)
        }
    };
    let renewal = signed_in.as_ref().and_then(|issued| {
        let refresh = issued.refresh_token.clone().filter(|t| credentials::check_token(t).is_ok())?;
        Some(Renewal::new(refresh, Duration::from_secs(issued.expires_in.max(1))))
    });
    let saved = credentials::save(&path, &c.url, &token, &trust.anchor, scope, signed_in.is_some(), renewal.as_ref())?;
    // A sign-in token this one takes the place of ends on its server too (unless no server is to be asked).
    let revoke = |gone: &credentials::Gone| {
        (gone.signed_in && gone.token != token).then(|| match a.no_verify {
            true => Revocation::NotRevoked("--no-verify asks no server".into()),
            false => revoke_saved(gone, Some(&trust)),
        })
    };
    let replaced = saved.replaced.as_ref().map(|gone| (gone, revoke(gone)));
    let dropped = saved.dropped.as_ref().map(|gone| (gone, revoke(gone)));
    let revocations: Vec<Value> = replaced
        .iter()
        .chain(dropped.iter())
        .filter_map(|(gone, revocation)| revocation.as_ref().map(|r| r.view(&gone.key)))
        .collect();
    let reach = match scope {
        Scope::Server => format!("{} (every workspace it allows there)", saved.key),
        Scope::Workspace => saved.key.clone(),
    };
    let mut view = json!({
        "url": c.url,
        "path": path,
        "key": saved.key,
        "scope": scope.as_str(),
        "verified": !a.no_verify,
        "actor": actor,
        "replaced": replaced.is_some(),
        "dropped": dropped.as_ref().map(|(gone, _)| &gone.key),
        "revocations": revocations,
        "ca_cert": c.ca_cert,
    });
    if let Some(issued) = &signed_in {
        view["account"] = json!({ "login": issued.login, "via": issued.via });
        view["token"] = json!({
            "name": issued.name,
            "role": issued.role,
            "kind": issued.kind,
            "workspaces": issued.workspaces,
            "max_claims": issued.max_claims,
            "expires_at": issued.expires_at,
            "refreshable_until": renewal.as_ref().and(issued.refreshable_until.as_ref()),
        });
    }
    let saved_line = format!("✓ Saved the access token for {reach} in {}", path.display());
    let mut out = match &signed_in {
        Some(issued) => {
            use crate::agents::show::printable;
            let mut workspaces = match issued.workspaces.iter().any(|w| w == "*") {
                true => "all".to_string(),
                false => issued.workspaces.join(","),
            };
            if let Some(n) = issued.max_claims {
                workspaces.push_str(&format!(", at most {n} claims"));
            }
            let renewed = match (&renewal, &issued.refreshable_until) {
                (Some(_), Some(until)) => format!(", renewed automatically until {until}"),
                _ => String::new(),
            };
            Out::new(view)
                .line(format!("✓ Signed in as {} ({})", printable(&issued.login), printable(&issued.via)))
                .line(saved_line)
                .line(printable(&format!(
                    "  acts as {0} or {0}/<agent>, role {1}, kind {2}, workspaces {workspaces}; expires {3}{renewed}",
                    issued.actor, issued.role, issued.kind, issued.expires_at
                )))
        }
        None => Out::new(view).line(saved_line).line(match &actor {
            Some(actor) => format!("  {} accepts it, as actor {actor}", c.url),
            None => "  not checked (--no-verify): `bd remote show` checks it".to_string(),
        }),
    };
    if let Some(ca) = &c.ca_cert {
        out = out.line(format!("  bound to the CA certificate {}: it is not sent trusting any other", ca.display()));
    }
    if let Some((_, revocation)) = &replaced {
        out = out.line("  it replaces the token saved there before");
        out = out.lines(revocation.iter().map(Revocation::line));
    }
    if let Some((gone, revocation)) = &dropped {
        out = out.line(format!("  removed the token saved for {} only, which would have taken precedence", gone.key));
        out = out.lines(revocation.iter().map(Revocation::line));
    }
    if let Some(mode) = saved.loose_mode {
        out = out.line(format!(
            "  note: other users could read this file (mode {mode:03o}); it is private now, but consider revoking the \
             tokens it held"
        ));
    }
    if env("BD_TOKEN").is_some() {
        out = out.line("  note: $BD_TOKEN is set, and takes precedence over saved tokens for the server named by --remote or $BD_REMOTE");
    }
    let here = configured(app).ok().flatten().is_some_and(|here| here.url == c.url);
    if !a.no_verify
        && here
        && let Some(hint) = agents_hint(app, Remote::new(c, trust, token))
    {
        out = out.line(hint);
    }
    app.print(out.id(saved.key));
    Ok(())
}

fn logout(app: &mut App, a: &RemoteLogoutArgs) -> Result<()> {
    no_extra_args("logout", &a.extra)?;
    let url = match &a.url {
        Some(url) => url_arg(url, "https://host[:port][/prefix][/w/<workspace>]")?.to_string(),
        None => configured(app)?.ok_or_else(|| no_remote_here("logout"))?.url,
    };
    let path = credentials::default_path()?;
    let r = credentials::remove(&path, &url, a.workspace_only)?;
    // A token from GitHub sign-in ends on its server too; one an admin created may serve elsewhere, and stays.
    let trust = if r.removed.iter().any(|gone| gone.signed_in) { trust_for(app, &url) } else { None };
    let revocations: Vec<Option<Revocation>> =
        r.removed.iter().map(|gone| gone.signed_in.then(|| revoke_saved(gone, trust.as_ref()))).collect();
    let keys: Vec<&str> = r.removed.iter().map(|gone| gone.key.as_str()).collect();
    let views: Vec<Value> = r
        .removed
        .iter()
        .zip(&revocations)
        .filter_map(|(gone, revocation)| revocation.as_ref().map(|r| r.view(&gone.key)))
        .collect();
    let mut out =
        Out::new(json!({ "path": path, "removed": keys, "file_removed": r.file_removed, "revocations": views }));
    if r.removed.is_empty() {
        out = out.line(format!("= No access token saved for {}", url.trim()));
    }
    for (gone, revocation) in r.removed.iter().zip(&revocations) {
        out = out.line(format!("✓ Removed the access token saved for {}", gone.key)).id(gone.key.clone());
        out = out.lines(revocation.iter().map(Revocation::line));
    }
    if r.file_removed {
        out = out.line(format!("  removed {}, which is empty now", path.display()));
    }
    if r.removed.iter().any(|gone| !gone.signed_in) {
        out = out.line(
            "  the server still accepts a token its admin created until it is revoked there (`bd serve token revoke`)",
        );
    }
    if env("BD_TOKEN").is_some() {
        out = out.line("  note: $BD_TOKEN is still set, and keeps providing a token for the server named by --remote or $BD_REMOTE");
    }
    app.print(out);
    Ok(())
}

/// The token to save: piped on stdin, or typed at a prompt that does not echo it.
fn read_token(label: &str) -> Result<String> {
    use std::io::IsTerminal;
    let text = if std::io::stdin().is_terminal() {
        prompt_hidden(&format!("Access token for {label} (input hidden): "))?
    } else {
        io::read_stdin()?
    };
    let token = text.trim();
    if token.is_empty() {
        return Err(Error::invalid(format!("no access token given; {}", how_to_pipe())));
    }
    Ok(token.to_string())
}

fn how_to_pipe() -> &'static str {
    if cfg!(windows) {
        "pipe it in, e.g. `Read-Host -MaskInput Token | bd remote login` in PowerShell 7"
    } else {
        "pipe it in, e.g. `printf %s \"$TOKEN\" | bd remote login`, or run it in a terminal to be prompted"
    }
}

/// Read a line from the terminal on stdin with echo turned off by `stty`.
/// Only for the machine-local `bd remote login`, so it uses the process's
/// stdio directly.
#[cfg(unix)]
fn prompt_hidden(prompt: &str) -> Result<String> {
    use std::io::{BufRead, Write};
    use std::process::{Command, Stdio};
    let stty = |arg: &str| {
        Command::new("stty")
            .arg(arg)
            .stdin(Stdio::inherit())
            .stderr(Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
    };
    struct Restore(String);
    impl Drop for Restore {
        fn drop(&mut self) {
            let _ = Command::new("stty").arg(&self.0).stdin(Stdio::inherit()).stderr(Stdio::null()).status();
        }
    }
    let saved = stty("-g").map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()).filter(|s| !s.is_empty());
    let Some(restore) = saved.map(Restore) else {
        return Err(Error::invalid(format!("cannot turn off echo on this terminal; {}", how_to_pipe())));
    };
    if stty("-echo").is_none() {
        return Err(Error::invalid(format!("cannot turn off echo on this terminal; {}", how_to_pipe())));
    }
    let mut stderr = std::io::stderr();
    // The label comes from a checkout's remote.toml, so it must not redraw the prompt.
    let _ = write!(stderr, "{}", io::printable(prompt));
    let _ = stderr.flush();
    let mut line = String::new();
    let read = std::io::stdin().lock().read_line(&mut line);
    drop(restore);
    let _ = writeln!(stderr);
    read?;
    Ok(line)
}

#[cfg(not(unix))]
fn prompt_hidden(_: &str) -> Result<String> {
    Err(Error::invalid(format!("bd remote login does not prompt on this system; {}", how_to_pipe())))
}
