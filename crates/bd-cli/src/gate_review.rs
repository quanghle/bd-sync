//! `bd gate review`: a person at a terminal goes through the human gates
//! waiting for them and resolves each one they approve.
//!
//! Only a person runs it ([`people_only`]: no agent session, a terminal on
//! stdin), on the machine where they sit (`Access::Local`). Locally it reads
//! and writes the workspace; in a remote workspace it sends `info`, `gate
//! list`, `gate show` and `gate resolve` to the server with the person's
//! token from the keychain, and nothing else (`remote::detect_for` builds
//! that remote, never from `$BD_TOKEN` or saved credentials).
//!
//! The loop ([`review`]) runs over the [`Gates`] trait, so it is tested with
//! a scripted fake on every OS. Each gate is read again right before it is
//! asked about, and skipped when it is no longer a human gate, is resolved,
//! is not armed, or (remotely) its approvers do not match the token's
//! [`Caller`] by [`policy::approved_by`], the rule the server applies: an
//! account signed in with an OIDC provider matches only the `oidc:sha256:`
//! identity reference of its own issuer and subject, derived from the
//! `token.account` of the server's `info` answer (a malformed account stops
//! the review, never falling back to the actor), and any other token its
//! actor and sub-actors. Every text that came from the store, the server or the
//! configuration is shown escaped to one line, errors included
//! ([`one_line`]), so none can forge a prompt or a link line.

use std::collections::BTreeSet;
use std::io::{BufRead, Write};

use bd_core::gates::{self, GateKind, GatePhase, GateView};
use bd_core::{Error, Queries, Result, Timestamp, issues, policy};
use serde::Serialize;
use serde_json::Value;

use crate::actor::{self, Env};
use crate::agents::approve::{Answer, ask};
use crate::agents::show;
use crate::app::App;
use crate::cli::GateReviewArgs;
use crate::gates::state_text;
use crate::io;
use crate::keychain;
use crate::protocol::{ExecRequest, ExecResponse};
use crate::remote::{Remote, identity, response_error};
use crate::tokens::random_hex;

/// Refuse to review gates unless a person runs it: never inside an agent
/// session (checked first, before anything else is looked at), and only with
/// a terminal on stdin. Nothing gets past either.
pub fn people_only(env: &Env<'_>, terminal: &dyn Fn() -> bool) -> Result<()> {
    actor::refuse_in_agent_session(
        env,
        "bd gate review",
        "opening a human gate is a person's decision. An agent should give the person the gate's approval link (bd \
         gate show or bd prime shows it where the server offers one) or ask them to run `bd gate review` in a \
         separate terminal",
    )?;
    if !terminal() {
        return Err(Error::Refused(
            "bd gate review asks about each gate and runs only in a terminal (stdin is not one)".into(),
        ));
    }
    Ok(())
}

/// `e` with its message escaped to one line, keeping its variant (so its
/// code and exit code), needs and gate. Variants whose text is bd's own come
/// back as they are.
pub(crate) fn one_line(e: Error) -> Error {
    let p = |m: String| show::printable(&m);
    match e {
        Error::Invalid(m) => Error::Invalid(p(m)),
        Error::Refused(m) => Error::Refused(p(m)),
        Error::Busy(m) => Error::Busy(p(m)),
        Error::Locked(m) => Error::Locked(p(m)),
        Error::NoWorkspace(m) => Error::NoWorkspace(p(m)),
        Error::Unauthorized(m) => Error::Unauthorized(p(m)),
        Error::Remote(m) => Error::Remote(p(m)),
        Error::AnswerLost(m) => Error::AnswerLost(p(m)),
        Error::Needs { message, needs, gate } => Error::Needs { message: p(message), needs, gate },
        Error::Approvable(inner) => one_line(*inner).approvable(),
        other => other,
    }
}

/// A gate as read for the review, with the run it is part of.
#[derive(Clone, Debug)]
pub(crate) struct Detail {
    pub view: GateView,
    /// The run (or parent) it is part of: id and title.
    pub part_of: Option<(String, String)>,
}

/// What reading one gate found.
#[derive(Clone, Debug)]
pub(crate) enum Shown {
    Gate(Box<Detail>),
    /// No such gate (or not a gate), and why, escaped.
    Missing(String),
}

/// A gate resolved.
#[derive(Clone, Debug, Default)]
pub(crate) struct Resolved {
    /// It was resolved already (by someone else meanwhile).
    pub already_open: bool,
    /// Issues it freed, and runs that completed: id and title.
    pub unblocked: Vec<(String, String)>,
    pub completed: Vec<(String, String)>,
}

/// A resolve that failed, as its JSON error says.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(crate) struct Failure {
    pub code: String,
    pub message: String,
    pub exit_code: i32,
}

/// Who the server decides approvers by: the token's actor and, for an
/// account signed in with an OIDC provider, its identity reference.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Caller {
    pub actor: String,
    /// The `oidc:sha256:` reference of the token's OIDC account, if any.
    pub oidc_approver: Option<String>,
}

/// Where the review reads and resolves gates. An outer `Err` stops the
/// review: a transport failure, a lost answer, an unreadable answer.
pub(crate) trait Gates {
    /// Who resolves the gates, for the default reason.
    fn actor(&self) -> &str;
    /// Who approvers are checked against, where they are enforced
    /// (remotely); `None` locally, where they are informational.
    fn approver(&self) -> Option<&Caller>;
    /// The open gates, in `bd gate list` order.
    fn list(&mut self) -> Result<Vec<GateView>>;
    fn show(&mut self, id: &str) -> Result<Shown>;
    fn resolve(&mut self, id: &str, reason: &str) -> Result<std::result::Result<Resolved, Failure>>;
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ResolvedGate {
    pub id: String,
    #[serde(skip)]
    pub title: String,
    pub unblocked: Vec<String>,
    pub completed: Vec<String>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct SkippedGate {
    pub id: String,
    pub reason: String,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct FailedGate {
    pub id: String,
    pub code: String,
    pub message: String,
    pub exit_code: i32,
}

/// What a review did, printed on stdout.
#[derive(Clone, Debug, Default, Serialize)]
pub(crate) struct Summary {
    pub resolved: Vec<ResolvedGate>,
    pub declined: Vec<String>,
    pub skipped: Vec<SkippedGate>,
    pub failed: Vec<FailedGate>,
    pub not_asked: Vec<String>,
    /// Human gates selected that wait for their work's prerequisites.
    pub waiting: usize,
}

impl Summary {
    /// The first failure's exit code, else 0.
    pub fn exit_code(&self) -> i32 {
        self.failed.first().map_or(0, |f| f.exit_code)
    }

    fn skip(&mut self, id: &str, reason: impl Into<String>) {
        self.skipped.push(SkippedGate { id: id.to_string(), reason: reason.into() });
    }

    fn reviewed_nothing(&self) -> bool {
        self.resolved.is_empty()
            && self.declined.is_empty()
            && self.skipped.is_empty()
            && self.failed.is_empty()
            && self.not_asked.is_empty()
    }
}

const ALREADY_OPEN: &str = "already open (resolved meanwhile)";

fn is_human(v: &GateView) -> bool {
    v.spec.as_ref().is_some_and(|s| s.kind == GateKind::Human)
}

fn line(s: String) -> String {
    show::cap_line(show::printable(&s))
}

/// Ask about each human gate waiting for a person (or each of `ids`) on
/// `out`, reading the answers from `input`, and resolve those approved.
pub(crate) fn review(
    gates: &mut dyn Gates,
    ids: &[String],
    reason: Option<&str>,
    input: &mut dyn BufRead,
    out: &mut dyn Write,
) -> Result<Summary> {
    let mut s = Summary::default();
    let mut candidates: Vec<String> = Vec::new();
    if ids.is_empty() {
        for g in gates.list()? {
            if !is_human(&g) {
                continue;
            }
            match g.phase {
                GatePhase::Armed | GatePhase::Escalated => candidates.push(g.id),
                GatePhase::Waiting => s.waiting += 1,
                GatePhase::Resolved => {}
            }
        }
    } else {
        let mut seen = BTreeSet::new();
        for raw in ids {
            match gates.show(raw)? {
                Shown::Missing(why) => {
                    if seen.insert(raw.clone()) {
                        s.skip(raw, why);
                    }
                }
                Shown::Gate(d) => {
                    let v = d.view;
                    if !seen.insert(v.id.clone()) {
                        continue;
                    }
                    if !is_human(&v) {
                        let kind = v.spec.as_ref().map_or("invalid", |s| s.kind.as_str());
                        s.skip(&v.id, format!("not a human gate (type {kind})"));
                    } else {
                        match v.phase {
                            GatePhase::Resolved => s.skip(&v.id, "already open (resolved)"),
                            GatePhase::Waiting => {
                                s.waiting += 1;
                                s.skip(&v.id, "waiting for its prerequisites");
                            }
                            GatePhase::Armed | GatePhase::Escalated => candidates.push(v.id),
                        }
                    }
                }
            }
        }
    }
    let now = Timestamp::now();
    for (i, id) in candidates.iter().enumerate() {
        let d = match gates.show(id)? {
            Shown::Missing(why) => {
                s.skip(id, why);
                continue;
            }
            Shown::Gate(d) => d,
        };
        let v = &d.view;
        if !is_human(v) {
            s.skip(id, "no longer a human gate");
            continue;
        }
        if v.phase == GatePhase::Resolved {
            s.skip(id, ALREADY_OPEN);
            continue;
        }
        if !v.is_armed() {
            s.skip(id, "not armed: its work's prerequisites are open again");
            continue;
        }
        let approvers = v.spec.as_ref().and_then(|s| s.approvers.clone());
        if let Some(me) = gates.approver() {
            match approvers.as_deref() {
                Some([]) => {
                    s.skip(id, "its approvers are not valid");
                    continue;
                }
                Some(list) if !policy::approved_by(list, &me.actor, me.oidc_approver.as_deref()) => {
                    let who = if me.oidc_approver.is_some() {
                        "an account signed in with an OIDC provider matches only an oidc:sha256: identity \
                         reference for its own issuer and subject"
                            .to_string()
                    } else {
                        format!("you are {}", me.actor)
                    };
                    s.skip(id, format!("only {} may approve it ({who})", list.join(", ")));
                    continue;
                }
                _ => {}
            }
        }
        let mut block = vec![line(format!("{} {}", v.id, v.title)), line(format!("  state: {}", state_text(v, now)))];
        if let Some((pid, ptitle)) = &d.part_of {
            block.push(line(format!("  part of: {pid} {ptitle}")));
        }
        for b in &v.blocks {
            block.push(line(format!("  holds back: {} {} [{}]", b.id, b.title, b.status)));
        }
        let local = gates.approver().is_none();
        block.push(line(match (approvers.as_deref(), local) {
            (None, _) => "  approvers: any person".to_string(),
            (Some([]), true) => "  approvers: invalid (not checked in a local workspace)".to_string(),
            (Some(list), true) => format!("  approvers: {} (not checked in a local workspace)", list.join(", ")),
            (Some(list), false) => format!("  approvers: {}", list.join(", ")),
        }));
        for l in block {
            let _ = writeln!(out, "{l}");
        }
        match ask(input, out, &format!("Resolve {}?", show::printable(id))) {
            Answer::End => {
                s.not_asked.extend(candidates[i..].iter().cloned());
                break;
            }
            Answer::No => s.declined.push(id.clone()),
            Answer::Yes => {
                let why = reason
                    .map(String::from)
                    .unwrap_or_else(|| format!("approved in bd gate review by {}", gates.actor()));
                match gates.resolve(id, &why)? {
                    Ok(r) if r.already_open => s.skip(id, ALREADY_OPEN),
                    Ok(r) => s.resolved.push(ResolvedGate {
                        id: id.clone(),
                        title: v.title.clone(),
                        unblocked: r.unblocked.into_iter().map(|(i, _)| i).collect(),
                        completed: r.completed.into_iter().map(|(i, _)| i).collect(),
                    }),
                    Err(f) => {
                        let _ = writeln!(out, "{}", line(format!("  failed: {}", f.message)));
                        s.failed.push(FailedGate {
                            id: id.clone(),
                            code: f.code,
                            message: f.message,
                            exit_code: f.exit_code,
                        });
                    }
                }
            }
        }
    }
    Ok(s)
}

/// The text summary: a count line, then one line per gate resolved,
/// skipped or failed, each escaped.
pub(crate) fn summary_text(s: &Summary) -> Vec<String> {
    let waiting = |n: usize| format!("{n} waiting for their work's prerequisites");
    if s.reviewed_nothing() {
        let mut head = "No human gates waiting for approval".to_string();
        if s.waiting > 0 {
            head.push_str(&format!(" ({})", waiting(s.waiting)));
        }
        return vec![head];
    }
    let mut head = format!("Resolved {}, declined {}, skipped {}", s.resolved.len(), s.declined.len(), s.skipped.len());
    if !s.not_asked.is_empty() {
        head.push_str(&format!(", not asked {}", s.not_asked.len()));
    }
    if !s.failed.is_empty() {
        head.push_str(&format!(", failed {}", s.failed.len()));
    }
    if s.waiting > 0 {
        head.push_str(&format!(", {}", waiting(s.waiting)));
    }
    let mut lines = vec![head];
    for r in &s.resolved {
        let mut l = format!("  resolved {} {}", r.id, r.title);
        if !r.unblocked.is_empty() {
            l.push_str(&format!(" (unblocked {})", r.unblocked.join(", ")));
        }
        if !r.completed.is_empty() {
            l.push_str(&format!(" (completed {})", r.completed.join(", ")));
        }
        lines.push(line(l));
    }
    for k in &s.skipped {
        lines.push(line(format!("  skipped {}: {}", k.id, k.reason)));
    }
    for f in &s.failed {
        lines.push(line(format!("  failed {}: {}", f.id, f.message)));
    }
    lines
}

/// `bd gate review`: locally, or against `remote` (which must send the
/// person's keychain token). Every error it reports is on one line.
pub fn cmd_review(app: &mut App, remote: Option<&Remote>, a: &GateReviewArgs) -> Result<i32> {
    run_review(app, remote, a).map_err(one_line)
}

fn run_review(app: &mut App, remote: Option<&Remote>, a: &GateReviewArgs) -> Result<i32> {
    io::require_local("bd gate review")?;
    people_only(&actor::env, &keychain::stdin_is_terminal)?;
    // Prompts and gates go to this process's own terminal: the command is machine-local (require_local above).
    let mut input = std::io::stdin().lock();
    let mut out = std::io::stderr();
    let summary = match remote {
        Some(r) => {
            if !r.sends_keychain_token() {
                return Err(Error::Refused("bd gate review sends only a person's keychain token".into()));
            }
            let mut g = RemoteGates::new(r)?;
            review(&mut g, &a.ids, a.reason.as_deref(), &mut input, &mut out)?
        }
        None => {
            let mut g = LocalGates::new(app);
            review(&mut g, &a.ids, a.reason.as_deref(), &mut input, &mut out)?
        }
    };
    if app.g.json {
        app.print_json(&summary);
    } else {
        for l in summary_text(&summary) {
            io::outln(l);
        }
    }
    Ok(summary.exit_code())
}

/// The workspace on this machine. Approvers are not checked here: locally
/// they are informational.
struct LocalGates<'a> {
    app: &'a mut App,
    actor: String,
}

impl<'a> LocalGates<'a> {
    fn new(app: &'a mut App) -> LocalGates<'a> {
        let actor = app.resolved_actor().actor;
        LocalGates { app, actor }
    }
}

fn refs(list: Vec<bd_core::IssueRef>) -> Vec<(String, String)> {
    list.into_iter().map(|r| (r.id, r.title)).collect()
}

impl Gates for LocalGates<'_> {
    fn actor(&self) -> &str {
        &self.actor
    }

    fn approver(&self) -> Option<&Caller> {
        None
    }

    fn list(&mut self) -> Result<Vec<GateView>> {
        self.app.read(|r| gates::list(r.conn(), false))
    }

    fn show(&mut self, raw: &str) -> Result<Shown> {
        self.app.read(|r| {
            let id = match r.resolve_id(raw) {
                Ok(id) => id,
                Err(e @ (Error::Sqlite(_) | Error::Io(_) | Error::Busy(_))) => return Err(e),
                Err(e) => return Ok(Shown::Missing(show::printable(&e.to_string()))),
            };
            let Some(issue) = issues::get(r.conn(), &id)? else {
                return Ok(Shown::Missing(show::printable(&format!("{id} not found"))));
            };
            if issue.issue_type != bd_core::model::GATE_TYPE {
                return Ok(Shown::Missing(show::printable(&format!("{id} is not a gate"))));
            }
            let view = gates::view_of(r.conn(), &issue)?;
            let part_of = gates::run_of(r.conn(), &id)?.map(|p| (p.id, p.title));
            Ok(Shown::Gate(Box::new(Detail { view, part_of })))
        })
    }

    fn resolve(&mut self, id: &str, reason: &str) -> Result<std::result::Result<Resolved, Failure>> {
        // One write, with its events and recompute; never forced, so it ends no claim.
        match self.app.write("gate.resolve", |tx| tx.resolve_gate(id, Some(reason), false, None)) {
            Ok(r) => Ok(Ok(Resolved {
                already_open: r.already_closed,
                unblocked: refs(r.unblocked),
                completed: refs(r.completed),
            })),
            Err(e) if matches!(e.exit_code(), 8 | 9) => Err(e),
            Err(e) => Ok(Err(Failure {
                code: e.code().to_string(),
                message: show::printable(&e.to_string()),
                exit_code: e.exit_code(),
            })),
        }
    }
}

/// A remote workspace, reached with the person's keychain token: only
/// `info`, `gate list`, `gate show` and `gate resolve` are sent.
struct RemoteGates<'a> {
    remote: &'a Remote,
    caller: Caller,
}

impl<'a> RemoteGates<'a> {
    fn new(remote: &'a Remote) -> Result<RemoteGates<'a>> {
        let r = remote.exec(&request(remote, ["--json", "info"]))?;
        if r.exit_code != 0 {
            return Err(response_error(&r, &remote.url));
        }
        let info: Value = serde_json::from_str(&r.stdout)
            .map_err(|e| Error::Remote(format!("{}: unreadable answer to info: {e}", remote.url)))?;
        let actor = actor_of_info(&info)
            .ok_or_else(|| Error::Remote(format!("{}: the answer to info names no actor", remote.url)))?;
        let oidc_approver = oidc_approver_of_info(&info)
            .map_err(|e| Error::Remote(format!("{}: unreadable answer to info: {e}", remote.url)))?;
        Ok(RemoteGates { remote, caller: Caller { actor, oidc_approver } })
    }

    fn unreadable(&self, what: &str, e: impl std::fmt::Display) -> Error {
        Error::Remote(format!("{}: unreadable answer to {what}: {e}", self.remote.url))
    }
}

fn request<'s>(remote: &Remote, argv: impl IntoIterator<Item = &'s str>) -> ExecRequest {
    let (actor, session) = identity();
    ExecRequest {
        argv: argv.into_iter().map(String::from).collect(),
        actor,
        session,
        location: Some(remote.url.clone()),
        ..Default::default()
    }
}

/// The actor the server's policy decides by: the token's, else the request's.
pub(crate) fn actor_of_info(info: &Value) -> Option<String> {
    info.pointer("/token/actor")
        .and_then(Value::as_str)
        .or_else(|| info.get("actor").and_then(Value::as_str))
        .filter(|a| !a.is_empty())
        .map(String::from)
}

/// The identity reference the server matches the token's account by
/// ([`gates::account_oidc_approver`]): `None` for a token with no account
/// (absent or null) or a GitHub one; an error for an account that is not an
/// object with non-empty `provider`, `issuer` and `subject` strings, so a
/// malformed answer never falls back to matching the actor.
pub(crate) fn oidc_approver_of_info(info: &Value) -> std::result::Result<Option<String>, String> {
    let account = match info.get("token") {
        None | Some(Value::Null) => return Ok(None),
        Some(t) => match t.get("account") {
            None | Some(Value::Null) => return Ok(None),
            Some(a) => a,
        },
    };
    let field = |name: &str| account.get(name).and_then(Value::as_str).filter(|v| !v.is_empty());
    match (field("provider"), field("issuer"), field("subject")) {
        (Some(provider), Some(issuer), Some(subject)) => Ok(gates::account_oidc_approver(provider, issuer, subject)),
        _ => Err("malformed token.account".to_string()),
    }
}

/// The human gates of a `gate list --json` answer, each read strictly;
/// gates of other kinds (a kind this client does not know included) are left
/// aside unread.
pub(crate) fn parse_list(v: &Value) -> std::result::Result<Vec<GateView>, String> {
    let entries = v.as_array().ok_or("not a JSON array")?;
    entries
        .iter()
        .filter(|e| e.pointer("/spec/type").and_then(Value::as_str) == Some("human"))
        .map(|e| serde_json::from_value::<GateView>(e.clone()).map_err(|e| e.to_string()))
        .collect()
}

/// A `gate show --json` answer; `part_of` is optional (older servers send none).
pub(crate) fn parse_show(v: &Value) -> std::result::Result<Detail, String> {
    let view = serde_json::from_value::<GateView>(v.clone()).map_err(|e| e.to_string())?;
    let part_of = match v.get("part_of") {
        None | Some(Value::Null) => None,
        Some(p) => {
            let field = |k: &str| p.get(k).and_then(Value::as_str).map(String::from);
            Some((field("id").ok_or("part_of without an id")?, field("title").unwrap_or_default()))
        }
    };
    Ok(Detail { view, part_of })
}

fn pairs(v: Option<&Value>) -> std::result::Result<Vec<(String, String)>, String> {
    let Some(v) = v.filter(|v| !v.is_null()) else { return Ok(Vec::new()) };
    v.as_array()
        .ok_or("not an array")?
        .iter()
        .map(|r| {
            let id = r.get("id").and_then(Value::as_str).ok_or("an issue without an id")?;
            Ok((id.to_string(), r.get("title").and_then(Value::as_str).unwrap_or_default().to_string()))
        })
        .collect()
}

/// A `gate resolve --json` answer for one gate.
pub(crate) fn parse_resolved(v: &Value) -> std::result::Result<Resolved, String> {
    v.pointer("/issue/id").and_then(Value::as_str).ok_or("no issue.id")?;
    let already_open = v.get("already_closed").and_then(Value::as_bool).ok_or("no already_closed")?;
    Ok(Resolved { already_open, unblocked: pairs(v.get("unblocked"))?, completed: pairs(v.get("completed"))? })
}

/// A failed command's error: its `--json` error on stderr, else its first
/// stderr line and exit code. The message is escaped.
pub(crate) fn failure_of(r: &ExecResponse) -> Failure {
    let error = r.stderr.lines().find_map(|l| {
        let v: Value = serde_json::from_str(l).ok()?;
        let e = v.get("error")?;
        Some((
            e.get("code")?.as_str()?.to_string(),
            e.get("message")?.as_str()?.to_string(),
            e.get("exit_code").and_then(Value::as_i64).map_or(r.exit_code, |c| c as i32),
        ))
    });
    let (code, message, exit_code) = error.unwrap_or_else(|| {
        let first = r.stderr.lines().next().unwrap_or("failed").trim_start_matches("error: ");
        ("failed".to_string(), first.to_string(), r.exit_code)
    });
    Failure { code, message: show::printable(&message), exit_code }
}

impl Gates for RemoteGates<'_> {
    fn actor(&self) -> &str {
        &self.caller.actor
    }

    fn approver(&self) -> Option<&Caller> {
        Some(&self.caller)
    }

    fn list(&mut self) -> Result<Vec<GateView>> {
        let r = self.remote.exec(&request(self.remote, ["--json", "gate", "list"]))?;
        if r.exit_code != 0 {
            return Err(response_error(&r, &self.remote.url));
        }
        let v: Value = serde_json::from_str(&r.stdout).map_err(|e| self.unreadable("gate list", e))?;
        parse_list(&v).map_err(|e| self.unreadable("gate list", e))
    }

    fn show(&mut self, id: &str) -> Result<Shown> {
        let r = self.remote.exec(&request(self.remote, ["--json", "gate", "show", "--", id]))?;
        match r.exit_code {
            0 => {
                let v: Value = serde_json::from_str(&r.stdout).map_err(|e| self.unreadable("gate show", e))?;
                let d = parse_show(&v).map_err(|e| self.unreadable("gate show", e))?;
                Ok(Shown::Gate(Box::new(d)))
            }
            2 | 3 => Ok(Shown::Missing(failure_of(&r).message)),
            _ => Err(response_error(&r, &self.remote.url)),
        }
    }

    fn resolve(&mut self, id: &str, reason: &str) -> Result<std::result::Result<Resolved, Failure>> {
        let reason = format!("--reason={reason}");
        let mut req = request(self.remote, ["--json", "gate", "resolve", reason.as_str(), "--", id]);
        req.request_id = Some(random_hex(16)?);
        let r = self.remote.exec_collected(&req, true)?;
        match r.exit_code {
            0 => {
                let v: Value = serde_json::from_str(&r.stdout).map_err(|e| self.unreadable("gate resolve", e))?;
                Ok(Ok(parse_resolved(&v).map_err(|e| self.unreadable("gate resolve", e))?))
            }
            8 | 9 => Err(response_error(&r, &self.remote.url)),
            _ => Ok(Err(failure_of(&r))),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::collections::VecDeque;
    use std::io::Cursor;

    use bd_core::gates::GateSpec;
    use bd_core::model::{IssueRef, Status};
    use serde_json::json;

    use super::*;

    fn spec(kind: GateKind, approvers: Option<Vec<&str>>) -> GateSpec {
        GateSpec {
            kind,
            await_id: None,
            timeout: (kind == GateKind::Timer).then(|| "1h".into()),
            repo: None,
            branch: None,
            event: None,
            approvers: approvers.map(|l| l.into_iter().map(String::from).collect()),
        }
    }

    fn gate(id: &str, title: &str, kind: GateKind, phase: GatePhase) -> GateView {
        GateView {
            id: id.into(),
            title: title.into(),
            status: if phase == GatePhase::Resolved { Status::Closed } else { Status::Open },
            phase,
            spec: Some(spec(kind, None)),
            spec_error: None,
            assignee: None,
            created_at: Timestamp(0),
            armed_at: matches!(phase, GatePhase::Armed | GatePhase::Escalated).then_some(Timestamp(0)),
            deadline: None,
            escalated_at: None,
            escalation: (phase == GatePhase::Escalated).then(|| "too long".into()),
            run_id: None,
            closed_at: None,
            close_reason: None,
            blocks: vec![IssueRef {
                id: format!("{id}-task"),
                title: "Ship".into(),
                status: Status::Open,
                priority: 2,
                issue_type: "task".into(),
                assignee: None,
            }],
        }
    }

    fn human(id: &str) -> GateView {
        gate(id, &format!("Approve {id}"), GateKind::Human, GatePhase::Armed)
    }

    /// Scripted answers, counting each call.
    struct FakeGates {
        approver: Option<Caller>,
        listed: Vec<GateView>,
        /// What `show` answers per id; a gate missing here is Missing.
        shows: std::collections::BTreeMap<String, VecDeque<Result<Shown>>>,
        resolves: VecDeque<Result<std::result::Result<Resolved, Failure>>>,
        resolved: Vec<(String, String)>,
        shown: Cell<usize>,
    }

    impl FakeGates {
        fn new(approver: Option<&str>) -> FakeGates {
            FakeGates {
                approver: approver.map(|a| Caller { actor: a.into(), oidc_approver: None }),
                listed: Vec::new(),
                shows: Default::default(),
                resolves: VecDeque::new(),
                resolved: Vec::new(),
                shown: Cell::new(0),
            }
        }

        /// List `v` and show it as it is.
        fn as_oidc(actor: &str, reference: &str) -> FakeGates {
            let mut g = FakeGates::new(None);
            g.approver = Some(Caller { actor: actor.into(), oidc_approver: Some(reference.into()) });
            g
        }

        fn with(mut self, v: GateView) -> FakeGates {
            self.listed.push(v.clone());
            self.shows_as(&v.id.clone(), v)
        }

        fn shows_as(mut self, id: &str, v: GateView) -> FakeGates {
            let d = Detail { view: v, part_of: Some(("r-1".into(), "Run".into())) };
            self.shows.entry(id.into()).or_default().push_back(Ok(Shown::Gate(Box::new(d))));
            self
        }
    }

    impl Gates for FakeGates {
        fn actor(&self) -> &str {
            "carol"
        }

        fn approver(&self) -> Option<&Caller> {
            self.approver.as_ref()
        }

        fn list(&mut self) -> Result<Vec<GateView>> {
            Ok(self.listed.clone())
        }

        fn show(&mut self, id: &str) -> Result<Shown> {
            self.shown.set(self.shown.get() + 1);
            let q = self.shows.get_mut(id);
            match q {
                Some(q) if q.len() > 1 => q.pop_front().unwrap(),
                Some(q) => match q.front().unwrap() {
                    Ok(s) => Ok(s.clone()),
                    Err(_) => q.pop_front().unwrap(),
                },
                None => Ok(Shown::Missing(format!("issue not found: {id}"))),
            }
        }

        fn resolve(&mut self, id: &str, reason: &str) -> Result<std::result::Result<Resolved, Failure>> {
            self.resolved.push((id.into(), reason.into()));
            self.resolves.pop_front().unwrap_or_else(|| {
                Ok(Ok(Resolved { unblocked: vec![(format!("{id}-task"), "Ship".into())], ..Default::default() }))
            })
        }
    }

    fn run(g: &mut FakeGates, ids: &[&str], answers: &str) -> (Result<Summary>, String) {
        let ids: Vec<String> = ids.iter().map(|s| s.to_string()).collect();
        let mut out = Vec::new();
        let s = review(g, &ids, None, &mut Cursor::new(answers.as_bytes().to_vec()), &mut out);
        (s, String::from_utf8(out).unwrap())
    }

    #[test]
    fn yes_resolves_and_anything_else_declines() {
        for answer in ["y\n", "yes\n", "Y\n"] {
            let mut g = FakeGates::new(None).with(human("g-1"));
            let (s, shown) = run(&mut g, &[], answer);
            let s = s.unwrap();
            assert_eq!(s.resolved.len(), 1, "{answer:?}");
            assert_eq!(g.resolved, [("g-1".to_string(), "approved in bd gate review by carol".to_string())]);
            assert_eq!(s.resolved[0].unblocked, ["g-1-task"]);
            assert!(shown.contains("g-1 Approve g-1\n  state: armed"), "{shown}");
            assert!(shown.contains("  part of: r-1 Run\n  holds back: g-1-task Ship [open]\n"), "{shown}");
            assert!(shown.contains("  approvers: any person\nResolve g-1? [y/N] "), "{shown}");
            assert_eq!(s.exit_code(), 0);
        }
        for answer in ["n\n", "\n"] {
            let mut g = FakeGates::new(None).with(human("g-1"));
            let s = run(&mut g, &[], answer).0.unwrap();
            assert_eq!(s.declined, ["g-1"], "{answer:?}");
            assert!(g.resolved.is_empty());
        }
        let mut g = FakeGates::new(None).with(human("g-1"));
        let ids = vec!["g-1".to_string()];
        let mut out = Vec::new();
        review(&mut g, &ids, Some("ship it"), &mut Cursor::new(b"y\n".to_vec()), &mut out).unwrap();
        assert_eq!(g.resolved, [("g-1".to_string(), "ship it".to_string())]);
    }

    #[test]
    fn the_end_of_input_stops_asking() {
        let mut g = FakeGates::new(None).with(human("g-1")).with(human("g-2")).with(human("g-3"));
        let s = run(&mut g, &[], "n\n").0.unwrap();
        assert_eq!(s.declined, ["g-1"]);
        assert_eq!(s.not_asked, ["g-2", "g-3"]);
        assert!(g.resolved.is_empty());
        assert_eq!(summary_text(&s)[0], "Resolved 0, declined 1, skipped 0, not asked 2");
    }

    #[test]
    fn a_gate_resolved_meanwhile_is_skipped_and_failures_go_on() {
        let mut g = FakeGates::new(None).with(human("g-1")).with(human("g-2")).with(human("g-3"));
        g.resolves.push_back(Ok(Ok(Resolved { already_open: true, ..Default::default() })));
        g.resolves.push_back(Ok(Err(Failure {
            code: "unauthorized".into(),
            message: "only a person".into(),
            exit_code: 7,
        })));
        let (s, shown) = run(&mut g, &[], "y\ny\ny\n");
        let s = s.unwrap();
        assert_eq!(s.skipped.len(), 1);
        assert_eq!((s.skipped[0].id.as_str(), s.skipped[0].reason.as_str()), ("g-1", ALREADY_OPEN));
        assert_eq!(s.failed.len(), 1);
        assert_eq!(s.failed[0].exit_code, 7);
        assert_eq!(s.resolved.len(), 1, "the review went on");
        assert!(shown.contains("  failed: only a person\n"), "{shown}");
        assert_eq!(s.exit_code(), 7);

        let mut g = FakeGates::new(None).with(human("g-1"));
        g.resolves.push_back(Ok(Ok(Resolved { already_open: true, ..Default::default() })));
        assert_eq!(run(&mut g, &[], "y\n").0.unwrap().exit_code(), 0);
    }

    #[test]
    fn a_fatal_error_stops_the_review() {
        let mut g = FakeGates::new(None).with(human("g-1")).with(human("g-2"));
        g.resolves.push_back(Err(Error::Remote("u: unreachable".into())));
        let e = run(&mut g, &[], "y\ny\n").0.unwrap_err();
        assert_eq!(e.exit_code(), 8);
        assert_eq!(g.resolved.len(), 1);
    }

    #[test]
    fn approvers_are_checked_remotely_before_asking() {
        let mut other = human("g-1");
        other.spec = Some(spec(GateKind::Human, Some(vec!["github:alice"])));
        let mut invalid = human("g-2");
        invalid.spec = Some(spec(GateKind::Human, Some(vec![])));
        let mut mine = human("g-3");
        mine.spec = Some(spec(GateKind::Human, Some(vec!["github:alice", "carol"])));
        let mut g = FakeGates::new(Some("carol/laptop")).with(other.clone()).with(invalid.clone()).with(mine.clone());
        let (s, shown) = run(&mut g, &[], "y\n");
        let s = s.unwrap();
        let reasons: Vec<_> = s.skipped.iter().map(|k| (k.id.as_str(), k.reason.as_str())).collect();
        assert_eq!(
            reasons,
            [
                ("g-1", "only github:alice may approve it (you are carol/laptop)"),
                ("g-2", "its approvers are not valid")
            ]
        );
        assert_eq!(shown.matches("Resolve ").count(), 1, "{shown}");
        assert!(shown.contains("  approvers: github:alice, carol\nResolve g-3?"), "{shown}");
        assert_eq!(g.resolved.len(), 1);

        // Locally approvers are shown, not checked.
        let mut g = FakeGates::new(None).with(other);
        let (s, shown) = run(&mut g, &[], "y\n");
        assert_eq!(s.unwrap().resolved.len(), 1);
        assert!(shown.contains("  approvers: github:alice (not checked in a local workspace)"), "{shown}");
    }

    #[test]
    fn oidc_accounts_are_asked_only_about_their_own_reference() {
        let reference = gates::oidc_approver("https://login.example.com", "248289761001");
        let other = gates::oidc_approver("https://login.example.com", "248289761002");
        let with = |id: &str, list: Vec<&str>| {
            let mut g = human(id);
            g.spec = Some(spec(GateKind::Human, Some(list)));
            g
        };
        // Its own actor and an actor spelled as its reference are not its approvers.
        let mut g = FakeGates::as_oidc("corp:alice", &reference)
            .with(with("g-1", vec!["corp:alice"]))
            .with(with("g-2", vec![&other]))
            .with(with("g-3", vec!["carol", &reference]));
        let (s, shown) = run(
            &mut g,
            &[],
            "y
",
        );
        let s = s.unwrap();
        let skipped: Vec<_> = s.skipped.iter().map(|k| k.id.as_str()).collect();
        assert_eq!(skipped, ["g-1", "g-2"]);
        for k in &s.skipped {
            assert!(k.reason.contains("matches only an oidc:sha256: identity reference"), "{}", k.reason);
            assert!(!k.reason.contains(&reference), "the caller's reference is not shown: {}", k.reason);
        }
        assert_eq!(shown.matches("Resolve ").count(), 1, "{shown}");
        assert!(shown.contains("Resolve g-3?"), "{shown}");
        assert_eq!(g.resolved.len(), 1);

        // An actor spelled as a reference matches nothing, nor does its sub-actor.
        for actor in [reference.clone(), format!("{reference}/laptop")] {
            let mut g = FakeGates::new(Some(&actor)).with(with("g-1", vec![&reference]));
            let s = run(
                &mut g,
                &[],
                "y
",
            )
            .0
            .unwrap();
            assert_eq!(s.skipped.len(), 1, "{actor}");
            assert!(g.resolved.is_empty(), "{actor}");
        }
    }

    #[test]
    fn the_account_of_the_info_answer_gives_the_reference() {
        let account = |a: Value| json!({"actor": "corp:alice", "token": {"actor": "corp:alice", "account": a}});
        assert_eq!(oidc_approver_of_info(&json!({"actor": "a"})), Ok(None), "no token");
        assert_eq!(oidc_approver_of_info(&json!({"actor": "a", "token": null})), Ok(None));
        assert_eq!(oidc_approver_of_info(&json!({"token": {"actor": "a"}})), Ok(None), "a manual token");
        assert_eq!(oidc_approver_of_info(&account(Value::Null)), Ok(None));
        let github = json!({"provider": "github", "issuer": "github.com", "subject": "583231", "login": "alice"});
        assert_eq!(oidc_approver_of_info(&account(github)), Ok(None), "GitHub sign-ins match by actor");
        let acme = json!({"provider": "acme", "issuer": "https://login.example.com", "subject": "248289761001",
                          "login": "alice"});
        assert_eq!(
            oidc_approver_of_info(&account(acme)),
            Ok(Some(gates::oidc_approver("https://login.example.com", "248289761001")))
        );
        for bad in [
            json!("acme"),
            json!([]),
            json!({"provider": "acme", "subject": "1"}),
            json!({"provider": "acme", "issuer": "https://login.example.com"}),
            json!({"issuer": "https://login.example.com", "subject": "1"}),
            json!({"provider": "acme", "issuer": "https://login.example.com", "subject": 1}),
            json!({"provider": "acme", "issuer": null, "subject": "1"}),
            json!({"provider": "acme", "issuer": "https://login.example.com", "subject": ""}),
            json!({"provider": "", "issuer": "https://login.example.com", "subject": "1"}),
        ] {
            assert!(oidc_approver_of_info(&account(bad.clone())).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_gate_read_again_as_another_kind_or_state_is_skipped() {
        let timer = gate("g-1", "Wait", GateKind::Timer, GatePhase::Armed);
        let mut g = FakeGates::new(None).shows_as("g-1", timer);
        g.listed.push(human("g-1"));
        let (s, shown) = run(&mut g, &[], "y\n");
        let s = s.unwrap();
        assert_eq!(s.skipped[0].reason, "no longer a human gate");
        assert!(shown.is_empty(), "no prompt: {shown}");
        assert!(g.resolved.is_empty());

        let mut g = FakeGates::new(None).shows_as("g-2", gate("g-2", "Later", GateKind::Human, GatePhase::Waiting));
        g.listed.push(human("g-2"));
        let s = run(&mut g, &[], "y\n").0.unwrap();
        assert_eq!(s.skipped.len(), 1);
        assert!(g.resolved.is_empty());

        let mut g = FakeGates::new(None).shows_as("g-3", gate("g-3", "Done", GateKind::Human, GatePhase::Resolved));
        g.listed.push(human("g-3"));
        let s = run(&mut g, &[], "y\n").0.unwrap();
        assert_eq!(s.skipped[0].reason, ALREADY_OPEN);
    }

    #[test]
    fn named_gates_are_checked_and_waiting_ones_counted_once() {
        let mut g = FakeGates::new(None)
            .with(gate("g-1", "Later", GateKind::Human, GatePhase::Waiting))
            .with(gate("g-2", "Wait", GateKind::Timer, GatePhase::Armed))
            .with(gate("g-3", "Done", GateKind::Human, GatePhase::Resolved))
            .with(human("g-4"));
        let (s, shown) = run(&mut g, &["g-1", "g-1", "nope", "g-2", "g-3", "g-4"], "y\n");
        let s = s.unwrap();
        assert_eq!(s.waiting, 1);
        let reasons: Vec<_> = s.skipped.iter().map(|k| (k.id.as_str(), k.reason.as_str())).collect();
        assert_eq!(
            reasons,
            [
                ("g-1", "waiting for its prerequisites"),
                ("nope", "issue not found: nope"),
                ("g-2", "not a human gate (type timer)"),
                ("g-3", "already open (resolved)"),
            ]
        );
        assert_eq!(shown.matches("Resolve ").count(), 1);
        assert_eq!(s.resolved[0].id, "g-4");

        let mut g = FakeGates::new(None)
            .with(gate("g-1", "Later", GateKind::Human, GatePhase::Waiting))
            .with(gate("g-2", "Later", GateKind::Human, GatePhase::Waiting))
            .with(gate("g-3", "Wait", GateKind::Timer, GatePhase::Waiting));
        let s = run(&mut g, &[], "").0.unwrap();
        assert_eq!(s.waiting, 2, "human gates only");
        assert_eq!(
            summary_text(&s),
            ["No human gates waiting for approval (2 waiting for their work's prerequisites)"]
        );
        assert_eq!(summary_text(&Summary::default()), ["No human gates waiting for approval"]);
    }

    #[test]
    fn the_summary_reports_the_waiting_gates_beside_the_others() {
        let mut g =
            FakeGates::new(None).with(human("g-1")).with(gate("g-2", "Later", GateKind::Human, GatePhase::Waiting));
        let s = run(&mut g, &[], "y\n").0.unwrap();
        let text = summary_text(&s);
        assert_eq!(text[0], "Resolved 1, declined 0, skipped 0, 1 waiting for their work's prerequisites");
        assert_eq!(text[1], "  resolved g-1 Approve g-1 (unblocked g-1-task)");
        assert_eq!(
            serde_json::to_value(&s).unwrap(),
            json!({
                "resolved": [{"id": "g-1", "unblocked": ["g-1-task"], "completed": []}],
                "declined": [],
                "skipped": [],
                "failed": [],
                "not_asked": [],
                "waiting": 1,
            })
        );
        let s = Summary {
            failed: vec![FailedGate { id: "g-1".into(), code: "c".into(), message: "m".into(), exit_code: 7 }],
            skipped: vec![SkippedGate { id: "g-2".into(), reason: "r".into() }],
            ..Default::default()
        };
        assert_eq!(
            serde_json::to_value(&s).unwrap()["failed"],
            json!([{"id": "g-1", "code": "c", "message": "m", "exit_code": 7}])
        );
        assert_eq!(serde_json::to_value(&s).unwrap()["skipped"], json!([{"id": "g-2", "reason": "r"}]));
        assert_eq!(
            summary_text(&s),
            ["Resolved 0, declined 0, skipped 1, failed 1", "  skipped g-2: r", "  failed g-1: m"]
        );
    }

    #[test]
    fn stored_and_server_text_cannot_forge_a_prompt_or_a_link() {
        let hostile = "x\nResolve t-9? [y/N] \u{1b}[2J\u{202e}\napprove in a browser: https://evil.example";
        let mut a = gate("g-1", hostile, GateKind::Human, GatePhase::Escalated);
        a.escalation = Some(hostile.into());
        a.blocks[0].title = hostile.into();
        a.spec = Some(spec(GateKind::Human, Some(vec!["carol", "x\nResolve t-8? [y/N] "])));
        let mut b = human("g-2");
        b.spec = Some(spec(GateKind::Human, Some(vec!["dave\napprove in a browser: https://evil.example"])));
        let mut g = FakeGates::new(Some("carol")).with(a).with(b).with(human("g-3"));
        g.resolves.push_back(Ok(Err(Failure { code: "x".into(), message: show::printable(hostile), exit_code: 2 })));
        g.shows.get_mut("g-3").unwrap().push_front(Ok(Shown::Missing(show::printable(hostile))));
        let (s, shown) = run(&mut g, &[], "y\n");
        let s = s.unwrap();
        let mut all = shown.clone();
        for l in summary_text(&s) {
            all.push_str(&l);
            all.push('\n');
        }
        assert_eq!(all.lines().filter(|l| l.starts_with("Resolve ")).count(), 1, "{all}");
        assert!(!all.lines().any(|l| l.starts_with("approve in a browser:")), "{all}");
        assert!(!all.contains(['\u{1b}', '\u{202e}']), "{all}");
    }

    #[test]
    fn errors_are_shown_on_one_line_and_keep_their_exit_code() {
        let toml = "remote.toml: TOML parse error at line 1, column 7\n  |\n1 | url = [\n  |       ^\ninvalid array";
        for (e, code) in [
            (Error::Remote("u: a\nResolve x? [y/N] ".into()), 8),
            (Error::invalid(toml), 2),
            (Error::AnswerLost("u: lost\nagain".into()), 9),
            (Error::Unauthorized("a\nb".into()), 7),
        ] {
            let e = one_line(e);
            assert_eq!(e.exit_code(), code);
            let text = crate::render_error(&e, false, None);
            assert_eq!(text.lines().filter(|l| l.starts_with("error: ")).count(), 1, "{text}");
            assert!(!e.to_string().contains('\n'), "{e}");
        }
        let e = one_line(Error::with_needs(&[bd_core::Need::Human], "x\ny").with_gate("g-1"));
        assert_eq!((e.needs(), e.gate(), e.exit_code()), (&[bd_core::Need::Human][..], Some("g-1"), 7));
        assert!(!e.to_string().contains('\n'));
    }

    #[test]
    fn only_people_at_a_terminal_review_gates() {
        let asked = Cell::new(0);
        let terminal = || {
            asked.set(asked.get() + 1);
            true
        };
        let in_session = |v: &str| (v == "COPILOT_AGENT_SESSION_ID").then(|| "s1".to_string());
        let e = people_only(&in_session, &terminal).unwrap_err();
        assert_eq!(e.exit_code(), 2);
        let text = e.to_string();
        assert!(text.contains("$COPILOT_AGENT_SESSION_ID") && text.contains("`bd gate review`"), "{text}");
        assert_eq!(asked.get(), 0, "the session is checked first");
        let none = |_: &str| -> Option<String> { None };
        let e = people_only(&none, &|| false).unwrap_err();
        assert!(matches!(e, Error::Refused(_)), "{e:?}");
        assert!(e.to_string().contains("terminal"), "{e}");
        people_only(&none, &terminal).unwrap();
        assert_eq!(asked.get(), 1);
    }

    #[test]
    fn server_answers_are_read_strictly() {
        let view = serde_json::to_value(human("g-1")).unwrap();
        let d = parse_show(&view).unwrap();
        assert_eq!((d.view.id.as_str(), d.part_of), ("g-1", None));
        let mut with = view.clone();
        with["part_of"] = json!({"id": "r-1", "title": "Run"});
        with["approval_url"] = json!("https://x/w/p/gates/g-1");
        assert_eq!(parse_show(&with).unwrap().part_of, Some(("r-1".into(), "Run".into())));
        let mut broken = view.clone();
        broken.as_object_mut().unwrap().remove("phase");
        assert!(parse_show(&broken).is_err());

        let mut future = serde_json::to_value(gate("g-2", "New", GateKind::Timer, GatePhase::Armed)).unwrap();
        future["spec"]["type"] = json!("quantum");
        let timer = serde_json::to_value(gate("g-3", "Wait", GateKind::Timer, GatePhase::Armed)).unwrap();
        let listed = parse_list(&json!([future, view, timer])).unwrap();
        assert_eq!(listed.iter().map(|g| g.id.as_str()).collect::<Vec<_>>(), ["g-1"]);
        assert!(parse_list(&json!({"error": 1})).is_err());
        assert!(parse_list(&json!([broken])).is_err(), "a human entry is read strictly");

        let r = parse_resolved(&json!({
            "issue": {"id": "g-1"}, "already_closed": false,
            "unblocked": [{"id": "t-1", "title": "Ship"}]
        }))
        .unwrap();
        assert_eq!((r.already_open, r.unblocked, r.completed), (false, vec![("t-1".into(), "Ship".into())], vec![]));
        assert!(parse_resolved(&json!({"issue": {"id": "g-1"}})).is_err());

        let failed = ExecResponse {
            exit_code: 7,
            stderr: "{\"error\":{\"code\":\"unauthorized\",\"message\":\"no\\nway\",\"exit_code\":7}}\n".into(),
            ..Default::default()
        };
        assert_eq!(
            failure_of(&failed),
            Failure { code: "unauthorized".into(), message: "no\\u{a}way".into(), exit_code: 7 }
        );
        let plain = ExecResponse { exit_code: 4, stderr: "error: held\nmore".into(), ..Default::default() };
        assert_eq!(failure_of(&plain), Failure { code: "failed".into(), message: "held".into(), exit_code: 4 });

        assert_eq!(actor_of_info(&json!({"actor": "a/s", "token": {"actor": "a"}})).as_deref(), Some("a"));
        assert_eq!(actor_of_info(&json!({"actor": "a", "token": null})).as_deref(), Some("a"));
        assert_eq!(actor_of_info(&json!({})), None);
    }
}
