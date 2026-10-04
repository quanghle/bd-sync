//! `bd serve token …`: an admin's commands, on this machine.

use super::*;

fn root_dir(a: &TokenRootArgs) -> Result<PathBuf> {
    if !a.root.is_dir() {
        return Err(Error::invalid(format!("--root {}: not a directory", a.root.display())));
    }
    // A workspace's own directory is a likely slip: its tokens would be in a server.db no server reads.
    if a.root.join(".bd").is_dir() {
        return Err(Error::invalid(format!(
            "--root {}: that is a workspace (it has .bd/); --root names the directory holding the workspaces",
            a.root.display()
        )));
    }
    Ok(a.root.clone())
}

pub fn cmd_token(app: &mut App, cmd: &TokenCommand) -> Result<()> {
    match cmd {
        TokenCommand::Create(a) => create(app, a),
        TokenCommand::List(a) => list(app, a),
        TokenCommand::Accounts(a) => accounts(app, a),
        TokenCommand::Revoke(a) => revoke(app, a),
        TokenCommand::Events(a) => events(app, a),
        TokenCommand::Link(a) => link_command(app, a),
        TokenCommand::Name(a) => name_command(app, a),
    }
}

pub(super) fn create(app: &mut App, a: &TokenCreateArgs) -> Result<()> {
    let root = root_dir(&a.root)?;
    let grant = Grant { role: a.role, kind: a.kind, workspaces: a.workspaces.clone(), max_claims: a.max_claims };
    let holder = Holder::Admin { name: a.name.trim(), actor: a.act_as.trim(), resource: a.resource.as_deref() };
    let (token, secret) = add_token(&root, holder, grant).map(|issued| (issued.token, issued.secret))?;
    // Workspaces are named before they exist, which may be on purpose; a typo is not, so say so.
    for w in token.workspaces.iter().filter(|w| *w != "*") {
        if !root.join(w).join(".bd").join("bd.db").is_file() {
            crate::io::errln(format!(
                "warning: no workspace {w} under {}: the token works there once it exists",
                root.display()
            ));
        }
    }
    let mut view = token.view();
    view["token"] = json!(secret);
    let out = Out::new(view)
        .line(format!("✓ Created access token {}: {}", token.name, token.describe()))
        .line(secret.clone())
        .line(match &token.resource {
            Some(url) => format!(
                "Shown only once. It works at {url} only: give it to the MCP client as its bearer token \
                 (docs/mcp.md, Connecting clients)."
            ),
            None => "Shown only once. On the client, save it with `bd remote login`, or set it as BD_TOKEN.".into(),
        })
        .id(secret);
    app.print(out);
    Ok(())
}

pub(super) fn list(app: &mut App, a: &TokenRootArgs) -> Result<()> {
    let file = read(&root_dir(a)?)?;
    let now = Timestamp::now();
    let mut out = Out::new(file.tokens.iter().map(Token::view).collect::<Vec<_>>());
    if file.tokens.is_empty() {
        out = out.line(
            "No access tokens. Create one with `bd serve token create <name> --as <actor>`, or let people sign in \
             (auth.toml).",
        );
    }
    for t in &file.tokens {
        out = out.line(format!("{:<20} {}  ({})", t.name, t.describe(), t.state(now))).id(t.name.clone());
    }
    app.print(out);
    Ok(())
}

fn name_command(app: &mut App, a: &TokenNameArgs) -> Result<()> {
    let name = a.name.as_deref().map(str::trim);
    let account = set_name(&root_dir(&a.root)?, a.account.trim(), name)?;
    let line = match &account.name {
        Some(n) => format!("✓ {} ({}) is named {n}", account.actor, account.who()),
        None => format!("✓ {} ({}) has no name", account.actor, account.who()),
    };
    app.print(Out::new(json!(account)).line(line));
    Ok(())
}

fn link_command(app: &mut App, a: &TokenLinkArgs) -> Result<()> {
    let done = link(&root_dir(&a.root)?, a.account.trim(), a.to.trim())?;
    let to = &done.account.actor;
    let mut out = Out::new(json!({
        "account": done.account, "was": done.was, "actor": to, "revoked": done.revoked,
    }))
    .line(format!("✓ Linked {} to actor {to} (it acted as {})", done.account.who(), done.was));
    if !done.revoked.is_empty() {
        out = out.line(format!(
            "  Revoked its {} token{} ({}): its next sign-in acts as {to}",
            done.revoked.len(),
            if done.revoked.len() == 1 { "" } else { "s" },
            done.revoked.join(", ")
        ));
    }
    app.print(out);
    Ok(())
}

pub(super) fn events(app: &mut App, a: &TokenEventsArgs) -> Result<()> {
    let root = root_dir(&a.root)?;
    let since = match &a.since {
        Some(d) => Timestamp::now().millis() - bd_core::time::parse_duration(d)?.as_millis() as i64,
        None => 0,
    };
    if let Some(kind) = a.kinds.iter().find(|k| !server_db::KINDS.contains(&k.as_str())) {
        return Err(Error::invalid(format!("--kind {kind:?} is not one of {}", server_db::KINDS.join(", "))));
    }
    let events = server_db::events(&root, since, a.actor.as_deref(), &a.kinds, a.limit)?;
    let mut out = Out::new(json!(events));
    if events.is_empty() {
        out = out.line("No events.");
    }
    for e in &events {
        let ev = &e.event;
        let mut line = format!("{} {:<17}", e.at, ev.kind);
        for (name, value) in [
            ("", &ev.actor),
            ("token ", &ev.token),
            ("client ", &ev.client),
            ("subject ", &ev.subject),
            ("at ", &ev.provider),
        ] {
            if let Some(v) = value {
                line.push_str(&format!(" {name}{v}"));
            }
        }
        if let Some(why) = &ev.detail {
            line.push_str(&format!(": {why}"));
        }
        out = out.line(line);
    }
    app.print(out);
    Ok(())
}

pub(super) fn accounts(app: &mut App, a: &TokenRootArgs) -> Result<()> {
    let file = read(&root_dir(a)?)?;
    let now = Timestamp::now();
    let live = |account: &Account| {
        // Expired sign-ins that may still be refreshed count: their clients carry on.
        file.tokens
            .iter()
            .filter(|t| !t.ended(now))
            .filter(|t| t.identity.as_ref().is_some_and(|g| account.is(g)))
            .count()
    };
    let views: Vec<serde_json::Value> = file
        .accounts
        .iter()
        .map(|account| {
            let mut view = json!(account);
            view["live_tokens"] = json!(live(account));
            view
        })
        .collect();
    let mut out = Out::new(views);
    if file.accounts.is_empty() {
        out = out.line("No account is bound to an actor.");
    }
    for account in &file.accounts {
        let n = live(account);
        out = out
            .line(format!(
                "{:<20} {}{} (subject {} at {}), signed in first {}, last {}; {n} live token{}",
                account.actor,
                account.name.as_deref().map(|n| format!("{n}: ")).unwrap_or_default(),
                account.who(),
                account.subject,
                account.issuer,
                account.first_seen,
                account.last_seen,
                if n == 1 { "" } else { "s" }
            ))
            .id(account.actor.clone());
    }
    app.print(out);
    Ok(())
}

pub(super) fn revoke(app: &mut App, a: &TokenRevokeArgs) -> Result<()> {
    let root = root_dir(&a.root)?;
    if let Some(client) = a.client.as_deref().map(str::trim) {
        let theirs = |t: &Token| t.client.as_deref() == Some(client);
        let (known, revoked) = revoke_where(&root, "an admin revoked the client's tokens", theirs)?;
        if known == 0 {
            return Err(Error::not_found("OAuth client with access tokens", client));
        }
        let text = match revoked.len() {
            0 => format!("= OAuth client {client} has no live access tokens"),
            1 => format!("✓ Revoked the access token of OAuth client {client}: {}", revoked[0]),
            n => format!("✓ Revoked {n} access tokens of OAuth client {client}: {}", revoked.join(", ")),
        };
        let out = Out::new(json!({ "client": client, "revoked": revoked })).line(text);
        app.print(revoked.iter().fold(out, |out, name| out.id(name.clone())));
        return Ok(());
    }
    match (&a.name, a.account.as_deref().map(str::trim)) {
        (Some(name), None) => {
            let named = |t: &Token| t.name == *name;
            let (known, revoked) = revoke_where(&root, "an admin revoked it", named)?;
            if known == 0 {
                return Err(Error::not_found("access token", name.as_str()));
            }
            let text = match revoked.is_empty() {
                true => format!("= {name} was already revoked"),
                false => format!("✓ Revoked access token {name}"),
            };
            app.print(Out::new(json!({ "name": name, "revoked": revoked })).line(text).id(name.clone()));
        }
        (None, Some(login)) => {
            let done = revoke_account(&root, login, a.forget)?;
            let view = json!({
                "account": login, "revoked": done.revoked, "accounts": done.accounts, "forgot": a.forget,
                "erased": done.erased,
            });
            let mut out = Out::new(view).line(match done.revoked.len() {
                0 => format!("= account {login} has no live access tokens"),
                1 => format!("✓ Revoked the access token of account {login}: {}", done.revoked[0]),
                n => format!("✓ Revoked {n} access tokens of account {login}: {}", done.revoked.join(", ")),
            });
            for account in &done.accounts {
                out = out.line(match a.forget {
                    true => format!(
                        "✓ Released actor {} of {} (subject {}) and deleted its records: the next account to sign in \
                         as {} gets it",
                        account.actor,
                        account.who(),
                        account.subject,
                        account.actor
                    ),
                    false => format!(
                        "  actor {} stays bound to {} (subject {}); --forget releases it",
                        account.actor,
                        account.who(),
                        account.subject
                    ),
                });
            }
            if done.erased == Some(false) {
                out = out.line(
                    "  The deleted records stay in server.db's write-ahead log until bd serve's next checkpoint, \
                     which overwrites them",
                );
            }
            app.print(done.revoked.iter().fold(out, |out, name| out.id(name.clone())));
        }
        _ => return Err(Error::invalid("name the access token to revoke, or an account with --account")),
    }
    Ok(())
}
