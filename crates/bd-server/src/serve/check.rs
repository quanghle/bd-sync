//! `bd serve check`: `<root>/auth.toml` and its secret files read as a
//! running server reads them, and what to register at providers and
//! clients, without starting a server (a second one on a root must not run).

use super::*;
use bd_cli::app::Out;
use serde_json::json;

pub(super) fn check(app: &mut App, c: &ServeCheckArgs) -> Result<()> {
    let root = &c.root.root;
    if !root.is_dir() {
        return Err(Error::invalid(format!("--root {}: not a directory", root.display())));
    }
    crate::server_db::open_existing(root)?;
    let public_url = c
        .public_url
        .as_deref()
        .map(mcp_http::public_url)
        .transpose()
        .map_err(|e| Error::invalid(format!("--public-url {e}")))?;
    let Some(sign_in) = oauth::load(root)? else {
        let out = Out::new(json!({ "sign_in": false }))
            .line(format!("No {}: people get tokens from the admin only (bd serve token create).", oauth::FILE));
        app.print(out);
        return Ok(());
    };
    let workspaces: Vec<String> = std::fs::read_dir(root)?
        .filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|n| bd_cli::protocol::valid_workspace_name(n) && root.join(n).join(".bd").join("bd.db").is_file())
        .collect();
    let mut lines = vec![format!("✓ {} is valid", root.join(oauth::FILE).display())];
    let mut warnings = Vec::new();
    let decides = match &sign_in.authorizer {
        Some(_) => "the authorizer".to_string(),
        None => "rules".to_string(),
    };
    // Every provider alike: GitHub's issuer is where its accounts sign in.
    let github = sign_in.github.iter().map(|g| ("github", "GitHub", g.url.as_str()));
    let listed: Vec<(&str, &str, &str)> =
        github.chain(sign_in.oidc.iter().map(|o| (o.name.as_str(), o.label.as_str(), o.issuer.as_str()))).collect();
    let mut providers = Vec::new();
    for (name, label, issuer) in listed {
        let refreshed = sign_in.refreshes(name);
        providers.push(json!({ "name": name, "label": label, "issuer": issuer, "refreshed": refreshed }));
        lines.push(format!(
            "  {name}: {label} at {issuer}, decided by {decides}; tokens {}refreshed",
            if refreshed { "" } else { "not " }
        ));
        for r in sign_in.allow(name) {
            let rule = format!(
                "an [[{}.allow]] rule",
                if name == "github" { name.to_string() } else { format!("oidc.{name}") }
            );
            note_workspaces(&r.grant.workspaces, &workspaces, &rule, &mut warnings);
        }
    }
    for file in sign_in.secret_files(root) {
        if let Some(mode) = open_to_others(&file) {
            warnings
                .push(format!("{} is readable by others than its owner (mode {mode:o}): chmod 600 it", file.display()));
        }
    }
    let mut register = Vec::new();
    match (&sign_in.oauth, public_url.as_deref()) {
        (Some(_), None) => warnings.push("[oauth] needs --public-url (or BD_SERVE_PUBLIC_URL): the issuer".into()),
        (Some(o), Some(url)) => {
            let issuer = oauth_server::issuer(Some(url)).map_err(Error::invalid)?;
            lines.push(format!(
                "  [oauth]: issuer {issuer}; redirects {}{}{}; registration {}",
                o.redirect_uris.join(", "),
                if o.redirect_hosts.is_empty() {
                    String::new()
                } else {
                    format!(" any path on {}", o.redirect_hosts.join(", "))
                },
                if o.loopback_redirects { ", this machine" } else { "" },
                if o.registration { "on" } else { "off" }
            ));
            for (name, label) in sign_in.browser_providers() {
                register.push(format!("{label}: callback (redirect) URL {issuer}{}", oauth_server::callback(name)));
            }
            for p in sign_in.oidc.iter().filter(|p| !p.account_events.is_empty()) {
                register.push(format!("{}: account notifications at {issuer}/oauth/{}/events", p.label, p.name));
            }
            for w in &workspaces {
                register.push(format!("MCP clients: {url}/w/{w}/mcp"));
            }
        }
        (None, _) => {}
    }
    if !register.is_empty() {
        lines.push("To register:".into());
        lines.extend(register.iter().map(|r| format!("  {r}")));
    }
    lines.extend(warnings.iter().map(|w| format!("warning: {w}")));
    let view = json!({ "sign_in": true, "providers": providers, "register": register, "warnings": warnings });
    app.print(lines.into_iter().fold(Out::new(view), Out::line));
    Ok(())
}

/// Warn of `named` workspaces no workspace under the root has.
fn note_workspaces(named: &[String], have: &[String], rule: &str, warnings: &mut Vec<String>) {
    for w in named.iter().filter(|w| *w != "*" && !have.contains(w)) {
        warnings.push(format!("{rule} names workspace {w}, which the root does not have (yet)"));
    }
}
