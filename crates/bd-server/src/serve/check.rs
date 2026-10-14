//! `bd serve check`: `<root>/auth.toml` and its secret files read as a
//! running server reads them, and what to register at providers and clients,
//! without starting a server (a second one on a root must not run). Its
//! `[secrets]` command runs, on Unix, only for the root's owner (`gate`):
//! anyone else, root included, is forbidden every command (`helper::forbid`)
//! before anything loads, and refused when `auth.toml` has `[secrets]`.

use super::*;
use bd_cli::app::Out;
use serde_json::json;

pub(super) fn check(app: &mut App, c: &ServeCheckArgs) -> Result<()> {
    if !c.root.root.is_dir() {
        return Err(Error::invalid(format!("--root {}: not a directory", c.root.root.display())));
    }
    // One path for everything after: the gate, server.db, auth.toml, and the command's directory.
    let root = &canonical_root(&c.root.root)?;
    // Only the root's owner runs its [secrets] command, which it could change anyway; anyone else is forbidden every
    // command before anything loads, and refused outright when auth.toml has [secrets].
    #[cfg(unix)]
    gate(root)?;
    crate::server_db::open_existing(root)?;
    let public_url = c
        .public_url
        .as_deref()
        .map(mcp_http::public_url)
        .transpose()
        .map_err(|e| Error::invalid(format!("--public-url {e}")))?;
    // Secrets the [secrets] command does not give fail the check as a mistake would.
    let (sign_in, unanswered) = oauth::load_at_start(root)?;
    if let Some(why) = unanswered {
        return Err(Error::invalid(why));
    }
    let Some(sign_in) = sign_in else {
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
    // How many, not their names: a value pasted in a name's place would be printed.
    let secrets = sign_in.secret_names().len();
    if let Some(s) = &sign_in.secrets {
        lines.push(format!("  [secrets]: {secrets} fetched by {}", s.helper.argv[0]));
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
    let view = json!({
        "sign_in": true, "providers": providers, "secrets": secrets, "register": register, "warnings": warnings,
    });
    app.print(lines.into_iter().fold(Out::new(view), Out::line));
    Ok(())
}

/// The root as typed, made canonical on Unix (where the gate decides by its
/// owner). Elsewhere as typed: no gate there, and a verbatim `\\?\` path
/// would keep a root-relative command's `/` unparsed.
fn canonical_root(root: &std::path::Path) -> Result<std::path::PathBuf> {
    if cfg!(unix) {
        std::fs::canonicalize(root).map_err(|e| Error::invalid(format!("--root {}: {e}", root.display())))
    } else {
        Ok(root.to_path_buf())
    }
}

/// Whether this process may run the root's `[secrets]` command: only as the
/// root directory's owner, who can change everything under it anyway. Run as
/// anyone else (root included: it would run what the owner wrote with root's
/// rights), no command runs, and with `[secrets]` the check stops here,
/// before any file `auth.toml` names is read.
#[cfg(unix)]
fn gate(root: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let owner = std::fs::metadata(root).map_err(|e| Error::invalid(format!("{}: {e}", root.display())))?.uid();
    // SAFETY: geteuid(2) cannot fail and touches no memory.
    let me = unsafe { libc::geteuid() };
    gate_as(root, owner, me)
}

/// [`gate`] for a root owned by `owner`, run as `me`.
#[cfg(unix)]
fn gate_as(root: &std::path::Path, owner: u32, me: u32) -> Result<()> {
    let Some(why) = refusal(root, owner, user_name(owner).as_deref(), me) else {
        return Ok(());
    };
    crate::helper::forbid(why.clone());
    if wants_secrets(root) {
        return Err(Error::invalid(format!("{}: {why}", root.display())));
    }
    Ok(())
}

/// Why `me` may not run the `[secrets]` command of a root `owner` (named
/// `name`, if a plain name) owns, and what to do instead; `None` for its owner.
#[cfg(unix)]
fn refusal(root: &std::path::Path, owner: u32, name: Option<&str>, me: u32) -> Option<String> {
    if owner == me {
        return None;
    }
    let (who, user) = match name {
        Some(n) => (format!("{n}, uid {owner}"), n.to_string()),
        None => (format!("uid {owner}"), format!("'#{owner}'")),
    };
    Some(format!(
        "[secrets] runs a command, which bd serve check runs only as the root's owner ({who}), not as uid {me}: \
         run it as that user (for example sudo -u {user} bd serve check --root {})",
        shell_word(&root.display().to_string())
    ))
}

/// `word` as a shell reads it back whole: as is when made of plain path
/// characters, else single-quoted (each `'` written `'\''`), control
/// characters shown as `?`.
#[cfg(unix)]
fn shell_word(word: &str) -> String {
    if !word.is_empty() && word.bytes().all(|b| b.is_ascii_alphanumeric() || b"._/-+@:,".contains(&b)) {
        return word.to_string();
    }
    let shown: String = word.chars().map(|c| if c.is_control() { '?' } else { c }).collect();
    format!("'{}'", shown.replace('\'', "'\\''"))
}

/// The user name of `uid`, when it is a plain one (ASCII letters, digits,
/// `.`, `_`, `-`): nothing odd reaches a terminal or a suggested command.
#[cfg(unix)]
fn user_name(uid: u32) -> Option<String> {
    // SAFETY: passwd is plain data (integers and pointers), for which all zeroes is a valid value.
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut buf = vec![0 as libc::c_char; 4096];
    let mut found: *mut libc::passwd = std::ptr::null_mut();
    // SAFETY: every pointer is valid for the call, buf's length is passed, and getpwuid_r points pwd's strings into
    // buf, which outlives their use below.
    let rc = unsafe { libc::getpwuid_r(uid, &mut pwd, buf.as_mut_ptr(), buf.len(), &mut found) };
    if rc != 0 || found.is_null() || pwd.pw_name.is_null() {
        return None;
    }
    // SAFETY: on success pw_name is a NUL-terminated string within buf.
    let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) }.to_str().ok()?;
    let plain = !name.is_empty() && name.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b));
    plain.then(|| name.to_string())
}

/// Whether `<root>/auth.toml` (followed if a link) is a regular file whose
/// plain TOML has `[secrets]`. Nothing it names is read, and a pipe never
/// holds the check; a miss only changes the message, as `forbid` stops any
/// command anyway.
#[cfg(unix)]
fn wants_secrets(root: &std::path::Path) -> bool {
    let config = root.join(oauth::FILE);
    if !std::fs::metadata(&config).is_ok_and(|m| m.is_file()) {
        return false;
    }
    let Ok(text) = std::fs::read_to_string(&config) else {
        return false;
    };
    toml::from_str::<toml::Table>(&text).is_ok_and(|t| t.contains_key("secrets"))
}

/// Warn of `named` workspaces no workspace under the root has.
fn note_workspaces(named: &[String], have: &[String], rule: &str, warnings: &mut Vec<String>) {
    for w in named.iter().filter(|w| *w != "*" && !have.contains(w)) {
        warnings.push(format!("{rule} names workspace {w}, which the root does not have (yet)"));
    }
}

#[cfg(all(test, unix))]
mod tests {
    use crate::helper::forbid_tests::{child_dir, rerun};
    use std::path::Path;

    #[test]
    fn refusal_names_the_owner() {
        let root = Path::new("/srv/bd");
        assert_eq!(super::refusal(root, 1000, Some("alice"), 1000), None, "the owner");
        let e = super::refusal(root, 1000, Some("alice"), 0).unwrap();
        assert!(e.contains("uid 1000") && e.contains("not as uid 0") && e.contains("sudo -u alice"), "{e}");
        assert!(e.contains("[secrets] runs a command") && e.contains("--root /srv/bd"), "{e}");
        let e = super::refusal(root, 1000, None, 1001).unwrap();
        assert!(e.contains("sudo -u '#1000'") && e.contains("not as uid 1001"), "{e}");
        // A root a shell would split or run part of is quoted, so the example can be pasted as it is.
        let e = super::refusal(Path::new("/srv/my bd;x'y"), 1000, Some("alice"), 0).unwrap();
        assert!(e.ends_with("--root '/srv/my bd;x'\\''y')"), "{e}");
    }

    #[test]
    fn the_owner_may_run_the_command() {
        // The test's own directory: the test user's, root's when tests run as root.
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("auth.toml"), "[secrets]\ncommand = [\"/bin/true\"]\n").unwrap();
        assert!(super::gate(dir.path()).is_ok());
        assert!(crate::helper::forbidden().is_none());
    }

    #[test]
    fn what_auth_toml_wants_is_read_as_plain_toml() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("root");
        std::fs::create_dir(&root).unwrap();
        let config = root.join("auth.toml");
        assert!(!super::wants_secrets(&root), "missing");
        std::fs::write(&config, "[github]\nclient_id = \"x\"\n").unwrap();
        assert!(!super::wants_secrets(&root), "no [secrets]");
        std::fs::write(&config, "[secrets\n").unwrap();
        assert!(!super::wants_secrets(&root), "invalid");
        std::fs::write(&config, "[secrets]\ncommand = [\"bin/x\"]\n").unwrap();
        assert!(super::wants_secrets(&root), "[secrets]");
        // A link to a file elsewhere is read as the file.
        std::fs::remove_file(&config).unwrap();
        std::fs::write(dir.path().join("elsewhere.toml"), "[secrets]\ncommand = [\"bin/x\"]\n").unwrap();
        std::os::unix::fs::symlink(dir.path().join("elsewhere.toml"), &config).unwrap();
        assert!(super::wants_secrets(&root), "a link");
        // Not a regular file: never opened, so a pipe with no writer does not hold the check.
        std::fs::remove_file(&config).unwrap();
        let made = std::process::Command::new("mkfifo").arg(&config).status().unwrap();
        assert!(made.success());
        assert!(!super::wants_secrets(&root), "a pipe");
    }

    /// Anyone but the owner (a root owned by another uid, as injected) runs no command, and is refused when
    /// auth.toml has [secrets]. In a child process: forbidding lasts for the process.
    #[test]
    fn anyone_else_runs_nothing_and_is_refused_with_secrets() {
        if let Some(dir) = child_dir() {
            // SAFETY: geteuid(2) cannot fail and touches no memory.
            let me = unsafe { libc::geteuid() };
            let owner = me.wrapping_add(1);
            let root = dir.join("root");
            std::fs::create_dir(&root).unwrap();
            super::gate_as(&root, owner, me).unwrap();
            let why = crate::helper::forbidden().expect("forbidden");
            assert!(why.contains(&format!("uid {owner}")), "{why}");
            std::fs::write(root.join("auth.toml"), "[github]\nclient_id = \"x\"\n").unwrap();
            super::gate_as(&root, owner, me).unwrap();
            std::fs::write(
                root.join("auth.toml"),
                "[secrets]\ncommand = [\"/bin/sh\", \"-c\", \"echo ran > marker\"]\n",
            )
            .unwrap();
            let e = super::gate_as(&root, owner, me).unwrap_err();
            assert_eq!(e.exit_code(), 2);
            let text = e.to_string();
            assert!(text.starts_with(&root.display().to_string()), "{text}");
            assert!(text.contains("[secrets] runs a command"), "{text}");
            assert!(!root.join("marker").exists(), "the command ran");
            return;
        }
        let dir = tempfile::tempdir().unwrap();
        rerun(concat!(module_path!(), "::anyone_else_runs_nothing_and_is_refused_with_secrets"), dir.path());
        assert!(!dir.path().join("root/marker").exists(), "the command ran");
    }
}
