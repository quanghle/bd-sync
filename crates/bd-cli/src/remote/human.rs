//! The person's access token in the OS keychain (`bd remote login --human`),
//! used for a command only after the server refused it naming what it
//! `needs` with nothing committed (`forward`), or up front for `bd publish`.
//!
//! It is never looked at inside an agent session or without a terminal on
//! stdin, both checked before the keychain is opened, and only a token whose
//! saved kind and role cover what the command needs, saved trusting the CA
//! this remote is reached through, is sent.

use bd_core::{Error, Need};

use super::{Configured, Remote, Trust, config};
use crate::actor::{self, Env};
use crate::keychain;
use crate::tokens::{Kind, Role};

/// Why the person's token was not used.
#[derive(Debug)]
pub(super) enum Skip {
    AgentSession,
    NotTerminal,
    NoToken,
    /// The keychain could not be read: why.
    Unavailable(String),
    /// The token saved may not do what the command needs.
    Uncovered {
        kind: Kind,
        role: Role,
        needs: Vec<Need>,
    },
    /// It was saved trusting another CA than this remote is reached through: why.
    Trust(String),
}

/// Whether the keychain may be looked at: outside agent sessions, with a
/// terminal on stdin. Nothing of the keychain is touched before this passes.
fn gate(env: &Env<'_>, terminal: &dyn Fn() -> bool) -> Result<(), Skip> {
    if !actor::agent_session_vars(env).is_empty() {
        return Err(Skip::AgentSession);
    }
    if !terminal() {
        return Err(Skip::NotTerminal);
    }
    Ok(())
}

/// A remote sending the person's token saved for `c.url`, reached under
/// `trust` (the same snapshot its renewal rechecks under the lock), when it
/// may be used for a command that `needs` these rights; and the note saying so.
pub(super) fn human_remote(c: Configured, trust: Trust, needs: &[Need]) -> Result<(Remote, String), Skip> {
    gate(&actor::env, &keychain::stdin_is_terminal)?;
    let unavailable = |e: bd_core::Error| Skip::Unavailable(keychain::reason(&e));
    let store = keychain::open(keychain::IMPLICIT).map_err(unavailable)?;
    let human = keychain::lookup(&store, &c.url).map_err(unavailable)?.ok_or(Skip::NoToken)?;
    let entry = human.entry;
    if config::saved_trust_error(&c.url, &human.key, &entry.ca, &trust).is_some() {
        return Err(Skip::Trust(format!(
            "the person's access token saved for {} in the {} was saved trusting another CA certificate than {} is \
             now reached through, so it was not sent; if that CA is trusted, save it again with `bd remote login \
             --human`",
            human.key,
            store.name(),
            c.url
        )));
    }
    if !keychain::covers(entry.kind, entry.role, needs) {
        return Err(Skip::Uncovered { kind: entry.kind, role: entry.role, needs: needs.to_vec() });
    }
    let note = format!(
        "bd: using the person's access token saved in the {} (role {}) for this command",
        store.name(),
        entry.role.as_str()
    );
    let renewal = entry.renewal();
    let remote = Remote::new(c, trust, entry.token).renewing_keychain(store, human.key, renewal);
    Ok((remote, note))
}

/// What to tell the person about a skip, in text mode: nothing when there
/// was no token to use or no person to use it (the server's hint covers
/// those), else why the token saved was not used. Never a secret.
pub(super) fn skip_note(skip: &Skip) -> Option<String> {
    match skip {
        Skip::AgentSession | Skip::NotTerminal | Skip::NoToken => None,
        Skip::Unavailable(why) => Some(format!("bd: keychain unavailable: {why}")),
        Skip::Uncovered { kind, role, needs } => Some(format!(
            "bd: the person's access token saved in the keychain is role {}, kind {}, and this command needs {}, so \
             it was not used",
            role.as_str(),
            kind.as_str(),
            needed(needs)
        )),
        Skip::Trust(why) => Some(format!("bd: {why}")),
    }
}

/// Why a command that sends only the person's token (`bd gate review`)
/// cannot run against `url`: no token saved (exit 7), a keychain that
/// cannot be read (exit 2), a token that may not do it or was saved
/// trusting another CA (exit 7), or no person at a terminal (exit 2).
/// Never a secret.
pub(super) fn person_error(skip: Skip, url: &str) -> Error {
    match skip {
        Skip::NoToken => Error::Unauthorized(format!(
            "no person's access token is saved in the keychain for {url}; save one with `bd remote login --human`"
        )),
        Skip::Unavailable(why) => {
            Error::Refused(format!("keychain unavailable: {}", crate::agents::show::printable(&why)))
        }
        Skip::AgentSession => {
            Error::Refused("the person's access token in the keychain is not used inside an agent session".into())
        }
        Skip::NotTerminal => Error::Refused(
            "the person's access token in the keychain is used only with a terminal on stdin (stdin is not one)".into(),
        ),
        skip @ (Skip::Uncovered { .. } | Skip::Trust(_)) => {
            let note = skip_note(&skip).unwrap_or_default();
            Error::Unauthorized(note.strip_prefix("bd: ").unwrap_or(&note).to_string())
        }
    }
}

/// What a command needs, for people.
fn needed(needs: &[Need]) -> &'static str {
    match (needs.contains(&Need::Admin), needs.contains(&Need::Human)) {
        (true, true) => "a person's admin token",
        (true, false) => "an admin token",
        _ => "a person's token (kind human)",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_keychain_is_not_looked_at_in_agent_sessions_or_without_a_terminal() {
        let none = |_: &str| -> Option<String> { None };
        let in_session = |v: &str| (v == "COPILOT_AGENT_SESSION_ID").then(|| "s1".to_string());
        let asked = std::cell::Cell::new(false);
        let terminal = || {
            asked.set(true);
            true
        };
        assert!(matches!(gate(&in_session, &terminal), Err(Skip::AgentSession)));
        assert!(!asked.get(), "the session is checked first");
        assert!(matches!(gate(&none, &|| false), Err(Skip::NotTerminal)));
        assert!(gate(&none, &terminal).is_ok());
    }

    #[test]
    fn a_person_only_command_says_why_the_keychain_token_was_not_used() {
        let url = "https://bd.example.com/w/proj";
        let cases = [
            (Skip::NoToken, 7),
            (Skip::Unavailable("test keychain:\nunavailable".into()), 2),
            (Skip::Uncovered { kind: Kind::Agent, role: Role::Write, needs: vec![Need::Human] }, 7),
            (Skip::Trust("saved trusting another CA certificate".into()), 7),
            (Skip::AgentSession, 2),
            (Skip::NotTerminal, 2),
        ];
        for (skip, code) in cases {
            let shown = format!("{skip:?}");
            let e = person_error(skip, url);
            assert_eq!(e.exit_code(), code, "{shown}");
            let text = e.to_string();
            assert!(!text.contains("bdt_") && !text.contains("bdr_") && !text.starts_with("bd: "), "{text}");
            assert!(!text.contains('\n'), "{text}");
        }
        let text = person_error(Skip::NoToken, url).to_string();
        assert!(text.contains(url) && text.contains("bd remote login --human"), "{text}");
        let text =
            person_error(Skip::Uncovered { kind: Kind::Agent, role: Role::Write, needs: vec![Need::Human] }, url)
                .to_string();
        assert!(
            text.starts_with("the person's access token saved in the keychain is role write, kind agent"),
            "{text}"
        );
    }

    #[test]
    fn skip_notes_say_why_and_never_a_secret() {
        for silent in [Skip::AgentSession, Skip::NotTerminal, Skip::NoToken] {
            assert!(skip_note(&silent).is_none(), "{silent:?}");
        }
        let notes = [
            skip_note(&Skip::Unavailable("test keychain: unavailable".into())).unwrap(),
            skip_note(&Skip::Uncovered { kind: Kind::Human, role: Role::Write, needs: vec![Need::Admin] }).unwrap(),
            skip_note(&Skip::Uncovered { kind: Kind::Agent, role: Role::Admin, needs: vec![Need::Admin, Need::Human] })
                .unwrap(),
            skip_note(&Skip::Trust("saved trusting another CA certificate".into())).unwrap(),
        ];
        assert_eq!(notes[0], "bd: keychain unavailable: test keychain: unavailable");
        assert!(notes[1].contains("is role write, kind human") && notes[1].contains("needs an admin token"));
        assert!(notes[2].contains("needs a person's admin token"), "{}", notes[2]);
        assert!(notes[3].contains("another CA"));
        for note in &notes {
            assert!(note.starts_with("bd: ") && !note.contains("bdt_") && !note.contains("bdr_"), "{note}");
        }
    }
}
