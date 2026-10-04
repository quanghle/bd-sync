//! `[[github.allow]]` rules: whom they let in, and what they grant
//! (`decide`).

use super::*;

/// One `[[github.allow]]` rule: whom it lets in, and what their token may do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// Any GitHub account: the rule names nobody, and is the last.
    pub anyone: bool,
    /// Logins, matched whatever their case.
    pub users: Vec<String>,
    pub orgs: Vec<String>,
    /// `(organization, team slug)`.
    pub teams: Vec<(String, String)>,
    /// Accounts GitHub created less than this long ago are not let in by the rule.
    pub min_account_age: Option<Duration>,
    pub grant: Grant,
}

/// Whether a GitHub account belongs to an organization or a team.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Member {
    Yes,
    No,
    /// GitHub would not tell, and why: the account counts as no member.
    Unknown(String),
}

/// The memberships of the account signing in, asked of GitHub as rules need them.
pub trait Memberships {
    fn org(&mut self, org: &str) -> Result<Member>;
    fn team(&mut self, org: &str, team: &str) -> Result<Member>;
}

/// What the rules make of an account signing in to a workspace.
#[derive(Debug)]
pub enum Decision {
    /// What the first rule that lets the account into the workspace grants
    /// it, what matched (`GitHub user alice`, `member of acme`), and whether
    /// that was its login in the rule's `users`.
    In { grant: Grant, via: String, by_login: bool },
    /// Rules let the account in, but only into these other workspaces.
    Elsewhere(Vec<String>),
    /// A rule would let the account into the workspace, were its GitHub
    /// account this old (the least such `min_account_age`).
    TooNew(Duration),
    /// No rule lets the account in.
    Out,
    /// GitHub would not tell whether a rule that covers the workspace lets
    /// the account in (a membership it keeps from this server): later rules
    /// are not tried, as they may grant more than that one would.
    Unknown,
}

/// The first rule that lets `login` into `workspace`: a rule that lets the
/// account in elsewhere only leaves it to the rules after it, and then the
/// grant covers `workspace` alone, never one where an earlier rule decides.
/// A rule whose `min_account_age` the account's `age` falls short of (or
/// whose age GitHub did not tell) does not let it in. Memberships GitHub
/// would not tell are noted in `unknown`.
pub fn decide(
    github: &Github,
    login: &str,
    age: Option<Duration>,
    workspace: &str,
    m: &mut dyn Memberships,
    unknown: &mut Vec<String>,
) -> Result<Decision> {
    let mut elsewhere: Vec<String> = Vec::new();
    let mut too_new: Option<Duration> = None;
    for rule in &github.rules {
        let before = unknown.len();
        let Some((via, by_login)) = lets_in(rule, login, m, unknown)? else {
            // Not knowing is not "no": a rule further down may grant more than this one would have.
            if unknown.len() > before && rule.grant.allows_workspace(workspace) {
                return Ok(Decision::Unknown);
            }
            continue;
        };
        if let Some(min) = rule.min_account_age.filter(|min| age.is_none_or(|age| age < *min)) {
            if rule.grant.allows_workspace(workspace) {
                too_new = Some(too_new.map_or(min, |t| t.min(min)));
            }
            continue;
        }
        if rule.grant.allows_workspace(workspace) {
            let mut grant = rule.grant.clone();
            if !elsewhere.is_empty() {
                grant.workspaces = vec![workspace.to_string()];
            }
            return Ok(Decision::In { grant, via, by_login });
        }
        for w in &rule.grant.workspaces {
            if !elsewhere.contains(w) {
                elsewhere.push(w.clone());
            }
        }
    }
    Ok(match too_new {
        Some(min) => Decision::TooNew(min),
        None if elsewhere.is_empty() => Decision::Out,
        None => Decision::Elsewhere(elsewhere),
    })
}

/// What lets `login` in by `rule`, if anything, and whether it is the login.
pub(super) fn lets_in(
    rule: &Rule,
    login: &str,
    m: &mut dyn Memberships,
    unknown: &mut Vec<String>,
) -> Result<Option<(String, bool)>> {
    let mut note = |what: String| {
        if !unknown.contains(&what) {
            unknown.push(what);
        }
    };
    if rule.anyone {
        return Ok(Some((format!("GitHub user {login}, as anyone"), false)));
    }
    if rule.users.iter().any(|u| u.eq_ignore_ascii_case(login)) {
        return Ok(Some((format!("GitHub user {login}"), true)));
    }
    for org in &rule.orgs {
        match m.org(org)? {
            Member::Yes => return Ok(Some((format!("member of {org}"), false))),
            Member::No => {}
            Member::Unknown(why) => note(format!("{org}: {why}")),
        }
    }
    for (org, team) in &rule.teams {
        match m.team(org, team)? {
            Member::Yes => return Ok(Some((format!("member of team {org}/{team}"), false))),
            Member::No => {}
            Member::Unknown(why) => note(format!("team {org}/{team}: {why}")),
        }
    }
    Ok(None)
}
