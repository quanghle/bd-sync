//! `[[<provider>.allow]]` rules, one engine for every provider: whom they
//! let in, by what the provider proves of an account (`Facts`), and what
//! they grant (`decide`). A provider only proves: GitHub's adapter
//! (`github.rs`) asks GitHub, an OIDC provider's ID token says (`oidc.rs`).

use super::*;

/// `[[<provider>.allow]]` as written.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct RuleDoc {
    #[serde(default)]
    anyone: bool,
    #[serde(default)]
    subjects: Vec<String>,
    #[serde(default)]
    users: Vec<String>,
    #[serde(default)]
    emails: Vec<String>,
    #[serde(default)]
    email_domains: Vec<String>,
    #[serde(default)]
    groups: Vec<String>,
    #[serde(default)]
    min_account_age: Option<String>,
    #[serde(default)]
    role: Option<Role>,
    #[serde(default = "agent_kind")]
    kind: Kind,
    #[serde(default)]
    workspaces: Vec<String>,
    #[serde(default)]
    max_claims: Option<u32>,
}

/// What a provider proves of its accounts, and so which fields its rules
/// may use: GitHub proves logins, memberships and accounts' age, never an
/// email; an OIDC provider proves a verified email and groups, never a
/// login (people often choose their own `preferred_username`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Proves {
    Github,
    Oidc,
}

/// One `[[<provider>.allow]]` rule: whom it lets in, and what their token may do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// Any account of the provider: the rule names nobody, and is the last.
    pub anyone: bool,
    /// Accounts' subjects (GitHub user ids, `sub` claims): never change.
    pub subjects: Vec<String>,
    /// Logins, lowercased (GitHub).
    pub users: Vec<String>,
    /// Verified emails, lowercased (OIDC).
    pub emails: Vec<String>,
    /// Domains of verified emails, lowercased, without `@` (OIDC).
    pub email_domains: Vec<String>,
    /// GitHub organizations and teams (`acme`, `acme/eng`), or values of an
    /// OIDC provider's groups claim.
    pub groups: Vec<String>,
    /// Accounts made less than this long ago are not let in (GitHub).
    pub min_account_age: Option<Duration>,
    pub grant: Grant,
}

impl Rule {
    /// Whether it needs facts beyond the account's subject, which a refresh
    /// has only when the provider can be asked again.
    fn needs_facts(&self) -> bool {
        !(self.users.is_empty() && self.emails.is_empty() && self.email_domains.is_empty() && self.groups.is_empty())
            || self.min_account_age.is_some()
    }

    /// Whether what it matches may pass from one account to another (a login
    /// given up, an email given to someone else): an account let in so must
    /// not pass for an account that held it before (`auth::bind`).
    fn names_movable(&self) -> bool {
        !(self.users.is_empty() && self.emails.is_empty() && self.email_domains.is_empty())
    }

    /// What tells this rule from any other, or from itself changed: kept
    /// with a sign-in it let in.
    pub fn fingerprint(&self) -> String {
        auth::hash(&format!("{self:?}"))[..16].to_string()
    }
}

/// `[[<table>.allow]]`, checked for a provider that `proves` so much.
pub(crate) fn rules(table: &str, docs: Vec<RuleDoc>, proves: Proves) -> std::result::Result<Vec<Rule>, String> {
    let rules: Vec<Rule> = docs
        .into_iter()
        .enumerate()
        .map(|(i, r)| rule(table, i + 1, r, proves))
        .collect::<std::result::Result<_, _>>()?;
    check_anyone(table, &rules)?;
    Ok(rules)
}

/// A provider's `deny`: subjects of accounts that may never sign in.
pub(crate) fn deny_list(table: &str, deny: Vec<String>, proves: Proves) -> std::result::Result<Vec<String>, String> {
    deny.into_iter()
        .map(|s| {
            let s = s.trim().to_string();
            match subject_ok(&s, proves) {
                true => Ok(s),
                false => Err(format!("{table}.deny {s:?} is not {}", subject_kind(proves))),
            }
        })
        .collect()
}

fn subject_ok(s: &str, proves: Proves) -> bool {
    match proves {
        Proves::Github => !s.is_empty() && s.len() <= 20 && s.bytes().all(|b| b.is_ascii_digit()),
        Proves::Oidc => !s.is_empty() && s.len() <= 255 && s.chars().all(|c| !c.is_control() && !c.is_whitespace()),
    }
}

fn subject_kind(proves: Proves) -> &'static str {
    match proves {
        Proves::Github => "a GitHub user id (`bd serve token accounts` shows them)",
        Proves::Oidc => "an account's subject (its sub claim; `bd serve token accounts` shows them)",
    }
}

/// `[[<table>.allow]]` rule `n`, checked.
fn rule(table: &str, n: usize, r: RuleDoc, proves: Proves) -> std::result::Result<Rule, String> {
    let at = format!("[[{table}.allow]] rule {n}");
    let plain = |field: &str, list: Vec<String>, lower: bool, ok: &dyn Fn(&str) -> bool| {
        list.into_iter()
            .map(|s| {
                let v = s.trim();
                let v = if lower { v.to_lowercase() } else { v.to_string() };
                let plain = !v.is_empty() && v.len() <= 255 && v.chars().all(|c| !c.is_control() && !c.is_whitespace());
                match plain && ok(&v) {
                    true => Ok(v),
                    false => Err(format!("{at}: {field} {s:?} is not one")),
                }
            })
            .collect::<std::result::Result<Vec<_>, _>>()
    };
    let any = |_: &str| true;
    let github_group = |g: &str| match g.split_once('/') {
        Some((org, team)) => github_name(org) && github_name(team),
        None => github_name(g),
    };
    let subjects = plain("subjects", r.subjects, false, &|s| subject_ok(s, proves))?;
    let users = plain("users", r.users, true, &github_name)?;
    let emails = plain("emails", r.emails, true, &|e| e.contains('@'))?;
    let email_domains: Vec<String> = plain("email_domains", r.email_domains, true, &any)?
        .into_iter()
        .map(|d| d.trim_start_matches('@').to_string())
        .collect();
    let groups = match proves {
        Proves::Github => plain("groups", r.groups, true, &github_group)?,
        Proves::Oidc => plain("groups", r.groups, false, &any)?,
    };
    let min_account_age = match &r.min_account_age {
        None => None,
        Some(raw) => Some(bd_core::time::parse_duration(raw).map_err(|e| format!("{at}: min_account_age: {e}"))?),
    };
    match proves {
        Proves::Github if !(emails.is_empty() && email_domains.is_empty()) => {
            return Err(format!("{at}: GitHub proves no email: name users, subjects or groups"));
        }
        Proves::Oidc if !users.is_empty() => {
            return Err(format!(
                "{at}: an OIDC provider's logins are not proved names: name subjects, emails, email_domains or groups"
            ));
        }
        Proves::Oidc if min_account_age.is_some() => {
            return Err(format!(
                "{at}: min_account_age is GitHub's: an OIDC provider does not say when it made an account"
            ));
        }
        _ => {}
    }
    let names_someone = !(subjects.is_empty()
        && users.is_empty()
        && emails.is_empty()
        && email_domains.is_empty()
        && groups.is_empty());
    if r.anyone && names_someone {
        return Err(format!("{at} lets anyone in: drop whom it names, or anyone"));
    }
    if !r.anyone && !names_someone {
        return Err(format!("{at} names nobody, so it lets nobody in (anyone = true lets everyone)"));
    }
    let grant = rule_grant(&at, r.anyone, r.role, r.kind, &r.workspaces, r.max_claims)?;
    Ok(Rule { anyone: r.anyone, subjects, users, emails, email_domains, groups, min_account_age, grant })
}

/// What a rule grants, as written, checked (`at` names the rule): an
/// `anyone` rule lets in any account of its provider, and its throwaway
/// ones, so never as an admin nor a person who may open human gates.
fn rule_grant(
    at: &str,
    anyone: bool,
    role: Option<Role>,
    kind: Kind,
    workspaces: &[String],
    max_claims: Option<u32>,
) -> std::result::Result<Grant, String> {
    if anyone && role == Some(Role::Admin) {
        return Err(format!("{at} lets anyone in, so its role may be read or write, not admin"));
    }
    if anyone && kind == Kind::Human {
        return Err(format!("{at} lets anyone in, so its kind may be agent only: human tokens open human gates"));
    }
    let role = role.unwrap_or(if anyone { Role::Read } else { Role::Write });
    let workspaces = auth::workspace_list(workspaces).map_err(|e| format!("{at}: {e}"))?;
    if max_claims == Some(0) {
        return Err(format!("{at}: max_claims must be at least 1 (role read lets its accounts claim nothing)"));
    }
    Ok(Grant { role, kind, workspaces, max_claims })
}

pub(crate) fn agent_kind() -> Kind {
    Kind::Agent
}

/// The rules, checked as a list: an `anyone` rule is the last, and gives no
/// more in a workspace than a rule before it would.
fn check_anyone(table: &str, rules: &[Rule]) -> std::result::Result<(), String> {
    let Some(i) = rules.iter().position(|r| r.anyone) else { return Ok(()) };
    if i + 1 < rules.len() {
        return Err(format!(
            "[[{table}.allow]] rule {} lets anyone in, so the rules after it never match: make it the last",
            i + 1
        ));
    }
    // An account an earlier rule lets into a workspace gets that rule's token there, never the anyone rule's.
    let anyone = &rules[i].grant;
    if let Some(n) = rules[..i].iter().position(|r| r.grant.role < anyone.role && overlap(&r.grant, anyone)) {
        return Err(format!(
            "[[{table}.allow]] rule {} gives its accounts role {} where rule {} gives anyone role {}: raise its \
             role, or keep their workspaces apart",
            n + 1,
            rules[n].grant.role.as_str(),
            i + 1,
            anyone.role.as_str()
        ));
    }
    // Read tokens hold nothing, so only a writing `anyone` rule sets a floor.
    let fewer =
        |g: &Grant| anyone.role != Role::Read && g.max_claims.is_some_and(|n| anyone.max_claims.is_none_or(|a| n < a));
    if let Some(n) = rules[..i].iter().position(|r| fewer(&r.grant) && overlap(&r.grant, anyone)) {
        return Err(format!(
            "[[{table}.allow]] rule {} lets its accounts hold fewer claims than rule {} lets anyone hold: raise its \
             max_claims, or keep their workspaces apart",
            n + 1,
            i + 1
        ));
    }
    Ok(())
}

/// Whether two grants share a workspace.
fn overlap(a: &Grant, b: &Grant) -> bool {
    let all = |g: &Grant| g.workspaces.iter().any(|w| w == "*");
    all(a) || all(b) || a.workspaces.iter().any(|w| b.workspaces.contains(w))
}

/// Whether an account belongs to a group.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Member {
    Yes,
    No,
    /// The provider would not tell, and why: the account counts as no member.
    Unknown(String),
}

/// What a provider proves of an account, as rules need it.
pub trait Facts {
    fn identity(&self) -> &Identity;
    /// Whether facts beyond its subject are known now: at a sign-in, or at a
    /// refresh from a provider asked again. Without them, a rule that needs
    /// them lets the account in only if it is the one that let it in before.
    fn fresh(&self) -> bool;
    /// How long ago the provider made the account, if it says.
    fn age(&self) -> Option<Duration> {
        None
    }
    /// Its verified email, if any.
    fn email(&self) -> Option<&str> {
        None
    }
    /// Whether it belongs to `group`, asked as rules need it.
    fn member(&mut self, group: &str) -> Result<Member>;
}

/// Facts given whole (an ID token's claims), or none beyond the identity
/// (a refresh with nothing to ask).
pub struct Listed<'a> {
    pub user: &'a Identity,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub fresh: bool,
}

impl<'a> Listed<'a> {
    /// Nothing but who the account is, as kept since it signed in.
    pub fn kept(user: &'a Identity) -> Listed<'a> {
        Listed { user, email: None, groups: Vec::new(), fresh: false }
    }
}

impl Facts for Listed<'_> {
    fn identity(&self) -> &Identity {
        self.user
    }

    fn fresh(&self) -> bool {
        self.fresh
    }

    fn email(&self) -> Option<&str> {
        self.email.as_deref()
    }

    fn member(&mut self, group: &str) -> Result<Member> {
        Ok(if self.groups.iter().any(|g| g == group) { Member::Yes } else { Member::No })
    }
}

/// What the rules make of an account signing in to a workspace.
#[derive(Debug)]
pub enum Decision {
    /// What the first rule that lets the account into the workspace grants
    /// it, what matched (`GitHub user alice`, `member of acme`), and whether
    /// that may pass between accounts (a login, an email).
    In { grant: Grant, via: String, by_login: bool },
    /// Rules let the account in, but only into these other workspaces.
    Elsewhere(Vec<String>),
    /// A rule would let the account into the workspace, were it this old
    /// (the least such `min_account_age`).
    TooNew(Duration),
    /// No rule lets the account in.
    Out,
    /// The provider would not tell whether a rule that covers the workspace
    /// lets the account in (a membership it keeps from this server): later
    /// rules are not tried, as they may grant more than that one would.
    Unknown,
}

/// A decision, the fingerprint of the rule that let the account in, and the
/// memberships the provider would not tell (for the log).
#[derive(Debug)]
pub struct Decided {
    pub decision: Decision,
    pub rule: Option<String>,
    pub unknown: Vec<String>,
}

/// The workspaces rules before the one that decides let an account into:
/// that rule's grant then covers the workspace asked for alone, and, with
/// none deciding, they are where it may go instead.
#[derive(Default)]
struct Elsewhere(Vec<String>);

impl Elsewhere {
    fn note(&mut self, grant: &Grant) {
        for w in &grant.workspaces {
            if !self.0.contains(w) {
                self.0.push(w.clone());
            }
        }
    }

    fn grant(&self, grant: &Grant, workspace: &str) -> Grant {
        let mut grant = grant.clone();
        if !self.0.is_empty() {
            grant.workspaces = vec![workspace.to_string()];
        }
        grant
    }
}

/// The first of `rules` that lets the account `facts` tell of into
/// `workspace`: a rule that lets it in elsewhere only leaves it to the rules
/// after it, and then the grant covers `workspace` alone, never one where
/// an earlier rule decides. A rule whose `min_account_age` the account falls
/// short of (or whose age the provider did not tell) does not let it in.
/// `kept` is the fingerprint of the rule that let it in before (a refresh).
pub fn decide(rules: &[Rule], facts: &mut dyn Facts, kept: Option<&str>, workspace: &str) -> Result<Decided> {
    let mut elsewhere = Elsewhere::default();
    let mut too_new: Option<Duration> = None;
    let mut unknown = Vec::new();
    for rule in rules {
        let before = unknown.len();
        let Some((via, by_login)) = lets_in(rule, facts, kept, &mut unknown)? else {
            // Not knowing is not "no": a rule further down may grant more than this one would have.
            if unknown.len() > before && rule.grant.allows_workspace(workspace) {
                return Ok(Decided { decision: Decision::Unknown, rule: None, unknown });
            }
            continue;
        };
        if let Some(min) = rule.min_account_age.filter(|min| facts.fresh() && facts.age().is_none_or(|a| a < *min)) {
            if rule.grant.allows_workspace(workspace) {
                too_new = Some(too_new.map_or(min, |t| t.min(min)));
            }
            continue;
        }
        if rule.grant.allows_workspace(workspace) {
            let decision = Decision::In { grant: elsewhere.grant(&rule.grant, workspace), via, by_login };
            return Ok(Decided { decision, rule: Some(rule.fingerprint()), unknown });
        }
        elsewhere.note(&rule.grant);
    }
    let decision = match too_new {
        Some(min) => Decision::TooNew(min),
        None if elsewhere.0.is_empty() => Decision::Out,
        None => Decision::Elsewhere(elsewhere.0),
    };
    Ok(Decided { decision, rule: None, unknown })
}

/// What lets the account in by `rule`, if anything, and whether that may
/// pass between accounts.
fn lets_in(
    rule: &Rule,
    facts: &mut dyn Facts,
    kept: Option<&str>,
    unknown: &mut Vec<String>,
) -> Result<Option<(String, bool)>> {
    let who = facts.identity().who();
    if rule.anyone {
        return Ok(Some((format!("{who}, as anyone"), false)));
    }
    if rule.subjects.contains(&facts.identity().subject) {
        return Ok(Some((who, false)));
    }
    if !rule.needs_facts() {
        return Ok(None);
    }
    if !facts.fresh() {
        let same = kept == Some(rule.fingerprint().as_str());
        return Ok(same.then(|| (format!("{who}, as at sign-in"), rule.names_movable())));
    }
    if rule.users.contains(&facts.identity().login.to_lowercase()) {
        return Ok(Some((who, true)));
    }
    if let Some(email) = facts.email().map(str::to_lowercase) {
        if rule.emails.contains(&email) {
            return Ok(Some(("a listed email".into(), true)));
        }
        let domain = email.rsplit_once('@').map(|(_, d)| d.to_string()).unwrap_or_default();
        if rule.email_domains.contains(&domain) {
            return Ok(Some((format!("an email at {domain}"), true)));
        }
    }
    for group in &rule.groups {
        match facts.member(group)? {
            Member::Yes => return Ok(Some((format!("member of {group}"), false))),
            Member::No => {}
            Member::Unknown(why) => {
                let what = format!("{group}: {why}");
                if !unknown.contains(&what) {
                    unknown.push(what);
                }
            }
        }
    }
    Ok(None)
}
