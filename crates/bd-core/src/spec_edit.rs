//! Writing feature specs: `bd spec new`, `bd spec add`, `bd spec change`,
//! `bd spec remove` and `bd spec link` (the experimental feature `specs`).
//!
//! Each operation validates everything it can before its first write, then
//! runs in the caller's write transaction:
//!
//! * [`WriteCtx::spec_new`] creates a spec: a pinned `feature` labelled
//!   `spec` and `area:<area>`, optionally the child of a pinned spec.
//! * [`WriteCtx::spec_add`] adds a requirement (or non-goal): a pinned
//!   `story` under a pinned spec, labelled `requirement` (plus `non-goal`).
//! * [`WriteCtx::spec_change`] adds the new requirement under the old one's
//!   spec, of the old one's kind, and supersedes the old one by it
//!   (`bd supersede <old> --with <new>`), all or nothing.
//! * [`WriteCtx::spec_remove`] closes a requirement that no longer holds,
//!   with outcome `done` and the reason `removed: <why>`.
//! * [`WriteCtx::spec_link`] links work to specs or requirements in force by
//!   `related` edges, which is what `bd spec drift` looks for.
//!
//! Sources (`--from`) become outgoing `related` edges from the spec or
//! requirement, the sources `bd spec show` lists; they may not be spec parts
//! themselves. Ids are full ids: callers resolve user input first.
//!
//! Nothing here adds SQL: the operations are built from `require`,
//! `parent_of`, `load_edge`, `dependencies_of`, [`WriteCtx::create_issue`],
//! [`WriteCtx::add_dependency`], [`WriteCtx::close_as`] and
//! [`WriteCtx::close_issue`], so events, `graph::recompute` seeds, claim
//! overrides (`take_over` is never set, nor implied) and the lease invariant
//! are the ones those already keep. `related` and `supersedes` edges never
//! block.

use rusqlite::Connection;
use serde::Serialize;

use crate::duplicates::{CloseAsOptions, Replacement};
use crate::error::{Error, Result};
use crate::graph::{self, DepChange};
use crate::issues::{self, CloseOptions};
use crate::model::{DepType, Issue, NewIssue, Outcome, Status};
use crate::specs::{NON_GOAL, REQUIREMENT, SPEC, is_spec_part, require_on};
use crate::store::WriteCtx;

/// The longest area name `bd spec new` takes.
pub const MAX_AREA_CHARS: usize = 64;

/// An area name: 1 to [`MAX_AREA_CHARS`] ASCII letters, digits, `-`, `_`,
/// `.` or `/`, so `area:<area>` is one plain label.
pub fn check_area(area: &str) -> Result<()> {
    let ok = !area.is_empty()
        && area.chars().count() <= MAX_AREA_CHARS
        && area.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/'));
    if ok {
        Ok(())
    } else {
        Err(Error::invalid(format!("invalid area {area:?}: 1-64 ASCII letters, digits, '-', '_', '.' or '/'")))
    }
}

/// The text of a new spec or requirement and where it came from.
#[derive(Clone, Debug, Default)]
pub struct Sentence {
    pub title: String,
    pub description: String,
    /// Full ids of the issues and runs it came from.
    pub from: Vec<String>,
}

/// What `bd spec new` created.
#[derive(Clone, Debug, Serialize)]
pub struct SpecCreated {
    pub spec: Issue,
    pub area: String,
    pub parent: Option<String>,
    pub sources: Vec<String>,
}

/// What `bd spec add` created.
#[derive(Clone, Debug, Serialize)]
pub struct RequirementAdded {
    pub requirement: Issue,
    pub spec: String,
    pub non_goal: bool,
    pub sources: Vec<String>,
}

/// What `bd spec change` created and closed.
#[derive(Clone, Debug, Serialize)]
pub struct RequirementChanged {
    /// The new requirement.
    pub requirement: Issue,
    /// The old one, now closed as superseded by the new one.
    pub superseded: Issue,
    pub spec: String,
    pub non_goal: bool,
    pub sources: Vec<String>,
}

/// What `bd spec remove` closed.
#[derive(Clone, Debug, Serialize)]
pub struct RequirementRemoved {
    pub requirement: Issue,
    pub spec: String,
    /// The close reason stored: `removed: <why>`.
    pub reason: String,
    /// The `related` edges this removal added.
    pub sources: Vec<String>,
    /// The reason without its `removed:` prefix, for text output.
    #[serde(skip)]
    pub why: String,
}

/// One link `bd spec link` made, or found already made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Linked {
    pub issue: String,
    pub target: String,
    /// A `related` edge (either direction) joined them already: nothing was written.
    pub already: bool,
}

fn has(issue: &Issue, label: &str) -> bool {
    issue.labels.iter().any(|l| l == label)
}

/// `spec` as a spec in force: labelled spec, not closed, pinned.
fn check_spec_state(spec: &Issue) -> Result<()> {
    let id = &spec.id;
    match spec.status {
        Status::Pinned => Ok(()),
        Status::Closed => {
            Err(Error::Refused(format!("{id} is a closed spec; use the spec that replaced it (`bd spec list`)")))
        }
        status => Err(Error::Refused(format!(
            "{id} is {status}, not pinned: pin it first (bd update {id} --status pinned)",
            status = status.as_str()
        ))),
    }
}

/// The spec `id`, which must be in force (pinned) to take new parts.
fn spec_target(conn: &Connection, id: &str) -> Result<Issue> {
    let spec = issues::require(conn, id)?;
    if !has(&spec, SPEC) {
        return Err(Error::invalid(format!("{id} is not a spec (labelled spec): name one from `bd spec list`")));
    }
    check_spec_state(&spec)?;
    Ok(spec)
}

/// The requirement or non-goal `id`, not closed, and the spec it is a
/// direct child of (pinned, when `need_pinned_spec`).
fn requirement_target(conn: &Connection, id: &str, need_pinned_spec: bool) -> Result<(Issue, Issue)> {
    let req = issues::require(conn, id)?;
    if !has(&req, REQUIREMENT) && !has(&req, NON_GOAL) {
        return Err(Error::invalid(format!(
            "{id} is not a requirement (labelled requirement or non-goal): name one from `bd spec show <spec>`"
        )));
    }
    if req.status == Status::Closed {
        return Err(Error::Refused(format!(
            "{id} is already closed ({}): see `bd spec show <spec> --history`",
            req.close_reason.as_deref().filter(|r| !r.trim().is_empty()).unwrap_or("no reason")
        )));
    }
    let spec = match graph::parent_of(conn, id)? {
        Some(p) => issues::require(conn, &p)?,
        None => {
            return Err(Error::invalid(format!(
                "{id} is not a direct child of a spec: move it under one (bd update {id} --parent <spec>)"
            )));
        }
    };
    if !has(&spec, SPEC) {
        return Err(Error::invalid(format!(
            "{id} is not a direct child of a spec: move it under one (bd update {id} --parent <spec>)"
        )));
    }
    if need_pinned_spec {
        check_spec_state(&spec)?;
    }
    Ok((req, spec))
}

/// `from` deduplicated in first-seen order; each must exist (any status)
/// and not be part of a spec.
fn sources(conn: &Connection, from: &[String]) -> Result<Vec<String>> {
    let mut out: Vec<String> = Vec::new();
    for id in from {
        if out.contains(id) {
            continue;
        }
        let issue = issues::require(conn, id)?;
        if is_spec_part(&issue.labels) {
            return Err(Error::invalid(format!(
                "--from {id} is part of a spec (labelled spec, requirement or non-goal): name the issue or playbook run it came from"
            )));
        }
        out.push(id.clone());
    }
    Ok(out)
}

/// An edge of another type than `related` from `issue` to `target` would be
/// refused by `add_dependency`: refused here before anything is written.
fn check_no_other_edge(conn: &Connection, issue: &str, target: &str) -> Result<bool> {
    match graph::load_edge(conn, issue, target)? {
        Some(e) if e.dep_type == DepType::Related => Ok(true),
        Some(e) => Err(Error::Refused(format!(
            "{issue} already depends on {target} via {}; remove that edge first",
            e.dep_type
        ))),
        None => Ok(false),
    }
}

/// The close reason of `bd spec remove` (`removed: <why>`) and `<why>`:
/// trimmed, a leading `removed:` in any case dropped so it is never doubled.
fn removed_reason(why: &str) -> Result<(String, String)> {
    const PREFIX: &str = "removed:";
    let mut rest = why.trim();
    if rest.get(..PREFIX.len()).is_some_and(|p| p.eq_ignore_ascii_case(PREFIX)) {
        rest = rest[PREFIX.len()..].trim();
    }
    if rest.is_empty() {
        return Err(Error::invalid("give the reason the requirement no longer holds (-r)"));
    }
    Ok((format!("removed: {rest}"), rest.to_string()))
}

impl WriteCtx<'_> {
    /// `bd spec new`: a pinned feature labelled `spec` and `area:<area>`,
    /// the child of `parent` (a spec in force) when given, with `related`
    /// edges to its sources.
    pub fn spec_new(&mut self, area: &str, s: &Sentence, parent: Option<&str>) -> Result<SpecCreated> {
        require_on(self.conn())?;
        check_area(area)?;
        if let Some(p) = parent {
            spec_target(self.conn(), p)?;
        }
        let sources = sources(self.conn(), &s.from)?;
        let spec = self.create_issue(NewIssue {
            title: s.title.clone(),
            description: s.description.clone(),
            issue_type: Some("feature".into()),
            status: Some(Status::Pinned),
            labels: vec![SPEC.into(), format!("area:{area}")],
            parent: parent.map(String::from),
            deps: sources.iter().map(|id| (DepType::Related, id.clone())).collect(),
            ..Default::default()
        })?;
        Ok(SpecCreated { spec, area: area.to_string(), parent: parent.map(String::from), sources })
    }

    /// `bd spec add`: a pinned story under `spec` (a spec in force),
    /// labelled `requirement` (plus `non-goal`), with `related` edges to its
    /// sources.
    pub fn spec_add(&mut self, spec: &str, s: &Sentence, non_goal: bool) -> Result<RequirementAdded> {
        require_on(self.conn())?;
        spec_target(self.conn(), spec)?;
        let sources = sources(self.conn(), &s.from)?;
        if sources.is_empty() {
            return Err(Error::invalid("give the issue or playbook run the requirement came from (--from ID)"));
        }
        let requirement = self.new_requirement(spec, s, non_goal, &sources)?;
        Ok(RequirementAdded { requirement, spec: spec.to_string(), non_goal, sources })
    }

    fn new_requirement(&mut self, spec: &str, s: &Sentence, non_goal: bool, sources: &[String]) -> Result<Issue> {
        let mut labels = vec![REQUIREMENT.to_string()];
        if non_goal {
            labels.push(NON_GOAL.into());
        }
        self.create_issue(NewIssue {
            title: s.title.clone(),
            description: s.description.clone(),
            issue_type: Some("story".into()),
            status: Some(Status::Pinned),
            labels,
            parent: Some(spec.to_string()),
            deps: sources.iter().map(|id| (DepType::Related, id.clone())).collect(),
            ..Default::default()
        })
    }

    /// `bd spec change`: the new requirement under `old`'s spec (in force),
    /// of `old`'s kind, then `old` superseded by it. Another actor's live
    /// claim on `old` is refused before anything is written; a refusal of
    /// the supersede (open children, say) fails the whole transaction.
    pub fn spec_change(&mut self, old: &str, s: &Sentence) -> Result<RequirementChanged> {
        require_on(self.conn())?;
        let (old_issue, spec) = requirement_target(self.conn(), old, true)?;
        let sources = sources(self.conn(), &s.from)?;
        if sources.is_empty() {
            return Err(Error::invalid("give the issue or playbook run the requirement came from (--from ID)"));
        }
        self.check_claim_override(&old_issue, false)?;
        let non_goal = has(&old_issue, NON_GOAL);
        let new = self.new_requirement(&spec.id, s, non_goal, &sources)?;
        self.close_as(old, &new.id, Replacement::Supersede, &CloseAsOptions::default())?;
        let superseded = issues::require(self.conn(), old)?;
        let requirement = issues::require(self.conn(), &new.id)?;
        Ok(RequirementChanged { requirement, superseded, spec: spec.id, non_goal, sources })
    }

    /// `bd spec remove`: `old` closed with outcome `done` and the reason
    /// `removed: <why>`, after `related` edges from it to `from` (the work
    /// that removed it). Its spec may be in any state. Open children and
    /// blockers refuse the close, and another actor's live claim, as
    /// `bd close` does without `--force` or `--take-over`.
    pub fn spec_remove(&mut self, old: &str, why: &str, from: &[String]) -> Result<RequirementRemoved> {
        require_on(self.conn())?;
        let (old_issue, spec) = requirement_target(self.conn(), old, false)?;
        let (reason, why) = removed_reason(why)?;
        let from = sources(self.conn(), from)?;
        self.check_claim_override(&old_issue, false)?;
        let mut to_add = Vec::new();
        for src in &from {
            // An existing `related` edge stays as it is, with its metadata.
            if !check_no_other_edge(self.conn(), old, src)? {
                to_add.push(src.clone());
            }
        }
        let mut sources = Vec::new();
        for src in to_add {
            if self.add_dependency(old, &src, DepType::Related, None)? == DepChange::Added {
                sources.push(src);
            }
        }
        self.close_issue(
            old,
            &CloseOptions {
                reason: Some(reason.clone()),
                outcome: Some(Outcome::Done),
                force: false,
                take_over: false,
                ..Default::default()
            },
        )?;
        let requirement = issues::require(self.conn(), old)?;
        Ok(RequirementRemoved { requirement, spec: spec.id, reason, sources, why })
    }

    /// `bd spec link`: a `related` edge `issue -> target` for each target (a
    /// spec, requirement or non-goal not closed), unless one joins them in
    /// either direction already. `issue` (any status) may not be a spec part.
    /// Every target is checked before any edge is written.
    pub fn spec_link(&mut self, issue: &str, targets: &[String]) -> Result<Vec<Linked>> {
        require_on(self.conn())?;
        let work = issues::require(self.conn(), issue)?;
        if is_spec_part(&work.labels) {
            return Err(Error::invalid(format!(
                "{issue} is part of a spec (labelled spec, requirement or non-goal): only other work is linked to specs"
            )));
        }
        let mut uniq: Vec<&String> = Vec::new();
        for t in targets {
            if !uniq.contains(&t) {
                uniq.push(t);
            }
        }
        // (target, already linked)
        let mut plan: Vec<(String, bool)> = Vec::new();
        for t in uniq {
            let target = issues::require(self.conn(), t)?;
            if !is_spec_part(&target.labels) {
                return Err(Error::invalid(format!(
                    "{t} is not a spec or requirement (labelled spec, requirement or non-goal)"
                )));
            }
            if target.status == Status::Closed {
                if let Some(by) =
                    graph::dependencies_of(self.conn(), t)?.into_iter().find(|e| e.dep_type == DepType::Supersedes)
                {
                    return Err(Error::Refused(format!("{t} is superseded by {}: link that", by.id)));
                }
                return Err(Error::Refused(format!(
                    "{t} is closed ({}): link a spec or requirement in force (`bd spec show`)",
                    target.close_reason.as_deref().filter(|r| !r.trim().is_empty()).unwrap_or("no reason")
                )));
            }
            let already = check_no_other_edge(self.conn(), issue, t)?
                || graph::load_edge(self.conn(), t, issue)?.is_some_and(|e| e.dep_type == DepType::Related);
            plan.push((t.clone(), already));
        }
        let mut out = Vec::new();
        for (target, already) in plan {
            if !already {
                self.add_dependency(issue, &target, DepType::Related, None)?;
            }
            out.push(Linked { issue: issue.to_string(), target, already });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests;
