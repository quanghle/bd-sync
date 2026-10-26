//! Closing an issue as a duplicate of, or superseded by, another:
//! `bd duplicate <id> --of <canonical>` and `bd supersede <id> --with <newer>`.
//!
//! One write transaction adds an informational edge and closes the issue.
//! The edge points from the closed issue to the one that replaces it, as in
//! beads: `X duplicates Y` ("X is a duplicate of Y") and `X supersedes Y`
//! (read "X is superseded by Y", beads' label for the edge). The close has
//! outcome `done` and the reason `duplicate of Y` or `superseded by Y`, so
//! the other id is always named. Nothing else moves: children, labels,
//! comments and other edges of the closed issue stay where they are, and the
//! replacing issue is not touched at all.
//!
//! The same module holds [`similar_pairs`], the pure search behind
//! `bd find-duplicates`: it ranks pairs of unfinished issues by how alike
//! their titles and texts are, and reads nothing but the issues it is given.
//!
//! Nothing here adds SQL: the operation is built from `require`,
//! `load_edge`, `dependencies_of`, [`WriteCtx::add_dependency`] and
//! [`WriteCtx::close_issue`], so events, claim overrides (`take_over`, never
//! implied by `force`), the lease invariant and the blocked flags are the
//! ones those already keep.

use std::collections::{BinaryHeap, HashMap};

use serde::Serialize;

use crate::error::{Error, Result};
use crate::graph;
use crate::issues::{self, CloseOptions};
use crate::model::{DepType, GATE_TYPE, Guard, Issue, IssueRef, Outcome, Status};
use crate::store::WriteCtx;

/// Which relation the closed issue has to the one that replaces it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Replacement {
    /// `X duplicates Y`: X repeats Y.
    Duplicate,
    /// `X supersedes Y`: X is superseded by Y.
    Supersede,
}

impl Replacement {
    pub fn dep_type(self) -> DepType {
        match self {
            Replacement::Duplicate => DepType::Duplicates,
            Replacement::Supersede => DepType::Supersedes,
        }
    }

    /// The close reason: always names the other issue.
    pub fn reason(self, target: &str) -> String {
        match self {
            Replacement::Duplicate => format!("duplicate of {target}"),
            Replacement::Supersede => format!("superseded by {target}"),
        }
    }

    /// "a duplicate of" / "superseded by", for messages.
    pub fn verb(self) -> &'static str {
        match self {
            Replacement::Duplicate => "a duplicate of",
            Replacement::Supersede => "superseded by",
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct CloseAsOptions {
    /// Close despite open children or live blockers. Never past another
    /// actor's live claim: that is `take_over`.
    pub force: bool,
    /// Close another actor's live claim (a takeover, recorded in the
    /// `closed` event).
    pub take_over: bool,
    pub guard: Guard,
}

#[derive(Clone, Debug, Serialize)]
pub struct CloseAsOutcome {
    pub issue: Issue,
    pub target: IssueRef,
    #[serde(rename = "type")]
    pub dep_type: DepType,
    /// The issue was already closed with this edge: nothing was written.
    pub already: bool,
    /// Issues whose last blocker this close released.
    pub unblocked: Vec<IssueRef>,
    /// Playbook runs and groups that closed because their last open step did.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub completed: Vec<IssueRef>,
}

impl WriteCtx<'_> {
    /// Add the `kind` edge `id -> target` and close `id` with a reason naming
    /// `target`, in this transaction. Refuses (writing nothing, as the
    /// caller's transaction rolls back) when: `id` is `target`; either does
    /// not exist; the guard fails; another actor holds a live claim on `id`
    /// and `take_over` is not set; `id` is closed already without that edge;
    /// `target` has the same edge back to `id`, or is itself closed as a
    /// duplicate (or superseded), when the root is the one to name; an edge of
    /// another type joins the two, in either direction; or `id` has open children or blockers and
    /// `force` is not set.
    pub fn close_as(
        &mut self,
        id: &str,
        target: &str,
        kind: Replacement,
        opts: &CloseAsOptions,
    ) -> Result<CloseAsOutcome> {
        if id == target {
            return Err(Error::invalid(format!("{id} cannot be {} itself", kind.verb())));
        }
        let old = issues::require(self.conn(), id)?;
        let other = issues::require(self.conn(), target)?;
        opts.guard.check(&old)?;
        let dep_type = kind.dep_type();
        let existing = graph::load_edge(self.conn(), id, target)?;
        let has_edge = existing.as_ref().is_some_and(|e| e.dep_type == dep_type);

        if old.status == Status::Closed {
            if has_edge {
                return Ok(CloseAsOutcome {
                    issue: old,
                    target: other.to_ref(),
                    dep_type,
                    already: true,
                    unblocked: Vec::new(),
                    completed: Vec::new(),
                });
            }
            return Err(Error::Refused(format!(
                "{id} is already closed; reopen it first, or record the relation with `bd dep add {id} {target} -t {dep_type}`"
            )));
        }
        // Someone else's work is named before anything `force` gets past;
        // `close_issue` checks again and records the override.
        self.check_claim_override(&old, opts.take_over)?;

        match graph::load_edge(self.conn(), target, id)? {
            Some(e) if e.dep_type == dep_type => {
                return Err(Error::Refused(format!(
                    "{target} is already {} {id}; the relation would run both ways",
                    kind.verb()
                )));
            }
            // An edge of another type either way joins the two (the one from `id` is refused by `add_dependency`).
            Some(e) => {
                return Err(Error::Refused(format!(
                    "{target} already depends on {id} via {}; remove that edge first",
                    e.dep_type
                )));
            }
            None => {}
        }
        if other.status == Status::Closed
            && let Some(root) =
                graph::dependencies_of(self.conn(), target)?.into_iter().find(|e| e.dep_type == dep_type)
        {
            return Err(Error::Refused(format!(
                "{target} is itself {} {}; mark {id} {} {} instead",
                kind.verb(),
                root.id,
                kind.verb(),
                root.id
            )));
        }

        // An existing edge of this type stays as it is (with its metadata);
        // one of another type is refused by `add_dependency`.
        if !has_edge {
            self.add_dependency(id, target, dep_type.clone(), None)?;
        }
        // The guard held above and the edge does not bump the revision.
        let closed = self.close_issue(
            id,
            &CloseOptions {
                reason: Some(kind.reason(target)),
                outcome: Some(Outcome::Done),
                force: opts.force,
                take_over: opts.take_over,
                guard: Guard::default(),
                token: None,
                via: None,
            },
        )?;
        Ok(CloseAsOutcome {
            issue: closed.issue,
            target: other.to_ref(),
            dep_type,
            already: false,
            unblocked: closed.unblocked,
            completed: closed.completed,
        })
    }
}

/// Words too common to say what an issue is about.
const STOPWORDS: &[&str] = &[
    "a", "an", "the", "and", "or", "of", "to", "in", "on", "for", "with", "is", "be", "it", "as", "at", "by", "from",
    "this", "that",
];

/// Two issues that look alike. `a` is the older one (creation time, then id).
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SimilarPair {
    pub a: IssueRef,
    pub b: IssueRef,
    /// 0 to 1, rounded to three decimals.
    pub score: f64,
}

/// Lowercased, with everything that is not a letter or digit as a space and
/// runs of spaces collapsed.
fn normalize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars().flat_map(char::to_lowercase) {
        if c.is_alphanumeric() {
            out.push(c);
        } else if !out.is_empty() && !out.ends_with(' ') {
            out.push(' ');
        }
    }
    if out.ends_with(' ') {
        out.pop();
    }
    out
}

/// What one issue is compared by: sorted, deduplicated feature ids.
struct Features<'a> {
    issue: &'a Issue,
    trigrams: Vec<u32>,
    words: Vec<u32>,
}

#[derive(Default)]
struct Interner<K: std::hash::Hash + Eq>(HashMap<K, u32>);

impl<K: std::hash::Hash + Eq> Interner<K> {
    fn id(&mut self, key: K) -> u32 {
        let next = self.0.len() as u32;
        *self.0.entry(key).or_insert(next)
    }
}

fn sorted_unique(mut v: Vec<u32>) -> Vec<u32> {
    v.sort_unstable();
    v.dedup();
    v
}

/// Whether the issue takes part in the search: unfinished, persistent, not a
/// gate and not a step of a playbook run (repeated runs share titles by design).
fn is_candidate(i: &Issue) -> bool {
    !i.status.is_terminal()
        && !i.ephemeral
        && i.issue_type != GATE_TYPE
        && i.metadata.get("playbook").is_none_or(serde_json::Value::is_null)
}

/// Jaccard similarity of two sorted, deduplicated lists; 0 when both are empty.
fn jaccard(a: &[u32], b: &[u32]) -> f64 {
    let (mut i, mut j, mut common) = (0, 0, 0usize);
    while i < a.len() && j < b.len() {
        match a[i].cmp(&b[j]) {
            std::cmp::Ordering::Less => i += 1,
            std::cmp::Ordering::Greater => j += 1,
            std::cmp::Ordering::Equal => {
                common += 1;
                i += 1;
                j += 1;
            }
        }
    }
    let union = a.len() + b.len() - common;
    if union == 0 { 0.0 } else { common as f64 / union as f64 }
}

/// Whether Jaccard of lists this long can reach `threshold`: it is at most
/// the ratio of the shorter to the longer.
fn can_reach(a: usize, b: usize, threshold: f64) -> bool {
    let (lo, hi) = (a.min(b), a.max(b));
    hi > 0 && lo as f64 / hi as f64 >= threshold
}

/// Pairs of unfinished issues (not closed, pinned, ephemeral, gates or
/// playbook steps) whose score reaches `threshold`, best first (then by `a`
/// and `b` ids). The score is the larger of the Jaccard similarity of the
/// titles' character trigrams (which forgives typos and plurals) and of the
/// words of title and description with stopwords and single characters left
/// out. Pairwise, O(n^2) with a length prune. With `limit`, only the best
/// `limit` pairs are kept while searching, so memory follows the limit and
/// not the number of pairs that qualify; the result is the first `limit`
/// pairs of the unlimited one.
pub fn similar_pairs(issues: &[Issue], threshold: f64, limit: Option<usize>) -> Vec<SimilarPair> {
    let mut trigram_ids = Interner::<[char; 3]>::default();
    let mut word_ids = Interner::<String>::default();
    let mut all = Vec::new();
    for issue in issues.iter().filter(|i| is_candidate(i)) {
        let title = normalize(&issue.title);
        let chars: Vec<char> = format!(" {title} ").chars().collect();
        let trigrams = sorted_unique(chars.windows(3).map(|w| trigram_ids.id([w[0], w[1], w[2]])).collect());
        if trigrams.is_empty() {
            continue;
        }
        let text = normalize(&format!("{} {}", issue.title, issue.description));
        let words = sorted_unique(
            text.split(' ')
                .filter(|w| w.chars().count() > 1 && !STOPWORDS.contains(w))
                .map(|w| word_ids.id(w.to_string()))
                .collect(),
        );
        all.push(Features { issue, trigrams, words });
    }

    let mut found: Vec<Candidate> = Vec::new();
    let mut best: BinaryHeap<Candidate> = BinaryHeap::new();
    for (n, x) in all.iter().enumerate() {
        for y in &all[n + 1..] {
            let by_title = can_reach(x.trigrams.len(), y.trigrams.len(), threshold);
            let by_text = can_reach(x.words.len(), y.words.len(), threshold);
            let mut score = 0.0f64;
            if by_title {
                score = score.max(jaccard(&x.trigrams, &y.trigrams));
            }
            if by_text {
                score = score.max(jaccard(&x.words, &y.words));
            }
            if score < threshold || !(by_title || by_text) {
                continue;
            }
            let older_first = (x.issue.created_at, &x.issue.id) <= (y.issue.created_at, &y.issue.id);
            let (a, b) = if older_first { (x.issue, y.issue) } else { (y.issue, x.issue) };
            let candidate = Candidate { score, a, b };
            match limit {
                None => found.push(candidate),
                Some(k) => {
                    best.push(candidate);
                    if best.len() > k {
                        best.pop();
                    }
                }
            }
        }
    }
    found.extend(best);
    found.sort();
    found
        .into_iter()
        .map(|c| SimilarPair { a: c.a.to_ref(), b: c.b.to_ref(), score: (c.score * 1000.0).round() / 1000.0 })
        .collect()
}

/// A pair found by the search, before its issues are summarized. Ordered as
/// the output is (best first, then by `a` and `b` ids), so the greatest is
/// the worst and tops a `BinaryHeap` of the best ones.
struct Candidate<'a> {
    score: f64,
    a: &'a Issue,
    b: &'a Issue,
}

impl Ord for Candidate<'_> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        other
            .score
            .total_cmp(&self.score)
            .then_with(|| self.a.id.cmp(&other.a.id))
            .then_with(|| self.b.id.cmp(&other.b.id))
    }
}

impl PartialOrd for Candidate<'_> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for Candidate<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other).is_eq()
    }
}

impl Eq for Candidate<'_> {}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn issue(id: &str, title: &str, description: &str, created: i64) -> Issue {
        serde_json::from_value(json!({
            "id": id, "title": title, "description": description, "status": "open",
            "priority": 2, "issue_type": "task", "created_at": created, "updated_at": created,
        }))
        .unwrap()
    }

    fn ids(pairs: &[SimilarPair]) -> Vec<(&str, &str)> {
        pairs.iter().map(|p| (p.a.id.as_str(), p.b.id.as_str())).collect()
    }

    #[test]
    fn identical_titles_score_one() {
        let v = [issue("t-1", "Fix login timeout", "", 1), issue("t-2", "fix  LOGIN timeout!", "", 2)];
        let pairs = similar_pairs(&v, 0.8, None);
        assert_eq!(ids(&pairs), [("t-1", "t-2")]);
        assert_eq!(pairs[0].score, 1.0);
    }

    #[test]
    fn typos_and_plurals_pass_and_unrelated_issues_do_not() {
        let v = [
            issue("t-1", "Fix login timeout", "", 1),
            issue("t-2", "Fix login timeouts", "", 2),
            issue("t-3", "Add dark mode to the settings page", "", 3),
        ];
        assert_eq!(ids(&similar_pairs(&v, 0.8, None)), [("t-1", "t-2")]);
        assert!(similar_pairs(&v, 0.99, None).is_empty());
        assert!(!similar_pairs(&v, 0.1, None).is_empty());
    }

    #[test]
    fn descriptions_can_make_the_match() {
        let text = "exporting a workspace crashes with a panic when any label contains a comma, because the label \
            list is joined with commas and split again while the file is written, so the second pass sees an \
            extra label and the writer aborts halfway through the snapshot";
        let v = [issue("t-1", "Exporter crash", text, 1), issue("t-2", "Labels with commas break export", text, 2)];
        let pairs = similar_pairs(&v, 0.8, None);
        assert_eq!(ids(&pairs), [("t-1", "t-2")]);
        // Without the shared text the titles alone are far apart.
        let v = [issue("t-1", "Exporter crash", "", 1), issue("t-2", "Labels with commas break export", "", 2)];
        assert!(similar_pairs(&v, 0.8, None).is_empty());
    }

    #[test]
    fn finished_scratch_and_generated_issues_are_left_out() {
        let mut closed = issue("t-2", "Same title", "", 2);
        closed.status = Status::Closed;
        let mut pinned = issue("t-3", "Same title", "", 3);
        pinned.status = Status::Pinned;
        let mut ephemeral = issue("t-4", "Same title", "", 4);
        ephemeral.ephemeral = true;
        let mut gate = issue("t-5", "Same title", "", 5);
        gate.issue_type = GATE_TYPE.into();
        let mut step = issue("t-6", "Same title", "", 6);
        step.metadata = json!({"playbook": {"role": "step"}});
        let v = [issue("t-1", "Same title", "", 1), closed, pinned, ephemeral, gate, step];
        assert!(similar_pairs(&v, 0.8, None).is_empty());
        // In-progress, blocked and deferred issues count.
        let mut a = issue("t-7", "Same title", "", 7);
        a.status = Status::InProgress;
        let mut b = issue("t-8", "Same title", "", 8);
        b.status = Status::Deferred;
        let mut c = issue("t-9", "Same title", "", 9);
        c.status = Status::Blocked;
        assert_eq!(similar_pairs(&[a, b, c], 1.0, None).len(), 3);
    }

    #[test]
    fn the_older_issue_comes_first() {
        let v = [
            issue("t-1", "Same title", "", 20),
            issue("t-2", "Same title", "", 10),
            issue("t-0", "Same title", "", 20),
        ];
        // All score 1, so the order is by `a`: t-2 is the oldest; t-0 and t-1 share a time, so the id breaks the tie.
        assert_eq!(ids(&similar_pairs(&v, 0.9, None)), [("t-0", "t-1"), ("t-2", "t-0"), ("t-2", "t-1")]);
    }

    #[test]
    fn pairs_are_ordered_by_score_then_ids() {
        let v = [
            issue("t-1", "Fix login timeout", "", 1),
            issue("t-2", "Fix login timeouts", "", 2),
            issue("t-3", "Fix login timeout", "", 3),
        ];
        let pairs = similar_pairs(&v, 0.5, None);
        assert_eq!(ids(&pairs), [("t-1", "t-3"), ("t-1", "t-2"), ("t-2", "t-3")]);
        assert!(pairs[0].score > pairs[1].score && pairs[1].score == pairs[2].score);
        assert_eq!(pairs[1].score, (pairs[1].score * 1000.0).round() / 1000.0);
    }

    #[test]
    fn the_threshold_is_inclusive_and_empty_titles_are_skipped() {
        // Words {alpha, beta, gamma, delta} against {alpha, beta, gamma, delta, omega}: 4/5.
        let v = [
            issue("t-1", "alpha beta gamma delta", "", 1),
            issue("t-2", "alpha beta gamma delta omega", "", 2),
            issue("t-3", "", "alpha beta gamma delta", 3),
            issue("t-4", "!!!", "alpha beta gamma delta", 4),
        ];
        let at = similar_pairs(&v, 0.8, None);
        assert!(at.iter().any(|p| p.a.id == "t-1" && p.b.id == "t-2"));
        assert!(at.iter().all(|p| p.a.id != "t-3" && p.b.id != "t-3" && p.a.id != "t-4" && p.b.id != "t-4"));
        assert_eq!(at.len(), 1);
        assert_eq!(at[0].score, 0.8);
        assert!(similar_pairs(&v, 0.801, None).is_empty());
    }

    #[test]
    fn normalizing_folds_case_and_punctuation() {
        assert_eq!(normalize("  Fix: the  Bug-Report (#12)! "), "fix the bug report 12");
        assert_eq!(normalize("ÄÖ straße"), "äö straße");
        assert_eq!(normalize("..."), "");
    }

    #[test]
    fn a_limit_keeps_the_first_pairs_of_the_unlimited_result() {
        // Several issues score 1.0 against each other (ties), others less.
        let v = [
            issue("t-0", "Fix login timeout", "", 1),
            issue("t-1", "Fix login timeout", "", 2),
            issue("t-2", "Fix login timeout", "", 3),
            issue("t-3", "Fix login timeouts", "", 4),
            issue("t-4", "Fix login timeouts", "", 5),
            issue("t-5", "Fix login timeout again", "", 6),
            issue("t-6", "Unrelated dark mode work", "", 7),
        ];
        let all = similar_pairs(&v, 0.3, None);
        assert!(all.len() > 10);
        assert!(all.windows(2).any(|w| w[0].score == w[1].score));
        for k in 1..=all.len() + 2 {
            let limited = similar_pairs(&v, 0.3, Some(k));
            let want = &all[..k.min(all.len())];
            assert_eq!(ids(&limited), ids(want), "k = {k}");
            assert_eq!(
                limited.iter().map(|p| p.score).collect::<Vec<_>>(),
                want.iter().map(|p| p.score).collect::<Vec<_>>()
            );
        }
        assert!(similar_pairs(&v, 0.3, Some(0)).is_empty());
    }
}
