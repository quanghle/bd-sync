//! The read API, shared by snapshots ([`crate::ReadCtx`]) and write
//! transactions ([`crate::WriteCtx`]), so a writer can read its own changes.

use std::io::Write;
use std::time::Duration;

use rusqlite::Connection;

use crate::asof::{self, IssueAsOf, Point};
use crate::claims::{self, LeaseView};
use crate::comments;
use crate::compaction::{self, Candidate, CompactStats};
use crate::config::{self, ConfigEntry};
use crate::error::Result;
use crate::events::{self, EventPage, EventQuery};
use crate::graph::{self, Direction, TreeNode};
use crate::hierarchy::{self, EpicStatus, Orphan, StaleIssue};
use crate::issues;
use crate::memory;
use crate::metrics::{self, Stats};
use crate::model::{
    BRIEF_DESCRIPTION_CHARS, Blocker, Comment, CommentBrief, Edge, Event, Issue, IssueBrief, IssueDetails, IssueRef,
    Lease, ListQuery, Memory, QueryRequest, ReadyQuery, ShowBrief, WorkFilter, cut_chars,
};
use crate::ready::{self, BlockedIssue, ExplainOptions, Readiness};
use crate::store::{ReadCtx, WriteCtx};
use crate::subgraph::{self, EdgeSet, Subgraph};
use crate::time::Timestamp;
use crate::transfer::{self, ExportOptions, ExportSummary};

pub trait Queries {
    fn conn(&self) -> &Connection;
    fn now(&self) -> Timestamp;

    fn issue(&self, id: &str) -> Result<Issue> {
        issues::require(self.conn(), id)
    }

    fn find_issue(&self, id: &str) -> Result<Option<Issue>> {
        issues::get(self.conn(), id)
    }

    /// Exact id, `<prefix>-<input>`, or a unique id prefix.
    fn resolve_id(&self, input: &str) -> Result<String> {
        issues::resolve_id(self.conn(), input)
    }

    fn details(&self, id: &str) -> Result<IssueDetails> {
        issues::details(self.conn(), id, self.now())
    }

    fn list(&self, q: &ListQuery) -> Result<Vec<Issue>> {
        issues::list(self.conn(), q)
    }

    /// The issues matching a `bd query` expression.
    fn query(&self, q: &QueryRequest) -> Result<Vec<Issue>> {
        issues::query(self.conn(), q, self.now())
    }

    fn children(&self, id: &str) -> Result<Vec<IssueRef>> {
        issues::children(self.conn(), id)
    }

    /// The children of `id` as full issues (every descendant with
    /// `recursive`), in creation order.
    fn child_issues(&self, id: &str, recursive: bool) -> Result<Vec<Issue>> {
        hierarchy::child_issues(self.conn(), id, recursive)
    }

    /// The progress of `id`'s subtree, counted recursively.
    fn epic_status(&self, id: &str) -> Result<EpicStatus> {
        hierarchy::epic_status(self.conn(), id)
    }

    /// [`Queries::epic_status`] of every epic not closed (every epic with `include_closed`).
    fn epics(&self, include_closed: bool) -> Result<Vec<EpicStatus>> {
        hierarchy::epics(self.conn(), include_closed)
    }

    /// Epics not closed whose children are all closed.
    fn close_eligible_epics(&self) -> Result<Vec<String>> {
        hierarchy::close_eligible(self.conn())
    }

    /// Open and in-progress issues not updated within `older_than`, or held
    /// under an expired lease.
    fn stale(&self, older_than: Duration, limit: Option<usize>) -> Result<Vec<StaleIssue>> {
        hierarchy::stale(self.conn(), self.now(), older_than, limit)
    }

    /// Issues whose text names `<prefix>-` ids that do not exist.
    fn orphans(&self, prefix: &str) -> Result<Vec<Orphan>> {
        hierarchy::orphans(self.conn(), prefix)
    }

    fn parent(&self, id: &str) -> Result<Option<String>> {
        graph::parent_of(self.conn(), id)
    }

    /// The brief form of each issue, with its parent.
    fn briefs(&self, issues: &[Issue]) -> Result<Vec<IssueBrief>> {
        issues.iter().map(|i| Ok(IssueBrief::new(i, graph::parent_of(self.conn(), &i.id)?))).collect()
    }

    /// The last `n` comments on an issue, in chronological order, and how
    /// many it has in all.
    fn comments_tail(&self, id: &str, n: usize) -> Result<(Vec<Comment>, i64)> {
        Ok((comments::tail(self.conn(), id, n)?, comments::count(self.conn(), id)?))
    }

    /// `show --brief`: the brief fields, a cut description, the open
    /// blockers' ids and the last `comments_tail` comments.
    fn show_brief(&self, id: &str, comments_tail: usize) -> Result<ShowBrief> {
        let issue = issues::require(self.conn(), id)?;
        let parent = graph::parent_of(self.conn(), id)?;
        let blockers = graph::blockers(self.conn(), id)?.into_iter().map(|b| b.id).collect();
        let (comments, comments_total) = self.comments_tail(id, comments_tail)?;
        let (description, description_truncated) = cut_chars(&issue.description, BRIEF_DESCRIPTION_CHARS);
        Ok(ShowBrief {
            brief: IssueBrief::new(&issue, parent),
            description,
            description_truncated,
            blockers,
            comments: comments.into_iter().map(CommentBrief::from).collect(),
            comments_total,
        })
    }

    /// Number of ancestors above each of `ids` in the hierarchy, in one pass.
    fn depths(&self, ids: &[String]) -> Result<Vec<usize>> {
        graph::depths(self.conn(), ids)
    }

    fn ready(&self, q: &ReadyQuery) -> Result<Vec<Issue>> {
        ready::ready(self.conn(), q, self.now())
    }

    fn blocked(&self, filter: &WorkFilter, limit: Option<usize>) -> Result<Vec<BlockedIssue>> {
        ready::blocked(self.conn(), filter, limit)
    }

    fn blockers(&self, id: &str) -> Result<Vec<Blocker>> {
        graph::blockers(self.conn(), id)
    }

    /// Why an issue is not in the ready queue (empty when it is ready).
    fn not_ready_reasons(&self, id: &str) -> Result<Vec<String>> {
        let issue = issues::require(self.conn(), id)?;
        ready::not_ready_reasons(self.conn(), &issue, self.now())
    }

    /// Whether an issue is ready and every reason it is not, counted as
    /// `opts` says (see [`ready::explain`]).
    fn explain(&self, id: &str, opts: ExplainOptions) -> Result<Readiness> {
        let issue = issues::require(self.conn(), id)?;
        let reasons = ready::explain(self.conn(), &issue, self.now(), opts)?;
        Ok(Readiness { id: issue.id, ready: reasons.is_empty(), reasons })
    }

    /// Open issues that `q`'s ready queue leaves out as blocked, waiting on
    /// their children or deferred (see [`ready::not_ready`]).
    fn not_ready(&self, q: &ReadyQuery) -> Result<Vec<Issue>> {
        ready::not_ready(self.conn(), q, self.now())
    }

    fn dependencies(&self, id: &str) -> Result<Vec<Edge>> {
        issues::require(self.conn(), id)?;
        graph::dependencies_of(self.conn(), id)
    }

    fn dependents(&self, id: &str) -> Result<Vec<Edge>> {
        issues::require(self.conn(), id)?;
        graph::dependents_of(self.conn(), id)
    }

    fn dep_tree(&self, id: &str, direction: Direction, max_depth: usize) -> Result<Vec<TreeNode>> {
        graph::dep_tree(self.conn(), id, direction, max_depth)
    }

    /// The subgraph around `root` (following edges only down or only up), or
    /// of every issue not closed or pinned; at most `max_nodes` issues.
    fn subgraph(&self, root: Option<&str>, edges: &EdgeSet, max_nodes: usize) -> Result<Subgraph> {
        match root {
            Some(id) => subgraph::around(self.conn(), id, edges, max_nodes),
            None => subgraph::open_issues(self.conn(), edges, max_nodes),
        }
    }

    fn cycles(&self) -> Result<Vec<Vec<String>>> {
        graph::find_cycles(self.conn())
    }

    fn comments(&self, id: &str) -> Result<Vec<Comment>> {
        issues::require(self.conn(), id)?;
        comments::list(self.conn(), id)
    }

    fn memory(&self, key: &str) -> Result<Option<Memory>> {
        memory::get(self.conn(), key)
    }

    fn memories(&self, query: Option<&str>) -> Result<Vec<Memory>> {
        memory::list(self.conn(), query)
    }

    fn lease(&self, id: &str) -> Result<Option<Lease>> {
        claims::get_lease(self.conn(), id)
    }

    fn leases(&self) -> Result<Vec<LeaseView>> {
        claims::leases(self.conn(), self.now())
    }

    fn events(&self, q: &EventQuery) -> Result<EventPage> {
        events::query(self.conn(), q)
    }

    /// The events [`Queries::events`] returns, handed to `f` oldest first in
    /// batches of at most `batch` instead of collected: the head and floor.
    fn events_each(
        &self,
        q: &EventQuery,
        batch: usize,
        f: &mut dyn FnMut(&[Event]) -> Result<()>,
    ) -> Result<(i64, i64)> {
        events::query_each(self.conn(), q, batch, f)
    }

    /// The issue as it was at `point`, rebuilt from its events ([`asof`]).
    fn issue_as_of(&self, id: &str, point: Point) -> Result<IssueAsOf> {
        asof::issue_as_of(self.conn(), id, point)
    }

    /// Closed issues to compact ([`compaction`]): closed at least `older_than` ago.
    fn compact_candidates(&self, older_than: Duration, limit: Option<usize>) -> Result<Vec<Candidate>> {
        compaction::candidates(self.conn(), self.now(), older_than, limit)
    }

    fn compact_stats(&self, older_than: Duration) -> Result<CompactStats> {
        compaction::stats(self.conn(), self.now(), older_than)
    }

    fn history(&self, id: &str) -> Result<Vec<Event>> {
        events::history(self.conn(), id)
    }

    fn event_head(&self) -> Result<i64> {
        events::head(self.conn())
    }

    fn stats(&self) -> Result<Stats> {
        metrics::stats(self.conn(), self.now())
    }

    fn config_value(&self, key: &str) -> Result<String> {
        config::get_or_default(self.conn(), key)
    }

    fn config_entries(&self) -> Result<Vec<ConfigEntry>> {
        config::list(self.conn())
    }

    fn label_counts(&self) -> Result<Vec<(String, i64)>> {
        issues::label_counts(self.conn())
    }

    fn export_jsonl(&self, out: &mut dyn Write, opts: &ExportOptions) -> Result<ExportSummary> {
        transfer::export(self.conn(), self.now(), out, opts)
    }
}

impl Queries for ReadCtx<'_> {
    fn conn(&self) -> &Connection {
        ReadCtx::conn(self)
    }
    fn now(&self) -> Timestamp {
        ReadCtx::now(self)
    }
}

impl Queries for WriteCtx<'_> {
    fn conn(&self) -> &Connection {
        WriteCtx::conn(self)
    }
    fn now(&self) -> Timestamp {
        WriteCtx::now(self)
    }
}
