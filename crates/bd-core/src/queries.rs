//! The read API, shared by snapshots ([`crate::ReadCtx`]) and write
//! transactions ([`crate::WriteCtx`]), so a writer can read its own changes.

use std::io::Write;

use rusqlite::Connection;

use crate::claims::{self, LeaseView};
use crate::comments;
use crate::config::{self, ConfigEntry};
use crate::error::Result;
use crate::events::{self, EventPage, EventQuery};
use crate::graph::{self, Direction, TreeNode};
use crate::issues;
use crate::memory;
use crate::metrics::{self, Stats};
use crate::model::{
    Blocker, Comment, Edge, Event, Issue, IssueDetails, IssueRef, Lease, ListQuery, Memory, ReadyQuery, WorkFilter,
};
use crate::ready::{self, BlockedIssue};
use crate::store::{ReadCtx, WriteCtx};
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

    fn children(&self, id: &str) -> Result<Vec<IssueRef>> {
        issues::children(self.conn(), id)
    }

    fn parent(&self, id: &str) -> Result<Option<String>> {
        graph::parent_of(self.conn(), id)
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
