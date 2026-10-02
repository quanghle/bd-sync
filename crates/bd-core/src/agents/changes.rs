//! Change events for agent sets: `bd serve` records each harness's set
//! revision per workspace, and appends an [`AGENTS_CHANGED`] event when one
//! changes, which `events --since N --wait D` followers (`bd agents
//! watch`) wake on.
//!
//! The revisions last recorded live in the database's internal metadata,
//! under `agents.revision.<harness>`. A harness without one counts as
//! having served an empty set, so a workspace that never served anything
//! never gets an event.

use std::collections::BTreeMap;

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use super::{AgentSet, Harness};
use crate::error::Result;
use crate::store::{Store, WriteCtx, meta_get, meta_set};

/// The op of the event appended when a harness's set changed.
pub const AGENTS_CHANGED: &str = "agents_changed";

/// What an [`AGENTS_CHANGED`] event holds (its issue is none):
/// `{"harness": "claude", "revision": "<sha256>", "previous": "<sha256>"}`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentsChanged {
    pub harness: Harness,
    /// The set's revision now.
    pub revision: String,
    /// The revision recorded before (an empty set's, if none was).
    pub previous: String,
}

fn meta_key(h: Harness) -> String {
    format!("agents.revision.{h}")
}

/// The harnesses whose revision in `revisions` differs from the one recorded.
fn changes(conn: &Connection, revisions: &BTreeMap<Harness, String>) -> Result<Vec<AgentsChanged>> {
    let mut changed = Vec::new();
    for (&harness, revision) in revisions {
        let previous = meta_get(conn, &meta_key(harness))?.unwrap_or_else(|| AgentSet::empty(harness).revision);
        if previous != *revision {
            changed.push(AgentsChanged { harness, revision: revision.clone(), previous });
        }
    }
    Ok(changed)
}

/// Record `revisions`, the current revision of each harness's set
/// ([`AgentSet::load`]) in `store`'s workspace, as `actor`: for each that
/// differs from the one recorded, append an [`AGENTS_CHANGED`] event and
/// record it, in one write transaction. Harnesses left out keep what was
/// recorded. When nothing changed, this is a read: no write transaction.
pub fn record_revisions(
    store: &mut Store,
    actor: &str,
    revisions: &BTreeMap<Harness, String>,
) -> Result<Vec<AgentsChanged>> {
    if store.read(|r| changes(r.conn(), revisions))?.is_empty() {
        return Ok(Vec::new());
    }
    store.write("agents.revisions", actor, |tx| record_in(tx, revisions))
}

/// The write of [`record_revisions`], which compares again: another
/// process may have recorded the same change since it read.
fn record_in(tx: &mut WriteCtx<'_>, revisions: &BTreeMap<Harness, String>) -> Result<Vec<AgentsChanged>> {
    let changed = changes(tx.conn(), revisions)?;
    for c in &changed {
        meta_set(tx.conn(), &meta_key(c.harness), &c.revision)?;
        tx.emit(AGENTS_CHANGED, None, serde_json::to_value(c)?)?;
    }
    Ok(changed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::EventQuery;
    use crate::{InitOptions, NewIssue, OpenOptions, Queries};

    fn store() -> (tempfile::TempDir, Store) {
        let dir = tempfile::tempdir().unwrap();
        let init = InitOptions { prefix: "t".into(), id_mode: Default::default() };
        let store = Store::init(&dir.path().join("bd.db"), init, OpenOptions::default()).unwrap();
        (dir, store)
    }

    fn revs(pairs: &[(Harness, &str)]) -> BTreeMap<Harness, String> {
        pairs.iter().map(|(h, r)| (*h, r.to_string())).collect()
    }

    fn events(store: &Store) -> Vec<crate::Event> {
        store.read(|r| r.events(&EventQuery { since: Some(0), ..Default::default() })).unwrap().events
    }

    fn last_write(store: &Store) -> &'static str {
        store.last_tx_stats().map_or("", |s| s.op)
    }

    #[test]
    fn changed_sets_append_one_event_each_and_unchanged_ones_write_nothing() {
        let (_dir, mut store) = store();
        let empty = AgentSet::empty(Harness::Claude).revision;
        let (r1, r2) = ("1".repeat(64), "2".repeat(64));

        // Nothing served: nothing recorded, not even a write.
        let none = revs(&[(Harness::Claude, &empty), (Harness::Codex, &empty), (Harness::Copilot, &empty)]);
        assert_eq!(record_revisions(&mut store, "bd-serve", &none).unwrap(), []);
        assert_eq!(last_write(&store), "init");
        assert!(events(&store).iter().all(|e| e.op != AGENTS_CHANGED));

        // The first sight of a set: from an empty one.
        let first = revs(&[(Harness::Claude, &r1), (Harness::Codex, &empty), (Harness::Copilot, &empty)]);
        let changed = record_revisions(&mut store, "bd-serve", &first).unwrap();
        let want = AgentsChanged { harness: Harness::Claude, revision: r1.clone(), previous: empty.clone() };
        assert_eq!(changed, std::slice::from_ref(&want));
        let e = events(&store).pop().unwrap();
        assert_eq!((e.op.as_str(), e.issue_id.as_deref(), e.actor.as_str()), (AGENTS_CHANGED, None, "bd-serve"));
        assert_eq!(e.data, serde_json::json!({"harness": "claude", "revision": r1, "previous": empty}));
        assert_eq!(serde_json::from_value::<AgentsChanged>(e.data).unwrap(), want);

        // Unchanged: no write transaction at all.
        store.write("create", "alice", |tx| tx.create_issue(NewIssue::titled("x"))).unwrap();
        let head = events(&store).last().unwrap().seq;
        assert_eq!(record_revisions(&mut store, "bd-serve", &first).unwrap(), []);
        assert_eq!(last_write(&store), "create", "only read");
        assert_eq!(events(&store).last().unwrap().seq, head);

        // Only the harness that changed, with what it was; one left out keeps its record.
        let second = revs(&[(Harness::Claude, &r1), (Harness::Codex, &r2)]);
        let changed = record_revisions(&mut store, "bd-serve", &second).unwrap();
        assert_eq!(changed, [AgentsChanged { harness: Harness::Codex, revision: r2.clone(), previous: empty.clone() }]);
        let third = revs(&[(Harness::Codex, &r1)]);
        let changed = record_revisions(&mut store, "bd-serve", &third).unwrap();
        assert_eq!(changed, [AgentsChanged { harness: Harness::Codex, revision: r1.clone(), previous: r2.clone() }]);

        // Emptied: back to the empty revision, once.
        let emptied = revs(&[(Harness::Claude, &empty), (Harness::Codex, &empty)]);
        let changed = record_revisions(&mut store, "bd-serve", &emptied).unwrap();
        assert_eq!(
            changed,
            [
                AgentsChanged { harness: Harness::Claude, revision: empty.clone(), previous: r1.clone() },
                AgentsChanged { harness: Harness::Codex, revision: empty.clone(), previous: r1.clone() },
            ]
        );
        assert_eq!(record_revisions(&mut store, "bd-serve", &emptied).unwrap(), []);

        // Gapless: each change is one event, and the two of one write share its transaction.
        let all = events(&store);
        assert!(all.windows(2).all(|w| w[1].seq == w[0].seq + 1), "{all:?}");
        let ours: Vec<&crate::Event> = all.iter().filter(|e| e.op == AGENTS_CHANGED).collect();
        assert_eq!(ours.len(), 5);
        assert_eq!(ours[3].tx, ours[4].tx);
        assert_ne!(ours[2].tx, ours[3].tx);
    }

    #[test]
    fn a_change_recorded_meanwhile_is_not_recorded_twice() {
        let (dir, mut store) = store();
        let mut other = Store::open(&dir.path().join("bd.db"), OpenOptions::default()).unwrap();
        let changed = revs(&[(Harness::Copilot, &"3".repeat(64))]);
        // Another process records the change between this one's read and its write.
        assert_eq!(store.read(|r| changes(r.conn(), &changed)).unwrap().len(), 1);
        assert_eq!(record_revisions(&mut other, "bd-serve", &changed).unwrap().len(), 1);
        assert_eq!(store.write("agents.revisions", "bd-serve", |tx| record_in(tx, &changed)).unwrap(), []);
        assert_eq!(events(&store).iter().filter(|e| e.op == AGENTS_CHANGED).count(), 1);
    }
}
