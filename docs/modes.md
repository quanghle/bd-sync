# Modes of operation

bd runs one way, against one SQLite database per workspace, reached in one of
three ways:

| mode | database | who uses it | set up with |
|---|---|---|---|
| Local workspace | `.bd/bd.db` in the checkout | agents and people on one machine | `bd init` |
| Remote workspace | on a `bd serve` host; clients send commands over HTTPS | laptops, CI runners and cloud agents sharing work | `bd serve` on the server, `bd remote set` in each checkout |
| Embedded library | any path, opened by your program | Rust programs that coordinate work themselves | `bd_core::Store::open` |

Every mode gives the same guarantees: claims are atomic, lease tokens and
times come from one clock, and the event log is gapless, because every write
is one SQLite transaction on one database.

## Local workspace

`bd init --prefix <prefix>` creates `.bd/bd.db` (SQLite in WAL mode) in the
current directory, and bd finds it from any subdirectory, like git finds
`.git`. Every `bd` process on the machine opens the database directly; SQLite's
single writer lock makes claims atomic between them. The database is local
state: `bd init` writes a `.bd/.gitignore` that keeps it and its WAL files out
of commits; `bd export`/`bd import` move a workspace. Everything stays on the machine
([Observability](observability.md)).

A local workspace serves one host only: SQLite's WAL needs every process on
one host, so a `bd.db` on a network file system is not safe. To share work
between machines, use a remote workspace.

### Backing up a local workspace

`bd backup --to DIR` copies the workspace's database to
`DIR/<name>/<name>-<UTC time>.db` (e.g. `proj-20261001T214244.014Z.db`), where
`<name>` is the workspace's issue prefix (`--name` picks another: letters,
digits, `.`, `_` and `-`), and deletes all but the newest `--keep` copies
(default 24, the new one included; `0` keeps them all). These are the copies
`bd serve --backup-dir` takes of each workspace it serves, with the same
guarantees ([Background jobs and backups](remote.md#background-jobs-and-backups)):
each is a compact, self-contained database taken with `VACUUM INTO` without
holding up writers, checked and flushed to disk under a temporary name before
it is renamed into place, and the copy just written is never deleted, even
when older ones are dated after it (a warning says so). On Unix, copies are created 0600
and the directories `bd backup` creates 0700. It prints the new file, its
size, and how many old copies were deleted and kept (`--json`: `file`,
`bytes`, `removed`, `kept`, `name`, `workspace`; `-q`: the file only). Run it
from cron for periodic copies:

```bash
# Every hour, keeping a day of copies in /backups/bd/proj/.
0 * * * * bd -C /home/me/proj backup --to /backups/bd --keep 24 -q
```

To restore, stop the agents using the workspace, move `.bd/bd.db` and its
`-wal` and `-shm` files aside, copy a backup to `.bd/bd.db`, and run
`bd doctor`. In a remote workspace `bd backup` is refused: the server holds
the database, and `bd serve --backup-dir` backs it up.

## Remote workspace

`bd serve` holds the databases of several workspaces and runs each client's
command there, as it would run locally. The same `bd` binary is the client:
a checkout with `.bd/remote.toml` (written by `bd remote set <url>`) sends
every command to the server, with an access token from `bd remote login` or
`$BD_TOKEN`. The server also reclaims dead workers' leases, checks gates and
takes backups on its own. See [Remote server](remote.md) for running a
server, tokens, GitHub sign-in and clients, and [Security](security.md) for
what the tokens allow.

A `.bd/remote.toml` takes precedence over a `.bd/bd.db` in the same
directory; `--db` always means a local database, and `--remote` (or
`$BD_REMOTE`) a server.

## Embedded library

The engine is the `bd-core` crate; the `bd` CLI is a thin layer over it.

```rust
use bd_core::{ClaimOptions, CloseOptions, NewIssue, OpenOptions, Queries, ReadyQuery, Store};

let mut store = Store::open(std::path::Path::new(".bd/bd.db"), OpenOptions::default())?;
let id = store.write("create", "planner", |tx| Ok(tx.create_issue(NewIssue::titled("Index the repo"))?.id))?;
if let Some(claim) = store.write("claim", "agent-1", |tx| tx.claim_next(&ReadyQuery::default(), &ClaimOptions::default()))? {
    let close = CloseOptions { token: Some(claim.lease.token), ..Default::default() };
    store.write("close", "agent-1", |tx| tx.close_issue(&claim.issue.id, &close))?;
}
let ready = store.read(|r| r.ready(&ReadyQuery::default()))?;
```

`Store::write` runs the closure in one `BEGIN IMMEDIATE` transaction and
records its timing. `Store::read` runs against one consistent snapshot. Open
one `Store` per thread or process; the database file is the coordination
point.
