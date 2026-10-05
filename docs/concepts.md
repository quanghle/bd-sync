# Concepts

A workspace is one SQLite database (`.bd/bd.db`) holding issues, the
dependencies between them, claims, comments, memories and an event log.
Every change is one transaction that also appends its events, so the state
and its history never disagree.

## Issues

An issue has an id, a title, a status, a type, a priority and optional
text fields (`description`, `design`, `acceptance`, `notes`), labels, an
assignee, an estimate, a due time, a defer time, an external reference and
a JSON `metadata` object.

- **Ids** are `<prefix>-<base36 hash>` by default (`id.mode = hash`, short
  and adaptive in length), or sequential numbers with `id.mode = counter`.
  A child created with `--parent` gets `<parent>.<n>`. Commands accept any
  unique prefix of an id.
- **Types**: `task` (default), `bug`, `feature`, `epic`, `chore`,
  `decision`, `spike`, `story`, `milestone`, and `gate` (reserved for
  [gates](playbooks.md#gates)). `types.custom` adds more.
- **Priority**: `0` (critical) to `4` (backlog), default `2`; `P0`–`P4` is
  accepted too.

## Statuses

| status | ready? | releases dependents? | notes |
|---|---|---|---|
| `open` | yes, unless blocked or deferred | no | |
| `in_progress` | no | no | always has an assignee and a lease |
| `blocked` | no | no | set by hand: "stuck" |
| `deferred` | no | no | parked indefinitely (`bd defer <id>`) |
| `closed` | no | **yes** | outcome `done` or `failed` (`bd close --failed`) |
| `pinned` | no | **yes** | persistent context, never work |

`bd defer <id> --until 2026-01-15` keeps the status and hides the issue and
its whole subtree from ready work until then (`bd undefer` ends it early).

Closing an issue with open children, or one still blocked, is refused
unless you pass `--force`. The exception is a *spawner*, an issue others
wait on through `waits-for`: it may close before the children it spawned.
`--force` never ends another actor's live claim (see
[Claims](#claims-leases-and-recovery)).

## Dependency types

`bd dep add ISSUE DEPENDS_ON -t TYPE` (also `bd create --dep TYPE:ID`):

| type | effect on ISSUE |
|---|---|
| `blocks` (default) | blocked until DEPENDS_ON is closed or pinned |
| `conditional-blocks` | runs only if DEPENDS_ON closes as **failed**; stays blocked if it succeeds |
| `parent-child` | hierarchy, one parent per issue. A blocked parent blocks its whole subtree; a parent with open children waits for them (see below) |
| `waits-for` | fan-in on DEPENDS_ON's children: `--gate all-children` (default) or `any-children`. Edge metadata `--metadata '{"also_blocks": true}'` also waits on DEPENDS_ON itself |
| `related`, `discovered-from`, `tracks`, `caused-by`, `validates`, `supersedes`, `duplicates`, `replies-to` | informational only |
| custom (`[a-z][a-z0-9-]{0,31}`) | informational only |

Only the first four affect readiness. Cycles of `blocks`,
`conditional-blocks` and `parent-child` edges are refused when the edge is
written, with the cycle's path in the error; `bd dep cycles` checks a whole
workspace. `bd dep list` and `bd dep tree` show edges (`--direction`,
`--max-depth`), and `bd blocked` lists blocked issues with their blockers.

## Ready work

`bd ready` lists open issues that are not blocked, not deferred and not
waiting on children, in one deterministic order:

- `--sort priority` (default): priority, then oldest, then id.
- `--sort oldest`: creation time, then id.
- `--sort hybrid`: issues from the last 48 hours by priority, then older
  ones by age.

Every order ends with the id, so the same state and clock always give the
same queue. The blocked flag is materialized and kept up to date in the
same transaction as every change; `bd doctor` checks it against a full
recompute.

- **Children first.** An issue with a child that is not closed waits for
  its children, whatever its type, until all of them have closed. Waiting
  is not a block: the children are ready as usual, and `bd ready` and
  `bd stats` count the issues waiting on children. A spawner never waits.
- **Epics** are containers and are left out unless you pass
  `--include-epics` or `-t epic`. **Gates** are left out too (`-t gate`
  lists the open, unblocked ones), and can never be claimed.
- **Filters**: `-l/--label` (all of), `--label-any`, `--exclude-label`,
  `-t/--type`, `--exclude-type`, `-a/--assignee`, `--unassigned`,
  `-p/--priority`, `--max-priority` and `--parent` (alias `--run`), which
  `claim --next` shares with `--sort`; plus `--include-deferred` and
  `-n/--limit` (default 50, `0` for all).

## Claims, leases and recovery

A claim makes an issue `in_progress`, assigns it to you and gives you a
**lease** (`lease.ttl`, default 5 minutes) with a **fencing token**.

```bash
bd claim <id>              # or: bd claim --next [--parent <id>] [filters]
bd heartbeat <id> --token <t>
bd close <id> --reason "..." --token <t>     # --failed when it failed
bd release <id> --token <t>                  # give it back
```

- **Atomic.** A claim runs inside one `BEGIN IMMEDIATE` transaction, under
  SQLite's single writer lock: two agents never take the same issue.
  `claim --next` takes the head of the ready queue and never returns work
  someone holds.
- **What can be claimed.** An issue that is `open`, ready, and unassigned,
  reserved for you, or held by a `claim.pools` alias. An issue with open
  children is not ready: the refusal (exit 4) names the children, and
  `claim --next --parent <id>` claims one of them. `--allow-blocked` claims
  a blocked or deferred issue by id anyway.
- **The token** is the sequence number of the `claimed` event: unique and
  increasing. Pass it to `heartbeat`, `close` and `release`, so a worker
  that lost its claim cannot act on it. Claiming again with `--token` is an
  idempotent renewal.
- **Live and dead claims.** A claim is *live* until its lease has been
  expired for longer than `lease.grace` (default 10 minutes). A live claim
  is never claimed twice, not even by its own actor without its token. A
  dead claim is anyone's: `bd reclaim` reverts it to `open` with a
  `reclaimed` event, and `claim --next` reclaims dead claims first (unless
  `lease.auto_reclaim` is `false`). `bd leases` shows lease health
  (`--expired` for the expired ones).
- **A live claim belongs to its holder.** Ending or taking over another
  actor's live claim fails with exit 4 (`not_owner`, or `already_claimed`
  for a reassignment): `close`, `release`, `update --status` out of
  `in_progress`, `update --assignee`, `delete`, `import`, `playbook
  discard`/`compact`, and `reclaim` with a `--grace` shorter than
  `lease.grace`. "Another actor" means any other name, including the
  holder's parent actor (`alice` for `alice/agent-1`) and its siblings.
- **`--take-over`** is the only way past that, and the event records it as
  `claim_override` with the holder and lease token. `--force` never takes
  over a claim: it only gets past open children, blockers, dependents and
  unfinished runs, and the claim is checked first. `release --if-assignee
  <holder>` is a guard, not a takeover.
- **The holder** needs neither `--take-over` nor its token (a token it
  passes must match). Sessions that share one actor name can therefore end
  each other's claims, which is why each agent session gets its own actor
  ([Actors](#actors)).
- **Invariant** (checked by `bd doctor`): a lease exists if and only if the
  issue is `in_progress`, and the lease holder is the assignee.

Through `bd serve`, a takeover also needs an admin token, unless the claim
is held by the token's own actor or one of its sub-actors
([Remote server](remote.md#roles-and-what-tokens-may-do)). `bd serve` also
reclaims dead claims in every workspace each minute.

## Optimistic concurrency

Every issue has a `revision` that increases with each change to the issue
itself (comments, heartbeats and blocked-flag changes do not bump it). Read
it, decide, then write conditionally:

```bash
rev=$(bd show demo-xyz --json | jq .revision)
bd update demo-xyz --status blocked --if-revision "$rev"   # exit 13 if it changed
bd release demo-xyz --if-assignee worker-7 --take-over     # compare-and-set takeover
bd remember --key deploy "use blue/green" --if-revision 0  # create-only memory
```

`--if-status` and `--if-assignee` guard on those fields. A stale guard
exits 13 (`conflict`): read again before retrying.

## Event history

Each change appends events in its own transaction. `seq` is gapless and
commit-ordered; `tx` groups the events of one transaction.

| group | ops |
|---|---|
| issues | `created`, `updated` (field-level old/new), `closed`, `reopened`, `deleted` (with a snapshot) |
| claims | `claimed`, `released`, `reclaimed`, `lease_granted` |
| graph | `dep_added`, `dep_removed`, `dep_updated`, `blocked`, `unblocked` |
| other | `commented`, `memory_set`, `memory_deleted`, `config_set`, `config_unset`, `imported`, `pruned` |
| playbooks and gates | `run_started`, `run_compacted`, `purged`, `gate_escalated`, `gate_updated` |
| agent assets | `agents_changed` (written by `bd serve`; see [Agent assets](agents.md#serving-sets)) |

```bash
bd events -n 20                                # recent events
bd events --since 1200 --follow                # tail from a cursor (JSON lines with --json)
bd events --since 1200 --wait 5m --op closed   # wait for the next match, print, exit
bd history demo-xyz                            # one issue's events (survives deletion)
bd events prune --older-than 30d               # also --before, --keep
```

`--follow` keeps printing new events. `--wait` waits up to the given time
for an event matching the filters (`--issue`, `--op`, `--by`), then prints
like a plain `bd events --since`. Locally both poll every `--interval-ms`
(default 500); through a [bd server](remote.md#followers) they are woken as
events commit. A cursor older than what retention kept fails with exit 6.
Retention can also be automatic: `events.retain_days`, `events.retain_rows`.

To mirror a workspace elsewhere, load a `bd export` snapshot (its header
carries `head_seq`), then tail `bd events --since <head_seq>`.

## Comments and memory

```bash
bd comment add demo-xyz "API shape agreed"     # --file, --stdin; list: bd comments demo-xyz
bd remember "Integration tests need docker"    # key derived from the text
bd memories docker                             # search
bd recall <key>; bd forget <key>               # also: bd memory add|get|list|rm
```

Memories are durable project insights, with authorship and revisions.
`bd prime` prints them with your claims, ready work, gates waiting on a
person and the [playbooks](playbooks.md) available. Outside a workspace it
prints nothing, so it is safe in session hooks.

## Actors

Every write records its actor, and a live claim belongs to the actor that
took it. The actor is the first of:

1. `--actor NAME`
2. `$BD_ACTOR`, then `$BEADS_ACTOR`
3. the user (`git config user.name`, else `$USER` or `$USERNAME`), as the
   sub-actor `<user>/<session>` when the command runs in an agent session

The session joins, with `.`, a part for each of these that is set:

| variable | part |
|---|---|
| `$CLAUDE_CODE_SESSION_ID` (Claude Code) | `claude-<id>` |
| `$COPILOT_AGENT_SESSION_ID` (Copilot CLI) | `copilot-<id>` |
| `$CODEX_THREAD_ID`, else `$CODEX_SESSION_ID` (Codex) | `codex-<id>` |
| `$BD_SESSION` (or `--session` for one command) | the name itself |

`<id>` is the last 8 letters and digits of the session id, so an actor
looks like `Quang Le/copilot-b9bb2788`. A `$BD_SESSION` name keeps letters,
digits, `.`, `_` and `-` (anything else becomes `-`), loses leading and
trailing `-` and `.`, and is cut to 64 characters.

Harnesses set their variable in every shell command of a session, so all
of a session's bd commands act alike and two sessions never do. A plain
terminal keeps the plain user. An agent started from another agent's shell
inherits its parent's variables and adds its own, so it acts as, say,
`<user>/claude-<id>.codex-<id>`: apart from its parent and its siblings.
Naming the actor outright (`--actor`, `$BD_ACTOR`) turns all of this off,
and every session with the same `$BD_ACTOR` shares its claims again.

`bd info` and `bd prime` show the actor and where it came from; `bd claim`
prints it. `bd prime` warns when you act as the plain default actor and it
holds claims.

**Claims from earlier sessions.** After a harness starts a new session id
(a resume, a cleared conversation, a subagent with its own id), earlier
claims belong to another actor of yours. `bd prime` lists the in-progress
claims of your user's other actors under "Held by other sessions of
yours", each with the command that takes it over:
`bd update <id> --assignee <you> --take-over`, which prints the new lease
token. Take one over only if this session continues that work. Only
derived actors have "sessions of yours": with `BD_ACTOR=pool/w1`, a claim
of `pool/w2` is simply another actor's.

Subagents, session hooks and harness-specific details are in
[Sessions and subagents](agents.md#sessions-and-subagents).

**In a remote workspace** the access token decides: `--actor` and
`$BD_ACTOR` may name only the token's actor or one of its sub-actors.
Without them, a client in an agent session sends its session and acts as
`<token actor>/<session>`; the server never derives an actor from its own
environment.
