# bd — a coordination engine for agents, on SQLite WAL

`bd` is a Rust re-implementation of [beads](https://github.com/gastownhall/beads)
(the `bd` issue tracker for AI coding agents) as a fast, embeddable
coordination engine:

- **Task lifecycle**: `open → in_progress → closed`, plus `blocked`, `deferred`, `pinned`
- **Typed dependency graph**: `blocks`, `conditional-blocks`, `parent-child`, `waits-for` gate readiness; informational edges (`related`, `discovered-from`, …) never do. Cycles and hierarchy deadlocks are rejected at write time.
- **Deterministic ready work**: a materialized blocked flag maintained in the same transaction as every change, and a total queue order (policy, then id)
- **Leased atomic claiming**: claims run under SQLite's write lock and return a lease with a fencing token; a live claim is its holder's alone, and taking one over takes `--take-over`
- **Crash recovery**: expired leases are reclaimed after a grace window (automatically by `claim --next`, and every minute by `bd serve`); WAL makes every transaction atomic
- **Optimistic concurrency**: per-issue revisions and `--if-revision/--if-status/--if-assignee` guards (exit code 13 on conflict)
- **Comments, durable memory, and transactional event history** with gapless, commit-ordered sequence numbers
- **Playbooks and gates**: repeatable multi-step work declared once in TOML and run atomically as `<run>.<step>` issues; human, timer, issue, and GitHub gates that arm when their step could start ([Playbooks](#playbooks-repeatable-multi-step-work))
- **Remote server**: `bd serve` shares workspaces over HTTPS with laptops, CI runners and cloud agents; the same `bd` binary is the client, with access tokens (roles, and human or agent kinds) that an admin creates or people get by signing in with GitHub, and retries that apply a write once. The server also reclaims dead workers' leases, checks gates and takes backups on its own ([Remote server](#remote-server-one-workspace-many-machines))
- **Agent assets**: a workspace serves skills and MCP server definitions per harness (Claude Code, Codex, Copilot CLI); checkouts pull them into each harness's own places, skills at session start, MCP definitions only once a person approves them ([Agent skills and MCP definitions](#agent-skills-and-mcp-definitions))
- Extras: JSONL export/import (reads beads exports), `bd batch` (many writes, one transaction), `bd bench`, and local observability (structured logs, timing, Prometheus metrics, `bd doctor`)

It ships as a library (`crates/bd-core`) and a CLI (`crates/bd-cli`, binary `bd`).

## How beads works (and what this keeps)

Beads stores issues in an embedded Dolt (versioned SQL) database under
`.beads/`, syncs it across machines with `bd dolt push/pull`, and gives agents
a dependency-aware work queue:

| beads concept | beads implementation | here |
|---|---|---|
| Issues | `issues` table; hash ids `prefix-<base36>` with adaptive length; child ids `parent.N` | same id scheme (plus `counter` mode) |
| Dependencies | `dependencies(issue_id, depends_on_id, type)`; one edge per pair; cycle check via recursive CTE | same, plus BFS cycle *path* in errors |
| Ready work | materialized `issues.is_blocked`, recomputed per affected set to a fixpoint; ready = `open` ∧ ¬blocked ∧ not deferred | same model; deferral also hides grandchildren (beads checks one level) |
| `conditional-blocks` | documented as "runs only if the blocker fails"; implemented exactly like `blocks` | implemented as documented, using an explicit close outcome (`bd close --failed`) |
| Claims | `UPDATE … WHERE row_lock = ?` compare-and-swap; Dolt merges + retries | `BEGIN IMMEDIATE`: the read-check-write runs under SQLite's single writer lock, so no retries |
| Leases | node-local `leases` table, 5 min TTL, `bd heartbeat`, `bd reclaim` with 2×TTL grace | same, plus a fencing token, and `claim --next` auto-reclaims |
| Concurrency guards | random `row_lock`; `--if-assignee/--if-status` (exit 13) | monotonic `revision` plus the same guards |
| Events | audit `events` table plus an opt-in `bd_events_journal` with gapless seq from a counter row | one always-on log; `AUTOINCREMENT` seq written in the mutation's transaction |
| Memory | `config` rows `kv.memory.<key>`, key derived from content, injected by `bd prime` | dedicated table with authorship, revisions, and CAS |
| Workflows | formulas cooked into protos, poured into molecules (hash-id issues); gates; wisps in a separate table | playbooks run straight into `<run>.<step>` issues in one transaction; gates arm when their step could start; ephemeral runs ([Playbooks](#playbooks-repeatable-multi-step-work)) |

## Install

### Prebuilt binaries

Each [GitHub Release](https://github.com/quanghle/bd-sync/releases) has an
archive per platform, holding `bd` (`bd.exe` on Windows) and this README, plus
a `SHA256SUMS` file and a signed build-provenance attestation for every archive:

| Platform | Archive |
|---|---|
| Linux x86_64 (static, any distro) | `bd-<tag>-x86_64-unknown-linux-musl.tar.gz` |
| Linux arm64 (static, any distro) | `bd-<tag>-aarch64-unknown-linux-musl.tar.gz` |
| macOS Apple silicon (11+) | `bd-<tag>-aarch64-apple-darwin.tar.gz` |
| macOS Intel (11+) | `bd-<tag>-x86_64-apple-darwin.tar.gz` |
| Windows x86_64 | `bd-<tag>-x86_64-pc-windows-msvc.zip` |
| Windows arm64 | `bd-<tag>-aarch64-pc-windows-msvc.zip` |

Linux and macOS:

```bash
tag=v0.1.0 target=x86_64-unknown-linux-musl     # a release tag and a target from the table
base=https://github.com/quanghle/bd-sync/releases/download/$tag
curl -fL -O "$base/bd-$tag-$target.tar.gz" -O "$base/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS   # macOS: shasum -a 256 --check --ignore-missing SHA256SUMS
gh attestation verify "bd-$tag-$target.tar.gz" --repo quanghle/bd-sync   # optional: built by this repo's release workflow
tar -xzf "bd-$tag-$target.tar.gz" bd
mkdir -p ~/.local/bin && mv bd ~/.local/bin/   # or any other directory on PATH
bd version
```

Windows (PowerShell):

```powershell
$tag = "v0.1.0"; $target = "x86_64-pc-windows-msvc"    # or aarch64-pc-windows-msvc
$base = "https://github.com/quanghle/bd-sync/releases/download/$tag"
Invoke-WebRequest "$base/bd-$tag-$target.zip" -OutFile "bd-$tag-$target.zip"
Invoke-WebRequest "$base/SHA256SUMS" -OutFile SHA256SUMS
(Get-FileHash "bd-$tag-$target.zip" -Algorithm SHA256).Hash   # must match its line in SHA256SUMS
Expand-Archive "bd-$tag-$target.zip" -DestinationPath "$env:LOCALAPPDATA\Programs\bd"
# then add $env:LOCALAPPDATA\Programs\bd to your user PATH and open a new terminal
```

The Windows binaries link the C runtime statically, so no Visual C++
redistributable is needed. The macOS binaries are not notarized: if a browser
download is blocked by Gatekeeper, run `xattr -d com.apple.quarantine bd`
(downloads with `curl` are not quarantined).

### From source

```bash
cargo install --path crates/bd-cli      # installs ~/.cargo/bin/bd
```

Either way the binary is named `bd`, so put its directory ahead of any Go
beads install on `PATH`, or migrate first (below). How releases are built,
checked and published: [RELEASING.md](RELEASING.md).

### Migrating from Go beads

Run the export with the Go binary, before uninstalling it:

```bash
beads export --all -o beads.jsonl       # the Go CLI (still named bd if not renamed)
bd init --prefix <same-prefix>          # same prefix keeps new ids consistent; existing ids are kept as-is
bd import beads.jsonl --dry-run         # preview, then run without --dry-run
bd doctor
git config --unset core.hooksPath       # beads routes git hooks to .beads/hooks
rm -rf .beads                           # once the import checks out
```

The import keeps ids, statuses, priorities, timestamps, close reasons,
labels, dependencies, comments, and memories. Gates keep their condition
(`metadata.gate`), wisps stay ephemeral, and protos (template issues) are
skipped: copy the formula files to `.bd/playbooks/` instead, where they load
as playbooks. Beads' `owner` field and its
Dolt commit history have no equivalent here; `hooked` issues become
`in_progress` with a fresh lease, and `tombstone` rows are skipped.
Agent hooks generated by beads (`bd prime --hook-json`, `bd codex-hook`,
`bd cursor-hook`) must be switched to plain `bd prime` (`bd prime --hook
copilot` in Copilot CLI hooks, which read only a JSON object).

## Quick start

```bash
bd init --prefix demo                       # creates .bd/bd.db (WAL)
bd create "Design schema" -p 1
bd create "Implement API" -p 2 --dep demo-xyz   # blocked until demo-xyz closes
bd ready                                    # unblocked work, queue order
bd claim --next                             # atomic claim + 5m lease (prints token)
bd heartbeat demo-xyz --token 42            # renew while working
bd close demo-xyz --reason "merged" --token 42
bd prime                                    # agent context: claims, ready work, memories
```

Agent loop: `bd claim --next --json` → work, heartbeating every few minutes
→ `bd close <id> --token <t>` (or `--failed`). If `heartbeat` exits 4, the
lease was lost (reclaimed or taken over): stop working on that issue. A
claim is protected from every other actor name, not from other sessions
sharing its own, so each agent session acts as its own actor
`<you>/<session>`, derived from the session id its agent harness sets
(Claude Code, Copilot CLI, Codex) or `BD_SESSION`; see
[Actors](#actors).

## Concepts

### Statuses

| status | ready? | releases dependents? | notes |
|---|---|---|---|
| `open` | yes, if not blocked or deferred | no | |
| `in_progress` | no | no | always has an assignee and a lease |
| `blocked` | no | no | manual "stuck" state |
| `deferred` | no | no | parked indefinitely (`bd defer <id>`) |
| `closed` | no | **yes** | outcome `done` or `failed` |
| `pinned` | no | **yes** | persistent context, never work |

`bd defer <id> --until 2026-01-15` keeps the status but hides the issue and
its whole subtree from ready work until then. Closing a parent with open
children, or closing a blocked issue, is refused unless you pass `--force`
(which never closes another actor's live claim: see [Claims](#claims-leases-and-recovery)).
The exception is a spawner: an issue others wait on with `waits-for` may close
before the children it spawned, since the waits-for edge tracks them.

### Dependency types (`bd dep add ISSUE DEPENDS_ON -t TYPE`)

| type | effect on ISSUE |
|---|---|
| `blocks` (default) | blocked while DEPENDS_ON is not closed/pinned |
| `conditional-blocks` | runs only if DEPENDS_ON closes as **failed**; stays blocked if it succeeds |
| `parent-child` | hierarchy (one parent); a blocked parent blocks its whole subtree, never the reverse |
| `waits-for` | fan-in gate on DEPENDS_ON's children: `--gate all-children` (default) or `any-children`; metadata `also_blocks: true` also waits on the spawner itself |
| `related`, `discovered-from`, `tracks`, `caused-by`, `validates`, `supersedes`, `duplicates`, `replies-to`, custom | informational only |

### Ready-work order

`--sort priority` (default): priority, then oldest, then id. `--sort oldest`:
creation time, then id. `--sort hybrid`: issues from the last 48h by
priority, then older ones by age. Every policy ends with `id`, so the same
state and clock always give the same queue. Epics are containers and are
excluded unless you pass `--include-epics` or `-t epic`. Gates are never
ready work (`-t gate` lists them).

### Claims, leases, and recovery

- `bd claim <id>` succeeds only if the issue is `open`, ready, and unassigned, reserved for you, or held by a `claim.pools` alias. A claim is *live* until `bd reclaim` could take it back (its lease expired more than `lease.grace` ago), and a live claim is never claimed twice: not even by its own actor, since two sessions may share an actor name. Its holder renews it with `bd claim <id> --token <t>` (an idempotent retry that returns the same lease); without the token, or with a stale one, the claim fails with exit 4. A dead claim (past `lease.grace`) is reclaimed by the claim first, with a `reclaimed` event.
- `bd claim --next` claims the head of the ready queue inside one write transaction, so two agents can never take the same issue, and never returns work someone holds. It first reclaims leases that expired more than `lease.grace` ago.
- The lease `token` is the sequence number of the `claimed` event: unique and increasing. Pass it to `claim`, `heartbeat`, `close`, or `release` so a stale worker cannot act on a claim it no longer holds.
- A live claim is its holder's. Ending or taking over one held by another actor name fails with exit 4 (`not_owner`, or `already_claimed` for a reassignment), alone or in a `bd batch`: `close`, `release`, `update --status` out of `in_progress`, `update --assignee`, `delete`, `playbook discard` and `compact` (of the run issue or a step), `import`, and `reclaim` with a `--grace` shorter than `lease.grace`. Another actor name is any other: the holder's root actor (`alice` for `alice/agent-1`) and its sibling sub-actors too. Only `--take-over` takes it over, deliberately, and the event (`closed`, `released`, `updated`, `deleted`, `imported`, `reclaimed`, or `run_compacted`'s `claim_overrides`) records the takeover as `claim_override` with the holder and lease token. `--force` never does: it only gets past open children, blockers, dependents, unfinished runs and your own work in progress, and the claim is checked first, so the first refusal names its holder (an operation that would end several claims lists every one, with its holder). On `update` and `release`, where `--force` used to mean a takeover, it is now refused as a usage error (exit 2) pointing at `--take-over`; `release --if-assignee <holder>` is a guard, not a takeover. The holder needs neither `--take-over` nor its token (a token it passes must match), so sessions sharing one actor name can still end each other's claims: give each agent its own actor. A dead claim is anyone's to claim, close or release without `--take-over`. A playbook run or group claimed by another actor stays open, still claimed, when its last step closes; its holder closes it.
- `bd reclaim` reverts dead workers' issues (leases expired more than `lease.grace` ago) to `open` and records `reclaimed` events. A shorter `--grace` reaches claims that are still live, so other actors' need `--take-over`. `bd leases` shows lease health. `bd serve` runs it with the configured grace in every workspace each minute ([Background jobs](#background-jobs-and-backups)).
- Invariant (checked by `bd doctor`): a lease exists if and only if the issue is `in_progress`, and the lease holder is the assignee.
- Through `bd serve`, a takeover also needs an admin token, unless the token's own actor or one of its sub-actors holds the claim ([Remote server](#remote-server-one-workspace-many-machines)).

### Optimistic concurrency

Every issue has a `revision` that increases on each change to the issue
itself. Comments, heartbeats, and derived blocked-flag changes do not bump
it. Read it, decide, then write conditionally:

```bash
rev=$(bd show demo-xyz --json | jq .revision)
bd update demo-xyz --status blocked --if-revision "$rev"   # exit 13 if someone else changed it
bd release demo-xyz --if-assignee worker-7 --take-over      # CAS takeover for supervisors
bd remember --key deploy "use blue/green" --if-revision 0   # create-only memory
```

### Event history

Each mutation appends events in its own transaction, so the log and the state
never disagree. Ops:

- issue lifecycle: `created`, `updated` (field-level old/new), `closed`, `reopened`, `deleted` (with a snapshot)
- claims: `claimed`, `released`, `reclaimed`, `lease_granted`
- graph: `dep_added`, `dep_removed`, `dep_updated`, `blocked`, `unblocked`
- other: `commented`, `memory_set`, `memory_deleted`, `config_set`, `imported`, `pruned`
- agent assets: `agents_changed` (a harness's skills and MCP definitions under `.bd/agents` changed: `harness`, `revision`, `previous`; written by `bd serve`)
- playbooks and gates: `run_started`, `run_compacted`, `purged` (one event listing every removed issue), `gate_escalated`, `gate_updated`

`seq` is gapless and commit-ordered. `tx` groups the events of one
transaction.

```bash
bd events -n 20                    # recent events
bd events --since 1200 --follow    # tail from a cursor (JSON lines with --json)
bd events --since 1200 --wait 5m --op closed   # wait for the next match, print it, exit
bd history demo-xyz                # one issue (survives deletion)
bd events prune --older-than 30d   # retention; a cursor behind it fails (exit 6)
```

`--follow` keeps printing new events; `--wait` prints the events after
`--since` like a plain `bd events --since`, but first waits up to the given
time for one matching the filters (`--issue`, `--op`, `--by`), so a script can
block until something happens. Locally both check the database every
`--interval-ms` (default 500). Through a [bd server](#followers), they are told
of new events as they are committed instead. A deleted issue keeps its events
(`--issue` still finds them, as `bd history` does).

To mirror the state elsewhere, `bd export` writes a snapshot whose header
carries `head_seq`. Load it, then tail `--since head_seq`.

### Comments and memory

```bash
bd comment add demo-xyz "API shape agreed with the frontend team"
bd remember "Integration tests need docker running"   # key derived: integration-tests-need-docker-running
bd memories docker ; bd recall <key> ; bd forget <key>
```

`bd prime` prints workflow context, your actor and claims, top ready work,
and all memories. Outside a workspace it prints nothing (safe in session
hooks). It warns when you act as the plain default actor, shared by every
session without one of its own, and that actor holds claims.

## Playbooks: repeatable multi-step work

A playbook declares a multi-step process once (a release, an incident drill,
an onboarding checklist). `bd playbook run` turns it into real issues that
flow through `bd ready` like any other work. Playbooks replace beads'
formulas and molecules:

| beads | here |
|---|---|
| formula (`.beads/formulas/*.formula.toml`) | playbook (`.bd/playbooks/*.toml`; `*.formula.toml` files load too) |
| `bd cook`, then `bd mol pour` | `bd playbook run`, in one step (`bd playbook plan` previews) |
| proto (a template epic stored in the database) | none: the file is the template |
| molecule | run: an epic with one issue per step |
| wisp (`bd mol wisp`) | ephemeral run (`--ephemeral`, or `ephemeral = true` in the playbook) |
| `bd mol bond` | `bd playbook run --parent <issue>` or `--after <issue>` |
| `bd mol squash` / `burn` / `distill` | `bd playbook compact` / `discard` / `extract` |
| `bd mol current` / `progress` | `bd playbook status`, `bd playbook runs` |
| gate | gate |

### Writing a playbook

```toml
# .bd/playbooks/ship.toml
description = "Cut and ship a release"
title = "Release {{version}}"         # title of the run issue

[vars.version]
description = "Semver to release"
required = true
pattern = '^\d+\.\d+\.\d+$'

[vars.platforms]
default = "linux,macos"

[[steps]]
id = "bump"
title = "Bump version to {{version}}"

[[steps]]
id = "build"
title = "Build {{item}}"
needs = ["bump"]
[steps.loop]                           # one step per platform, run in parallel
over = "{{platforms}}"

[[steps]]
id = "verify"                          # a group: an epic holding its children
needs = ["build"]                      # waits for every build-* iteration
[[steps.children]]
id = "smoke"
[[steps.children]]
id = "notes"
title = "Write release notes"

[[steps]]
id = "publish"
needs = ["verify"]
[steps.gate]                           # a person signs off first
type = "human"
timeout = "4h"                         # escalate if nobody has after 4h
```

```bash
bd playbook list                                  # playbooks on the search path
bd playbook show ship                             # the validated definition
bd playbook plan ship --var version=1.2.0         # what a run would create; writes nothing
bd playbook run ship --var version=1.2.0          # run t-12: t-12.bump, t-12.build-linux, ...
bd ready --run t-12                               # the run's claimable steps
bd playbook status t-12                           # every step, its state, and what it waits on
```

Steps take `title`, `description`, `design`, `acceptance_criteria`, `notes`,
`type`, `priority`, `labels`, `assignee`, `estimate` (minutes), `metadata`, and:

| key | meaning |
|---|---|
| `needs = ["a", "b"]` | starts after those steps close (`depends_on` works too). Steps without `needs` run in parallel. |
| `[[steps.children]]` | makes the step a group: an epic that closes with its children. Needing a group waits for all of it. |
| `condition = "{{env}} == prod && !{{dry_run}}"` | leaves the step out when false; steps that needed it inherit its `needs`, so the order holds |
| `[steps.loop]` | `count = 3`, `range = "1..{{n}}"` (inclusive), `items = [...]`, or `over = "{{csv}}"`; `var` names the loop variable (default `i` or `item`); `sequential = true` chains the iterations. Ids get a suffix (`build-linux`, `shard-2`). |
| `expand = "checks"`, `expand_vars = { suite = "{{env}}" }` | runs another playbook's steps inside this step, with their own variables and `needs` |
| `waits_for = "all-children"` | fan-in on work created at run time: waits for its spawner step (the first of `needs`, or `children-of(<step>)`) to close, then for every child it created (`any-children`: the first one to close; also `any-children-of(<step>)`) |
| `[steps.gate]` | a gate in front of the step ([Gates](#gates)) |

Variables (`[vars.NAME]`) take `description`, `required`, `default`, `enum`,
`pattern` (a regex), and `type` (`string`, `int`, `bool`). `{{name}}` works in
every text field, labels, metadata, gate fields, and loop sources; `\{{` is a
literal `{{`. `extends = ["base"]` merges another playbook first: its steps come
first, a step with the same id replaces the parent's, and this file's
variables and top-level fields win.

Parsing is strict, and everything is checked before anything is written:
unknown keys (with file and line), unknown step types, bad durations and
patterns, undeclared variables, unknown `--var` names, missing required
variables, and `needs` that dangle, form a cycle, or point at the step's own
group are all errors. Playbooks are found by name in the workspace's
`.bd/playbooks/`, then in `$BD_PLAYBOOK_PATH` (colon separated; semicolons on
Windows), then in `$XDG_CONFIG_HOME/bd/playbooks` (default
`~/.config/bd/playbooks`, or `%APPDATA%\bd\playbooks` on Windows); a file path
works too. In a remote workspace the checkout's playbooks come first, then the
server's, then your own ([Clients](#clients)). beads formula files load as they are
(`formula`, `depends_on`, `expand_vars`, gate `id`, `phase = "vapor"`); a
`type = "human"` step is rejected with a pointer to human gates.

Limits keep a run, and the work of planning it, bounded: a playbook holds at
most 2,000 steps, which nest at most 32 levels deep (counting expansions), and
a run at most 2,000 issues, 20,000 dependencies and 16 MiB of text. Variables
hold at most 256 KiB together, one field renders to at most 1 MiB, and a
condition is at most 1,024 bytes long. One command loads at most 20,000 steps
and variables (read from files or inherited through `extends`), and copies at
most 16 MiB of the descriptions, titles, labels and variable names playbooks
inherit (inherited steps and variable definitions are shared, not copied).
Planning a run takes at most 100,000 units of work: each loop iteration (even
one a condition leaves out), each expansion, and each dependency looked up
(one, plus one for each issue it stands for).

### Runs

`bd playbook run` creates the run issue (an epic) and one issue per step and
gate in a single transaction, with readable ids `<run>.<step>`. The run and
its groups close themselves when their last step closes (as `failed` if a
step failed), and reopen when a step is reopened. `--assignee` reserves every
step for one agent, `--after <id>` holds the run until other work closes, and
`--parent <id>` attaches it below an existing issue.

Work found while running can fan out: give a collector step
`needs = ["spawn"]` and `waits_for = "all-children"`, then create children
under the spawner step at run time (`bd create --parent t-12.spawn` or
`bd playbook run worker --parent t-12.spawn`). The spawner may close as soon
as it has spawned them; the collector waits for all of them.

```bash
bd playbook runs [--all]                     # runs and their progress
bd playbook compact t-12                     # a finished run: digest in its notes, steps deleted, run kept for good
bd playbook discard t-12                     # delete a run and every issue in it
bd playbook extract t-9 --save --name onboarding   # write a playbook from any epic
```

An ephemeral run (`ephemeral = true`, or `--ephemeral`; `--persistent`
overrides) works like any other, but `bd export` leaves it out, along with
edges pointing at it, unless you pass `--include-ephemeral`.
`bd purge [--older-than 7d]` deletes closed ephemeral work a whole run at a
time, with one `purged` event instead of a snapshot per issue.
`bd create --ephemeral` marks a single issue the same way.

### Gates

A gate is an issue of type `gate` in front of a step. The step waits on it
like on any blocker; the gate itself is never ready, cannot be claimed, and
is never `in_progress` (an issue in progress cannot become a gate either).
`bd gate check` applies each gate's verdict on its own: a gate it cannot
open or escalate is reported as an error, and the others still are.

| type | opens when | escalates when |
|---|---|---|
| `human` | someone runs `bd gate resolve <id>` (through `bd serve`: with a human access token) | `timeout` passes after arming |
| `timer` | `timeout` (`30m`, `24h`, `2d`) has passed since arming | never |
| `issue` | the `await_id` issue closes as done | it closes as failed, or `timeout` passes |
| `gh:pr` | pull request `await_id` merges | it is closed without merging, or `timeout` passes |
| `gh:run` | the GitHub Actions run succeeds | it fails or is cancelled, or `timeout` passes |

A gate **arms** when the step it guards could otherwise start (the step's
`needs` are closed), and timers and timeouts count from that moment, not from
when the run was created. For `gh:run`, `await_id` is a run id or a workflow
name or file; for a workflow, the first run started after arming is watched
and pinned (runs created up to a minute before arming count, to allow for
clock skew with GitHub). `branch` and `event` narrow the runs considered
(`branch = "v{{version}}"`, `event = "push"`); with `branch`, the gate follows
the branch or tag: when a newer run is for a different commit (a new push,
or a re-created tag), it watches that commit's first run instead, dropping
any escalation about the old one. GitHub gates use `gh` (`BD_GH` overrides
the binary) in the workspace's repository, or in `repo = "owner/name"`; a
`gh` call that takes longer than 60 seconds is killed and reported as an
error for that gate.

`gh` runs with the credentials of whoever checks the gate, so the `gate.repos`
config lists the repositories gates may name in `repo`: `OWNER/REPO`,
`HOST/OWNER/REPO`, `OWNER/*`, `HOST/OWNER/*`, or `*` for any. Entries match
the way gates write the repository: `OWNER/REPO` is on `gh`'s default host
(`GH_HOST`, or the host `gh` is logged in to), so it never matches
`HOST/OWNER/REPO`, nor the other way round. Unset, any repository works
locally, while through `bd serve` (whose `gh` has the server's credentials,
for requests and its own gate checks alike) only gates without `repo`,
which watch the workspace's own repository. A gate naming another repository
is refused when it is created or changed (by `bd gate create`, a playbook
run, an update or an import), and `bd gate check` escalates it instead of
probing it.

`bd gate check` (from cron or CI; `bd serve` runs it on its own, see
[Background jobs](#background-jobs-and-backups)) opens the gates whose
condition holds and escalates the ones that failed or ran past their
timeout. `--type gh` checks only GitHub gates, `--type local` only the
others. Escalation records
the reason on the gate, comments on it, and lists it in `bd prime`; it never
opens the gate. A person decides with `bd gate resolve`.

```bash
bd gate list                                      # waiting, armed, escalated
bd gate check [--dry-run] [--type gh|local]       # evaluate the armed gates
bd gate resolve t-12.gate-publish -r "approved"
bd gate create -t gh:pr --await-id 42 --blocks t-7   # a gate in front of existing work
bd gate create -t gh:run --await-id release.yml --branch v1.2.0 --event push --blocks t-9
```

## Remote server: one workspace, many machines

Several machines (laptops, CI runners, cloud agents) can share one
workspace through `bd serve`. The database stays on the server; clients send
whole commands, and each command runs there as it would locally, normally as
one `Store::write` transaction. Claims stay atomic, fencing tokens and lease
times come from one clock, and the event log stays gapless. The alternatives
cannot keep those guarantees. Putting `bd.db` on a network file system
breaks SQLite's WAL, which needs every process on one host. Replicating and
merging copies (beads' `bd dolt push/pull`) lets two disconnected machines
claim the same issue.

### Server

```bash
# One directory per workspace under a root: <root>/<name>/.bd/bd.db is served at /w/<name>
mkdir -p /srv/bd/proj && bd -C /srv/bd/proj init --prefix proj
# Or move an existing workspace: bd export -o proj.jsonl, then bd -C /srv/bd/proj import proj.jsonl

# Access tokens live in <root>/tokens.json (hashes only); each secret is printed once
bd serve token create alice-laptop --as alice --root /srv/bd
bd serve token create alice-desk --as alice --kind human --root /srv/bd   # a person's: approves human gates
bd serve token create ci --as ci --workspace proj --root /srv/bd
bd serve token create dashboard --as dash --role read --root /srv/bd
bd serve token create intern --as intern --max-claims 2 --root /srv/bd   # holds at most 2 issues at once
bd serve token list --root /srv/bd
bd serve token revoke ci --root /srv/bd          # takes effect at once, no restart
# Or let people get their own by signing in with GitHub: <root>/auth.toml (below)

bd serve --root /srv/bd --listen 0.0.0.0:7420 --tls-cert cert.pem --tls-key key.pem
```

Without a public CA, a self-signed certificate works if it is not a CA
certificate (rustls refuses a CA certificate as a server's own); clients then
trust it with `BD_CA_CERT=cert.pem`:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -keyout key.pem -out cert.pem -subj "/CN=bd.example.com" \
  -addext "subjectAltName=DNS:bd.example.com" -addext "basicConstraints=critical,CA:FALSE"
```

`bd serve` refuses plain HTTP on a non-loopback address, since tokens would
cross the network unencrypted. Either give it a certificate, or keep the
default `--listen 127.0.0.1:7420` behind a TLS-terminating proxy (Caddy,
nginx, a Cloudflare or Tailscale tunnel), which may also serve it under a path
prefix (`https://example.com/bd/w/proj`). `--insecure-http` allows plain HTTP
on an encrypted private network. `GET /healthz` answers `ok` for load
balancers. A request may carry up to `--max-body-mib` (default 64). Requests
in progress share a 256 MiB memory budget (more if one maximum-size request
needs it), and the server answers 503 when it is used up, which clients
retry. Answers stream: past 64 KiB, a command's output goes to the client
as the command writes it, through less than 1 MiB of buffers per request, so
a large `bd export` costs the server no more memory than a claim. `bd events`
reads and sends a long page a thousand events at a time, and lists (`list`,
`ready`, `blocked`, `show` of several issues, `history`, `comments`) write
their JSON element by element, so they hold their results but no copy of them
as JSON. At most 8
reads stream their answers at once (another is answered 503, which clients
retry), so slow readers cannot take the slots of short commands like claims.
A client that takes nothing for 60 s, or takes a streamed answer slower than
64 KiB/s on average after its first 30 s, loses the rest of it, and its
command ends. A write's answer is held until the write is done (see below).
At most four requests that bring their own playbooks plan at once (another
is answered 503, which clients retry). The server logs one
line per request on stderr; set `BD_LOG` to change that. Ctrl-C or SIGTERM
lets running commands finish first (up to 30 seconds). The server keeps
connections to each database open, so restart it after replacing or moving a
workspace's `bd.db`.

### Signing in with GitHub

Instead of creating each person's token, an admin can let people get their
own: `bd remote login --github` shows a one-time code to enter at GitHub, and
the server issues an access token if a rule of `<root>/auth.toml` lets the
GitHub account in, with that rule's role, kind and workspaces. An account no
rule lets in gets nothing.

1. Register a [GitHub OAuth app](https://github.com/settings/developers) (any
   homepage and callback URL will do) or a GitHub App, and tick **Enable
   Device Flow** in its settings. Only its client ID is needed, no secret. A
   GitHub App that checks memberships needs the **Members** organization
   permission (read), and must be installed in those organizations.
2. Write `<root>/auth.toml` on the server:

```toml
[github]
client_id = "Ov23li0123456789abcd"
token_ttl = "30d"                       # issued tokens expire (1h to 366d; default 30d)
# url = "https://ghe.example.com"       # GitHub Enterprise Server; its API defaults to <url>/api/v3 (api_url)
# deny = [12345]                        # GitHub user ids that may never sign in (`bd serve token accounts`)

# Rules, in order: the first that lets an account into the workspace decides its token.
[[github.allow]]
users = ["alice"]                       # GitHub logins, whatever their case
role = "admin"                          # read, write (default) or admin
kind = "human"                          # agent (default) or human

[[github.allow]]
teams = ["acme/bd-maintainers"]         # <organization>/<team slug>
kind = "human"

[[github.allow]]
orgs = ["acme"]
role = "read"
workspaces = ["proj"]                   # default: every workspace

# [[github.allow]]
# anyone = true                         # any GitHub account, e.g. for an open source project
# workspaces = ["oss"]
# role = "write"                        # read (default here) or write
# min_account_age = "30d"               # GitHub accounts younger than this are not let in by the rule
# max_claims = 3                        # its tokens' actors hold at most 3 issues at once
```

`bd serve` checks the file when it starts, and refuses to start with a
mistake in it (an unknown field, a rule that names nobody, an `http` URL to
another host, an `anyone` rule that is not the last or gives more than a rule
before it). After that, each sign-in reads it again, so changes need no
restart; a mistake made meanwhile fails sign-ins, with the reason in the
server log only.

- A rule lets an account in if `users` lists its login, or if it is an active
  member (not just invited) of one of its `orgs` or `teams`. Memberships are
  read with the account's own GitHub token, so the sign-in asks for the
  `read:org` scope when a rule names organizations or teams. An organization
  that restricts OAuth apps only answers once an owner approves the app
  (organization settings, Third-party access), and one with SAML single
  sign-on only for a GitHub token authorized for it (GitHub offers that on its
  authorization page); until then its members count as no members, and the
  server log says why (also when a later rule lets the account in).
- A rule that lets an account in, but not into the workspace the sign-in is
  for, leaves it to the rules after it; the token a later rule then issues
  covers that workspace only, never one where an earlier rule decides. An
  account no rule lets into that workspace is refused, and so is a workspace the server does not have:
  nothing is issued.
- A rule with `anyone = true` lets in every GitHub account the rules before
  it do not, so it names no users, orgs or teams and must be the last rule.
  Since anyone can create GitHub accounts, its tokens read by default, may
  write at most (never `admin`), and are always `agent` tokens, which cannot
  open human gates. A rule before it may not give a lower role in a workspace
  it shares with it, so members never get less than strangers. Each account
  still gets its own actor; to keep one out, add its user id to `deny` and
  revoke its tokens (below), since revoking alone lets it sign in again.
- Any rule may set `min_account_age` (like `token_ttl`, e.g. `"30d"`): an
  account GitHub created more recently, or whose creation date GitHub does
  not give, is not let in by that rule, and is left to the rules after it.
  If none lets it in, the sign-in is refused with the age it needs. This
  keeps out accounts made on the spot, not determined ones.
- Any rule may set `max_claims`, and `bd serve token create` takes
  `--max-claims N`: the token's actor and its sub-actors may then hold at
  most that many open issues, claimed (`in_progress`) or reserved (assigned),
  so that no one takes the whole ready queue. A command that would make them
  hold more (`claim`, `update --status in_progress` or `--assignee`,
  `create --assignee`, an import, a batch or a playbook run) fails with exit
  7 and changes nothing. Issues others assign to them count, but never stop
  them from working on those, and closing or releasing in the same command
  makes room. An abandoned claim counts until its lease runs out and is
  reclaimed. A rule before an `anyone` rule with `role = "write"` may not
  set fewer `max_claims` than it in a workspace they share. With `role = "write"`, tokens can still
  change issues in other ways, so the limit is a guard against greed, not
  malice.
- The token acts as the account's actor, or its sub-actors `<actor>/<agent>`:
  the account's login when it first signed in, which it keeps when its login
  changes. The token is named `github-<actor>-<random>` and expires after
  `token_ttl`; each sign-in gets a token of its own, so one account may sign
  in on several machines. Once it expires, commands fail with exit 7 naming
  the time, and `bd remote login --github` gets a new one.
- An actor belongs to one principal, and to an account for good: the server
  binds each account (by its GitHub user id) to its actor at its first
  sign-in, in `tokens.json`, and keeps the binding when the account's tokens
  expire or are revoked. A sign-in is refused while its login's actor belongs
  to another account (one that had the login before), or while a live token
  an admin created acts as it or one of its sub-actors. An account that
  `users` lets in by a login it took after another account gave it up is
  refused too, even if bound before under another login, while the login
  names another account's actor, that account's login at its latest
  sign-in, or a live admin-created token's actor: so it does not pass for
  the previous holder. Under another rule (`orgs`, `teams`, `anyone`), such
  an account signs in as its own actor. `bd serve token create` refuses
  an account's actor in the same way. `bd serve token accounts` lists the
  bindings, and `bd serve token revoke --github <login> --forget` releases
  one: it revokes the account's tokens, and the next account to sign in as
  that login binds the actor again.
- A change to `auth.toml` (`deny` included) applies to the next sign-ins:
  tokens already issued keep their permissions until they expire. To cut an
  account off at once,
  `bd serve token revoke --github alice --root /srv/bd` revokes every token it
  got by signing in, including those from before a rename (`alice` may be its
  latest login or its actor). `bd serve token list` shows each token's
  GitHub account and expiry; expired ones leave the list a week later.

The server runs GitHub's device flow itself, so the client needs to reach only
the bd server, and the GitHub token never leaves the server: it reads the
account and its memberships during the sign-in, and is never stored or
logged. A few things to keep in mind:

- `users` matches current logins: after a rename, update the rule (the
  account keeps its actor). A login given up by renaming can be registered by
  someone else, who is refused while the old account's actor is bound, but
  whom `users` lets in once that binding is released; memberships of
  organizations and teams follow the account itself.
- Tokens saved by `bd remote login` serve every process of that user on that
  machine, agents included, so a rule's `kind = "human"` lets those agents
  resolve human gates too. `agent` is the default.
- Whoever started a sign-in gets its token: enter only codes shown by one's
  own `bd remote login --github`.
- The sign-in endpoints, `POST /v2/auth/github/device` and
  `POST /v2/auth/github/token`, need no token. `POST /v2/auth/revoke`, sent
  with a token, revokes it if it came from sign-in: `bd remote logout` and a
  new sign-in on the same machine use it, so a token people no longer use
  stops working at once rather than when it expires. At most 8 sign-in requests run
  at once (others are answered 503, which clients retry), and GitHub limits
  how many codes an app may have entered per hour. GitHub gives a code's token
  only once, so the server keeps the answer that issued a bd token for 5
  minutes: a client whose answer was lost in transit gets it again by asking
  again.

### Background jobs and backups

`bd serve` keeps every workspace under `--root` up to date by itself, including
workspaces no client has used since it started (it looks for new ones every
30 seconds):

| job | default | flag | what it does |
|---|---|---|---|
| lease reclaim | every minute | `--reclaim-every` | `bd reclaim`: puts claimed issues back in the queue once their lease expired more than `lease.grace` ago (not in workspaces where `lease.auto_reclaim` is `false`) |
| gate checks | every minute | `--gate-check-every` | `bd gate check --type local`: opens timer and issue gates, escalates failures and timeouts |
| GitHub gate checks | every 5 minutes | `--gh-check-every` | `bd gate check --type gh` with the server's `gh` (its `BD_GH` and `gh auth`); each armed GitHub gate costs one or two API calls of that account per check |
| agent sets | every 30 seconds | `--agents-every` | reads each harness's set in `.bd/agents` and appends an `agents_changed` event when its revision changed, which `bd agents watch` clients wait for; a set that cannot be read gets no event and a warning in the log (once per error), and the other sets are still checked ([Agent skills](#serving-sets)) |
| backups | off | `--backup-dir DIR`, `--backup-every 1h`, `--backup-keep 24` | a snapshot of each workspace, below |
| request records | every hour | | deletes idempotency records older than a day |

`0` or `off` turns a job off. Jobs run the commands' own code as actor
`bd-serve`, so their events (`reclaimed`, `closed`, `gate_escalated`) read like
the commands'. That actor is the server's own: no access token may act as it
or its sub-actors (in any case), and a GitHub account whose actor would be
it cannot sign in. Each workspace's timers are jittered so workspaces do not fire
together, a job never overlaps itself, and only a few jobs run at once, on
threads of their own, so client requests keep their slots. Writes are short
transactions: `gh` runs outside any transaction, and a backup is a read
transaction. A failed job is logged and retried later, backing off up to 32
intervals; it never stops the server. On shutdown no job starts any more,
running `gh` calls are cancelled, and running jobs get 10 seconds to finish.
A job still running after that is abandoned safely: an unfinished transaction
rolls back, and the next backup removes an unfinished one.

With `--backup-dir /backups`, each workspace is copied to
`/backups/<name>/<name>-<UTC time>.db` (e.g. `proj-20261001T214244.014Z.db`)
every `--backup-every`, and all but the newest `--backup-keep` copies are
deleted (`0` keeps them all). A copy is taken with SQLite's `VACUUM INTO`,
which does not hold up writers, and is a compact, self-contained database
file. It is checked (`PRAGMA quick_check`) and flushed to disk under a
temporary name before it is renamed into place, so a file with the final name
is always complete. The copy just written is never deleted, even when older
copies are dated after it (the clock was wrong, then corrected); the server
logs a warning then. Copies hold everything in a workspace, so on Unix they
are readable by the user running `bd serve` only: files are created 0600, and
the directories it creates 0700 (an existing `--backup-dir` keeps its mode).
Keep the directory on another disk, or ship it elsewhere (rsync, restic,
object storage). To restore a workspace from a copy:

```bash
# Stop bd serve first: it keeps the database open, and could open a half-copied file.
cd /srv/bd/proj/.bd
mkdir -p broken && mv bd.db* broken/            # the database and its -wal and -shm files
cp /backups/proj/proj-20261001T214244.014Z.db bd.db
bd -C /srv/bd/proj doctor                        # then start bd serve again
```

The workspace is then as it was at the time of the copy: later changes are
gone, and the sequence numbers of their events are given out again, so
anything following events with a cursor (`bd events --since`) should
re-baseline from `bd export`. To bring a copy up as another workspace while
the server runs, copy it to `<root>/<new name>/.bd/bd.db.tmp`, then rename it
to `bd.db`: a rename is atomic, so the server never sees half a file.

For continuous replication instead of (or besides) periodic copies, run
[Litestream](https://litestream.io) next to `bd serve`, one database per
workspace: `litestream replicate /srv/bd/proj/.bd/bd.db s3://bucket/bd/proj`
(or a config file listing them). It suits bd's settings: WAL mode, a busy
timeout, and `synchronous=NORMAL`. To restore, stop `bd serve`, move the old
files aside as above, and run
`litestream restore -o /srv/bd/proj/.bd/bd.db s3://bucket/bd/proj`.

### Clients

The same `bd` binary is the client. Point a checkout at the server once and
commit the result, so every checkout and agent uses the shared workspace:

```bash
bd remote set https://bd.example.com/w/proj   # writes .bd/remote.toml (--ca-cert ca.pem for a private CA)
bd remote login --github                      # signs in with GitHub, where the server allows it; the server issues the token
bd remote login                               # or: prompts for a token from the server's admin, checks it, saves it
bd remote show                                # checks the URL, certificate, token and actor; shows what the token may do
bd ready                                      # every command now runs on the server
BD_ACTOR=alice/agent-2 bd claim --next        # sub-actors: one lease holder per agent
BD_SESSION=agent-3 bd claim --next            # outside an agent harness: acts as <token actor>/agent-3
```

```toml
# .bd/remote.toml
url = "https://bd.example.com/w/proj"
# ca_cert = "ca.pem"    # a private CA, relative to this file
```

A `.bd/remote.toml` takes precedence over a `.bd/bd.db` in the same
directory (`bd remote set` refuses to hide one unless given `--force`), `--db`
always means a local database, and `bd remote unset` removes the file.

The access token comes from `$BD_TOKEN`, else from the tokens saved by
`bd remote login`, never from the repository. CI and agents usually take
`BD_TOKEN` from a secret; people log in once per machine:

```bash
bd remote login --github               # sign in with GitHub; or: bd remote login --github https://bd.example.com/w/proj
bd remote login                        # the checkout's server; or: bd remote login https://bd.example.com/w/proj
printf %s "$TOKEN" | bd remote login   # a piped token is read from stdin, not from a prompt
bd remote login --workspace-only       # this workspace only, e.g. for a token limited to it
bd remote logout                       # forget it, and revoke it on the server if it came from GitHub sign-in
```

With `--github`, `login` gets the token from the server instead of reading
one: it shows a one-time code to enter at GitHub
(`https://github.com/login/device`), waits until it is entered (Ctrl-C
cancels; the code lasts 15 minutes), and saves the token the server issues,
reporting its actor, role, kind, workspaces and expiry. The server must have
GitHub sign-in on, and must let the account in
([Signing in with GitHub](#signing-in-with-github)).

Otherwise the token is never taken from the command line, so it stays out of shell
history and process lists, and it is never printed. `login` reads it from
stdin when stdin is piped, and otherwise prompts without echoing it (on
Windows, pipe it: `Read-Host -MaskInput Token | bd remote login` in
PowerShell 7). It runs `bd info` on the server with the token first and saves
nothing if that fails; `--no-verify` skips the check. Tokens are saved in
`$XDG_CONFIG_HOME/bd/credentials.toml` (default `~/.config/bd/credentials.toml`,
or `%APPDATA%\bd\credentials.toml` on Windows), one per server: the URL up to
`/w/<workspace>`, so `https://bd.example.com/w/proj` and
`https://bd.example.com/w/other` share the token saved for
`https://bd.example.com`, and a path prefix (`https://example.com/bd`) is part
of the server. A `--workspace-only` token takes precedence over its server's,
and `$BD_TOKEN` over both; `bd remote show` says which one is used. A saved
token is bound to the certificate authorities it was checked against: the
system's, or the CA file in use at login (`ca_cert` in `.bd/remote.toml`, or
`BD_CA_CERT`). It is not sent where another CA would be trusted, so a cloned
repository whose `remote.toml` names its own CA for your server cannot
redirect it; log in again from that checkout if you trust its CA. Setting
`BD_CA_CERT` yourself overrides the check.

On Unix, the file is replaced atomically by one with mode 0600, in a
directory created 0700, and bd refuses to use it if other users can read it. On Windows it is
protected by the per-user permissions of `%APPDATA%`. `bd remote logout`
forgets the token saved for a workspace URL and for its server (`--workspace-only`
keeps the server's), or for a server URL and all its workspaces. A token from
GitHub sign-in is revoked on its server too, and so is one that signing in
again replaces: within a few seconds, and only trusting the server as when
the token was saved. If that fails (the server cannot be reached, say), the
token is forgotten all the same and works on the server until it expires. A
token an admin created may serve elsewhere too, so it stays valid until it is
revoked on the server (`bd serve token revoke`).

| variable | meaning |
|---|---|
| `BD_TOKEN` | access token; takes precedence over tokens saved by `bd remote login` |
| `BD_REMOTE` / `--remote URL` | use this workspace URL instead of `.bd/remote.toml` |
| `BD_CA_CERT` | PEM file of the CA that signed the server certificate |
| `BD_ACTOR` | act as `<token actor>/<name>`; anything else is refused |
| `BD_SESSION` | act as `<token actor>/<name>` (added to the session's part in an agent session); agent sessions send theirs on their own ([Actors](#actors)) |
| `BD_REMOTE_RETRY_SECS` | how long to retry an unreachable server (default 30; 0 = once) |
| `BD_INSECURE_HTTP=1` | allow plain `http://` to a non-loopback host |

A token acts as one actor (`--as`; for a token from GitHub sign-in, the actor
its account is bound to), or as that actor's sub-actors `<actor>/<name>`, so
leases keep naming who holds them. Roles:

| role | may run |
|---|---|
| `read` | read-only commands; its database connection is query-only |
| `write` (default) | every command except the admin ones |
| `admin` | also `config set/unset`, `import`, `events prune`, `doctor`, and taking over other actors' claims (with `--take-over`) |

A token's kind, independent of its role, says who holds it: `agent` (the
default) or `human` (`--kind human`, or `kind = "human"` in an `auth.toml`
rule). Keep human tokens out of agents' environments, since they
can approve. A client sees its own token's name, role, kind, workspaces,
expiry and GitHub account in `bd remote show` (its `access` line) and in
`bd info` (`token` in its JSON), never the secret: that tells a refusal
(exit 7) by role or kind apart from one by actor or workspace. The server
enforces roles and kinds in the engine, so a `bd batch`
or a playbook gets the same answer as a single command:

- Taking over a live claim of another actor needs `--take-over`, as
  locally ([Claims](#claims-leases-and-recovery)), and an admin token:
  `release`, `update --assignee` or moving the issue out of `in_progress`,
  `close`, `delete`, `import`, discarding or compacting a run with such a
  claim, and `reclaim` with a `--grace` shorter than `lease.grace`. A claim
  held by the token's own actor or one of its sub-actors needs only
  `--take-over`. A token that may not take the claim over is refused (exit
  7) with or without `--take-over`, except a release or reassignment without
  it (exit 4, as before). Dead claims stay reclaimable by any write token
  (`bd reclaim`, `bd claim`), and unclaimed work may be reassigned as
  before. A run or group claimed by another actor stays open, still claimed,
  when its last step closes.
- Opening a human gate needs a human token, whatever the role: `gate
  resolve`, `close`, pinning it, changing its type or condition, or deleting
  it. So does getting the work it holds back past it early: removing that
  edge, `close --force`, pinning or deleting the work (or a group, run or
  epic around it), or moving the work or the gate out of its parent.
  `import` is checked too. Other gates may be resolved by hand with any
  write token.
- `metadata.playbook`, which makes runs and groups close themselves, belongs
  to playbook runs: only an admin token may change it on an existing issue
  (closing such a run or group still checks claims and human gates).
- GitHub gates may only name repositories in the workspace's `gate.repos`,
  which only admins set ([Gates](#gates)); unset, only the workspace's own.

`bd` on the server's host, which opens `bd.db` directly, is not limited by
tokens (`gate.repos`, once set, applies there too).

Every invocation carries a random request id. The client retries connection
failures, timeouts, busy answers and a proxy's gateway errors (such as
Cloudflare's 524 for a command running over 100 s) with the same id; once a
write may have run, it gets the whole retry time again to ask for its stored
answer. The server records the id in the same transaction as the write, and
stores the write's answer (up to 1 MiB of output) before sending it, to
replay it to a retry, so a write whose answer was lost in transit is applied
once. A write's answer is printed once it has arrived whole; a read prints a
long output as it arrives, so a read whose connection breaks after that
fails (exit 8, output incomplete) instead of being retried. Exit codes are
the same as locally, plus 7 (access denied), 8 (server unreachable: the
command did not take effect) and 9 (a write that may have reached the server
lost its answer: more than 1 MiB of output, or no answer before the retries
gave up; it may have taken effect, so check before running it again).

What runs where:

- Input and output files stay on the client: `import FILE` and `batch -f FILE`
  send the file, `--stdin` and `-` send stdin, and `export -o` and
  `playbook extract -o` write the file locally, as `FILE.tmp` renamed into
  place once the command succeeds (so a failed export leaves `FILE` alone).
- A playbook name is looked up in the checkout's `.bd/playbooks` first (next
  to `remote.toml`, or in the nearest `.bd` directory with `--remote` or
  `BD_REMOTE`), then on the server's playbook path (the workspace's
  `.bd/playbooks`, `<root>/<name>/.bd/playbooks`, then the server's
  `$BD_PLAYBOOK_PATH` and user config directory), and only then in your own
  `$BD_PLAYBOOK_PATH` and user config directory. File paths are relative to
  the client's current directory. `playbook show`, `plan` and `run` of a
  playbook found on the client send it along with every file it extends or
  expands, resolved on the client as locally (at most 256 files of 512 KiB,
  8 MiB in all), and the server checks and compiles it as a local run would,
  without reading any other file for it. `playbook list` shows them all in that
  order, marking the server's, and `show` marks a playbook from the server.
  `playbook extract --save` writes into the checkout, with a note when the
  playbook is too large to send. GitHub gates are checked by the server's
  `gh`, for the repositories `gate.repos` allows, also on the server's own
  schedule ([Background jobs](#background-jobs-and-backups)).
- `events --follow` and `events --wait` wait on the server for new events
  ([Followers](#followers)). `init`, `bench` and `serve` only run on the
  machine that holds the database.
- `bd prime`, which session hooks run, gives up within seconds when the
  server is unreachable or there is no access token, and prints a notice instead
  of failing the hook. With `--json` it fails like any other command.
- `bd agents status`, `pull`, `approve` and `watch` run on the client and
  write into the checkout, reading the server's sets with the client's
  token; `bd agents manifest` runs on the server
  ([Agent skills and MCP definitions](#agent-skills-and-mcp-definitions)).

Claims stay atomic however clients reach the database: remote clients, and
local `bd` processes on the server's host, all take the same SQLite write
lock. `bd bench --mode remote` checks this end to end
([Benchmarks](#benchmarks)).

The protocol (version 2) is one endpoint, so other clients can call it
directly: `POST /w/<name>/v2/exec` with `Authorization: Bearer <token>` and
`{"argv": ["claim", "--next", "--json"], "request_id": "..."}`. The answer
(`application/x-ndjson`) has one JSON frame per line, in the order the command
wrote them: `{"stdout": "..."}` for output, `{"file": {"path", "data"}}` for
part of an output file, and last `{"exit": {"exit_code", "stderr", "replayed"}}`.
Blank lines are keep-alives, and an answer without the exit frame was cut
off. An event listing (`events`) also sends `{"cursor": N}` before its exit
frame: the `--since` value that continues after it, past the events its
filters skipped. `["events", "--since", "N", "--wait", "25s", "--json"]` is a
long poll: answered as soon as an event matching its filters follows `N`, or
with no events (and the cursor) when the wait ends. Failures before the
command runs return a non-200 status with the `--json` error shape. Every
answer carries a `bd-protocol: 2` header, which tells bd serve's own answers
(a 503 before the command ran, say) apart from a proxy's.

### Followers

`bd events --follow` and `bd events --wait` on a remote workspace are long
polls. Each request asks for the events after the client's cursor, and when
none matches yet, the server holds the request until one is committed, then
answers at once: a follower sees an event within milliseconds of its commit,
and an idle follower costs one request per `--max-wait` (25 s by default)
instead of one per poll interval. Each answer says where the next request
continues, so a follower prints every event once and in order, even when an
answer is lost and asked for again: a request that waited is retried for the
whole retry time (`BD_REMOTE_RETRY_SECS`, default 30 s) from its failure,
however long it had waited, and a retry that the server held and then
refused (busy, or shutting down) gets the whole retry time again, up to 5
times in a row, so a follower rides out server restarts. A follower that
falls so far behind that retention deleted events it had not read says so on
stderr and continues from the newest event. Under load, a follower asks at
most once per `--interval-ms` (default 500), so events arrive in batches; a
`--wait` longer than the server's `--max-wait` takes several requests.

A waiting request holds no command slot, database connection, transaction or
memory budget on the server, only its connection and its small request (one
larger than 16 KiB, say with stdin, is answered at once). The server learns of new
events from the commands it runs (clients' writes and its own background
jobs), and, while anyone waits on a workspace, by reading its events head
every 500 ms, for writes by other processes on its host (`bd` opening
`bd.db` directly). One reader per workspace checks for all the requests
waiting on it, and after waking them it waits 100 ms before it checks again,
so a burst of commits wakes them once.

| flag | default | meaning |
|---|---|---|
| `--max-followers N` | 256 | requests waiting at once (0 to 256, half the server's 512 connections); others are answered at once, and their clients poll every `--interval-ms` |
| `--max-wait DURATION` | 25s | the longest a request waits before answering that nothing came (1s to 5m) |

Keep `--max-wait` below the idle timeout of every proxy between clients and
the server: Cloudflare ends requests idle for 100 s, many load balancers
after 60 s, and Google Cloud's after 30 s by default. On shutdown, waiting
requests are answered at once (503, which clients retry), so the server does
not wait for them.

## Agent skills and MCP definitions

A workspace can serve agent skills and MCP server definitions to the agent
harnesses of its checkouts: Claude Code (`claude`), Codex (`codex`) and
Copilot CLI (`copilot`). Each harness has a set of its own, served as it is
to that harness only: nothing is translated or shared between harnesses,
and a harness without a set gets nothing (a Copilot CLI checkout gets
nothing from a Claude-only set). The server provides definitions only: MCP
servers run on the client and authenticate there (`${VAR}` references in
Claude Code and Copilot CLI definitions, `env_vars` and
`bearer_token_env_var` in Codex, OAuth in the harness). The server holds no
secrets, and bd never handles MCP credentials. Mostly a feature of
[remote workspaces](#remote-server-one-workspace-many-machines), it works the
same in a local workspace, whose checkout pulls from its own `.bd/agents`.

### Serving sets

A set lives next to the database, as playbooks do: `.bd/agents/<harness>/`,
so `<root>/<name>/.bd/agents/<harness>/` on a server. Clients see an edit at
their next request, with no restart.

| harness | in `.bd/agents/<harness>/` | in a client checkout |
|---|---|---|
| `claude` | `skills/<name>/**`, `mcp.json` (`{"mcpServers": {...}}`) | `.claude/skills/<name>/`, `.mcp.json` |
| `codex` | `skills/<name>/**`, `mcp.toml` (`[mcp_servers.<name>]` tables) | `.agents/skills/<name>/`, `.codex/config.toml` |
| `copilot` | `skills/<name>/**`, `mcp.json` (`{"mcpServers": {...}}`) | `.github/skills/<name>/`, `.github/mcp.json` |

```bash
/srv/bd/proj/.bd/agents/claude/skills/deploy/SKILL.md
/srv/bd/proj/.bd/agents/claude/skills/deploy/scripts/run.sh    # executable: clients get it executable (Unix)
/srv/bd/proj/.bd/agents/claude/mcp.json
/srv/bd/proj/.bd/agents/codex/skills/deploy/SKILL.md
/srv/bd/proj/.bd/agents/codex/mcp.toml
```

```json
{"mcpServers": {
  "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
             "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"}},
  "docs": {"type": "http", "url": "https://docs.example.com/mcp",
           "headers": {"Authorization": "Bearer ${DOCS_TOKEN}"}}
}}
```

```toml
# .bd/agents/codex/mcp.toml
[mcp_servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
env_vars = ["GITHUB_PERSONAL_ACCESS_TOKEN"]

[mcp_servers.docs]
url = "https://docs.example.com/mcp"
bearer_token_env_var = "DOCS_TOKEN"
```

Sets are read strictly. A set that breaks a rule is refused whole, with an
error naming the file, by `bd agents manifest`, by the server when a client
asks for it, and by clients, which check every answer before writing
anything:

- An MCP file holds only its entries key, `mcpServers` or `mcp_servers`:
  settings, hooks, permissions and any other key are refused. Server names
  are letters, digits, `-` and `_`, at most 64 bytes. Each entry has a
  `command` (a server the client starts) or a `url` (a remote server), as
  non-empty strings; `args` is an array of strings and `env` maps names to
  strings. Other fields are the harness's own and pass as they are, but
  top-level field names are 1 to 64 characters of `[A-Za-z0-9_.-]`,
  starting with a letter or `_` (nested keys are free).
- Each skill is a directory under `skills/` holding a `SKILL.md`, named with
  lowercase letters, digits, `-`, `_` and `.`, starting with a letter or
  digit, not ending with `.`, at most 64 bytes, and not a Windows device
  name (`con`, `nul`, `com1`, ...).
- File paths within a skill are portable: ASCII only; no `\ : < > " | ? *`
  or control characters; no component ending with a space or `.`, or
  naming a Windows device; at most 8 levels and 200 bytes; and no two paths
  differing only in case.
- Hidden entries (names starting with `.`, such as `.DS_Store` or `.git`)
  are ignored, and so is anything in `.bd/agents` besides the harness
  directories. A symlink may lead anywhere inside `.bd/agents` (to share a
  skill between sets, say), never outside it.
- Files are UTF-8 text without NUL characters.
- Limits per set: 256 files (skill files and the MCP file), 256 directories
  below the skill directories, 512 KiB per file, 8 MiB in all, and 64 MCP
  servers.

`bd agents manifest` checks the sets and lists what each harness gets
(`--harness` for some, `--json` for the hashes):

```
$ bd -C /srv/bd/proj agents manifest
claude: revision de260d525b5e (clients place it in .claude/skills/ and .mcp.json)
  skill deploy (2 files)
  MCP server docs
  MCP server github
codex: revision 48596ad57c35 (clients place it in .agents/skills/ and .codex/config.toml)
  skill deploy (1 file)
  MCP server docs
  MCP server github
copilot: nothing served
```

A manifest holds a SHA-256 per skill file (and, for a text with CRLF line
endings, `lf_sha256`: its hash with them as LF) and per MCP entry (over its
canonical JSON, so reformatting an MCP file changes no hash), and a set's
revision is the hash of its manifest. The server's agents job
(`--agents-every`, default 30 s, `0` or `off` to turn it off;
[Background jobs](#background-jobs-and-backups)) reads each workspace's sets
and appends an `agents_changed` event (actor `bd-serve`, no issue, data
`{harness, revision, previous}`) for each harness whose revision changed,
which `bd agents watch` clients wait for. The revisions last recorded are
kept in the database, so a change made while the server was down still gets
its event after a restart; a harness never served counts as an empty set,
so a workspace that serves nothing gets no events. A set that cannot be
read gets no event and one log warning per distinct error (`agent set
cannot be read; its clients keep what they have`, with the workspace,
harness and error), then `agent set readable again`; the job still checks
the other sets, and clients asking for the broken set get its error.

### Trust

Skills are code, not just text. A Claude Code project skill can run
`` !`<command>` `` lines and ```` ```! ```` blocks on the user's machine
before the model reads it, register `hooks` for the session from its
frontmatter, and pre-approve tools with `allowed-tools` (such as
`Bash(...)`); Claude Code invokes a skill by itself when its description
matches, and refuses `!` commands only in skills synced from claude.ai, not
in project skills such as those bd writes. Copilot CLI skills honour
`allowed-tools` too (such as `shell`). Scripts bundled with a skill, which
bd makes executable, are commands agents are told to run.

bd applies skills without review: `bd agents pull`, the session-start hook
at every session, and `bd agents watch` at every change. Only MCP
definitions wait for `bd agents approve`. Editing `.bd/agents/*/skills` on
the server, or taking over the server, is therefore running code on every
client that syncs. So:

- Guard `.bd/agents` on the server like a code deployment: only admins
  edit it, and changes are reviewed as code is.
- Enable the session-start hook and `bd agents watch` only for a server
  trusted like the repository's own code.
- To look before anything applies, leave the hook and watch out and pull
  by hand. `bd agents status` lists what a pull would change (skills added,
  updated or removed, by name and, with `--json`, by file path), not their
  content; `bd agents manifest` gives hashes only. The server's text can be
  read with the hidden `bd agents fetch --harness <h>` (a read token is
  enough), which prints the whole set as one JSON object with strings
  escaped (`jq '.skills'`); `jq -r` prints the text as the server sent it,
  terminal control characters included. When the skill directories are
  committed, `git diff` after `bd agents pull` shows what the pull wrote,
  before an agent session uses it.

A later change may gate skills that can run commands behind approval as
well.

### Pulling into a checkout

```bash
bd agents status --harness claude       # what a pull would do; changes nothing
bd agents pull --harness claude,codex   # skills written; MCP removals applied; new or changed MCP definitions wait
bd agents approve                       # in a terminal: review and approve waiting MCP definitions
bd agents watch                         # keep pulling as the server's sets change, until Ctrl-C
```

These run on the client, in a checkout: the directory holding the `.bd`
that configures the remote workspace (next to `remote.toml`, else the
nearest `.bd`), or the local workspace's. In a remote workspace they read
the server's sets with any token (a read token is enough); `bd serve`
refuses them. A command picks its harnesses from `--harness` (repeatable or
comma-separated), else the running agent session's
(`$CLAUDE_CODE_SESSION_ID`, `$COPILOT_AGENT_SESSION_ID`, `$CODEX_THREAD_ID`;
a nested session gets each), else those `.bd/agents.lock` records
(`approve` skips the session step). With none of these it fails (exit 2).
Each harness's set goes to its own places only: a copilot pull leaves the
claude and codex ones alone. When nothing changed, a command makes one
request (the manifests); a set is fetched whole only when files are to be
written or MCP changes shown.

```
$ bd agents status --harness claude,copilot
claude: local edits kept: .claude/skills/deploy/SKILL.md
claude: MCP github new: not applied; review and approve with `bd agents approve` in a terminal
claude: unset environment variables the MCP servers read: DOCS_TOKEN, GITHUB_TOKEN
copilot: conflict: .github/skills/triage/SKILL.md: differs from the server's and was not written by bd; left as it is (move it away to get the server's)
```

`.bd/agents.lock` records, per harness, the server revision last pulled,
each skill file bd wrote or adopted (`sha256`, `lf_sha256` for a text with
CRLF line endings, `executable`, and `executable_not_kept` where the file
system did not keep that bit), and
each MCP entry bd wrote or adopted, with the definition approved. It is
local state: the first lock written adds `agents.lock*` to `.bd/.gitignore`
(covering `agents.lock.mutex`, the checkout's OS-locked mutex, and temp
files), and `bd init` writes that line too. Changes to a checkout are serialized by the
mutex, which the system releases when its process ends: a session hook and
a watch can run at once, and one that waits past `--busy-timeout-ms` fails
with exit 5. The rules a pull follows:

- **Ownership.** A file or MCP entry bd did not record that already matches
  the server's is adopted: recorded, not written (a fresh clone with the
  skills committed). One that differs is a conflict, reported and left
  alone; moving it away lets the next pull write the server's.
- **Line endings.** A skill file that differs from the server's, or from
  the one bd wrote, only in line endings (the same text once each CRLF in
  either is read as LF, as when git's `core.autocrlf` checks text files out
  with CRLF line endings on Windows) counts as the same file: adopted,
  never an edit, and kept with its line endings, also when the server
  changes only those.
- **Local edits.** A file or entry bd wrote that was edited here is kept and
  reported as edited, or as a conflict when the server changed or removed it
  too. `pull --force` replaces or removes such edits; it never touches what
  bd did not write, and never writes a new or changed MCP definition.
- **Restores and removals.** Files bd wrote that were deleted here are
  written again, and so is an approved MCP definition deleted here and
  unchanged on the server. Files and MCP entries the server removed are
  deleted (unless edited here), with the directories that leaves empty
  below the skills directory, before anything is written: a file renamed on
  the server only in case is written under its new name on file systems
  that ignore case, and a file may become a directory, or the other way
  round.
- **Symlinks.** A pull never follows a symlink at or below a skill's
  directory (the skills directory and its parents may be symlinks), and
  never writes an MCP file that is a symlink: those are conflicts.
- **Executable bits** (Unix): files the server marks executable get their
  executable bits, also when adopted or kept with the server's text; a
  server change of the bit alone applies even to an edited file. An
  executable bit the server never set is left alone (some file systems show
  every file executable). Where the file system does not keep the bit
  (`chmod` has no effect or is refused, and files read back without it:
  vfat, exfat, or SMB mounts with an `fmask` that clears it), the pull says
  so once (`not executable here`; `skills.not_executable` in JSON), records
  it in the lock (`executable_not_kept`), and later pulls and `status` count
  the file as up to date. bd sets the bit again when the server's set
  changes (reporting it only if it is kept then), or with `pull --force`,
  and drops the mark once the file has it (set by hand, say).
- **MCP definitions.** New and changed definitions are never written by a
  pull, a hook or a watch: they wait for `bd agents approve`. Removals of
  unedited entries bd wrote apply at once, as they add nothing that runs.
- **Session-start hook.** `pull` also gives the harness the session-start
  hook ([Session-start hooks](#session-start-hooks)) when none is
  configured, so that the first agent session in a fresh checkout runs
  `bd prime` and keeps the checkout's assets up to date: Claude Code's in
  `.claude/settings.local.json`, Codex's in `.codex/hooks.json`, Copilot
  CLI's in `.github/hooks/bd.json`. The hook is bd's own, never the
  server's (a server's sets hold no hooks). One already configured for the
  harness, in the checkout or for the user (`~/.claude/settings.json`,
  `$CODEX_HOME/hooks.json`, `$COPILOT_HOME/hooks/*.json` or
  `settings.json`, an installed Copilot CLI plugin's), is left as it is,
  and nothing is written. bd's entries are appended to what the file
  holds, which is rewritten pretty-printed with sorted keys; a file that is
  not a JSON object, keeps its hooks elsewhere than `hooks.<event>`, or is
  a symlink is left alone and reported (`session-start hook not added`).
  `status` reports `session-start hook to add`; `--no-hook` leaves the hook
  out of either command. The files are local: keep them out of commits
  where teammates or Copilot cloud agent run sessions without bd
  (Copilot cloud agent runs `.github/hooks/*.json` too).

MCP files keep everything bd did not write. `.mcp.json` and
`.github/mcp.json` keep every other key and server, and are written
pretty-printed with sorted keys when bd changes an entry. `.codex/config.toml`
is edited in place (with `toml_edit`): bd inserts, replaces or removes
`[mcp_servers.<name>]` tables only, and keeps Codex's other settings,
comments and formatting byte for byte. bd does not write a file it cannot
read in its format, a JSON file holding servers outside `mcpServers`
(Copilot's bare form), a `.codex/config.toml` whose `mcp_servers` is an
inline table (`mcp_servers = {...}`), or a symlink: changes to such a file
are reported as conflicts, and the file is left as it is.

Every report lists the environment variables that MCP definitions (in
effect or waiting) read and that are unset or empty here, by name only:
`${VAR}` and `$VAR` in `command`, `args`, `env`, `url` and `headers` for
Claude Code and Copilot CLI (not `${VAR:-default}`); `env_vars` (but not
`source = "remote"` ones), `bearer_token_env_var` and the values of
`env_http_headers` for Codex.

With `--json`, `status` and `pull` print `{"applied", "checkout",
"harnesses": {"<harness>": {"server_revision", "applied_revision", "skills",
"mcp", "unset_env", "hook"}}}`, where `skills` and `mcp` list what changed, was
adopted, edited, left or is in conflict, and `mcp.pending` the definitions
waiting (`name`, `change`: `new` or `changed`, the top-level `fields` that
changed, and whether the entry was `edited` here), and `hook` the
session-start hook's `file` and `state` (`present`, `added`, or `conflict`
with a `reason`; left out with `--no-hook`); `approve` prints, per
harness, the entries `approved`, `declined`, `skipped` (with a reason) and
in `conflicts`. The module docs of `crates/bd-cli/src/agents.rs` have the
full shapes. Exit codes: 0 when the command did its work (pending MCP
changes, conflicts, local edits, and declined or skipped approvals are
findings, not failures); 2 no harness, no checkout, an unusable
`.bd/agents.lock`, or an invalid set; for `approve` also a refusal (below)
or a name neither served nor recorded; 3 no workspace; 5 the checkout's
mutex stayed busy; 7 access denied; 8 server unreachable, or an answer that
failed its checks (nothing was written).

`bd agents watch [--harness ...] [--interval 10s] [--json]` pulls once,
then again each time a watched set changes, printing each pull's report
(one JSON object per line with `--json`). In a remote workspace it waits
for `agents_changed` events with long polls ([Followers](#followers)), and
after each wait that ends with no event it reads the manifests once, so it
also catches changes the job missed and servers running with
`--agents-every 0`; `--interval` is the least time between two requests. A
local workspace's `.bd/agents` is read every `--interval`. A watch never
approves anything. Failures (the server unreachable, the checkout busy, an
unusable set or lock) print `bd agents watch: <error> (trying again)` on
stderr once, then `bd agents watch: working again`, and are retried (after
pauses growing to 30 s in a remote workspace); only a refused token ends it
(exit 7). Ctrl-C exits 0 once a pull under way is done; a second one exits
130 at once. For long agent sessions with a trusted server
([Trust](#trust)), run it in a separate terminal: the session-start hook
pulls only at session start.

### Approving MCP definitions

A stdio MCP definition is a command that every client runs, with the
user's privileges, so a pull never writes a new or changed one: it waits
until a person approves it. Skills, which can run commands too, are not
gated this way ([Trust](#trust)). The harnesses' own checks do not cover this:
Claude Code approves `.mcp.json` servers by name (a changed command under
an approved name passes) and skips the prompt in `-p` and SDK runs, and
Copilot CLI only checks folder trust.

`bd agents approve [NAME...] [--harness ...] [--full]` shows each waiting
definition on stderr and asks `Approve <name>? [y/N]` on the terminal:

```
claude: MCP server github: new, to be added to .mcp.json
  runs on this machine: npx -y @modelcontextprotocol/server-github
  definition:
    "github": {
      "args": [
        "-y",
        "@modelcontextprotocol/server-github"
      ],
      "command": "npx",
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"
      }
    }
  reads environment variables: GITHUB_TOKEN (unset here)
  runs on this machine: npx -y @modelcontextprotocol/server-github
Approve github? [y/N] y

claude: approved github: written to .mcp.json
claude: to load them, restart the Claude Code session; Claude Code may also ask to approve new .mcp.json servers itself
```

Each entry shows what it runs (`runs on this machine: <command args>`) or
connects to (`connects to: <url>`), repeated right before its prompt; a new
definition in full, in its harness's native form; a changed one as the old
and new value of each top-level field that changed, and the fields
unchanged; the environment variables it reads, marked `(unset here)`; and
a warning when approving replaces a local edit. Nothing the server sent is
printed as sent: definitions are rendered from their JSON form, each string
and key one escaped literal on one line (line breaks, control characters
and bidirectional or invisible formatting characters escaped), so no value
can fake a line, move the cursor or reorder what is shown. Strings over 200
characters and arrays or tables over 100 items are cut short with a note
(`--full` shows them whole); the run/connect summary stays short (400
characters).

Once every answer is in, approve takes the checkout's mutex and writes
exactly the definitions shown, recording them in `.bd/agents.lock`. It
skips an entry whose place in the MCP file or the lock changed since it was
shown, and never replaces an entry bd did not write (a conflict): remove or
rename the local entry, then pull and approve again. A definition that
changes again on the server before approval is shown in its newest version;
an approved one is not asked about again until it changes.

`approve` refuses to run inside an agent session (`$CLAUDE_CODE_SESSION_ID`,
`$COPILOT_AGENT_SESSION_ID`, `$CODEX_THREAD_ID` or `$CODEX_SESSION_ID` set)
and, when there is something to ask about, without a terminal on stdin
(exit 2), with no flag or variable to get past either. That keeps agents
from approving by accident; it is not a security boundary, since an agent
with a shell can edit the MCP files directly. Agents are told to ask the
user to run `bd agents approve` in a separate terminal.

### Session-start hooks

`bd hook session-start --harness <claude|codex|copilot>` pulls the
harness's set at the start of each agent session, with pull semantics
(skills added, updated, removed or restored; MCP removals and restores of
approved definitions applied; new and changed MCP definitions only
reported), and tells the session what changed, in the format the harness
reads: plain text for Claude Code and Codex, one `{"additionalContext":
"..."}` JSON object for Copilot CLI. Without `--harness` it takes the
session's harness from its session variable, else the lock's harnesses
with plain-text output; Codex and Copilot CLI set no session variable for
hook processes, so their hooks pass `--harness`. It works in the session's
directory, the `cwd` of the hook's JSON input on stdin (`-C` wins), as
Copilot CLI runs a plugin's hooks in the plugin's own directory. `bd prime
--hook <harness>` does the same for the prime text: Copilot CLI gets it as
one JSON object (it drops plain text), Claude Code and Codex as plain text.
The skills it applies run in the session that starts, unreviewed: enable it
only for a server trusted like the repository's own code ([Trust](#trust)).

It says nothing when nothing changed, outside a checkout, and with no
harness known; a session start with nothing served writes nothing (no lock,
no mutex file). Otherwise each line starts with `bd:`:

```
bd: agent skills updated from the bd server: deploy (updated), triage (added).
bd: if these skills are not available yet, ask the user to run `/reload-skills`.
bd: MCP server definitions applied to .mcp.json: old (removed). Ask the user to restart Claude Code to apply the change.
bd: MCP server definitions changed on the bd server and not applied: github (changed: args), linear (new). Ask the user to review them and run `bd agents approve` in a separate terminal.
bd: 1 agent asset conflict (files or MCP entries in the way, left as they are): `bd agents status` lists it.
bd: environment variables the MCP servers read are unset: LINEAR_KEY.
```

Pending MCP changes and conflicts are repeated at every session start
until resolved. A problem (the server unreachable or stalling, the token
missing or refused, the checkout's mutex busy, an invalid set or lock) is
one line, `bd: agent skills and MCP definitions not checked: <reason>`, and
the hook still exits 0. The whole hook takes at most about 5 s from the
start of its process: reading its input takes 2 s at most (when stdin is
left open); of what is left, a fifth (0.2 to 1 s) goes to waiting for the
checkout's mutex and the rest (at least 1 s) to the server, all its
requests and retries against one deadline, even when the server accepts the
connection and never answers. Files are written only once the server's
answers are in and checked, so running out of time leaves nothing half
written.

`bd remote set` (with a token available) and `bd remote login` (for the
checkout's own workspace, unless `--no-verify`) add a hint
when the workspace serves sets, so the skill directories exist before the
first session (nothing is pulled, as no harness is known yet; nothing is
said when nothing is served or no answer came within 3 s):

```
  agent assets are served for claude, codex, copilot: `bd agents pull --harness <claude|codex|copilot>` (for each harness used here) places them in this checkout before the first agent session
```

`bd agents pull --harness <h>` writes the harness's entries below where
none is configured ([Pulling into a checkout](#pulling-into-a-checkout)),
so a fresh checkout needs only `bd remote set` (or login) and one pull.

**Claude Code** (`.claude/settings.json`; the `SessionStart` entry of this
repository's): `bd hook session-start` also gives the session its own actor
([Actors](#actors)). `--harness claude` acts only when Claude Code runs it
(`$CLAUDE_ENV_FILE` or `$CLAUDE_CODE_SESSION_ID` set), and prints and
writes nothing otherwise, as Copilot CLI also runs a repository's
`.claude/settings.json` hooks; a Copilot CLI session started from a Claude
Code shell inherits `$CLAUDE_CODE_SESSION_ID` and is taken for Claude Code.

```json
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "bd hook session-start --harness claude"
          },
          {
            "type": "command",
            "command": "bd prime"
          }
        ]
      }
    ]
  }
}
```

**Copilot CLI**: this repository's plugin, `.copilot-plugin/plugin.json`,
runs `bd hook session-start --harness copilot`, then `bd prime --hook
copilot`, on `SessionStart`. A repository can use a hook file instead,
`.github/hooks/bd.json` (any `.github/hooks/*.json`):

```json
{"version": 1, "hooks": {"sessionStart": [
  {"type": "command", "command": "bd hook session-start --harness copilot"},
  {"type": "command", "command": "bd prime --hook copilot"}
]}}
```

Copilot CLI also runs a repository's `.claude/settings.json` hooks, where
`--harness claude` stays inert and plain `bd prime`'s output is dropped.
Leave out `matcher` to match every occurrence of an event, rather than
writing `"matcher": ""`: Copilot CLI 1.0.91 refuses a `.claude/settings.json`
with an empty `matcher`, warning at each session start (`matcher cannot be
empty`) and skipping the whole file, while Claude Code treats both alike.

**Codex** (`.codex/hooks.json` in the repository):

```json
{"hooks": {"SessionStart": [{"matcher": "startup|resume|clear|compact", "hooks": [
  {"type": "command", "command": "bd hook session-start --harness codex", "timeout": 30},
  {"type": "command", "command": "bd prime", "timeout": 30}
]}]}}
```

Codex loads project hooks only when the project's `.codex/` layer is
trusted, and each hook must be reviewed and trusted in `/hooks` (per hook
hash: an edited hook needs trust again; `codex exec
--dangerously-bypass-hook-trust` skips that for one run). Codex shows the
model about 2,500 tokens of hook output by default and spills the rest to a
file: a long `bd prime` (many memories) may need `"additionalContextLimit"`
raised on its handler.

### Reloading

Skills written at session start were not listed on the session's first
turn by any of the three harnesses, and MCP changes need a reload:

| harness | skills | MCP definitions |
|---|---|---|
| Claude Code | live, but `.claude/skills` is watched only if it existed at session start: `/reload-skills` | restart Claude Code (it may also ask to approve new `.mcp.json` servers) |
| Copilot CLI | `/skills reload` | `/mcp reload` |
| Codex | automatic | restart Codex (it reads a project's `.codex/config.toml` only in trusted projects) |

The hook's lines and `approve`'s output name the step to take.

### Caveats

- Copilot CLI also reads `.claude/skills`, `.agents/skills` and `.mcp.json`,
  and `.mcp.json` wins over `.github/mcp.json` when a server name is in
  both. Pull only the sets of the harnesses used in a checkout, or a
  Copilot CLI session there also gets the Claude and Codex sets.
- On mounts that keep no executable bits (vfat, exfat, or SMB mounts with
  an `fmask` that clears them), scripts the server marks executable stay
  without them: run them through their interpreter (`sh run.sh`). Mounts
  that show every file as executable (WSL's `/mnt/c` without `metadata`)
  are fine.

## Observability

Everything is local; nothing is sent anywhere (a remote workspace talks only to its own `bd serve`).

- **Logs**: `BD_LOG=bd=debug bd …` shows per-transaction lock-wait, exec, and commit timings on stderr. `--log-format json` emits structured logs. Colors appear only on a terminal (`NO_COLOR` turns them off), so redirected logs stay plain text.
- **Server logs**: `bd serve` logs (target `bd::serve`) one line per request (with `waited_ms` for a request that waited for events), its background job settings at startup, and one line per background job that changed something (`reclaimed expired leases`, `checked gates`, `agent sets changed`, `backed up`, `pruned request records`, with the workspace, counts, issue ids, and `ms`). Failures are warnings (`background job failed`, `gate check failed` with the gate and the `gh` error, `agent set cannot be read` with the harness and error). `BD_LOG=bd::serve=debug` also logs the jobs that found nothing to do, and each request that starts `waiting for events` or finds `too many followers`.
- **Timing**: `--timing` (or `BD_TIMING=1`) prints a per-command breakdown. Commands and transactions slower than `--slow-ms` (default 250) log `bd::slow` warnings and increment the `slow_writes` counter.
- **Metrics**: `bd metrics` prints Prometheus text, `--format json` prints JSON:
  - issues by status, ready count by priority, blocked/deferred counts
  - lease health (active, expired, expiring soon, reclaimable, oldest heartbeat age)
  - event totals and the last 24h by op
  - durable contention counters (`claim_conflicts`, `cas_conflicts`, `lease_lost`, `not_owner`, `reclaims`)
  - lead time, cycle time, and queue-wait percentiles
  - database and WAL size
- **Health**: `bd doctor [--fix] [--full]` checks:
  - SQLite `quick_check`/`integrity_check`, foreign keys, WAL mode, schema version
  - status and lease invariants
  - blocked-flag drift against an independent full recompute
  - dependency cycles, event-sequence continuity, stale leases

  `--fix` repairs leases and blocked flags in one transaction.

## Benchmarks

`bd bench` seeds a random DAG on a scratch database, drains it with N
workers (claim → work → close), and verifies from the event log that every
issue was claimed and closed exactly once and never before its blockers
closed. It has four modes:

- `threads`: an embedded library, one connection per thread
- `processes`: long-lived worker processes
- `cli`: a fresh `bd` process per operation, which is what agents experience
- `remote`: like `cli`, but through a scratch `bd serve` on loopback (HTTP,
  access token, one sub-actor per worker), which is what clients of a bd
  server experience

Results on a WSL2 laptop (release build, `durability=normal`, 3,000 issues, about one blocking edge each):

| mode | workers | claims/s | write tx/s | claim p50 | claim p99 |
|---|---|---|---|---|---|
| threads | 1 | 3,600 | 7,100 | 63 µs | 0.2 ms |
| threads | 4 | 4,500 | 9,000 | 87 µs | 10 ms |
| processes | 8 | 4,700 | 9,300 | 85 µs | 11 ms |
| cli | 1 | 235 | 470 | 2.0 ms | 2.6 ms |
| cli | 8 | 920 | 1,800 | 2.7 ms | 22 ms |
| remote | 1 | 180 | 370 | 2.6 ms | 3.5 ms |
| remote | 8 | 1,030 | 2,060 | 3.1 ms | 15 ms |

SQLite has one writer, so throughput plateaus around the single-writer rate.
Tail latency comes from contention and WAL-checkpoint fsyncs: with
`--durability off`, p99 drops below 0.4 ms. `durability=full` fsyncs every
commit and is bounded by the disk's fsync latency. Through a server, one
worker pays about 0.4 ms per command for HTTP, but 8 workers outran `cli`
(1,030 against 810 claims/s in the same run): the server keeps its database
connections open, while each `cli` process opens the database again.

## Configuration (`bd config list|get|set|unset`)

| key | default | meaning |
|---|---|---|
| `issue_prefix` | from the directory name | id prefix |
| `id.mode` | `hash` | `hash` or `counter` |
| `lease.ttl` | `5m` | claim lease duration |
| `lease.grace` | `10m` | how long past expiry before reclaim reverts a claim; until then it stays live, its holder's |
| `lease.auto_reclaim` | `true` | `claim --next` reclaims stale leases first, and `bd serve` reclaims them every minute |
| `claim.pools` | | comma-separated assignees anyone may claim from |
| `types.custom` | | extra issue types |
| `durability` | `normal` | SQLite `synchronous`: `off`, `normal`, `full` |
| `events.retain_days` / `events.retain_rows` | `0` | automatic event retention (`0` keeps everything) |
| `gate.repos` | | repositories GitHub gates may name: `OWNER/REPO`, `HOST/OWNER/REPO`, `OWNER/*`, `*` (unset: any locally, the workspace's own through `bd serve`) |

### Actors

Every write records its actor, and a live claim belongs to the actor that
took it: another actor name cannot end it without `--take-over`. The actor
comes from the first of:

1. `--actor`
2. `$BD_ACTOR`, then `$BEADS_ACTOR`
3. the user, `git config user.name` (then `$USER`, `$USERNAME`), as the
   sub-actor `<user>/<session>` when the command runs in an agent session.
   The session joins, with `.`, a part for each of these that is set:
   - `$CLAUDE_CODE_SESSION_ID` (Claude Code 2.1.132+): `claude-<id>`
   - `$COPILOT_AGENT_SESSION_ID` (Copilot CLI 1.0.29+): `copilot-<id>`
   - `$CODEX_THREAD_ID`, else `$CODEX_SESSION_ID` (Codex): `codex-<id>`
   - `$BD_SESSION=<name>`: `<name>` (characters other than letters, digits,
     `.`, `_` and `-` become `-`), for scripts and other harnesses; the
     global flag `--session <name>` stands in for it on one command

   where `<id>` is the last 8 letters and digits of the session id, so
   `Quang Le/copilot-b9bb2788`. Harnesses set these in every shell command
   of a session, so all of its bd commands act alike, and two sessions never
   do. A terminal without them keeps the plain user.

Concurrent sessions of one user thus never share claims, with no setup.
Environment variables are inherited, so an agent started from another
agent's shell sees its parent's variables as well as its own: a harness
sets its own variable afresh (a nested Claude Code session has its own
`$CLAUDE_CODE_SESSION_ID`), while another harness's stays, so Codex started
from Claude Code acts as `<user>/claude-<id>.codex-<id>`. Joining every part
keeps a nested session apart from its parent and its siblings without
guessing which harness is the innermost. `$BD_SESSION` only adds a part, so
one exported in a shell that starts agents does not merge them.

Naming the actor outright (`--actor`, `$BD_ACTOR`) turns this off: every
session with the same `$BD_ACTOR` shares its claims again. For an older
Claude Code, the `SessionStart` hook `bd hook session-start --harness claude`
(in this repository's `.claude/settings.json`) writes the session's own id, from the
hook's input, as `export CLAUDE_CODE_SESSION_ID=<id>` to `$CLAUDE_ENV_FILE`,
replacing any id inherited from a parent session. `bd info` and `bd prime`
show the actor and where it came from, and `bd claim` prints it.

Claude Code subagents need hooks. A subagent (the Agent/Task tool) runs its shell commands with
its parent session's environment: the same `$CLAUDE_CODE_SESSION_ID`, and
no variable of its own (checked with Claude Code 2.1.287, whose main and
subagent Bash environments were identical). Left alone, its bd commands act
as the parent, and the parent and its subagents can end each other's
claims by name. Only hook inputs tell a subagent apart, by `agent_id`, so
two hooks (in this repository's `.claude/settings.json`) give each subagent
an actor of its own, `<user>/claude-<id>.agent-<id>`:

- `SubagentStart` runs `bd hook subagent-start`, which adds to the
  subagent's context that every bd command it runs takes `--session
  agent-<id>` (the last 8 letters and digits of its `agent_id`), the actor
  that gives it, and how to take over a claim its parent hands it.
- `PreToolUse` on Bash (with `"if": "Bash(bd *)"`, Claude Code 2.1.85+)
  runs `bd hook pre-tool-use`, which, inside a subagent, denies a command
  that runs bd without `--session`, `BD_SESSION=`, `--actor` or
  `BD_ACTOR=`, with the corrected command as the reason. It never
  rewrites or approves a command: a flag rather than a variable keeps
  allow rules such as `Bash(bd *)` matching, which a `BD_SESSION=...`
  prefix would not.

Both do nothing in the main conversation, when `$BD_ACTOR` or
`$BEADS_ACTOR` names the actor, and on input they cannot read; `|| true`
keeps an older bd without them from failing the hook. The guard looks
through assignments and the wrappers `timeout`, `nice`, `env`, `sudo`,
`stdbuf`, `nohup`, `time`, `command` and `exec` with their options, and
reads here-document bodies as text. A form it does not understand is let
through rather than refused, and a bd run it cannot see in the command
line (from a script, through `xargs`) still acts as the parent. Without the hooks, give each subagent its own session
in its prompt: "run every bd command as `bd --session <name> ...`", with a
distinct `<name>` per subagent.

A claim taken in one session is another actor's in the next: after Claude
Code's `/clear` or a resume that starts a new session id, and in a subagent
that has its own id (Codex threads, Copilot CLI, and Claude Code subagents
with their `--session`). `bd prime` lists the in-progress claims of your user's
other actors (`<user>` and `<user>/*`) under "Held by other sessions of
yours", each with the command that takes it over, `bd update <id>
--assignee <you> --take-over` (it prints the new lease token to renew and
close with), and a claim conflict (exit 4) with one of
them names that command in its hint. Take a claim over only if this session
is continuing that work; otherwise another session is on it. To delegate a
claimed issue to a subagent with its own session id, either have the
subagent take it over that way, or run the subagent's bd commands with
`BD_ACTOR=<your actor>` so that it acts as you.

Only an actor bd derived has "sessions of yours": the plain user and its
`<user>/<session>` sub-actors. An actor named outright (`--actor`,
`$BD_ACTOR`, `$BEADS_ACTOR`) has none, since its first segment may be a
pool rather than a user: with `BD_ACTOR=pool/w1`, a claim of `pool/w2` is
another actor's, answered with the usual "pick other work" and not listed
by `bd prime`.

In a remote workspace, the access token decides: `--actor` and `$BD_ACTOR`
may only name the token's actor or one of its sub-actors. Without them, a
client in an agent session sends its session, not its user name, and acts
as `<token actor>/<session>`; `bd serve` never derives an actor from its own
environment. Servers older than this ignore the session and use the
token's actor. A client's `--session` travels in its session label, not
in the command line it sends. The token's actor is then the user: its sub-actors are the
"other sessions" of a request that names no actor, while a request whose
actor comes from `--actor` or the client's `$BD_ACTOR` has none.

## Exit codes

| code | meaning |
|---|---|
| 0 | ok |
| 1 | internal or doctor problems |
| 2 | invalid input (including `--force` on `update`/`release`: use `--take-over`), cycle, or policy refusal |
| 3 | not found or no workspace |
| 4 | claim conflict: already claimed (a live claim, even your own actor's, without its `--token`), not ready, not the holder of a live claim (`--take-over` takes it over; `--force` does not), or lease lost |
| 5 | database busy, or another bd process kept a checkout's agent assets mutex (`.bd/agents.lock.mutex`) past `--busy-timeout-ms` |
| 6 | event cursor truncated |
| 7 | access denied: missing, invalid or expired token, or its role, kind, workspaces or actor do not allow it; or a GitHub sign-in that was refused |
| 8 | bd server unreachable, its certificate not trusted, or a server failure: the command did not take effect (retrying is safe) |
| 9 | a write reached the bd server, but its answer was lost: it may have taken effect, so check before running it again |
| 13 | stale optimistic-concurrency guard |

With `--json`, errors are printed to stderr as `{"error":{"code","message","exit_code"}}`.

## Library

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

## Layout

```
crates/bd-core/src/   store (WAL, transactions, busy handling) · schema · issues · graph (deps + blocked state)
                      ready · claims (leases) · events · comments · memory · config · transfer (JSONL)
                      metrics · doctor · queries (read API) · gates (conditions, arming, evaluation)
                      policy (what a request's access token may override) · requests (idempotency records)
                      · playbook/ (model + strict parsing · template · loader · bundle (a remote client's
                      playbook files) · compile · run · extract) · agents/ (harness sets: strict loading,
                      manifests, MCP definitions, agents_changed events)
crates/bd-core/tests/ engine integration tests (graph semantics, leases with a manual clock, concurrency,
                      playbook runs and gates, write policies)
crates/bd-cli/src/    cli (clap) · commands · playbooks · gates (gh probes) · batch · bench · fmt · logging
                      io (stdio and files, or a captured request) · serve (bd serve) · jobs (its background
                      jobs: reclaim, gate checks, agent sets, backups) · auth (access tokens)
                      · oauth (GitHub sign-in) · remote (client) · credentials (bd remote login)
                      · protocol (wire format) · stream (streamed answers) · agents (bd agents) + agents/
                      (checkout, lock, mcp_file, sync, approve, show, hook, watch) · hook (session hook
                      output per harness)
crates/bd-cli/tests/  end-to-end CLI tests; remote.rs runs real bd serve and client processes
```

Build and test: `cargo build --release && cargo test --workspace`.
