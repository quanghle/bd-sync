# bd — a coordination engine for agents, on SQLite WAL

`bd` is a Rust re-implementation of [beads](https://github.com/gastownhall/beads)
(the `bd` issue tracker for AI coding agents) as a fast, embeddable
coordination engine:

- **Task lifecycle**: `open → in_progress → closed`, plus `blocked`, `deferred`, `pinned`
- **Typed dependency graph**: `blocks`, `conditional-blocks`, `parent-child`, `waits-for` gate readiness; informational edges (`related`, `discovered-from`, …) never do. Cycles and hierarchy deadlocks are rejected at write time.
- **Deterministic ready work**: a materialized blocked flag maintained in the same transaction as every change, and a total queue order (policy, then id)
- **Leased atomic claiming**: claims run under SQLite's write lock and return a lease with a fencing token
- **Crash recovery**: expired leases are reclaimed after a grace window (automatically by `claim --next`); WAL makes every transaction atomic
- **Optimistic concurrency**: per-issue revisions and `--if-revision/--if-status/--if-assignee` guards (exit code 13 on conflict)
- **Comments, durable memory, and transactional event history** with gapless, commit-ordered sequence numbers
- **Playbooks and gates**: repeatable multi-step work declared once in TOML and run atomically as `<run>.<step>` issues; human, timer, issue, and GitHub gates that arm when their step could start ([Playbooks](#playbooks-repeatable-multi-step-work))
- **Remote server**: `bd serve` shares workspaces over HTTPS with laptops, CI runners and cloud agents; the same `bd` binary is the client, with access tokens, roles, and retries that apply a write once ([Remote server](#remote-server-one-workspace-many-machines))
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
`bd cursor-hook`) must be switched to plain `bd prime`.

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
lease was lost (reclaimed or taken over): stop working on that issue.

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
children, or closing a blocked issue, is refused unless you pass `--force`.
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

- `bd claim <id>` succeeds only if the issue is `open`, ready, and unassigned, reserved for you, or held by a `claim.pools` alias. Re-claiming your own claim is idempotent and refreshes the lease.
- `bd claim --next` claims the head of the ready queue inside one write transaction, so two agents can never take the same issue. It first reclaims leases that expired more than `lease.grace` ago.
- The lease `token` is the sequence number of the `claimed` event: unique and increasing. Pass it to `heartbeat`, `close`, or `release` so a stale worker cannot act on a claim it no longer holds.
- `bd reclaim [--grace 10m]` reverts dead workers' issues to `open` and records `reclaimed` events. `bd leases` shows lease health.
- Invariant (checked by `bd doctor`): a lease exists if and only if the issue is `in_progress`, and the lease holder is the assignee.

### Optimistic concurrency

Every issue has a `revision` that increases on each change to the issue
itself. Comments, heartbeats, and derived blocked-flag changes do not bump
it. Read it, decide, then write conditionally:

```bash
rev=$(bd show demo-xyz --json | jq .revision)
bd update demo-xyz --status blocked --if-revision "$rev"   # exit 13 if someone else changed it
bd release demo-xyz --if-assignee worker-7                  # CAS release for supervisors
bd remember --key deploy "use blue/green" --if-revision 0   # create-only memory
```

### Event history

Each mutation appends events in its own transaction, so the log and the state
never disagree. Ops:

- issue lifecycle: `created`, `updated` (field-level old/new), `closed`, `reopened`, `deleted` (with a snapshot)
- claims: `claimed`, `released`, `reclaimed`, `lease_granted`
- graph: `dep_added`, `dep_removed`, `dep_updated`, `blocked`, `unblocked`
- other: `commented`, `memory_set`, `memory_deleted`, `config_set`, `imported`, `pruned`
- playbooks and gates: `run_started`, `run_compacted`, `purged` (one event listing every removed issue), `gate_escalated`, `gate_updated`

`seq` is gapless and commit-ordered. `tx` groups the events of one
transaction.

```bash
bd events -n 20                    # recent events
bd events --since 1200 --follow    # tail from a cursor (JSON lines with --json)
bd history demo-xyz                # one issue (survives deletion)
bd events prune --older-than 30d   # retention; a cursor behind it fails (exit 6)
```

To mirror the state elsewhere, `bd export` writes a snapshot whose header
carries `head_seq`. Load it, then tail `--since head_seq`.

### Comments and memory

```bash
bd comment add demo-xyz "API shape agreed with the frontend team"
bd remember "Integration tests need docker running"   # key derived: integration-tests-need-docker-running
bd memories docker ; bd recall <key> ; bd forget <key>
```

`bd prime` prints workflow context, your claims, top ready work, and all
memories. Outside a workspace it prints nothing (safe in session hooks).

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
works too. beads formula files load as they are (`formula`, `depends_on`,
`expand_vars`, gate `id`, `phase = "vapor"`); a `type = "human"` step is
rejected with a pointer to human gates.

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
like on any blocker; the gate itself is never ready and cannot be claimed.

| type | opens when | escalates when |
|---|---|---|
| `human` | someone runs `bd gate resolve <id>` | `timeout` passes after arming |
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
the binary) in the workspace's repository, or in `repo = "owner/name"`.

`bd gate check` (from cron or CI) opens the gates whose condition holds and
escalates the ones that failed or ran past their timeout. Escalation records
the reason on the gate, comments on it, and lists it in `bd prime`; it never
opens the gate. A person decides with `bd gate resolve`.

```bash
bd gate list                                      # waiting, armed, escalated
bd gate check [--dry-run] [--type gh]             # evaluate the armed gates
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
bd serve token create ci --as ci --workspace proj --root /srv/bd
bd serve token create dashboard --as dash --role read --root /srv/bd
bd serve token list --root /srv/bd
bd serve token revoke ci --root /srv/bd          # takes effect at once, no restart

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
retry. The server logs one
line per request on stderr; set `BD_LOG` to change that. Ctrl-C or SIGTERM
lets running commands finish first. Back up `<root>` like any SQLite data
(`sqlite3 bd.db ".backup copy.db"`, or Litestream). The server keeps
connections to each database open, so restart it after replacing or moving a
workspace's `bd.db`.

### Clients

The same `bd` binary is the client. Point a checkout at the server once and
commit the result, so every checkout and agent uses the shared workspace:

```bash
bd remote set https://bd.example.com/w/proj   # writes .bd/remote.toml (--ca-cert ca.pem for a private CA)
export BD_TOKEN=bdt_...                       # never commit it; CI takes it from a secret
bd remote show                                # checks the URL, certificate, token and actor
bd ready                                      # every command now runs on the server
BD_ACTOR=alice/agent-2 bd claim --next        # sub-actors: one lease holder per agent
```

```toml
# .bd/remote.toml
url = "https://bd.example.com/w/proj"
# ca_cert = "ca.pem"    # a private CA, relative to this file
```

A `.bd/remote.toml` takes precedence over a `.bd/bd.db` in the same
directory (`bd remote set` refuses to hide one unless given `--force`), `--db`
always means a local database, and `bd remote unset` removes the file.

| variable | meaning |
|---|---|
| `BD_TOKEN` | access token (required) |
| `BD_REMOTE` / `--remote URL` | use this workspace URL instead of `.bd/remote.toml` |
| `BD_CA_CERT` | PEM file of the CA that signed the server certificate |
| `BD_ACTOR` | act as `<token actor>/<name>`; anything else is refused |
| `BD_REMOTE_RETRY_SECS` | how long to retry an unreachable server (default 30; 0 = once) |
| `BD_INSECURE_HTTP=1` | allow plain `http://` to a non-loopback host |

A token acts as one actor (`--as`), or as that actor's sub-actors
`<actor>/<name>`, so leases keep naming who holds them. Roles:

| role | may run |
|---|---|
| `read` | read-only commands; its database connection is query-only |
| `write` (default) | every command except the admin ones |
| `admin` | also `config set/unset`, `import`, `events prune`, `doctor` |

Every invocation carries a random request id. The client retries
connection failures, timeouts and busy answers with the same id. The server
records the id in the same transaction as the write and replays the stored
answer to a retry, so a write whose response was lost in transit is applied
once. Exit codes are the same as locally, plus 7 (access denied) and 8
(server unreachable).

What runs where:

- Input and output files stay on the client: `import FILE` and `batch -f FILE`
  send the file, `--stdin` and `-` send stdin, and `export -o` and
  `playbook extract -o` write the file locally.
- Playbooks run by name from the server's playbook path: the workspace's
  `.bd/playbooks` (`<root>/<name>/.bd/playbooks`), then the server's
  `$BD_PLAYBOOK_PATH` and user config directory. File paths are refused.
  GitHub gates are checked by the server's `gh`.
- `events --follow` polls the server. `init`, `bench`, `serve` and
  `playbook extract --save` only run on the machine that holds the database.
- `bd prime`, which session hooks run, gives up within seconds when the
  server is unreachable or `BD_TOKEN` is missing, and prints a notice instead
  of failing the hook. With `--json` it fails like any other command.

Claims stay atomic however clients reach the database: remote clients, and
local `bd` processes on the server's host, all take the same SQLite write
lock. `bd bench --mode remote` checks this end to end
([Benchmarks](#benchmarks)).

The protocol is one endpoint, so other clients can call it directly:
`POST /w/<name>/v1/exec` with `Authorization: Bearer <token>` and
`{"argv": ["claim", "--next", "--json"], "request_id": "..."}`. The answer is
`{"exit_code", "stdout", "stderr", "replayed"}`. Failures before the command
runs return a non-200 status with the `--json` error shape.

## Observability

Everything is local; nothing is sent anywhere (a remote workspace talks only to its own `bd serve`).

- **Logs**: `BD_LOG=bd=debug bd …` shows per-transaction lock-wait, exec, and commit timings on stderr. `--log-format json` emits structured logs. Colors appear only on a terminal (`NO_COLOR` turns them off), so redirected logs stay plain text.
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
| `lease.grace` | `10m` | how long past expiry before reclaim reverts a claim |
| `lease.auto_reclaim` | `true` | `claim --next` reclaims stale leases first |
| `claim.pools` | | comma-separated assignees anyone may claim from |
| `types.custom` | | extra issue types |
| `durability` | `normal` | SQLite `synchronous`: `off`, `normal`, `full` |
| `events.retain_days` / `events.retain_rows` | `0` | automatic event retention (`0` keeps everything) |

The actor comes from `--actor`, then `$BD_ACTOR`, `$BEADS_ACTOR`, `git config user.name`, then `$USER`. In a remote workspace, the access token decides: `--actor` and `$BD_ACTOR` may only name the token's actor or one of its sub-actors.

## Exit codes

| code | meaning |
|---|---|
| 0 | ok |
| 1 | internal or doctor problems |
| 2 | invalid input, cycle, or policy refusal |
| 3 | not found or no workspace |
| 4 | claim conflict: already claimed, not ready, not owner, or lease lost |
| 5 | database busy |
| 6 | event cursor truncated |
| 7 | access denied: missing or invalid token, or its role, workspaces or actor do not allow it |
| 8 | bd server unreachable, its certificate not trusted, or a server failure (retrying is safe) |
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
                      requests (idempotency records) · playbook/ (model + strict parsing · template · loader
                      · compile · run · extract)
crates/bd-core/tests/ engine integration tests (graph semantics, leases with a manual clock, concurrency,
                      playbook runs and gates)
crates/bd-cli/src/    cli (clap) · commands · playbooks · gates (gh probes) · batch · bench · fmt · logging
                      io (stdio and files, or a captured request) · serve (bd serve) · auth (access tokens)
                      · remote (client) · protocol (wire format)
crates/bd-cli/tests/  end-to-end CLI tests; remote.rs runs real bd serve and client processes
```

Build and test: `cargo build --release && cargo test --workspace`.
