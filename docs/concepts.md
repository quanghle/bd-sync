# Concepts

## Statuses

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

## Dependency types (`bd dep add ISSUE DEPENDS_ON -t TYPE`)

| type | effect on ISSUE |
|---|---|
| `blocks` (default) | blocked while DEPENDS_ON is not closed/pinned |
| `conditional-blocks` | runs only if DEPENDS_ON closes as **failed**; stays blocked if it succeeds |
| `parent-child` | hierarchy (one parent); a blocked parent blocks its whole subtree, never the reverse; a parent with open children is not ready (its children come first), unless others wait on it through `waits-for` |
| `waits-for` | fan-in gate on DEPENDS_ON's children: `--gate all-children` (default) or `any-children`; metadata `also_blocks: true` also waits on the spawner itself |
| `related`, `discovered-from`, `tracks`, `caused-by`, `validates`, `supersedes`, `duplicates`, `replies-to`, custom | informational only |

## Ready-work order

`--sort priority` (default): priority, then oldest, then id. `--sort oldest`:
creation time, then id. `--sort hybrid`: issues from the last 48h by
priority, then older ones by age. Every policy ends with `id`, so the same
state and clock always give the same queue. A parent's children come first:
an issue with a child that is not closed waits on its children, whatever its
type, until every child has closed, exactly when `bd close` refuses to close
it for them. A spawner, which others wait on through `waits-for`, never
waits: it may finish before the work it spawned. Waiting is no block: the
children are ready as before, and `bd ready` and `bd stats` count the
issues waiting on children. Epics are containers and are also excluded
unless you pass `--include-epics` or `-t epic`. Gates are never ready work
(`-t gate` lists them).

## Claims, leases, and recovery

- `bd claim <id>` succeeds only if the issue is `open`, ready, and unassigned, reserved for you, or held by a `claim.pools` alias. An issue with open children is not ready: the refusal (exit 4) names them and their holders, and `bd claim --next --parent <id>` claims one; a parent with no children, or with every child closed, is claimable. `--allow-blocked` claims a blocked or deferred issue, or such a parent, by id anyway. A claim is *live* until `bd reclaim` could take it back (its lease expired more than `lease.grace` ago), and a live claim is never claimed twice: not even by its own actor, since two sessions may share an actor name. Its holder renews it with `bd claim <id> --token <t>` (an idempotent retry that returns the same lease); without the token, or with a stale one, the claim fails with exit 4. A dead claim (past `lease.grace`) is reclaimed by the claim first, with a `reclaimed` event.
- `bd claim --next` claims the head of the ready queue inside one write transaction, so two agents can never take the same issue, and never returns work someone holds. It first reclaims leases that expired more than `lease.grace` ago.
- The lease `token` is the sequence number of the `claimed` event: unique and increasing. Pass it to `claim`, `heartbeat`, `close`, or `release` so a stale worker cannot act on a claim it no longer holds.
- A live claim is its holder's. Ending or taking over one held by another actor name fails with exit 4 (`not_owner`, or `already_claimed` for a reassignment), alone or in a `bd batch`: `close`, `release`, `update --status` out of `in_progress`, `update --assignee`, `delete`, `playbook discard` and `compact` (of the run issue or a step), `import`, and `reclaim` with a `--grace` shorter than `lease.grace`. Another actor name is any other: the holder's root actor (`alice` for `alice/agent-1`) and its sibling sub-actors too. Only `--take-over` takes it over, deliberately, and the event (`closed`, `released`, `updated`, `deleted`, `imported`, `reclaimed`, or `run_compacted`'s `claim_overrides`) records the takeover as `claim_override` with the holder and lease token. `--force` never does: it only gets past open children, blockers, dependents, unfinished runs and your own work in progress, and the claim is checked first, so the first refusal names its holder (an operation that would end several claims lists every one, with its holder). On `update` and `release`, where `--force` used to mean a takeover, it is now refused as a usage error (exit 2) pointing at `--take-over`; `release --if-assignee <holder>` is a guard, not a takeover. The holder needs neither `--take-over` nor its token (a token it passes must match), so sessions sharing one actor name can still end each other's claims: give each agent its own actor. A dead claim is anyone's to claim, close or release without `--take-over`. A playbook run or group claimed by another actor stays open, still claimed, when its last step closes; its holder closes it.
- `bd reclaim` reverts dead workers' issues (leases expired more than `lease.grace` ago) to `open` and records `reclaimed` events. A shorter `--grace` reaches claims that are still live, so other actors' need `--take-over`. `bd leases` shows lease health. `bd serve` runs it with the configured grace in every workspace each minute ([Background jobs](remote.md#background-jobs-and-backups)).
- Invariant (checked by `bd doctor`): a lease exists if and only if the issue is `in_progress`, and the lease holder is the assignee.
- Through `bd serve`, a takeover also needs an admin token, unless the token's own actor or one of its sub-actors holds the claim ([Remote server](remote.md)).

## Optimistic concurrency

Every issue has a `revision` that increases on each change to the issue
itself. Comments, heartbeats, and derived blocked-flag changes do not bump
it. Read it, decide, then write conditionally:

```bash
rev=$(bd show demo-xyz --json | jq .revision)
bd update demo-xyz --status blocked --if-revision "$rev"   # exit 13 if someone else changed it
bd release demo-xyz --if-assignee worker-7 --take-over      # CAS takeover for supervisors
bd remember --key deploy "use blue/green" --if-revision 0   # create-only memory
```

## Event history

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
`--interval-ms` (default 500). Through a [bd server](remote.md#followers), they are told
of new events as they are committed instead. A deleted issue keeps its events
(`--issue` still finds them, as `bd history` does).

To mirror the state elsewhere, `bd export` writes a snapshot whose header
carries `head_seq`. Load it, then tail `--since head_seq`.

## Comments and memory

```bash
bd comment add demo-xyz "API shape agreed with the frontend team"
bd remember "Integration tests need docker running"   # key derived: integration-tests-need-docker-running
bd memories docker ; bd recall <key> ; bd forget <key>
```

`bd prime` prints workflow context, your actor and claims, top ready work,
gates waiting on a person, the playbooks available ([Playbooks](playbooks.md#writing-a-playbook)),
and all memories. Outside a workspace it prints nothing (safe in session
hooks). It warns when you act as the plain default actor, shared by every
session without one of its own, and that actor holds claims.
## Actors

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
replacing any id inherited from a parent session. Session hooks act as the
session too: Copilot CLI keeps `$COPILOT_AGENT_SESSION_ID` from hook
processes, Codex `$CODEX_THREAD_ID`, and an older Claude Code
`$CLAUDE_CODE_SESSION_ID`, but each gives the same id in the hook's input,
which `bd prime --hook <harness>` and
`bd hook session-start --harness <harness>` take, so the session-start
context shows the actor and claims of the session's commands
([Session-start hooks](agents.md#session-start-hooks)). `bd info` and
`bd prime` show the actor and where it came from, and `bd claim` prints it.

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
that has its own id (Codex threads, Copilot CLI subagents, each given its
own `$COPILOT_AGENT_SESSION_ID` (checked with 1.0.91), and Claude Code
subagents with their `--session`). `bd prime` lists the in-progress claims of your user's
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
