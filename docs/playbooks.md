# Playbooks: repeatable multi-step work

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

## Writing a playbook

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
server's, then your own ([Clients](remote.md#clients)). beads formula files load as they are
(`formula`, `depends_on`, `expand_vars`, gate `id`, `phase = "vapor"`); a
`type = "human"` step is rejected with a pointer to human gates.

`bd prime` lists the playbooks in that order, each name once (the one a
command naming it loads), so agents know which work has one: its name, the
first line of its `description` (cut at 100 characters), where it lives when
not in the checkout (on the server, or the user's own), and a flag on one that
does not load. It lists 10 at most (`--max-playbooks N`, 0 for all) and
points to `bd playbook list` for the rest; `bd prime --json` has them under
`playbooks` (`name`, `description`, `location`: `checkout`, `server` or
`user`, `invalid`), with their number in `playbooks_total`.

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

## Runs

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

## Gates

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
[Background jobs](remote.md#background-jobs-and-backups)) opens the gates whose
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
