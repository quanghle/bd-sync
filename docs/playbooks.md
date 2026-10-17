# Playbooks and gates

A playbook declares a multi-step process once: a release, an incident
drill, an onboarding checklist. `bd playbook run` turns it into real issues
that flow through `bd ready` like any other work. A gate holds a step back
until a person, a timer, another issue or a CI result says it may go.

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
[steps.loop]                           # one step per platform, in parallel
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
bd playbook list                                  # playbooks on the search path (alias: ls)
bd playbook show ship                             # the validated definition
bd playbook plan ship --var version=1.2.0         # what a run would create; writes nothing
bd playbook run ship --var version=1.2.0          # run t-12: t-12.bump, t-12.build-linux, ...
bd ready --run t-12                               # the run's claimable steps
bd playbook status t-12                           # every step, its state, what it waits on
```

Playbooks are TOML or JSON files (`.toml`, `.json`, `.formula.toml`,
`.formula.json`).

### Top-level keys

| key | meaning |
|---|---|
| `playbook` (or `name`) | the name (letters, digits, `-`, `_`, `.`, at most 64); defaults to the file name |
| `description` | shown by `list` and `bd prime` (first line) |
| `title` | title of the run issue |
| `version`, `priority`, `labels` | carried onto the run |
| `ephemeral` | `true` makes runs ephemeral (default `false`; [Runs](#runs)) |
| `extends = ["base"]` | merge other playbooks first (below) |
| `[vars.NAME]` | variables |
| `[[steps]]` | steps |

### Steps

Steps take `id` (required: ASCII letters, digits, `-` and `_`, starting
with a letter, at most 64), `title` (default: the id with `-` and `_` as
spaces), `description`, `design`, `acceptance_criteria`, `notes`, `type`,
`priority` (`0`–`4` or `P0`–`P4`), `labels`, `assignee`, `estimate`
(minutes) and `metadata`, plus:

| key | meaning |
|---|---|
| `needs = ["a", "b"]` | starts after those steps close. Steps without `needs` run in parallel |
| `[[steps.children]]` | makes the step a group: an epic that closes with its children. Needing a group waits for all of it. A group takes no `assignee` and no type other than `epic` |
| `condition = "{{env}} == prod && !{{dry_run}}"` | leaves the step out when false; steps that needed it inherit its `needs`, so the order holds |
| `[steps.loop]` | one step per iteration (below) |
| `expand = "checks"`, `expand_vars = { suite = "{{env}}" }` | runs another playbook's steps inside this step, with their own variables and `needs`. Not with `children` |
| `waits_for = "all-children"` | fan-in on work created at run time (below) |
| `[steps.gate]` | a gate in front of the step ([Gates](#gates)) |

`type = "gate"` and the metadata keys `playbook` and `gate` are reserved.

**Loops** take exactly one source: `count = 3`, `range = "1..{{n}}"`
(inclusive), `items = [...]` (not empty) or `over = "{{csv}}"`. `var`
names the loop variable (default `i` for `count` and `range`, `item`
otherwise; it may not shadow a playbook variable), and `sequential = true`
chains the iterations. Iteration ids get a suffix: `build-linux`,
`shard-2`.

**Conditions** use `==`, `!=`, `&&`, `||`, `!`, parentheses, and quoted or
bare words. A lone value is false when it is empty, `false`, `0`, `no` or
`off`. A condition is at most 1,024 bytes. Besides the declared vars, templates and
conditions may read `{{experimental.<name>}}`, `true` when the workspace
has that [experimental feature](commands.md#experimental-features) on and
`false` otherwise (`condition = "{{experimental.specs}}"` keeps a step only
where feature specs are on); a name bd does not know is an error when the
playbook loads, and none can be passed with `--var`. In a remote workspace
the server compiles the run, so it must know the feature too.

**Fan-in** (`waits_for`): `all-children` waits for its spawner step (the
first of `needs`) to close, then for every child created below it;
`any-children` for the first of them to close. `children-of(<step>)`,
`all-children-of(<step>)` and `any-children-of(<step>)` name the spawner.

### Variables

`[vars.NAME]` takes `description`, `required` (a required variable has no
`default`), `default`, `enum`, `pattern` (a regex) and `type`: `string`
(default), `int` (`integer`) or `bool` (`boolean`; `true/yes/on/1` and
`false/no/off/0`).

`{{name}}` works in every text field, labels, metadata, gate fields and
loop sources; `\{{` is a literal `{{`.

### Inheritance

`extends = ["base"]` merges other playbooks first: their steps come first,
a step with the same id replaces the parent's, and this file's variables
and top-level fields win.

### Validation

Parsing is strict, and everything is checked before anything is written:
unknown keys (with file and line), unknown step types, bad durations and
patterns, undeclared variables, unknown `--var` names, missing required
variables, and `needs` that dangle, form a cycle or point at the step's own
group are all errors.

### Where playbooks are found

By name, in this order:

1. the workspace's `.bd/playbooks/`
2. `$BD_PLAYBOOK_PATH` (`:`-separated; `;` on Windows)
3. `$XDG_CONFIG_HOME/bd/playbooks` (default `~/.config/bd/playbooks`;
   `%APPDATA%\bd\playbooks` on Windows)

A file path works too. In a remote workspace, the checkout's playbooks come
first, then the server's that a person approved on this machine (kept in
`.bd/approved/playbooks`), then your own
([What runs where](remote.md#what-runs-where)). The server's playbooks are
used only once approved here with `bd agents approve`, and then exactly as
approved: a change on the server waits for approval while the version
approved stays in use, and a playbook never approved is not found
([Approving the server's playbooks](agents.md#approving-the-servers-playbooks)).

A remote workspace can make the server's playbooks the only source:
`bd config set playbooks.source server` (default `checkout`; an admin's
setting through `bd serve`). Its clients then ignore the checkout's
`.bd/playbooks/`: `bd playbook show/plan/run <name>` looks every name up,
the one on the command line and those its playbooks `extends` or `expand`
by name, among the server's playbooks approved on this machine, then in
your own paths (2 and 3 above) only for a name the server does not serve.
A name the server serves but this machine has not approved is not found
(exit 3, saying how to approve it), even when your own paths have a copy;
names compare ignoring case (`CHANGE` is `change.toml`). Each checkout copy
skipped gets one warning on stderr naming it (the exit code is unchanged).
`bd playbook list` lists the checkout's last, marked `(ignored:
playbooks.source = server)` (`"ignored": true` in JSON), shadowing nothing,
and marks your own of a name the server serves and this machine has not
approved `(waiting for approval: the bd server serves this name)`
(`"unavailable": true`); `bd prime` leaves both out, and says how many
checkout playbooks are ignored and that [`bd publish`](agents.md#publishing)
brings them to the server. A file path on the command line (`bd playbook
run ./x.toml`) still works as before, to try a playbook before publishing
it.

The client asks the server's setting (one `config get`) only when the
answer matters: `show`/`plan`/`run` when some name resolves outside the
approved playbooks (in the checkout or your own paths), never for one
made only of approved playbooks; `list` when the checkout holds playbooks
or one of your own has a name the server serves unapproved, and then its
JSON has the answer as `"source"` at the top (absent when it did not ask).
That read fails open: a server that predates the setting, a failed read
or an answer other than exactly `server` counts as `checkout`. In server
mode, telling whether the server serves a name takes its playbook list
(`bd agents manifest --playbooks`), read only when some name resolves on
your own paths; that read fails closed: if it fails, the command stops
saying the server's list could not be read, rather than take a name it
may serve from elsewhere. It is a policy for bd clients, not a security
boundary: the server runs what a client sends. In a local workspace the
setting changes nothing (its `bd playbook list --json` shows it as
`"source"`).

A workspace's `.bd/playbooks/` is best kept by [`bd publish`](agents.md#publishing)
from a source directory in the repository (`.bd/source/playbooks/`,
subdirectories allowed): it validates every playbook, with its `extends`
and `expand`, before replacing the directory, which then mirrors the
source. A server loads its own playbooks held to their directories: a
reference that leads outside them (`../`, an absolute path, a symlink out)
is refused, as is a file over 512 KiB.

`bd prime` lists the playbooks in that order, each name once: its name, the
first line of its description (cut at 100 characters), where it lives when
not in the checkout, and a flag on one that does not load; in a remote
workspace it also names the server's playbooks waiting for approval here.
It lists 10 (`--max-playbooks N`, `0` for all); `bd prime --json` has them
under `playbooks` (`name`, `description`, `location`: `checkout`,
`approved`, `user`, or `server` for a client that predates approvals,
`invalid`) with their count in `playbooks_total`, those waiting in
`playbooks_pending` (`path`, `change`), and the checkout's ignored with
`playbooks.source = server` counted in `playbooks_ignored`.

### Bootstrapping feature specs

This repository's `spec-bootstrap` playbook (`.bd/playbooks/spec-bootstrap.toml`)
is a worked example of loops and a human gate: `--var groups=` takes group
keys from `bd spec candidates`, the loop runs one draft step per group in
turn (`sequential = true`), and a person resolves the review gate before the
run finishes ([Feature specs](concepts.md#feature-specs)). Another repository
uses it by copying the file into its `.bd/playbooks` or the user playbook
directory.

### Limits

| limit | value |
|---|---|
| steps in a playbook | 2,000 |
| nesting (groups and expansions) | 32 levels; expansions 8 deep |
| a run | 2,000 issues, 20,000 dependencies, 16 MiB of text |
| variables | 256 KiB together |
| one rendered field | 1 MiB |
| loaded by one command | 20,000 steps and variables; 16 MiB of inherited text |
| planning work | 100,000 units (each loop iteration, expansion and dependency lookup) |

## Runs

```bash
bd playbook run ship --var version=1.2.0 [--title T] [--assignee A] [--parent ID] [--after ID,...] [--ephemeral|--persistent] [--dry-run]
bd playbook runs [--all] [--playbook NAME] [-n 50]   # runs and their progress
bd playbook compact t-12 [-s SUMMARY]                # a finished run: digest in its notes, steps deleted
bd playbook discard t-12                             # delete a run and every issue in it
bd playbook extract t-9 --save --name onboarding     # write a playbook from any epic (-o FILE)
```

`bd playbook run` creates the run issue (an epic) and one issue per step
and gate in a single transaction, with readable ids `<run>.<step>`.

- The run and its groups close themselves when their last step closes (as
  `failed` if a step failed), and reopen when a step reopens. A run or
  group claimed by another actor stays open, still claimed, for its holder
  to close.
- `--assignee` assigns the run and every step without an assignee of its
  own (groups are never assigned). `--after <id>` holds the run until other
  work closes; `--parent <id>` attaches it below an existing issue.
- `compact` and `discard` take `--dry-run`, `--force` (unfinished runs) and
  `--take-over` (other actors' claims in the run). `bd playbook compact`
  folds a run; to summarise the text of old closed issues instead, see `bd
  compact` ([Compaction](concepts.md#compaction)).

**Fan-out at run time.** Give a collector step `needs = ["spawn"]` and
`waits_for = "all-children"`, then create children under the spawner step
while running (`bd create --parent t-12.spawn`, or `bd playbook run worker
--parent t-12.spawn`). The spawner may close as soon as it has spawned
them; the collector waits for all of them.

**Ephemeral runs** (`ephemeral = true`, or `--ephemeral`; `--persistent`
overrides) work like any other, but `bd export` leaves them out unless you
pass `--include-ephemeral`. `bd purge [--older-than 7d] [--dry-run]`
deletes closed ephemeral work a whole run at a time, with one `purged`
event. `bd create --ephemeral` marks a single issue the same way.

## Gates

A gate is an issue of type `gate` in front of a step. The step waits on it
like on any blocker. The gate itself is never ready, cannot be claimed and
is never `in_progress`.

| type | opens when | escalates when |
|---|---|---|
| `human` | someone runs `bd gate resolve <id>` (through `bd serve`: with a human token) | `timeout` passes after arming |
| `timer` | `timeout` (`30m`, `24h`, `2d`) has passed since arming | never |
| `issue` | the `await_id` issue closes as done | it closes as failed, or `timeout` passes |
| `gh:pr` | GitHub pull request `await_id` (a number, `#` optional) merges | it closes without merging, or `timeout` passes |
| `gh:run` | the GitHub Actions run succeeds | it fails or is cancelled, or `timeout` passes |

Gate keys: `type`, `await_id`, `timeout` (positive), `title`,
`description`, `assignee`, and for GitHub gates `repo`, plus `branch` (at
most 255 characters) and `event` (lowercase letters and `_`) for a
`gh:run` that names a workflow.

A gate **arms** when the step it guards could otherwise start (its `needs`
are closed); timers and timeouts count from that moment.

**`gh:run`**: `await_id` is a run id, or a workflow name or file. For a
workflow, the first run started after arming is watched and pinned (runs
created up to a minute before arming count, for clock skew). `branch` and
`event` narrow the runs considered (`branch = "v{{version}}"`, `event =
"push"`). With `branch`, the gate follows the branch or tag: when a newer
run is for a different commit, it watches that commit's first run instead,
dropping any escalation about the old one.

**GitHub gates** run `gh` (`$BD_GH` overrides the binary) in the
workspace's repository, or in `repo = "owner/name"`. A `gh` call that takes
longer than 60 seconds is killed and reported as an error for that gate.
`gh` runs with the credentials of whoever checks the gate, so the
`gate.repos` setting lists the repositories gates may name in `repo`:
`OWNER/REPO`, `HOST/OWNER/REPO`, `OWNER/*`, `HOST/OWNER/*`, or `*`.
`OWNER/REPO` means `gh`'s default host, so it never matches a
`HOST/OWNER/REPO` entry, nor the other way round. Unset, any repository
works locally, while through `bd serve` only gates without `repo` (the
workspace's own repository) do. A gate naming another repository is
refused when it is written, and `bd gate check` escalates it instead of
probing it.

```bash
bd gate list [--all]                              # waiting, armed, escalated (alias: ls)
bd gate show t-12.gate-publish
bd gate check [IDS] [--dry-run] [--type all|gh|local|<type>]
bd gate resolve t-12.gate-publish -r "approved"   # --force: before it armed
bd gate create -t gh:pr --await-id 42 --blocks t-7
bd gate create -t gh:run --await-id release.yml --branch v1.2.0 --event push --blocks t-9
```

`bd gate create` also takes `--timeout`, `--repo`, `--title`, `-d`, `-a`,
`--parent` and `-p`.

`bd gate check` (from cron or CI; `bd serve` runs it on its own, see
[Background jobs](remote.md#background-jobs)) opens the gates whose
condition holds and escalates the ones that failed or timed out. Each
gate's verdict is applied on its own: one it cannot evaluate is reported
as an error, and the others still are. `--type local` checks every type but
the GitHub ones, `--type gh` only those.

Escalation records the reason on the gate, comments on it and lists it in
`bd prime`; it never opens the gate. A person decides with
`bd gate resolve`.
