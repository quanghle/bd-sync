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
of a name it looks up gets one warning on stderr naming it, even a copy that
does not load (the exit code is unchanged).
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

This repository's `spec-bootstrap` playbook (`.bd/source/playbooks/spec-bootstrap.toml`)
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
| `human` | someone runs `bd gate resolve <id>` (through `bd serve`: with a human token, of one of its [approvers](#approvers) when it names them) or approves it [in a browser](sign-in.md#approving-human-gates-in-the-browser) | `timeout` passes after arming |
| `timer` | `timeout` (`30m`, `24h`, `2d`) has passed since arming | never |
| `issue` | the `await_id` issue closes as done | it closes as failed, or `timeout` passes |
| `gh:pr` | GitHub pull request `await_id` (a number, `#` optional) merges | it closes without merging, or `timeout` passes |
| `gh:run` | the GitHub Actions run succeeds | it fails or is cancelled, or `timeout` passes |

Gate keys: `type`, `await_id`, `timeout` (positive), `title`,
`description`, `assignee`, `approvers` for human gates ([below](#approvers)),
and for GitHub gates `repo`, plus `branch` (at most 255 characters) and
`event` (lowercase letters and `_`) for a `gh:run` that names a workflow.

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
bd gate create -t human --blocks t-8 --approver github:alice,github:bob
bd gate create -t human --blocks t-8 --oidc-approver https://login.example.com 248289761001
bd gate update t-12.gate-publish --approver github:carol   # replace the approvers
bd gate update t-12.gate-publish --clear-approvers        # anyone with a human token again
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
`bd gate resolve` or [`bd gate review`](#reviewing-human-gates).

**Approval links.** Through a `bd serve` started with `--public-url` and
an `auth.toml` whose `[oauth]` loads, the commands it runs for clients
name where a person can [approve a human gate in a
browser](sign-in.md#approving-human-gates-in-the-browser), for each open
human gate that is armed or escalated:

- `bd prime`'s "Gates needing a person" section ends the gate's line with
  `; or approve in a browser: <url>` (`--json`: `approval_url` on its
  `gates_needing_attention` entry), and says once that only a person opens
  a human gate, so an agent hands the person the link or asks them to run
  `bd gate review` in a terminal of their own;
- a refusal at a human gate (resolving it, or closing, moving or editing
  the work it holds back, with a token that may not) prints `approve in a
  browser: <url>` right after its `error:` line; its JSON error, and an MCP
  tool's, add `gate` (the gate's id, also without a link) and
  `approval_url`;
- `bd playbook status` adds `· approve in a browser: <url>` to the gate's
  line (`--json`: `approval_url` on its node);
- `bd gate show` adds `approve in a browser: <url>`, and for any gate in a
  run `part of: <id> <title>` (`--json`: `approval_url` and `part_of`
  `{id, title}`); `bd gate list --json` adds `approval_url` to such gates.

A link is `<public-url>/w/<workspace>/gates/<gate id>`, composed by the
server from its public URL and the gate's id (ids of letters, digits,
`.`, `_` and `-` only), never taken from stored text; lines that carry one
are escaped to one line. A local workspace, a local `bd mcp`, or a server
without `--public-url` or a valid `[oauth]` shows none: the line is left
out and the JSON key is absent. Other commands, `bd show` and `bd gate
list`'s text among them, show no links.

### Reviewing human gates

```bash
bd gate review                      # every open human gate that is armed or escalated
bd gate review bd-15 bd-16          # only these (partial ids resolve)
bd gate review -r "ship it"         # the reason recorded with each gate resolved
bd gate review --json               # the summary as JSON
```

`bd gate review` walks the human gates waiting for a person, in `bd gate
list` order, and resolves the ones you say yes to. Before asking about
each one it reads it again, skipping it if it is no longer a human gate,
already resolved, or no longer armed, then shows on stderr its id and
title, its state, the run it belongs to, the work it holds back and its
approvers, and asks `Resolve <id>? [y/N]`. `y` or `yes` resolves it, with
the `-r` text or `approved in bd gate review by <actor>` as its reason,
each in one write of its own and never with `--force`; any other answer
declines; the end of input (Ctrl-D) stops asking and lists the rest as
not asked. Gates named that are not human, already resolved, or missing
are skipped with the reason; a human gate still waiting for its work's
prerequisites is skipped too, and counted.

- **People only.** It refuses inside an agent session (any of the harness
  session variables set) and without a terminal on stdin (exit 2), before
  it reads any token or gate, with no flag to get past either. Locally
  that is a convention, as human gates are; through `bd serve` the
  server's human and approver checks back it.
- **Remotely it sends only the person's keychain token** ([Person's token
  in the keychain](remote.md#persons-token-in-the-keychain)) and skips
  gates whose [approvers](#approvers) do not match the token (or are not
  valid), by the server's rule: an account signed in with an OIDC
  provider matches only the identity reference of its issuer and subject,
  read from the token's account in the `info` answer, and any other token
  matches by actor. An `info` answer whose account cannot be read stops
  the review before any gate (exit 8), with no fallback to the actor.
  Locally approvers are shown, marked not checked.
- **Summary** on stdout: `Resolved N, declined M, skipped K`, with `not
  asked`, `failed` and `N waiting for their work's prerequisites` when
  there are any, then a line per gate resolved, skipped or failed; or `No
  human gates waiting for approval` (with the waiting count when there is
  one). With `--json`: `{"resolved": [{"id", "unblocked": [ids],
  "completed": [ids]}], "declined": [ids], "skipped": [{"id", "reason"}],
  "failed": [{"id", "code", "message", "exit_code"}], "not_asked": [ids],
  "waiting": N}`. A gate someone resolved meanwhile is skipped as `already
  open (resolved meanwhile)`, not a failure.
- **Exit codes.** 0, or the first failed resolve's code (the review goes
  on past it); a lost connection (8) or a lost answer (9) stops it. 2 in an
  agent session, without a terminal, or with the keychain unavailable; 7
  with no keychain token for the workspace, or one that is not a person's
  or was saved trusting another CA. Every message from the server, the
  workspace or the configuration is escaped to one line.

### Approvers

A human gate may name who may open it: actors, and accounts of OIDC
providers named by an [identity reference](#oidc-identity-references).

```toml
[steps.gate]
type = "human"
approvers = ["github:alice", "{{reviewer}}"]   # templated like other gate fields
```

or `bd gate create -t human --approver <actor>` (repeatable, or comma
separated) and `--oidc-approver <issuer> <subject>`, and `bd gate update
<id>` with either or both flags (replacing the list) or
`--clear-approvers` on an open gate. Approvers apply to human gates only.
A list holds 1 to 32 entries, each trimmed, at most 255 characters, with
no control characters, no `,`, and no `/` at either end; a later entry
equal to an earlier one ignoring ASCII case is dropped, and any other bad
entry (or a template that renders blank) is refused with exit 2. `bd gate
show` and `bd gate list` show them (`human by github:alice or
github:bob`), in text and in JSON (`spec.approvers`, `[]` for a stored
list that is not valid).

An approver `github:alice` matches the actor `github:alice` and its
sub-actors (`github:alice/laptop`), ignoring ASCII case, for tokens an
admin created and for GitHub sign-ins. A signed-in person acts as
`<provider>:<login>` ([Accounts and
actors](sign-in.md#accounts-and-actors)). An account signed in with an
OIDC provider (its token, the same token after a refresh, or a browser
approval) matches only the identity reference of its own issuer and
subject, by exact equality, and never an actor: not the actor bound to
the account at its first sign-in, not an actor shared with a linked
account, and not a sub-actor of either. No actor matches an identity
reference, however spelled. The login and the bound actor are not
identity proof ([Approvers and OIDC
accounts](sign-in.md#approvers-and-oidc-accounts)).

- **Locally** approvers are informational: anyone may resolve the gate,
  as with human gates themselves.
- **Through `bd serve`** only a human token that matches an approver
  opens the gate or moves the work it holds back past it, on every path a
  human token is needed for ([Roles and what tokens may
  do](remote.md#roles-and-what-tokens-may-do)), in batches, playbooks and
  imports too; an admin is no exception. A [browser
  approval](sign-in.md#approving-human-gates-in-the-browser) follows the
  same rule. Changing the approvers of an open human gate (`bd gate
  update`, `bd update --set-metadata`, an import) needs a human token
  that matches one of its approvers (of any person, when it has none) or
  a human admin's; agent tokens never may.
- **A stored list that is not valid** (written by hand with `bd update
  --set-metadata`, say, or holding an `oidc:sha256:` entry that is not
  canonical) does not change the gate's condition, but matches nobody:
  through `bd serve` nobody may open the gate until a human admin
  replaces or clears it with `bd gate update`. `bd gate show` says so.
  `bd playbook extract` refuses a step held by a gate with such a list
  until it is fixed, rather than write the step without its gate.
- **Lists naming OIDC accounts by actor** (`corp:alice` for an account of
  the OIDC provider `corp`), as written before identity references
  existed, fail closed: no OIDC account matches such a list any longer,
  and bd converts nothing. A human allowed to change the list (a human
  admin, or an approver whose token still matches) replaces the actor
  with the account's reference.

#### OIDC identity references

An identity reference names one account of an OIDC provider by the
issuer and subject (`sub`) of its ID tokens:

```text
oidc:sha256:<64 lowercase hex digits>
```

The digits are the SHA-256 of the bytes `bd:oidc-approver:v1` and a zero
byte, then the issuer and then the subject, each as its length in bytes
(8 bytes, big-endian) followed by its exact UTF-8 bytes. Nothing is
normalized: a different case, a trailing `/` on the issuer or spaces
around the subject give another reference, naming another account or
none.
Neither the provider's name in `auth.toml`, the login nor the actor goes
into the digest. The prefix `oidc:sha256:` is reserved in any ASCII case:
an entry under it that is not exactly this shape (uppercase hex, 63 or 65
digits, a suffix such as `/laptop`) is refused with exit 2 and never read
as an actor, and a stored list holding one matches nobody.

`--oidc-approver ISSUER SUBJECT` computes the reference on `bd gate
create` and `bd gate update`:

- Each occurrence takes exactly two values, taken verbatim: never split
  at `,`, never trimmed, and a subject may start with `-`. The flag may
  be repeated.
- The issuer has 1 to 4096 bytes with no whitespace or control
  characters; the subject has 1 to 255 bytes with no control characters
  and is not all whitespace.
- The list is the `--approver` entries in order, then the references in
  order, and the limit of 32 counts both. `--oidc-approver` cannot be
  combined with `--clear-approvers`.
- Errors never repeat the issuer or subject, and the commands print only
  the stored list (an `approvers` line in text), so references appear
  and the raw issuer and subject do not.

A playbook names no issuer or subject: its `approvers` take the
canonical reference as a string, a literal or a variable's value. To get
one, create or update a gate with `--oidc-approver` and copy the entry
from `bd gate show <id> --json` (`spec.approvers`):

```bash
bd gate update t-12.gate-publish --oidc-approver https://login.example.com 248289761001
bd gate show t-12.gate-publish --json | jq -r '.spec.approvers[]'
```

A reference is only as good as the issuer and subject it was computed
from: obtain the pair from a source that verifies the pair ([Approvers and OIDC
accounts](sign-in.md#approvers-and-oidc-accounts)). A reference copied
from elsewhere proves nothing about whose account it names. References
are linkable identifiers, the same for the same account on every gate
and server, not anonymization.

People can approve a human gate in a browser at `<public-url>/w/<workspace>/gates/<gate id>`
([Approving human gates in the
browser](sign-in.md#approving-human-gates-in-the-browser)). The gate is
resolved as their actor, with the reason `approved in the browser by
<actor>`, and its `closed` event carries `"via": "browser"`.
