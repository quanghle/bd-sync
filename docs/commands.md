# Command reference

Every command takes `--help` for its full options (`bd claim --help`,
`bd serve token create --help`). This page groups the commands, then lists
the global options, environment variables, configuration keys, exit codes
and error codes.

## Commands

| area | commands | see |
|---|---|---|
| Workspace | `init` (`--prefix`, `--id-mode hash\|counter`), `info`, `config get/set/unset/list`, `rename-prefix`, `stats`, `doctor`, `version`, `completion bash\|zsh\|fish\|powershell\|elvish` | [Configuration](#configuration), [Renaming the prefix](#renaming-the-prefix), [Observability](observability.md), [Shell completions](install.md#shell-completions) |
| Issues | `create`, `q`, `show` (`--as-of`), `list`, `query`, `update`, `edit`, `close`, `duplicate`, `supersede`, `find-duplicates`, `reopen`, `defer`, `undefer`, `delete`, `label add/rm/list`, `compact` (`--analyze`, `--apply`, `--stats`) | [Issues](concepts.md#issues), [Query language](#query-language), [Compaction](#compaction) |
| Dependencies | `dep add/rm/list/tree/cycles`, `blocked`, `graph` | [Dependency types](concepts.md#dependency-types), [Graph export](#graph-export) |
| Epics and hierarchy | `epic status/close-eligible`, `children`, `stale`, `orphans` | [Epics and hierarchy](#epics-and-hierarchy) |
| Ready work and claims | `ready`, `claim` (`--next`), `heartbeat` (`hb`), `release` (`unclaim`), `reclaim`, `leases` | [Ready work](concepts.md#ready-work), [Claims](concepts.md#claims-leases-and-recovery) |
| Comments and memory | `comment add/list`, `comments`, `remember`, `recall`, `memories`, `forget`, `memory add/get/list/rm` | [Comments and memory](concepts.md#comments-and-memory) |
| Events | `events` (`--follow`, `--wait`, `prune`), `history` (`--diff`), `show --as-of` | [Event history](concepts.md#event-history), [Reading an issue as of a past moment](concepts.md#reading-an-issue-as-of-a-past-moment) |
| Agents | `prime`, `hook session-start/subagent-start/pre-tool-use`, `setup`, `agents manifest/status/pull/approve/watch`, `mcp` | [Agent assets](agents.md), [Setup and the Claude Code plugin](setup.md), [MCP server](mcp.md) |
| Playbooks and gates | `playbook list/show/plan/run/status/runs/compact/discard/extract`, `gate list/show/check/resolve/create`, `purge` | [Playbooks](playbooks.md) |
| Data | `export`, `import`, `batch`, `backup` | [below](#data) |
| GitHub | `github status/pull/push/sync` | [GitHub Issues sync](github.md) |
| Operations | `metrics`, `bench` | [Observability](observability.md), [Benchmarks](benchmarks.md) |
| Remote | `serve`, `serve check`, `serve token create/list/revoke/events/accounts/link/name`, `remote set/show/unset/login/logout` | [Remote server](remote.md), [Signing in](sign-in.md) |

`rm` subcommands also answer to `remove`, and `list` subcommands of
`playbook`, `gate` and `serve token` to `ls`.

### Issues

```bash
bd create "Title" -d "why and what" -t task -p 2 [-a ASSIGNEE] [-l a,b] [--parent ID] [--dep TYPE:ID]
          [--design T] [--acceptance T] [--notes T] [--estimate MIN] [--due WHEN] [--defer WHEN]
          [--external-ref REF] [--metadata JSON] [--id ID] [--pinned] [--ephemeral] [--claim]
bd q "Title" [-d T] [-t TYPE] [-p N] [-l a,b] [--parent ID] [--dep TYPE:ID]   # prints only the new id
bd update ID [--title T] [-d T] [--status S] [-p N] [-t TYPE] [-a A] [--append-notes T]
          [--add-label L] [--remove-label L] [--set-labels a,b] [--parent ID]
          [--set-metadata K=V] [--unset-metadata K] [--ephemeral BOOL] [--if-revision N] [--take-over] ...
bd show ID... [--brief] [--comments-tail N] [--why]
bd list [-s S,S] [--search TEXT] [--all] [--blocked] [--sort priority|created|updated|id] [--reverse] [-n 100] [--brief] [filters]
        [--created-after T] [--created-before T] [--updated-after T] [--updated-before T]
        [--closed-after T] [--closed-before T] [--overdue] [--stale DURATION] [--title-contains TEXT]
bd ready [-n 50] [--brief] [--explain] [--sort priority|hybrid|oldest] [--include-deferred] [--include-epics] [filters]
bd edit ID [--field title|description|design|acceptance|notes]   # in $VISUAL/$EDITOR; terminal only, not through bd serve
bd close ID... -r "reason" [--failed] [--token T] [--force] [--take-over]   # --reason, or --message
         [--claim-next [--ttl D] | --suggest-next] [-a A] [--unassigned] [-t T] [-l L] [--parent ID] [--sort S]
bd duplicate ID --of ID [--force] [--take-over] [--if-revision N]   # edge ID -> canonical, closes ID
bd supersede ID --with ID [--force] [--take-over] [--if-revision N] # edge ID -> newer, closes ID
bd find-duplicates [--threshold 0.8] [-n 50]    # likely duplicate pairs among open issues, read-only
bd delete ID... [--cascade] [--force] [--dry-run] [--take-over]
bd show ID... [--as-of SEQ|#SEQ|TIME|-DURATION]   # the issues as they were then, rebuilt from their events
bd history ID [--diff]                            # --diff: each changed field's old and new value
```

`--brief` keeps only what an agent needs to pick up work: id, title,
status, priority, type, and assignee, parent and labels when set (in JSON
under the same key names as the full issue). Text puts one issue on a line,
`ID P2 task open @alice parent:ID [a,b] — Title`. `bd show --brief` also
gives the description cut to 500 characters (`description_truncated: true`
when cut), the ids of open blockers and the last 3 comments, with
`comments_total`. `--comments-tail N` keeps only the last N comments, with or
without `--brief` (JSON then adds `comments_total`). `bd ready` shows at most
`-n` issues (default 50, `-n 0` for all); when it cut the list, its text ends
with `-- more ready issues not shown`, while `--json` stays a plain array. The
[MCP](mcp.md#results) `ready` and `list` tools always run in brief mode,
and `show` does with `brief: true`.

`bd show ID --why` says whether the issue is ready and, if not, every reason:
its status, a claim (holder and lease expiry, never the token), each open
blocker with how it blocks (`blocks`, `conditional`, `waits_for` with its
gate, `parent` for a blocked parent, with `root`: the ancestor up from it
that something other than its parent blocks, and those blockers; `gate`
also names the kind of a gate issue that blocks it), a deferral of the issue or an ancestor, open children
coming first, or a type the queue leaves out (epic, gate). Text adds
`Ready: yes` or a `Not ready:` list after the status lines; JSON adds
`why: {ready, reasons: [{kind, ...}]}` to each issue, brief or full.
`bd ready --explain` adds each ready issue's order key (`order`, with
`rank`) and lists the open issues the same filters match that are not ready
(blocked, deferred or waiting on their children; epics and gates follow
ready's own rules) with the same reasons, each list bounded by `-n`. Its JSON
is an object, `{sort, ready: [brief + rank, order], more_ready, not_ready:
[brief + reasons], more_not_ready}`. Both read a few index lookups per issue,
never a recompute. A claim refused as not ready points to `--why`.

`bd close ID --claim-next` closes and then claims the next ready issue in
the same write transaction, so the two take effect together or not at all
(in `bd batch` too, where a later line failing rolls both back). It looks
first below the first named issue's parent (its other children, at any
depth: `from: siblings`), then in the whole queue (`from: queue`); the parent
itself, ready once its last child closed, comes in normal queue order. The
filters `-a`, `--unassigned`, `-t`, `-l` (all of the labels), `--parent` (only
that subtree, with no fallback to the queue) and `--sort` (default
`priority`) narrow the search as they do for `bd claim --next`, and `--ttl`
sets the new lease (default `lease.ttl`, as for `bd claim`). With
`lease.auto_reclaim` on, leases expired past `lease.grace` are reclaimed
first, as `bd claim --next` does. It claims nothing when every issue named was
already closed, so a retried close does not claim a second issue.
`--suggest-next` names the same issue without claiming it or writing
anything: an issue held by a dead claim that `--claim-next` would reclaim is
named as it stands (still held), and `bd claim` reclaims it. The filters and
`--ttl` are checked before anything closes, so a bad one fails (exit 2) even
when nothing would close. Without one of the two modes, the filter flags and
`--ttl` are refused (exit 2), as are both modes together.
With a mode, `--json` gives `{closed, next}`: `closed` is what `bd close`
alone prints, and `next` is null or `{from, parent, issue, lease,
reclaimed}` (`lease.token` is the new fencing token; `--suggest-next` has
no lease). Text prints the claim as `bd claim` does under `→ Next (from
siblings under ID):`, or `→ Suggested next (…): … (bd claim ID)`.

`bd q` is quick capture: it takes the title and the `create` flags `-d`, `-t`,
`-p`, `-l`, `--parent` and `--dep`, creates the issue exactly as `bd create`
does (same validation and events), and prints only the id, with or without
`-q`, for `ID=$(bd q "Fix login" -p 1)`. With `--json` it prints what
`bd create --json` prints.

`bd edit` edits one field (default `description`) in an editor, for text too
long for a flag. The field is written to a private temporary file and opened
in `$VISUAL`, else `$EDITOR`, else `vi` (`notepad` on Windows); the value may
carry arguments, as in `EDITOR='code --wait'`. Line ends are normalized
(CRLF to LF, trailing ones stripped) before comparing with the original.
Unchanged text writes nothing (`= ID description unchanged`). Otherwise the
issue is updated with `--if-revision` set to the revision read before
editing: an issue changed meanwhile is not overwritten but refused (exit 13),
and the edited text stays in the temporary file, whose path is printed (it is
also kept when the title is empty or has several lines, exit 2). An editor
that exits non-zero changes nothing. `bd edit` needs a terminal on stdin
(exit 2 otherwise, pointing to `bd update`) and runs only on the machine
holding the workspace, so `bd serve` refuses it.

`bd duplicate X --of Y` and `bd supersede X --with Y` add a `duplicates` or
`supersedes` edge from X to Y and close X in one transaction, with outcome
`done` and the reason `duplicate of Y` or `superseded by Y`. Nothing else
moves: X keeps its children, labels, comments and other edges, and Y is not
touched. They are refused, with nothing written, for the same issue named
twice (exit 2), a missing issue (3), another actor's live claim without
`--take-over` (4), open children or blockers on X without `--force` (2), a
failed `--if-revision`, `--if-status` or `--if-assignee` (13), and, each with
exit 2, a Y that is itself closed as a duplicate (or superseded: the message
names its root), an edge back from Y to X, another type of edge between the
two in either direction, and an X that is closed already without that edge. An X closed already
with that edge makes the command a no-op. See
[dependency types](concepts.md#dependency-types) for the direction.

#### Finding duplicates

`bd find-duplicates` compares every pair of unfinished issues (open,
in progress, blocked or deferred) and lists the pairs that score at least
`--threshold` (default 0.8, above 0 and at most 1; anything else is a usage
error, exit 2), best first, at most `-n` pairs (default 50, 0 for all). The
score is the larger of two similarities: the share of character trigrams the
normalized titles have in common (so a typo or a plural still scores high),
and the share of words the title and description texts have in common (common
words and single characters left out). Closed and pinned issues, ephemeral
issues, gates and playbook run issues are not compared. In each pair `a` is
the older issue, usually the one to keep. The JSON output is an array of
`{a, b, score}`, with each issue as a summary (`id`, `title`, `status`,
`priority`, `issue_type`, `assignee`) and the score rounded to three
decimals. The text output shows two lines per pair and ends with the count
and a hint. The comparison is pairwise, so time grows with the square of the
number of open issues, and it suits workspaces of up to some thousands. Through
`bd serve` at most 1000 pairs are returned (`-n 0` means 1000 there).

The command only reads, so it also runs through `bd serve`. Act on a pair with
`bd duplicate B --of A`.

Times (`--due`, `--defer`, `--until`) take a date (`2026-01-15`), an
offset (`+2d`) or RFC 3339. Status values accept `wip`/`inprogress` for
`in_progress` and `done` for `closed`.

`show --as-of` takes an event seq (`120` or `#120`: the state just after
that event), a time as above, or `-DURATION` for that long ago (`-2h`).
It prints the fields it can rebuild from the issue's events and lists
what it cannot (see [Reading an issue as of a past
moment](concepts.md#reading-an-issue-as-of-a-past-moment)); a point
before the retained history exits 6 (`history_pruned`), unless the issue
had not been created yet then.

### Compaction

```bash
bd compact --analyze [--older-than 30d] [-n 20] [--json]     # closed issues to summarise, with their text
bd compact --apply ID --if-revision N --summary TEXT|@FILE|-  # the summary replaces the issue's text
bd compact --stats [--older-than 30d] [--json]               # closed, compacted, bytes saved, candidates
```

An agent summarises old closed issues: `--analyze` lists them (closed at
least `--older-than` ago, not ephemeral, never compacted, with text), oldest
closed first, `-n` at a time (0 = all); `--apply` puts the summary in place of
the description, design, acceptance criteria and notes of a closed issue,
whose revision must still be `--if-revision` (exit 13 if not). The summary
must be shorter than the text it replaces. `@FILE` reads a file, `-` stdin;
through `bd serve` the client sends either with the command. `--analyze` and
`--stats` need a read token, `--apply` a write token. See
[Compaction](concepts.md#compaction).

Time filters of `bd list` and `bd ready` take the same times, except that a
bare duration counts back from now: `--created-after 7d` keeps issues
created within the last 7 days (`-7d` means the same), and `+7d` is 7 days
from now. Each `--X-after T` keeps issues with X at or after T, and each
`--X-before T` those with X before T, so adjacent windows never overlap.
Only closed issues have a closed time, so `--closed-after`/`--closed-before`
without `--status` imply `--all`; `bd ready` has no closed bounds.
`--overdue` keeps issues not closed whose due time has passed; `--stale 14d`
keeps open and in-progress issues not updated within 14 days.
`--title-contains TEXT` matches the title only, ignoring ASCII case, with `%`
and `_` taken literally. `--no-assignee` is another name for `--unassigned`.

### Query language

```bash
bd query EXPR... [--sort priority|created|updated|id] [--reverse] [-n 100] [--parse-only]
```

`bd query` lists the issues an expression matches, sorted and limited like
`bd list` (`--json` prints the same array of issues). Every status is
searched: no status is left out unless the expression says so
(`status != closed`). The words of the expression are joined with single
spaces, so simple expressions need no outer quotes, and error columns refer
to the joined text.

```ebnf
query      = or ;
or         = and , { "OR" , and } ;
and        = unary , { "AND" , unary } ;
unary      = "NOT" , unary | "(" , or , ")" | comparison ;
comparison = field , op , value ;
op         = "=" | "!=" | "<" | "<=" | ">" | ">=" | "~" ;
value      = word | "'" , { char } , "'" | '"' , { char } , '"' ;
word       = char - ( space | "(" | ")" | "=" | "!" | "<" | ">" | "~" | '"' | "'" ) ,
             { char - ( space | "(" | ")" | "=" | "!" | "<" | ">" | "~" | '"' | "'" ) } ;
```

`AND`, `OR`, `NOT`, `none` and field names are case-insensitive; `NOT`
binds tighter than `AND`, and `AND` tighter than `OR`. Keywords are only
keywords where one is expected: in value position every word is a value
(`title = and`). Quoted strings take the escapes `\\`, `\'` and `\"`, and no
other. The bare word `none` means absent; quoted, `"none"` is the word.

| field | values | operators | `none` |
| --- | --- | --- | --- |
| `status` | a status (`wip`, `done` accepted) | `=` `!=` | |
| `priority` | `0`-`4` or `P0`-`P4` | `=` `!=` `<` `<=` `>` `>=` | |
| `type` | an issue type (lowercased) | `=` `!=` `~` | |
| `assignee` | an actor | `=` `!=` `~` | no assignee |
| `label` | a label: `=` has it, `!=` does not, `~` has one containing the text | `=` `!=` `~` | no labels |
| `title`, `description`, `notes` | text: `=` the whole field, `~` a part of it | `=` `!=` `~` | |
| `id` | an id; with `=`, `*` matches any characters (`bd-12*`) and nothing else is special | `=` `!=` `~` | |
| `parent` | the direct parent's id, resolved like `--parent` (exact id, then `<prefix>-ID`, then a unique id prefix); an id that matches nothing matches no issue, an ambiguous one is an error | `=` `!=` | no parent |
| `external_ref` | an external reference, such as `gh:owner/name#N` (the repository lowercased) for a linked GitHub issue: `=` the whole reference (case-sensitive), `~` a part of it | `=` `!=` `~` | no external reference |
| `created`, `updated` | a time; with `=`/`!=` a date | `=` `!=` `<` `<=` `>` `>=` | |
| `closed`, `due`, `defer` | a time; with `=`/`!=` a date or `none` | `=` `!=` `<` `<=` `>` `>=` | not set |
| `pinned`, `ephemeral` | `true`/`false` (`yes`/`no`, `1`/`0`) | `=` `!=` | |

`~` ignores ASCII case only, and takes `%` and `_` literally; `=` on text
is exact and case-sensitive.

Times: a time is anything `--created-after` takes. A bare duration counts
back from now and `+` counts forward: `created > 7d` keeps issues created
within the last 7 days (after now minus 7 days), `due < +3d` those due
before 3 days from now, and `updated < 30d` those not updated in 30 days.
Dates and RFC 3339 times are absolute (`closed >= 2026-01-01`). `=` and
`!=` on a time take only a date (`YYYY-MM-DD`), meaning that local day,
midnight to midnight (`created = 2026-01-15`), or `none`.

Comparisons are two-valued: a comparison on an absent field (no assignee, no
due time, no parent) is false, except `= none`. `a != b` is exactly
`NOT a = b`, and `NOT` is the exact complement, so `assignee != bob`
includes unassigned issues and `NOT due < now` includes issues with no due
time.

Limits: at most 4096 bytes, 128 comparisons and a nesting depth of 32.
Every `NOT` and every opening parenthesis adds one level for what it
encloses (`NOT (a = x)` is depth 2, `NOT NOT NOT a = x` depth 3), and the
error points at the `NOT` or `(` that crosses the limit. They keep the SQL
an expression compiles to far within SQLite's limits.

Errors (exit 2) give the column, then the expression with a caret under it:

```text
error: query: column 19: unknown field "bogus" (fields: status, priority, ...)
  status = open AND bogus = 1
                    ^
```

`--parse-only` prints the parsed expression without opening a workspace:
in canonical form (keywords upper case, values quoted, parentheses only
where the grouping needs them), or as a JSON tree with `--json`
(`{"and": [...]}`, `{"or": [...]}`, `{"not": ...}`, and
`{"field", "op", "value"}` with `null` for `none`). The canonical text
parses back to the same expression. It can be longer than the query it came
from (quotes, spaces, escapes, `wip` written `"in_progress"`), at most twice
as long plus 14 bytes a comparison, so a query over 4096 bytes is accepted
when it is exactly canonical text, up to 10240 bytes.

```bash
bd query 'status = open AND (priority <= 1 OR label = urgent)'
bd query 'updated < 30d AND status != closed' --sort updated
bd query 'assignee = none AND type = bug AND NOT label = triaged'
bd query 'parent = bd-7 AND status != closed' --json
bd query 'id = bd-12*' --parse-only          # id = "bd-12*"
bd query '(title ~ draft OR label = wip) AND NOT (status = closed)' --parse-only
                                             # (title ~ "draft" OR label = "wip") AND NOT status = "closed"
```

### Epics and hierarchy

```bash
bd epic status [ID] [--all]
bd epic close-eligible [--close] [-r REASON] [--force] [--take-over]
bd children ID [--recursive]
bd stale [--days N] [-n LIMIT]
bd orphans [--prefix PREFIX]
```

- **`bd epic status`** reports on ID (an issue of any type: a playbook run
  or an ordinary parent works too), or else on every epic that is not
  closed (every epic with `--all`), in id order. The counts are recursive,
  over every descendant at any depth: `total`, `closed`, `open`,
  `in_progress`, and `blocked`, the descendants that are neither closed nor
  pinned and carry the materialized blocked flag (`is_blocked`, what
  `bd blocked` lists), so they also count as open or in progress.
  `percent` is `floor(100 * closed / total)`, so 100 means everything is
  closed, and `null` without descendants. `--json` prints
  `{id, title, status, issue_type, total, closed, open, in_progress,
  blocked, percent, close_eligible}`, one object for an ID and a list
  otherwise.
- **`bd epic close-eligible`** lists the epics that are eligible to close:
  epics that are not closed, have at least one child, and whose direct
  children are all closed. These are the epics `bd stats` lists as ready to
  close, and `close_eligible` in `bd epic status` says the same. Nothing
  changes without `--close`. `--close` closes every eligible epic in one
  transaction, all or none, with the reason (default `All children
  closed`). The claim rules of `bd close` apply: if another actor holds a
  live claim on any of them, nothing closes and the command exits 4 naming
  the holder, unless `--take-over` is given (recorded as `claim_override`
  in the `closed` event). `--force` gets past open blockers only, never a
  claim. Closing an epic can make its parent epic eligible; run it again to
  close that one too.
- **`bd children`** lists the direct children of ID, or every descendant
  with `--recursive`, in creation order and across every status, closed
  ones included. Text output nests descendants under their parents as
  `bd list` does; `--json` prints full issues, the `bd list --json` shape.
- **`bd stale`** lists open and in-progress issues that were not updated in
  the last N days (default 30; `stale: true`), and in-progress issues whose
  claim lease has expired (`expires_at` at or before now), however recently
  they were updated: those carry `lease_holder` and `lease_expired_at`.
  Rows are ordered by `updated_at`, oldest first, then by id. A claim
  expired for longer than `lease.grace` is dead, and `bd reclaim` frees it.
- **`bd orphans`** finds text that names issues that do not exist. It
  reads the title, description, design, acceptance criteria, notes, close
  reason and comments of every issue. A reference is a whole token as
  [`bd rename-prefix`](#renaming-the-prefix) reads one: a maximal run of
  letters, digits, `_`, `.` and `-` not preceded by such a character, with
  trailing `.`, `-` and `_` dropped, that starts with `PREFIX-` (default:
  the `issue_prefix`). It dangles when neither the token nor any part of it
  before a `.` is an issue id: `bd-7.2` is fine while `bd-7` exists.
  `--json` prints `[{id, title, references: [{id, field}]}]`, where `field`
  is `title`, `description`, `design`, `acceptance_criteria`, `notes`,
  `close_reason` or `comment`. Dependencies are not checked because they
  cannot dangle: foreign keys (`ON DELETE CASCADE`) are enforced on every
  connection, and imports skip edges to missing issues; `bd doctor` checks
  foreign keys in a damaged file.

### Graph export

```bash
bd graph ID|--all [--format text|dot|html] [--edges TYPE,...|all] [--max-nodes N] [-o FILE]
```

- **Selection.** With ID: ID and every issue reachable from it by following
  edges only down (what it depends on, then what those depend on, and so
  on) or only up (what depends on it, and so on). The walk never turns
  around, so a sibling that shares a blocker with ID is left out. It is
  breadth first: nearer issues first, and issues at the same distance in id
  order. With `--all`: every issue that is neither closed nor pinned, in id
  order. One of ID and `--all` is required (exit 2 otherwise).
- **Edges.** `--edges` takes dependency types, comma-separated (the names
  `bd dep add --type` accepts), or `all`. The default is every type but
  `related`, as in `bd dep tree`. The selected types are followed by the
  walk, and every edge of a selected type between two included issues is
  drawn. An invalid type exits 2.
- **Limit.** At most `--max-nodes` issues (default 200, 1 to 2000), the
  starting issue included. Past it the walk stops (or `--all` keeps the
  first N by id), and the output says it was truncated: a footer line in
  text, a `// truncated` comment in DOT, a banner in HTML, and
  `truncated: true` in JSON.
- **Direction.** Arrows run from what an issue depends on to the issue: a
  blocker to what it blocks, a parent to its children.
- **Formats.** `text` (the default) draws a tree from prerequisites to
  dependents with `├─`, `└─` and `│` and the edge type before each issue;
  the issues no arrow points to start trees, in id order, then any issues
  left (in cycles). An issue reached again is marked `(shown above)` and
  not expanded again, and past 64 levels lines stop indenting and say
  their depth. `dot` is a Graphviz `digraph` (render it with
  `dot -Tsvg deps.dot -o deps.svg`): each node labelled `id · status · P#`
  over its title and filled by status, each edge labelled with its type
  and styled by it (`blocks` bold, `conditional-blocks` dashed, `waits-for`
  dotted, `parent-child` gray with a hollow head, `related` gray, dashed
  and without direction, other types gray and dotted). `html` is one
  self-contained page: an SVG drawing in columns, each issue placed after
  the longest chain of prerequisites before it, with a legend and light
  and dark colours. It contains no script and loads nothing (its
  Content-Security-Policy allows inline styles only), and an issue's full
  title shows as its tooltip.
- **Escaping.** Titles are made printable first (control and
  bidirectional characters shown as `\uXXXX`, as on the terminal) and cut
  to 60 characters, then escaped for the format: `\`, `"` and newlines in
  DOT strings, `&`, `<`, `>`, `"` and `'` in HTML.
- **Output.** Without `-o` the rendering goes to stdout, and `--json`
  prints `{root, nodes: [{id, title, status, priority, issue_type,
  is_blocked, assignee}], edges: [{issue, depends_on, type}], truncated,
  max_nodes}` instead. `-o FILE` writes the rendering to FILE through a
  temp file next to it, then prints `✓ Wrote graph (N issues, M edges) to
  FILE` (`--json`: `{output, nodes, edges, truncated}`). In a remote
  workspace the server sends the file and the client writes it on its own
  machine, as with `bd export -o`.

### Data

- **`bd export [-o FILE]`** writes JSONL: a header with `head_seq`, then
  issues, dependencies, comments and memories. `--no-memories`,
  `--open-only`, `--include-ephemeral`.
- **`bd import FILE`** reads bd or beads JSONL, all or nothing.
  `--dry-run` validates and reports without writing, adding a per-field
  report of what is mapped, kept in `metadata.beads` or dropped
  ([beads fields](beads.md#import-what-happens-to-each-beads-field));
  `--lenient` keeps unknown issue types and maps unknown statuses to `open`;
  `--take-over` imports over other actors' live claims.
- **`bd batch [-f FILE]`** (default stdin) runs many writes in one
  transaction: each line is a subcommand with its usual flags (`create`,
  `update`, `close`, `duplicate`, `supersede`, `dep add`, …), `$N` stands
  for the id produced by the Nth operation, and `#` starts a comment. Any
  failure rolls back everything; `--dry-run` runs everything, reports, then
  rolls back. `compact ID --summary TEXT --if-revision N` (or `compact
  --apply ID ...`) is the apply form of `bd compact`, with the summary on
  the line itself: `--summary -` and `--summary @FILE` are refused there,
  as the batch's own input is the stdin or file
  ([Compaction](concepts.md#compaction)).
- **`bd backup --to DIR [--keep 24] [--name NAME]`** writes a verified copy
  of a local workspace's database ([Backing up](modes.md#backing-up-a-local-workspace)).

### Renaming the prefix

```bash
bd rename-prefix NEW [--from OLD] [--dry-run]
```

`bd config set issue_prefix` changes only the prefix of new ids;
`bd rename-prefix` also renames the existing issues, all in one
transaction, and then sets `issue_prefix` to `NEW`. `NEW` is normalized
like `config set issue_prefix` (lowercased, a trailing `-` dropped).

- **What is renamed.** Every issue whose id starts with `OLD-` becomes
  `NEW-` and the rest of its id, children included (`old-abc.1` becomes
  `new-abc.1`). `OLD` defaults to the current `issue_prefix`; `--from`
  names another, such as the prefix of imported issues or the old one
  after a `config set issue_prefix`. Other ids are left alone.
- **What moves with an issue:** both ends of its dependencies (with their
  type and metadata), labels, comments, its claim (same holder, token and
  expiry), its child counter (the next child of `new-abc` continues the
  numbering) and its event history (`bd history NEW-…`).
- **References.** JSON strings that equal a renamed id are rewritten in
  issue and dependency metadata (playbook runs and `issue` gates
  included, `<rig>:<id>` too) and in event payloads. An `issue` gate
  awaiting a unique partial id (`--await old-ab` for `old-abc`) awaits
  the renamed id; a partial that matched several ids already stays. In titles,
  descriptions, design, acceptance criteria, notes, close reasons,
  comments and memories, a whole-word id (or a child id of one, like
  `old-abc.2`) is rewritten when it names a renamed issue; look-alikes
  such as `old-abcd` with no such issue stay. Event payloads keep their
  text as recorded; only exact id strings change there.
- **Nested prefixes.** When `NEW` extends `OLD` (`bd` to `bd-sync`), ids
  that already start with `NEW-` are kept, not prefixed twice. Renaming
  back (`bd-sync` to `bd`) works too.
- **Conflicts refuse.** If a new id already belongs to an issue that is
  not being renamed, or would be longer than 255 characters, nothing
  changes and the command exits 2 naming the ids.
- **Live claims keep running** under the new ids: holders must use them
  from then on (their lease tokens stay valid). The output says how many
  claims moved.
- Revisions and `updated_at` are unchanged, so `--if-revision` guards
  taken on the new ids hold. `bd backup`'s default name follows
  `issue_prefix`, so later backups go to a new name.
- The event log records a `references_renamed` event on each issue whose
  text, close reason or metadata the rename rewrote (`from`, `to` and the
  `changes`, old and new), then a `config_set` of `issue_prefix` and one
  `prefix_renamed` event (from, to and the counts). Renaming to the current
  prefix does nothing. `--from NEW`, when the ids already carry `NEW-` and
  `issue_prefix` is another prefix, only sets `issue_prefix` (a
  `config_set` event, no `prefix_renamed`). A rename to another prefix
  that finds no ids still sets `issue_prefix` and records
  `prefix_renamed` with `renamed` 0.
- `--dry-run` reports the same counts, then rolls back.
- Through `bd serve` it needs an admin token. It is not available in
  `bd batch` or as an MCP tool.

## Global options

| option | env | meaning |
|---|---|---|
| `--db PATH` | `BD_DB` | database file (default: the nearest `.bd/bd.db` walking up from the current directory) |
| `--remote URL` | `BD_REMOTE` | a workspace on a bd server (default: `.bd/remote.toml`); not with `--db` |
| `-C, --directory DIR` | | run as if started in `DIR` |
| `--actor NAME` | | act as this actor (else `$BD_ACTOR`; [Actors](concepts.md#actors)) |
| `--session NAME` | | name this session, as `$BD_SESSION` does |
| `--json` | | machine-readable output; errors go to stderr as `{"error": {"code", "message", "exit_code"}}` |
| `-q, --quiet` | | minimal output (ids only) |
| `--log-format text\|json` | `BD_LOG_FORMAT` | diagnostics format on stderr (default text; filter with `BD_LOG`) |
| `--timing` | `BD_TIMING=1` | per-command timing on stderr |
| `--slow-ms MS` | `BD_SLOW_MS` | warn about operations slower than this (default 250) |
| `--busy-timeout-ms MS` | `BD_BUSY_TIMEOUT_MS` | how long a writer waits for the database write lock, and `bd agents` for a checkout's mutex (default 10000) |

## Environment variables

Besides those of the global options:

| variable | meaning |
|---|---|
| `BD_ACTOR`, then `BEADS_ACTOR` | the actor ([Actors](concepts.md#actors)) |
| `BD_SESSION` | name this session: act as `<user>/<harness session>.<NAME>` |
| `CLAUDE_CODE_SESSION_ID`, `COPILOT_AGENT_SESSION_ID`, `CODEX_THREAD_ID` (`CODEX_SESSION_ID`) | set by agent harnesses; give each session its own actor |
| `CLAUDE_ENV_FILE`, `CLAUDE_CONFIG_DIR`, `CODEX_HOME`, `COPILOT_HOME` | harness locations read by hooks and `bd agents pull` ([Agent assets](agents.md)) |
| `BD_LOG` | log filter, e.g. `bd=debug` or `bd::serve=debug` ([Observability](observability.md)) |
| `NO_COLOR` | no colors in logs |
| `BD_PLAYBOOK_PATH` | extra playbook directories, `:`-separated (`;` on Windows) |
| `BD_GH` | the `gh` binary GitHub gates and `bd github` run |
| `BD_TOKEN`, `BD_CA_CERT`, `BD_REMOTE_RETRY_SECS`, `BD_INSECURE_HTTP` | remote clients ([Environment](remote.md#environment)) |
| `BD_SERVE_ROOT`, `BD_SERVE_PUBLIC_URL` | `--root` of `bd serve`, `bd serve check` and `bd serve token`; `--public-url` of `bd serve` and `bd serve check` |
| `XDG_CONFIG_HOME`, `APPDATA`, `HOME`, `USERPROFILE` | where saved tokens and user playbooks live |
| `USER`, `USERNAME` | the user, when `git config user.name` is unset |

## Configuration

`bd config list|get|set|unset KEY [VALUE]`. Through `bd serve`, setting
and unsetting need an admin token.

| key | default | meaning |
|---|---|---|
| `issue_prefix` | set by `bd init` (from the directory name) | id prefix of new issues; cannot be unset; [`bd rename-prefix`](#renaming-the-prefix) renames existing ones |
| `id.mode` | `hash` | `hash` or `counter` |
| `lease.ttl` | `5m` | claim lease duration (at least 1s) |
| `lease.grace` | `10m` | how long past expiry before a claim is dead and reclaimable |
| `lease.auto_reclaim` | `true` | `claim --next` reclaims dead claims first, and `bd serve` reclaims them every minute |
| `claim.pools` | | comma-separated assignees anyone may claim from |
| `types.custom` | | extra issue types |
| `durability` | `normal` | SQLite `synchronous`: `off`, `normal`, `full` |
| `events.retain_days`, `events.retain_rows` | `0` | automatic event retention (`0` keeps everything) |
| `gate.repos` | | repositories GitHub gates may name: `OWNER/REPO`, `HOST/OWNER/REPO`, `OWNER/*`, `HOST/OWNER/*`, `*` (unset: any locally, only the workspace's own through `bd serve`) |
| `github.repos` | | repositories [`bd github`](github.md) may sync, with the syntax of `gate.repos` (unset: any locally, only the workspace's own through `bd serve`) |
| `github.assignees` | | `login=actor,...`: GitHub logins mapped to bd assignees by `bd github` |
| `github.priority_labels` | | label prefix `bd github` maps to priority, `<prefix>0`..`<prefix>4` (unset: no mapping) |
| `custom.*` | | free-form keys for your own tools |

## Exit codes

| code | meaning |
|---|---|
| 0 | ok |
| 1 | internal error (SQLite, JSON, I/O), a database written by a newer bd, or `doctor` found problems |
| 2 | invalid input, a cycle, or a refusal (such as `--force` on a command that has none) |
| 3 | not found, or no workspace |
| 4 | claim conflict: already claimed (a live claim, even your own actor's, without its `--token`), not claimable, not ready, another actor's live claim (`--take-over` takes it over), or lease lost |
| 5 | busy: the database write lock, a checkout's agent mutex or saved credentials stayed locked past `--busy-timeout-ms`; retry |
| 6 | event cursor or `--as-of` point older than what retention kept |
| 7 | access denied (remote): no token, an invalid or expired one, or one that does not allow this; a refused sign-in; a `max_claims` limit |
| 8 | bd server unreachable, its certificate not trusted, or a server failure: the command did not take effect |
| 9 | a write reached the bd server but its answer was lost: check before running it again |
| 13 | stale optimistic-concurrency guard (`--if-revision`, `--if-status`, `--if-assignee`) |
| 130 | `bd agents watch` interrupted twice |

With `--json`, errors are printed to stderr as `{"error": {"code",
"message", "exit_code"}}`. The codes:

| code | exit |
|---|---|
| `sqlite`, `json`, `io`, `schema_too_new` | 1 |
| `invalid`, `cycle`, `refused` | 2 |
| `not_found`, `no_workspace` | 3 |
| `already_claimed`, `not_claimable`, `not_ready`, `not_owner`, `lease_lost` | 4 |
| `busy` | 5 |
| `events_truncated`, `history_pruned` | 6 |
| `unauthorized` | 7 |
| `remote` | 8 |
| `answer_lost` | 9 |
| `conflict` | 13 |
