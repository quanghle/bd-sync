# GitHub Issues sync

`bd github` keeps bd issues and the issues of a GitHub repository in step,
both ways, through the [GitHub CLI](https://cli.github.com) (`gh`). It never
holds the database's write lock while it talks to GitHub: a run reads a
snapshot, fetches, makes its GitHub writes, then applies everything in one
write transaction.

## Commands

| command | does |
|---|---|
| `bd github status` | shows what a sync would do; changes nothing and fetches no comments |
| `bd github pull` | brings GitHub issues, their changes and comments into bd |
| `bd github push` | sends bd changes of linked issues to GitHub |
| `bd github sync` | both, in one run |

Every subcommand takes:

| flag | meaning |
|---|---|
| `--repo OWNER/REPO` (or `HOST/OWNER/REPO`) | the repository (default: the one `gh repo view` sees in the workspace directory) |
| `--label L` | only GitHub issues with this label (and, with `--create`, bd issues with it) |
| `--state open\|all` | which GitHub issues to list (default `open`) |
| `--prefer local\|github\|newer` | who wins when both sides changed an issue (default: report a conflict) |

`pull`, `push` and `sync` take `--dry-run`. `push` and `sync` also take
`--create` (create GitHub issues for bd issues carrying `--label`; refused
without `--label`, so a whole workspace is never published by accident)
and `--comments` (post bd comments GitHub does not have yet).

```bash
bd github pull --repo acme/app --state all
bd github sync --prefer newer --comments
bd github push --create --label sync --dry-run
```

`$BD_GH` names another `gh` binary. The exit code is 0 when the run
finished, conflicts and refused changes included (they are reported per
issue), and 1 when GitHub writes were stopped partway (see
[Failures](#rate-limits-and-failures)).

## Linking

A linked bd issue has `external_ref` `gh:owner/name#N` (the repository
lowercased; `gh:host/owner/name#N` off github.com) and a `metadata.github`
object:

| field | holds |
|---|---|
| `repo`, `number`, `node_id`, `url`, `updated_at` | the GitHub issue |
| `github_hash`, `local_hash` | the hash of each side's synced fields when that side was last synced |
| `assignee`, `github_priority` | GitHub's first assignee and priority label then; `local_assignee`, `local_priority`: bd's assignee and priority then |
| `comments` | GitHub comment id → bd comment id, of every comment synced either way |
| `comment_count` | GitHub's comment count at the last fetch (see [Comments](#comments)) |
| `own_local_at`, `own_github_at` | when bd github last wrote each side itself |
| `local_edit_at`, `github_edit_at` | a side's last real edit, noted while it waited to be synced |

`bd query 'external_ref = gh:owner/name#N'` finds the bd issue linked to
GitHub issue N (the repository lowercased), and
`bd query 'external_ref ~ gh:owner/name#'` all of a github.com
repository's.

## Mapping

| GitHub | bd |
|---|---|
| title | title |
| body | description: CRLF as LF, trailing whitespace trimmed, a final issue-marker line left out |
| open / closed | open (any status but closed) / closed |
| `state_reason` `not_planned` | close outcome `failed`; `completed`, `duplicate`, other reasons or none close as `done`; from bd, `failed` closes as `not_planned`, `done` as `completed` |
| labels | labels, over the values both sides can hold |
| `<prefix>0`..`<prefix>4` labels (`github.priority_labels`) | priority: the lowest number wins; never copied into bd labels |
| first assignee | assignee, through `github.assignees` (`login=actor,...`) |

New bd issues pulled from GitHub are tasks. Labels GitHub cannot hold (over
50 characters) or bd cannot hold (commas, control characters, over 128
characters, priority labels) are left out of the comparison, and never
removed from the side that has them.

Writes change only the fields where the sides differ, and keep what the
other side cannot represent:

- a pull adds and removes labels (never replaces the set), changes the
  priority only when GitHub has a differing priority label, and clears the
  bd assignee only when GitHub dropped or replaced the assignee that mapped
  to it: an unmapped bd assignee is never cleared;
- a push PATCHes only the differing fields; `labels` is GitHub's list with
  bd's changes merged in, keeping labels bd cannot hold and higher-numbered
  priority labels; a priority label is written when bd's priority differs
  from GitHub's label, or, with no label on GitHub, when bd's priority
  changed since the last sync; `assignees` is sent only to replace the
  first assignee with another mapped login (keeping the others), or to
  remove it when bd unassigned the actor it mapped to; a marker already in
  the GitHub body is kept.

**Outcomes.** A change of close outcome between two closed states goes both
ways. On bd it is applied by reopening the issue and closing it again with
the new outcome, so the usual checks apply (open children, blockers,
another actor's claim) and the history shows `reopened` and `closed`; a
refusal is reported and retried by the next run. On GitHub, which applies a
`state_reason` only along with a change of state, bd reopens the issue and
closes it again with the new reason.

## Changes, conflicts and deferred changes

Each side is projected to its synced fields and hashed. A side whose hash
differs from the one stored at its last sync changed.

- Neither changed: nothing to do.
- One changed: it wins when the command goes that way (`pull` carries
  GitHub changes, `push` bd changes, `sync` both). Otherwise the issue is
  **deferred** (`local change; run push`, or `GitHub change; run pull`) and
  neither side is marked synced: a pull never marks a pending bd edit as
  synced, nor a push a pending GitHub edit.
- Both changed (or the issue was never synced): when the sides already
  agree, they are recorded as synced; otherwise `--prefer` decides. Without
  it the issue is reported as a **conflict** (`--json` lists its id, number
  and both hashes) and its fields are left alone on both sides; its
  comments still flow. When the preferred side has nothing either can
  carry (a change the other cannot hold, such as an unmapped assignee), the
  other side's change goes instead, unless it would overwrite an assignee or
  priority the preferred side changed: then it is a conflict too.

`--prefer newer` picks the side edited last, leaving out bd github's own
writes: a Link written or a change pulled on bd, a PATCH or a comment posted
on GitHub. GitHub's `updated_at` also moves when anyone comments or reacts,
which counts as an edit there.

An issue claimed by another actor is never taken over: a GitHub close of it
is refused and reported, and an assignee change from GitHub of an
in_progress issue waits until its claim ends. Gates and ephemeral issues are
never synced.

## Issue markers

An issue `--create` makes on GitHub ends with `<!-- bd:<id> -->`. A listed
GitHub issue opened by the account `gh` is signed in as (`gh api user`),
whose body ends with the marker of an existing bd issue that is not linked
yet, is linked to it on every run (`linked`), never created again: a push
that crashed before recording its link duplicates nothing. A marker on an
issue anyone else opened is ignored, so no one can link a bd issue to their
own GitHub issue by writing its marker. When GitHub will not say which
account that is (`gh api user` refused, as for an App installation or
Actions token), every marker is ignored for the run, which goes on. A marker naming an issue linked
elsewhere, a gate or an ephemeral issue, or two GitHub issues naming the
same one, is reported as an error.

## Comments

- Comments are fetched only when GitHub's `comments` count differs from
  `comment_count`, so a run with no new comments makes no comment calls.
- Pulling directions import GitHub comments new to bd as bd comments,
  written by the syncing actor with a header naming the GitHub author, time
  and URL, whatever happens to the issue's fields (a conflict, a deferred
  change, a refused close).
- With `--comments`, push and sync post the bd comments GitHub does not have
  yet, each ending with a comment marker `<!-- bd:<id>#c<comment> -->`, and
  record their GitHub ids.
- A fetched comment carrying the marker of a comment of the same bd issue is
  recorded, never imported or posted again, in every direction: a push
  that crashed after posting duplicates nothing. A push-only run fetches
  comments for this only for issues with bd comments to post; it imports
  nothing, and records its count so that comments it did not import still
  reach the next pull.
- A bump of GitHub's `updated_at` alone (by a comment bd posted, say) is not
  a change and writes nothing.

## Creating GitHub issues

`push --create --label L` (or `sync`) creates a GitHub issue for each bd
issue that carries `L`, has no `external_ref`, is neither a gate nor
ephemeral, and is open (closed ones too with `--state all`). It carries the
title, the description and marker, the labels GitHub can hold, the priority
label and the mapped assignee; a closed bd issue is then closed on GitHub.
If closing fails, the link is still recorded and the next push closes it.

## Rate limits and failures

Listings read pages of 100 (`page=N`) until GitHub's `Link` header has no
next page. A rate-limited answer (403 or 429 with `x-ratelimit-remaining: 0`
and a reset, or `retry-after`) is retried after waiting, when the wait is at
most a minute, up to three times; otherwise the run fails, naming when the
limit resets.

A failure while fetching fails the run before anything is written. During
the GitHub writes, a validation or not-found answer for one issue is
reported for it and the others go on; a rate limit, an authentication or
permission failure, a server error, a timeout or a cancellation stops the
writes. What succeeded is still recorded, the rest is retried by the next
run, and the command exits 1.

A push GitHub accepts but answers without some of the fields sent (an
assignee it will not assign, say) is reported as `partial`, not `pushed`:
`! ID #N partial: FIELDS (GitHub did not apply FIELDS; the next push tries
again)` in text, `"action": "partial"` and a `partial` count in `--json`.
GitHub's side is recorded as synced and bd's is not, so the next push sends
those fields again.

## Configuration

| key | meaning |
|---|---|
| `github.repos` | repositories `bd github` may sync: `OWNER/REPO`, `HOST/OWNER/REPO`, `OWNER/*`, `HOST/OWNER/*`, `*` (unset: any locally, only the workspace's own through `bd serve`); a `--repo` it does not allow is refused before any GitHub call |
| `github.assignees` | `login=actor` pairs mapping GitHub logins to bd assignees |
| `github.priority_labels` | label prefix of priority labels, such as `P` or `priority:` (unset: no priority mapping) |

## Through bd serve

Every `bd github` subcommand needs an admin token: it acts with the
server's `gh` credentials, in the workspace's directory, and can publish
workspace content. `status` is a read, the others writes. Unless
`github.repos` allows others, only the workspace's own repository may be
synced. `bd github` is not an MCP tool.

## Events

A run writes the usual events of what it changes (`created`, `updated`,
including `metadata.github`, `closed`, `reopened`, `commented`), as the
command's actor (through bd serve, the token's). A run that changed
anything also writes one `github_synced` event with the repository, the
direction, the counts and the bd ids pushed, created and linked. A run that
changes nothing writes nothing.

## Limits

- A linked bd issue that is deleted is created again by the next pull,
  unless the GitHub issue's marker names an issue that still exists.
- Conflicting fields are not merged: one side wins as a whole.
- Edits and deletions of comments already synced are not synced.
- A comment deleted and another added on GitHub between two runs leave the
  count unchanged; the new one is fetched once the count differs again.
- Two syncs of the same repository at once are not coordinated.
- Markers are found only among the issues the run lists (its `--label` and
  `--state`).
- A pull change bd keeps refusing (an open child, another actor's claim) is
  retried and reported on every run until it can apply.
- Pull requests, milestones, projects, reactions and assignees beyond the
  first are not synced.
