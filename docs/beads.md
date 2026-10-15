# Differences from beads

bd re-implements [beads](https://github.com/gastownhall/beads), the `bd`
issue tracker for AI coding agents, as a coordination engine on SQLite WAL.
It keeps beads' data model and command vocabulary, and changes how state is
stored, shared and guarded. This page is the only one that compares the
two; the rest of the documentation describes bd on its own.

## Data model and engine

Beads stores issues in an embedded Dolt (versioned SQL) database under
`.beads/` and syncs copies of it with `bd dolt push/pull`.

| concept | beads | bd |
|---|---|---|
| Issues | hash ids `prefix-<base36>` of adaptive length; child ids `parent.N` | same scheme, plus `id.mode = counter` |
| Dependencies | one typed edge per pair; cycle check by recursive CTE | same, and a cycle error shows the cycle's path |
| Ready work | materialized `is_blocked`, recomputed per affected set; ready = `open`, not blocked, not deferred | same model; deferral also hides grandchildren (beads checks one level) |
| `conditional-blocks` | documented as "runs only if the blocker fails", implemented like `blocks` | implemented as documented, through an explicit close outcome (`bd close --failed`) |
| Claims | `UPDATE … WHERE row_lock = ?` compare-and-swap, with Dolt merges and retries | `BEGIN IMMEDIATE`: read, check and write under SQLite's single writer lock, no retries |
| Leases | node-local `leases` table, 5 min TTL, `heartbeat`, `reclaim` with 2×TTL grace | same, plus a fencing token; `claim --next` reclaims dead claims first |
| Concurrency guards | random `row_lock`; `--if-assignee`/`--if-status` (exit 13) | a monotonic `revision` and the same guards |
| Events | audit table, plus an opt-in journal with gapless seq from a counter row | one always-on log; `AUTOINCREMENT` seq written in the change's own transaction |
| Memory | `config` rows `kv.memory.<key>` | a table of its own, with authorship, revisions and compare-and-set |
| Sharing | copies of the database synced with `bd dolt push/pull`: two disconnected machines can claim the same issue | one database, shared through `bd serve`, where claims stay atomic ([Remote server](remote.md)) |
| History | Dolt commits | the event log ([Event history](concepts.md#event-history)); `bd show --as-of` rebuilds an issue at a past seq or time |
| Compaction | `bd compact` (`--analyze`, `--apply`, `--stats`): summaries of old closed issues | `bd compact --analyze` / `--apply --if-revision N --summary` / `--stats`: the agent writes the summary, and the original stays in the event log while retained ([Compaction](concepts.md#compaction)); beads' compaction fields are not imported |

### Import: what happens to each beads field

`bd import` reads beads' export format ([Migrating](#migrating-from-go-beads)).
Every field of an issue line is mapped, kept or dropped:

| What | Fields |
|---|---|
| mapped to a bd column, label, edge, comment or gate | `id`, `title`, `description`, `design`, `acceptance_criteria`, `notes`, `status`, `priority`, `issue_type`, `assignee`, `created_by`, `external_ref`, `estimated_minutes`, `metadata`, the timestamps (`created_at`, `updated_at`, `started_at`, `closed_at`, `due_at`, `defer_until`), `close_reason`, `labels`, `dependencies`, `comments`, `ephemeral` (and the old `wisp`), `parent` when a parent-child edge backs it, and `await_type`, `await_id`, `timeout` and `waiters` when they form a gate |
| kept in `metadata.beads.<field>` | every other field: `owner`, `spec_id`, `closed_by_session`, `source_system`, `sender`, `mol_type`, `wisp_type`, `work_type`, the compaction fields, and any key bd does not know. A dependency's `thread_id` is kept in the edge's metadata as `beads.thread_id` |
| dropped | derived and node-local values bd computes itself: `is_blocked`, `revision`, `dependency_count`, `dependent_count`, `comment_count` and the lease fields; also every field of a tombstone or proto (template) line, which is skipped |

`owner` is kept rather than mapped: bd's `assignee` reserves claims (only
that actor may claim), which beads' owner, an attribution, does not mean,
and `created_by` is the creator. If `metadata.beads` already has a key, it
wins over the top-level field, which is counted as dropped, with a warning.
Exporting and importing again adds nothing, and importing the same file
again reports every issue unchanged.

Not carried over: beads' Dolt commit history.

## Commands kept from beads

`bd q` (quick capture, prints only the id), `bd edit` (one field in
`$VISUAL`/`$EDITOR`), `bd duplicate` and `bd supersede` keep beads' names and
meaning. The differences:

- `bd edit ID [--field ...]` edits one field, `description` by default, and
  writes it conditionally on the revision it read: a concurrent change is
  refused (exit 13) instead of overwritten, and the edited text stays in the
  printed temporary file. It runs only in a terminal on the machine holding
  the workspace, never through `bd serve`.
- `bd duplicate X --of Y` and `bd supersede X --with Y` add the edge from X to
  Y, as beads does, and close X in one transaction, honoring `--take-over`
  and the `--if-*` guards. Chains are refused (name the root).
- `bd find-duplicates` is a local similarity search over titles and
  descriptions ([Finding duplicates](commands.md#finding-duplicates)); beads'
  `--method ai` (a model) and its `bd duplicates` (merging by content hash)
  have no counterpart.

## Workflows: formulas become playbooks

| beads | bd |
|---|---|
| formula (`.beads/formulas/*.formula.toml`) | playbook (`.bd/playbooks/*.toml`; `*.formula.toml` files load too) |
| `bd cook`, then `bd mol pour` | `bd playbook run`, in one step (`bd playbook plan` previews) |
| proto (a template epic stored in the database) | none: the file is the template |
| molecule | run: an epic with one issue per step, ids `<run>.<step>` |
| wisp (`bd mol wisp`) | ephemeral run (`--ephemeral`, or `ephemeral = true`) |
| `bd mol bond` | `bd playbook run --parent <issue>` or `--after <issue>` |
| `bd mol squash` / `burn` / `distill` | `bd playbook compact` / `discard` / `extract` |
| `bd mol current` / `progress` | `bd playbook status`, `bd playbook runs` |
| gate | gate; arms when its step could start, rather than at creation |

Formula files load as playbooks as they are. The loader accepts beads'
spellings:

- top level: `formula` (for the name), `type = "workflow"` (any other type
  is refused), `phase = "vapor"` (ephemeral) and `"liquid"`/`"solid"`
  (persistent);
- steps: `depends_on` (for `needs`), `acceptance`, `estimated_minutes`,
  `with` (for `expand_vars`);
- gates: `id` (for `await_id`), `duration` (for `timeout`), type `bead`
  (for `issue`).

A step with `type = "human"` is refused, with a pointer to
[human gates](playbooks.md#gates).

## Migrating from Go beads

Export with the Go binary before uninstalling it:

```bash
beads export --all -o beads.jsonl       # the Go CLI (still named bd if not renamed)
bd init --prefix <same-prefix>          # the same prefix keeps new ids consistent
bd import beads.jsonl --dry-run         # preview, then run without --dry-run
bd doctor
git config --unset core.hooksPath       # beads routes git hooks to .beads/hooks
rm -rf .beads                           # once the import checks out
```

`--dry-run` adds a per-field report to the summary: `fields mapped`,
`fields kept in metadata.beads` and `fields dropped` list each field with
the number of lines that had it (the JSON summary has the same counts under
`fields`). Nothing is written.

The import is all or nothing. It keeps ids, statuses, priorities,
timestamps, close reasons, labels, dependencies, comments and memories.
Gates keep their condition (`metadata.gate`), wisps stay ephemeral, and
protos are skipped: copy the formula files to `.bd/playbooks/` instead.
`hooked` issues become `in_progress` with a fresh lease, and `tombstone`
rows are skipped. Issues imported with another prefix can be renamed
afterwards with `bd rename-prefix <prefix> --from <beads prefix>`
([Renaming the prefix](commands.md#renaming-the-prefix)).

After migrating:

- Replace agent hooks generated by beads (`bd prime --hook-json`,
  `bd codex-hook`, `bd cursor-hook`) with plain `bd prime`, or with
  `bd prime --hook <harness>` ([Session-start hooks](agents.md#session-start-hooks)).
- `$BEADS_ACTOR` still works: it is read after `$BD_ACTOR`
  ([Actors](concepts.md#actors)).
- Both binaries are named `bd`: put this one first on `PATH`.
