# Setting up agent harnesses

`bd setup <harness>` writes what makes an agent harness's sessions in a
project use bd. Claude Code, Codex and Copilot CLI get hooks that run
`bd hook session-start` and `bd prime` when a session starts, so every
session begins with its actor, its claims with their lease tokens and the
ready work. Cursor, Gemini CLI and opencode get a section of instructions
telling the agent to run `bd prime`.

```bash
bd setup claude                 # hooks in .claude/settings.json
bd setup codex --dry-run        # show what would be written
bd setup opencode --remove      # take bd's section out of AGENTS.md
bd setup --list                 # every recipe, and whether it is set up here
```

| harness | mechanism | file | what is written |
|---|---|---|---|
| `claude` | hooks | `.claude/settings.json` | SessionStart (`bd hook session-start --harness claude`, `bd prime --hook claude`), SubagentStart (`bd hook subagent-start`) and PreToolUse (`bd hook pre-tool-use`), as in this repository's own settings |
| `codex` | hooks | `.codex/hooks.json` | SessionStart, matcher `startup\|resume\|clear\|compact`, `bd hook session-start --harness codex` and `bd prime --hook codex` |
| `copilot` | hooks | `.github/hooks/bd.json` | `version: 1`, sessionStart: `bd hook session-start --harness copilot` and `bd prime --hook copilot` |
| `cursor` | instructions | `.cursor/rules/bd.mdc` | a rule with `alwaysApply: true`, holding the bd section |
| `gemini` | instructions | `GEMINI.md` | the bd section |
| `opencode` | instructions | `AGENTS.md` | the bd section |

The bd section says that the project tracks its work with bd, to run
`bd prime` at the start of a session and again after the conversation is
compacted or summarized, and gives the core loop (`bd ready`,
`bd claim --next`, `bd heartbeat <id> --token <t>`, `bd close <id>`).

The hooks are bd's own fixed commands, so `bd setup` runs in agent
sessions too, with no approval step. It runs only on the local machine:
it is never forwarded to a bd server, and refused through `bd serve`.

## Where setup writes

The project is the nearest directory, from the working directory (or
`-C`) up, that holds a `.bd` directory or a `.git` (a directory, or a git
worktree's file), whichever is closer. A git worktree nested in its main
checkout, like Claude Code's `.claude/worktrees/<name>`, is set up in
itself, not in the main checkout, even when the main checkout holds
`.bd/remote.toml` or `.bd/bd.db`: harnesses read project configuration
from the session's working tree. Outside any project the command is
refused (exit 2).

Setup takes the checkout's lock, which serializes it with `bd agents
pull`, only when the project is the checkout that pull writes to (in a
local workspace, the directory holding the workspace's `.bd`; in a remote
one, the directory holding the `.bd` that configures it). Anywhere else
there is nothing to serialize with, and no lock file is created. `--dry-run`
and `--list` never lock.

## What counts as already set up

Setup adds each hook event only when no bd hook for it is configured yet,
so a harness never runs bd's hook twice:

- **Claude Code**: the shared `.claude/settings.json` itself, or an
  installed Claude Code plugin running bd's hooks (found in the plugin
  cache, `<claude home>/plugins/cache`). Personal settings
  (`.claude/settings.local.json`, `~/.claude/settings.json`) do not count:
  Claude Code runs an identical handler once across settings files, so the
  shared file gets the hooks for everyone else who opens the project.
- **Codex and Copilot CLI**: every file the harness reads hooks from, the
  user's included (`~/.codex/hooks.json`; `~/.copilot` hook files and
  installed plugins). Neither documents running an identical hook once, so
  a second copy would print the context twice. The report names the file
  holding the hook, marked as personal when it is outside the project or a
  `.local.json` file.

## Merging, never clobbering

Setup merges hook entries into an existing JSON file, keeping every other
key and hook, and appends the bd section to a Markdown file after a blank
line, between two marker lines:

```text
<!-- BEGIN bd setup: bd setup opencode --remove removes this section -->
## Task tracking with bd
...
<!-- END bd setup -->
```

Only the text between bd's markers is ever changed: a section an older bd
wrote is replaced in place (reported `updated`), and the file's line
endings (CRLF or LF) are kept. Running setup again changes nothing and
reports `present`.

A file setup cannot merge into is reported as a conflict and left as it
is: not valid JSON, not a JSON object, `hooks` or an event not where the
harness keeps them, a symlink, not a regular file, not UTF-8, or markers
that are not one begin line followed by one end line. The command then
exits 1, after printing the whole report.

## Options

- `--dry-run` reports what would change and writes nothing.
- `--remove` takes out only what setup writes: hook handlers whose command
  is exactly bd's (a hand-written variant such as `bd prime --hook claude
  --ready 5` stays), then any group, event or `hooks` object that removal
  emptied, or the marked section and the blank line before it. A file left
  with nothing else (only `version`, for Copilot CLI's) is deleted, so
  setup followed by `--remove` leaves the project as it was.
- `--list` lists every recipe with its mechanism, its file and its state
  in this project: `present`, `partial` (some hook events missing),
  `missing`, `outdated` (an older section) or `conflict`. It takes no
  harness, `--remove` or `--dry-run`.
- `--json` prints the report as JSON: `harness`, `action` (`add` or
  `remove`), `dry_run`, `root`, `files` (each with `file`, `state`,
  `reason` for a conflict, and `events` added or removed) and `next`.

## Next steps per harness

- **Claude Code**: start a new session, or review the hooks with `/hooks`.
- **Codex**: trust the hooks with `/hooks`; Codex loads a project's
  `.codex` layer only when the project is trusted.
- **Copilot CLI**: start a new session.
- **Cursor, Gemini CLI, opencode**: nothing; the instructions load with
  the next session.

## Why Cursor, Gemini CLI and opencode get instructions

- **Gemini CLI** supports hooks, and its SessionStart hook can return
  `hookSpecificOutput.additionalContext`, which it adds as the session's
  first turn. bd still writes `GEMINI.md`, for three reasons: Gemini CLI
  requires a hook's stdout to be its JSON answer only, while bd's
  session-start output is plain text for every harness but Copilot CLI;
  bd has no Gemini harness to name in `--hook` and `--harness`; and
  Gemini CLI's SessionStart sources are startup, resume and clear, while
  its PreCompress hook is advisory (a `systemMessage` shown to the user
  only), so a hook would not restore bd's context after compression.
  `GEMINI.md`, loaded as instructions rather than conversation history,
  survives compression and tells the agent to run `bd prime` again. A
  Gemini hook may come later.
- **Cursor**: its hooks take JSON output in a format bd does not print,
  and its preCompact hook only offers a message to the user.
- **opencode** takes a project's instructions from `AGENTS.md`.

## The Claude Code plugin

This repository is also a Claude Code plugin marketplace
(`.claude-plugin/marketplace.json`) with one plugin, `plugins/bd`:

```text
/plugin marketplace add quanghle/bd-sync
/plugin install bd@bd
```

From a shell: `claude plugin marketplace add quanghle/bd-sync`, then
`claude plugin install bd@bd`. The plugin runs the same hooks as
`bd setup claude` writes (SessionStart, SubagentStart and PreToolUse, all
bare `bd` commands, so `bd` must be on `PATH`), and adds a short `bd`
skill teaching the work loop. It has no version, so installs follow the
repository's commits.

Use the plugin or the hooks in settings, not both: Claude Code runs a
plugin's handler separately from a settings copy, so the context would
print twice. `bd setup claude` and `bd agents pull` skip the events an
installed bd plugin provides, found in `<claude home>/plugins/cache`.
This repository's own `.claude/settings.json` already has the hooks. Two
limits: a disabled plugin still in the cache still counts, and a plugin
loaded in place from a local-path marketplace is not seen.

## Compared with `bd agents pull`

`bd agents pull` (and the session-start hook's pull) adds only the
session-start hook, for Claude Code into the personal
`.claude/settings.local.json`, in the checkout holding the workspace's
`.bd`. `bd setup` writes the shared, committed configuration of the
project it runs in, Claude Code's subagent hooks included, and the
instruction files of harnesses without hooks. See [Agent assets, sessions
and hooks](agents.md#session-start-hooks), and [After
compaction](agents.md#after-compaction) for what each harness runs then.
