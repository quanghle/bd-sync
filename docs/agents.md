# Agent assets, sessions and hooks

bd works with three agent harnesses: Claude Code (`claude`), Codex
(`codex`) and Copilot CLI (`copilot`). This page covers:

- [serving skills and MCP definitions](#serving-sets) from a workspace to
  its checkouts, and [pulling](#pulling-into-a-checkout) and
  [approving](#approving-skills-and-mcp-definitions) them;
- [session-start hooks](#session-start-hooks) that run `bd prime` and keep
  a checkout's assets current;
- [sessions and subagents](#sessions-and-subagents): how each agent session
  gets an actor of its own.

## Serving sets

A workspace can serve agent skills and MCP server definitions to the
harnesses of its checkouts. Each harness has a set of its own,
`.bd/agents/<harness>/` next to the database (`<root>/<name>/.bd/agents/`
on a server), served as it is to that harness only: nothing is translated
or shared between harnesses. Clients see an edit at their next request,
with no restart. It is mostly a feature of [remote
workspaces](remote.md), and works the same in a local one.

| harness | in `.bd/agents/<harness>/` | placed in a checkout |
|---|---|---|
| `claude` | `skills/<name>/**`, `mcp.json` (`{"mcpServers": {...}}`) | `.claude/skills/<name>/`, `.mcp.json` |
| `codex` | `skills/<name>/**`, `mcp.toml` (`[mcp_servers.<name>]` tables) | `.agents/skills/<name>/`, `.codex/config.toml` |
| `copilot` | `skills/<name>/**`, `mcp.json` (`{"mcpServers": {...}}`) | `.github/skills/<name>/`, `.github/mcp.json` |

```text
/srv/bd/proj/.bd/agents/claude/skills/deploy/SKILL.md
/srv/bd/proj/.bd/agents/claude/skills/deploy/scripts/run.sh    # executable: clients get it executable (Unix)
/srv/bd/proj/.bd/agents/claude/mcp.json
/srv/bd/proj/.bd/agents/codex/skills/deploy/SKILL.md
/srv/bd/proj/.bd/agents/codex/mcp.toml
```

```json
{"mcpServers": {
  "tracker": {"command": "npx", "args": ["-y", "@example/tracker-mcp"],
              "env": {"TRACKER_TOKEN": "${TRACKER_TOKEN}"}},
  "docs": {"type": "http", "url": "https://docs.example.com/mcp",
           "headers": {"Authorization": "Bearer ${DOCS_TOKEN}"}}
}}
```

```toml
# .bd/agents/codex/mcp.toml
[mcp_servers.tracker]
command = "npx"
args = ["-y", "@example/tracker-mcp"]
env_vars = ["TRACKER_TOKEN"]

[mcp_servers.docs]
url = "https://docs.example.com/mcp"
bearer_token_env_var = "DOCS_TOKEN"
```

The server provides definitions only. MCP servers run and authenticate on
the client (`${VAR}` references, `env_vars`, `bearer_token_env_var`, or
OAuth in the harness); the server holds no secrets.

### Rules for a set

Sets are read strictly. A set that breaks a rule is refused whole, with an
error naming the file, by `bd agents manifest`, by the server when a client
asks for it, and by clients, which check every answer before writing:

- **Layout.** A harness directory holds only `skills/` and its MCP file.
  Hidden entries (`.DS_Store`, `.git`) are ignored, and so is anything in
  `.bd/agents` besides the harness directories. Symlinks may point
  anywhere inside `.bd/agents` (to share a skill between sets), never
  outside it; dangling or looping symlinks, devices and FIFOs are refused.
- **MCP files** hold only their entries key (`mcpServers` or
  `mcp_servers`): settings, hooks, permissions and any other key are
  refused, as are duplicate JSON keys and TOML dates. A file without the
  key is an empty set. Server names are letters, digits, `-` and `_`, 1 to
  64 bytes. Each entry has a non-blank `command` or `url`; `args` is an
  array of strings and `env` maps names to strings. Other fields are the
  harness's own and pass as they are, but top-level field names are 1 to
  64 characters of `[A-Za-z0-9_.-]`, starting with a letter or `_`.
- **Skills** are directories under `skills/` holding a `SKILL.md`, named
  with lowercase letters, digits, `-`, `_` and `.`, starting with a letter
  or digit, not ending with `.`, at most 64 bytes, and not a Windows device
  name (`con`, `nul`, `com1`, …).
- **Paths** within a skill are portable: ASCII only; no `\ : < > " | ? *`
  or control characters; no component ending with a space or `.`, or
  naming a Windows device; at most 8 levels and 200 bytes; no two
  differing only in case. Files are UTF-8 text without NUL characters.
- **Limits** per set: 256 files, 256 directories, 256 entries per
  directory, 512 KiB per file, 8 MiB in all, and 64 MCP servers.

`bd agents manifest [--harness …] [--json]` checks the sets and lists what
each harness gets:

```console
$ bd -C /srv/bd/proj agents manifest
claude: revision de260d525b5e (clients place it in .claude/skills/ and .mcp.json)
  skill deploy (2 files)
  MCP server docs
  MCP server tracker
codex: revision 48596ad57c35 (clients place it in .agents/skills/ and .codex/config.toml)
  skill deploy (1 file)
  MCP server docs
  MCP server tracker
copilot: nothing served
```

A manifest holds a SHA-256 per skill file (and `lf_sha256`, its hash with
CRLF line endings read as LF) and per MCP entry (over its canonical JSON,
so reformatting an MCP file changes no hash); a set's revision is the hash
of its manifest. `bd serve`'s agents job (`--agents-every`, default 30
seconds) appends an `agents_changed` event (actor `bd-serve`, data
`{harness, revision, previous}`) for each harness whose revision changed,
which `bd agents watch` waits for. Revisions are kept in the database, so a
change made while the server was down still gets its event. A set that
cannot be read gets no event and one log warning per distinct error;
clients asking for it get the error.

## Trust

Skills are code, not just text. A Claude Code project skill can run
`` !`<command>` `` lines and ```` ```! ```` blocks before the model reads
it, register `hooks` from its frontmatter, and pre-approve tools with
`allowed-tools`; Copilot CLI skills honour `allowed-tools` too. Scripts
bundled with a skill, which bd makes executable, are commands agents are
told to run. A stdio MCP definition is a command every client runs with
the user's privileges.

So both wait for a person. A pull, the session-start hook and `bd agents
watch` never write a new or changed skill file, a new executable bit, or a
new or changed MCP definition; `bd agents approve` shows each one and asks
on a terminal. What applies without approval adds nothing that runs:
removals, restores of the very bytes approved, and adoption of files
already in place. The harnesses' own checks do not cover this: some
approve MCP servers by name only (a changed command under an approved name
passes) or skip prompts in non-interactive runs.

An approved skill still runs with the user's privileges in every session,
and whoever can edit `.bd/agents` on the server can put anything up for
approval. So:

- Guard `.bd/agents` on the server like a code deployment: only admins
  edit it, and changes are reviewed as code is.
- Read what `bd agents approve` shows before answering. `bd agents status`
  names what is waiting; the hidden `bd agents fetch --harness <h>` (any
  token) prints a whole set as one JSON object with strings escaped.

## Pulling into a checkout

```bash
bd agents status --harness claude       # what a pull would do; changes nothing
bd agents pull --harness claude,codex   # removals and restores applied; new or changed assets wait
bd agents approve                       # in a terminal: review and approve what waits
bd agents watch                         # keep pulling as the server's sets change, until Ctrl-C
```

These run on the client, in a checkout: the directory holding the `.bd`
that configures the workspace (next to `remote.toml`, else the nearest
`.bd`). In a remote workspace they read the server's sets with any token.

**Harnesses.** A command takes its harnesses from `--harness` (repeatable
or comma-separated), else from the running agent session's variable
(`$CLAUDE_CODE_SESSION_ID`, `$COPILOT_AGENT_SESSION_ID`, `$CODEX_THREAD_ID`
or `$CODEX_SESSION_ID`; a nested session gets each), else from those
`.bd/agents.lock` records (`approve` skips the session step). With none it
fails (exit 2). Each harness's set goes to its own places only.

```console
$ bd agents status --harness claude,copilot
claude: local edits kept: .claude/skills/deploy/SKILL.md
claude: MCP tracker new: not applied; review and approve with `bd agents approve` in a terminal
claude: unset environment variables the MCP servers read: DOCS_TOKEN, TRACKER_TOKEN
copilot: conflict: .github/skills/triage/SKILL.md: differs from the server's and was not written by bd; left as it is (move it away to get the server's)
```

When nothing changed, a command makes one request (the manifests). A set
is fetched whole only when files are to be written, adopted or shown, and
those decisions are made again from hashes checked against the texts,
never from a manifest's word for them.

### The lock

`.bd/agents.lock` records, per harness, the server revision last pulled;
each skill file bd wrote or adopted (`sha256` of its bytes, `lf_sha256`
for CRLF text, `executable`, and `executable_not_kept` where the file
system lost the bit); and each MCP entry bd wrote or adopted, with the
definition approved. It is local state: the first lock written adds
`agents.lock*` to `.bd/.gitignore` (`bd init` writes that line too).

Changes to a checkout are serialized by `.bd/agents.lock.mutex`, an
OS-level lock released when its process ends. `status`, `pull` and
`approve` wait up to `--busy-timeout-ms` for it, then fail with exit 5; a
watch reports the checkout busy and tries again; the session-start hook
waits only within its time budget.

### How a pull decides

- **Approval.** A skill file is written only with the bytes recorded for
  it by `bd agents approve` (or a pull's adoption), and made executable
  only if it was approved so. A new file, a changed text or a newly set
  executable bit waits, as the skill's change (`skills waiting for
  approval: deploy (changed: SKILL.md)`). A pull still records the
  server's revision, so later pulls and session starts keep reporting the
  waiting skill.
- **Ownership.** A file or MCP entry bd did not record but that already
  matches the server's is adopted: recorded, not written (a fresh clone
  with the skills committed), unless it needs an executable bit, which
  waits. One that differs is a conflict, reported and left alone; moving
  it away lets the next pull put the server's up for approval.
- **Line endings.** A skill file that differs only in line endings (CRLF
  read as LF, as git's `core.autocrlf` checks out on Windows) counts as
  the same file: adopted, never an edit, and kept with its line endings.
  Writing is stricter, since line endings change what a script runs: only
  the recorded bytes are written without approval.
- **Local edits.** A file or entry bd wrote that was edited here is kept
  and reported. When the server changed it too, it waits for approval,
  which replaces the edit; when the server removed it, it is a conflict.
  `pull --force` puts the recorded bytes back over such edits, or removes
  them; it never touches what bd did not write, and never writes anything
  new.
- **Restores and removals.** Files bd wrote that were deleted here are
  written again with the recorded bytes, and so is an approved MCP
  definition deleted here and unchanged on the server. Files and entries
  the server removed are deleted (unless edited here), with directories
  left empty, before anything is written, so renames that change only case
  and files that become directories work.
- **Symlinks.** A pull never follows a symlink at or below a skill's
  directory, and never writes an MCP file that is a symlink: those are
  conflicts.
- **Executable bits** (Unix). Files the server marks executable get the
  bit once approved; a change of the bit alone touches no text, so it
  applies even to an edited file, and a bit the server clears is cleared
  without approval. A bit the server never set is left alone. Where the
  file system does not keep the bit (vfat, exfat, some SMB mounts), the
  pull says so once (`not executable here`), records it, and counts the
  file as up to date; run such scripts through their interpreter
  (`sh run.sh`).
- **MCP files keep everything bd did not write.** `.mcp.json` and
  `.github/mcp.json` keep every other key and server, and are rewritten
  pretty-printed with sorted keys when bd changes an entry.
  `.codex/config.toml` is edited in place: bd inserts, replaces or removes
  `[mcp_servers.<name>]` tables only, keeping other settings, comments and
  formatting byte for byte. bd does not write a file it cannot read, a JSON
  file holding servers outside `mcpServers`, a `.codex/config.toml` whose
  `mcp_servers` is an inline table, or a symlink: changes to those are
  reported as conflicts.
- **Session-start hook.** `pull` also adds the harness's
  [session-start hook](#session-start-hooks) when none is configured, so
  the first agent session in a fresh checkout runs `bd prime` and keeps the
  assets current. It writes bd's own entries (never the server's) to
  `.claude/settings.local.json`, `.codex/hooks.json` or
  `.github/hooks/bd.json`. One already configured for the harness, in the
  checkout or for the user (`$CLAUDE_CONFIG_DIR` or `~/.claude`,
  `$CODEX_HOME`, `$COPILOT_HOME`, `.github/copilot/settings*.json`, an
  installed Copilot CLI plugin), is left as it is. A file that is not a
  JSON object, keeps its hooks elsewhere, or is a symlink is reported
  (`session-start hook not added`). `--no-hook` leaves the hook out. Keep
  these local files out of commits where teammates run sessions without
  bd.

`status` and `pull` reports also list the environment variables MCP
definitions (applied or waiting) read that are unset or empty here, by
name only: `${VAR}` and `$VAR` in `command`, `args`, `env`, `url` and
`headers` (not `${VAR:-default}`), or Codex's `env_vars` (not
`source = "remote"`), `bearer_token_env_var` and `env_http_headers`.

**JSON.** With `--json`, `status` and `pull` print `{"applied",
"checkout", "harnesses": {"<harness>": {"server_revision",
"applied_revision", "skills", "mcp", "unset_env", "hook"}}}`, where
`skills.pending` lists the skills waiting (`change`: `new` or `changed`,
and their `files`, each with `path`, `change`: `new`, `changed` or
`executable`, `executable`, `edited`) and `mcp.pending` the definitions
waiting (`name`, `change`, the top-level `fields` that changed, `edited`).
`approve` prints, per harness, `skills` (`dir`, `approved`, `declined`,
`skipped` with reasons, `not_executable`) and `mcp` (`file`, `approved`,
`declined`, `skipped`, `conflicts`). The module docs of
`crates/bd-cli/src/agents.rs` have the full shapes.

**Exit codes.** 0 when the command did its work (pending changes,
conflicts, local edits, and declined or skipped approvals are findings,
not failures); 2 no harness, no checkout, an unusable lock, an invalid set,
or for `approve` a refusal or an unknown name; 3 no workspace; 5 the
mutex stayed busy; 7 access denied; 8 server unreachable, or an answer that
failed its checks (nothing was written).

### Watching

`bd agents watch [--harness …] [--interval 10s] [--json]` pulls once, then
again each time a watched set changes, printing each pull's report (one
JSON object per line with `--json`). It never approves anything and never
adds the session-start hook.

- In a remote workspace it waits for `agents_changed` events with long
  polls ([Followers](remote.md#followers)), and after each wait that ends
  with no event it reads the manifests once, so it also catches changes on
  servers running with `--agents-every 0`. A local workspace's
  `.bd/agents` is read every `--interval` (100ms to 1h; also the least
  time between two requests).
- Failures (server unreachable, checkout busy, an unusable set or lock)
  print `bd agents watch: <error> (trying again)` on stderr when they
  start or change, then `bd agents watch: working again`, and are retried
  (backing off to 30 seconds remotely). Only a refused token ends it (exit
  7).
- Ctrl-C or SIGTERM exits 0 once a pull under way is done; a second Ctrl-C
  exits 130 at once.

Run it in a separate terminal during long agent sessions: the
session-start hook pulls only at session start.

## Approving skills and MCP definitions

`bd agents approve [NAME…] [--harness …] [--full]` shows each waiting
skill, then each waiting MCP definition, on stderr, and asks
`Approve skill <name>? [y/N]` or `Approve MCP server <name>? [y/N]` on the
terminal (only `y` or `yes` approves). NAME picks skills and servers by
name.

A skill is shown file by file: a new file in full, a changed one as a diff
against the file here (three lines of context), a file only made
executable in full:

```text
claude: skill deploy: new, to be added to .claude/skills/deploy
  SKILL.md: new
    + ---
    + name: deploy
    + description: Deploy the app
    + ---
    + Run `scripts/run.sh`.
  scripts/run.sh: new, executable
    + #!/bin/sh
    + make deploy
  skill deploy: SKILL.md (new), scripts/run.sh (new, executable)
Approve skill deploy? [y/N] y

claude: approved skill deploy: written to .claude/skills/deploy
claude: to load the skills, run `/reload-skills` in Claude Code if .claude/skills did not exist when the session started
```

An MCP definition is shown with what it runs or connects to (repeated
right before its prompt), the definition in full when new or the old and
new value of each changed top-level field, the environment variables it
reads (marked `(unset here)`), and a warning when approving replaces a
local edit:

```text
claude: MCP server tracker: new, to be added to .mcp.json
  runs on this machine: npx -y @example/tracker-mcp
  definition:
    "tracker": {
      "args": [
        "-y",
        "@example/tracker-mcp"
      ],
      "command": "npx",
      "env": {
        "TRACKER_TOKEN": "${TRACKER_TOKEN}"
      }
    }
  reads environment variables: TRACKER_TOKEN (unset here)
  runs on this machine: npx -y @example/tracker-mcp
Approve MCP server tracker? [y/N] y
```

- **Nothing is printed as the server sent it.** Control characters,
  bidirectional and other invisible formatting characters are escaped, so
  no line can fake another, move the cursor or reorder what is shown. A
  file shows at most 200 lines of at most 400 characters; a definition's
  strings at most 200 characters and its arrays or tables 100 items, with a
  note (`--full` shows everything).
- **Approval is exact.** Once every answer is in, approve takes the
  checkout's mutex and writes exactly what was shown, recording it in the
  lock. It skips a skill or entry that changed here or in the lock since
  it was shown, never replaces something bd did not write, and skips a
  skill with a removal still to apply. A skill is approved or declined
  whole. An approved asset is not asked about again until it changes.
- **People only.** `approve` refuses to run inside an agent session (any of
  the harness session variables set) and, when there is something to ask,
  without a terminal on stdin (exit 2), with no flag to get past either.
  That keeps agents from approving by accident; it is not a security
  boundary, since an agent with a shell can edit the files directly.
  Agents are told to ask the user to run `bd agents approve` in a separate
  terminal.

## Session-start hooks

Two commands run at the start of each agent session:

- `bd hook session-start --harness <claude|codex|copilot>` pulls the
  harness's set with pull semantics (removals and restores applied, new or
  changed assets only reported), and tells the session what changed.
- `bd prime --hook <harness>` prints the [prime](concepts.md#comments-and-memory)
  context: the actor, its claims, ready work, gates, playbooks and
  memories.

Both print in the format the harness reads: plain text for Claude Code and
Codex, one `{"additionalContext": "..."}` JSON object for Copilot CLI. Both
work in the session's directory, the `cwd` of the hook's JSON input (`-C`
wins), and act as the session's own actor, taking the session id from the
hook's input (`sessionId` or `session_id`; a Codex subagent's own
`agent_id`) where the harness does not set its variable for hooks.
Without `--harness`, `session-start` takes the harness from the session
variable, else the lock's harnesses.

The session-start hook says nothing when nothing changed, outside a
checkout, or with no harness known. Otherwise each line starts with `bd:`:

```text
bd: agent skills updated from the bd server: deploy (restored), old (removed).
bd: if these skills are not available yet, ask the user to run `/reload-skills`.
bd: agent skills changed on the bd server and not applied: lint (new), triage (changed: SKILL.md). Ask the user to review them and run `bd agents approve` in a separate terminal.
bd: MCP server definitions changed on the bd server and not applied: tracker (changed: args). Ask the user to review them and run `bd agents approve` in a separate terminal.
bd: 1 agent asset conflict (files or MCP entries in the way, left as they are): `bd agents status` lists it.
bd: environment variables the MCP servers read are unset: DOCS_TOKEN.
```

Pending assets and conflicts are repeated at every session start until
resolved; unset variables are listed when MCP entries were applied or are
waiting. A problem (server unreachable, token missing or refused, mutex
busy, invalid set or lock) is one line, `bd: agent skills and MCP
definitions not checked: <reason>`, and the hook still exits 0.

**Time budget.** The whole hook takes at most about 5 seconds: reading its
input at most 2 seconds; of what is left, a fifth (0.2 to 1 second) for the
checkout's mutex and the rest (at least 1 second) for the server, all its
requests and retries against one deadline. Files are written only once the
server's answers are in and checked, so running out of time leaves nothing
half written.

`bd remote set` and `bd remote login` mention when the workspace serves
sets, so you can run `bd agents pull --harness <h>` before the first
session (which also adds the hook).

### Claude Code

`.claude/settings.json` (as in this repository):

```json
{
  "hooks": {
    "SessionStart": [
      {"hooks": [
        {"type": "command", "command": "bd hook session-start --harness claude"},
        {"type": "command", "command": "bd prime --hook claude"}
      ]}
    ]
  }
}
```

`--harness claude` acts only when Claude Code runs it (`$CLAUDE_ENV_FILE`
or `$CLAUDE_CODE_SESSION_ID` set), since Copilot CLI also runs a
repository's `.claude/settings.json` hooks. When `$CLAUDE_ENV_FILE` is
set, it also writes `export CLAUDE_CODE_SESSION_ID=<id>` there, from the
hook's input, so the session's commands act as the session even on
versions that do not set the variable themselves. Leave out `matcher`
rather than writing `"matcher": ""`: Copilot CLI refuses a
`.claude/settings.json` with an empty matcher.

### Copilot CLI

This repository's plugin, `.copilot-plugin/plugin.json`, runs both
commands on `SessionStart`. A repository can use a hook file instead,
`.github/hooks/bd.json`:

```json
{"version": 1, "hooks": {"sessionStart": [
  {"type": "command", "command": "bd hook session-start --harness copilot"},
  {"type": "command", "command": "bd prime --hook copilot"}
]}}
```

Copilot CLI runs a hook file's commands in the checkout and a plugin's in
the plugin's own directory, and adds each command's `additionalContext` to
the session. A command printing anything but one JSON object adds nothing.

### Codex

`.codex/hooks.json`:

```json
{"hooks": {"SessionStart": [{"matcher": "startup|resume|clear|compact", "hooks": [
  {"type": "command", "command": "bd hook session-start --harness codex", "timeout": 30},
  {"type": "command", "command": "bd prime --hook codex", "timeout": 30}
]}]}}
```

Codex loads project hooks only when the project's `.codex/` layer is
trusted, and each hook must be trusted in `/hooks` (an edited hook needs
trust again). A subagent's thread runs no `SessionStart` hooks. Codex
shows the model a limited amount of hook output by default: a long
`bd prime` may need `"additionalContextLimit"` raised.

### Reloading

Skills written at session start are not listed on the session's first
turn, and MCP changes need a reload:

| harness | skills | MCP definitions |
|---|---|---|
| Claude Code | live, but `.claude/skills` is watched only if it existed at session start: `/reload-skills` | restart (it may also ask to approve new `.mcp.json` servers) |
| Copilot CLI | `/skills reload` | `/mcp reload` |
| Codex | automatic | restart (it reads a project's `.codex/config.toml` only in trusted projects) |

The hook's lines and `approve`'s output name the step to take.

Copilot CLI also reads `.claude/skills`, `.agents/skills` and `.mcp.json`
(which wins over `.github/mcp.json` for the same server name). Pull only
the sets of the harnesses used in a checkout.

## Sessions and subagents

Each agent session acts as its own actor, `<user>/<session>`, derived from
the session id its harness sets ([Actors](concepts.md#actors)), so
concurrent sessions never share claims. Some cases need help.

**Claude Code subagents** run their shell commands with the parent
session's environment, the same `$CLAUDE_CODE_SESSION_ID` and nothing of
their own, so their bd commands would act as the parent. Only hook inputs
tell a subagent apart (by `agent_id`), so two hooks give each subagent an
actor of its own, `<user>/claude-<id>.agent-<id>`:

```json
{
  "hooks": {
    "SubagentStart": [{"hooks": [
      {"type": "command", "command": "bd hook subagent-start || true"}]}],
    "PreToolUse": [{"matcher": "Bash", "hooks": [
      {"type": "command", "if": "Bash(bd *)", "command": "bd hook pre-tool-use || true"}]}]
  }
}
```

- `bd hook subagent-start` adds to the subagent's context that every bd
  command it runs takes `--session agent-<id>` (the last 8 letters and
  digits of its `agent_id`), the actor that gives it, and how to take over
  a claim its parent hands it.
- `bd hook pre-tool-use` denies, inside a subagent, a command that runs bd
  without `--session`, `BD_SESSION=`, `--actor`, `BD_ACTOR=` or
  `BEADS_ACTOR=`, with the corrected command as the reason. It never
  rewrites or approves a command: a flag rather than a variable keeps
  allow rules such as `Bash(bd *)` matching.

Both do nothing in the main conversation, when `$BD_ACTOR` or
`$BEADS_ACTOR` names the actor, and on input they cannot read; `|| true`
keeps an older bd without them from failing the hook. The guard looks
through assignments, here-documents and the wrappers `timeout`, `nice`,
`env`, `sudo`, `stdbuf`, `nohup`, `time`, `command`, `builtin` and `exec`.
A form it does not understand is let through, and a bd run it cannot see
(from a script, through `xargs`) still acts as the parent. Without the
hooks, tell each subagent in its prompt to run every bd command as
`bd --session <name> ...`, with a distinct name.

**Copilot CLI subagents** and **Codex threads** get session ids of their
own, so they act as their own actors with no setup.

**Handing a claim to a subagent** with its own actor: have the subagent
take it over (`bd update <id> --assignee <its actor> --take-over`), or run
its bd commands with `BD_ACTOR=<your actor>` so that it acts as you.
