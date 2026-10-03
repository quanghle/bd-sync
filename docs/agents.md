# Agent skills and MCP definitions

A workspace can serve agent skills and MCP server definitions to the agent
harnesses of its checkouts: Claude Code (`claude`), Codex (`codex`) and
Copilot CLI (`copilot`). Each harness has a set of its own, served as it is
to that harness only: nothing is translated or shared between harnesses,
and a harness without a set gets nothing (a Copilot CLI checkout gets
nothing from a Claude-only set). The server provides definitions only: MCP
servers run on the client and authenticate there (`${VAR}` references in
Claude Code and Copilot CLI definitions, `env_vars` and
`bearer_token_env_var` in Codex, OAuth in the harness). The server holds no
secrets, and bd never handles MCP credentials. Mostly a feature of
[remote workspaces](remote.md), it works the
same in a local workspace, whose checkout pulls from its own `.bd/agents`.

## Serving sets

A set lives next to the database, as playbooks do: `.bd/agents/<harness>/`,
so `<root>/<name>/.bd/agents/<harness>/` on a server. Clients see an edit at
their next request, with no restart.

| harness | in `.bd/agents/<harness>/` | in a client checkout |
|---|---|---|
| `claude` | `skills/<name>/**`, `mcp.json` (`{"mcpServers": {...}}`) | `.claude/skills/<name>/`, `.mcp.json` |
| `codex` | `skills/<name>/**`, `mcp.toml` (`[mcp_servers.<name>]` tables) | `.agents/skills/<name>/`, `.codex/config.toml` |
| `copilot` | `skills/<name>/**`, `mcp.json` (`{"mcpServers": {...}}`) | `.github/skills/<name>/`, `.github/mcp.json` |

```bash
/srv/bd/proj/.bd/agents/claude/skills/deploy/SKILL.md
/srv/bd/proj/.bd/agents/claude/skills/deploy/scripts/run.sh    # executable: clients get it executable (Unix)
/srv/bd/proj/.bd/agents/claude/mcp.json
/srv/bd/proj/.bd/agents/codex/skills/deploy/SKILL.md
/srv/bd/proj/.bd/agents/codex/mcp.toml
```

```json
{"mcpServers": {
  "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
             "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"}},
  "docs": {"type": "http", "url": "https://docs.example.com/mcp",
           "headers": {"Authorization": "Bearer ${DOCS_TOKEN}"}}
}}
```

```toml
# .bd/agents/codex/mcp.toml
[mcp_servers.github]
command = "npx"
args = ["-y", "@modelcontextprotocol/server-github"]
env_vars = ["GITHUB_PERSONAL_ACCESS_TOKEN"]

[mcp_servers.docs]
url = "https://docs.example.com/mcp"
bearer_token_env_var = "DOCS_TOKEN"
```

Sets are read strictly. A set that breaks a rule is refused whole, with an
error naming the file, by `bd agents manifest`, by the server when a client
asks for it, and by clients, which check every answer before writing
anything:

- An MCP file holds only its entries key, `mcpServers` or `mcp_servers`:
  settings, hooks, permissions and any other key are refused. Server names
  are letters, digits, `-` and `_`, at most 64 bytes. Each entry has a
  `command` (a server the client starts) or a `url` (a remote server), as
  non-empty strings; `args` is an array of strings and `env` maps names to
  strings. Other fields are the harness's own and pass as they are, but
  top-level field names are 1 to 64 characters of `[A-Za-z0-9_.-]`,
  starting with a letter or `_` (nested keys are free).
- Each skill is a directory under `skills/` holding a `SKILL.md`, named with
  lowercase letters, digits, `-`, `_` and `.`, starting with a letter or
  digit, not ending with `.`, at most 64 bytes, and not a Windows device
  name (`con`, `nul`, `com1`, ...).
- File paths within a skill are portable: ASCII only; no `\ : < > " | ? *`
  or control characters; no component ending with a space or `.`, or
  naming a Windows device; at most 8 levels and 200 bytes; and no two paths
  differing only in case.
- Hidden entries (names starting with `.`, such as `.DS_Store` or `.git`)
  are ignored, and so is anything in `.bd/agents` besides the harness
  directories. A symlink may lead anywhere inside `.bd/agents` (to share a
  skill between sets, say), never outside it.
- Files are UTF-8 text without NUL characters.
- Limits per set: 256 files (skill files and the MCP file), 256 directories
  below the skill directories, 512 KiB per file, 8 MiB in all, and 64 MCP
  servers.

`bd agents manifest` checks the sets and lists what each harness gets
(`--harness` for some, `--json` for the hashes):

```
$ bd -C /srv/bd/proj agents manifest
claude: revision de260d525b5e (clients place it in .claude/skills/ and .mcp.json)
  skill deploy (2 files)
  MCP server docs
  MCP server github
codex: revision 48596ad57c35 (clients place it in .agents/skills/ and .codex/config.toml)
  skill deploy (1 file)
  MCP server docs
  MCP server github
copilot: nothing served
```

A manifest holds a SHA-256 per skill file (and, for a text with CRLF line
endings, `lf_sha256`: its hash with them as LF) and per MCP entry (over its
canonical JSON, so reformatting an MCP file changes no hash), and a set's
revision is the hash of its manifest. The server's agents job
(`--agents-every`, default 30 s, `0` or `off` to turn it off;
[Background jobs](remote.md#background-jobs-and-backups)) reads each workspace's sets
and appends an `agents_changed` event (actor `bd-serve`, no issue, data
`{harness, revision, previous}`) for each harness whose revision changed,
which `bd agents watch` clients wait for. The revisions last recorded are
kept in the database, so a change made while the server was down still gets
its event after a restart; a harness never served counts as an empty set,
so a workspace that serves nothing gets no events. A set that cannot be
read gets no event and one log warning per distinct error (`agent set
cannot be read; its clients keep what they have`, with the workspace,
harness and error), then `agent set readable again`; the job still checks
the other sets, and clients asking for the broken set get its error.

## Trust

Skills are code, not just text. A Claude Code project skill can run
`` !`<command>` `` lines and ```` ```! ```` blocks on the user's machine
before the model reads it, register `hooks` for the session from its
frontmatter, and pre-approve tools with `allowed-tools` (such as
`Bash(...)`); Claude Code invokes a skill by itself when its description
matches, and refuses `!` commands only in skills synced from claude.ai, not
in project skills such as those bd writes. Copilot CLI skills honour
`allowed-tools` too (such as `shell`). Scripts bundled with a skill, which
bd makes executable, are commands agents are told to run.

So skills wait for a person, as MCP definitions do: a pull, the
session-start hook and `bd agents watch` never write a new skill file, a
changed one, or an executable bit the user has not approved; `bd agents
approve` shows each waiting skill, file by file, and asks on a terminal
([Approving skills and MCP definitions](#approving-skills-and-mcp-definitions)).
What applies without approval adds nothing that runs: removals, files bd
wrote that were deleted here written again as approved, files already here
as the server has them adopted. Still, an approved skill runs with the
user's privileges in every session, and someone who edits `.bd/agents/*`
on the server, or takes the server over, can put anything up for approval.
So:

- Guard `.bd/agents` on the server like a code deployment: only admins
  edit it, and changes are reviewed as code is.
- Read what `bd agents approve` shows before answering: a skill's files in
  full when new, as a diff when changed. `bd agents status` names the
  skills waiting and their changed files; the server's text can also be
  read with the hidden `bd agents fetch --harness <h>` (a read token is
  enough), which prints the whole set as one JSON object with strings
  escaped (`jq '.skills'`); `jq -r` prints the text as the server sent it,
  terminal control characters included.

## Pulling into a checkout

```bash
bd agents status --harness claude       # what a pull would do; changes nothing
bd agents pull --harness claude,codex   # removals and restores applied; new or changed skills and MCP definitions wait
bd agents approve                       # in a terminal: review and approve waiting skills and MCP definitions
bd agents watch                         # keep pulling as the server's sets change, until Ctrl-C
```

These run on the client, in a checkout: the directory holding the `.bd`
that configures the remote workspace (next to `remote.toml`, else the
nearest `.bd`), or the local workspace's. In a remote workspace they read
the server's sets with any token (a read token is enough); `bd serve`
refuses them. A command picks its harnesses from `--harness` (repeatable or
comma-separated), else the running agent session's
(`$CLAUDE_CODE_SESSION_ID`, `$COPILOT_AGENT_SESSION_ID`, `$CODEX_THREAD_ID`;
a nested session gets each), else those `.bd/agents.lock` records
(`approve` skips the session step). With none of these it fails (exit 2).
Each harness's set goes to its own places only: a copilot pull leaves the
claude and codex ones alone. When nothing changed, a command makes one
request (the manifests); a set is fetched whole only when files are to be
written, adopted or made executable, or changes shown: those are decided
again from hashes checked against the texts they name, never from a
manifest's word for them.

```
$ bd agents status --harness claude,copilot
claude: local edits kept: .claude/skills/deploy/SKILL.md
claude: MCP github new: not applied; review and approve with `bd agents approve` in a terminal
claude: unset environment variables the MCP servers read: DOCS_TOKEN, GITHUB_TOKEN
copilot: conflict: .github/skills/triage/SKILL.md: differs from the server's and was not written by bd; left as it is (move it away to get the server's)
```

`.bd/agents.lock` records, per harness, the server revision last pulled,
each skill file bd wrote or adopted (`sha256` of the bytes written, or of
those found here when adopted, `lf_sha256` for a text with CRLF line
endings, `executable`, and `executable_not_kept` where the file system did
not keep that bit), and
each MCP entry bd wrote or adopted, with the definition approved. It is
local state: the first lock written adds `agents.lock*` to `.bd/.gitignore`
(covering `agents.lock.mutex`, the checkout's OS-locked mutex, and temp
files), and `bd init` writes that line too. Changes to a checkout are serialized by the
mutex, which the system releases when its process ends, so a session hook and
a watch can run at once. `bd agents status`, `pull` and `approve` wait up to
`--busy-timeout-ms` for it, then fail with exit 5; a watch waits as long, then
reports the checkout busy and tries again; the session-start hook waits only
within its own time budget, then reports it in one line and still exits 0
([Session-start hooks](#session-start-hooks)). The rules a pull follows:

- **Approval.** A skill file is written only with the bytes bd recorded for
  it, which `bd agents approve` recorded (or a pull adopted), and made
  executable only if it was then: a new file, a changed text, or an
  executable bit the server now sets waits for approval, as the skill's
  change (`skills waiting for approval: deploy (changed: SKILL.md)`; a
  path with a space is quoted, and past five files the rest are counted). A
  pull still records the server's revision, so later pulls and session
  starts report the waiting skill until it is approved.
- **Ownership.** A file or MCP entry bd did not record that already matches
  the server's is adopted: recorded, not written (a fresh clone with the
  skills committed), unless it needs an executable bit, which waits for
  approval. One that differs is a conflict, reported and left alone;
  moving it away lets the next pull put the server's up for approval.
- **Line endings.** A skill file that differs from the server's, or from
  the one bd wrote, only in line endings (the same text once each CRLF in
  either is read as LF, as when git's `core.autocrlf` checks text files out
  with CRLF line endings on Windows) counts as the same file: adopted,
  never an edit, and kept with its line endings and its record, also when
  the server changes only those. Writing them is another matter: line
  endings can change what a script runs (a `\` before CRLF continues no
  line in sh), so only the bytes recorded are written without approval: a
  file deleted here whose server text has other line endings waits for
  approval, its CRs shown (`\u{d}`), and `pull --force` keeps an edit to
  such a file.
- **Local edits.** A file or entry bd wrote that was edited here is kept and
  reported as edited. When the server changed it too, it waits for
  approval, which replaces the edit (`edited here`); when the server
  removed it, it is a conflict. `pull --force` puts the recorded bytes back
  over such edits, or removes them; it never touches what bd did not
  write, and never writes a new or changed skill file or MCP definition.
- **Restores and removals.** Files bd wrote that were deleted here are
  written again with the bytes recorded, and so is an approved MCP definition deleted here and
  unchanged on the server. Files and MCP entries the server removed are
  deleted (unless edited here), with the directories that leaves empty
  below the skills directory, before anything is written: a file renamed on
  the server only in case is written under its new name on file systems
  that ignore case, and a file may become a directory, or the other way
  round.
- **Symlinks.** A pull never follows a symlink at or below a skill's
  directory (the skills directory and its parents may be symlinks), and
  never writes an MCP file that is a symlink: those are conflicts.
- **Executable bits** (Unix): files the server marks executable get their
  executable bits once approved, also when adopted or kept with the
  server's text; a server change of the bit alone (approved like any other)
  touches no text, so it applies even to an edited file, and a bit the
  server clears is cleared without approval. An
  executable bit the server never set is left alone (some file systems show
  every file executable). Where the file system does not keep the bit
  (`chmod` has no effect or is refused, and files read back without it:
  vfat, exfat, or SMB mounts with an `fmask` that clears it), the pull says
  so once (`not executable here`; `skills.not_executable` in JSON), records
  it in the lock (`executable_not_kept`), and later pulls and `status` count
  the file as up to date. bd sets the bit again when the server's set
  changes (reporting it only if it is kept then), or with `pull --force`,
  and drops the mark once the file has it (set by hand, say).
- **MCP definitions.** New and changed definitions are never written by a
  pull, a hook or a watch: they wait for `bd agents approve`. Removals of
  unedited entries bd wrote apply at once, as they add nothing that runs.
- **Session-start hook.** `pull` also gives the harness the session-start
  hook ([Session-start hooks](#session-start-hooks)) when none is
  configured, so that the first agent session in a fresh checkout runs
  `bd prime` and keeps the checkout's assets up to date: Claude Code's in
  `.claude/settings.local.json`, Codex's in `.codex/hooks.json`, Copilot
  CLI's in `.github/hooks/bd.json`. The hook is bd's own, never the
  server's (a server's sets hold no hooks). One already configured for the
  harness, in the checkout or for the user (`~/.claude/settings.json`,
  `$CODEX_HOME/hooks.json`, `$COPILOT_HOME/hooks/*.json` or
  `settings.json`, an installed Copilot CLI plugin's), is left as it is,
  and nothing is written. bd's entries are appended to what the file
  holds, which is rewritten pretty-printed with sorted keys; a file that is
  not a JSON object, keeps its hooks elsewhere than `hooks.<event>`, or is
  a symlink is left alone and reported (`session-start hook not added`).
  `status` reports `session-start hook to add`; `--no-hook` leaves the hook
  out of either command. The files are local: keep them out of commits
  where teammates or Copilot cloud agent run sessions without bd
  (Copilot cloud agent runs `.github/hooks/*.json` too).

MCP files keep everything bd did not write. `.mcp.json` and
`.github/mcp.json` keep every other key and server, and are written
pretty-printed with sorted keys when bd changes an entry. `.codex/config.toml`
is edited in place (with `toml_edit`): bd inserts, replaces or removes
`[mcp_servers.<name>]` tables only, and keeps Codex's other settings,
comments and formatting byte for byte. bd does not write a file it cannot
read in its format, a JSON file holding servers outside `mcpServers`
(Copilot's bare form), a `.codex/config.toml` whose `mcp_servers` is an
inline table (`mcp_servers = {...}`), or a symlink: changes to such a file
are reported as conflicts, and the file is left as it is.

Every report lists the environment variables that MCP definitions (in
effect or waiting) read and that are unset or empty here, by name only:
`${VAR}` and `$VAR` in `command`, `args`, `env`, `url` and `headers` for
Claude Code and Copilot CLI (not `${VAR:-default}`); `env_vars` (but not
`source = "remote"` ones), `bearer_token_env_var` and the values of
`env_http_headers` for Codex.

With `--json`, `status` and `pull` print `{"applied", "checkout",
"harnesses": {"<harness>": {"server_revision", "applied_revision", "skills",
"mcp", "unset_env", "hook"}}}`, where `skills` and `mcp` list what changed, was
adopted, edited, left or is in conflict; `skills.pending` the skills
waiting, by name (`change`: `new` or `changed`, and their `files`, each
with its `path`, `change`: `new`, `changed` or `executable`, whether it is
`executable`, and whether it was `edited` here); `mcp.pending` the
definitions waiting (`name`, `change`: `new` or `changed`, the top-level
`fields` that changed, and whether the entry was `edited` here); and
`hook` the session-start hook's `file` and `state` (`present`, `added`, or
`conflict` with a `reason`; left out with `--no-hook`). `approve` prints,
per harness, `skills` (the skills `dir`, and the skills `approved`,
`declined`, `skipped` with a reason, and the paths `not_executable` here)
and `mcp` (its `file`, and the entries `approved`, `declined`, `skipped`
with a reason, and in `conflicts`). The module docs of
`crates/bd-cli/src/agents.rs` have the full shapes. Exit codes: 0 when the
command did its work (pending skills and MCP
changes, conflicts, local edits, and declined or skipped approvals are
findings, not failures); 2 no harness, no checkout, an unusable
`.bd/agents.lock`, or an invalid set; for `approve` also a refusal (below)
or a name neither served nor recorded; 3 no workspace; 5 the checkout's
mutex stayed busy; 7 access denied; 8 server unreachable, or an answer that
failed its checks (nothing was written).

`bd agents watch [--harness ...] [--interval 10s] [--json]` pulls once,
then again each time a watched set changes, printing each pull's report
(one JSON object per line with `--json`). In a remote workspace it waits
for `agents_changed` events with long polls ([Followers](remote.md#followers)), and
after each wait that ends with no event it reads the manifests once, so it
also catches changes the job missed and servers running with
`--agents-every 0`; `--interval` is the least time between two requests. A
local workspace's `.bd/agents` is read every `--interval`. A watch never
approves anything. Failures (the server unreachable, the checkout busy, an
unusable set or lock) print `bd agents watch: <error> (trying again)` on
stderr once, then `bd agents watch: working again`, and are retried (after
pauses growing to 30 s in a remote workspace); only a refused token ends it
(exit 7). Ctrl-C exits 0 once a pull under way is done; a second one exits
130 at once. For long agent sessions, run it in a separate terminal: the
session-start hook pulls only at session start.

## Approving skills and MCP definitions

A stdio MCP definition is a command that every client runs, with the
user's privileges, and a skill can run commands too ([Trust](#trust)), so a
pull never writes a new or changed one: it waits until a person approves
it. The harnesses' own checks do not cover this: Claude Code approves
`.mcp.json` servers by name (a changed command under an approved name
passes) and skips the prompt in `-p` and SDK runs, runs a project skill's
`!` commands without asking, and Copilot CLI only checks folder trust.

`bd agents approve [NAME...] [--harness ...] [--full]` shows each waiting
skill, then each waiting MCP definition, on stderr, and asks `Approve skill
<name>? [y/N]` or `Approve MCP server <name>? [y/N]` on the terminal. NAME
picks skills and MCP servers by name. A skill is shown file by file: a new
file in full, a changed one as a diff against the file here (three lines
of context), a file only made executable in full, each line behind a `+ `,
`- ` or `  ` gutter:

```
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

```
claude: skill deploy: changed, in .claude/skills/deploy
  SKILL.md: changed
    @@ -2,4 +2,4 @@
      name: deploy
      description: Deploy the app
      ---
    - Run `scripts/run.sh`.
    + Run `scripts/run.sh --prod`.
  skill deploy: SKILL.md (changed)
Approve skill deploy? [y/N]
```

The files of a skill are listed again, with their change, right before its
prompt, and a file edited here carries a warning that approving replaces
the edit. As for definitions, nothing is printed as the server sent it:
control characters, bidirectional and other invisible formatting
characters (Unicode format characters, tag characters, variation
selectors) are escaped, so no line can fake another, move the cursor or reorder what
is shown; a file shows at most 200 lines and each line at most 400
characters, with a note (`--full` shows them whole). A skill is approved
or declined whole; files the server removed from it are deleted at the
next pull, with no approval. An MCP definition is shown so:

```
claude: MCP server github: new, to be added to .mcp.json
  runs on this machine: npx -y @modelcontextprotocol/server-github
  definition:
    "github": {
      "args": [
        "-y",
        "@modelcontextprotocol/server-github"
      ],
      "command": "npx",
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "${GITHUB_TOKEN}"
      }
    }
  reads environment variables: GITHUB_TOKEN (unset here)
  runs on this machine: npx -y @modelcontextprotocol/server-github
Approve MCP server github? [y/N] y

claude: approved MCP server github: written to .mcp.json
claude: to load the MCP servers, restart the Claude Code session; Claude Code may also ask to approve new .mcp.json servers itself
```

Each entry shows what it runs (`runs on this machine: <command args>`) or
connects to (`connects to: <url>`), repeated right before its prompt; a new
definition in full, in its harness's native form; a changed one as the old
and new value of each top-level field that changed, and the fields
unchanged; the environment variables it reads, marked `(unset here)`; and
a warning when approving replaces a local edit. Nothing the server sent is
printed as sent: definitions are rendered from their JSON form, each string
and key one escaped literal on one line (line breaks, control characters
and bidirectional or invisible formatting characters escaped), so no value
can fake a line, move the cursor or reorder what is shown. Strings over 200
characters and arrays or tables over 100 items are cut short with a note
(`--full` shows them whole); the run/connect summary stays short (400
characters).

Once every answer is in, approve takes the checkout's mutex and writes
exactly the skill files and definitions shown, recording them in
`.bd/agents.lock`. It skips a skill whose files here or in the lock
changed since it was shown, and an entry whose place in the MCP file or
the lock changed, and never replaces a file or entry bd did not write (a
conflict): move it away, then pull and approve again. A skill with a
removal still to apply is skipped until a pull applies it. Where the file
system keeps no executable bit, approve says so (`not executable here`). A
skill or definition that changes again on the server before approval is
shown in its newest version; an approved one is not asked about again
until it changes. A harness with nothing waiting says `nothing waiting for
approval`.

`approve` refuses to run inside an agent session (`$CLAUDE_CODE_SESSION_ID`,
`$COPILOT_AGENT_SESSION_ID`, `$CODEX_THREAD_ID` or `$CODEX_SESSION_ID` set)
and, when there is something to ask about, without a terminal on stdin
(exit 2), with no flag or variable to get past either. That keeps agents
from approving by accident; it is not a security boundary, since an agent
with a shell can edit the skill and MCP files directly. Agents are told to ask the
user to run `bd agents approve` in a separate terminal.

## Session-start hooks

`bd hook session-start --harness <claude|codex|copilot>` pulls the
harness's set at the start of each agent session, with pull semantics
(removals and restores of approved skills and MCP definitions applied; new
and changed skills and MCP definitions only reported), and tells the session what changed, in the format the harness
reads: plain text for Claude Code and Codex, one `{"additionalContext":
"..."}` JSON object for Copilot CLI. Without `--harness` it takes the
session's harness from its session variable, else the lock's harnesses
with plain-text output; Codex and Copilot CLI set no session variable for
hook processes, so their hooks pass `--harness`. It works in the session's
directory, the `cwd` of the hook's JSON input on stdin (`-C` wins), as
Copilot CLI runs a plugin's hooks in the plugin's own directory. `bd prime
--hook <harness>` does the same for the prime text: Copilot CLI gets it as
one JSON object (it drops plain text), Claude Code and Codex as plain text.
The skills it restores run in the session that starts, as approved before.

It says nothing when nothing changed, outside a checkout, and with no
harness known; a session start with nothing served writes nothing (no lock,
no mutex file). Otherwise each line starts with `bd:`:

```
bd: agent skills updated from the bd server: deploy (restored), old (removed).
bd: if these skills are not available yet, ask the user to run `/reload-skills`.
bd: agent skills changed on the bd server and not applied: lint (new), triage (changed: SKILL.md). Ask the user to review them and run `bd agents approve` in a separate terminal.
bd: MCP server definitions applied to .mcp.json: old (removed). Ask the user to restart Claude Code to apply the change.
bd: MCP server definitions changed on the bd server and not applied: github (changed: args), linear (new). Ask the user to review them and run `bd agents approve` in a separate terminal.
bd: 1 agent asset conflict (files or MCP entries in the way, left as they are): `bd agents status` lists it.
bd: environment variables the MCP servers read are unset: LINEAR_KEY.
```

Pending skills, pending MCP changes and conflicts are repeated at every session start
until resolved. A problem (the server unreachable or stalling, the token
missing or refused, the checkout's mutex busy, an invalid set or lock) is
one line, `bd: agent skills and MCP definitions not checked: <reason>`, and
the hook still exits 0. The whole hook takes at most about 5 s from the
start of its process: reading its input takes 2 s at most (when stdin is
left open); of what is left, a fifth (0.2 to 1 s) goes to waiting for the
checkout's mutex and the rest (at least 1 s) to the server, all its
requests and retries against one deadline, even when the server accepts the
connection and never answers. Files are written only once the server's
answers are in and checked, so running out of time leaves nothing half
written.

`bd remote set` (with a token available) and `bd remote login` (for the
checkout's own workspace, unless `--no-verify`) add a hint
when the workspace serves sets, so the skill directories exist before the
first session (nothing is pulled, as no harness is known yet; nothing is
said when nothing is served or no answer came within 3 s):

```
  agent assets are served for claude, codex, copilot: `bd agents pull --harness <claude|codex|copilot>` (for each harness used here) places them in this checkout before the first agent session
```

`bd agents pull --harness <h>` writes the harness's entries below where
none is configured ([Pulling into a checkout](#pulling-into-a-checkout)),
so a fresh checkout needs only `bd remote set` (or login) and one pull.

**Claude Code** (`.claude/settings.json`; the `SessionStart` entry of this
repository's): `bd hook session-start` also gives the session its own actor
([Actors](concepts.md#actors)). `--harness claude` acts only when Claude Code runs it
(`$CLAUDE_ENV_FILE` or `$CLAUDE_CODE_SESSION_ID` set), and prints and
writes nothing otherwise, as Copilot CLI also runs a repository's
`.claude/settings.json` hooks; a Copilot CLI session started from a Claude
Code shell inherits `$CLAUDE_CODE_SESSION_ID` and is taken for Claude Code.

```json
{
  "hooks": {
    "SessionStart": [
      {
        "hooks": [
          {
            "type": "command",
            "command": "bd hook session-start --harness claude"
          },
          {
            "type": "command",
            "command": "bd prime"
          }
        ]
      }
    ]
  }
}
```

**Copilot CLI**: this repository's plugin, `.copilot-plugin/plugin.json`,
runs `bd hook session-start --harness copilot`, then `bd prime --hook
copilot`, on `SessionStart`. A repository can use a hook file instead,
`.github/hooks/bd.json` (any `.github/hooks/*.json`):

```json
{"version": 1, "hooks": {"sessionStart": [
  {"type": "command", "command": "bd hook session-start --harness copilot"},
  {"type": "command", "command": "bd prime --hook copilot"}
]}}
```

Copilot CLI also runs a repository's `.claude/settings.json` hooks, where
`--harness claude` stays inert and plain `bd prime`'s output is dropped.
Leave out `matcher` to match every occurrence of an event, rather than
writing `"matcher": ""`: Copilot CLI 1.0.91 refuses a `.claude/settings.json`
with an empty `matcher`, warning at each session start (`matcher cannot be
empty`) and skipping the whole file, while Claude Code treats both alike.

**Codex** (`.codex/hooks.json` in the repository):

```json
{"hooks": {"SessionStart": [{"matcher": "startup|resume|clear|compact", "hooks": [
  {"type": "command", "command": "bd hook session-start --harness codex", "timeout": 30},
  {"type": "command", "command": "bd prime", "timeout": 30}
]}]}}
```

Codex loads project hooks only when the project's `.codex/` layer is
trusted, and each hook must be reviewed and trusted in `/hooks` (per hook
hash: an edited hook needs trust again; `codex exec
--dangerously-bypass-hook-trust` skips that for one run). Codex shows the
model about 2,500 tokens of hook output by default and spills the rest to a
file: a long `bd prime` (many memories) may need `"additionalContextLimit"`
raised on its handler.

## Reloading

Skills written at session start were not listed on the session's first
turn by any of the three harnesses, and MCP changes need a reload:

| harness | skills | MCP definitions |
|---|---|---|
| Claude Code | live, but `.claude/skills` is watched only if it existed at session start: `/reload-skills` | restart Claude Code (it may also ask to approve new `.mcp.json` servers) |
| Copilot CLI | `/skills reload` | `/mcp reload` |
| Codex | automatic | restart Codex (it reads a project's `.codex/config.toml` only in trusted projects) |

The hook's lines and `approve`'s output name the step to take.

## Caveats

- Copilot CLI also reads `.claude/skills`, `.agents/skills` and `.mcp.json`,
  and `.mcp.json` wins over `.github/mcp.json` when a server name is in
  both. Pull only the sets of the harnesses used in a checkout, or a
  Copilot CLI session there also gets the Claude and Codex sets.
- On mounts that keep no executable bits (vfat, exfat, or SMB mounts with
  an `fmask` that clears them), scripts the server marks executable stay
  without them: run them through their interpreter (`sh run.sh`). Mounts
  that show every file as executable (WSL's `/mnt/c` without `metadata`)
  are fine.
