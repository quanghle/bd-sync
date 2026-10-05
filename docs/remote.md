# Remote server

`bd serve` lets several machines (laptops, CI runners, cloud agents) share
workspaces. The databases stay on the server; clients send whole commands,
and each runs there as it would locally, normally as one write
transaction. Claims stay atomic, lease times and fencing tokens come from
one clock, and the event log stays gapless.

The same `bd` binary is the server and the client. This page covers
running a server, access tokens, clients, background jobs and the
protocol. People can also get tokens by [signing in](sign-in.md), and each
workspace is an [MCP server](mcp.md) too.

## Running a server

A server serves every workspace under one root directory:
`<root>/<name>/.bd/bd.db` is served at `/w/<name>`. Workspace names are at
most 100 characters: a letter or digit, then letters, digits, `.`, `_` and
`-`.

```bash
# Create a workspace (or move one: bd export -o proj.jsonl, then bd -C /srv/bd/proj import proj.jsonl)
mkdir -p /srv/bd/proj && bd -C /srv/bd/proj init --prefix proj

# Access tokens: each secret is printed once
bd serve token create alice-laptop --as alice --root /srv/bd
bd serve token create ci --as ci --workspace proj --root /srv/bd

bd serve --root /srv/bd --listen 0.0.0.0:7420 --tls-cert cert.pem --tls-key key.pem
```

`bd serve` refuses plain HTTP on a non-loopback address. Either give it a
certificate, or keep the default `--listen 127.0.0.1:7420` behind a
TLS-terminating reverse proxy or tunnel, which may also serve it under a
path prefix (`https://example.com/bd/w/proj`). `--insecure-http` allows
plain HTTP, for an encrypted private network.

Without a public CA, a self-signed certificate works as long as it is not a
CA certificate; clients trust it with `BD_CA_CERT=cert.pem` or
`bd remote set --ca-cert`:

```bash
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 365 \
  -keyout key.pem -out cert.pem -subj "/CN=bd.example.com" \
  -addext "subjectAltName=DNS:bd.example.com" -addext "basicConstraints=critical,CA:FALSE"
```

### Options

| flag | default | meaning |
|---|---|---|
| `--root DIR` (`$BD_SERVE_ROOT`) | required | the directory of workspaces, and `server.db` |
| `--listen ADDR` | `127.0.0.1:7420` | address to listen on |
| `--tls-cert FILE`, `--tls-key FILE` | | serve HTTPS (HTTP/1.1) |
| `--insecure-http` | off | allow plain HTTP on a non-loopback address |
| `--public-url URL` (`$BD_SERVE_PUBLIC_URL`) | from each request's `Host` | the URL clients reach the server at, path prefix included; needed behind a proxy for MCP and OAuth ([Discovery](mcp.md#discovery)) |
| `--max-body-mib N` | 64 | largest request body (1 to 4096) |
| `--reclaim-every`, `--gate-check-every`, `--gh-check-every`, `--agents-every` | 1m, 1m, 5m, 30s | [background jobs](#background-jobs) |
| `--backup-dir DIR`, `--backup-every`, `--backup-keep` | off, 1h, 24 | [backups](#backups) |
| `--max-followers N`, `--max-wait D` | 256, 25s | [followers](#followers) |

`GET /healthz` answers `ok` for load balancers, and `GET /metrics` serves
counters to admin tokens ([Observability](observability.md)); both answer
only at those exact paths, so a proxy serving bd under a prefix must strip
it for them.

### Limits

Requests are bounded so that slow or greedy clients cannot crowd out
claims. Requests over the command, memory, planning or streaming limits are
answered `503`, which clients retry.

- **Connections**: at most 512, and 64 from one address (other than this
  machine's: a local proxy's connections are everyone's); a connection over
  either limit is closed as it is accepted. Request headers,
  and an idle keep-alive connection's next request, must arrive within 75
  seconds; a request body within 120 seconds; a TLS handshake within 15
  seconds. A connection closes after 15 minutes, once the answer under way
  is sent (cut 2 minutes later).
- **Commands**: at most 32 run at once. Requests in progress share a
  memory budget of 256 MiB (more if one maximum-size request needs it). A
  request waits up to 15 seconds for a slot or budget before its 503.
- **Streaming**: past 64 KiB, a read's output streams to the client as it
  is written, through under 1 MiB of buffers, so a large `bd export` costs
  no more memory than a claim. A write's output is held, up to 1 MiB, so a
  retry can be answered with it ([Retries](#retries-and-exit-codes)). At most 8 answers stream at once. A
  client that takes nothing for 60 seconds, or takes a streamed answer
  slower than 64 KiB/s on average after its first 30 seconds, loses the
  rest, and its command ends.
- **Playbooks from clients**: at most 4 requests that bring their own
  playbooks plan at once.

### One server per root

Run one `bd serve` per root: two would each run the background jobs, and
neither would know the other's sign-ins in progress. What lasts is on
disk: the workspaces' databases and `<root>/server.db` (accounts, tokens,
registered OAuth clients, the audit trail). A restart loses what is kept
in memory: OAuth authorizations in progress (the person starts again), a
device-flow answer the client did not receive (it signs in again), and
cached provider and client metadata (fetched again). Tokens, accounts and
refreshes carry on.

Ctrl-C or SIGTERM lets running commands finish (up to 30 seconds). The
server keeps database connections open, so restart it after replacing or
moving a workspace's `bd.db`. It warns at start if the root is open to
other users: `chmod 700` it.

With systemd, as an unprivileged user `bd` that owns the root:

```ini
# /etc/systemd/system/bd-serve.service
[Unit]
Description=bd serve
After=network-online.target
Wants=network-online.target

[Service]
User=bd
ExecStart=/usr/local/bin/bd serve --root /srv/bd --listen 127.0.0.1:7420 \
    --public-url https://bd.example.com --backup-dir /var/backups/bd
Restart=on-failure
RestartSec=2
TimeoutStopSec=45
UMask=0077
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/srv/bd /var/backups/bd
ProtectHome=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

`systemctl enable --now bd-serve` starts it now and at boot;
`journalctl -u bd-serve` shows its log (set journald's `MaxRetentionSec=`
to bound how long logins stay in it). An authorizer command runs as the
same user, under the same limits. On macOS, use a launchd agent with
`KeepAlive`.

## Access tokens

Tokens live in `<root>/server.db` as hashes; each secret is printed once.
`bd serve token` runs on the server's host:

```bash
bd serve token create NAME --as ACTOR [--role read|write|admin] [--kind agent|human] \
    [--workspace a,b] [--max-claims N] [--resource URL] --root /srv/bd
bd serve token list --root /srv/bd                  # alias: ls
bd serve token revoke NAME --root /srv/bd           # takes effect at once, no restart
bd serve token events --since 7d --root /srv/bd     # the audit trail
```

| option | meaning |
|---|---|
| `--as ACTOR` | the token acts as this actor, or its sub-actors `<actor>/<name>` |
| `--role` | `read`, `write` (default) or `admin` (below) |
| `--kind` | `agent` (default) or `human`: who holds it. Only human tokens open human gates; keep them out of agents' environments |
| `--workspace` | limit it to these workspaces (default: all) |
| `--max-claims N` | its actor and sub-actors hold at most N open issues at once ([Rules](sign-in.md#rules)) |
| `--resource URL` | bind it to one MCP endpoint ([Tokens bound to an endpoint](mcp.md#tokens-bound-to-an-endpoint)) |

`bd serve token events` lists the audit trail (kept 90 days): `signed_in`,
`token_created`, `refreshed`, `revoked`, `forgotten`,
`client_registered`, `linked` and `named`, filtered by `--since`,
`--actor` (alias `--by`), `--kind` and `-n` (default 100). The other
subcommands, `accounts`, `link`, `name` and `revoke --account/--client`,
manage [signed-in accounts](sign-in.md#accounts-and-actors).

The server's own actor, `bd-serve`, which runs the background jobs, is
reserved: no token acts as it or its sub-actors.

### Roles and what tokens may do

| role | may run |
|---|---|
| `read` | read-only commands; its database connection is query-only |
| `write` | every command except the admin ones |
| `admin` | also `config set/unset`, `import`, `events prune`, `doctor`, and taking over other actors' claims |

The server checks these in the engine, so `bd batch` and playbook runs get
the same answer as single commands:

- **Claims.** Taking over another actor's live claim needs `--take-over`,
  as locally, and an admin token, unless the claim is held by the token's
  own actor or one of its sub-actors. A token that may not take a claim
  over is refused with exit 7 (or exit 4 for a release or reassignment
  without `--take-over`). Dead claims stay reclaimable by any write token.
- **Human gates.** Opening one needs a human token, whatever the role:
  `gate resolve`, `close`, pinning it, changing its type or condition, or
  deleting it; and so does moving the work it holds back past it early
  (removing the edge, `close --force`, pinning or deleting the work or a
  container around it, moving either out of its parent). Imports are
  checked too. Other gates may be resolved by any write token.
- **Playbook metadata.** Only admins change `metadata.playbook`, which
  makes runs and groups close themselves, on an existing issue.
- **GitHub gates** may name only repositories in the workspace's
  `gate.repos`, which only admins set; unset, only the workspace's own.

`bd` run on the server's host opens `bd.db` directly and is not limited by
tokens. Guard the root like the databases it holds.

## Clients

Point a checkout at the server once and commit the result:

```bash
bd remote set https://bd.example.com/w/proj   # writes .bd/remote.toml (--ca-cert ca.pem for a private CA)
bd remote login                               # paste a token from the admin; it is checked, then saved
bd remote login --provider corp               # or sign in with one of the server's providers
bd remote show                                # checks URL, certificate, token and actor; shows the token's access
bd ready                                      # every command now runs on the server
```

```toml
# .bd/remote.toml
url = "https://bd.example.com/w/proj"
# ca_cert = "ca.pem"    # a private CA, relative to this file
```

A `.bd/remote.toml` takes precedence over a `.bd/bd.db` in the same
directory (`bd remote set` refuses to hide one without `--force`). `--db`
always means a local database and cannot be combined with `--remote`.
`bd remote unset` (alias `rm`) removes the file.

### Tokens on the client

The token comes from `$BD_TOKEN`, else from those saved by `bd remote
login`, never from the repository.

- **`$BD_TOKEN`** is sent only to the workspace URL that `--remote` or
  `$BD_REMOTE` names, never to one from a `.bd/remote.toml`: a cloned
  repository could name its own server there to collect it. CI and agents
  set `BD_REMOTE` (and `BD_CA_CERT` for a private CA) and take `BD_TOKEN`
  from a secret.
- **`bd remote login [URL]`** reads a token from stdin when piped, else
  from a prompt without echo, never from the command line. It checks the
  token with `bd info` on the server first (`--no-verify` skips that).
  With `--provider <name>` it signs in instead ([The device
  flow](sign-in.md#the-device-flow)), reporting the actor, role, kind,
  workspaces, expiry and refresh limit (`--json`: `actor`, `account`,
  `token`).
- **Saved tokens** go to `$XDG_CONFIG_HOME/bd/credentials.toml` (default
  `~/.config/bd/credentials.toml`; `%APPDATA%\bd\credentials.toml` on
  Windows), one per server: the URL up to `/w/<workspace>`, path prefix
  included. `--workspace-only` saves one for a single workspace, which
  takes precedence over its server's. On Unix the file is replaced
  atomically with mode 0600, in a directory created 0700, and refused if
  its group or others have any access bits.
- **A saved token is bound to the CAs it was checked against** (the
  system's, or the CA file in use at login). It is not sent where another
  CA would be trusted, so a checkout naming its own CA for your server
  cannot redirect it. Setting `BD_CA_CERT` yourself overrides the check.
- **`bd remote logout [URL]`** forgets the token saved for a workspace URL
  and its server (`--workspace-only` keeps the server's), or for a server
  URL and all its workspaces. A token from signing in is also revoked on
  the server; one an admin created stays valid until revoked there.

`bd remote show` and `bd info` show a token's name, role, kind,
workspaces, expiry and account, never its secret.

### Environment

| variable | meaning |
|---|---|
| `BD_REMOTE` / `--remote URL` | use this workspace URL instead of `.bd/remote.toml` |
| `BD_TOKEN` | access token for that URL; takes precedence over saved tokens |
| `BD_CA_CERT` | PEM file of the CA that signed the server certificate |
| `BD_ACTOR` (then `BEADS_ACTOR`) | act as the token's actor or `<token actor>/<name>`; anything else is refused |
| `BD_SESSION` | act as `<token actor>/<session>`; agent sessions send theirs on their own ([Actors](concepts.md#actors)) |
| `BD_REMOTE_RETRY_SECS` | how long to retry an unreachable server (default 30; `0` = once) |
| `BD_INSECURE_HTTP=1` | allow plain `http://` to a non-loopback host |

### Retries and exit codes

Every invocation carries a random request id. The client retries
connection failures, timeouts, busy answers and a proxy's gateway errors
with the same id, for up to `BD_REMOTE_RETRY_SECS` (each attempt has 120
seconds). The server records the id in the same transaction as the write
and stores its answer (up to 1 MiB of output), so a retry of a write whose
answer was lost gets the stored answer instead of running again: writes
apply once.

A write's answer is printed once it has arrived whole; a read prints a long
output as it arrives, so a read cut off after that fails rather than
retrying. Exit codes are the same as locally, plus:

| code | meaning |
|---|---|
| 7 | access denied: no token, an invalid or expired one, or one whose role, kind, workspaces or actor do not allow the command |
| 8 | server unreachable, untrusted certificate, or a read the server failed: the command did not take effect |
| 9 | a write may have reached the server but its answer was lost (over 1 MiB, the server failed while running it, or no answer before retries gave up): check before running it again |

### What runs where

- **Files stay on the client.** `import FILE` and `batch -f FILE` send the
  file; `--stdin` and `-` send stdin; `export -o` and `playbook extract -o`
  write locally (as `FILE.tmp`, renamed once the command succeeds).
- **Playbooks** are looked up in the checkout's `.bd/playbooks` first, then
  on the server's playbook path, then in your own `$BD_PLAYBOOK_PATH` and
  config directory. A playbook found on the client is sent with every file
  it extends or expands (at most 256 files of 512 KiB, 8 MiB in all), and
  the server compiles it as a local run would. `playbook list` and
  `bd prime` show all three sources, marking the server's.
- **Waiting**: `events --follow` and `events --wait` wait on the server
  ([Followers](#followers)).
- **Client only**: `init`, `backup`, `bench`, `serve`, `hook`, `remote` and
  `mcp` run only on the local machine; `bd agents status`, `pull`,
  `approve` and `watch` run on the client and read the server's sets
  ([Agent assets](agents.md)).
- **`bd prime`**, which session hooks run, gives up within seconds when the
  server is unreachable or there is no token, and prints a notice instead
  of failing the hook (with `--json` it fails like any other command).
- **GitHub gates** are checked by the server's `gh`.

Output never drives a terminal: control characters (except line ends and
tabs) and bidirectional formatting characters in stored text or a server's
answer are printed as `\uXXXX`, by the command and again by the client.
Output files (`-o`) are written as stored.

## Background jobs

`bd serve` keeps every workspace under the root up to date on its own,
including ones no client has used since it started (it looks for new ones
every 30 seconds):

| job | default | flag | what it does |
|---|---|---|---|
| lease reclaim | 1 minute | `--reclaim-every` | `bd reclaim` with the workspace's `lease.grace` (skipped where `lease.auto_reclaim` is `false`) |
| gate checks | 1 minute | `--gate-check-every` | `bd gate check --type local`: timer, issue and human-gate timeouts |
| GitHub gate checks | 5 minutes | `--gh-check-every` | `bd gate check --type gh` with the server's `gh` and its credentials; one or two API calls per armed gate |
| agent sets | 30 seconds | `--agents-every` | records an `agents_changed` event when a harness's set changes ([Agent assets](agents.md#serving-sets)) |
| backups | off | `--backup-dir` | [below](#backups) |
| request records | 1 hour | | deletes idempotency records older than a day |

Intervals take 100ms to 365d, or `0`/`off` to turn a job off. Jobs run the
commands' own code as actor `bd-serve`, so their events read like the
commands'. Timers are jittered per workspace, a job never overlaps
itself, and few run at once, so client requests keep their slots. `gh`
runs outside any transaction. A failed job is logged and retried later,
backing off up to 32 intervals; it never stops the server. At shutdown,
running jobs get 10 seconds; one still running is abandoned safely.

## Backups

With `--backup-dir /backups`, every `--backup-every` (default 1h) each
workspace is copied to `/backups/<name>/<name>-<UTC time>.db` (e.g.
`proj-20261001T214244.014Z.db`), keeping the newest `--backup-keep`
(default 24; `0` keeps all). `<root>/server.db` is copied the same way to
`/backups/_server/`.

- A copy is taken with SQLite's `VACUUM INTO`, which does not hold up
  writers, and is a compact, self-contained database.
- It is checked (`PRAGMA quick_check`) and flushed under a temporary name
  before it is renamed into place, so a file with the final name is
  complete.
- The copy just written is never deleted, even if older copies are dated
  after it (the clock was wrong); the server warns then.
- On Unix, files are created 0600 and the directories bd creates 0700.
  Keep them on another disk, or ship them elsewhere.

A local workspace gets the same copies from `bd backup --to DIR`
([Backing up a local workspace](modes.md#backing-up-a-local-workspace)).

**Restoring a workspace:**

```bash
# Stop bd serve first: it keeps the database open.
cd /srv/bd/proj/.bd
mkdir -p broken && mv bd.db* broken/            # the database and its -wal and -shm files
cp /backups/proj/proj-20261001T214244.014Z.db bd.db
bd -C /srv/bd/proj doctor                        # then start bd serve again
```

Later changes are gone, and their event sequence numbers are given out
again, so anything following events by cursor should re-baseline from
`bd export`. To bring a copy up as another workspace while the server
runs, copy it to `<root>/<new name>/.bd/bd.db.tmp`, then rename it to
`bd.db`.

**Restoring `server.db`:** stop `bd serve`, move `server.db` and its
`-wal` and `-shm` files aside, copy the backup to `<root>/server.db`, and
start it. Tokens issued or revoked since the copy are as they were then:
revoke again anything revoked since.

For continuous replication besides periodic copies, a WAL-based SQLite
replication tool can run next to `bd serve`, one database per workspace:
bd uses WAL mode, a busy timeout and `synchronous=NORMAL`.

## Followers

`bd events --follow` and `bd events --wait` on a remote workspace are long
polls. When no event matches yet, the server holds the request until one
is committed and answers at once: a follower sees an event within
milliseconds, and an idle one costs one request per `--max-wait`.

- **In order, once.** Each answer says where the next request continues,
  so a follower prints every event once and in order, even when an answer
  is lost and asked for again. A follower rides out server restarts: a
  retry that failed after the server held it gets the whole retry time
  again, up to 5 times. A server that stays down ends it after one retry
  time (exit 8).
- **Deleted issues.** A follower of `--issue` keeps the issue's full id
  from the first answer, so it keeps following an issue it named by a
  partial id after the issue is deleted.
- **Falling behind.** A follower whose events were deleted by retention
  says so on stderr and continues at the oldest event kept.
- **Cheap.** A waiting request holds no command slot, database connection
  or memory budget, only its connection (a request over 16 KiB is answered
  at once). The server learns of new events from the commands it runs,
  and, while anyone waits, by checking the events head every 500 ms for
  writes by other processes on its host. Under load a follower asks at
  most once per `--interval-ms` (default 500), so events arrive in batches.

| flag | default | meaning |
|---|---|---|
| `--max-followers N` | 256 | requests waiting at once (0 to 256); others are answered at once, and their clients poll |
| `--max-wait D` | 25s | the longest a request waits before answering that nothing came (1s to 5m) |

Keep `--max-wait` below the idle timeout of every proxy between clients
and the server (often 30 to 100 seconds). At shutdown, waiting requests
are answered with 503, which clients retry.

## Protocol

The CLI protocol (version 2) is one endpoint, so other clients can call it
directly:

```http
POST /w/<name>/v2/exec
Authorization: Bearer <token>
Content-Type: application/json

{"argv": ["claim", "--next", "--json"], "request_id": "..."}
```

`"tool_call": true` runs the command with the actor's own rights only, as
`bd mcp` sends a model's tool calls: never the token's admin or human
rights.

The answer (`application/x-ndjson`) is one JSON frame per line, in the
order the command wrote them:

| frame | meaning |
|---|---|
| `{"stdout": "..."}` | output |
| `{"file": {"path", "data"}}` | part of an output file |
| `{"cursor": N}` | (`events`) the `--since` value that continues after this answer |
| `{"issue": "ID"}` | (`events --issue`) the issue's full id |
| `{"exit": {"exit_code", "stderr", "replayed"}}` | last: the result |

Blank lines are keep-alives; an answer without the exit frame was cut off.
`["events", "--since", "N", "--wait", "25s", "--json"]` is a long poll.

Failures before the command runs (an unknown, expired or wrongly bound
token: 401; another workspace: 403; an unknown workspace: 404; a body too
large: 413; a bad body: 400; busy: 503) return that status with the
`--json` error shape. Failures decided once the request is read (a bad
command line, a read token writing, an actor the token may not use) are a
200 answer with an exit frame. Every answer carries `bd-protocol: 2` and
`bd-version` headers, which tell bd's own answers apart from a proxy's.
