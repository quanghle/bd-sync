# Security

This page collects bd's trust boundaries and safeguards in one place. Each
section links to the page with the details.

## Local workspaces

- **No authentication.** Any process that can open `.bd/bd.db` can read and
  change everything in it. Actor names (`--actor`, `$BD_ACTOR`, the derived
  `<user>/<session>`) label who did what and decide who holds a claim, but
  are not verified: claim ownership keeps cooperating agents from ending
  each other's work by mistake, not a hostile process out
  ([Actors](concepts.md#actors), [Claims](concepts.md#claims-leases-and-recovery)).
- **Nothing leaves the machine.** Logs, metrics and health checks are local;
  a remote workspace talks only to its own `bd serve`
  ([Observability](observability.md)).
- **GitHub gates run `gh` with the credentials of whoever checks them**, so
  `gate.repos` lists the repositories a gate may name; a gate naming another
  is refused when written and escalated instead of probed
  ([Gates](playbooks.md#gates)).

## Remote server

A bd server is the trust boundary of a remote workspace: tokens decide what
each client may do, and the checks run in the engine, so a `bd batch` or a
playbook run gets the same answer as a single command
([Remote server](remote.md)).

- **Transport.** `bd serve` refuses plain HTTP on a non-loopback address
  unless given `--insecure-http`: give it a certificate, or keep it on
  loopback behind a TLS-terminating proxy. Clients refuse plain `http://` to
  a non-loopback host unless `BD_INSECURE_HTTP=1`
  ([Server](remote.md#server)).
- **Access tokens.** `<root>/tokens.json` holds token hashes only; each
  secret is printed once, at creation. `bd serve token revoke` takes effect
  at once, with no restart.
- **Roles and kinds.** A token's role (`read`, `write`, `admin`) limits the
  commands it runs; a `read` token's database connection is query-only. Its
  kind (`agent` or `human`) says who holds it: only human tokens open human
  gates, so keep them out of agents' environments
  ([Clients](remote.md#clients)).
- **Overrides need the right token.** Taking over another actor's live claim
  needs `--take-over` and an admin token (a token's own actor and its
  sub-actors need only `--take-over`). Getting past a human gate early needs
  a human token. Only admins change `metadata.playbook` on existing issues,
  set configuration (`gate.repos` included), import, prune events or run
  `doctor`.
- **Actors are bound to tokens.** A token acts as its actor or its
  sub-actors `<actor>/<name>`; `--actor` and `$BD_ACTOR` may name nothing
  else. The server's own actor, `bd-serve`, which runs its background jobs,
  is reserved: no token may act as it.
- **Claim limits.** `max_claims` (per token, or per GitHub sign-in rule)
  caps the open issues a token's actors hold, so that no one takes the whole
  ready queue. It guards against greed, not malice.
- **Resource limits.** Request bodies (`--max-body-mib`, default 64), a
  shared memory budget, at most 8 streaming reads, at most 4 requests
  bringing their own playbooks, and at most `--max-followers` waiting
  requests; slow or stalled readers lose their answer. Excess requests are
  answered 503, which clients retry ([Followers](remote.md#followers)).
- **The server's host is not limited by tokens.** `bd` run on the host opens
  `bd.db` directly; guard the root directory like the database it is.
- **Backups hold everything.** On Unix, backup files are created 0600 and the
  directories bd creates 0700; keep them on another disk or ship them
  elsewhere ([Background jobs and backups](remote.md#background-jobs-and-backups)).

## GitHub sign-in

Sign-in lets people get their own tokens, under rules in `<root>/auth.toml`
([Signing in with GitHub](remote.md#signing-in-with-github)).

- The server runs GitHub's device flow with an OAuth or GitHub App client ID,
  no secret. The account's GitHub token reads its account and memberships
  during the sign-in and is never stored or logged.
- Refreshes ask GitHub as the GitHub App, with installation tokens minted
  from its private key (`private_key`): the one secret the server holds for
  sign-in. Keep the key file mode 0600, readable by `bd serve` only; whoever
  has it can read what the App may (organization members). Give the App
  nothing but **Members** (read).
- An account no rule lets in gets nothing. An `anyone = true` rule must be
  the last, and its tokens read by default, may write at most, and are
  always `agent` tokens. `min_account_age` keeps out accounts made on the
  spot; `deny` keeps out an account for good (also revoke its tokens).
- Each GitHub account is bound to its actor for good, by user id, at its
  first sign-in, so a renamed or re-registered login cannot pass for the
  previous holder. Only `bd serve token revoke --github <login> --forget`
  releases a binding.
- Sign-in access tokens expire (`token_ttl`, default 1 hour), and each
  refresh applies the rules again, so someone who leaves an organization
  loses access within `token_ttl`. Refresh tokens rotate at every refresh
  and work once: a copy used after the original (or the original after a
  copy) revokes the sign-in. A sign-in is refreshed for at most
  `refresh_limit` (30 days), and not after `refresh_idle` (7 days) unused.
  `tokens.json` keeps only hashes of both. `bd remote logout` and a
  replacing sign-in revoke them on the server; `bd serve token revoke` ends
  refreshes too.
- Whoever started a sign-in gets its token: enter only codes shown by one's
  own `bd remote login --github`.
- Tokens saved by `bd remote login` serve every process of that user on that
  machine, agents included: a rule's `kind = "human"` lets those agents
  resolve human gates too.

## Clients

- **`$BD_TOKEN` goes only where `--remote` or `$BD_REMOTE` points**, never
  to a URL from a `.bd/remote.toml`, which a cloned repository, a pull
  request or a submodule could set to its own server
  ([Clients](remote.md#clients)).
- **Saved tokens** live in `$XDG_CONFIG_HOME/bd/credentials.toml`
  (`%APPDATA%\bd\credentials.toml` on Windows). On Unix the file is mode
  0600 in a directory created 0700, and bd refuses a file other users can
  read. A saved token is bound to the certificate authorities it was checked
  against, so a checkout naming its own CA for a server cannot redirect it.
- **Tokens never appear on the command line or in output.** `bd remote
  login` reads them from stdin or a prompt without echo; `bd remote show`
  and `bd info` show a token's name, role, kind and expiry, never its secret.
- **Printed output never drives a terminal.** Control characters and
  bidirectional formatting characters in stored text or a server's answer
  are printed as `\uXXXX`, by the command and again by the client.

## Agent skills and MCP definitions

A workspace can serve skills and MCP server definitions to agent harnesses
([Agent skills and MCP definitions](agents.md)).

- **Skills and MCP definitions wait for a person.** Skills are code: they
  can run commands, register hooks and pre-approve tools, as an MCP
  definition runs a command. A pull, hook or watch never writes a new or
  changed skill file, executable bit or MCP definition; `bd agents approve`
  shows each skill file by file (in full, or as a diff) and each
  definition, asks on a terminal, and refuses agent sessions and
  non-terminals with no bypass ([Approving skills and MCP
  definitions](agents.md#approving-skills-and-mcp-definitions)). A client
  records only hashes it checked against the texts they name, never a
  manifest's word for them, and writes without approval only the very
  bytes approved, line endings included. Guard
  `.bd/agents` on the server like a code deployment all the same
  ([Trust](agents.md#trust)).
- **No secrets on the server.** MCP servers run and authenticate on the
  client; bd never handles MCP credentials.
- **Strict sets.** Sets are validated on the server and again by clients
  before anything is written: no settings or hooks in MCP files, portable
  paths, symlinks contained in `.bd/agents`, size limits. A pull never
  follows a symlink in a skill directory and never overwrites files it did
  not write.

## Release binaries

Each release has a `SHA256SUMS` file and a signed build-provenance
attestation per archive; [Install](install.md#prebuilt-binaries) shows how to
check both.

## Reporting a vulnerability

Please do not open a public issue for a vulnerability. Report it privately
through [GitHub's private vulnerability reporting](https://github.com/quanghle/bd-sync/security/advisories/new)
(the repository's Security tab, then "Report a vulnerability").
