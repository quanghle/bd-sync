//! `bd mcp`, `bd serve` and `bd serve token`.

use std::path::PathBuf;

use clap::{Args, Subcommand};

/// Long help of `bd mcp`.
pub const MCP_LONG_ABOUT: &str = "\
Serve this workspace to an AI assistant as MCP tools over stdio

Use it as the command of an MCP client's stdio server entry: the client starts
`bd mcp` and talks JSON-RPC on its stdin and stdout. The tools run as bd
commands in this workspace, or through bd serve in a remote workspace, as the
session's actor. With no actor named and no agent session, each `bd mcp`
process is a session of its own, named mcp-<hex>. For MCP over HTTP, use the
/w/<name>/mcp endpoints of `bd serve` instead.";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = "\
Examples:
  bd mcp
  bd mcp --read-only")]
pub struct McpArgs {
    /// Offer only the tools that read (ready, list, show, memories)
    #[arg(long)]
    pub read_only: bool,
}

/// Long help of `bd serve`.
pub const SERVE_LONG_ABOUT: &str = "\
Serve workspaces to bd and MCP clients over HTTP(S)

Use it to share workspaces between machines: each workspace <root>/<name>/.bd
is served at /w/<name>, to bd clients (`bd remote set`) and to MCP clients at
/w/<name>/mcp. Clients need an access token: one an admin creates with
`bd serve token create`, or one from signing in, set up in <root>/auth.toml.
Without --tls-cert the server speaks plain HTTP, always allowed on a loopback
address; on any other address it needs --insecure-http. Background jobs run
in every workspace: lease reclaim, gate checks, agent set changes and, with
--backup-dir, backups.";

#[derive(Args, Debug, Clone)]
#[command(
    args_conflicts_with_subcommands = true,
    after_long_help = "\
Examples:
  bd serve --root /srv/bd
  bd serve --root /srv/bd --listen 0.0.0.0:7420 --tls-cert cert.pem --tls-key key.pem
  bd serve --root /srv/bd --backup-dir /var/backups/bd --backup-every 6h"
)]
pub struct ServeArgs {
    #[command(subcommand)]
    pub action: Option<ServeAction>,
    /// Directory of workspaces: <root>/<name>/.bd/bd.db is served at /w/<name> (tokens in server.db, sign-in in
    /// auth.toml)
    #[arg(long, env = "BD_SERVE_ROOT", value_name = "DIR")]
    pub root: Option<PathBuf>,
    /// Address and port to listen on
    #[arg(long, default_value = "127.0.0.1:7420", value_name = "ADDR")]
    pub listen: String,
    /// TLS certificate chain (PEM): serve HTTPS
    #[arg(long, requires = "tls_key", value_name = "FILE")]
    pub tls_cert: Option<PathBuf>,
    /// TLS private key (PEM)
    #[arg(long, requires = "tls_cert", value_name = "FILE")]
    pub tls_key: Option<PathBuf>,
    /// Allow plain HTTP on a non-loopback address (behind a TLS proxy, or on an encrypted private network)
    #[arg(long)]
    pub insecure_http: bool,
    /// Largest request body accepted, in MiB (1 to 4096; imports and batches travel in the body)
    #[arg(long, default_value_t = 64, value_name = "MIB")]
    pub max_body_mib: u64,
    /// How often to reclaim leases expired past lease.grace in every workspace, from 100ms to 365d (0 or off =
    /// never)
    #[arg(long, default_value = "1m", value_name = "DURATION")]
    pub reclaim_every: String,
    /// How often to check timer, issue and human gates in every workspace, from 100ms to 365d (0 or off = never)
    #[arg(long, default_value = "1m", value_name = "DURATION")]
    pub gate_check_every: String,
    /// How often to check GitHub gates with this host's gh, from 100ms to 365d (0 or off = never)
    #[arg(long, default_value = "5m", value_name = "DURATION")]
    pub gh_check_every: String,
    /// How often to check every workspace's agent sets (.bd/agents) for changes, from 100ms to 365d (0 or off =
    /// never)
    ///
    /// A change appends an agents_changed event, which `bd agents watch` clients wait for.
    #[arg(long, default_value = "30s", value_name = "DURATION")]
    pub agents_every: String,
    /// Back up every workspace into DIR/<name>/ (default: no backups)
    #[arg(long, value_name = "DIR")]
    pub backup_dir: Option<PathBuf>,
    /// How often to back up each workspace, from 100ms to 365d (0 or off = never)
    #[arg(long, default_value = "1h", value_name = "DURATION", requires = "backup_dir")]
    pub backup_every: String,
    /// Backups kept per workspace; older ones are deleted (0 = keep all)
    #[arg(long, default_value_t = 24, value_name = "N", requires = "backup_dir")]
    pub backup_keep: usize,
    /// Clients waiting for new events at once (`events --follow`, `--wait`), 0 to 256; others poll
    #[arg(long, default_value_t = 256, value_name = "N")]
    pub max_followers: usize,
    /// Longest wait of a long poll, from 1s to 5m; keep it below the idle timeout of proxies in front
    #[arg(long, default_value = "25s", value_name = "DURATION")]
    pub max_wait: String,
    /// URL clients reach the server at, path prefix included, e.g. https://bd.example.com/bd
    ///
    /// MCP endpoints and the OAuth issuer name themselves by it. An http:// or https:// URL with no query,
    /// fragment or user info. Default for MCP endpoints: the request's Host and path prefix, with https when
    /// --tls-cert is set. [oauth] in auth.toml requires it, as an https URL (http only on a loopback host).
    #[arg(long, env = "BD_SERVE_PUBLIC_URL", value_name = "URL")]
    pub public_url: Option<String>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ServeAction {
    /// Manage access tokens (on the server host)
    #[command(subcommand)]
    Token(TokenCommand),
    /// Check auth.toml as the server reads it and print what to register
    #[command(long_about = SERVE_CHECK_LONG_ABOUT)]
    Check(ServeCheckArgs),
}

const SERVE_CHECK_LONG_ABOUT: &str = "\
Check auth.toml as the server reads it and print what to register

A running bd serve applies changes to <root>/auth.toml without a restart (it
re-reads the file when it changes and at least every 30 s), so check an edited
copy before it replaces the live file, or before starting bd serve: it reads
auth.toml and its secret files as a running server would, without starting
one, running its [secrets] command (on Unix only as the root directory's
owner). It prints the sign-in providers, and with --public-url what to register
at providers and clients (callback URLs, account notification URLs, MCP
endpoints). Exits 2 on a mistake.";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = "\
Examples:
  bd serve check --root /srv/bd
  bd serve check --root /srv/bd --public-url https://bd.example.com")]
pub struct ServeCheckArgs {
    /// URL clients reach the server at, as `bd serve --public-url`: the URLs to register are under it
    #[arg(long, env = "BD_SERVE_PUBLIC_URL", value_name = "URL")]
    pub public_url: Option<String>,
    #[command(flatten)]
    pub root: TokenRootArgs,
}

#[derive(Subcommand, Debug, Clone)]
pub enum TokenCommand {
    /// Create an access token and print its secret once
    #[command(long_about = TOKEN_CREATE_LONG_ABOUT)]
    Create(TokenCreateArgs),
    /// List access tokens (never their secrets)
    #[command(alias = "ls")]
    List(TokenRootArgs),
    /// List signed-in accounts and their actors
    Accounts(TokenRootArgs),
    /// Revoke a token, an account's sign-in tokens or a client's tokens
    #[command(long_about = TOKEN_REVOKE_LONG_ABOUT)]
    Revoke(TokenRevokeArgs),
    /// Show the audit trail of sign-ins and token changes (kept 90 days)
    Events(TokenEventsArgs),
    /// Bind an account to another account's actor
    #[command(long_about = TOKEN_LINK_LONG_ABOUT)]
    Link(TokenLinkArgs),
    /// Give an account a name shown to admins
    #[command(long_about = TOKEN_NAME_LONG_ABOUT)]
    Name(TokenNameArgs),
}

const TOKEN_CREATE_LONG_ABOUT: &str = "\
Create an access token and print its secret once

Use it to let a person, a machine or CI use workspaces on this server without
signing in. The secret is printed once and never stored: on the client, save
it with `bd remote login` or set it as $BD_TOKEN. The token acts as the --as
actor, or as any of its sub-actors <actor>/<name>. With --resource, it works
only at that MCP endpoint, as an MCP client's bearer token. Revoke it with
`bd serve token revoke <name>`.";

const TOKEN_REVOKE_LONG_ABOUT: &str = "\
Revoke a token, an account's sign-in tokens or a client's tokens

Name one token, or with --account every token an account got by signing in,
or with --client every token issued to an OAuth client. Revoked tokens stop
working at once. The account stays bound to its actor, so its next sign-in
acts as the same actor; --forget also releases the actor and deletes the
account's records.";

const TOKEN_LINK_LONG_ABOUT: &str = "\
Bind an account to another account's actor

Use it when one person signs in with several providers and should be one
actor: the account named first then acts as the actor of the account --to
names, which must have signed in already. This lets that account act as the
other's actor, so it is an admin's decision. The account's tokens are revoked,
as they act as its former actor; its next sign-in acts as the new one.";

const TOKEN_NAME_LONG_ABOUT: &str = "\
Give an account a name shown to admins

Accounts act as <provider>:<login>, and a login may be a pseudonym such as
u-3f9a2c1e7b04 when the provider gives no user name. A name, shown by
`bd serve token accounts`, tells admins whose account it is. It does not
change the account's actor.";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = "\
Examples:
  bd serve token name corp:u-3f9a2c1e7b04 \"Alice (contractor)\" --root /srv/bd
  bd serve token name corp:u-3f9a2c1e7b04 --clear --root /srv/bd")]
pub struct TokenNameArgs {
    /// Account: its actor, or its login
    pub account: String,
    /// Name to show (plain text, 1 to 64 characters)
    #[arg(required_unless_present = "clear")]
    pub name: Option<String>,
    /// Remove its name instead
    #[arg(long, conflicts_with = "name")]
    pub clear: bool,
    #[command(flatten)]
    pub root: TokenRootArgs,
}

#[derive(Args, Debug, Clone)]
#[command(after_long_help = "\
Examples:
  bd serve token link other:u-3f9a2c1e7b04 --to corp:alice --root /srv/bd")]
pub struct TokenLinkArgs {
    /// Account to bind: its actor, or its login
    pub account: String,
    /// Actor of the account to join, e.g. corp:alice
    #[arg(long, value_name = "ACTOR")]
    pub to: String,
    #[command(flatten)]
    pub root: TokenRootArgs,
}

#[derive(Args, Debug, Clone)]
pub struct TokenEventsArgs {
    /// Only events this recent, e.g. 7d (default: all kept)
    #[arg(long, value_name = "DURATION")]
    pub since: Option<String>,
    /// Only this actor's, and its sub-actors'
    #[arg(long, visible_alias = "by", value_name = "ACTOR")]
    pub actor: Option<String>,
    /// Only these kinds: signed_in, token_created, refreshed, revoked, forgotten, client_registered, linked or
    /// named (repeatable or comma separated)
    #[arg(long = "kind", value_name = "KIND", value_delimiter = ',')]
    pub kinds: Vec<String>,
    /// Show at most this many, the latest
    #[arg(short = 'n', long, default_value_t = 100, value_name = "N")]
    pub limit: usize,
    #[command(flatten)]
    pub root: TokenRootArgs,
}

#[derive(Args, Debug, Clone)]
pub struct TokenRootArgs {
    /// Server root holding server.db, where the access tokens are kept
    #[arg(long, env = "BD_SERVE_ROOT", value_name = "DIR")]
    pub root: PathBuf,
}

#[derive(Args, Debug, Clone)]
#[command(after_long_help = "\
Examples:
  bd serve token create ci --as ci-bot --role write --root /srv/bd
  bd serve token create alice-laptop --as alice --kind human --workspace proj --root /srv/bd
  bd serve token create assistant --as alice --resource https://bd.example.com/w/proj/mcp --root /srv/bd")]
pub struct TokenCreateArgs {
    /// Unique token name, e.g. alice-laptop or ci: a letter or digit, then letters, digits, '.', '_' or '-' (at
    /// most 64)
    pub name: String,
    /// Actor the token acts as, or any of its sub-actors <actor>/<name> (no ':' in its first part; bd-serve is
    /// reserved)
    #[arg(long = "as", value_name = "ACTOR")]
    pub act_as: String,
    /// What the token may do (each role includes the ones before it)
    ///
    /// bd serve never runs commands that act on the client's machine, whatever the role. serve, mcp, remote, hook
    /// and bench run where they are typed. init and backup work only on a local workspace. In a checkout that uses
    /// a bd server, events --follow, agents status/pull/approve/watch and playbook extract --save run on the
    /// client, through read requests any role allows.
    #[arg(long, value_enum, default_value = "write")]
    pub role: crate::tokens::Role,
    /// Who holds the token: a person's (human) may also resolve human gates
    #[arg(long, value_enum, default_value = "agent")]
    pub kind: crate::tokens::Kind,
    /// Workspaces the token may use (repeatable or comma separated; default: all)
    #[arg(long = "workspace", value_delimiter = ',', value_name = "NAME")]
    pub workspaces: Vec<String>,
    /// Most issues its actor and sub-actors may hold, claimed or reserved, at least 1; applies whatever the role
    /// (default: no limit)
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u32).range(1..))]
    pub max_claims: Option<u32>,
    /// Bind the token to one workspace's MCP endpoint, as clients reach it (https://<host>[/<prefix>]/w/<name>/mcp):
    /// refused anywhere else, CLI requests included
    #[arg(long, value_name = "URL")]
    pub resource: Option<String>,
    #[command(flatten)]
    pub root: TokenRootArgs,
}

#[derive(Args, Debug, Clone)]
#[command(after_long_help = "\
Examples:
  bd serve token revoke ci --root /srv/bd
  bd serve token revoke --account corp:alice --root /srv/bd
  bd serve token revoke --account corp:alice --forget --root /srv/bd")]
pub struct TokenRevokeArgs {
    /// Name of the token to revoke
    #[arg(required_unless_present_any = ["account", "client"])]
    pub name: Option<String>,
    /// Revoke every token this account got by signing in, with any provider, instead of a named one: the
    /// account's actor or login
    #[arg(long, value_name = "LOGIN", conflicts_with = "name")]
    pub account: Option<String>,
    /// With --account: also release the account's actor and delete its records; the next account to sign in as
    /// that actor gets it
    #[arg(long, requires = "account", conflicts_with = "name")]
    pub forget: bool,
    /// Revoke every token issued to this OAuth client (its client ID, as `bd serve token list` shows it), instead
    /// of a named one
    #[arg(long, value_name = "CLIENT_ID", conflicts_with_all = ["name", "account"])]
    pub client: Option<String>,
    #[command(flatten)]
    pub root: TokenRootArgs,
}
