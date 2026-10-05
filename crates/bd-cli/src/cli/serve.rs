//! `bd mcp`, `bd serve` and `bd serve token`.

use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Args, Debug, Clone)]
pub struct McpArgs {
    /// Offer only the tools that read (ready, list, show, memories)
    #[arg(long)]
    pub read_only: bool,
}

#[derive(Args, Debug, Clone)]
#[command(args_conflicts_with_subcommands = true)]
pub struct ServeArgs {
    #[command(subcommand)]
    pub action: Option<ServeAction>,
    /// Directory of workspaces: <root>/<name>/.bd/bd.db is served at /w/<name>; tokens in <root>/server.db,
    /// sign-in (GitHub, OIDC providers) set up in <root>/auth.toml
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
    /// Largest request accepted, in MiB (imports and batches travel in the request)
    #[arg(long, default_value_t = 64, value_name = "MIB")]
    pub max_body_mib: u64,
    /// Reclaim leases expired past lease.grace in every workspace this often (0 = off)
    #[arg(long, default_value = "1m", value_name = "DURATION")]
    pub reclaim_every: String,
    /// Check timer, issue and human gates in every workspace this often (0 = off)
    #[arg(long, default_value = "1m", value_name = "DURATION")]
    pub gate_check_every: String,
    /// Check GitHub gates with this host's gh this often (0 = off)
    #[arg(long, default_value = "5m", value_name = "DURATION")]
    pub gh_check_every: String,
    /// Check every workspace's agent sets (.bd/agents) for changes this often; a change appends an
    /// agents_changed event, which `bd agents watch` clients wait for (0 = off)
    #[arg(long, default_value = "30s", value_name = "DURATION")]
    pub agents_every: String,
    /// Back up every workspace into DIR/<name>/ (default: no backups)
    #[arg(long, value_name = "DIR")]
    pub backup_dir: Option<PathBuf>,
    /// Time between backups of a workspace
    #[arg(long, default_value = "1h", value_name = "DURATION", requires = "backup_dir")]
    pub backup_every: String,
    /// Backups kept per workspace; older ones are deleted (0 = keep all)
    #[arg(long, default_value_t = 24, value_name = "N", requires = "backup_dir")]
    pub backup_keep: usize,
    /// Clients waiting for new events at once (`events --follow`, `--wait`); others poll (0 to 256)
    #[arg(long, default_value_t = 256, value_name = "N")]
    pub max_followers: usize,
    /// The longest a request waits for new events: keep it below the idle timeout of proxies in front
    #[arg(long, default_value = "25s", value_name = "DURATION")]
    pub max_wait: String,
    /// The URL clients reach the server at, path prefix included (https://bd.example.com/bd): MCP endpoints name
    /// themselves by it. Default: the request's Host, its path prefix, and https with --tls-cert
    #[arg(long, env = "BD_SERVE_PUBLIC_URL", value_name = "URL")]
    pub public_url: Option<String>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum ServeAction {
    /// Manage access tokens (run on the server host)
    #[command(subcommand)]
    Token(TokenCommand),
    /// Check <root>/auth.toml and its secret files as a running server would read them, and print what to register
    /// at providers and clients (callback URLs, endpoints); exits 2 on a mistake
    Check(ServeCheckArgs),
}

#[derive(Args, Debug, Clone)]
pub struct ServeCheckArgs {
    /// The URL clients reach the server at (as bd serve --public-url): the URLs to register are under it
    #[arg(long, env = "BD_SERVE_PUBLIC_URL", value_name = "URL")]
    pub public_url: Option<String>,
    #[command(flatten)]
    pub root: TokenRootArgs,
}

#[derive(Subcommand, Debug, Clone)]
pub enum TokenCommand {
    /// Create an access token and print its secret once
    Create(TokenCreateArgs),
    /// List access tokens (never their secrets), including those issued by signing in
    #[command(alias = "ls")]
    List(TokenRootArgs),
    /// List the accounts that signed in (with any provider), and the actor each is bound to
    Accounts(TokenRootArgs),
    /// Revoke an access token, or every token an account got by signing in; it stops working at once
    Revoke(TokenRevokeArgs),
    /// The audit trail of sign-ins, tokens created, refreshed and revoked, accounts forgotten and clients
    /// registered (kept 90 days)
    Events(TokenEventsArgs),
    /// Bind an account to the actor of another account (one person signing in with several providers); the
    /// account's tokens are revoked, and its next sign-in acts as that actor
    Link(TokenLinkArgs),
    /// Name an account for admins (its actor may be a pseudonym such as apple:u-3f9a2c1e7b04)
    Name(TokenNameArgs),
}

#[derive(Args, Debug, Clone)]
pub struct TokenNameArgs {
    /// The account: its actor, or its login
    pub account: String,
    /// What to call it (plain text, up to 64 characters)
    #[arg(required_unless_present = "clear")]
    pub name: Option<String>,
    /// Remove its name instead
    #[arg(long, conflicts_with = "name")]
    pub clear: bool,
    #[command(flatten)]
    pub root: TokenRootArgs,
}

#[derive(Args, Debug, Clone)]
pub struct TokenLinkArgs {
    /// The account to bind: its actor, or its login
    pub account: String,
    /// The actor of the account it joins, e.g. github:alice
    #[arg(long, value_name = "ACTOR")]
    pub to: String,
    #[command(flatten)]
    pub root: TokenRootArgs,
}

#[derive(Args, Debug, Clone)]
pub struct TokenEventsArgs {
    /// Only events this recent (e.g. 1h, 7d; default all kept)
    #[arg(long, value_name = "DURATION")]
    pub since: Option<String>,
    /// Only this actor's, and its sub-actors'
    #[arg(long, visible_alias = "by", value_name = "ACTOR")]
    pub actor: Option<String>,
    /// Only these kinds (signed_in, token_created, refreshed, revoked, forgotten, client_registered, linked,
    /// named; repeatable or comma separated)
    #[arg(long = "kind", value_name = "KIND", value_delimiter = ',')]
    pub kinds: Vec<String>,
    /// At most this many, the latest
    #[arg(short = 'n', long, default_value_t = 100)]
    pub limit: usize,
    #[command(flatten)]
    pub root: TokenRootArgs,
}

#[derive(Args, Debug, Clone)]
pub struct TokenRootArgs {
    /// Server root holding server.db (the access tokens)
    #[arg(long, env = "BD_SERVE_ROOT", value_name = "DIR")]
    pub root: PathBuf,
}

#[derive(Args, Debug, Clone)]
pub struct TokenCreateArgs {
    /// Unique token name, e.g. alice-laptop or ci
    pub name: String,
    /// The actor the token acts as; clients may also use <actor>/<agent> sub-actors
    #[arg(long = "as", value_name = "ACTOR")]
    pub act_as: String,
    #[arg(long, value_enum, default_value = "write")]
    pub role: crate::tokens::Role,
    /// Who holds it: a person's token (human) may also resolve human gates
    #[arg(long, value_enum, default_value = "agent")]
    pub kind: crate::tokens::Kind,
    /// Workspaces the token may use (repeatable or comma separated; default all)
    #[arg(long = "workspace", value_delimiter = ',', value_name = "NAME")]
    pub workspaces: Vec<String>,
    /// The most issues its actor and its agents may hold, claimed or reserved (default no limit)
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
pub struct TokenRevokeArgs {
    /// The token's name
    #[arg(required_unless_present_any = ["account", "client"])]
    pub name: Option<String>,
    /// Revoke every token this account (a login, or the actor it is bound to) got by signing in, with any
    /// provider, instead of a named one
    #[arg(long, value_name = "LOGIN", conflicts_with = "name")]
    pub account: Option<String>,
    /// With --account: also release the account's actor, which another account (or the same one, under its
    /// login then) gets at its next sign-in
    #[arg(long, requires = "account", conflicts_with = "name")]
    pub forget: bool,
    /// Revoke every token issued to this OAuth client (its client ID, as `bd serve token list` shows it), instead
    /// of a named one
    #[arg(long, value_name = "CLIENT_ID", conflicts_with_all = ["name", "account"])]
    pub client: Option<String>,
    #[command(flatten)]
    pub root: TokenRootArgs,
}
