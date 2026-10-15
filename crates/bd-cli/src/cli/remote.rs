//! `bd remote`.

use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Subcommand, Debug, Clone)]
pub enum RemoteCommand {
    /// Point this checkout at a workspace on a bd server
    #[command(long_about = REMOTE_SET_LONG_ABOUT)]
    Set(RemoteSetArgs),
    /// Show the remote workspace and check the connection
    #[command(long_about = REMOTE_SHOW_LONG_ABOUT)]
    Show,
    /// Stop using the remote workspace
    #[command(alias = "rm", long_about = REMOTE_UNSET_LONG_ABOUT)]
    Unset,
    /// Save an access token for a bd server, or sign in
    #[command(long_about = REMOTE_LOGIN_LONG_ABOUT)]
    Login(RemoteLoginArgs),
    /// Forget saved tokens and revoke sign-in tokens
    #[command(long_about = REMOTE_LOGOUT_LONG_ABOUT)]
    Logout(RemoteLogoutArgs),
}

const REMOTE_SET_LONG_ABOUT: &str = "\
Point this checkout at a workspace on a bd server

Writes .bd/remote.toml: from then on, bd commands here run against that
workspace through bd serve, as --remote or $BD_REMOTE would. Use it once per
checkout, then save an access token with `bd remote login`.";

const REMOTE_SHOW_LONG_ABOUT: &str = "\
Show the remote workspace and check the connection

Shows the remote workspace in use and where it is configured, then checks the
connection, the server's certificate, the access token and the actor the
server resolves.";

const REMOTE_UNSET_LONG_ABOUT: &str = "\
Stop using the remote workspace

Removes .bd/remote.toml, so bd commands here use a local workspace again
unless --remote or $BD_REMOTE is set. Saved tokens stay; `bd remote logout`
forgets them.";

const REMOTE_LOGIN_LONG_ABOUT: &str = "\
Save an access token for a bd server, or sign in

Saves the token in the user config directory, so $BD_TOKEN is not needed:
for every workspace on the server, or with --workspace-only for one.

With --provider, sign in instead: bd shows a one-time code and the provider's
verification URL; once the code is entered there and the server lets the
account in, it issues a token. Otherwise the token is read from stdin when
piped, else from a prompt that does not echo it, never from the command line,
and is checked against the server first (--no-verify skips the check).";

const REMOTE_LOGOUT_LONG_ABOUT: &str = "\
Forget saved tokens and revoke sign-in tokens

Forgets the access tokens `bd remote login` saved for a workspace or server.
Tokens from signing in are revoked on their server too; tokens an admin
created stay valid, as they may be in use elsewhere.";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = "\
Examples:
  bd remote login --provider corp
  printf %s \"$TOKEN\" | bd remote login https://bd.example.com/w/proj
  bd remote login https://bd.example.com/w/proj --workspace-only")]
pub struct RemoteLoginArgs {
    /// Workspace URL, e.g. https://bd.example.com/w/proj (default: this checkout's remote workspace)
    pub url: Option<String>,
    /// Sign in with this provider of the server's (github, or the name of one of its OIDC providers) instead of
    /// entering a token
    #[arg(long, value_name = "NAME", conflicts_with = "no_verify")]
    pub provider: Option<String>,
    /// Save the token for this workspace only, instead of for every workspace on its server
    #[arg(long)]
    pub workspace_only: bool,
    /// Save the token without checking it against the server
    #[arg(long)]
    pub no_verify: bool,
    /// Refused without being echoed: a token pasted after the URL
    #[arg(hide = true)]
    pub extra: Vec<String>,
}

#[derive(Args, Debug, Clone)]
#[command(after_long_help = "\
Examples:
  bd remote logout
  bd remote logout https://bd.example.com")]
pub struct RemoteLogoutArgs {
    /// Workspace or server URL (default: this checkout's remote workspace); a server URL also forgets
    /// tokens saved for its workspaces
    pub url: Option<String>,
    /// Forget only the token saved for this workspace with `login --workspace-only`
    #[arg(long)]
    pub workspace_only: bool,
    /// Refused without being echoed: a token pasted after the URL
    #[arg(hide = true)]
    pub extra: Vec<String>,
}

#[derive(Args, Debug, Clone)]
#[command(after_long_help = "\
Examples:
  bd remote set https://bd.example.com/w/proj
  bd remote set https://bd.example.com/w/proj --ca-cert ca.pem")]
pub struct RemoteSetArgs {
    /// Workspace URL, e.g. https://bd.example.com/w/proj
    pub url: String,
    /// CA certificate (PEM) that signed the server's certificate; copied to .bd/ca.pem
    #[arg(long, value_name = "FILE")]
    pub ca_cert: Option<PathBuf>,
    /// Write remote.toml even though .bd/bd.db holds a local workspace, which it then hides
    #[arg(long)]
    pub force: bool,
    /// Refused without being echoed: a token pasted after the URL
    #[arg(hide = true)]
    pub extra: Vec<String>,
}
