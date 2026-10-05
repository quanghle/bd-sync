//! `bd remote`.

use std::path::PathBuf;

use clap::{Args, Subcommand};

#[derive(Subcommand, Debug, Clone)]
pub enum RemoteCommand {
    /// Point this checkout at a workspace on a bd server (writes .bd/remote.toml)
    Set(RemoteSetArgs),
    /// The remote workspace in use, and a check of the connection, certificate, token and actor
    Show,
    /// Stop using the remote workspace (removes .bd/remote.toml)
    #[command(alias = "rm")]
    Unset,
    /// Save an access token for a bd server in the user config directory, so BD_TOKEN is not needed
    ///
    /// With --provider, sign in instead: the one-time code shown is entered at the provider
    /// (github.com/login/device for GitHub), and the server issues a token if it lets the account in.
    /// Otherwise the token is read from stdin when it is piped (`printf %s "$TOKEN" | bd remote login`), else
    /// from a prompt that does not echo it; never from the command line. It is checked against the server first.
    Login(RemoteLoginArgs),
    /// Forget access tokens saved by `bd remote login`, revoking those from signing in on their server
    Logout(RemoteLogoutArgs),
}

#[derive(Args, Debug, Clone)]
pub struct RemoteLoginArgs {
    /// Workspace URL, e.g. https://bd.example.com/w/proj (default: this checkout's remote workspace)
    pub url: Option<String>,
    /// Sign in with this provider of the server's (`github`, or the name of one of its OIDC providers) to get a
    /// token, instead of entering one: a one-time code is shown, to enter at the provider
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
pub struct RemoteSetArgs {
    /// Workspace URL, e.g. https://bd.example.com/w/proj
    pub url: String,
    /// CA certificate (PEM) that signed the server's certificate; copied to .bd/ca.pem
    #[arg(long, value_name = "FILE")]
    pub ca_cert: Option<PathBuf>,
    /// Write it even though .bd/bd.db holds a local workspace, which remote.toml hides
    #[arg(long)]
    pub force: bool,
    /// Refused without being echoed: a token pasted after the URL
    #[arg(hide = true)]
    pub extra: Vec<String>,
}
