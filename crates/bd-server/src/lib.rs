//! `bd serve`: remote workspaces over HTTPS (`serve`), their background jobs
//! (`jobs`) and long polls (`follow`), access tokens and accounts in
//! `server.db` (`auth`, `server_db`), sign-in with GitHub or OpenID Connect
//! providers (`oauth`, `oidc`, `authorizer`), and the MCP endpoint
//! (`mcp_http`) with its authorization server (`oauth_server`). Each request
//! runs `bd-cli`'s commands in-process ([`bd_cli::execute`]).

pub mod auth;
pub mod authorizer;
pub mod follow;
pub mod jobs;
pub mod mcp_http;
pub mod oauth;
pub mod oauth_server;
pub mod oidc;
pub mod serve;
pub mod server_db;
pub mod stream;
