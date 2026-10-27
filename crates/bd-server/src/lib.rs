//! `bd serve`: remote workspaces over HTTPS (`serve`), their background jobs
//! (`jobs`) and long polls (`follow`), access tokens and accounts in
//! `server.db` (`auth`, `server_db`), sign-in with GitHub or OpenID Connect
//! providers (`oauth`, `oidc`, `authorizer`, with the admin's commands in
//! `helper` and secrets fetched by one in `secrets`), and the MCP endpoint
//! (`mcp_http`) with its authorization server (`oauth_server`), and the key
//! sealing operation approval links (`link_key`). Each request runs
//! `bd-cli`'s commands in-process ([`bd_cli::execute`]).

pub mod auth;
pub mod authorizer;
pub mod follow;
pub mod helper;
pub mod jobs;
mod link_key;
pub mod mcp_http;
pub mod metrics;
pub mod oauth;
pub mod oauth_server;
pub mod oidc;
pub mod secrets;
pub mod serve;
pub mod server_db;
pub mod stream;
