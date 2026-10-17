//! `bd publish`.

use std::path::PathBuf;

use clap::{Args, ValueEnum};

use super::*;

pub const PUBLISH_LONG_ABOUT: &str = "\
Publish playbooks and agent sets to the workspace

Replaces the workspace's playbooks (.bd/playbooks) and agent sets
(.bd/agents/<harness>) with those of a source directory, by default .bd/source
in the checkout: playbooks/** and agents/<harness>/** in the layout the
workspace serves. The workspace then mirrors the source: what it lacks is
removed. In a remote workspace the source is sent to the server, which
checks everything again.

Every path, symlink and limit is checked and every playbook and agent set
loaded before anything changes; any error refuses the whole publish. New and
changed files are written first and removals come last, so readers never
miss a file; the areas a publish changes are kept as they were in
.bd/publish.prev for --rollback. On Windows the agent sets' executable bits
and symlinks come from git (git ls-files -s), so publish them from a git
checkout. Records a `published` event (and `agents_changed` for each set
whose revision changed). Through bd serve it needs an admin token of a
person (role admin, kind human).";

const PUBLISH_HELP: &str = "\
An area the source leaves empty (no playbooks/, or no files under agents/)
is refused unless --only names the other area or --allow-empty is given:
publishing it would remove everything clients have of it.

Exit codes: 0 done; 2 a path, file or playbook refused (nothing changed), an
empty area, or nothing to roll back; 5 another publish to the workspace is
under way; 7 not an admin token of a person.

Examples:
  bd publish --dry-run
  bd publish
  bd publish --from ../ops/bd-source --only playbooks
  bd publish --rollback";

/// A served area `bd publish` replaces.
#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum PublishArea {
    /// The workspace's playbooks (.bd/playbooks)
    Playbooks,
    /// The workspace's agent sets (.bd/agents/<harness>)
    Agents,
}

impl From<PublishArea> for bd_core::publish::Area {
    fn from(a: PublishArea) -> Self {
        match a {
            PublishArea::Playbooks => bd_core::publish::Area::Playbooks,
            PublishArea::Agents => bd_core::publish::Area::Agents,
        }
    }
}

#[derive(Args, Debug, Clone)]
#[command(after_long_help = PUBLISH_HELP)]
pub struct PublishArgs {
    /// Source directory holding playbooks/ and agents/ (default: .bd/source in the checkout)
    #[arg(long, value_name = "DIR", conflicts_with = "rollback")]
    pub from: Option<PathBuf>,
    #[arg(long, help = DRY_RUN_HELP)]
    pub dry_run: bool,
    /// Publish only this area, leaving the other as it is
    #[arg(long, value_enum, value_name = "AREA")]
    pub only: Option<PublishArea>,
    /// Restore the areas the last publish changed (kept in .bd/publish.prev); with --only, that area
    #[arg(long)]
    pub rollback: bool,
    /// Publish an area the source leaves empty, removing everything in it
    #[arg(long)]
    pub allow_empty: bool,
}
