//! Dependencies, labels and comments.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

use super::*;

pub const DEP_ADD_LONG_ABOUT: &str = "\
Make ISSUE depend on DEPENDS_ON

Adds the edge ISSUE -> DEPENDS_ON, one per pair: adding it again with the same
type replaces its metadata with the --metadata and --gate given, and another
type is refused. Types that hold ISSUE back:
  blocks              until DEPENDS_ON is closed or pinned
  conditional-blocks  until DEPENDS_ON closes as failed (`bd close --failed`)
  parent-child        ISSUE is a child of DEPENDS_ON: a blocked parent blocks
                      its subtree, and open children come before their parent
  waits-for           until the children of DEPENDS_ON are closed
                      (--gate all-children) or one of them is (any-children)
The other built-in types (related, discovered-from, tracks, caused-by,
validates, supersedes, duplicates, replies-to) and custom types only record a
relation and never block. Types are case-insensitive and '_' reads as '-'.
Aliases: blocked-by and depends-on (blocks), conditional and on-failure
(conditional-blocks), parent and child-of (parent-child), relates-to
(related). A cycle among blocks, conditional-blocks and parent-child edges is
refused.";

const DEP_ADD_EXAMPLES: &str = "\
Examples:
  bd dep add bd-13 bd-12
  bd dep add bd-13 bd-12 -t waits-for --gate any-children
  bd dep add bd-14 bd-12 -t discovered-from";

#[derive(Subcommand, Debug, Clone)]
pub enum DepCommand {
    /// Make ISSUE depend on DEPENDS_ON
    #[command(long_about = DEP_ADD_LONG_ABOUT)]
    Add(DepAddArgs),
    /// Remove the edge between ISSUE and DEPENDS_ON
    #[command(alias = "remove")]
    Rm(DepPairArgs),
    /// List the edges of an issue
    List(DepListArgs),
    /// Show the dependency tree of an issue (related edges left out)
    Tree(DepTreeArgs),
    /// Report cycles among scheduling edges (blocks, conditional-blocks, parent-child)
    Cycles,
}

#[derive(Args, Debug, Clone)]
#[command(after_long_help = DEP_ADD_EXAMPLES)]
pub struct DepAddArgs {
    /// Issue that depends on DEPENDS_ON
    pub issue: String,
    /// Issue that ISSUE depends on
    pub depends_on: String,
    /// Edge type: blocks, conditional-blocks, parent-child, waits-for, related, discovered-from, tracks, caused-by,
    /// validates, supersedes, duplicates, replies-to, or a custom type (up to 32 characters: a lowercase letter, then
    /// lowercase letters, digits or '-')
    #[arg(short = 't', long = "type", default_value = "blocks")]
    pub dep_type: String,
    /// For waits-for edges: all-children or any-children (default: all-children)
    #[arg(long)]
    pub gate: Option<String>,
    /// Edge metadata, a JSON object
    #[arg(long, value_name = "JSON")]
    pub metadata: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct DepPairArgs {
    /// Issue that depends on DEPENDS_ON
    pub issue: String,
    /// Issue that ISSUE depends on
    pub depends_on: String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum DirectionArg {
    /// What the issue depends on
    Down,
    /// What depends on the issue
    Up,
    /// Both directions
    Both,
}

#[derive(Args, Debug, Clone)]
pub struct DepListArgs {
    /// Issue id
    pub id: String,
    /// Which edges to list
    #[arg(long, value_enum, default_value = "both")]
    pub direction: DirectionArg,
    /// Only edges of this type (types as in `bd dep add`)
    #[arg(short = 't', long = "type")]
    pub dep_type: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct DepTreeArgs {
    /// Issue at the root of the tree
    pub id: String,
    /// Which way to walk the edges
    #[arg(long, value_enum, default_value = "down")]
    pub direction: DirectionArg,
    /// Deepest level shown
    #[arg(long, default_value_t = 50)]
    pub max_depth: usize,
}

#[derive(Subcommand, Debug, Clone)]
pub enum LabelCommand {
    /// Add labels to an issue
    Add(LabelEditArgs),
    /// Remove labels from an issue
    #[command(alias = "remove")]
    Rm(LabelEditArgs),
    /// List the labels of an issue, or all labels with counts
    List(LabelListArgs),
}

#[derive(Args, Debug, Clone)]
pub struct LabelEditArgs {
    /// Issue id
    pub id: String,
    /// Labels, up to 128 characters each (several, or comma separated)
    #[arg(required = true, num_args = 1.., value_delimiter = ',')]
    pub labels: Vec<String>,
}

#[derive(Args, Debug, Clone)]
pub struct LabelListArgs {
    /// Issue id (omit to list every label with its count)
    pub id: Option<String>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CommentCommand {
    /// Add a comment to an issue
    Add(CommentAddArgs),
    /// List the comments on an issue
    List(IdArg),
}

#[derive(Args, Debug, Clone)]
pub struct CommentAddArgs {
    /// Issue id
    pub id: String,
    /// Comment text, up to 1 MiB (words are joined), unless --file or --stdin
    #[arg(num_args = 0..)]
    pub text: Vec<String>,
    /// Read the comment from FILE
    #[arg(long, value_name = "FILE", conflicts_with = "stdin")]
    pub file: Option<PathBuf>,
    /// Read the comment from stdin
    #[arg(long)]
    pub stdin: bool,
}

pub const DUPLICATE_LONG_ABOUT: &str = "\
Close an issue as a duplicate of another

Adds the edge ID -> CANONICAL of type `duplicates` and closes ID in one
transaction, with outcome done and the reason `duplicate of CANONICAL`. Nothing
else moves: the children, labels, comments and other edges of ID stay on ID,
and CANONICAL is not touched. As in beads, the edge points from the closed
issue to the one that replaces it.

Refused, with nothing written: an issue that is its own duplicate; a CANONICAL
that is closed as a duplicate itself (name its root instead) or a duplicate of
ID; an ID that is closed already, unless it has this edge (then nothing
changes); another type of edge between the two, either way; open children or
blockers on ID, unless --force; another actor's live claim on ID, unless
--take-over; and a failed --if-* guard (exit 13).";

const DUPLICATE_EXAMPLES: &str = "\
Examples:
  bd duplicate bd-14 --of bd-12
  bd duplicate bd-14 --of bd-12 --take-over --if-revision 3";

pub const SUPERSEDE_LONG_ABOUT: &str = "\
Close an issue as superseded by another

Adds the edge ID -> NEWER of type `supersedes` (read: ID is superseded by
NEWER) and closes ID in one transaction, with outcome done and the reason
`superseded by NEWER`. Nothing else moves: the children, labels, comments and
other edges of ID stay on ID, and NEWER is not touched. As in beads, the edge
points from the closed issue to the one that replaces it.

Refused, with nothing written: an issue that supersedes itself; a NEWER that is
closed as superseded itself (name its root instead) or superseded by ID; an ID
that is closed already, unless it has this edge (then nothing changes); another
type of edge between the two, either way; open children or blockers on ID,
unless --force; another actor's live claim on ID, unless --take-over; and a
failed --if-* guard (exit 13).";

const SUPERSEDE_EXAMPLES: &str = "\
Examples:
  bd supersede bd-12 --with bd-20
  bd supersede bd-12 --with bd-20 --force";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = DUPLICATE_EXAMPLES)]
pub struct DuplicateArgs {
    /// Issue to close as a duplicate
    pub id: String,
    /// Issue that ID repeats and that stays open
    #[arg(long, value_name = "ID", required = true)]
    pub of: String,
    #[arg(long, help = concat!("Close despite open children or blockers", force_claim_suffix!()))]
    pub force: bool,
    #[arg(long, help = concat!("Close another actor's live claim", take_over_suffix!()))]
    pub take_over: bool,
    #[command(flatten)]
    pub guard: GuardArgs,
}

#[derive(Args, Debug, Clone)]
#[command(after_long_help = SUPERSEDE_EXAMPLES)]
pub struct SupersedeArgs {
    /// Issue to close as superseded
    pub id: String,
    /// Issue that replaces ID
    #[arg(long = "with", value_name = "ID", required = true)]
    pub with: String,
    #[arg(long, help = concat!("Close despite open children or blockers", force_claim_suffix!()))]
    pub force: bool,
    #[arg(long, help = concat!("Close another actor's live claim", take_over_suffix!()))]
    pub take_over: bool,
    #[command(flatten)]
    pub guard: GuardArgs,
}
