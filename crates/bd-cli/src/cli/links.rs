//! Dependencies, labels and comments.

use std::path::PathBuf;

use clap::{Args, Subcommand, ValueEnum};

use super::*;

#[derive(Subcommand, Debug, Clone)]
pub enum DepCommand {
    /// ISSUE depends on DEPENDS_ON
    Add(DepAddArgs),
    /// Remove the edge between ISSUE and DEPENDS_ON
    #[command(alias = "remove")]
    Rm(DepPairArgs),
    /// Edges of an issue
    List(DepListArgs),
    /// Dependency tree
    Tree(DepTreeArgs),
    /// Report cycles among scheduling edges
    Cycles,
}

#[derive(Args, Debug, Clone)]
pub struct DepAddArgs {
    pub issue: String,
    pub depends_on: String,
    /// blocks, conditional-blocks, parent-child, waits-for, related, discovered-from, ...
    #[arg(short = 't', long = "type", default_value = "blocks")]
    pub dep_type: String,
    /// waits-for gate: all-children | any-children
    #[arg(long)]
    pub gate: Option<String>,
    /// Edge metadata JSON object
    #[arg(long)]
    pub metadata: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct DepPairArgs {
    pub issue: String,
    pub depends_on: String,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum DirectionArg {
    /// What the issue depends on
    Down,
    /// What depends on the issue
    Up,
    Both,
}

#[derive(Args, Debug, Clone)]
pub struct DepListArgs {
    pub id: String,
    #[arg(long, value_enum, default_value = "both")]
    pub direction: DirectionArg,
    #[arg(short = 't', long = "type")]
    pub dep_type: Option<String>,
}

#[derive(Args, Debug, Clone)]
pub struct DepTreeArgs {
    pub id: String,
    #[arg(long, value_enum, default_value = "down")]
    pub direction: DirectionArg,
    #[arg(long, default_value_t = 50)]
    pub max_depth: usize,
}

#[derive(Subcommand, Debug, Clone)]
pub enum LabelCommand {
    Add(LabelEditArgs),
    #[command(alias = "remove")]
    Rm(LabelEditArgs),
    /// Labels of an issue, or all labels with counts
    List(LabelListArgs),
}

#[derive(Args, Debug, Clone)]
pub struct LabelEditArgs {
    pub id: String,
    #[arg(required = true, num_args = 1.., value_delimiter = ',')]
    pub labels: Vec<String>,
}

#[derive(Args, Debug, Clone)]
pub struct LabelListArgs {
    pub id: Option<String>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum CommentCommand {
    Add(CommentAddArgs),
    List(IdArg),
}

#[derive(Args, Debug, Clone)]
pub struct CommentAddArgs {
    pub id: String,
    /// Comment text (words are joined); or use --file / --stdin
    #[arg(num_args = 0..)]
    pub text: Vec<String>,
    #[arg(long, conflicts_with = "stdin")]
    pub file: Option<PathBuf>,
    #[arg(long)]
    pub stdin: bool,
}
