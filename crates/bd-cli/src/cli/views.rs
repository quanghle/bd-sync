//! Views over issues: `bd query`, `bd epic`, `bd children`, `bd stale`,
//! `bd orphans` and `bd graph`.

use super::*;

pub const QUERY_LONG_ABOUT: &str = "\
Find issues matching an expression

The expression combines comparisons FIELD OP VALUE with AND, OR and NOT (in
any case; NOT binds tighter than AND, AND tighter than OR) and parentheses.
Operators: = != < <= > >= and ~ (contains, ASCII case-insensitive). Fields:
status, priority, type, assignee, label, title, description, notes, id (a
pattern with *), parent, created, updated, closed, due, defer, pinned and
ephemeral. Values are bare words or quoted strings ('...' or \"...\", with \\\\,
\\' and \\\" escapes); the bare word none means absent (no assignee, parent,
label, closed, due or defer time), and a comparison on an absent field is
false except = none.

Times take the forms of the filter flags: 7d alone means 7 days ago (created >
7d: created within the last 7 days), +3d means 3 days from now, and = with a
date (created = 2026-01-15) means that local day. parent = ID names the
direct parent, resolved like --parent; an unknown id matches no issue, an
ambiguous one is an error.

Every status is searched: the expression alone decides (status != closed
leaves closed issues out). Limits: 4096 bytes, 128 comparisons, and nesting
depth 32, where each NOT and each opening parenthesis counts one level. Errors
give the column and point at it. --parse-only prints the parsed expression in
canonical form (JSON with --json) without opening the workspace; that text
parses back to the same expression, and is accepted up to 10240 bytes.";

const QUERY_EXAMPLES: &str = "\
Examples:
  bd query 'status = open AND (priority <= 1 OR label = urgent)'
  bd query 'updated < 30d AND status != closed' --sort updated
  bd query 'id = bd-12*' --parse-only";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = QUERY_EXAMPLES)]
pub struct QueryArgs {
    /// The expression (several words are joined with spaces)
    #[arg(required = true, num_args = 1.., value_name = "EXPR")]
    pub expr: Vec<String>,
    /// Print the parsed expression, without running it
    #[arg(long)]
    pub parse_only: bool,
    /// Sort order: priority, created or updated (newest first), or id
    #[arg(long, default_value = "priority")]
    pub sort: String,
    /// Reverse the sort order
    #[arg(long)]
    pub reverse: bool,
    #[arg(short = 'n', long, default_value_t = 100, help = LIMIT_HELP)]
    pub limit: usize,
}

impl QueryArgs {
    /// The expression's source text: the words joined with single spaces.
    pub fn source(&self) -> String {
        self.expr.join(" ")
    }
}

pub const EPIC_STATUS_LONG_ABOUT: &str = "\
Show the progress of epics over their subtrees

For ID (an issue of any type), or else every epic not closed (every epic with
--all): its descendants at every depth, counted as total, closed, open and in
progress, and blocked (live descendants held back by dependencies, which also
count as open or in progress). Percent done is closed descendants over all,
rounded down, and none without descendants. An epic is eligible to close when
it is not closed, has children, and every direct child is closed (what
`bd stats` lists as epics ready to close).";

const EPIC_STATUS_EXAMPLES: &str = "\
Examples:
  bd epic status
  bd epic status bd-7 --json";

#[derive(Subcommand, Debug, Clone)]
pub enum EpicCommand {
    /// Show the progress of epics over their subtrees
    #[command(long_about = EPIC_STATUS_LONG_ABOUT)]
    Status(EpicStatusArgs),
    /// List the epics whose children are all closed, or close them
    #[command(long_about = CLOSE_ELIGIBLE_LONG_ABOUT)]
    CloseEligible(CloseEligibleArgs),
}

#[derive(Args, Debug, Clone)]
#[command(after_long_help = EPIC_STATUS_EXAMPLES)]
pub struct EpicStatusArgs {
    /// Issue id (default: every epic not closed)
    pub id: Option<String>,
    /// Every epic, closed ones included
    #[arg(long, conflicts_with = "id")]
    pub all: bool,
}

pub const CLOSE_ELIGIBLE_LONG_ABOUT: &str = "\
List the epics whose children are all closed, or close them

An epic is eligible when it is not closed, has children, and every direct
child is closed: the epics `bd stats` lists as ready to close. Without --close
nothing changes. --close closes every eligible epic in one transaction, all or
none, with the reason given (default: All children closed). An eligible epic
another actor holds a live claim on refuses the whole close (exit 4, naming
the holder) unless --take-over is given; --force gets past open blockers only.";

const CLOSE_ELIGIBLE_EXAMPLES: &str = "\
Examples:
  bd epic close-eligible
  bd epic close-eligible --close
  bd epic close-eligible --close -r \"Shipped in 2.4\"";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = CLOSE_ELIGIBLE_EXAMPLES)]
pub struct CloseEligibleArgs {
    /// Close the eligible epics, all or none
    #[arg(long)]
    pub close: bool,
    /// Reason recorded with each close (default: All children closed)
    #[arg(short, long, requires = "close")]
    pub reason: Option<String>,
    #[arg(long, requires = "close", help = concat!("Close despite blockers", force_claim_suffix!()))]
    pub force: bool,
    #[arg(
        long,
        requires = "close",
        help = concat!("Close epics other actors hold live claims on", take_over_suffix!())
    )]
    pub take_over: bool,
}

#[derive(Args, Debug, Clone)]
pub struct ChildrenArgs {
    /// Issue id
    pub id: String,
    /// Every descendant, at any depth
    #[arg(long)]
    pub recursive: bool,
}

pub const STALE_LONG_ABOUT: &str = "\
List open work not updated lately, and expired claims

Lists open and in-progress issues that were not updated in the last N days
(marked stale), and in-progress issues whose claim lease has expired, however
recently they were updated (marked with the lease's holder and expiry). Least
recently updated first.";

const STALE_EXAMPLES: &str = "\
Examples:
  bd stale
  bd stale --days 7 -n 20";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = STALE_EXAMPLES)]
pub struct StaleArgs {
    /// Days without an update before an issue is stale
    #[arg(long, default_value_t = 30, value_name = "N")]
    pub days: u32,
    #[arg(short = 'n', long, default_value_t = 100, help = LIMIT_HELP)]
    pub limit: usize,
}

pub const ORPHANS_LONG_ABOUT: &str = "\
Find issue text naming ids that do not exist

Scans the title, description, design, acceptance criteria, notes, close reason
and comments of every issue for ids with the prefix (default: the workspace's
issue_prefix). A reference is a whole word made of letters, digits, '_', '.'
and '-' that starts with PREFIX-, with trailing '.', '-' and '_' dropped (as
`bd rename-prefix` reads them). It dangles when no issue has that id, nor any
part of it before a '.' (bd-7.2 names a child of bd-7). Dependencies are not
checked: they cannot point to a deleted issue.";

const ORPHANS_EXAMPLES: &str = "\
Examples:
  bd orphans
  bd orphans --prefix old --json";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = ORPHANS_EXAMPLES)]
pub struct OrphansArgs {
    /// Id prefix of the references to check (default: config issue_prefix)
    #[arg(long, value_name = "PREFIX")]
    pub prefix: Option<String>,
}

pub const GRAPH_LONG_ABOUT: &str = "\
Export the dependency graph as text, Graphviz DOT or HTML

With ID: that issue and every issue reachable from it by following edges only
down (what it depends on, at any depth) or only up (what depends on it), never
turning around, nearest first. With --all: every issue not closed or pinned,
in id order. Either way the edges of the chosen types between those issues
are drawn as arrows from what an issue depends on to the issue (a blocker to
what it blocks, a parent to its children). --edges takes dependency types,
comma-separated, or all; by default every type but related, as in
`bd dep tree`. At most --max-nodes issues are drawn (default 200, at most
2000); past it the output is truncated and says so.

Formats: text, a tree from prerequisites to dependents in which an issue
reached again is marked (shown above); dot, for Graphviz (dot -Tsvg deps.dot
-o deps.svg); html, a page with an SVG drawing that runs no script and loads
nothing. -o writes FILE on this machine, from a remote workspace too, and
prints a summary; --json without -o prints the issues and edges.";

const GRAPH_EXAMPLES: &str = "\
Examples:
  bd graph bd-7
  bd graph bd-7 --format dot -o deps.dot
  bd graph --all --format html -o graph.html
  bd graph bd-7 --edges blocks,parent-child";

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum GraphFormat {
    /// A tree drawn with box-drawing characters
    Text,
    /// Graphviz DOT
    Dot,
    /// A self-contained HTML page with an SVG drawing
    Html,
}

#[derive(Args, Debug, Clone)]
#[command(after_long_help = GRAPH_EXAMPLES)]
pub struct GraphArgs {
    /// Issue to walk from, up and down (or --all)
    pub id: Option<String>,
    /// Every issue not closed or pinned, instead of the issues around one
    #[arg(long, conflicts_with = "id")]
    pub all: bool,
    /// Output format
    #[arg(long, value_enum, default_value = "text")]
    pub format: GraphFormat,
    /// Edge types to follow and draw, comma-separated, or all (default: all but related)
    #[arg(long, value_delimiter = ',', value_name = "TYPES")]
    pub edges: Vec<String>,
    /// Most issues drawn, 1 to 2000; past it the output is truncated and says so
    #[arg(long, default_value_t = 200, value_name = "N", value_parser = clap::value_parser!(u32).range(1..=2000))]
    pub max_nodes: u32,
    /// Output file (default: stdout)
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,
}
