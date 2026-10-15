//! `bd github`: two-way sync between GitHub Issues and bd issues.

use super::*;

#[derive(Subcommand, Debug, Clone)]
pub enum GithubCommand {
    /// Show what a sync would do, without changing anything
    #[command(long_about = GITHUB_STATUS_LONG_ABOUT, after_long_help = GITHUB_STATUS_EXAMPLES)]
    Status(GithubArgs),
    /// Bring GitHub issues and their comments into bd
    #[command(long_about = GITHUB_PULL_LONG_ABOUT, after_long_help = GITHUB_PULL_EXAMPLES)]
    Pull(GithubPullArgs),
    /// Send bd changes of linked issues to GitHub
    #[command(long_about = GITHUB_PUSH_LONG_ABOUT, after_long_help = GITHUB_PUSH_EXAMPLES)]
    Push(GithubPushArgs),
    /// Pull and push in one run
    #[command(long_about = GITHUB_SYNC_LONG_ABOUT, after_long_help = GITHUB_SYNC_EXAMPLES)]
    Sync(GithubPushArgs),
}

/// Which GitHub issues a run lists.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum GithubState {
    /// Open issues (and linked issues still open in bd, fetched one by one)
    #[default]
    Open,
    /// Open and closed issues
    All,
}

/// Who wins when both sides changed an issue since the last sync.
#[derive(ValueEnum, Debug, Clone, Copy, PartialEq, Eq)]
pub enum PreferArg {
    /// The bd issue
    Local,
    /// The GitHub issue
    Github,
    /// The side edited last (bd github's own writes left out)
    Newer,
}

#[derive(Args, Debug, Clone)]
pub struct GithubArgs {
    /// Repository: OWNER/REPO or HOST/OWNER/REPO (default: the workspace directory's, as `gh repo view` sees it)
    #[arg(long)]
    pub repo: Option<String>,
    /// Only GitHub issues with this label (and, with --create, bd issues with it)
    #[arg(long)]
    pub label: Option<String>,
    /// Which GitHub issues to list
    #[arg(long, value_enum, default_value_t = GithubState::Open)]
    pub state: GithubState,
    /// Who wins when both sides changed an issue (default: report a conflict and change neither)
    #[arg(long, value_enum)]
    pub prefer: Option<PreferArg>,
}

#[derive(Args, Debug, Clone)]
pub struct GithubPullArgs {
    #[command(flatten)]
    pub common: GithubArgs,
    #[arg(long, help = DRY_RUN_HELP)]
    pub dry_run: bool,
}

#[derive(Args, Debug, Clone)]
pub struct GithubPushArgs {
    #[command(flatten)]
    pub common: GithubArgs,
    #[arg(long, help = DRY_RUN_HELP)]
    pub dry_run: bool,
    /// Also create GitHub issues for bd issues with --label and no external_ref
    #[arg(long)]
    pub create: bool,
    /// Also post bd comments that GitHub does not have yet
    #[arg(long)]
    pub comments: bool,
}

const GITHUB_STATUS_LONG_ABOUT: &str = "\
Show what a sync would do, without changing anything

Lists the repository's issues and compares each with its linked bd issue:
what a pull or push would change, conflicts (both sides changed), deferred
changes, and GitHub issues new to bd. Comments are not fetched. Runs `gh`
($BD_GH overrides the binary) with the credentials of whoever runs it;
through bd serve, the server's, and only with an admin token.";

const GITHUB_STATUS_EXAMPLES: &str = "\
Examples:
  bd github status
  bd github status --repo acme/app --state all";

const GITHUB_PULL_LONG_ABOUT: &str = "\
Bring GitHub issues and their comments into bd

Creates a bd issue (type task) for each listed GitHub issue that is new to
bd, links it through external_ref gh:OWNER/REPO#N, and applies GitHub's
changes to linked issues: title, body, state and close outcome, labels,
priority labels (github.priority_labels) and the first assignee
(github.assignees). A bd change since the last sync is left for a push.
GitHub comments are imported, deduplicated by their GitHub id. A GitHub issue
whose body ends with the marker of a bd issue is linked to it, not created.
A change bd refuses (another actor's claim, open children) is reported and
retried by the next run; the issue's comments are still imported.";

const GITHUB_PULL_EXAMPLES: &str = "\
Examples:
  bd github pull
  bd github pull --repo acme/app --label bug --state all
  bd github pull --prefer github --dry-run";

const GITHUB_PUSH_LONG_ABOUT: &str = "\
Send bd changes of linked issues to GitHub

PATCHes each linked GitHub issue whose bd issue changed since the last sync,
with only the fields that differ, keeping labels and assignees bd cannot
represent. --create also creates GitHub issues for open bd issues carrying
--label (closed ones too with --state all), each ending with a marker naming
its bd issue; --comments posts bd comments GitHub does not have yet. A GitHub
change since the last sync is left for a pull. A failed write of one issue is
reported and the others go on; a rate limit, an authentication failure or a
server error stops the writes, records what succeeded, and exits 1.";

const GITHUB_PUSH_EXAMPLES: &str = "\
Examples:
  bd github push
  bd github push --create --label sync --comments
  bd github push --repo acme/app --dry-run";

const GITHUB_SYNC_LONG_ABOUT: &str = "\
Pull and push in one run

Each linked issue goes the way of the side that changed since the last sync.
When both did, --prefer decides; without it the issue is reported as a
conflict and neither side's fields change, while comments still flow (with
--comments, both ways). Takes the flags of pull and push.";

const GITHUB_SYNC_EXAMPLES: &str = "\
Examples:
  bd github sync
  bd github sync --prefer newer --comments
  bd github sync --create --label sync --state all";
