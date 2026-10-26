//! `bd playbook` and `bd gate`.

use std::path::PathBuf;

use clap::{ArgGroup, Args, Subcommand};

use super::*;

#[derive(Subcommand, Debug, Clone)]
pub enum PlaybookCommand {
    /// List available playbooks
    #[command(alias = "ls", long_about = PLAYBOOK_LIST_LONG_ABOUT)]
    List,
    /// Validate a playbook and show its variables and steps
    Show(PlaybookRefArgs),
    /// Preview the issues and edges a run would create
    #[command(long_about = PLAYBOOK_PLAN_LONG_ABOUT, after_long_help = PLAYBOOK_PLAN_EXAMPLES)]
    Plan(RunArgs),
    /// Start a playbook run
    #[command(long_about = PLAYBOOK_RUN_LONG_ABOUT, after_long_help = PLAYBOOK_RUN_EXAMPLES)]
    Run(RunArgs),
    /// Show every step of a run and what it waits on
    Status(IdArg),
    /// List playbook runs, newest first
    Runs(RunsArgs),
    /// Fold a finished run's steps into a digest on the run issue
    #[command(long_about = PLAYBOOK_COMPACT_LONG_ABOUT)]
    Compact(CompactArgs),
    /// Delete a run and all its issues
    #[command(long_about = PLAYBOOK_DISCARD_LONG_ABOUT)]
    Discard(DiscardArgs),
    /// Write a playbook from an existing epic and its children
    #[command(long_about = PLAYBOOK_EXTRACT_LONG_ABOUT)]
    Extract(ExtractArgs),
}

const PLAYBOOK_LIST_LONG_ABOUT: &str = "\
List available playbooks

Lists the playbooks on the search path, in lookup order: the workspace's
.bd/playbooks, the directories in $BD_PLAYBOOK_PATH, then bd/playbooks in the
user config directory. In a remote workspace: the checkout's .bd/playbooks,
then the server's playbooks, then the user's own. A playbook shadows those of
the same name found after it, and one that does not validate is listed with
its error.";

const PLAYBOOK_PLAN_LONG_ABOUT: &str = "\
Preview the issues and edges a run would create

The same as `bd playbook run --dry-run`: compiles the playbook with its
variables, checks the run against the database and shows it, then writes
nothing. Use it to try variables and --after/--parent before starting a run.";

const PLAYBOOK_PLAN_EXAMPLES: &str = "\
Examples:
  bd playbook plan release --var version=1.2.0
  bd playbook plan ./release.toml --var version=1.2.0 --json";

const PLAYBOOK_RUN_LONG_ABOUT: &str = "\
Start a playbook run

Creates the run issue (an epic), one issue per step and gate, and their edges
in one transaction, with ids <run>.<step>. The run and its groups close
themselves when their last step closes. Steps become ready like any other
work: claim them with `bd claim` and follow them with `bd playbook status`. In
a remote workspace, a playbook found in the checkout is sent with the command;
a name not found there is looked up on the server.";

const PLAYBOOK_RUN_EXAMPLES: &str = "\
Examples:
  bd playbook run release --var version=1.2.0 --dry-run
  bd playbook run release --var version=1.2.0 --after bd-12
  bd playbook run worker --parent bd-7 --ephemeral";

#[derive(Args, Debug, Clone)]
pub struct PlaybookRefArgs {
    /// Playbook name (looked up in the playbook path) or file path
    pub playbook: String,
}

#[derive(Args, Debug, Clone)]
pub struct RunArgs {
    /// Playbook name (looked up in the playbook path) or file path
    pub playbook: String,
    /// Variable value, each NAME once (repeatable)
    #[arg(long = "var", value_name = "NAME=VALUE")]
    pub vars: Vec<String>,
    /// Make the run ephemeral: left out of exports, deleted by `bd purge` once closed
    #[arg(long, conflicts_with = "persistent")]
    pub ephemeral: bool,
    /// Keep the run for good even if the playbook says ephemeral
    #[arg(long)]
    pub persistent: bool,
    /// Assign the run and every step that has no assignee of its own
    #[arg(short, long, value_name = "ACTOR")]
    pub assignee: Option<String>,
    /// Title of the run issue (default: the playbook's title)
    #[arg(long)]
    pub title: Option<String>,
    /// Create the run under this issue (e.g. a spawner step that others wait on)
    #[arg(long, value_name = "ID")]
    pub parent: Option<String>,
    /// Start only after these issues close (repeatable or comma separated)
    #[arg(long, value_delimiter = ',', value_name = "ID")]
    pub after: Vec<String>,
    #[arg(long, help = DRY_RUN_HELP)]
    pub dry_run: bool,
}

#[derive(Args, Debug, Clone)]
pub struct RunsArgs {
    /// Include finished runs
    #[arg(long)]
    pub all: bool,
    /// Only runs of this playbook
    #[arg(long, value_name = "NAME")]
    pub playbook: Option<String>,
    #[arg(short = 'n', long, default_value_t = 50, help = LIMIT_HELP)]
    pub limit: usize,
}

const PLAYBOOK_COMPACT_LONG_ABOUT: &str = "\
Fold a finished run's steps into a digest on the run issue

Appends a digest of every step, under the --summary, to the run issue's notes,
deletes the steps and keeps the run issue for good (no longer ephemeral). Use
it once a run is done, to keep its record without its steps. A run that is not
finished is refused unless --force, which deletes its open steps too.
--dry-run prints the digest without changing anything.";

const PLAYBOOK_COMPACT_EXAMPLES: &str = "\
Examples:
  bd playbook compact bd-7 --dry-run
  bd playbook compact bd-7 -s \"Shipped 1.2.0\"";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = PLAYBOOK_COMPACT_EXAMPLES)]
pub struct CompactArgs {
    /// Run issue to compact
    pub id: String,
    /// Summary written above the generated digest
    #[arg(short, long)]
    pub summary: Option<String>,
    #[arg(
        long,
        help = concat!(
            "Compact even though the run is not finished, deleting its open steps",
            force_claim_suffix!()
        )
    )]
    pub force: bool,
    #[arg(long, help = concat!("Delete steps other actors hold live claims on", take_over_suffix!()))]
    pub take_over: bool,
    #[arg(long, help = DRY_RUN_HELP)]
    pub dry_run: bool,
}

const PLAYBOOK_DISCARD_LONG_ABOUT: &str = "\
Delete a run and all its issues

Deletes the run issue and every issue below it, with no undo, and drops the
edges other issues have to them. Use it for a run started by mistake or given
up. Work in progress in the run is refused unless --force (the actor's own or
dead claims) or --take-over (other actors' live claims).";

const PLAYBOOK_DISCARD_EXAMPLES: &str = "\
Examples:
  bd playbook discard bd-7 --dry-run
  bd playbook discard bd-7 --force";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = PLAYBOOK_DISCARD_EXAMPLES)]
pub struct DiscardArgs {
    /// Run issue to discard
    pub id: String,
    #[arg(
        long,
        help = concat!(
            "Discard even with work in progress: the actor's own or dead claims",
            force_claim_suffix!()
        )
    )]
    pub force: bool,
    #[arg(
        long,
        help = concat!(
            "Discard although other actors hold live claims on the run or its steps",
            take_over_suffix!()
        )
    )]
    pub take_over: bool,
    #[arg(long, help = DRY_RUN_HELP)]
    pub dry_run: bool,
}

const PLAYBOOK_EXTRACT_LONG_ABOUT: &str = "\
Write a playbook from an existing epic and its children

Turns the issue's subtree into a playbook: children become steps
(grandchildren nested steps), blocks and waits-for edges inside the subtree
become needs and waits_for, and gates become the gates of the steps they hold
back; edges leaving the subtree, notes and run metadata are dropped. Use it to
make repeatable work of something done once by hand, then start it with `bd
playbook run <name>`. Prints TOML on stdout unless -o or --save is given; in a
remote workspace, --save writes into the checkout.";

const PLAYBOOK_EXTRACT_EXAMPLES: &str = "\
Examples:
  bd playbook extract bd-7 --save
  bd playbook extract bd-7 --name onboarding -o onboarding.toml";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = PLAYBOOK_EXTRACT_EXAMPLES)]
pub struct ExtractArgs {
    /// Issue whose subtree becomes the playbook (an epic or a run)
    pub id: String,
    /// Playbook name: letters, digits, '-', '_' or '.', starting with a letter or digit, at most 64 (default: the
    /// run's playbook name, else from the issue's title)
    #[arg(long)]
    pub name: Option<String>,
    /// Write to FILE instead of stdout
    #[arg(short, long, conflicts_with = "save", value_name = "FILE")]
    pub output: Option<PathBuf>,
    /// Write to .bd/playbooks/<name>.toml
    #[arg(long)]
    pub save: bool,
    /// Overwrite an existing file
    #[arg(long)]
    pub force: bool,
}

#[derive(Subcommand, Debug, Clone)]
pub enum GateCommand {
    /// List open gates
    #[command(alias = "ls")]
    List(GateListArgs),
    /// Show a gate's condition, phase, deadline and what it holds back
    Show(IdArg),
    /// Evaluate open gates: open those that hold, escalate failures and timeouts
    #[command(long_about = GATE_CHECK_LONG_ABOUT)]
    Check(GateCheckArgs),
    /// Open gates by hand
    #[command(long_about = GATE_RESOLVE_LONG_ABOUT)]
    Resolve(GateResolveArgs),
    /// Put a gate in front of existing work
    #[command(long_about = GATE_CREATE_LONG_ABOUT)]
    Create(Box<GateCreateArgs>),
    /// Replace or clear the approvers of an open human gate
    #[command(long_about = GATE_UPDATE_LONG_ABOUT)]
    Update(GateUpdateArgs),
}

#[derive(Args, Debug, Clone)]
pub struct GateListArgs {
    /// Include resolved gates
    #[arg(long)]
    pub all: bool,
}

const GATE_CHECK_LONG_ABOUT: &str = "\
Evaluate open gates: open those that hold, escalate failures and timeouts

Opens each armed gate whose condition holds, and escalates one whose condition
failed or whose --timeout passed after arming: escalation flags it for a
person, never opens it. Human gates only escalate. Each verdict is applied on
its own: a gate that cannot be evaluated is reported as an error and the
others are still applied. GitHub gates run `gh` ($BD_GH overrides the binary)
in the workspace's repository, with the credentials of whoever checks them.
Run it from cron or CI; bd serve runs it on its own.";

const GATE_CHECK_EXAMPLES: &str = "\
Examples:
  bd gate check --dry-run
  bd gate check --type local
  bd gate check bd-15";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = GATE_CHECK_EXAMPLES)]
pub struct GateCheckArgs {
    /// Only these gates, each still open (default: every open gate)
    pub ids: Vec<String>,
    /// Only gates of this type: human, timer, issue, gh:run, gh:pr, gh (both GitHub types), local (all others) or
    /// all (the default)
    #[arg(short = 't', long = "type")]
    pub kind: Option<String>,
    #[arg(long, help = DRY_RUN_HELP)]
    pub dry_run: bool,
}

const GATE_RESOLVE_LONG_ABOUT: &str = "\
Open gates by hand

Closes each gate as done, whatever its type, and frees the work it holds back:
the approval of a human gate, or an override of any other. A gate that is not
armed yet (the work it holds back still has open prerequisites) is refused
unless --force. Through bd serve, opening a human gate needs a human token.";

const GATE_RESOLVE_EXAMPLES: &str = "\
Examples:
  bd gate resolve bd-15 -r \"approved\"
  bd gate resolve bd-15 --force";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = GATE_RESOLVE_EXAMPLES)]
pub struct GateResolveArgs {
    /// Gates to open
    #[arg(required = true, num_args = 1..)]
    pub ids: Vec<String>,
    /// Reason recorded with the close (default: resolved by ACTOR)
    #[arg(short, long)]
    pub reason: Option<String>,
    /// Resolve before the gate is armed (its work still has open prerequisites)
    #[arg(long)]
    pub force: bool,
}

const GATE_CREATE_LONG_ABOUT: &str = "\
Put a gate in front of existing work

Creates a gate that each --blocks issue waits on, as on any blocker. The gate
also takes on their prerequisites, so it arms only once that work could
otherwise start; timers and timeouts count from arming. Gate types:
  human   opens with `bd gate resolve` (through bd serve, by a human token;
          with --approver, only one of the approvers or their sub-actors)
  timer   opens once --timeout has passed
  issue   opens when the --await-id issue closes as done
  gh:pr   opens when pull request --await-id merges
  gh:run  opens when GitHub Actions run --await-id succeeds; for a workflow,
          the first run started after arming
A failed condition, or --timeout passing on a gate other than a timer,
escalates the gate: it is flagged for a person, never opened. `bd gate check`
evaluates gates.";

const GATE_CREATE_EXAMPLES: &str = "\
Examples:
  bd gate create -t human --blocks bd-12 -a alice
  bd gate create -t human --blocks bd-12 --approver github:alice,github:bob
  bd gate create -t timer --timeout 24h --blocks bd-12
  bd gate create -t gh:pr --await-id 42 --blocks bd-12 --timeout 2d
  bd gate create -t gh:run --await-id ci.yml --branch main --blocks bd-12";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = GATE_CREATE_EXAMPLES)]
pub struct GateCreateArgs {
    /// Gate type: human, timer, issue, gh:run or gh:pr
    #[arg(short = 't', long = "type")]
    pub kind: String,
    /// Issues the gate holds back, none closed (repeatable or comma separated)
    #[arg(long, required = true, value_delimiter = ',', value_name = "ID")]
    pub blocks: Vec<String>,
    /// What to await, required for issue, gh:pr and gh:run gates: an issue id (issue), a pull request number, '#'
    /// optional (gh:pr), or a run id, workflow name or file (gh:run)
    #[arg(long)]
    pub await_id: Option<String>,
    /// Timer gates (required): how long to wait after arming; other types: escalate when still shut this long after
    /// arming; positive, e.g. 24h
    #[arg(long, value_name = "DURATION")]
    pub timeout: Option<String>,
    /// For gh:run and gh:pr gates: OWNER/REPO or HOST/OWNER/REPO (default: the workspace's repository); must match
    /// config gate.repos when set, and through bd serve gate.repos must allow it
    #[arg(long)]
    pub repo: Option<String>,
    /// For gh:run gates on a workflow: only runs for this branch or tag (at most 255 characters), following its
    /// newest head
    #[arg(long)]
    pub branch: Option<String>,
    /// For gh:run gates on a workflow: only runs triggered by this event, e.g. push or workflow_dispatch (lowercase
    /// letters and _)
    #[arg(long)]
    pub event: Option<String>,
    /// Gate title, at most 500 characters (default: made from its type and what it awaits, plus the title of a single issue held back)
    #[arg(long)]
    pub title: Option<String>,
    /// Description
    #[arg(short, long)]
    pub description: Option<String>,
    /// Who should act on it, e.g. the approver
    #[arg(short, long, value_name = "ACTOR")]
    pub assignee: Option<String>,
    #[arg(long = "approver", value_name = "ACTOR", value_delimiter = ',', help = APPROVER_HELP)]
    pub approvers: Vec<String>,
    /// Parent issue (default: the parent of the single issue it holds back, unless that parent is closed)
    #[arg(long, value_name = "ID")]
    pub parent: Option<String>,
    /// Priority 0 (critical) to 4 (backlog), P0-P4 also accepted (default: the highest priority of the issues it
    /// holds back)
    #[arg(short, long, value_parser = parse_priority)]
    pub priority: Option<u8>,
}

const APPROVER_HELP: &str = "Human gates only: who may open it through bd serve, an actor or any of its sub-actors \
(repeatable or comma separated, at most 32; locally informational)";

const GATE_UPDATE_LONG_ABOUT: &str = "\
Replace or clear the approvers of an open human gate

--approver replaces the whole list; --clear-approvers removes it, so any
human token may open the gate again. A list stored invalid (which matches
nobody) is replaced or cleared the same way. Through bd serve, this needs a
human token of one of the gate's approvers (of any person when it has none),
or a human admin's. Locally, approvers are informational.";

const GATE_UPDATE_EXAMPLES: &str = "\
Examples:
  bd gate update bd-15 --approver github:alice --approver github:bob
  bd gate update bd-15 --clear-approvers";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = GATE_UPDATE_EXAMPLES)]
#[command(group(ArgGroup::new("change").required(true).args(["approvers", "clear_approvers"])))]
pub struct GateUpdateArgs {
    /// The gate
    pub id: String,
    #[arg(
        long = "approver",
        value_name = "ACTOR",
        value_delimiter = ',',
        conflicts_with = "clear_approvers",
        help = APPROVER_HELP
    )]
    pub approvers: Vec<String>,
    /// Remove the approvers
    #[arg(long)]
    pub clear_approvers: bool,
}
