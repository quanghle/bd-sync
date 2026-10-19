//! `bd spec`: feature specs (the experimental feature `specs`).

use super::*;

pub const SPEC_LONG_ABOUT: &str = "\
Read feature specs and check that work stays linked to them

Feature specs are experimental: every subcommand refuses (exit 2) unless the
workspace has them on (bd config set experimental.features specs). A spec is
an issue labelled spec (pinned while in force, with area:<name> labels); its
requirements are its children labelled requirement (or non-goal), pinned
while in force, closed by `bd supersede <old> --with <new>` when they change,
closed with a reason when they no longer hold. A spec that is the child of an
open spec inherits its requirements. Work is linked to a spec with a related
edge to the spec or one of its requirements (bd dep add <id> <spec or
requirement> --type related), or marked as touching none (bd spec none).";

#[derive(Subcommand, Debug, Clone)]
pub enum SpecCommand {
    /// List the open specs
    List,
    /// Print the specs of an area, or one spec, as Markdown
    #[command(long_about = SPEC_SHOW_LONG_ABOUT)]
    Show(SpecShowArgs),
    /// Report work and requirements that drifted from the specs
    #[command(long_about = SPEC_DRIFT_LONG_ABOUT)]
    Drift(SpecDriftArgs),
    /// Mark issues as touching no spec, with the reason
    #[command(long_about = SPEC_NONE_LONG_ABOUT)]
    None(SpecNoneArgs),
    /// List closed work from before specs that no spec covers, grouped
    #[command(long_about = SPEC_CANDIDATES_LONG_ABOUT)]
    Candidates,
    /// Report requirements added, changed and removed in a window
    #[command(long_about = SPEC_CHANGES_LONG_ABOUT)]
    Changes(SpecChangesArgs),
}

pub const SPEC_SHOW_LONG_ABOUT: &str = "\
Print the specs of an area, or one spec, as Markdown

Takes a spec's id, or an area: every open spec labelled area:<AREA>, leaving
out those shown inside another one's tree. Each spec lists its requirements
in force, its non-goals and, for a spec printed at the top, the requirements
it inherits from the open specs above it (outermost first); its open
sub-specs follow, one heading level deeper. --history adds the closed
requirements: superseded (by which) or removed (why). An open spec under a
closed one is printed with an error naming the fixes; an issue that is not a
spec between two specs ends inheritance, with a warning. --json prints an
array of views: {spec, requirements, non_goals, history, errors, warnings,
inherited, subspecs}, each nested view with its full inherited list.

--as-of TIME prints the specs as they were then, rebuilt from the retained
events (the TIME forms of bd show --as-of: an event seq N, or #N quoted in a
shell ('#120'), a date or time, or -DURATION ago): an issue was a
requirement, non-goal or sub-spec of a spec then if it existed, its parent
was that spec and it was labelled requirement, non-goal or spec; in force if
it was not closed, else history (superseded if it had a supersedes edge). A
child whose existence, parent, labels, status or title the history cannot
tell is not placed but listed as `> Unknown: <id> <key>: <reason>`; one
whose description or edges it cannot tell is placed, with those keys
listed. With --json each view adds unknown [{id, key, reason}], and each
view printed at the top adds as_of {seq, time}, incomplete and
retained_from. A spec that did not exist then is not found (exit 3); a TIME
before the retained history exits 6.";

const SPEC_SHOW_EXAMPLES: &str = "\
Examples:
  bd spec show checkout
  bd spec show bd-7 --history
  bd spec show checkout --json
  bd spec show checkout --as-of 2026-09-01
  bd spec show bd-7 --as-of 120 --history";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = SPEC_SHOW_EXAMPLES)]
pub struct SpecShowArgs {
    /// A spec's id, or an area (its area:<name> label)
    #[arg(value_name = "SPEC|AREA")]
    pub target: String,
    /// Also list the closed requirements: superseded or removed
    #[arg(long)]
    pub history: bool,
    /// Show the specs as they were at TIME: an event seq (N or #N), a date or time, or -DURATION ago
    #[arg(long, value_name = "TIME", allow_hyphen_values = true)]
    pub as_of: Option<String>,
}

pub const SPEC_DRIFT_LONG_ABOUT: &str = "\
Report work and requirements that drifted from the specs

Since specs were turned on (experimental.specs.since, set when
experimental.features turns specs on; --since overrides it): unlinked, work
closed since then with no related edge to a spec or requirement, nor the
spec:none label (a link covers the issue's subtree and its ancestors: a
playbook run's link counts for the issue it sits under; spec:none covers
only its issue); shaky, requirements in force whose source (their own
outgoing related edge) was reopened (closed once, open now) or closed as
failed, a source still in progress is not; bad status, specs, requirements
and non-goals neither pinned nor closed; orphaned, open specs under a
closed spec. To link, open work created since then not linked yet, is
listed but is not drift. Playbook runs, groups and steps and everything
below a step, gates, decisions, spec issues, ephemeral issues, work closed
as failed and work closed as a duplicate or superseded never need a spec.
Exits 1 when it finds drift, 0 otherwise.";

const SPEC_DRIFT_EXAMPLES: &str = "\
Examples:
  bd spec drift
  bd spec drift --since 30d --json";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = SPEC_DRIFT_EXAMPLES)]
pub struct SpecDriftArgs {
    /// Start of the window instead of experimental.specs.since (2026-01-15, 30d for 30 days ago)
    #[arg(long, value_name = "TIME")]
    pub since: Option<String>,
}

pub const SPEC_NONE_LONG_ABOUT: &str = "\
Mark issues as touching no spec, with the reason

In one write, labels each issue spec:none and comments \"No spec: REASON\" on
it, so `bd spec drift` stops listing it. Nothing else changes: not its
status, assignee or claim; an issue already marked is left as it is. The mark
covers only that issue, not the issues above or below it. Refuses (exit 2)
spec issues themselves (labelled spec, requirement or non-goal).";

const SPEC_NONE_EXAMPLES: &str = "\
Examples:
  bd spec none bd-12 -r 'refactor, no behavior change'";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = SPEC_NONE_EXAMPLES)]
pub struct SpecNoneArgs {
    /// Issue ids
    #[arg(required = true)]
    pub ids: Vec<String>,
    /// Why the work touches no spec
    #[arg(short, long, required = true)]
    pub reason: String,
}

pub const SPEC_CANDIDATES_LONG_ABOUT: &str = "\
List closed work from before specs that no spec covers, grouped

Issues closed before experimental.specs.since (every closed issue when it is
unset), neither linked to a spec nor of a kind that needs none: what specs
could be written from. Grouped by their topmost epic (not a playbook run or
group), else by their first label in sorted order that is not change:*,
severity:*, spec:* or adr:*, else ungrouped; the largest groups first.";

pub const SPEC_CHANGES_LONG_ABOUT: &str = "\
Report requirements added, changed and removed in a window

Rebuilds the specs from the retained events and reports what changed between
--since and --until (the events after --since, up to and including --until;
--until defaults to now). Each takes an event seq N (#N, quoted in a shell:
'#120'), a date or time, -DURATION ago, or a bare duration (30d for 30 days
ago). The scope is the named spec, or the area's specs, at either end, with
their sub-specs; with no SPEC|AREA, every spec. Each change is listed under
the item's own parent spec, so inherited requirements are not repeated.
Kinds: added; superseded (by its replacement, whose own addition in the
window is folded into it); removed (the close reason, moved to <id>, moved
out, unlabelled <kind>, relabelled <kind>, deleted or purged); edited (the
title or description). A membership the history cannot tell is listed as
unknown, never as a change. --json prints {since, until, specs, changes,
unknown, incomplete}, the changes in event order. Exits 0 with or without
changes; a --since before the retained history exits 6, and a window needing
more than 2000 issues rebuilt exits 2 (name a narrower window or one spec).";

const SPEC_CHANGES_EXAMPLES: &str = "\
Examples:
  bd spec changes --since 30d
  bd spec changes checkout --since 2026-09-01 --until 2026-10-01 --json
  bd spec changes bd-7 --since 120";

#[derive(Args, Debug, Clone)]
#[command(after_long_help = SPEC_CHANGES_EXAMPLES)]
pub struct SpecChangesArgs {
    /// A spec's id, or an area (its area:<name> label); default every spec
    #[arg(value_name = "SPEC|AREA")]
    pub target: Option<String>,
    /// Start of the window, not included: an event seq (N or #N), a date or time, -DURATION or 30d ago
    #[arg(long, value_name = "TIME", allow_hyphen_values = true, required = true)]
    pub since: String,
    /// End of the window, included (default now): an event seq, a date or time, -DURATION or 30d ago
    #[arg(long, value_name = "TIME", allow_hyphen_values = true)]
    pub until: Option<String>,
}
