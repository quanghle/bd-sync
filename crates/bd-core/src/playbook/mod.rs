//! Playbooks: repeatable multi-step work, declared once and run on demand.
//!
//! A playbook is a TOML (or JSON) file of steps with `needs`, optional gates,
//! variables, conditions, loops, nested groups, and composition (`extends`,
//! `expand`). Running it creates a *run*: an epic with one issue per step,
//! wired so the steps flow through `bd ready` in order, in one transaction.
//!
//! This is the counterpart of beads' formulas and molecules (formula ->
//! playbook, pour -> run, wisp -> ephemeral run, squash -> compact,
//! burn -> discard, distill -> extract), with stricter parsing, readable
//! `<run>.<step>` ids, and gates that arm only when their step could start.

mod compile;
mod extract;
mod loader;
mod model;
mod run;
mod template;

pub use compile::{MAX_EXPAND_DEPTH, Plan, PlannedEdge, PlannedIssue, Role, RunRequest, compile, resolve_vars};
pub use extract::extract;
pub use loader::{EXTENSIONS, Listed, Loader, name_of};
pub use model::{
    Loop, LoopOver, MAX_RUN_ISSUES, Playbook, Step, StepGate, VarDef, VarKind, WaitsFor, parse_json, parse_toml,
    to_toml,
};
pub use run::{
    CompactOptions, CompactOutcome, Progress, RunStarted, RunStatus, RunSummary, RunsQuery, StartOptions, StatusNode,
    StepState, role_of, run_of, run_status, runs,
};
