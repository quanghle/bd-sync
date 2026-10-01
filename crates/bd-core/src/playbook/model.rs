//! The playbook file format: strict parsing and validation.
//!
//! Files are TOML (or JSON with the same shape). Unknown keys are errors, so
//! a typo never silently drops a gate or a dependency. beads formula keys are
//! accepted where they mean the same thing (`formula`, `depends_on`,
//! `expand_vars`, gate `id`, `phase = "vapor"`, `type = "workflow"`).

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt;
use std::path::PathBuf;

use serde::de::{self, Deserializer, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::template::{self, Condition, is_ident};
use crate::error::{Error, Result};
use crate::gates::{GateKind, GateSpec, validate_repo};
use crate::time::parse_duration;

/// Most steps (after loops and expansions) a single run may create.
pub const MAX_RUN_ISSUES: usize = 2_000;

/// A reusable multi-step process. Running it creates a *run*: one epic with
/// an issue per step, wired by the steps' `needs`.
#[derive(Clone, Debug, Serialize)]
pub struct Playbook {
    #[serde(rename = "playbook")]
    pub name: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
    /// Title template of the run issue.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Default priority of the run and its steps.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u8>,
    /// Labels on the run issue.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    /// Runs are ephemeral by default (`bd playbook run --persistent` overrides).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extends: Vec<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub vars: BTreeMap<String, VarDef>,
    pub steps: Vec<Step>,
    #[serde(skip)]
    pub source: Option<PathBuf>,
}

impl Playbook {
    pub fn is_ephemeral(&self) -> bool {
        self.ephemeral.unwrap_or(false)
    }

    /// Every step, depth first (children before the next sibling).
    pub fn all_steps(&self) -> Vec<&Step> {
        fn walk<'a>(steps: &'a [Step], out: &mut Vec<&'a Step>) {
            for s in steps {
                out.push(s);
                walk(&s.children, out);
            }
        }
        let mut out = Vec::new();
        walk(&self.steps, &mut out);
        out
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum VarKind {
    #[default]
    String,
    Int,
    Bool,
}

fn is_string_kind(k: &VarKind) -> bool {
    *k == VarKind::String
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct VarDef {
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
    #[serde(skip_serializing_if = "crate::model::is_false")]
    pub required: bool,
    #[serde(rename = "enum", skip_serializing_if = "Vec::is_empty")]
    pub choices: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "is_string_kind")]
    pub kind: VarKind,
}

impl VarDef {
    /// Check a value (already defaulted) and normalize booleans.
    pub(crate) fn check(&self, name: &str, value: &str) -> std::result::Result<String, String> {
        let value = match self.kind {
            VarKind::String => value.to_string(),
            VarKind::Int => {
                value.trim().parse::<i64>().map_err(|_| format!("var {name} must be an integer, got {value:?}"))?;
                value.trim().to_string()
            }
            VarKind::Bool => match value.trim().to_ascii_lowercase().as_str() {
                "true" | "yes" | "on" | "1" => "true".into(),
                "false" | "no" | "off" | "0" => "false".into(),
                _ => return Err(format!("var {name} must be true or false, got {value:?}")),
            },
        };
        if !self.choices.is_empty() && !self.choices.contains(&value) {
            return Err(format!("var {name} must be one of {}, got {value:?}", self.choices.join(", ")));
        }
        if let Some(p) = &self.pattern {
            let re = regex_lite::Regex::new(p).map_err(|e| format!("var {name}: invalid pattern {p:?}: {e}"))?;
            if !re.is_match(&value) {
                return Err(format!("var {name} must match {p}, got {value:?}"));
            }
        }
        Ok(value)
    }
}

/// Fan-in on the children of a spawner step (dynamic work). The step waits
/// for the spawner to close, then for the children it created.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WaitsFor {
    /// `all-children` or `any-children`.
    pub gate: String,
    /// The step whose children are awaited (default: the first of `needs`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spawner: Option<String>,
}

impl WaitsFor {
    /// `all-children`, `any-children`, `children-of(x)`, `all-children-of(x)`, `any-children-of(x)`.
    pub fn parse(s: &str) -> std::result::Result<WaitsFor, String> {
        let t = s.trim();
        let (gate, spawner) = match t {
            "all-children" => ("all-children", None),
            "any-children" => ("any-children", None),
            _ => {
                let (gate, rest) = if let Some(r) = t.strip_prefix("any-children-of(") {
                    ("any-children", r)
                } else if let Some(r) = t.strip_prefix("all-children-of(") {
                    ("all-children", r)
                } else if let Some(r) = t.strip_prefix("children-of(") {
                    ("all-children", r)
                } else {
                    return Err(format!(
                        "invalid waits_for {s:?} (all-children, any-children, children-of(<step>), any-children-of(<step>))"
                    ));
                };
                let id = rest.strip_suffix(')').map(str::trim).filter(|id| !id.is_empty());
                match id {
                    Some(id) => (gate, Some(id.to_string())),
                    None => return Err(format!("invalid waits_for {s:?}: missing step id")),
                }
            }
        };
        Ok(WaitsFor { gate: gate.into(), spawner })
    }

    pub fn as_spec(&self) -> String {
        match &self.spawner {
            None => self.gate.clone(),
            Some(s) if self.gate == "all-children" => format!("children-of({s})"),
            Some(s) => format!("{}-of({s})", self.gate),
        }
    }
}

/// A gate in front of a step.
#[derive(Clone, Debug, Serialize)]
pub struct StepGate {
    #[serde(rename = "type")]
    pub kind: GateKind,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub await_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    /// Who should act on it (e.g. the approver of a human gate).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
}

impl StepGate {
    /// Validate what can be checked before variables are known.
    fn check_static(&self) -> std::result::Result<(), String> {
        let templated = |v: &Option<String>| v.as_deref().is_some_and(|s| s.contains("{{"));
        let spec = GateSpec {
            kind: self.kind,
            await_id: self.await_id.clone(),
            timeout: if templated(&self.timeout) { Some("1s".into()) } else { self.timeout.clone() },
            repo: if templated(&self.repo) { None } else { self.repo.clone() },
        };
        let spec = if self.kind == GateKind::GhPr && templated(&self.await_id) {
            GateSpec { await_id: Some("1".into()), ..spec }
        } else {
            spec
        };
        spec.validate().map_err(|e| e.to_string())
    }
}

/// What a looped step iterates over.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LoopOver {
    /// `count = 3` (or a `{{var}}`): iterations 1..=n.
    Count(String),
    /// `range = "1..{{n}}"`: inclusive integer range.
    Range(String),
    /// `items = ["linux", "macos"]`.
    Items(Vec<String>),
    /// `over = "{{platforms}}"`: a comma-separated list.
    Over(String),
}

/// Repeat a step once per value; `needs` on a looped step waits for every iteration.
#[derive(Clone, Debug, Serialize)]
pub struct Loop {
    #[serde(flatten)]
    pub over: LoopOver,
    /// Variable bound to the current value (`i` for count/range, `item` otherwise).
    pub var: String,
    /// Chain iterations one after another instead of running them in parallel.
    #[serde(skip_serializing_if = "crate::model::is_false")]
    pub sequential: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct Step {
    pub id: String,
    pub title: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub design: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub acceptance_criteria: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub notes: String,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub issue_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority: Option<u8>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    /// Minutes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimate: Option<i64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub needs: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "ser_waits_for")]
    pub waits_for: Option<WaitsFor>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    /// Inline another playbook's steps as this step's children.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expand: Option<String>,
    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    pub expand_vars: BTreeMap<String, String>,
    #[serde(skip_serializing_if = "Map::is_empty")]
    pub metadata: Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate: Option<StepGate>,
    #[serde(rename = "loop", skip_serializing_if = "Option::is_none")]
    pub repeat: Option<Loop>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<Step>,
}

fn ser_waits_for<S: serde::Serializer>(w: &Option<WaitsFor>, s: S) -> std::result::Result<S::Ok, S::Error> {
    match w {
        Some(w) => s.serialize_str(&w.as_spec()),
        None => s.serialize_none(),
    }
}

impl Step {
    /// A step with children or `expand` is a group: an epic that closes by itself.
    pub fn is_group(&self) -> bool {
        !self.children.is_empty() || self.expand.is_some()
    }

    pub fn titled(id: &str, title: &str) -> Step {
        Step {
            id: id.into(),
            title: title.into(),
            description: String::new(),
            design: String::new(),
            acceptance_criteria: String::new(),
            notes: String::new(),
            issue_type: None,
            priority: None,
            labels: Vec::new(),
            assignee: None,
            estimate: None,
            needs: Vec::new(),
            waits_for: None,
            condition: None,
            expand: None,
            expand_vars: BTreeMap::new(),
            metadata: Map::new(),
            gate: None,
            repeat: None,
            children: Vec::new(),
        }
    }

    /// Fields that are `{{var}}` templates, with a label for error messages.
    pub(crate) fn templates(&self) -> Vec<(&'static str, &str)> {
        let mut out: Vec<(&'static str, &str)> = vec![
            ("title", &self.title),
            ("description", &self.description),
            ("design", &self.design),
            ("acceptance_criteria", &self.acceptance_criteria),
            ("notes", &self.notes),
        ];
        if let Some(a) = &self.assignee {
            out.push(("assignee", a));
        }
        out.extend(self.labels.iter().map(|l| ("labels", l.as_str())));
        out.extend(self.expand_vars.values().map(|v| ("expand_vars", v.as_str())));
        if let Some(g) = &self.gate {
            for (k, v) in [
                ("gate.await_id", &g.await_id),
                ("gate.timeout", &g.timeout),
                ("gate.repo", &g.repo),
                ("gate.title", &g.title),
                ("gate.assignee", &g.assignee),
            ] {
                if let Some(v) = v {
                    out.push((k, v));
                }
            }
            out.push(("gate.description", &g.description));
        }
        if let Some(l) = &self.repeat {
            match &l.over {
                LoopOver::Count(s) | LoopOver::Range(s) | LoopOver::Over(s) => out.push(("loop", s)),
                LoopOver::Items(items) => out.extend(items.iter().map(|i| ("loop.items", i.as_str()))),
            }
        }
        out
    }
}

// ------------------------------------------------------------ raw parsing

/// A string, number or boolean, kept as text.
#[derive(Clone, Debug)]
struct Scalar(String);

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct V;
        impl Visitor<'_> for V {
            type Value = Scalar;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a string, number or boolean")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Scalar, E> {
                Ok(Scalar(v.to_string()))
            }
            fn visit_i64<E: de::Error>(self, v: i64) -> std::result::Result<Scalar, E> {
                Ok(Scalar(v.to_string()))
            }
            fn visit_u64<E: de::Error>(self, v: u64) -> std::result::Result<Scalar, E> {
                Ok(Scalar(v.to_string()))
            }
            fn visit_f64<E: de::Error>(self, v: f64) -> std::result::Result<Scalar, E> {
                Ok(Scalar(v.to_string()))
            }
            fn visit_bool<E: de::Error>(self, v: bool) -> std::result::Result<Scalar, E> {
                Ok(Scalar(v.to_string()))
            }
        }
        d.deserialize_any(V)
    }
}

/// A string or a list of strings.
fn one_or_many<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<Vec<String>, D::Error> {
    struct V;
    impl<'de> Visitor<'de> for V {
        type Value = Vec<String>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("a string or a list of strings")
        }
        fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Vec<String>, E> {
            Ok(vec![v.to_string()])
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> std::result::Result<Vec<String>, A::Error> {
            let mut out = Vec::new();
            while let Some(s) = seq.next_element::<String>()? {
                out.push(s);
            }
            Ok(out)
        }
    }
    d.deserialize_any(V)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPlaybook {
    #[serde(alias = "formula", alias = "name")]
    playbook: Option<String>,
    #[serde(default)]
    description: String,
    version: Option<i64>,
    /// beads: only `workflow` formulas are playbooks.
    #[serde(rename = "type")]
    kind: Option<String>,
    title: Option<String>,
    priority: Option<Scalar>,
    #[serde(default)]
    labels: Vec<String>,
    ephemeral: Option<bool>,
    /// beads: `vapor` = ephemeral.
    phase: Option<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    extends: Vec<String>,
    #[serde(default)]
    vars: BTreeMap<String, RawVar>,
    #[serde(default)]
    steps: Vec<RawStep>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawVar {
    #[serde(default)]
    description: String,
    default: Option<Scalar>,
    #[serde(default)]
    required: bool,
    #[serde(default, rename = "enum")]
    choices: Vec<Scalar>,
    pattern: Option<String>,
    #[serde(rename = "type")]
    kind: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStep {
    id: String,
    title: Option<String>,
    #[serde(default)]
    description: String,
    #[serde(default)]
    design: String,
    #[serde(default, alias = "acceptance")]
    acceptance_criteria: String,
    #[serde(default)]
    notes: String,
    #[serde(rename = "type")]
    issue_type: Option<String>,
    priority: Option<Scalar>,
    #[serde(default)]
    labels: Vec<String>,
    assignee: Option<String>,
    #[serde(alias = "estimated_minutes")]
    estimate: Option<i64>,
    #[serde(default)]
    metadata: Map<String, Value>,
    #[serde(default, deserialize_with = "one_or_many")]
    needs: Vec<String>,
    #[serde(default, deserialize_with = "one_or_many")]
    depends_on: Vec<String>,
    waits_for: Option<String>,
    condition: Option<String>,
    #[serde(rename = "loop")]
    repeat: Option<RawLoop>,
    expand: Option<String>,
    #[serde(default, alias = "with")]
    expand_vars: BTreeMap<String, Scalar>,
    gate: Option<RawGate>,
    #[serde(default)]
    children: Vec<RawStep>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawGate {
    #[serde(rename = "type")]
    kind: String,
    /// beads' name for `await_id`.
    id: Option<Scalar>,
    await_id: Option<Scalar>,
    #[serde(alias = "duration")]
    timeout: Option<String>,
    repo: Option<String>,
    title: Option<String>,
    #[serde(default)]
    description: String,
    assignee: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLoop {
    count: Option<Scalar>,
    range: Option<String>,
    items: Option<Vec<Scalar>>,
    over: Option<String>,
    var: Option<String>,
    #[serde(default)]
    sequential: bool,
}

fn parse_priority(s: &str, what: &str) -> std::result::Result<u8, String> {
    let t = s.trim().trim_start_matches(['P', 'p']);
    match t.parse::<u8>() {
        Ok(p) if p <= 4 => Ok(p),
        _ => Err(format!("{what}: priority must be 0-4 (or P0-P4), got {s:?}")),
    }
}

pub(crate) fn valid_step_id(id: &str) -> bool {
    id.len() <= 64
        && id.starts_with(|c: char| c.is_ascii_alphabetic())
        && id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
}

pub(crate) fn valid_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.starts_with(|c: char| c.is_ascii_alphanumeric())
        && name.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

fn convert_step(raw: RawStep, path: &str) -> std::result::Result<Step, String> {
    let at = |field: &str| format!("step {path}: {field}");
    if !valid_step_id(&raw.id) {
        return Err(format!(
            "step {path}: invalid id {:?} (letters, digits, '-', '_'; starts with a letter; max 64)",
            raw.id
        ));
    }
    if let Some(t) = &raw.issue_type {
        let t = t.trim().to_ascii_lowercase();
        if t == "human" {
            return Err(at(
                "type \"human\" is not an issue type; put a human sign-off in front of the step with [steps.gate] type = \"human\"",
            ));
        }
        if t == crate::model::GATE_TYPE {
            return Err(at("type \"gate\" is reserved; declare gates with [steps.gate]"));
        }
    }
    let priority = raw.priority.map(|p| parse_priority(&p.0, &at("priority"))).transpose()?;
    if raw.estimate.is_some_and(|m| m < 0) {
        return Err(at("estimate must be non-negative minutes"));
    }
    for reserved in ["playbook", "gate"] {
        if raw.metadata.contains_key(reserved) {
            return Err(at(&format!("metadata key {reserved:?} is reserved")));
        }
    }
    let mut needs = raw.needs;
    for d in raw.depends_on {
        if !needs.contains(&d) {
            needs.push(d);
        }
    }
    let waits_for = raw.waits_for.as_deref().map(WaitsFor::parse).transpose().map_err(|e| at(&e))?;
    if let Some(c) = &raw.condition {
        Condition::parse(c).map_err(|e| at(&e))?;
    }
    let gate = match raw.gate {
        None => None,
        Some(g) => {
            let kind = GateKind::parse(&g.kind).map_err(|e| at(&format!("gate: {e}")))?;
            let await_id = match (g.await_id, g.id) {
                (Some(a), Some(b)) if a.0 != b.0 => {
                    return Err(at("gate: `id` and `await_id` disagree; use await_id"));
                }
                (a, b) => a.or(b).map(|s| s.0),
            };
            let gate = StepGate {
                kind,
                await_id,
                timeout: g.timeout,
                repo: g.repo,
                title: g.title,
                description: g.description,
                assignee: g.assignee,
            };
            gate.check_static().map_err(|e| at(&format!("gate: {e}")))?;
            Some(gate)
        }
    };
    let repeat = match raw.repeat {
        None => None,
        Some(l) => {
            let sources = [l.count.is_some(), l.range.is_some(), l.items.is_some(), l.over.is_some()];
            if sources.iter().filter(|s| **s).count() != 1 {
                return Err(at("loop needs exactly one of count, range, items, over"));
            }
            let (over, default_var) = if let Some(c) = l.count {
                (LoopOver::Count(c.0), "i")
            } else if let Some(r) = l.range {
                (LoopOver::Range(r), "i")
            } else if let Some(items) = l.items {
                if items.is_empty() {
                    return Err(at("loop.items must not be empty"));
                }
                (LoopOver::Items(items.into_iter().map(|s| s.0).collect()), "item")
            } else {
                (LoopOver::Over(l.over.unwrap_or_default()), "item")
            };
            let var = l.var.unwrap_or_else(|| default_var.to_string());
            if !is_ident(&var) {
                return Err(at(&format!("loop.var {var:?} is not a valid variable name")));
            }
            Some(Loop { over, var, sequential: l.sequential })
        }
    };
    if raw.expand.is_some() && !raw.children.is_empty() {
        return Err(at("use either expand or children, not both"));
    }
    if raw.expand.is_none() && !raw.expand_vars.is_empty() {
        return Err(at("expand_vars needs expand"));
    }
    let is_group = raw.expand.is_some() || !raw.children.is_empty();
    if is_group && raw.issue_type.as_deref().is_some_and(|t| !t.trim().eq_ignore_ascii_case("epic")) {
        return Err(at("steps with children (or expand) are groups and are always epics; remove type"));
    }
    if is_group && raw.assignee.is_some() {
        return Err(at("groups are containers and cannot be assigned; assign their steps"));
    }
    let children = raw
        .children
        .into_iter()
        .map(|c| {
            let child_path = format!("{path}.{}", c.id);
            convert_step(c, &child_path)
        })
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let title = raw.title.unwrap_or_else(|| raw.id.replace(['-', '_'], " "));
    if title.trim().is_empty() {
        return Err(at("title must not be empty"));
    }
    Ok(Step {
        id: raw.id,
        title,
        description: raw.description,
        design: raw.design,
        acceptance_criteria: raw.acceptance_criteria,
        notes: raw.notes,
        issue_type: raw.issue_type.map(|t| t.trim().to_ascii_lowercase()),
        priority,
        labels: raw.labels,
        assignee: raw.assignee,
        estimate: raw.estimate,
        needs,
        waits_for,
        condition: raw.condition,
        expand: raw.expand,
        expand_vars: raw.expand_vars.into_iter().map(|(k, v)| (k, v.0)).collect(),
        metadata: raw.metadata,
        gate,
        repeat,
        children,
    })
}

fn convert(raw: RawPlaybook, default_name: &str) -> std::result::Result<Playbook, String> {
    if let Some(kind) = &raw.kind {
        if !kind.eq_ignore_ascii_case("workflow") {
            return Err(format!(
                "type {kind:?} is not supported: playbooks are workflows (beads expansion/aspect formulas have no equivalent; compose with expand)"
            ));
        }
    }
    let name = raw.playbook.clone().unwrap_or_else(|| default_name.to_string());
    if !valid_name(&name) {
        return Err(format!("invalid playbook name {name:?} (letters, digits, '-', '_', '.'; max 64)"));
    }
    let ephemeral = match (raw.ephemeral, raw.phase.as_deref()) {
        (Some(e), _) => Some(e),
        (None, Some(p)) if p.eq_ignore_ascii_case("vapor") => Some(true),
        (None, Some(p)) if ["liquid", "solid"].iter().any(|x| p.eq_ignore_ascii_case(x)) => Some(false),
        (None, Some(p)) => return Err(format!("unknown phase {p:?} (beads phases: vapor, liquid)")),
        (None, None) => None,
    };
    let priority = raw.priority.map(|p| parse_priority(&p.0, "playbook")).transpose()?;
    let mut vars = BTreeMap::new();
    for (vname, v) in raw.vars {
        if !is_ident(&vname) {
            return Err(format!("invalid var name {vname:?} (letters, digits, '_'; starts with a letter)"));
        }
        let kind = match v.kind.as_deref().map(|k| k.trim().to_ascii_lowercase()) {
            None => VarKind::String,
            Some(k) if k == "string" => VarKind::String,
            Some(k) if k == "int" || k == "integer" => VarKind::Int,
            Some(k) if k == "bool" || k == "boolean" => VarKind::Bool,
            Some(k) => return Err(format!("var {vname}: unknown type {k:?} (string, int, bool)")),
        };
        if v.required && v.default.is_some() {
            return Err(format!("var {vname}: a required var cannot have a default"));
        }
        let def = VarDef {
            description: v.description,
            default: v.default.map(|d| d.0),
            required: v.required,
            choices: v.choices.into_iter().map(|c| c.0).collect(),
            pattern: v.pattern,
            kind,
        };
        if let Some(p) = &def.pattern {
            regex_lite::Regex::new(p).map_err(|e| format!("var {vname}: invalid pattern {p:?}: {e}"))?;
        }
        if let Some(d) = &def.default {
            def.check(&vname, d).map_err(|e| format!("default of {e}"))?;
        }
        vars.insert(vname, def);
    }
    let steps = raw.steps.into_iter().map(|s| {
        let path = s.id.clone();
        convert_step(s, &path)
    });
    Ok(Playbook {
        name,
        description: raw.description,
        version: raw.version,
        title: raw.title,
        priority,
        labels: raw.labels,
        ephemeral,
        extends: raw.extends,
        vars,
        steps: steps.collect::<std::result::Result<_, _>>()?,
        source: None,
    })
}

/// Parse a playbook from TOML. `origin` names it in errors and supplies the
/// default name (a file stem).
pub fn parse_toml(text: &str, origin: &str, default_name: &str) -> Result<Playbook> {
    let raw: RawPlaybook = toml::from_str(text).map_err(|e| Error::invalid(format!("{origin}: {e}")))?;
    convert(raw, default_name).map_err(|e| Error::invalid(format!("{origin}: {e}")))
}

/// Parse a playbook from JSON (same shape as TOML).
pub fn parse_json(text: &str, origin: &str, default_name: &str) -> Result<Playbook> {
    let raw: RawPlaybook = serde_json::from_str(text).map_err(|e| Error::invalid(format!("{origin}: {e}")))?;
    convert(raw, default_name).map_err(|e| Error::invalid(format!("{origin}: {e}")))
}

/// Render a playbook as TOML.
pub fn to_toml(pb: &Playbook) -> Result<String> {
    toml::to_string_pretty(pb).map_err(|e| Error::invalid(format!("cannot render playbook {}: {e}", pb.name)))
}

// ------------------------------------------------------------- validation

/// Checks one template field against the variables in scope.
type TextCheck = dyn Fn(&str, &str, &BTreeSet<String>) -> std::result::Result<(), String>;

impl Playbook {
    /// Whole-playbook checks (after `extends` is merged): unique step ids,
    /// resolvable `needs`, no cycles or ancestor deadlocks, declared variables.
    pub fn validate(&self) -> Result<()> {
        self.check().map_err(|e| Error::invalid(format!("playbook {}: {e}", self.name)))
    }

    fn check(&self) -> std::result::Result<(), String> {
        if self.steps.is_empty() {
            return Err("has no steps".into());
        }
        // id -> (ancestor ids, step)
        let mut index: HashMap<&str, (Vec<&str>, &Step)> = HashMap::new();
        fn walk<'a>(
            steps: &'a [Step],
            ancestors: &mut Vec<&'a str>,
            index: &mut HashMap<&'a str, (Vec<&'a str>, &'a Step)>,
        ) -> std::result::Result<(), String> {
            for s in steps {
                if index.insert(&s.id, (ancestors.clone(), s)).is_some() {
                    return Err(format!("duplicate step id {:?} (ids are unique across the playbook)", s.id));
                }
                ancestors.push(&s.id);
                walk(&s.children, ancestors, index)?;
                ancestors.pop();
            }
            Ok(())
        }
        walk(&self.steps, &mut Vec::new(), &mut index)?;

        for (id, (ancestors, step)) in &index {
            for n in &step.needs {
                let Some((n_ancestors, _)) = index.get(n.as_str()) else {
                    return Err(format!("step {id} needs unknown step {n:?}"));
                };
                if n == id {
                    return Err(format!("step {id} needs itself"));
                }
                if ancestors.contains(&n.as_str()) {
                    return Err(format!("step {id} needs its own group {n}; a group already runs its children"));
                }
                if n_ancestors.contains(id) {
                    return Err(format!("step {id} needs {n}, which is inside it; that would deadlock"));
                }
            }
            if let Some(w) = &step.waits_for {
                let spawner = match &w.spawner {
                    Some(s) => s.as_str(),
                    None => step.needs.first().map(String::as_str).ok_or_else(|| {
                        format!(
                            "step {id}: waits_for {:?} waits on the children of its first `needs`, but it has none",
                            w.gate
                        )
                    })?,
                };
                if !index.contains_key(spawner) {
                    return Err(format!("step {id}: waits_for names unknown step {spawner:?}"));
                }
                if spawner == *id {
                    return Err(format!("step {id} cannot wait for its own children"));
                }
                if ancestors.contains(&spawner) || index[spawner].0.contains(id) {
                    return Err(format!("step {id}: waits_for spawner {spawner} must not contain it or be inside it"));
                }
            }
        }
        // Cycles over `needs`, with a group standing for its whole subtree.
        let mut state: HashMap<&str, u8> = HashMap::new();
        fn visit<'a>(
            id: &'a str,
            index: &HashMap<&'a str, (Vec<&'a str>, &'a Step)>,
            state: &mut HashMap<&'a str, u8>,
            path: &mut Vec<&'a str>,
        ) -> std::result::Result<(), String> {
            match state.get(id) {
                Some(2) => return Ok(()),
                Some(1) => {
                    let start = path.iter().position(|p| *p == id).unwrap_or(0);
                    let mut cycle: Vec<&str> = path[start..].to_vec();
                    cycle.push(id);
                    return Err(format!("needs form a cycle: {}", cycle.join(" -> ")));
                }
                _ => {}
            }
            state.insert(id, 1);
            path.push(id);
            let (ancestors, step) = &index[id];
            let mut next: Vec<&str> = step.needs.iter().map(String::as_str).collect();
            // A step also waits for whatever its groups wait for, and a group
            // finishes only after its children.
            for a in ancestors {
                next.extend(index[a].1.needs.iter().map(String::as_str));
            }
            next.extend(step.children.iter().map(|c| c.id.as_str()));
            for n in next {
                if index.contains_key(n) {
                    visit(n, index, state, path)?;
                }
            }
            path.pop();
            state.insert(id, 2);
            Ok(())
        }
        let mut ids: Vec<&str> = index.keys().copied().collect();
        ids.sort_unstable();
        for id in ids {
            visit(id, &index, &mut state, &mut Vec::new())?;
        }

        // Variables: templates and conditions may only use declared vars and
        // the loop variables of the step and its groups.
        let declared: BTreeSet<String> = self.vars.keys().cloned().collect();
        let check_text = |what: &str, text: &str, scope: &BTreeSet<String>| -> std::result::Result<(), String> {
            for r in template::refs(text).map_err(|e| format!("{what}: {e}"))? {
                if !scope.contains(&r) {
                    return Err(format!("{what} uses undeclared variable `{r}`"));
                }
            }
            Ok(())
        };
        if let Some(t) = &self.title {
            check_text("title", t, &declared)?;
        }
        check_text("description", &self.description, &declared)?;
        for l in &self.labels {
            check_text("labels", l, &declared)?;
        }
        fn check_steps(
            steps: &[Step],
            scope: &BTreeSet<String>,
            declared: &BTreeSet<String>,
            check_text: &TextCheck,
        ) -> std::result::Result<(), String> {
            for s in steps {
                let mut inner = scope.clone();
                if let Some(l) = &s.repeat {
                    if declared.contains(&l.var) {
                        return Err(format!("step {}: loop variable `{}` shadows a playbook var", s.id, l.var));
                    }
                    // The loop source is evaluated outside the loop.
                    let source: Vec<&str> = match &l.over {
                        LoopOver::Count(x) | LoopOver::Range(x) | LoopOver::Over(x) => vec![x.as_str()],
                        LoopOver::Items(items) => items.iter().map(String::as_str).collect(),
                    };
                    for x in source {
                        check_text(&format!("step {} loop", s.id), x, scope)?;
                    }
                    inner.insert(l.var.clone());
                }
                for (field, text) in s.templates() {
                    if field.starts_with("loop") {
                        continue;
                    }
                    check_text(&format!("step {} {field}", s.id), text, &inner)?;
                }
                for (k, v) in &s.metadata {
                    check_value(&format!("step {} metadata.{k}", s.id), v, &inner, check_text)?;
                }
                if let Some(c) = &s.condition {
                    let cond = Condition::parse(c).map_err(|e| format!("step {}: {e}", s.id))?;
                    for v in cond.vars() {
                        if !inner.contains(&v) {
                            return Err(format!("step {} condition uses undeclared variable `{v}`", s.id));
                        }
                    }
                }
                check_steps(&s.children, &inner, declared, check_text)?;
            }
            Ok(())
        }
        fn check_value(
            what: &str,
            v: &Value,
            scope: &BTreeSet<String>,
            check_text: &TextCheck,
        ) -> std::result::Result<(), String> {
            match v {
                Value::String(s) => check_text(what, s, scope),
                Value::Array(items) => items.iter().try_for_each(|i| check_value(what, i, scope, check_text)),
                Value::Object(m) => m.values().try_for_each(|i| check_value(what, i, scope, check_text)),
                _ => Ok(()),
            }
        }
        check_steps(&self.steps, &declared, &declared, &check_text)?;
        for s in self.all_steps() {
            if let Some(g) = &s.gate {
                if let Some(t) = g.timeout.as_deref().filter(|t| !t.contains("{{")) {
                    parse_duration(t).map_err(|e| format!("step {} gate: {e}", s.id))?;
                }
                if let Some(r) = g.repo.as_deref().filter(|r| !r.contains("{{")) {
                    validate_repo(r).map_err(|e| format!("step {} gate: {e}", s.id))?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(text: &str) -> Result<Playbook> {
        let pb = parse_toml(text, "test.toml", "test")?;
        pb.validate()?;
        Ok(pb)
    }

    #[test]
    fn parses_a_beads_formula() {
        let pb = parse(
            r#"
formula = "release"
description = "Standard release"
version = 1
type = "workflow"
phase = "vapor"

[vars.version]
description = "Release version"
required = true
pattern = '^\d+\.\d+\.\d+$'

[[steps]]
id = "bump"
title = "Bump to {{version}}"

[[steps]]
id = "wait-ci"
title = "Wait for CI"
depends_on = ["bump"]
[steps.gate]
type = "gh:run"
id = "release.yml"
timeout = "30m"
"#,
        )
        .unwrap();
        assert_eq!(pb.name, "release");
        assert!(pb.is_ephemeral());
        assert_eq!(pb.steps[1].needs, vec!["bump"]);
        let gate = pb.steps[1].gate.as_ref().unwrap();
        assert_eq!((gate.kind, gate.await_id.as_deref()), (GateKind::GhRun, Some("release.yml")));
        assert!(pb.vars["version"].check("version", "1.2").is_err());
        assert_eq!(pb.vars["version"].check("version", "1.2.3").unwrap(), "1.2.3");
    }

    #[test]
    fn unknown_keys_are_errors_with_locations() {
        let err = parse("[[steps]]\nid = \"a\"\ntitle = \"A\"\n[steps.gate]\ntype = \"human\"\napprovers = [\"x\"]\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("approvers") && err.contains("line"), "{err}");
        let err = parse("[[steps]]\nid = \"a\"\nneeds_typo = []\n").unwrap_err().to_string();
        assert!(err.contains("needs_typo"), "{err}");
    }

    #[test]
    fn rejects_beads_pitfalls() {
        let err = parse("[[steps]]\nid = \"review\"\ntype = \"human\"\n").unwrap_err().to_string();
        assert!(err.contains("[steps.gate]"), "{err}");
        let err = parse("[[steps]]\nid = \"bake\"\n[steps.gate]\ntype = \"timer\"\ntimeout = \"1x\"\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid duration"), "{err}");
        let err = parse("[[steps]]\nid = \"t\"\n[steps.gate]\ntype = \"timer\"\n").unwrap_err().to_string();
        assert!(err.contains("needs a duration"), "{err}");
    }

    #[test]
    fn graph_errors() {
        let two = |a: &str, b: &str| format!("[[steps]]\nid = \"a\"\n{a}\n[[steps]]\nid = \"b\"\n{b}\n");
        assert!(parse(&two("needs = [\"zzz\"]", "")).unwrap_err().to_string().contains("unknown step"));
        assert!(parse(&two("needs = [\"b\"]", "needs = [\"a\"]")).unwrap_err().to_string().contains("cycle"));
        assert!(parse(&two("", "")).is_ok());
        let dup = "[[steps]]\nid = \"a\"\n[[steps.children]]\nid = \"a\"\n";
        assert!(parse(dup).unwrap_err().to_string().contains("duplicate"));
        let inner = "[[steps]]\nid = \"g\"\nneeds = [\"c\"]\n[[steps.children]]\nid = \"c\"\n";
        assert!(parse(inner).unwrap_err().to_string().contains("inside it"));
        let wf = "[[steps]]\nid = \"s\"\nwaits_for = \"all-children\"\n";
        assert!(parse(wf).unwrap_err().to_string().contains("first `needs`"));
    }

    #[test]
    fn variables_must_be_declared() {
        let err = parse("[[steps]]\nid = \"a\"\ntitle = \"Deploy {{env}}\"\n").unwrap_err().to_string();
        assert!(err.contains("undeclared variable `env`"), "{err}");
        let ok = "[vars.env]\ndefault = \"dev\"\n[[steps]]\nid = \"a\"\ntitle = \"Deploy {{env}} #{{n}}\"\n[steps.loop]\ncount = 2\nvar = \"n\"\n";
        parse(ok).unwrap();
        let shadow = "[vars.i]\ndefault = \"1\"\n[[steps]]\nid = \"a\"\n[steps.loop]\ncount = 2\n";
        assert!(parse(shadow).unwrap_err().to_string().contains("shadows"));
        let cond = "[[steps]]\nid = \"a\"\ncondition = \"{{prod}}\"\n";
        assert!(parse(cond).unwrap_err().to_string().contains("undeclared variable `prod`"));
        let bad_default = "[vars.n]\ntype = \"int\"\ndefault = \"x\"\n[[steps]]\nid = \"a\"\n";
        assert!(parse(bad_default).unwrap_err().to_string().contains("integer"));
    }

    #[test]
    fn toml_round_trip() {
        let pb = parse(
            "playbook = \"x\"\n[vars.v]\nrequired = true\n[[steps]]\nid = \"a\"\ntitle = \"A {{v}}\"\n[[steps]]\nid = \"g\"\nneeds = [\"a\"]\n[[steps.children]]\nid = \"c\"\n[steps.children.gate]\ntype = \"human\"\n",
        )
        .unwrap();
        let text = to_toml(&pb).unwrap();
        let again = parse(&text).unwrap();
        assert_eq!(to_toml(&again).unwrap(), text);
        assert!(text.contains("[[steps.children]]"), "{text}");
    }
}
