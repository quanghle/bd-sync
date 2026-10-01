//! Compiling a playbook and its variables into a [`Plan`]: exactly the issues
//! and edges a run creates, with every template rendered.
//!
//! * Issue keys are dotted step paths (`build.sign-2`); a run's issues get
//!   ids `<run id>.<key>`.
//! * A step whose condition is false is left out, and steps that need it
//!   inherit its `needs`, so ordering survives the omission.
//! * A looped step becomes one issue per iteration (`<id>-<value>`). Needing it
//!   from outside waits for every iteration; steps inside the same iteration
//!   see only their own iteration.
//! * `expand` runs another playbook's steps inside the step, with their own
//!   variables and `needs` namespace.
//! * A gate becomes a sibling issue `gate-<step>` that blocks the step and
//!   carries the step's prerequisites, so it arms when the step could start.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use serde::Serialize;
use serde_json::{Map, Value, json};

use super::loader::Loader;
use super::model::{Loop, LoopOver, MAX_RUN_ISSUES, Playbook, Step, StepGate, VarDef};
use super::template::{self, Condition, render};
use crate::error::{Error, Result};
use crate::gates::{GateKind, GateSpec};
use crate::model::{DepType, GATE_TYPE, MAX_TITLE_CHARS};

/// How deep `expand` may nest.
pub const MAX_EXPAND_DEPTH: usize = 8;

/// Inputs of a run besides the playbook itself.
#[derive(Clone, Debug, Default)]
pub struct RunRequest {
    pub vars: BTreeMap<String, String>,
    /// Overrides the playbook's `ephemeral`.
    pub ephemeral: Option<bool>,
    /// Assignee of the run and of every step without one.
    pub assignee: Option<String>,
    /// Overrides the run title.
    pub title: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// The run itself (an epic).
    Run,
    /// A step with children (an epic that closes when they do).
    Group,
    Step,
    Gate,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Run => "run",
            Role::Group => "group",
            Role::Step => "step",
            Role::Gate => "gate",
        }
    }

    pub fn parse(s: &str) -> Option<Role> {
        Some(match s {
            "run" => Role::Run,
            "group" => Role::Group,
            "step" => Role::Step,
            "gate" => Role::Gate,
            _ => return None,
        })
    }

    pub fn is_container(self) -> bool {
        matches!(self, Role::Run | Role::Group)
    }
}

/// An issue a run will create.
#[derive(Clone, Debug, Serialize)]
pub struct PlannedIssue {
    /// Dotted path below the run (`""` for the run itself).
    pub key: String,
    /// Key of the parent; `None` only for the run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<String>,
    pub role: Role,
    /// The playbook step it comes from (empty for the run).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub step: String,
    pub title: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub design: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub acceptance_criteria: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub notes: String,
    pub issue_type: String,
    pub priority: u8,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assignee: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub estimate: Option<i64>,
    #[serde(skip_serializing_if = "Map::is_empty")]
    pub metadata: Map<String, Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gate: Option<GateSpec>,
}

/// An edge `from -> to` ("from depends on to") between planned issues.
#[derive(Clone, Debug, Serialize)]
pub struct PlannedEdge {
    pub from: String,
    pub to: String,
    #[serde(rename = "type")]
    pub dep_type: DepType,
    #[serde(skip_serializing_if = "is_empty_object")]
    pub metadata: Value,
}

fn is_empty_object(v: &Value) -> bool {
    v.as_object().is_some_and(Map::is_empty)
}

/// Everything a run creates. Issues are in creation order (parents first).
#[derive(Clone, Debug, Serialize)]
pub struct Plan {
    pub playbook: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<PathBuf>,
    pub vars: BTreeMap<String, String>,
    pub ephemeral: bool,
    pub run: PlannedIssue,
    pub issues: Vec<PlannedIssue>,
    pub edges: Vec<PlannedEdge>,
}

impl Plan {
    pub fn count(&self, role: Role) -> usize {
        self.issues.iter().filter(|i| i.role == role).count()
    }
}

/// Apply defaults and check values. Unknown names and missing required
/// variables are errors (all reported at once).
pub fn resolve_vars(
    defs: &BTreeMap<String, VarDef>,
    given: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, String>> {
    let unknown: Vec<&str> = given.keys().filter(|k| !defs.contains_key(*k)).map(String::as_str).collect();
    if !unknown.is_empty() {
        let declared: Vec<&str> = defs.keys().map(String::as_str).collect();
        return Err(Error::invalid(format!(
            "unknown var(s) {} (declared: {})",
            unknown.join(", "),
            if declared.is_empty() { "none".to_string() } else { declared.join(", ") }
        )));
    }
    let mut out = BTreeMap::new();
    let mut missing = Vec::new();
    let mut problems = Vec::new();
    for (name, def) in defs {
        let value = match given.get(name).or(def.default.as_ref()) {
            Some(v) => v.clone(),
            None if def.required => {
                missing.push(if def.description.is_empty() {
                    name.clone()
                } else {
                    format!("{name} ({})", def.description)
                });
                continue;
            }
            None => String::new(),
        };
        if value.is_empty() && !def.required {
            out.insert(name.clone(), value);
            continue;
        }
        match def.check(name, &value) {
            Ok(v) => {
                out.insert(name.clone(), v);
            }
            Err(e) => problems.push(e),
        }
    }
    if !missing.is_empty() {
        problems.insert(0, format!("missing required var(s): {} (pass --var NAME=VALUE)", missing.join(", ")));
    }
    if !problems.is_empty() {
        return Err(Error::invalid(problems.join("; ")));
    }
    Ok(out)
}

/// Compile `pb` with `req` into the issues and edges of a run.
pub fn compile(pb: &Playbook, req: &RunRequest, loader: &Loader) -> Result<Plan> {
    let vars = resolve_vars(&pb.vars, &req.vars)?;
    let r = |what: &str, text: &str| render(text, &vars).map_err(|e| Error::invalid(format!("{what}: {e}")));
    let title = match (&req.title, &pb.title) {
        (Some(t), _) => t.trim().to_string(),
        (None, Some(t)) => r("title", t)?,
        (None, None) => default_run_title(&pb.name, &vars),
    };
    let run = PlannedIssue {
        key: String::new(),
        parent: None,
        role: Role::Run,
        step: String::new(),
        title: clip(&title),
        description: r("description", &pb.description)?,
        design: String::new(),
        acceptance_criteria: String::new(),
        notes: String::new(),
        issue_type: "epic".into(),
        priority: pb.priority.unwrap_or(2),
        labels: pb.labels.iter().map(|l| r("labels", l)).collect::<Result<_>>()?,
        assignee: req.assignee.clone(),
        estimate: None,
        metadata: Map::new(),
        gate: None,
    };
    let mut b = Builder {
        loader,
        issues: Vec::new(),
        edges: Vec::new(),
        keys: HashSet::new(),
        pairs: HashSet::new(),
        assignee: req.assignee.clone(),
        stack: vec![pb.name.clone()],
    };
    let dir = pb.source.as_deref().and_then(Path::parent).map(Path::to_path_buf);
    b.namespace(&pb.steps, &vars, "", run.priority, dir.as_deref())?;
    if b.issues.is_empty() {
        return Err(Error::invalid(format!(
            "playbook {}: every step was left out by its condition or loop; nothing to run",
            pb.name
        )));
    }
    Ok(Plan {
        playbook: pb.name.clone(),
        version: pb.version,
        source: pb.source.clone(),
        vars,
        ephemeral: req.ephemeral.unwrap_or_else(|| pb.is_ephemeral()),
        run,
        issues: b.issues,
        edges: b.edges,
    })
}

fn default_run_title(name: &str, vars: &BTreeMap<String, String>) -> String {
    let shown: Vec<String> = vars.iter().filter(|(_, v)| !v.is_empty()).map(|(k, v)| format!("{k}={v}")).collect();
    if shown.is_empty() { name.to_string() } else { format!("{name} ({})", shown.join(", ")) }
}

fn clip(s: &str) -> String {
    let t = s.trim();
    if t.chars().count() <= MAX_TITLE_CHARS { t.to_string() } else { t.chars().take(MAX_TITLE_CHARS).collect() }
}

fn join(parent: &str, local: &str) -> String {
    if parent.is_empty() { local.to_string() } else { format!("{parent}.{local}") }
}

fn slug(s: &str) -> String {
    let mut out = String::new();
    for c in s.trim().chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
        } else if !out.ends_with('-') && !out.is_empty() {
            out.push('-');
        }
    }
    let out: String = out.trim_end_matches('-').chars().take(32).collect();
    out.trim_end_matches('-').to_string()
}

/// Loop values with id suffixes (unique within the loop).
fn loop_values(l: &Loop, vars: &BTreeMap<String, String>) -> std::result::Result<Vec<(String, String)>, String> {
    let numbers = |a: i64, b: i64| -> std::result::Result<Vec<String>, String> {
        if b >= a && (b - a) as usize >= MAX_RUN_ISSUES {
            return Err(format!("loop of {} iterations is too large (max {MAX_RUN_ISSUES})", b - a + 1));
        }
        Ok(if b < a { Vec::new() } else { (a..=b).map(|n| n.to_string()).collect() })
    };
    let values: Vec<String> = match &l.over {
        LoopOver::Count(c) => {
            let text = render(c, vars)?;
            let n: i64 = text.trim().parse().map_err(|_| format!("loop count must be a whole number, got {text:?}"))?;
            if n < 0 {
                return Err(format!("loop count must not be negative, got {n}"));
            }
            numbers(1, n)?
        }
        LoopOver::Range(r) => {
            let text = render(r, vars)?;
            let (a, b) = text
                .split_once("..=")
                .or_else(|| text.split_once(".."))
                .ok_or_else(|| format!("loop range must look like 1..5 (inclusive), got {text:?}"))?;
            let parse =
                |s: &str| s.trim().parse::<i64>().map_err(|_| format!("loop range bound {s:?} is not a number"));
            numbers(parse(a)?, parse(b)?)?
        }
        LoopOver::Items(items) => items.iter().map(|i| render(i, vars)).collect::<std::result::Result<_, _>>()?,
        LoopOver::Over(o) => {
            render(o, vars)?.split(',').map(str::trim).filter(|s| !s.is_empty()).map(String::from).collect()
        }
    };
    let mut seen: HashMap<String, usize> = HashMap::new();
    let mut out = Vec::with_capacity(values.len());
    for (n, v) in values.into_iter().enumerate() {
        let base = match &l.over {
            LoopOver::Count(_) | LoopOver::Range(_) => v.trim_start_matches('-').to_string(),
            _ => Some(slug(&v)).filter(|s| !s.is_empty()).unwrap_or_else(|| (n + 1).to_string()),
        };
        let count = seen.entry(base.clone()).or_insert(0);
        *count += 1;
        let suffix = if *count == 1 { base } else { format!("{base}-{count}") };
        out.push((suffix, v));
    }
    Ok(out)
}

/// One placed step (one loop iteration of it).
struct Node<'a> {
    step: &'a Step,
    key: String,
    /// Enclosing loop iterations, outermost first: (loop step id, iteration key).
    iterations: Vec<(&'a str, String)>,
    /// Previous iteration of a sequential loop.
    prev: Option<String>,
    gate: Option<String>,
}

/// The steps of one playbook (the top level or an `expand`): `needs` resolve here.
#[derive(Default)]
struct Namespace<'a> {
    nodes: Vec<Node<'a>>,
    by_step: HashMap<&'a str, Vec<usize>>,
    steps: HashMap<&'a str, &'a Step>,
    ancestors: HashMap<&'a str, Vec<&'a str>>,
}

struct Builder<'l> {
    loader: &'l Loader,
    issues: Vec<PlannedIssue>,
    edges: Vec<PlannedEdge>,
    keys: HashSet<String>,
    pairs: HashSet<(String, String)>,
    assignee: Option<String>,
    stack: Vec<String>,
}

impl Builder<'_> {
    fn namespace(
        &mut self,
        steps: &[Step],
        vars: &BTreeMap<String, String>,
        parent_key: &str,
        priority: u8,
        dir: Option<&Path>,
    ) -> Result<()> {
        let mut ns = Namespace::default();
        self.place(steps, vars, parent_key, priority, &[], &[], dir, &mut ns)?;
        self.wire(&ns)
    }

    fn claim_key(&mut self, key: &str) -> Result<()> {
        if !self.keys.insert(key.to_string()) {
            return Err(Error::invalid(format!("two issues of the run would share the id suffix {key:?}")));
        }
        if self.keys.len() > MAX_RUN_ISSUES {
            return Err(Error::invalid(format!("a run may create at most {MAX_RUN_ISSUES} issues")));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn place<'a>(
        &mut self,
        steps: &'a [Step],
        vars: &BTreeMap<String, String>,
        parent_key: &str,
        priority: u8,
        iterations: &[(&'a str, String)],
        ancestors: &[&'a str],
        dir: Option<&Path>,
        ns: &mut Namespace<'a>,
    ) -> Result<()> {
        for step in steps {
            ns.steps.insert(&step.id, step);
            ns.ancestors.insert(&step.id, ancestors.to_vec());
            let at = |e: String| Error::invalid(format!("step {}: {e}", join(parent_key, &step.id)));
            let iters: Vec<(String, BTreeMap<String, String>)> = match &step.repeat {
                None => vec![(String::new(), vars.clone())],
                Some(l) => loop_values(l, vars)
                    .map_err(at)?
                    .into_iter()
                    .map(|(suffix, value)| {
                        let mut v = vars.clone();
                        v.insert(l.var.clone(), value);
                        (format!("-{suffix}"), v)
                    })
                    .collect(),
            };
            let condition = step.condition.as_deref().map(Condition::parse).transpose().map_err(at)?;
            let mut prev: Option<String> = None;
            for (suffix, ivars) in iters {
                if let Some(c) = &condition {
                    if !c.eval(&ivars).map_err(at)? {
                        continue;
                    }
                }
                let local = format!("{}{suffix}", step.id);
                let key = join(parent_key, &local);
                self.claim_key(&key)?;
                let prio = step.priority.unwrap_or(priority);
                let mut its = iterations.to_vec();
                if step.repeat.is_some() {
                    its.push((step.id.as_str(), key.clone()));
                }
                let issue = self.render_step(step, &ivars, &key, parent_key, prio)?;
                let step_title = issue.title.clone();
                self.issues.push(issue);
                let gate = match &step.gate {
                    Some(g) => {
                        let gk = join(parent_key, &format!("gate-{local}"));
                        self.claim_key(&gk)?;
                        let gate = self.render_gate(step, g, &ivars, &gk, parent_key, prio, &step_title)?;
                        self.issues.push(gate);
                        Some(gk)
                    }
                    None => None,
                };
                let sequential = step.repeat.as_ref().is_some_and(|l| l.sequential);
                ns.by_step.entry(&step.id).or_default().push(ns.nodes.len());
                ns.nodes.push(Node {
                    step,
                    key: key.clone(),
                    iterations: its.clone(),
                    prev: if sequential { prev.clone() } else { None },
                    gate,
                });
                prev = Some(key.clone());
                if !step.children.is_empty() {
                    let mut inner = ancestors.to_vec();
                    inner.push(&step.id);
                    self.place(&step.children, &ivars, &key, prio, &its, &inner, dir, ns)?;
                }
                if let Some(target) = &step.expand {
                    self.expand(step, target, &ivars, &key, prio, dir)?;
                }
            }
            // A step left out entirely still lists its children, so needs on
            // them resolve (to nothing, inheriting through the chain).
            if !ns.by_step.contains_key(step.id.as_str()) {
                fn register<'a>(steps: &'a [Step], anc: &mut Vec<&'a str>, ns: &mut Namespace<'a>) {
                    for s in steps {
                        ns.steps.insert(&s.id, s);
                        ns.ancestors.insert(&s.id, anc.clone());
                        anc.push(&s.id);
                        register(&s.children, anc, ns);
                        anc.pop();
                    }
                }
                let mut anc = ancestors.to_vec();
                anc.push(&step.id);
                register(&step.children, &mut anc, ns);
            }
        }
        Ok(())
    }

    fn expand(
        &mut self,
        step: &Step,
        target: &str,
        vars: &BTreeMap<String, String>,
        key: &str,
        priority: u8,
        dir: Option<&Path>,
    ) -> Result<()> {
        let at = |e: String| Error::invalid(format!("step {key}: expand {target}: {e}"));
        if self.stack.len() > MAX_EXPAND_DEPTH {
            return Err(at(format!("expansions nest deeper than {MAX_EXPAND_DEPTH}")));
        }
        let pb = self.loader.load_from(target, dir).map_err(|e| at(e.to_string()))?;
        if self.stack.contains(&pb.name) {
            return Err(at(format!("circular expand: {} -> {}", self.stack.join(" -> "), pb.name)));
        }
        let mut given = BTreeMap::new();
        for (k, v) in &step.expand_vars {
            given.insert(k.clone(), render(v, vars).map_err(at)?);
        }
        let inner = resolve_vars(&pb.vars, &given).map_err(|e| at(e.to_string()))?;
        let inner_dir = pb.source.as_deref().and_then(Path::parent).map(Path::to_path_buf);
        self.stack.push(pb.name.clone());
        self.namespace(&pb.steps, &inner, key, pb.priority.unwrap_or(priority), inner_dir.as_deref())?;
        self.stack.pop();
        Ok(())
    }

    fn render_step(
        &self,
        step: &Step,
        vars: &BTreeMap<String, String>,
        key: &str,
        parent_key: &str,
        priority: u8,
    ) -> Result<PlannedIssue> {
        let r = |field: &str, text: &str| {
            render(text, vars).map_err(|e| Error::invalid(format!("step {key} {field}: {e}")))
        };
        let mut title = r("title", &step.title)?;
        if let Some(l) = &step.repeat {
            let mentions = template::refs(&step.title).map(|refs| refs.contains(&l.var)).unwrap_or(false);
            if !mentions {
                title = format!("{title} [{}]", vars.get(&l.var).cloned().unwrap_or_default());
            }
        }
        if title.trim().is_empty() {
            return Err(Error::invalid(format!("step {key}: title renders empty")));
        }
        let role = if step.is_group() { Role::Group } else { Role::Step };
        let assignee = match &step.assignee {
            Some(a) => Some(r("assignee", a)?).filter(|a| !a.trim().is_empty()),
            None if role == Role::Step => self.assignee.clone(),
            None => None,
        };
        let mut metadata = Map::new();
        for (k, v) in &step.metadata {
            metadata.insert(
                k.clone(),
                render_value(v, vars).map_err(|e| Error::invalid(format!("step {key} metadata.{k}: {e}")))?,
            );
        }
        Ok(PlannedIssue {
            key: key.to_string(),
            parent: Some(parent_key.to_string()),
            role,
            step: step.id.clone(),
            title: clip(&title),
            description: r("description", &step.description)?,
            design: r("design", &step.design)?,
            acceptance_criteria: r("acceptance_criteria", &step.acceptance_criteria)?,
            notes: r("notes", &step.notes)?,
            issue_type: if role == Role::Group {
                "epic".into()
            } else {
                step.issue_type.clone().unwrap_or_else(|| "task".into())
            },
            priority,
            labels: step.labels.iter().map(|l| r("labels", l)).collect::<Result<_>>()?,
            assignee,
            estimate: step.estimate,
            metadata,
            gate: None,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn render_gate(
        &self,
        step: &Step,
        g: &StepGate,
        vars: &BTreeMap<String, String>,
        key: &str,
        parent_key: &str,
        priority: u8,
        step_title: &str,
    ) -> Result<PlannedIssue> {
        let at = |e: String| Error::invalid(format!("step {key}: {e}"));
        let r = |text: &str| render(text, vars).map_err(at);
        let opt = |v: &Option<String>| -> Result<Option<String>> {
            Ok(match v {
                Some(s) => Some(r(s)?.trim().to_string()).filter(|s| !s.is_empty()),
                None => None,
            })
        };
        let mut await_id = opt(&g.await_id)?;
        if g.kind == GateKind::GhPr {
            await_id = await_id.map(|a| a.trim_start_matches('#').to_string());
        }
        let spec = GateSpec { kind: g.kind, await_id, timeout: opt(&g.timeout)?, repo: opt(&g.repo)? };
        spec.validate().map_err(|e| at(e.to_string()))?;
        let title = match &g.title {
            Some(t) => r(t)?,
            None => spec.default_title(Some(step_title)),
        };
        Ok(PlannedIssue {
            key: key.to_string(),
            parent: Some(parent_key.to_string()),
            role: Role::Gate,
            step: step.id.clone(),
            title: clip(&title),
            description: r(&g.description)?,
            design: String::new(),
            acceptance_criteria: String::new(),
            notes: String::new(),
            issue_type: GATE_TYPE.into(),
            priority,
            labels: Vec::new(),
            assignee: opt(&g.assignee)?,
            estimate: None,
            metadata: Map::new(),
            gate: Some(spec),
        })
    }

    fn edge(&mut self, from: &str, to: &str, dep_type: DepType, metadata: Value) {
        if from != to && self.pairs.insert((from.to_string(), to.to_string())) {
            self.edges.push(PlannedEdge { from: from.into(), to: to.into(), dep_type, metadata });
        }
    }

    /// Keys of `need` as seen from `from`: inside a shared loop iteration only
    /// that iteration's, otherwise every placed instance.
    fn select(ns: &Namespace<'_>, need: &str, from: &Node<'_>) -> Vec<String> {
        let all: Vec<&Node<'_>> =
            ns.by_step.get(need).map(|ix| ix.iter().map(|i| &ns.nodes[*i]).collect()).unwrap_or_default();
        let need_ancestors = ns.ancestors.get(need).cloned().unwrap_or_default();
        for (loop_step, iteration) in from.iterations.iter().rev() {
            if need_ancestors.contains(loop_step) {
                let prefix = format!("{iteration}.");
                return all.into_iter().filter(|n| n.key.starts_with(&prefix)).map(|n| n.key.clone()).collect();
            }
        }
        all.into_iter().map(|n| n.key.clone()).collect()
    }

    fn resolve_need<'a>(
        ns: &Namespace<'a>,
        need: &'a str,
        from: &Node<'a>,
        out: &mut Vec<String>,
        visiting: &mut HashSet<&'a str>,
    ) {
        let keys = Builder::select(ns, need, from);
        if !keys.is_empty() {
            for k in keys {
                if !out.contains(&k) {
                    out.push(k);
                }
            }
            return;
        }
        // Left out here: inherit what it needed (and what its groups needed).
        if !visiting.insert(need) {
            return;
        }
        let Some(step) = ns.steps.get(need) else { return };
        let mut inherited: Vec<&'a str> = step.needs.iter().map(String::as_str).collect();
        for a in ns.ancestors.get(need).into_iter().flatten() {
            if let Some(s) = ns.steps.get(a) {
                inherited.extend(s.needs.iter().map(String::as_str));
            }
        }
        for n in inherited {
            Builder::resolve_need(ns, n, from, out, visiting);
        }
    }

    fn wire(&mut self, ns: &Namespace<'_>) -> Result<()> {
        for node in &ns.nodes {
            let step = node.step;
            let mut needs: Vec<String> = Vec::new();
            for n in &step.needs {
                Builder::resolve_need(ns, n, node, &mut needs, &mut HashSet::new());
            }
            // An inherited need may point into this step's own subtree or at
            // one of its groups; an edge there would deadlock.
            let own = format!("{}.", node.key);
            needs.retain(|k| *k != node.key && !k.starts_with(&own) && !node.key.starts_with(&format!("{k}.")));
            if let Some(p) = &node.prev {
                if !needs.contains(p) {
                    needs.push(p.clone());
                }
            }
            let mut waits: Option<(String, Value)> = None;
            if let Some(w) = &step.waits_for {
                let spawner = w.spawner.as_deref().or(step.needs.first().map(String::as_str)).unwrap_or_default();
                let keys = Builder::select(ns, spawner, node);
                match keys.as_slice() {
                    [] => {}
                    [k] => {
                        // A spawner that has not run has no children yet, so the
                        // fan-in also waits for the spawner itself to close.
                        needs.retain(|n| n != k);
                        let meta = json!({ "gate": w.gate, "also_blocks": true });
                        waits = Some((k.clone(), meta));
                    }
                    _ => {
                        return Err(Error::invalid(format!(
                            "step {}: waits_for spawner {spawner} is a loop; wait on a single step",
                            node.key
                        )));
                    }
                }
            }
            for k in &needs {
                self.edge(&node.key, k, DepType::Blocks, json!({}));
            }
            if let Some((k, meta)) = &waits {
                self.edge(&node.key, k, DepType::WaitsFor, meta.clone());
            }
            if let Some(g) = &node.gate {
                self.edge(&node.key, g, DepType::Blocks, json!({}));
                for k in &needs {
                    self.edge(g, k, DepType::Blocks, json!({}));
                }
                if let Some((k, meta)) = &waits {
                    self.edge(g, k, DepType::WaitsFor, meta.clone());
                }
            }
        }
        Ok(())
    }
}

fn render_value(v: &Value, vars: &BTreeMap<String, String>) -> std::result::Result<Value, String> {
    Ok(match v {
        Value::String(s) => Value::String(render(s, vars)?),
        Value::Array(items) => {
            Value::Array(items.iter().map(|i| render_value(i, vars)).collect::<std::result::Result<_, _>>()?)
        }
        Value::Object(m) => Value::Object(
            m.iter()
                .map(|(k, v)| Ok((k.clone(), render_value(v, vars)?)))
                .collect::<std::result::Result<_, String>>()?,
        ),
        other => other.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::model::parse_toml;

    fn plan(text: &str, vars: &[(&str, &str)]) -> Result<Plan> {
        let pb = parse_toml(text, "t.toml", "t")?;
        pb.validate()?;
        let req = RunRequest {
            vars: vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            ..Default::default()
        };
        compile(&pb, &req, &Loader::default())
    }

    fn edges(p: &Plan) -> Vec<String> {
        let mut v: Vec<String> = p.edges.iter().map(|e| format!("{}->{}:{}", e.from, e.to, e.dep_type)).collect();
        v.sort();
        v
    }

    fn keys(p: &Plan) -> Vec<&str> {
        p.issues.iter().map(|i| i.key.as_str()).collect()
    }

    #[test]
    fn vars_are_strict() {
        let text = "[vars.env]\nenum = [\"staging\", \"prod\"]\ndefault = \"staging\"\n[vars.version]\nrequired = true\n[[steps]]\nid = \"a\"\ntitle = \"{{version}} to {{env}}\"\n";
        let err = plan(text, &[]).unwrap_err().to_string();
        assert!(err.contains("missing required var(s): version"), "{err}");
        let err = plan(text, &[("version", "1"), ("colour", "red")]).unwrap_err().to_string();
        assert!(err.contains("unknown var(s) colour"), "{err}");
        let err = plan(text, &[("version", "1"), ("env", "qa")]).unwrap_err().to_string();
        assert!(err.contains("one of staging, prod"), "{err}");
        let p = plan(text, &[("version", "1.0")]).unwrap();
        assert_eq!(p.issues[0].title, "1.0 to staging");
        assert_eq!(p.run.title, "t (env=staging, version=1.0)");
    }

    #[test]
    fn conditions_drop_steps_and_keep_order() {
        let text = "[vars.sign]\ntype = \"bool\"\ndefault = \"false\"\n\
            [[steps]]\nid = \"build\"\n\
            [[steps]]\nid = \"sign\"\nneeds = [\"build\"]\ncondition = \"{{sign}}\"\n\
            [[steps]]\nid = \"publish\"\nneeds = [\"sign\"]\n";
        let p = plan(text, &[]).unwrap();
        assert_eq!(keys(&p), vec!["build", "publish"]);
        assert_eq!(edges(&p), vec!["publish->build:blocks"]);
        let p = plan(text, &[("sign", "yes")]).unwrap();
        assert_eq!(edges(&p), vec!["publish->sign:blocks", "sign->build:blocks"]);
    }

    #[test]
    fn loops_fan_out_and_in() {
        let text = "[vars.platforms]\ndefault = \"linux, macOS\"\n\
            [[steps]]\nid = \"prep\"\n\
            [[steps]]\nid = \"build\"\ntitle = \"Build {{item}}\"\nneeds = [\"prep\"]\n[steps.loop]\nover = \"{{platforms}}\"\n\
            [[steps]]\nid = \"ship\"\nneeds = [\"build\"]\n";
        let p = plan(text, &[]).unwrap();
        assert_eq!(keys(&p), vec!["prep", "build-linux", "build-macos", "ship"]);
        assert_eq!(p.issues[2].title, "Build macOS");
        assert_eq!(
            edges(&p),
            vec![
                "build-linux->prep:blocks",
                "build-macos->prep:blocks",
                "ship->build-linux:blocks",
                "ship->build-macos:blocks"
            ]
        );
        let seq = "[[steps]]\nid = \"migrate\"\n[steps.loop]\nrange = \"1..3\"\nsequential = true\n";
        let p = plan(seq, &[]).unwrap();
        assert_eq!(keys(&p), vec!["migrate-1", "migrate-2", "migrate-3"]);
        assert_eq!(p.issues[0].title, "migrate [1]");
        assert_eq!(edges(&p), vec!["migrate-2->migrate-1:blocks", "migrate-3->migrate-2:blocks"]);
    }

    #[test]
    fn loops_over_groups_wire_within_each_iteration() {
        let text = "[[steps]]\nid = \"shard\"\n[steps.loop]\ncount = 2\n\
            [[steps.children]]\nid = \"run\"\n\
            [[steps.children]]\nid = \"report\"\nneeds = [\"run\"]\n\
            [[steps]]\nid = \"merge\"\nneeds = [\"report\"]\n";
        let p = plan(text, &[]).unwrap();
        assert_eq!(
            keys(&p),
            vec!["shard-1", "shard-1.run", "shard-1.report", "shard-2", "shard-2.run", "shard-2.report", "merge"]
        );
        assert_eq!(
            edges(&p),
            vec![
                "merge->shard-1.report:blocks",
                "merge->shard-2.report:blocks",
                "shard-1.report->shard-1.run:blocks",
                "shard-2.report->shard-2.run:blocks"
            ]
        );
        assert_eq!(p.issues[0].role, Role::Group);
        assert_eq!(p.issues[0].issue_type, "epic");
    }

    #[test]
    fn gates_carry_the_steps_prerequisites() {
        let text = "[[steps]]\nid = \"build\"\n\
            [[steps]]\nid = \"deploy\"\nneeds = [\"build\"]\n[steps.gate]\ntype = \"human\"\n";
        let p = plan(text, &[]).unwrap();
        assert_eq!(keys(&p), vec!["build", "deploy", "gate-deploy"]);
        let gate = &p.issues[2];
        assert_eq!((gate.role, gate.issue_type.as_str()), (Role::Gate, "gate"));
        assert_eq!(gate.title, "Approval: deploy");
        assert_eq!(edges(&p), vec!["deploy->build:blocks", "deploy->gate-deploy:blocks", "gate-deploy->build:blocks"]);
    }

    #[test]
    fn waits_for_becomes_a_fan_in_edge() {
        let text = "[[steps]]\nid = \"spawn\"\n\
            [[steps]]\nid = \"collect\"\nneeds = [\"spawn\"]\nwaits_for = \"all-children\"\n";
        let p = plan(text, &[]).unwrap();
        assert_eq!(p.edges.len(), 1);
        let e = &p.edges[0];
        assert_eq!((e.from.as_str(), e.to.as_str(), &e.dep_type), ("collect", "spawn", &DepType::WaitsFor));
        assert_eq!(e.metadata, json!({ "gate": "all-children", "also_blocks": true }));
        // An explicit spawner outside `needs` still waits for the spawner to run.
        let text = "[[steps]]\nid = \"spawn\"\n[[steps]]\nid = \"first\"\nwaits_for = \"any-children-of(spawn)\"\n";
        let p = plan(text, &[]).unwrap();
        assert_eq!(p.edges[0].metadata, json!({ "gate": "any-children", "also_blocks": true }));
    }

    #[test]
    fn gate_values_are_validated_after_rendering() {
        let text = "[vars.wait]\nrequired = true\n[[steps]]\nid = \"bake\"\n[steps.gate]\ntype = \"timer\"\ntimeout = \"{{wait}}\"\n";
        assert!(plan(text, &[("wait", "1x")]).unwrap_err().to_string().contains("invalid duration"));
        let p = plan(text, &[("wait", "2d")]).unwrap();
        assert_eq!(p.issues[1].gate.as_ref().unwrap().timeout.as_deref(), Some("2d"));
    }
}
