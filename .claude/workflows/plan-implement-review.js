export const meta = {
  name: 'plan-implement-review',
  description:
    'Planner turns requirements into a vetted plan, coder implements it step by step, gates run, reviewers report, controller validates, planner triages fixes against a decision ledger to stop circular fixes',
  whenToUse:
    "Implementing requirements (often a bd issue or a `change` playbook run) that need a plan before coding and an independent review loop that must not oscillate. args: { requirements (string or string[]; alias task), issue?, reviewStep?, tier?, model?, effort?, actor?, token?, ttl?, workdir?, logDir?, base?, baseline?, maxRounds?, maxGateFixes?, maxPlanRevisions?, maxAmendments?, planOnly?, plan?, planIssues?, skipImplement?, shadowReview? }. With issue, pass actor (your bd actor) so you can close it later, and run score-issue on it just before closing it. model and effort set the coding agents (implement, gate fixes, review fixes). Before passing reviewStep or any arg beyond these, read the args comment in .claude/workflows/plan-implement-review.js.",
  phases: [
    { title: 'Setup', detail: 'claim the bd issue, worktree + baseline snapshot' },
    { title: 'Plan', detail: 'planner drafts, critic challenges, planner revises' },
    { title: 'Implement', detail: 'coder implements the plan step by step' },
    { title: 'Gate', detail: 'cargo fmt --check, clippy -D warnings, cargo test under the suite lock; coder fixes failures' },
    { title: 'Review', detail: 'independent reviewers examine the diff against the plan and ledger' },
    { title: 'Validate', detail: 'controller tries to refute each finding' },
    { title: 'Triage', detail: 'planner checks approved findings against the decision ledger: fix, drop, amend or escalate' },
    { title: 'Fix', detail: 'coder applies the triaged fixes only' },
    { title: 'Record', detail: 'with reviewStep: file findings as bd issues under it, comment confirmed fixes and drops' },
  ],
}

// ---------- args ----------
// Kept here rather than in meta.whenToUse, which the skill listing truncates at about 1,500 characters.
// - requirements (string or string[]; alias task): what to build.
// - issue: the workflow claims it (pass actor = your bd actor so you can close it later, and token if you already hold
//   it) and renews the lease (ttl, default 30m) between stages.
// - reviewStep (a `change` playbook run's review step): the planner reads the run's requirements and decisions steps as
//   settled input; each finding approved for a fix becomes a bug issue under that step, commented once a later round
//   confirms the fix and returned as confirmedFixes for the caller to close after closing the implement and verify
//   steps (bd refuses to close a child of a blocked step); a filed finding the planner later drops is commented with why
//   and listed in dropped with its bdId, for the caller to close as not a defect; findings still open at the end keep
//   the step from closing. bd is reached through its own workspace discovery (bd -C <main checkout>), never a pinned path.
// - tier (small | standard | critical, the playbook run's): critical adds the security reviewer. It also runs whenever
//   the diff touches bd-server, bd-cli's remote, credentials, tokens, agents, actor, hook or mcp code, CI workflows,
//   Cargo manifests or deny.toml; the engine-invariants reviewer runs whenever it touches bd-core or bd-cli's commands,
//   batch, app or io.
// - model, effort: the coding agents (implement, gate fixes, review fixes); the others keep theirs: claim, heartbeat,
//   setup, gates and bd records on haiku at low effort, escalated once to sonnet at medium when one fails its schema
//   (retry labelled <label>@sonnet); planner, critic, triage and validators at high effort; reviewers the session's.
// - workdir (with base, default main): without it the workflow works in a new worktree under .claude/worktrees/. Every
//   cargo command runs with CARGO_TARGET_DIR=<main checkout>/target/implement-review, shared by runs so a fresh worktree
//   reuses compiled dependencies.
// - baseline (a commit, with workdir): what reviewers diff against instead of the workdir's state at the start.
// - logDir (an absolute directory without '..' or control characters; pass your scratchpad): every agent that runs cargo
//   writes each command's output to its own file, <logDir>/<run>/<label>.log, and reads results only from it, where run
//   is the issue id with [^A-Za-z0-9.-] replaced by '-' (without an issue, 'run-' plus an FNV-1a hash of the
//   requirements and workdir). Without logDir the root is <the setup agent's TMPDIR>/plan-implement-review. Reviewers
//   write to mktemp files there whose instruction names no label or model, so a real reviewer's prompt and its shadows'
//   stay identical. A full cargo test --workspace runs from the worktree through .github/scripts/suite-lock.mjs, which
//   runs full suites one at a time across worktrees (exit 75: the lock was still busy, so rerun the command). The gate's
//   log starts with a `bd-gate: dir=$PWD run=<run>` marker that its agent returns; a report whose marker names another
//   directory or run (or does not parse), or a pass without one, is escalated once and then ends the run as escalated
//   ('gate log contaminated: ...'), never reaching the gate-fix coder.
// - maxRounds, maxGateFixes, maxPlanRevisions, maxAmendments: loop limits (defaults below).
// - planOnly: return the vetted plan without implementing.
// - plan: start from a given plan (e.g. an escalated run's) instead of drafting one; planIssues lists blocking issues
//   already known against it ({ issue, evidence?, suggestion? }), handled as the first critique.
// - skipImplement (needs plan, workdir and baseline): go straight to the gate and review loop over work already in
//   workdir.
// - shadowReview ({ model, effort } or an array of them): also run each reviewer of every review pass at that model and
//   effort with the same prompt (label review:<kind>:r<N>@shadow:<model>-<effort>); its findings are returned as
//   shadowFindings and journaled, but never validated, triaged, fixed or filed: they are data for
//   .github/scripts/reviewer-catch.mjs. Optional here because it adds reviewer cost, but the `change` playbook's
//   implement step requires it.
// Scoring is the caller's last step, not this workflow's: it runs before the caller commits and closes the steps and
// findings, so a score here would miss that work. Run score-issue (passing this result) just before closing the issue,
// or in a `change` run, in its score step.
const A = typeof args === 'string' ? { requirements: args } : { ...args }
const REQS = A.requirements ?? A.task
if (!REQS || (Array.isArray(REQS) && !REQS.length)) {
  throw new Error('args.requirements is required (string, string[], or { requirements, ... }; alias task)')
}
const REQ_TEXT = Array.isArray(REQS) ? REQS.map((r, i) => `${i + 1}. ${r}`).join('\n') : REQS
if (A.plan != null && !['requirements', 'steps', 'decisions'].every((k) => Array.isArray(A.plan[k]))) {
  throw new Error('args.plan must be a plan object with requirements, steps and decisions arrays (as returned by planOnly)')
}
if (A.skipImplement && !(A.plan && A.workdir && A.baseline)) {
  throw new Error('args.skipImplement needs args.plan, args.workdir and args.baseline (the commit the work started from)')
}
if (A.tier && !['small', 'standard', 'critical'].includes(A.tier)) {
  throw new Error(`args.tier must be small, standard or critical, got ${JSON.stringify(A.tier)}`)
}
if (A.baseline && !A.workdir) throw new Error('args.baseline needs args.workdir')
if (A.planIssues != null && (!A.plan || !Array.isArray(A.planIssues) || !A.planIssues.every((i) => typeof i?.issue === 'string'))) {
  throw new Error('args.planIssues needs args.plan and must be an array of { issue, evidence?, suggestion? }')
}
// Opt-in shadow reviewers: each real reviewer also runs at these models and efforts with the same prompt, for
// .github/scripts/reviewer-catch.mjs. Their findings are only returned (shadowFindings) and journaled, never acted on.
// The label review:<kind>:r<N>@shadow:<model>-<effort> must parse back, so the model has no ':' and effort is a known word.
const EFFORTS = ['low', 'medium', 'high', 'xhigh', 'max']
const shadowsOf = (v) => {
  if (v == null) return []
  const list = [v].flat()
  const ok = (o) => typeof o?.model === 'string' && /^[a-z0-9][a-z0-9.-]*$/.test(o.model) && EFFORTS.includes(o.effort)
  if (!list.length || !list.every(ok)) {
    throw new Error(`args.shadowReview must be { model, effort } or an array of them (effort: ${EFFORTS.join('|')}), got ${JSON.stringify(v)}`)
  }
  return list.map((o) => ({ model: o.model, effort: o.effort }))
}
const SHADOWS = shadowsOf(A.shadowReview)
// args.logDir (and the TMPDIR the setup agent reports): an absolute directory, put into prompts and shell commands, so no
// '..' segment and no control character (a newline would split a command). Trailing slashes are dropped.
const logDirOf = (v) => {
  if (v == null) return null
  // Built from char codes, so the source holds no raw control characters: U+0000-U+001F and U+007F.
  const control = new RegExp(`[${String.fromCharCode(0)}-${String.fromCharCode(31)}${String.fromCharCode(127)}]`)
  const ok = typeof v === 'string' && v.startsWith('/') && !v.split('/').includes('..') && !control.test(v)
  if (!ok) throw new Error(`args.logDir must be an absolute directory without '..' or control characters (your scratchpad), got ${JSON.stringify(v)}`)
  return v.replace(/\/+$/, '') || '/'
}
const LOG_DIR = logDirOf(A.logDir)
const TASK = `Requirements:\n${REQ_TEXT}` + (A.issue ? `\n\n(bd issue: ${A.issue}; read it with \`bd show ${A.issue}\`)` : '')
const BASE = A.base || 'main'
const MAX_ROUNDS = A.maxRounds ?? 3
const MAX_GATE_FIXES = A.maxGateFixes ?? 2
const MAX_PLAN_REVISIONS = A.maxPlanRevisions ?? 2
// Each amendment overturns a settled decision; past this many the plan is not holding and a human should look.
const MAX_AMENDMENTS = A.maxAmendments ?? 2
// Longer than any single stage: the script has no clock, so it can only renew between agents.
const TTL = A.ttl || '30m'

// Model and effort for the coding agents (implement, gate fixes, review fixes); the others keep theirs: mechanical
// agents (claim, heartbeat, setup, gates, bd records) on haiku at low effort (sonnet at medium on a schema failure; see
// ops()), planner, critic, triage and validators high, reviewers the session's.
const CODER_OPTS = { ...(A.model ? { model: A.model } : {}), ...(A.effort ? { effort: A.effort } : {}) }

// Mechanical agents (claim, heartbeat, bd:root, setup, gate, bd records) only run commands and report output: haiku at low
// effort (AGENTS.md). One that fails its schema (null, or a result its caller rejects) is escalated once to sonnet, never
// retried at the same level; the retry's label gets @sonnet so calibrate and trace-run still read its role.
const OPS = { model: 'haiku', effort: 'low' }
const OPS_ESCALATED = { model: 'sonnet', effort: 'medium' }
// prompt is a string or a function of the attempt's label (so each attempt can name its own log file); valid gets the
// report and that label.
async function ops(prompt, opts, valid = Boolean) {
  const text = (l) => (typeof prompt === 'function' ? prompt(l) : prompt)
  const r = await agent(text(opts.label), { ...opts, ...OPS })
  if (valid(r, opts.label)) return r
  log(`${opts.label} failed its schema on ${OPS.model}; escalating to ${OPS_ESCALATED.model}`)
  const retryLabel = `${opts.label}@${OPS_ESCALATED.model}`
  const again = await agent(
    `${text(retryLabel)}\n\nAn earlier attempt at this may have run some of these commands before failing: check their effects first and do not repeat one that already took effect.`,
    { ...opts, ...OPS_ESCALATED, label: retryLabel },
  )
  return valid(again, retryLabel) ? again : null
}

// ---------- schemas ----------
const CLAIM = {
  type: 'object',
  properties: {
    ok: { type: 'boolean' },
    token: { type: 'string', description: 'lease.token from the claim' },
    actor: { type: 'string', description: 'lease.holder from the claim' },
    root: { type: 'string', description: 'absolute path of the main checkout, where bd finds its workspace' },
    error: { type: 'string' },
  },
  required: ['ok'],
}
const BD_ROOT = { type: 'object', properties: { root: { type: 'string' } }, required: ['root'] }
const HEARTBEAT = {
  type: 'object',
  properties: { ok: { type: 'boolean' }, error: { type: 'string' } },
  required: ['ok'],
}
const LEASE = {
  type: 'object',
  properties: {
    has: { type: 'boolean', description: 'false when bd show prints no lease' },
    holder: { type: 'string', description: 'lease.holder, verbatim' },
    token: { type: 'string', description: 'lease.token, verbatim' },
  },
  required: ['has'],
}
const SETUP = {
  type: 'object',
  properties: {
    workdir: { type: 'string' },
    branch: { type: 'string' },
    baseline: { type: 'string' },
    target: { type: 'string', description: 'absolute CARGO_TARGET_DIR shared by workflow runs' },
    tmpdir: { type: 'string', description: 'output of printf %s "${TMPDIR:-/tmp}", when asked for' },
  },
  required: ['workdir', 'baseline', 'target'],
}
const RECORD = {
  type: 'object',
  properties: {
    ok: { type: 'boolean' },
    filed: {
      type: 'array',
      items: { type: 'object', properties: { id: { type: 'string' }, bdId: { type: 'string' } }, required: ['id', 'bdId'] },
    },
    followedUp: {
      type: 'array',
      items: { type: 'object', properties: { id: { type: 'string' }, bdId: { type: 'string' } }, required: ['id', 'bdId'] },
    },
    error: { type: 'string' },
  },
  required: ['ok'],
}
const PLAN = {
  type: 'object',
  properties: {
    summary: { type: 'string', description: 'the approach in a few sentences' },
    requirements: {
      type: 'array',
      description: 'the requirements restated as testable acceptance criteria, ids R1, R2, ...',
      items: {
        type: 'object',
        properties: { id: { type: 'string' }, text: { type: 'string' }, acceptance: { type: 'string', description: 'how a reviewer can tell it is met' } },
        required: ['id', 'text', 'acceptance'],
      },
    },
    steps: {
      type: 'array',
      description: 'ordered implementation steps, ids S1, S2, ...; each leaves the workspace passing its checks',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          title: { type: 'string' },
          covers: { type: 'array', items: { type: 'string' }, description: 'requirement ids' },
          files: { type: 'array', items: { type: 'string' } },
          approach: { type: 'string', description: 'what to change and how, naming modules, functions, types and commands' },
          tests: { type: 'string', description: 'tests that prove this step (unit tests in the crate, end-to-end ones in crates/bd/tests/)' },
        },
        required: ['id', 'title', 'covers', 'approach', 'tests'],
      },
    },
    decisions: {
      type: 'array',
      description: 'design choices a reviewer might question later, with why; these become settled in the ledger',
      items: {
        type: 'object',
        properties: { decision: { type: 'string' }, rationale: { type: 'string' }, files: { type: 'array', items: { type: 'string' } } },
        required: ['decision', 'rationale'],
      },
    },
    outOfScope: { type: 'array', items: { type: 'string' } },
    risks: { type: 'array', items: { type: 'string' } },
  },
  required: ['summary', 'requirements', 'steps', 'decisions'],
}
const CRITIQUE = {
  type: 'object',
  properties: {
    approved: { type: 'boolean', description: 'true when no blocking issue remains' },
    issues: {
      type: 'array',
      items: {
        type: 'object',
        properties: {
          blocking: { type: 'boolean' },
          issue: { type: 'string' },
          evidence: { type: 'string', description: 'code, rule or requirement that shows it' },
          suggestion: { type: 'string' },
        },
        required: ['blocking', 'issue', 'evidence'],
      },
    },
  },
  required: ['approved', 'issues'],
}
const CODER = {
  type: 'object',
  properties: {
    summary: { type: 'string' },
    filesChanged: { type: 'array', items: { type: 'string' } },
    deviations: { type: 'string', description: 'where and why the code departs from the plan' },
    notes: { type: 'string', description: 'decisions, open questions, anything the reviewer should know' },
  },
  required: ['summary', 'filesChanged'],
}
const FIXED = {
  type: 'object',
  properties: {
    summary: { type: 'string' },
    filesChanged: { type: 'array', items: { type: 'string' } },
    changes: {
      type: 'array',
      description: 'one entry per finding fixed',
      items: {
        type: 'object',
        properties: { id: { type: 'string' }, change: { type: 'string', description: 'what was changed and why it fixes the finding' } },
        required: ['id', 'change'],
      },
    },
    notes: { type: 'string' },
  },
  required: ['summary', 'filesChanged', 'changes'],
}
const GATE = {
  type: 'object',
  properties: {
    passed: { type: 'boolean' },
    failures: {
      type: 'array',
      items: {
        type: 'object',
        properties: { command: { type: 'string' }, excerpt: { type: 'string' } },
        required: ['command', 'excerpt'],
      },
    },
    snapshot: { type: 'string', description: 'tree id from the snapshot command' },
    changedFiles: { type: 'array', items: { type: 'string' } },
    log: { type: 'string', description: 'the log file the gate command wrote' },
    marker: { type: 'string', description: 'the first line of that log (head -1), verbatim' },
  },
  required: ['passed', 'failures', 'snapshot', 'changedFiles'],
}
const FINDING = {
  type: 'object',
  properties: {
    file: { type: 'string' },
    line: { type: 'number' },
    severity: { type: 'string', enum: ['blocker', 'serious', 'minor', 'nit'] },
    category: { type: 'string', description: 'correctness | requirement | invariant | security | convention | portability | test-coverage | docs | perf | other' },
    claim: { type: 'string', description: 'what is wrong, one or two sentences' },
    evidence: { type: 'string', description: 'concrete failure scenario or quoted code / rule' },
    suggestedFix: { type: 'string' },
    reverses: { type: 'array', items: { type: 'string' }, description: 'ledger ids this finding would undo, if any' },
  },
  required: ['file', 'severity', 'category', 'claim', 'evidence'],
}
const REVIEW = {
  type: 'object',
  properties: {
    findings: { type: 'array', items: FINDING },
    resolved: {
      type: 'array',
      description: 'focused re-review only: one entry per previously approved finding',
      items: {
        type: 'object',
        properties: { id: { type: 'string' }, resolved: { type: 'boolean' }, why: { type: 'string' } },
        required: ['id', 'resolved'],
      },
    },
  },
  required: ['findings'],
}
const VERDICT = {
  type: 'object',
  properties: {
    valid: { type: 'boolean', description: 'the defect is real in the current code' },
    blocking: { type: 'boolean', description: 'valid AND must be fixed before this is done' },
    reasoning: { type: 'string' },
    conflictsWith: { type: 'array', items: { type: 'string' }, description: 'ledger ids a fix would undo or contradict' },
    fixInstruction: { type: 'string', description: 'precise, minimal instruction for the coder if blocking' },
  },
  required: ['valid', 'blocking', 'reasoning'],
}
const TRIAGE = {
  type: 'object',
  properties: {
    items: {
      type: 'array',
      description: 'one entry per open finding',
      items: {
        type: 'object',
        properties: {
          id: { type: 'string' },
          action: {
            type: 'string',
            enum: ['fix', 'drop', 'amend', 'escalate'],
            description:
              'fix: consistent with the ledger; drop: would reverse a settled decision without new evidence, or repeats a settled/rejected finding; ' +
              'amend: a settled decision is itself the defect and must be superseded; escalate: needs a human',
          },
          instruction: { type: 'string', description: 'fix/amend: precise minimal instruction that keeps every other ledger decision intact' },
          preserve: { type: 'array', items: { type: 'string' }, description: 'ledger ids the fix must not disturb' },
          supersedes: { type: 'array', items: { type: 'string' }, description: 'amend: ledger ids this overturns' },
          newDecision: { type: 'string', description: 'amend: the decision that replaces them' },
          reason: { type: 'string' },
        },
        required: ['id', 'action', 'reason'],
      },
    },
    converging: { type: 'boolean', description: 'false if the loop is going in circles or the open set is not shrinking for a structural reason' },
    concern: { type: 'string', description: 'when not converging: the underlying tension a human must decide' },
  },
  required: ['items', 'converging'],
}

// ---------- shared prompt pieces ----------
const SNAPSHOT_CMD =
  'tmp=$(mktemp) && cp "$(git rev-parse --git-path index)" "$tmp" && GIT_INDEX_FILE="$tmp" git add -A && GIT_INDEX_FILE="$tmp" git write-tree; rm -f "$tmp"'
// The main checkout (not a worktree): bd finds its workspace there, whether a remote server or a local database.
const ROOT_CMD = 'dirname "$(git rev-parse --path-format=absolute --git-common-dir)"'
// One target dir for every run, so a fresh worktree reuses compiled dependencies instead of a cold build.
const TARGET_CMD = `echo "$(${ROOT_CMD})/target/implement-review"`
let TARGET = ''
let DIR = ''
const inDir = (dir) =>
  `Work ONLY in the directory ${dir} (use absolute paths; do not cd elsewhere). Do not commit, push, or touch git branches/index. ` +
  `Run every cargo command with CARGO_TARGET_DIR=${TARGET} set. ` +
  `Do not change .claude/settings.json, and do not create or change skills, MCP definitions, hooks or executable bits (AGENTS.md gates these on the user's approval); mention the need in notes instead.`
const readOnly = (dir) => `Read the code in ${dir} (absolute paths). You are read-only: do not edit files, commit, or touch git state.`
const fmtFinding = (f) =>
  `[${f.id}] ${f.severity} ${f.category} — ${f.file}${f.line ? ':' + f.line : ''}\n  Claim: ${f.claim}\n  Evidence: ${f.evidence}` +
  (f.fixInstruction ? `\n  Fix: ${f.fixInstruction}` : f.suggestedFix ? `\n  Suggested: ${f.suggestedFix}` : '') +
  (f.conflictsWith?.length ? `\n  Conflicts with: ${f.conflictsWith.join(', ')}` : '')
const fmtPlan = (p) =>
  `Plan: ${p.summary}\n\nRequirements:\n` +
  p.requirements.map((r) => `- ${r.id}: ${r.text}\n    accept: ${r.acceptance}`).join('\n') +
  `\n\nSteps:\n` +
  p.steps
    .map((s) => `- ${s.id} ${s.title} [${(s.covers || []).join(', ')}]${s.files?.length ? ` (${s.files.join(', ')})` : ''}\n    ${s.approach}\n    tests: ${s.tests}`)
    .join('\n') +
  (p.outOfScope?.length ? `\n\nOut of scope:\n${p.outOfScope.map((o) => `- ${o}`).join('\n')}` : '')
const fmtDecisions = (p) => p.decisions.map((d) => `- ${d.decision} (why: ${d.rationale})`).join('\n')
const fmtBlockers = (bs) => bs.map((b) => `- ${b.issue}\n    evidence: ${b.evidence}${b.suggestion ? `\n    suggestion: ${b.suggestion}` : ''}`).join('\n')

// ---------- logs ----------
// 32-bit FNV-1a of a string, as 8 hex digits (the hash followUpKey computes inline).
const fnv1a = (s) => {
  let h = 0x811c9dc5
  for (const c of s) h = Math.imul(h ^ c.codePointAt(0), 0x01000193) >>> 0
  return h.toString(16).padStart(8, '0')
}
// Per-run logs: every agent that runs cargo writes each command's output to its own file, <LOG_ROOT>/<RUN_ID>/<label>.log
// (reviewers to a mktemp file there, so a real reviewer and its shadows keep identical prompts), and reads results only
// from it, so parallel runs and parallel agents never read each other's logs. Full suites (cargo test --workspace) go
// through the suite lock (.github/scripts/suite-lock.mjs), which runs them one at a time across worktrees.
const safeId = (s) => String(s).replace(/[^A-Za-z0-9.-]/g, '-')
// A path as one POSIX single-quoted shell word; unlike shq, nothing is collapsed or cut.
const shPath = (s) => `'${String(s).replaceAll("'", `'\\''`)}'`
const RUN_ID = A.issue ? safeId(A.issue) : `run-${fnv1a(`${REQ_TEXT}\n${A.workdir ?? ''}`)}`
// args.logDir, or <the setup agent's TMPDIR>/plan-implement-review once setup reports it.
let LOG_ROOT = LOG_DIR ?? ''
const tmpRootOf = (t) => {
  try {
    return logDirOf(t) ?? '/tmp'
  } catch {
    return '/tmp'
  }
}
const logFile = (label) => `${LOG_ROOT}/${RUN_ID}/${safeId(label)}.log`
// The full suite under the lock, or unlocked in a worktree on an older base without the script.
const SUITE_TEST = `if [ -f .github/scripts/suite-lock.mjs ]; then node .github/scripts/suite-lock.mjs --run ${RUN_ID} -- cargo test --workspace --locked; else cargo test --workspace --locked; fi`
const lockText =
  `The full suite (cargo test --workspace) runs from the worktree as \`${SUITE_TEST}\` with CARGO_TARGET_DIR set; it waits while another worktree runs one, ` +
  `and exit 75 means the lock was still busy and nothing ran: run the same command again. ` +
  `cargo fmt, cargo clippy and single-crate tests (\`cargo test -p <crate> [filter]\`) run without the lock.`
const logRule = (label) => {
  const file = shPath(logFile(label))
  return (
    `Logs: write the full output of every cargo command you run to ${file} only. ` +
    `Run \`mkdir -p ${shPath(`${LOG_ROOT}/${RUN_ID}`)}\` first, then overwrite the file per command with ` +
    `\`<command> > ${file} 2>&1; echo "exit=$?"\` (the shell may be zsh, which has no $PIPESTATUS, so do not pipe a command into tee). ` +
    `Read results only from that file (grep, tail), never from another log. ${lockText}`
  )
}
// A reviewer's rule names neither its label nor its model, so a real reviewer and its shadows get byte-identical prompts
// (reviewer-catch.mjs pairs them by prompt hash); mktemp still gives each its own file.
const reviewLogRule = (kind, round) =>
  `Logs: if you run a cargo command, give its output a file of your own (outside the worktree): ` +
  `\`mkdir -p ${shPath(`${LOG_ROOT}/${RUN_ID}`)} && f=$(mktemp ${shPath(`${LOG_ROOT}/${RUN_ID}/review-${safeId(kind)}-r${round}.XXXXXX`)}) && <command> > "$f" 2>&1; echo "log=$f exit=$?"\`, ` +
  `then read results only from the file it printed, never from another log. ${lockText}`
// The gate's shell writes `bd-gate: dir=$PWD run=<RUN_ID>` as the first line of its own log, and the gate agent returns
// that line as "marker". A marker naming another directory or run, or one that does not parse, means the agent read
// another run's log (or a stale one), so its verdict says nothing about this worktree; so does a pass with no marker at
// all. Such a report never counts as a pass and never reaches the gate-fix coder. A failure without a marker (the agent
// stopped before the log was read back) stays an ordinary failure.
const markerOf = (line) => {
  const m = /^bd-gate: dir=(.*) run=(\S*)$/.exec(String(line ?? '').trim())
  return m ? { dir: m[1], run: m[2] } : null
}
// macOS reports /var/... as /private/var/... from $PWD in some shells; a trailing slash is not another directory.
const normDir = (p) => p.replace(/\/+$/, '').replace(/^\/private(?=\/)/, '')
const sameDir = (a, b) => !!a && !!b && normDir(a) === normDir(b)
const contamination = (r, dir, run) => {
  const marker = String(r.marker ?? '').trim()
  if (!marker) return r.passed ? { dir: '', run: '', marker: '' } : null
  const m = markerOf(marker)
  if (m && sameDir(m.dir, dir) && m.run === run) return null
  return { dir: m?.dir ?? '', run: m?.run ?? '', marker }
}
const contaminatedReason = (g, dir, run) =>
  `gate log contaminated: ${g.marker ? `its marker says "${g.marker}"` : 'no bd-gate marker although the gate passed'}, expected dir=${dir} run=${run} (log ${g.log})`

// Areas whose AGENTS.md rules are easy to break without a failing test.
const touchesEngine = (files) => files.some((f) => /^crates\/bd-core\//.test(f) || /^crates\/bd-cli\/src\/(commands|batch|app|io)/.test(f))
const touchesSecurity = (files) =>
  files.some(
    (f) =>
      /^crates\/bd-server\//.test(f) ||
      /^crates\/bd-cli\/src\/(remote|credentials|tokens|agents|actor|hook|mcp)/.test(f) ||
      /^(\.github\/workflows\/|Cargo\.(toml|lock)$|crates\/[^/]+\/Cargo\.toml$|deny\.toml$)/.test(f),
  )

const dedupe = (fs) => {
  const seen = new Set()
  return fs.filter((f) => {
    const k = `${f.file}:${f.line ?? ''}:${f.category}`
    return seen.has(k) ? false : (seen.add(k), true)
  })
}

// ---------- decision ledger ----------
// Every settled choice (plan decisions, applied fixes, gate fixes, amendments) with why. Reviewers,
// the controller and the triage planner all see it, so a later round cannot quietly undo an earlier one.
const ledger = []
let nextDecision = 1
function settle(entry) {
  const e = { id: `D${nextDecision++}`, files: [], ...entry }
  ledger.push(e)
  return e
}
const live = () => ledger.filter((e) => !e.supersededBy)
const fmtLedger = (entries = live()) =>
  entries.length
    ? entries
        .map(
          (e) =>
            `[${e.id}] (${e.source}${e.round != null ? ` r${e.round}` : ''}${e.about ? `, for ${e.about}` : ''}) ${e.decision}` +
            (e.rationale ? `\n    why: ${e.rationale}` : '') +
            (e.files?.length ? `\n    files: ${e.files.join(', ')}` : ''),
        )
        .join('\n')
    : '(empty)'
// Findings already decided, so reviewers do not raise them again in other words: rejected or dropped ones, and valid ones
// left out of this change (filed as follow-ups or noted as nits), which would otherwise be filed again when reworded.
const settledFindings = []
// Shadow reviewers' results (args.shadowReview): data only, kept out of dedupe, validate, triage and record.
const shadowFindings = []
const fmtSettled = () =>
  settledFindings.length ? settledFindings.map((f) => `- [${f.id}] ${f.file}: ${f.claim} — ${f.outcome}: ${f.why}`).join('\n') : '(none)'
function noteSettled(checked) {
  for (const v of checked) {
    if (!v.valid) settledFindings.push({ ...v, outcome: 'rejected', why: v.reasoning })
    else if (!v.blocking)
      settledFindings.push({ ...v, outcome: v.severity === 'nit' ? 'noted as a nit' : 'filed as a follow-up', why: 'valid but not blocking; left out of this change' })
  }
}
const ledgerBlock = () =>
  `DECISION LEDGER (settled; do not reverse an entry without new, concrete evidence that the entry itself causes a defect; ` +
  `if a finding would undo one, list its id in "reverses"):\n${fmtLedger()}\n\n` +
  `ALREADY DECIDED FINDINGS (do not raise again, even reworded):\n${fmtSettled()}`

// ---------- Setup ----------
phase('Setup')
// Claim the issue under a lease. Every later bd call pins this actor and token, because workflow agents may not
// resolve to the same bd actor as each other or as the launching session. bd runs with -C <main checkout> so agents
// in a worktree reach the same workspace, which bd discovers itself: never a pinned --db path.
let lease = null
if (A.issue) {
  const c = await ops(
    `Claim bd issue ${A.issue}. Find the main checkout with: ${ROOT_CMD}\n` +
      `Then run: bd -C <that path> claim ${A.issue} --ttl ${TTL} --json` +
      (A.actor ? ` --actor "${A.actor}"` : '') +
      (A.token ? ` --token ${A.token}` : '') +
      `\nReturn ok=true with lease.token, lease.holder (as actor) and that path (as root) if it succeeded; otherwise ok=false and the error. ` +
      `Do not retry with --force or --take-over.`,
    { label: 'claim', phase: 'Setup', schema: CLAIM },
  )
  if (!c || !c.ok) return { status: 'escalated', reason: `could not claim ${A.issue}: ${c ? c.error : 'claim agent failed'}` }
  lease = { issue: A.issue, token: c.token, actor: c.actor, root: c.root }
  log(`Claimed ${A.issue} as ${c.actor} (token ${c.token}, ttl ${TTL})`)
}

// Renew between stages. A failed heartbeat is escalated once (it is idempotent under the token); if that fails too, the
// lease itself decides: an agent that mangles the command (a dropped --actor reads as "now held by <the same actor>")
// must not end the run, or resume would replay the cached failure. Someone else holding the issue now: stop.
let beats = 0
async function renew(phase) {
  if (!lease) return
  const label = `heartbeat:${beats++}`
  let failed = null
  const h = await ops(
    `Run exactly: bd -C ${lease.root} heartbeat ${lease.issue} --token ${lease.token} --ttl ${TTL} --actor "${lease.actor}" --json\n` +
      `Return ok=true if it succeeded, otherwise ok=false with the error output. Do nothing else.`,
    { label, phase, schema: HEARTBEAT },
    (r) => r?.ok === true || ((failed = r ?? failed), false),
  )
  if (h) return
  const l = await ops(
    `Run exactly: bd -C ${lease.root} show ${lease.issue} --json\n` +
      `Return the "lease" object's holder and token exactly as printed (has=false if there is no lease). Do nothing else.`,
    { label: `${label}:lease`, phase, schema: LEASE },
  )
  if (l?.has && l.holder === lease.actor && String(l.token) === String(lease.token)) {
    log(`Heartbeat on ${lease.issue} failed (${failed?.error ?? 'heartbeat agent failed'}) but the lease is still ${l.holder}'s, token ${l.token}; continuing.`)
    return
  }
  const now = l ? (l.has ? `held by ${l.holder}, token ${l.token}` : 'no lease') : 'lease check failed'
  throw new Error(
    `Lost the lease on ${lease.issue} (${failed?.error ?? 'heartbeat agent failed'}; ${now}); stopping. Work so far is in ${DIR || 'no worktree yet'}.`,
  )
}

// Where bd records go (reviewStep): the lease's checkout and actor, or the main checkout found here.
let bdTarget = lease && { root: lease.root, actor: lease.actor }
if (A.reviewStep && !bdTarget) {
  const r = await ops(`Run exactly: ${ROOT_CMD} and return its output as root.`, { label: 'bd:root', phase: 'Setup', schema: BD_ROOT })
  if (!r) throw new Error('Could not find the main checkout for bd')
  bdTarget = { root: r.root, actor: A.actor }
}
const bdFlags = () => ` -C ${bdTarget.root}` + (bdTarget.actor ? ` --actor "${bdTarget.actor}"` : '')

// Setup runs only git commands here (dependencies build in the gate), so it gets no log file. Without args.logDir the log
// root is under the agent's TMPDIR, which only an agent's shell can expand, so setup reports it as tmpdir.
const setupPrompt = () =>
  (A.workdir && A.baseline
    ? `In ${A.workdir}, run \`git rev-parse ${A.baseline}^{tree}\` and return its output as "baseline" (and workdir="${A.workdir}").\n` +
      `Then run this there and return its output as "target":\n${TARGET_CMD}`
    : A.workdir
      ? `In ${A.workdir}, run this snapshot command and return its output as "baseline" (and workdir="${A.workdir}"):\n${SNAPSHOT_CMD}\n` +
        `Then run this there and return its output as "target":\n${TARGET_CMD}`
      : `Create an isolated git worktree for this work:\n${TASK}\n\n` +
        `1. Pick a short kebab-case slug. From the repo root run: git worktree add .claude/worktrees/<slug> -b <slug> ${BASE}\n` +
        `2. In that worktree run this and capture the tree id:\n${SNAPSHOT_CMD}\n` +
        `3. In that worktree run this and capture the path:\n${TARGET_CMD}\n` +
        `Return the absolute worktree path as workdir, the branch, the tree id as baseline, and the path as target.`) +
  (LOG_DIR ? '' : `\nAlso run \`printf %s "\${TMPDIR:-/tmp}"\` and return its output as tmpdir.`)
const setup = await ops(setupPrompt, { label: 'setup', phase: 'Setup', schema: SETUP }, (r) => !!(r?.workdir && r.baseline && r.target))
if (!setup?.workdir || !setup.baseline || !setup.target) return { status: 'escalated', reason: 'setup agent failed', lease }
DIR = setup.workdir
TARGET = setup.target
LOG_ROOT ||= `${tmpRootOf(setup.tmpdir).replace(/\/$/, '')}/plan-implement-review`
log(`Working in ${DIR} (baseline ${setup.baseline.slice(0, 8)})`)
log(`Logs in ${LOG_ROOT}/${RUN_ID}`)
if (SHADOWS.length) log(`Shadow reviewers: ${SHADOWS.map((o) => `${o.model}/${o.effort}`).join(', ')}`)

// ---------- Plan ----------
phase('Plan')
await renew('Plan')
const runContext = A.reviewStep
  ? `\n\nThis work is part of a \`change\` playbook run: \`bd${bdFlags()} show ${A.reviewStep}\` is its review step; its parent is the run. ` +
    `Read the run's requirements and decisions steps (and their decision children): their acceptance and design fields are settled input. ` +
    `Plan within them; a needed departure goes in "risks", not silently into the plan.`
  : ''
const planIntro =
  `${readOnly(DIR)}\nYou are the planner. Turn these requirements into an implementation plan for a coder who will follow it step by step, ` +
  `then independent reviewers who will check the result against it.\n\n${TASK}${runContext}\n\n` +
  `Read the code the change touches first; name real files, functions and types. Restate each requirement as a testable acceptance criterion. ` +
  `Order steps so each leaves the workspace building and tested. Follow AGENTS.md Conventions & Patterns (Store::write and events in one transaction, ` +
  `graph::recompute seeds, the lease invariant, claim overrides, io.rs for I/O, cli::access classes, minimal indexes, fixed query plans) and say in the step how. ` +
  `Keep Linux, macOS and Windows building. Name the docs/ or CONTRIBUTING.md page each step updates. ` +
  `Record in "decisions" every design choice a reviewer could reasonably push back on (alternatives you rejected and why): ` +
  `those become settled and stop the review loop from flip-flopping. Keep scope to the requirements; list tempting extras as outOfScope.`
const badPlan = (p) => !p.steps?.length || !p.requirements?.length
let plan = A.plan ?? (await agent(planIntro, { label: 'planner:draft', phase: 'Plan', effort: 'high', schema: PLAN }))
if (!plan || badPlan(plan)) return { status: 'escalated', reason: 'planner failed', workdir: DIR, lease }
if (A.plan) log(`Starting from the given plan (${plan.steps.length} step(s))`)
// Issues already known against a given plan stand in for the first critique.
let pending = A.planIssues?.length ? A.planIssues.map((i) => ({ evidence: '', ...i, blocking: true })) : null
let corrections = []
const critiques = []
// A plan whose work is already done (skipImplement) is not critiqued again.
for (let rev = 0; !A.skipImplement; rev++) {
  let blockers
  if (pending) {
    blockers = pending
    pending = null
  } else {
    const crit = await agent(
      `${readOnly(DIR)}\nYou are the plan critic. Try to break this plan before any code is written.\n\n${TASK}${runContext}\n\n${fmtPlan(plan)}\n\n` +
        `Plan decisions:\n${fmtDecisions(plan)}\n\n` +
        (critiques.length
          ? `Earlier critique rounds and how the planner answered (do not re-raise an issue the planner resolved; ` +
            `only raise it again if the revision did not actually address it):\n${critiques.map((c, i) => `Round ${i + 1}:\n${c}`).join('\n')}\n\n`
          : '') +
        `Blocking issues only: a requirement not covered or covered wrongly, a step that would not work against the actual code, ` +
        `a step order that leaves the build or tests broken, a violated AGENTS.md convention, missing tests for new behavior, code that would not ` +
        `build on macOS or Windows, or a decision whose rationale is wrong. Preferences and alternatives that are merely different are not blocking. ` +
        `approved=true if nothing blocks.`,
      { label: `planner:critic:${rev}`, phase: 'Plan', effort: 'high', schema: CRITIQUE },
    )
    if (!crit) log(`Plan critic ${rev} failed; accepting the plan as is`)
    blockers = (crit?.issues || []).filter((i) => i.blocking)
  }
  if (!blockers.length) break
  if (rev >= MAX_PLAN_REVISIONS) {
    // A large plan keeps drawing new small corrections; when each one comes with a concrete fix,
    // apply them once without another critique, and settle them so reviewers hold the code to them.
    const unfixable = blockers.filter((b) => !b.suggestion)
    if (unfixable.length) {
      return {
        status: 'escalated',
        reason: `plan still has ${unfixable.length} blocking issue(s) without a suggested fix after ${MAX_PLAN_REVISIONS} revision(s)`,
        workdir: DIR,
        plan,
        blockers,
        lease,
      }
    }
    log(`Plan: applying ${blockers.length} suggested correction(s) without another critique`)
    const final = await agent(
      `${planIntro}\n\nYour previous plan:\n${fmtPlan(plan)}\n\nIts decisions:\n${fmtDecisions(plan)}\n\n` +
        `Verified blocking issues, each with its fix:\n${fmtBlockers(blockers)}\n\n` +
        `Return the full plan with exactly these corrections applied (adopt each suggestion; if the code shows one is wrong, ` +
        `make the smallest change that resolves the issue and record why in "decisions"). Change nothing else.`,
      { label: `planner:final:${rev}`, phase: 'Plan', effort: 'high', schema: PLAN },
    )
    if (!final || badPlan(final)) return { status: 'escalated', reason: 'planner failed to apply the final corrections', workdir: DIR, plan, blockers, lease }
    plan = final
    corrections = blockers
    break
  }
  log(`Plan critic: ${blockers.length} blocking issue(s); revising`)
  critiques.push(blockers.map((b) => `- ${b.issue} (evidence: ${b.evidence})`).join('\n'))
  const revised = await agent(
    `${planIntro}\n\nYour previous plan:\n${fmtPlan(plan)}\n\nIts decisions:\n${fmtDecisions(plan)}\n\n` +
      `The critic raised these blocking issues:\n${fmtBlockers(blockers)}\n\n` +
      `Return the full revised plan. Address each issue, or keep your choice and strengthen its rationale in "decisions" if the critic is wrong. ` +
      `Do not reintroduce anything an earlier critique round made you remove:\n${critiques.slice(0, -1).join('\n') || '(no earlier rounds)'}`,
    { label: `planner:revise:${rev + 1}`, phase: 'Plan', effort: 'high', schema: PLAN },
  )
  if (!revised || badPlan(revised)) return { status: 'escalated', reason: 'planner failed to revise the plan', workdir: DIR, plan, blockers, lease }
  plan = revised
}
for (const d of plan.decisions) settle({ source: 'plan', decision: d.decision, rationale: d.rationale, files: d.files || [] })
for (const b of corrections) settle({ source: 'critique', decision: b.suggestion, rationale: b.issue })
log(`Plan: ${plan.steps.length} step(s) covering ${plan.requirements.length} requirement(s); ${ledger.length} decision(s) settled`)
if (A.planOnly) return { status: 'planned', workdir: DIR, branch: setup.branch, baseline: setup.baseline, plan, ledger, lease }

// ---------- gate ----------
// The CI gates from .github/workflows/ci.yml as one shell line: a marker first (contamination), then fmt, clippy and the
// full suite (under the suite lock), each run even if an earlier one fails, all into the attempt's own log; then the
// exit[...] lines. gateRerunCmd runs the suite again when the lock was still busy (exit[test]=75), appending to the log.
const gateCmd = (label) => {
  const file = shPath(logFile(label))
  return (
    `mkdir -p ${shPath(`${LOG_ROOT}/${RUN_ID}`)} && cd ${shPath(DIR)} && { echo "bd-gate: dir=$PWD run=${RUN_ID}"; ` +
    `export CARGO_TARGET_DIR=${shPath(TARGET)}; cargo fmt --all --check; echo "exit[fmt]=$?"; ` +
    `cargo clippy --workspace --all-targets --locked -- -D warnings; echo "exit[clippy]=$?"; ` +
    `${SUITE_TEST}; echo "exit[test]=$?"; } > ${file} 2>&1; grep '^exit\\[' ${file}`
  )
}
const gateRerunCmd = (label) => {
  const file = shPath(logFile(label))
  return (
    `cd ${shPath(DIR)} && { export CARGO_TARGET_DIR=${shPath(TARGET)}; ${SUITE_TEST}; echo "exit[test]=$?"; } >> ${file} 2>&1; ` +
    `grep '^exit\\[test\\]' ${file} | tail -1`
  )
}
const gatePrompt = (label) => {
  const file = shPath(logFile(label))
  return (
    `${inDir(DIR)}\nRun the CI gates there (cargo fmt check, clippy -D warnings, the full test suite under the suite lock): ` +
    `in the foreground, with the Bash tool's longest timeout (600000 ms), run exactly:\n${gateCmd(label)}\n` +
    `While the last exit[test] line is exit[test]=75 (another worktree held the suite lock and the tests did not run), run this, as often as it takes:\n` +
    `${gateRerunCmd(label)}\n` +
    `Running the checks changes nothing, so run them even if an earlier attempt already did. ` +
    `Read the results only from ${file} (grep, tail), never from another log.\n` +
    `Do NOT fix anything. For each failing command, return a trimmed excerpt with the real errors (max ~60 lines each; ` +
    `for tests, the failing test names and their panic messages).\n` +
    `Return ${file} as "log", and the output of \`head -1 ${file}\` verbatim as "marker".\n` +
    `Then run this and return its output as "snapshot":\n${SNAPSHOT_CMD}\n` +
    `Then run \`git diff --name-only ${setup.baseline} <snapshot>\` and return the list as changedFiles.`
  )
}
// A gate report that contradicts itself, or whose log is contaminated, counts as a failed gate agent and is escalated
// once. If the last attempt is still contaminated, gate() returns a { contaminated } marker instead of null; the marker
// reflects only that attempt.
const gate = async (label) => {
  let dirty = null
  const r = await ops(gatePrompt, { label, phase: 'Gate', schema: GATE }, (x, l) => {
    dirty = null
    if (!(x?.snapshot && x.passed !== x.failures.length > 0)) return false
    const c = contamination(x, DIR, RUN_ID)
    if (c) {
      dirty = { contaminated: true, ...c, log: logFile(l) }
      log(`gate ${l}: log contaminated (${c.marker || 'no marker'})`)
    }
    return !c
  })
  return r ?? dirty
}

const gateFixPrompt = (g, label) =>
  `${inDir(DIR)}\nThe automated checks fail for this work:\n${TASK}\n\n` +
  g.failures.map((f) => `### ${f.command}\n${f.excerpt}`).join('\n\n') +
  `\n\nFix the causes (not the checks: no #[allow(...)] to silence clippy, no #[ignore] or weakened assertions, no --no-verify). ` +
  `Run \`cargo fmt --all\` after editing. Keep the change minimal and on-task.\n\n` +
  `${ledgerBlock()}\n\nDo not undo a ledger decision to make a check pass; if one makes the checks unpassable, say so in notes and stop.\n\n` +
  logRule(label)

// Run the gate; on failure send the coder back up to MAX_GATE_FIXES times. Gate fixes are settled too,
// and must not undo earlier decisions to get green. Returns null if the gate agent itself failed, and the { contaminated }
// marker if its log was another run's (never sent to the gate-fix coder).
async function gateUntilGreen(tag, round) {
  phase('Gate')
  await renew('Gate')
  let g = await gate(`gate:${tag}`)
  for (let i = 1; g && !g.passed && !g.contaminated && i <= MAX_GATE_FIXES; i++) {
    log(`Gate failed (${g.failures.map((f) => f.command).join(', ')}); coder fix ${i}/${MAX_GATE_FIXES}`)
    await renew('Gate')
    const label = `coder:gate-fix:${tag}:${i}`
    const r = await agent(gateFixPrompt(g, label), { label, phase: 'Gate', schema: CODER, ...CODER_OPTS })
    if (r) settle({ source: 'gate', round, decision: r.summary, rationale: `make ${g.failures.map((f) => f.command).join(', ')} pass`, files: r.filesChanged })
    await renew('Gate')
    g = await gate(`gate:${tag}:${i}`)
  }
  return g
}

// ---------- bd record (reviewStep) ----------
// The review step of a `change` playbook run holds the review-fix loop's record: one bug issue per finding the planner
// sends to the coder (or escalates), commented when a focused re-review confirms the fix or a later triage drops it. The
// step is blocked (by verify, then implement) while this runs, and bd refuses to close a child of a blocked step, so
// confirmed findings are returned as confirmedFixes for the caller to close once implement and verify are closed.
// bd refuses to close the step while any is open.
const confirmedFixes = []
// A follow-up's key: FNV-1a of its file and claim. Finding ids restart at F1 each run, so an id alone would match another
// run's follow-up on the same step; the claim is the same on resume (cached agents) and differs between findings.
const followUpKey = (step, f) => {
  let h = 0x811c9dc5
  for (const c of `${f.file}\n${f.claim}`) h = Math.imul(h ^ c.codePointAt(0), 0x01000193) >>> 0
  return `followup:${step}/${h.toString(16).padStart(8, '0')}`
}
// A title as one POSIX single-quoted shell word: reviewer-written claims can hold $(...), backticks or !, and nothing in
// single quotes is expanded. One line, at most 200 characters, as bd titles are.
const shq = (s) => `'${s.replace(/\s+/g, ' ').trim().slice(0, 200).replaceAll("'", `'\\''`)}'`
async function record(round, { file = [], close = [], drop = [], followUps = [], note = '' }) {
  if (!A.reviewStep) return
  const step = A.reviewStep
  const text = (t) => `\n  Text:\n${t}`
  const lines = [
    ...file.map(
      (f) =>
        `FILE ${f.id}: bd create ${shq(`Finding ${f.id}: ${f.claim}`)} -t bug --parent ${step} ` +
        `-l severity:${f.severity} -d <Text> --json${bdFlags()}\n  then add { id: "${f.id}", bdId: <the new issue's id> } to filed.` +
        text(fmtFinding(f)),
    ),
    ...close.map(
      (f) =>
        `CONFIRM: bd comment add ${f.bdId} ` +
        `${JSON.stringify(`Fix confirmed by focused re-review in round ${round} (tree ${g.snapshot.slice(0, 8)}); close it once implement and verify are closed`)}${bdFlags()}`,
    ),
    ...drop.map(
      (x) =>
        `DROP: bd comment add ${x.f.bdId} <Text>${bdFlags()}` +
        text(`Dropped by planner triage in round ${round}: ${x.d.reason}\nClose it as not a defect once implement and verify are closed, unless a person disagrees.`),
    ),
    // The label keys a follow-up to its step and finding, so a rerun finds it instead of filing it again.
    ...followUps.map(
      (f) =>
        `FOLLOW-UP ${f.id}: bd create ${shq(f.claim)} -t task -p 3 --dep discovered-from:${step} ` +
        `-l ${followUpKey(step, f)} -d <Text> --json${bdFlags()}\n  then add { id: "${f.id}", bdId: <the new issue's id> } to followedUp.` +
        text(fmtFinding(f)),
    ),
    ...(note ? [`COMMENT: bd comment add ${step} <Text>${bdFlags()}` + text(note)] : []),
  ]
  if (!lines.length) return
  const r = await ops(
    `Record review results in bd. Run each command below, in order, exactly as given except that <Text> is the "Text" under it, ` +
      `passed verbatim as one shell argument (use a quoted heredoc, e.g. "$(cat <<'EOF' ... EOF)", so quotes and backticks survive). ` +
      `An earlier attempt may have run some of them: before each FILE, look for the issue with ` +
      `\`bd list --all --parent ${step} --search "Finding <id>:" --json${bdFlags()}\` and reuse its id instead of creating a duplicate; ` +
      `likewise before each FOLLOW-UP, with \`bd list --all -l <its followup: label> --json${bdFlags()}\`; ` +
      `a CONFIRM or DROP already commented counts as done. Do nothing else.\n\n${lines.join('\n\n')}\n\n` +
      `Return ok=true, filed (one entry per FILE) and followedUp (one entry per FOLLOW-UP) if every command succeeded; otherwise ok=false and the error. ` +
      `A failed FOLLOW-UP is the exception: leave it out of followedUp and keep going; it does not make ok false.`,
    { label: `record:r${round}`, phase: 'Record', schema: RECORD },
  )
  if (!r || !r.ok || (r.filed || []).length !== file.length) throw new Error(`Could not record review round ${round} on ${step} (${r ? r.error : 'record agent failed'}); stopping. Work so far is in ${DIR}.`)
  for (const m of r.filed || []) {
    const f = file.find((x) => x.id === m.id)
    if (f) f.bdId = m.bdId
  }
  // Follow-ups are optional work, so a missing one is logged rather than stopping the run.
  const followed = new Map((r.followedUp || []).map((m) => [m.id, m.bdId]))
  for (const f of followUps) f.bdId = followed.get(f.id)
  const missed = followUps.filter((f) => !f.bdId).map((f) => f.id)
  if (missed.length) log(`Round ${round}: follow-ups not confirmed filed on ${step}: ${missed.join(', ')}`)
  confirmedFixes.push(...close.map((f) => f.bdId))
}

// Rejected findings, nits, drops and unvalidated findings stay on the step as a comment; the reasoning is the evidence.
const roundNote = (round, { verdicts, blocking, resolved, stillOpen, dropped = [], escalated = [] }) =>
  [
    `plan-implement-review round ${round}: ${verdicts.length} new finding(s), ${blocking.length} approved` +
      (resolved.length ? `, fixes confirmed for ${resolved.map((f) => f.bdId || f.id).join(', ')}` : '') +
      (stillOpen.length ? `, still open: ${stillOpen.map((f) => f.bdId || f.id).join(', ')}` : '') +
      (dropped.length ? `, dropped by triage: ${dropped.map((x) => x.f.bdId || x.f.id).join(', ')}` : '') +
      (escalated.length ? `, escalated: ${escalated.map((f) => f.bdId || f.id).join(', ')}` : '') +
      (blocking.length || stillOpen.length ? '' : ' (nothing left to fix)'),
    ...verdicts.filter((v) => v.unvalidated).map((v) => `- unvalidated ${v.id} (${v.file}): ${v.claim}`),
    ...verdicts.filter((v) => !v.unvalidated && !v.valid).map((v) => `- rejected ${v.id} (${v.file}): ${v.claim} — ${v.reasoning}`),
    ...verdicts.filter((v) => v.valid && !v.blocking && v.severity === 'nit').map((v) => `- nit ${v.id} (${v.file}): ${v.claim}`),
    ...dropped.filter((x) => !x.f.bdId).map((x) => `- dropped ${x.f.id} (${x.f.file}): ${x.f.claim} — ${x.d.reason}`),
  ].join('\n')

// ---------- review ----------
// Reviewers run read-only. Full review on round 0; focused re-review afterwards. Shadow reviewers (args.shadowReview)
// start in the same parallel() call with the same prompt; their results go to shadowFindings and only the real ones return.
// Each kind's prompt ends with its log rule (reviewLogRule), which names no label or model, so the prompts stay identical.
async function review(round, snap, files, prevSnap, approved) {
  const focused = round > 0
  const scope = focused
    ? `FOCUSED RE-REVIEW. The coder just fixed these approved findings:\n\n${approved.map(fmtFinding).join('\n\n')}\n\n` +
      `Fix diff: \`git diff ${prevSnap} ${snap}\` (run in ${DIR}). For EACH finding above, return a "resolved" entry (id, resolved, why). ` +
      `In "findings", report ONLY new problems introduced by the fix diff; do not re-review untouched code.`
    : `FULL REVIEW of the change for:\n${TASK}\n\n${fmtPlan(plan)}\n\nDiff: \`git diff ${setup.baseline} ${snap}\` (run in ${DIR}); read surrounding code as needed. ` +
      `Look for correctness bugs, violations of the Conventions & Patterns in AGENTS.md, code that would not build ` +
      `on macOS or Windows (cfg-gated paths), docs/ or CONTRIBUTING.md pages the change makes wrong, and missing tests for new behavior.`
  const common =
    `${scope}\n\n${ledgerBlock()}\n\n` +
    `You are read-only: do not edit files. Report only defects you can back with a concrete failure scenario or a specific rule; ` +
    `no style preferences, and no re-litigating a ledger decision unless you show it causes a defect. ` +
    `Severity: blocker/serious = must fix before merge; minor/nit = optional. Return an empty list if clean.`

  const reviewer = (name, focus, extra = {}) => ({ name, prompt: `${focus ? `${common}\n${focus}` : common}\n\n${reviewLogRule(name, round)}`, extra })
  const reviewers = [reviewer('code', '')]
  if (!focused) {
    reviewers.push(
      reviewer(
        'requirements',
        `Focus on the requirements: for each of ${plan.requirements.map((r) => r.id).join(', ')}, check its acceptance criterion ` +
          `against the code and tests. Report each unmet or partly met one as category "requirement", naming the requirement id in the claim. ` +
          `Also report work outside the plan's scope that changes behavior.`,
      ),
    )
  }
  if (touchesEngine(files)) {
    reviewers.push(
      reviewer(
        'invariants',
        `Focus on the engine invariants in AGENTS.md: mutations only through Store::write with events emitted in the same ` +
          `transaction; graph::recompute with the right seeds when readiness can change; the lease invariant; claim-ending paths calling ` +
          `check_claim_override before any force refusal; Policy checks on token-dependent overrides; no new indexes or ANALYZE; ` +
          `fixed query plans for per-issue walks (crates/bd-core/tests/plans.rs); I/O only through io.rs; cli::access classes for new commands.`,
      ),
    )
  }
  if (A.tier === 'critical' || touchesSecurity(files)) {
    reviewers.push(
      reviewer(
        'security',
        `Focus on security: authentication and authorization (token roles, actor binding, admin/local checks), ` +
          `untrusted input from clients, providers and servers (escaping via agents/show.rs, size and time limits), secrets never ` +
          `logged or shown, file permissions, the agent-asset approval gate, new dependencies and supply chain, and CI and release configuration.`,
      ),
    )
  }
  const real = reviewers.map((s) => () => agent(s.prompt, { label: `review:${s.name}:r${round}`, phase: 'Review', schema: REVIEW, ...s.extra }))
  const shadows = reviewers.flatMap((s) => SHADOWS.map((o) => ({ s, o, label: `review:${s.name}:r${round}@shadow:${o.model}-${o.effort}` })))
  const shadow = shadows.map(({ s, o, label }) => () => agent(s.prompt, { label, phase: 'Review', schema: REVIEW, ...s.extra, model: o.model, effort: o.effort }))
  const out = await parallel([...real, ...shadow])
  shadows.forEach(({ s, o, label }, i) =>
    shadowFindings.push({ round, kind: s.name, model: o.model, effort: o.effort, label, findings: out[real.length + i]?.findings ?? null }),
  )
  return out.slice(0, real.length)
}

// Controller: each finding gets an independent skeptic who must try to refute it.
let nextId = 1
function validate(findings, tag, snap) {
  const ids = findings.map(() => `F${nextId++}`)
  return pipeline(findings, (f) => {
    const id = ids[findings.indexOf(f)]
    const label = `validate:${tag}:${id}`
    return agent(
      `You are the controller validating a code-review finding. Try to REFUTE it by reading the actual code in ${DIR} ` +
        `(current state = \`git diff ${setup.baseline} ${snap}\` on top of ${BASE}). Do not edit files.\n\n` +
        `${TASK}\n\nFinding:\n${fmtFinding({ ...f, id })}${f.reverses?.length ? `\n  Reviewer says it reverses: ${f.reverses.join(', ')}` : ''}\n\n` +
        `${ledgerBlock()}\n\n` +
        `valid=true only if the defect really exists now. blocking=true only if valid AND it is a correctness bug, an unmet requirement, ` +
        `a security issue, a broken rule from AGENTS.md Conventions & Patterns, a build break on Linux/macOS/Windows, ` +
        `or missing tests for new behavior. Nits, preferences, speculative risks and pre-existing issues outside the diff are not blocking. ` +
        `If fixing it would undo or contradict a ledger entry, list that id in conflictsWith; such a finding is valid only if the entry ` +
        `itself causes a concrete defect. A finding that restates an already decided one is valid=false. If uncertain, valid=false. ` +
        `If blocking, write a precise minimal fixInstruction.\n\n${logRule(label)}`,
      { label, phase: 'Validate', effort: 'high', schema: VERDICT },
    ).then((v) => (v ? { ...f, id, ...v } : { ...f, id, unvalidated: true }))
  })
}

// Files approved findings landed on, per round: a file in several rounds is where the loop is circling.
const hot = new Map()
const markHot = (fs, round) => fs.forEach((f) => hot.set(f.file, new Set([...(hot.get(f.file) || []), round])))
const fmtHot = () =>
  [...hot]
    .filter(([, rs]) => rs.size > 1)
    .map(([file, rs]) => `- ${file}: approved findings in rounds ${[...rs].join(', ')}`)
    .join('\n') || '(none)'
let amendments = 0

// Planner triage: decide each approved finding against the ledger before any code changes.
const triage = (open, round, history) =>
  agent(
    `${readOnly(DIR)}\nYou are the planner, triaging approved review findings for round ${round} before the coder touches anything. ` +
      `Your job is to keep the loop converging: no fix may undo an earlier fix or plan decision unless that decision is itself the defect.\n\n` +
      `${TASK}\n\n${fmtPlan(plan)}\n\nDECISION LEDGER (live entries):\n${fmtLedger()}\n\n` +
      `SUPERSEDED ENTRIES (overturned earlier; must not come back):\n${fmtLedger(ledger.filter((e) => e.supersededBy))}\n\n` +
      `ALREADY DECIDED FINDINGS:\n${fmtSettled()}\n\n` +
      `Files with approved findings in more than one round (likely circling):\n${fmtHot()}\n\n` +
      `Open-finding counts by round so far: ${history.openCounts.join(' → ') || '(first round)'}; amendments used: ${amendments}/${MAX_AMENDMENTS}.\n\n` +
      `Approved findings now open:\n${open.map(fmtFinding).join('\n\n')}\n\n` +
      `For each finding, read the code and choose:\n` +
      `- fix: it does not conflict with any live ledger entry. Give a minimal instruction and list in "preserve" the entries near it the coder must keep intact.\n` +
      `- drop: it would reverse a live entry without new evidence that the entry causes a defect, or it is an earlier finding coming back reworded, ` +
      `or fixing it would bring back a superseded entry. Say which.\n` +
      `- amend: a live entry is itself the cause of a real defect. List it in "supersedes", state the newDecision, and give the instruction. ` +
      `Never amend an entry that is itself an amendment, and never restore a superseded entry: that is a cycle, escalate instead.\n` +
      `- escalate: two requirements or decisions are in real tension, or no fix exists that keeps the ledger consistent.\n` +
      `Two findings that pull the same code in opposite directions: pick one consistent resolution, fix that one, drop the other. ` +
      `converging=false if the same files keep drawing findings and the cause is structural (the plan, not the fixes); then say the tension in "concern".`,
    { label: `planner:triage:r${round}`, phase: 'Triage', effort: 'high', schema: TRIAGE },
  )

// ---------- Implement ----------
const done = []
const stepCoderPrompt = (step, label) =>
  `${inDir(DIR)}\nYou are the coder. Implement step ${step.id} of this plan, and only that step; earlier steps are already in the worktree.\n\n` +
  `${TASK}\n\n${fmtPlan(plan)}\n\n` +
  `Plan decisions (settled, follow them):\n${fmtLedger()}\n\n` +
  (done.length ? `Done so far:\n${done.map((d) => `- ${d.id}: ${d.summary}${d.deviations ? ` (deviated: ${d.deviations})` : ''}`).join('\n')}\n\n` : '') +
  `NOW: ${step.id} ${step.title}\n${step.approach}\nTests: ${step.tests}\n\n` +
  `Follow AGENTS.md, especially Conventions & Patterns. Add the tests the step names (unit tests in the crate, end-to-end ones in ` +
  `crates/bd/tests/), update the docs/ or CONTRIBUTING.md page the change affects, and run \`cargo fmt --all\`. ` +
  `Run the relevant tests (\`cargo test -p <crate> <filter>\`) before returning. If the plan is wrong for the actual code, ` +
  `do the smallest correct thing and explain it in "deviations".\n\n` +
  logRule(label)
if (A.skipImplement) log(`Skipping Implement: reviewing the work already in ${DIR} against ${A.baseline}`)
else phase('Implement')
for (const step of A.skipImplement ? [] : plan.steps) {
  await renew('Implement')
  const label = `coder:${step.id}`
  const r = await agent(stepCoderPrompt(step, label), { label, phase: 'Implement', schema: CODER, ...CODER_OPTS })
  if (!r) return { status: 'escalated', reason: `coder did not finish ${step.id}`, workdir: DIR, plan, done, ledger, lease }
  done.push({ id: step.id, ...r })
  if (r.deviations) settle({ source: 'deviation', about: step.id, decision: r.deviations, rationale: 'plan did not fit the actual code', files: r.filesChanged })
  log(`${step.id} done: ${r.summary}`)
}

// ---------- Gate → Review → Validate → Triage → Fix loop ----------
const history = { approved: [], rejected: [], nonBlocking: [], unvalidated: [], dropped: [], amended: [], openCounts: [] }
const result = (status, extra) => ({
  confirmedFixes,
  status,
  workdir: DIR,
  branch: setup.branch,
  baseline: setup.baseline,
  plan,
  done,
  ledger,
  lease,
  ...history,
  ...(SHADOWS.length ? { shadowFindings } : {}),
  ...extra,
})

let g = await gateUntilGreen('impl', 0)
if (!g) return result('escalated', { reason: 'gate agent failed' })
if (g.contaminated) return result('escalated', { reason: contaminatedReason(g, DIR, RUN_ID) })
if (!g.passed) return result('escalated', { reason: 'automated checks still failing after coder fixes', failures: g.failures })

let prevSnap = setup.baseline
let open = [] // findings fixed last round, awaiting confirmation

// One review pass: review, validate, and move `open` to the findings still unresolved plus the newly approved ones.
async function reviewPass(round) {
  phase('Review')
  await renew('Review')
  const prevOpen = open
  const reviews = (await review(round, g.snapshot, g.changedFiles, prevSnap, open)).filter(Boolean)
  if (!reviews.length) return null

  const unresolvedIds = new Set(
    reviews
      .flatMap((r) => r.resolved || [])
      .filter((r) => !r.resolved)
      .map((r) => r.id),
  )
  const stillOpen = prevOpen.filter((f) => unresolvedIds.has(f.id))
  const fresh = dedupe(reviews.flatMap((r) => r.findings))
  log(`Round ${round}: ${fresh.length} new finding(s), ${stillOpen.length} previously fixed still open`)
  if (fresh.length) {
    phase('Validate')
    await renew('Validate')
  }
  const verdicts = (await validate(fresh, `r${round}`, g.snapshot)).filter(Boolean)
  const unvalidated = verdicts.filter((v) => v.unvalidated)
  if (unvalidated.length) log(`Round ${round}: ${unvalidated.length} finding(s) could not be validated; reported, not fixed`)
  history.unvalidated.push(...unvalidated)
  const checked = verdicts.filter((v) => !v.unvalidated)
  const blocking = checked.filter((v) => v.valid && v.blocking).map((v) => ({ ...v, round }))
  history.rejected.push(...checked.filter((v) => !v.valid))
  noteSettled(checked)
  history.nonBlocking.push(...checked.filter((v) => v.valid && !v.blocking))
  history.approved.push(...blocking)
  open = [...stillOpen, ...blocking]
  return { verdicts, blocking, stillOpen, resolved: prevOpen.filter((f) => !stillOpen.includes(f)) }
}

const followUpsOf = (verdicts) => verdicts.filter((v) => !v.unvalidated && v.valid && !v.blocking && v.severity !== 'nit')
const unfiled = (fs) => fs.filter((f) => !f.bdId)
const fixPrompt = (work, label) =>
  `${inDir(DIR)}\nThe planner approved these fixes for:\n${TASK}\n\n` +
  work
    .map((x) => `${fmtFinding(x.f)}\n  DO: ${x.d.instruction || x.f.fixInstruction}` + (x.d.preserve?.length ? `\n  KEEP INTACT: ${x.d.preserve.join(', ')}` : ''))
    .join('\n\n') +
  `\n\nDECISION LEDGER (live; your fix must leave every entry true):\n${fmtLedger()}\n\n` +
  `Fix ONLY these findings, minimally, as instructed. Do not refactor, restyle, or address anything else, even if you notice it ` +
  `(mention it in notes instead). If an instruction cannot be done without breaking a ledger entry, skip that finding and say why in notes. ` +
  `Add or adjust tests that prove each fix. Run \`cargo fmt --all\` and the affected tests before returning. ` +
  `Return one "changes" entry per finding you fixed.\n\n` +
  logRule(label)

for (let round = 0; round <= MAX_ROUNDS; round++) {
  const pass = await reviewPass(round)
  if (!pass) return result('escalated', { reason: `every reviewer failed in round ${round}`, open })
  const recordRound = (extra = {}) =>
    record(round, {
      close: pass.resolved.filter((f) => f.bdId),
      followUps: followUpsOf(pass.verdicts),
      note: roundNote(round, { ...pass, ...extra }),
      ...extra,
    })

  history.openCounts.push(open.length)
  if (!open.length) {
    await recordRound()
    return result('done', { rounds: round, snapshot: g.snapshot })
  }
  if (round === MAX_ROUNDS) {
    await recordRound({ file: unfiled(open), escalated: open })
    break
  }
  const c = history.openCounts
  if (round >= 2 && c[round] >= c[round - 1] && c[round - 1] >= c[round - 2]) {
    await recordRound({ file: unfiled(open), escalated: open })
    return result('escalated', { reason: `open findings not shrinking (${c.join(' → ')})`, open, hotspots: fmtHot() })
  }
  markHot(open, round)

  phase('Triage')
  await renew('Triage')
  const t = await triage(open, round, history)
  if (!t) {
    await recordRound({ file: unfiled(open), escalated: open })
    return result('escalated', { reason: 'triage agent failed', open })
  }
  const byId = new Map(t.items.map((i) => [i.id, i]))
  // A finding the triage left out is fixed as the controller wrote it.
  const decided = open.map((f) => ({ f, d: byId.get(f.id) || { action: 'fix', reason: 'not triaged', instruction: f.fixInstruction } }))

  // Cycle guards the planner cannot talk its way past.
  for (const x of decided.filter((x) => x.d.action === 'amend')) {
    const targets = (x.d.supersedes || []).map((id) => ledger.find((e) => e.id === id)).filter(Boolean)
    const superseded = targets.filter((e) => e.supersededBy).map((e) => e.id)
    const amends = targets.filter((e) => e.source === 'amend').map((e) => e.id)
    const why = !targets.length
      ? 'amend names no ledger entry'
      : superseded.length
        ? `${superseded.join(', ')} already superseded`
        : amends.length
          ? `would overturn an amendment (${amends.join(', ')}): flip-flop`
          : amendments >= MAX_AMENDMENTS
            ? `amendment budget (${MAX_AMENDMENTS}) spent`
            : null
    if (why) x.d = { ...x.d, action: 'escalate', reason: `${x.d.reason} [guard: ${why}]` }
  }
  const escalate = decided.filter((x) => x.d.action === 'escalate')
  if (escalate.length || t.converging === false) {
    await recordRound({ file: unfiled(open), escalated: open })
    return result('escalated', {
      reason: escalate.length ? `planner escalated ${escalate.map((x) => x.f.id).join(', ')}` : 'review loop is not converging',
      concern: t.concern,
      open,
      triage: t.items,
      hotspots: fmtHot(),
    })
  }
  const drops = decided.filter((x) => x.d.action === 'drop')
  for (const x of drops) {
    history.dropped.push({ ...x.f, triage: x.d.reason })
    settledFindings.push({ ...x.f, outcome: 'dropped', why: x.d.reason })
  }
  const work = decided.filter((x) => x.d.action === 'fix' || x.d.action === 'amend')
  for (const x of work.filter((x) => x.d.action === 'amend')) {
    amendments++
    const e = settle({ source: 'amend', round, about: x.f.id, decision: x.d.newDecision || x.d.instruction, rationale: x.d.reason, files: [x.f.file] })
    for (const id of x.d.supersedes) ledger.find((l) => l.id === id).supersededBy = e.id
    history.amended.push({ finding: x.f.id, supersedes: x.d.supersedes, by: e.id })
    log(`Amended ${x.d.supersedes.join(', ')} → ${e.id} for ${x.f.id}`)
  }
  await recordRound({ file: unfiled(work.map((x) => x.f)), drop: drops.filter((x) => x.f.bdId), dropped: drops })
  if (!work.length) {
    log(`Round ${round}: all ${open.length} finding(s) dropped by triage`)
    return result('done', { rounds: round, snapshot: g.snapshot })
  }

  phase('Fix')
  await renew('Fix')
  log(`Fixing ${work.length} finding(s): ${work.map((x) => x.f.id).join(', ')}; dropped ${drops.length}`)
  const fixLabel = `coder:fix:r${round + 1}`
  const fixed = await agent(fixPrompt(work, fixLabel), { label: fixLabel, phase: 'Fix', schema: FIXED, ...CODER_OPTS })
  if (!fixed) return result('escalated', { reason: 'fix coder failed', open: work.map((x) => x.f) })
  for (const ch of fixed.changes) {
    const f = open.find((o) => o.id === ch.id)
    settle({ source: 'fix', round: round + 1, about: ch.id, decision: ch.change, rationale: f ? f.claim : '', files: f ? [f.file] : fixed.filesChanged })
  }
  const fixedIds = new Set(fixed.changes.map((ch) => ch.id))
  const skipped = work.filter((x) => !fixedIds.has(x.f.id))
  if (skipped.length) {
    return result('escalated', {
      reason: `coder could not fix ${skipped.map((x) => x.f.id).join(', ')} without breaking the ledger`,
      notes: fixed.notes,
      open: work.map((x) => x.f),
    })
  }

  open = work.map((x) => x.f)
  prevSnap = g.snapshot
  g = await gateUntilGreen(`r${round + 1}`, round + 1)
  if (!g) return result('escalated', { reason: 'gate agent failed', open })
  if (g.contaminated) return result('escalated', { reason: contaminatedReason(g, DIR, RUN_ID), open })
  if (!g.passed) return result('escalated', { reason: 'checks failing after fixing findings', failures: g.failures, open })
}

return result('escalated', { reason: `blocking findings remain after ${MAX_ROUNDS} fix rounds`, open, hotspots: fmtHot() })
