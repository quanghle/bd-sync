//! Rules for the help text, checked on the help as written (`authored_text`),
//! never on rendered help, which shows ambient values: environment variables
//! and defaults.

use clap::{Arg, Command, CommandFactory, Parser};

use super::*;

fn cli() -> Command {
    let mut cmd = Cli::command();
    cmd.build();
    cmd
}

/// Every visible command with its path ("bd dep add"), the root first; hidden
/// commands and clap's own `help` are left out.
fn visible(root: &Command) -> Vec<(String, &Command)> {
    fn walk<'a>(cmd: &'a Command, path: String, out: &mut Vec<(String, &'a Command)>) {
        for sub in cmd.get_subcommands() {
            if sub.is_hide_set() || sub.get_name() == "help" {
                continue;
            }
            let sub_path = format!("{path} {}", sub.get_name());
            out.push((sub_path.clone(), sub));
            walk(sub, sub_path, out);
        }
    }
    let mut out = vec![(root.get_name().to_string(), root)];
    walk(root, root.get_name().to_string(), &mut out);
    out
}

/// A command's visible arguments, without clap's own --help and --version.
fn visible_args(cmd: &Command) -> impl Iterator<Item = &Arg> {
    cmd.get_arguments().filter(|a| !a.is_hide_set() && !matches!(a.get_id().as_str(), "help" | "version"))
}

fn help(arg: &Arg) -> String {
    arg.get_help().map(ToString::to_string).unwrap_or_default()
}

/// The help text written for a command and its visible arguments.
fn authored_text(cmd: &Command) -> String {
    let mut parts: Vec<String> = [
        cmd.get_about(),
        cmd.get_long_about(),
        cmd.get_before_help(),
        cmd.get_before_long_help(),
        cmd.get_after_help(),
        cmd.get_after_long_help(),
    ]
    .into_iter()
    .flatten()
    .map(ToString::to_string)
    .collect();
    for arg in visible_args(cmd) {
        parts.extend(arg.get_help().map(ToString::to_string));
        parts.extend(arg.get_long_help().map(ToString::to_string));
        parts.extend(arg.get_value_names().into_iter().flatten().map(ToString::to_string));
        parts.extend(arg.get_possible_values().iter().filter_map(|v| v.get_help()).map(ToString::to_string));
    }
    parts.join("\n")
}

fn command<'a>(root: &'a Command, path: &str) -> &'a Command {
    path.split_whitespace()
        .skip(1)
        .fold(root, |cmd, name| cmd.find_subcommand(name).unwrap_or_else(|| panic!("no command `{path}`")))
}

fn flag<'a>(root: &'a Command, path: &str, long: &str) -> &'a Arg {
    command(root, path)
        .get_arguments()
        .find(|a| a.get_long() == Some(long))
        .unwrap_or_else(|| panic!("no flag `{path} --{long}`"))
}

/// Capitalized (or a literal in backticks, or an environment variable), with no trailing period.
fn styled(text: &str) -> bool {
    let first = text.chars().next();
    first.is_some_and(|c| c.is_uppercase() || c == '`' || c == '$') && !text.ends_with('.')
}

#[test]
fn clap_debug_assert() {
    Cli::command().debug_assert();
}

#[test]
fn help_summaries_are_short_capitalized_without_period() {
    let root = cli();
    for (path, cmd) in visible(&root) {
        let about = cmd.get_about().map(ToString::to_string).unwrap_or_default();
        assert!(styled(&about), "`{path}`: summary {about:?} must be capitalized, without a trailing period");
        assert!(about.chars().count() <= 80, "`{path}`: summary {about:?} is longer than 80 characters");
        assert!(!about.contains('\n'), "`{path}`: summary {about:?} must be one line");
    }
}

#[test]
fn every_visible_argument_has_help() {
    let root = cli();
    for (path, cmd) in visible(&root) {
        for arg in visible_args(cmd) {
            let id = arg.get_id();
            let text = help(arg);
            assert!(styled(&text), "`{path}` {id}: help {text:?} must be capitalized, without a trailing period");
            if arg.is_global_set() {
                assert!(text.chars().count() <= 80, "`{path}` {id}: global help {text:?} is longer than 80 characters");
            }
            let values = arg.get_possible_values();
            // Clap's own bool parser offers true/false with no help; the flag's help says what each means.
            if values.iter().map(|v| v.get_name()).eq(["true", "false"]) {
                continue;
            }
            // A flag that hides its values names them in its own help (the global --log-format).
            if arg.is_hide_possible_values_set() {
                assert!(
                    values.iter().all(|v| text.contains(v.get_name())),
                    "`{path}` {id}: hides its possible values but its help does not name them all"
                );
                continue;
            }
            for value in values.iter().filter(|value| !value.is_hide_set()) {
                let name = value.get_name();
                let value_help = value.get_help().map(ToString::to_string).unwrap_or_default();
                assert!(!value_help.trim().is_empty(), "`{path}` {id}={name}: possible value has no help");
                assert!(
                    styled(&value_help),
                    "`{path}` {id}={name}: help {value_help:?} must be capitalized, without a trailing period"
                );
            }
        }
    }
}

const PRONOUNS: [&str; 10] = ["me", "my", "we", "us", "our", "ours", "you", "your", "yours", "yourself"];

fn pronouns_in(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_alphanumeric())
        .map(str::to_lowercase)
        .filter(|w| PRONOUNS.contains(&w.as_str()))
        .collect()
}

#[test]
fn help_uses_no_first_or_second_person_pronouns() {
    let root = cli();
    for (path, cmd) in visible(&root) {
        let found = pronouns_in(&authored_text(cmd));
        assert!(found.is_empty(), "`{path}`: help uses {found:?}; use impersonal or imperative phrasing");
    }
}

#[test]
fn sign_in_help_names_no_products() {
    let root = cli();
    for (path, cmd) in visible(&root) {
        let text = authored_text(cmd).to_lowercase();
        for product in ["github.com", "apple", "chatgpt", "claude.ai", "google"] {
            assert!(!text.contains(product), "`{path}`: help names {product:?}");
        }
        if path.starts_with("bd remote") || path.starts_with("bd serve token") {
            assert!(!text.contains("github:"), "`{path}`: examples must not use a github: account");
        }
    }
}

#[test]
fn help_lint_ignores_ambient_values() {
    let mut demo =
        Command::new("demo").arg(Arg::new("db").long("db").help("Database file").default_value("/home/me/apple"));
    let rendered = demo.render_long_help().to_string();
    assert!(rendered.contains("me") && rendered.contains("apple"), "{rendered}");
    let text = authored_text(&demo);
    assert!(pronouns_in(&text).is_empty() && !text.contains("apple"), "{text}");

    let root = cli();
    for (path, cmd) in visible(&root) {
        let text = authored_text(cmd);
        assert!(!text.contains("[env:") && !text.contains("[default:"), "`{path}`: {text}");
    }
}

#[test]
fn shared_flags_are_worded_alike() {
    let root = cli();
    let same = |flags: &[(&str, &str)], expected: &str| {
        for (path, long) in flags {
            assert_eq!(help(flag(&root, path, long)), expected, "`{path} --{long}`");
        }
    };
    same(&[("bd claim", "ttl"), ("bd heartbeat", "ttl"), ("bd close", "ttl")], TTL_HELP);
    same(&[("bd heartbeat", "token"), ("bd close", "token"), ("bd release", "token")], FENCING_TOKEN_HELP);
    same(
        &[
            ("bd list", "limit"),
            ("bd query", "limit"),
            ("bd ready", "limit"),
            ("bd stale", "limit"),
            ("bd blocked", "limit"),
            ("bd playbook runs", "limit"),
            ("bd find-duplicates", "limit"),
        ],
        LIMIT_HELP,
    );
    assert_eq!(
        help(flag(&root, "bd claim", "if-revision")),
        format!("{}{IF_REVISION_BY_ID_SUFFIX}", help(flag(&root, "bd update", "if-revision")))
    );

    let (mut dry_runs, mut take_overs) = (0, 0);
    for (path, cmd) in visible(&root) {
        let find = |long| visible_args(cmd).find(|a| a.get_long() == Some(long));
        if let Some(dry_run) = find("dry-run") {
            dry_runs += 1;
            assert_eq!(help(dry_run), DRY_RUN_HELP, "`{path} --dry-run`");
        }
        let Some(take_over) = find("take-over") else { continue };
        take_overs += 1;
        let text = help(take_over);
        assert!(text.contains(TAKE_OVER_CLAUSE), "`{path} --take-over`: {text:?}");
        let suffix = if path == "bd import" { IMPORT_TAKE_OVER_SUFFIX } else { TAKE_OVER_SUFFIX };
        assert!(text.ends_with(suffix), "`{path} --take-over` must end with {suffix:?}: {text:?}");
        if let Some(force) = find("force") {
            let text = help(force);
            assert!(
                text.ends_with(FORCE_CLAIM_SUFFIX),
                "`{path} --force` must end with {FORCE_CLAIM_SUFFIX:?}: {text:?}"
            );
        }
    }
    assert!(dry_runs >= 8 && take_overs >= 8, "{dry_runs} --dry-run, {take_overs} --take-over");
}

#[test]
fn duration_and_time_flags_name_their_value() {
    const DURATION: &[(&str, &str)] = &[
        ("bd claim", "ttl"),
        ("bd heartbeat", "ttl"),
        ("bd close", "ttl"),
        ("bd reclaim", "grace"),
        ("bd events", "wait"),
        ("bd events prune", "older-than"),
        ("bd purge", "older-than"),
        ("bd compact", "older-than"),
        ("bd gate create", "timeout"),
        ("bd agents watch", "interval"),
        ("bd serve", "reclaim-every"),
        ("bd serve", "gate-check-every"),
        ("bd serve", "gh-check-every"),
        ("bd serve", "agents-every"),
        ("bd serve", "backup-every"),
        ("bd serve", "max-wait"),
        ("bd serve token events", "since"),
        ("bd list", "stale"),
        ("bd ready", "stale"),
    ];
    const TIME: &[(&str, &str)] = &[
        ("bd create", "due"),
        ("bd create", "defer"),
        ("bd update", "due"),
        ("bd update", "defer"),
        ("bd defer", "until"),
        ("bd show", "as-of"),
        ("bd list", "created-after"),
        ("bd list", "created-before"),
        ("bd list", "updated-after"),
        ("bd list", "updated-before"),
        ("bd list", "closed-after"),
        ("bd list", "closed-before"),
        ("bd ready", "created-after"),
        ("bd ready", "created-before"),
        ("bd ready", "updated-after"),
        ("bd ready", "updated-before"),
        ("bd spec drift", "since"),
    ];
    let root = cli();
    let value_name =
        |arg: &Arg| arg.get_value_names().unwrap_or_default().iter().map(ToString::to_string).collect::<Vec<_>>();
    for (list, name) in [(DURATION, "DURATION"), (TIME, "TIME")] {
        for (path, long) in list {
            assert_eq!(value_name(flag(&root, path, long)), [name], "`{path} --{long}`");
        }
    }
    // And no other flag takes a duration or a time.
    for (path, cmd) in visible(&root) {
        for arg in visible_args(cmd) {
            let Some(long) = arg.get_long() else { continue };
            for (list, name) in [(DURATION, "DURATION"), (TIME, "TIME")] {
                if value_name(arg) == [name] {
                    assert!(list.contains(&(path.as_str(), long)), "`{path} --{long}` takes a {name}: list it here");
                }
            }
        }
    }
}

/// The lines of `after_long_help` in its "Examples:" blocks that run bd, with
/// any `  # comment` dropped.
fn examples(cmd: &Command) -> Vec<String> {
    let text = cmd.get_after_long_help().map(ToString::to_string).unwrap_or_default();
    let mut in_examples = false;
    let mut out = Vec::new();
    for line in text.lines() {
        if !line.starts_with(' ') {
            in_examples = line.trim_end().ends_with("Examples:");
            continue;
        }
        let line = line.trim_start();
        if in_examples && line.starts_with("bd ") {
            out.push(line.split("  #").next().unwrap_or(line).trim_end().to_string());
        }
    }
    out
}

#[test]
fn long_help_examples_parse() {
    let root = cli();
    let mut count = 0;
    for (path, cmd) in visible(&root) {
        for example in examples(cmd) {
            count += 1;
            let argv =
                shlex::split(&example).unwrap_or_else(|| panic!("`{path}`: example {example:?} has unbalanced quotes"));
            if let Err(e) = Cli::try_parse_from(&argv) {
                panic!("`{path}`: example {example:?} does not parse:\n{e}");
            }
        }
    }
    assert!(count >= 50, "only {count} examples found");
}

#[test]
fn commands_that_are_not_obvious_have_long_help_and_examples() {
    let root = cli();
    for path in [
        "bd claim",
        "bd heartbeat",
        "bd release",
        "bd reclaim",
        "bd defer",
        "bd ready",
        "bd query",
        "bd epic status",
        "bd epic close-eligible",
        "bd stale",
        "bd orphans",
        "bd graph",
        "bd create",
        "bd q",
        "bd update",
        "bd edit",
        "bd close",
        "bd duplicate",
        "bd supersede",
        "bd find-duplicates",
        "bd dep add",
        "bd events",
        "bd events prune",
        "bd prime",
        "bd batch",
        "bd import",
        "bd export",
        "bd backup",
        "bd purge",
        "bd compact",
        "bd doctor",
        "bd playbook plan",
        "bd playbook run",
        "bd playbook compact",
        "bd playbook discard",
        "bd playbook extract",
        "bd gate create",
        "bd gate check",
        "bd gate resolve",
        "bd github status",
        "bd github pull",
        "bd github push",
        "bd github sync",
        "bd agents status",
        "bd agents pull",
        "bd agents approve",
        "bd agents watch",
        "bd agents manifest",
        "bd hook session-start",
        "bd setup",
        "bd mcp",
        "bd serve",
        "bd serve check",
        "bd serve token create",
        "bd serve token revoke",
        "bd serve token link",
        "bd serve token name",
        "bd remote set",
        "bd remote login",
        "bd remote logout",
        "bd completion",
    ] {
        let cmd = command(&root, path);
        assert!(cmd.get_long_about().is_some(), "`{path}` has no long help");
        assert!(!examples(cmd).is_empty(), "`{path}` has no Examples: block in its long help");
    }
}

#[test]
fn serve_help_matches_oauth_and_reload_behavior() {
    let root = cli();
    let public_url = flag(&root, "bd serve", "public-url").get_long_help().map(ToString::to_string).unwrap_or_default();
    assert!(
        public_url.contains("Default for MCP endpoints"),
        "the Host default applies to MCP endpoints only: {public_url:?}"
    );
    assert!(public_url.contains("[oauth] in auth.toml requires it"), "the OAuth issuer has no default: {public_url:?}");
    let check = command(&root, "bd serve check").get_long_about().map(ToString::to_string).unwrap_or_default();
    assert!(check.contains("without a restart"), "a running bd serve reloads auth.toml: {check:?}");
    assert!(!check.contains("(re)starting"), "{check:?}");
}

#[test]
fn create_help_says_parent_child_dep_sets_the_parent() {
    let root = cli();
    let create = command(&root, "bd create").get_long_about().map(ToString::to_string).unwrap_or_default();
    let joined = create.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(joined.contains("parent-child:ID (aliases parent:, child-of:) is the same as --parent ID"), "{create:?}");
    assert!(create.lines().all(|l| l.len() <= 78), "{create:?}");
}

#[test]
fn title_and_id_help_state_their_bounds() {
    let root = cli();
    let title =
        command(&root, "bd create").get_arguments().find(|a| a.get_id() == "title").map(help).unwrap_or_default();
    assert!(title.contains("at most 500 characters"), "{title:?}");
    for (path, long) in [("bd update", "title"), ("bd gate create", "title")] {
        let text = help(flag(&root, path, long));
        assert!(text.contains("at most 500 characters"), "`{path} --{long}`: {text:?}");
    }
    let id = help(flag(&root, "bd create", "id"));
    assert!(id.contains("at most 255 characters"), "{id:?}");
}

#[test]
fn root_help_limits_plain_text_errors_to_clap() {
    let root = cli();
    let long = root.get_after_long_help().map(ToString::to_string).unwrap_or_default();
    let joined = long.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        joined.contains(
            "Argument errors that clap reports (unknown flags, missing or malformed values) stay plain text (exit 2)"
        ),
        "{long:?}"
    );
    assert!(!joined.contains("reported before a command runs"), "{long:?}");
}
