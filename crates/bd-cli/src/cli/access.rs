//! Which commands `bd serve` runs for clients, and whether they read or write.

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// Only on the machine holding the workspace.
    Local,
    Read,
    /// May write (admin-only operations check the role when they run).
    Write,
}

/// Where a command may run: only on the machine holding the workspace, or
/// through `bd serve` as a read or a write.
pub fn access(cmd: &Command) -> Access {
    use Command as C;
    match cmd {
        C::Init(_)
        | C::Backup(_)
        | C::Serve(_)
        | C::Mcp(_)
        | C::Remote(_)
        | C::Edit(_)
        | C::Hook(_)
        | C::Setup(_)
        | C::Bench(_)
        | C::BenchWorker(_)
        | C::Completion(_) => Access::Local,
        C::Events(a) if a.follow => Access::Local,
        // It asks a person at the terminal and sends its own requests (with the keychain token remotely).
        C::Gate(GateCommand::Review(_)) => Access::Local,
        C::Events(a) if a.action.is_none() => Access::Read,
        C::Playbook(PlaybookCommand::Extract(a)) if a.save => Access::Local,
        // They write into the client's checkout, reading the server's sets with Read requests.
        C::Agents(
            AgentsCommand::Status(_) | AgentsCommand::Pull(_) | AgentsCommand::Approve(_) | AgentsCommand::Watch(_),
        ) => Access::Local,
        C::Compact(a) if a.apply.is_none() => Access::Read,
        C::Epic(EpicCommand::CloseEligible(a)) if !a.close => Access::Read,
        C::Show(_)
        | C::List(_)
        | C::Query(_)
        | C::Epic(EpicCommand::Status(_))
        | C::Children(_)
        | C::Stale(_)
        | C::Orphans(_)
        | C::Spec(
            SpecCommand::List
            | SpecCommand::Show(_)
            | SpecCommand::Drift(_)
            | SpecCommand::Candidates
            | SpecCommand::Changes(_),
        )
        | C::Ready(_)
        | C::Blocked(_)
        | C::FindDuplicates(_)
        | C::Leases(_)
        | C::Comments(_)
        | C::Recall(_)
        | C::Memories(_)
        | C::History(_)
        | C::Prime(_)
        | C::Stats
        | C::Metrics(_)
        | C::Export(_)
        | C::Info
        | C::Version
        | C::Dep(DepCommand::List(_) | DepCommand::Tree(_) | DepCommand::Cycles)
        | C::Graph(_)
        | C::Label(LabelCommand::List(_))
        | C::Comment(CommentCommand::List(_))
        | C::Memory(MemoryCommand::Get(_) | MemoryCommand::List(_))
        | C::Config(ConfigCommand::Get(_) | ConfigCommand::List)
        | C::Playbook(
            PlaybookCommand::List
            | PlaybookCommand::Show(_)
            | PlaybookCommand::Status(_)
            | PlaybookCommand::Runs(_)
            | PlaybookCommand::Extract(_),
        )
        | C::Gate(GateCommand::List(_) | GateCommand::Show(_))
        | C::Github(GithubCommand::Status(_))
        | C::Agents(AgentsCommand::Manifest(_) | AgentsCommand::Fetch(_)) => Access::Read,
        // Everything else writes: `RenamePrefix` and `github pull|push|sync` (admin-only, checked when they run),
        // and `epic close-eligible --close`.
        _ => Access::Write,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compact_reads_unless_it_applies() {
        let args = |apply: Option<&str>| IssueCompactArgs {
            analyze: apply.is_none(),
            apply: apply.map(String::from),
            stats: false,
            summary: apply.map(|_| "-".to_string()),
            older_than: None,
            limit: 20,
            if_revision: apply.map(|_| 3),
        };
        assert_eq!(access(&Command::Compact(args(None))), Access::Read);
        assert_eq!(
            access(&Command::Compact(IssueCompactArgs { analyze: false, stats: true, ..args(None) })),
            Access::Read
        );
        assert_eq!(access(&Command::Compact(args(Some("t-1")))), Access::Write);
    }

    #[test]
    fn rename_prefix_is_a_write() {
        let cmd = Command::RenamePrefix(RenamePrefixArgs { prefix: "x".into(), from: None, dry_run: true });
        assert_eq!(access(&cmd), Access::Write);
    }

    #[test]
    fn edit_runs_only_on_the_machine_holding_the_workspace() {
        let edit = Command::Edit(EditArgs { id: "t-1".into(), field: EditField::Description });
        assert_eq!(access(&edit), Access::Local);
    }

    #[test]
    fn find_duplicates_is_a_read() {
        let find = Command::FindDuplicates(FindDuplicatesArgs { threshold: 0.8, limit: 50 });
        assert_eq!(access(&find), Access::Read);
    }

    #[test]
    fn query_is_a_read() {
        let cmd = Cli::try_parse_from(["bd", "query", "status = open"]).unwrap().command;
        assert_eq!(access(&cmd), Access::Read);
        let cmd = Cli::try_parse_from(["bd", "query", "--parse-only", "status = open"]).unwrap().command;
        assert_eq!(access(&cmd), Access::Read);
        assert!(crate::always_local(&cmd), "--parse-only reads no workspace");
    }

    #[test]
    fn close_eligible_writes_only_with_close() {
        let access_of = |argv: &[&str]| access(&Cli::try_parse_from(argv).unwrap().command);
        assert_eq!(access_of(&["bd", "epic", "close-eligible"]), Access::Read);
        assert_eq!(access_of(&["bd", "epic", "close-eligible", "--close"]), Access::Write);
        assert_eq!(access_of(&["bd", "epic", "close-eligible", "--close", "--take-over", "--force"]), Access::Write);
        assert_eq!(access_of(&["bd", "epic", "status"]), Access::Read);
        assert_eq!(access_of(&["bd", "children", "t-1", "--recursive"]), Access::Read);
        assert_eq!(access_of(&["bd", "stale", "--days", "7"]), Access::Read);
        assert_eq!(access_of(&["bd", "orphans"]), Access::Read);
        // The close flags mean nothing without --close.
        assert!(Cli::try_parse_from(["bd", "epic", "close-eligible", "--take-over"]).is_err());
    }

    #[test]
    fn spec_reads_but_none_writes() {
        let access_of = |argv: &[&str]| access(&Cli::try_parse_from(argv).unwrap().command);
        for argv in [
            &["bd", "spec", "list"][..],
            &["bd", "spec", "show", "checkout", "--history"],
            &["bd", "spec", "drift", "--since", "7d"],
            &["bd", "spec", "candidates"],
            &["bd", "spec", "changes", "--since", "7d"],
            &["bd", "spec", "show", "x", "--as-of", "-1d"],
        ] {
            assert_eq!(access_of(argv), Access::Read, "{argv:?}");
        }
        assert_eq!(access_of(&["bd", "spec", "none", "t-1", "-r", "refactor"]), Access::Write);
        assert!(Cli::try_parse_from(["bd", "spec", "none", "t-1"]).is_err(), "a reason is required");
        for argv in [
            &["bd", "spec", "new", "checkout", "Checkout", "--parent", "s-1", "--from", "t-1"][..],
            &["bd", "spec", "add", "s-1", "Requires", "sign-in", "--from", "t-1,t-2", "--non-goal"],
            &["bd", "spec", "change", "s-1.1", "Requires", "a", "verified", "email", "--from", "t-3"],
            &["bd", "spec", "remove", "s-1.2", "-r", "obsolete", "--from", "t-4"],
            &["bd", "spec", "link", "t-5", "s-1", "s-1.3"],
        ] {
            assert_eq!(access_of(argv), Access::Write, "{argv:?}");
        }
        assert!(Cli::try_parse_from(["bd", "spec", "add", "s-1", "x"]).is_err(), "add needs --from");
        assert!(Cli::try_parse_from(["bd", "spec", "change", "s-1.1", "x"]).is_err(), "change needs --from");
        assert!(Cli::try_parse_from(["bd", "spec", "remove", "s-1.2"]).is_err(), "remove needs a reason");
        assert!(Cli::try_parse_from(["bd", "spec", "link", "t-5"]).is_err(), "link needs a target");
    }

    #[test]
    fn gate_update_writes_and_requires_a_change() {
        let access_of = |argv: &[&str]| access(&Cli::try_parse_from(argv).unwrap().command);
        assert_eq!(access_of(&["bd", "gate", "update", "t-1", "--approver", "a,b", "--approver", "c"]), Access::Write);
        assert_eq!(access_of(&["bd", "gate", "update", "t-1", "--clear-approvers"]), Access::Write);
        assert_eq!(
            access_of(&["bd", "gate", "create", "-t", "human", "--blocks", "t-2", "--approver", "a"]),
            Access::Write
        );
        assert!(Cli::try_parse_from(["bd", "gate", "update", "t-1"]).is_err(), "a change is required");
        assert!(Cli::try_parse_from(["bd", "gate", "update", "t-1", "--approver", "a", "--clear-approvers"]).is_err());
        let Command::Gate(GateCommand::Update(a)) =
            Cli::try_parse_from(["bd", "gate", "update", "t-1", "--approver", "a,b", "--approver", "c"])
                .unwrap()
                .command
        else {
            panic!("not gate update");
        };
        assert_eq!(a.approvers, ["a", "b", "c"]);
    }

    #[test]
    fn oidc_approvers_take_two_verbatim_values_per_occurrence() {
        let parse = |argv: &[&str]| Cli::try_parse_from(argv).map(|c| c.command);
        let update = |rest: &[&str]| {
            let argv: Vec<&str> = ["bd", "gate", "update", "t-1"].iter().chain(rest).copied().collect();
            match parse(&argv) {
                Ok(Command::Gate(GateCommand::Update(a))) => Ok(a),
                Ok(_) => panic!("not gate update"),
                Err(e) => Err(e),
            }
        };
        let a = update(&["--oidc-approver", "i1", "s1", "--oidc-approver", "i2", "s2"]).unwrap();
        assert_eq!(a.oidc_approvers, ["i1", "s1", "i2", "s2"]);
        assert!(a.approvers.is_empty() && !a.clear_approvers, "--oidc-approver alone is a change");
        assert_eq!(update(&["--oidc-approver", "a,b", "c"]).unwrap().oidc_approvers, ["a,b", "c"]);
        assert_eq!(update(&["--oidc-approver", "i", "-dash-subject"]).unwrap().oidc_approvers, ["i", "-dash-subject"]);
        assert!(update(&["--oidc-approver", "i"]).is_err(), "one value");
        assert!(update(&["--oidc-approver", "i", "s", "--clear-approvers"]).is_err());
        assert!(update(&["--clear-approvers", "--oidc-approver", "i", "s"]).is_err());
        let a = update(&["--approver", "x", "--oidc-approver", "i", "s"]).unwrap();
        assert_eq!((a.approvers, a.oidc_approvers), (vec!["x".to_string()], vec!["i".to_string(), "s".to_string()]));
        let both = parse(&["bd", "gate", "update", "t-1", "--approver", "x", "--oidc-approver", "i", "s"]).unwrap();
        assert_eq!(access(&both), Access::Write);
        let create = parse(&[
            "bd",
            "gate",
            "create",
            "-t",
            "human",
            "--blocks",
            "t-2",
            "--approver",
            "a",
            "--oidc-approver",
            "i",
            "s",
        ])
        .unwrap();
        assert_eq!(access(&create), Access::Write);
        let Command::Gate(GateCommand::Create(c)) = create else { panic!("not gate create") };
        assert_eq!((c.approvers, c.oidc_approvers), (vec!["a".to_string()], vec!["i".to_string(), "s".to_string()]));
        assert!(
            parse(&["bd", "gate", "create", "-t", "human", "--blocks", "t-2", "--oidc-approver", "i"]).is_err(),
            "one value"
        );
    }

    #[test]
    fn publish_is_a_write_through_the_server_and_no_mcp_tool() {
        for argv in [&["bd", "publish"][..], &["bd", "publish", "--dry-run"], &["bd", "publish", "--rollback"]] {
            let cmd = Cli::try_parse_from(argv).unwrap().command;
            assert_eq!(access(&cmd), Access::Write, "{argv:?}");
            assert!(!crate::always_local(&cmd));
        }
        let names: Vec<&str> = crate::mcp::tools::TOOLS.iter().map(|t| t.name).collect();
        assert!(!names.iter().any(|n| n.contains("publish")), "{names:?}");
        assert!(Cli::try_parse_from(["bd", "publish", "--rollback", "--from", "x"]).is_err());
    }

    #[test]
    fn gate_review_runs_only_on_the_client() {
        let cmd = Cli::try_parse_from(["bd", "gate", "review", "t-1", "-r", "ship it"]).unwrap().command;
        assert_eq!(access(&cmd), Access::Local);
        assert!(!crate::always_local(&cmd), "in a remote workspace the client runs it against the server");
        let Command::Gate(GateCommand::Review(a)) = cmd else { panic!("not gate review") };
        assert_eq!((a.ids, a.reason.as_deref()), (vec!["t-1".to_string()], Some("ship it")));
    }

    #[test]
    fn setup_runs_only_on_the_client() {
        let cmd =
            Command::Setup(SetupArgs { harness: Some(SetupTarget::Claude), list: false, remove: false, dry_run: true });
        assert_eq!(access(&cmd), Access::Local);
        assert!(crate::always_local(&cmd));
    }
}
