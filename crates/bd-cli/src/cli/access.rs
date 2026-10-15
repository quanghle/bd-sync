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
    fn setup_runs_only_on_the_client() {
        let cmd =
            Command::Setup(SetupArgs { harness: Some(SetupTarget::Claude), list: false, remove: false, dry_run: true });
        assert_eq!(access(&cmd), Access::Local);
        assert!(crate::always_local(&cmd));
    }
}
