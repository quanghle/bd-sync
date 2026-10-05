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
        | C::Hook(_)
        | C::Bench(_)
        | C::BenchWorker(_) => Access::Local,
        C::Events(a) if a.follow => Access::Local,
        C::Events(a) if a.action.is_none() => Access::Read,
        C::Playbook(PlaybookCommand::Extract(a)) if a.save => Access::Local,
        // They write into the client's checkout, reading the server's sets with Read requests.
        C::Agents(
            AgentsCommand::Status(_) | AgentsCommand::Pull(_) | AgentsCommand::Approve(_) | AgentsCommand::Watch(_),
        ) => Access::Local,
        C::Show(_)
        | C::List(_)
        | C::Ready(_)
        | C::Blocked(_)
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
        | C::Agents(AgentsCommand::Manifest(_) | AgentsCommand::Fetch(_)) => Access::Read,
        _ => Access::Write,
    }
}
