//! `bd remote login --provider`, on the client: asks the server to sign
//! in, shows the one-time code, polls.

use super::*;

/// A one-time code as GitHub writes them (`WDJB-MJHT`).
pub(super) fn plain_code(s: &str) -> bool {
    (1..=32).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// An `https://` address of printable characters, nothing else.
pub(super) fn plain_url(s: &str) -> bool {
    let lower = s.to_ascii_lowercase();
    (lower.starts_with("https://") || lower.starts_with("http://"))
        && s.len() <= 300
        && s.bytes().all(|b| b.is_ascii_graphic())
}

/// `bd remote login --provider github`: sign in at GitHub through `remote`'s server
/// (`server`, its URL), for `workspace`. Shows the one-time code on stderr
/// and waits until it was entered, or expired; the token issued.
pub fn sign_in(remote: &Remote, workspace: &str, server: &str, provider: &str) -> Result<Issued> {
    let plain = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
    if provider.is_empty() || provider.len() > 32 || !provider.chars().all(plain) {
        return Err(Error::invalid(format!("--provider {provider:?} is not a provider's name, such as github")));
    }
    let start = SignInStart { workspace: workspace.to_string() };
    let code: SignInCode = remote.auth_request(&format!("{provider}/device"), &start, Duration::ZERO)?;
    let label = crate::agents::show::printable(&code.provider);
    if !plain_code(&code.user_code) || !plain_url(&code.verification_uri) || code.device_code.is_empty() {
        return Err(Error::Remote(format!("{server}: unexpected sign-in answer: not a one-time code and address")));
    }
    let lasts = Duration::from_secs(code.expires_in.clamp(1, MAX_CODE_LIFE));
    io::errln(format!("! One-time code: {}", code.user_code));
    io::errln(format!(
        "  Enter it at {} within {} minutes to sign in to {server} with {label}",
        code.verification_uri,
        lasts.as_secs().div_ceil(60)
    ));
    io::errln(format!("  Waiting for {label} (Ctrl-C cancels)..."));
    let deadline = Instant::now() + lasts;
    // GitHub's least time between polls, which only grows; past the deadline, the code is gone anyway.
    let mut interval = Duration::from_secs(code.interval.clamp(1, MAX_CODE_LIFE));
    let poll = SignInPoll { device_code: code.device_code, workspace: workspace.to_string() };
    loop {
        if Instant::now() + interval > deadline {
            return Err(Error::Unauthorized(format!(
                "the one-time code expired before it was entered at {label}: run `bd remote login --provider \
                 {provider}` again"
            )));
        }
        std::thread::sleep(interval);
        match remote.auth_request(&format!("{provider}/token"), &poll, interval)? {
            SignInAnswer::Pending => {}
            SignInAnswer::SlowDown { interval: asked } => {
                let asked = Duration::from_secs(asked.min(MAX_CODE_LIFE));
                interval = (interval + Duration::from_secs(5)).max(asked);
            }
            SignInAnswer::Issued(issued) => return Ok(*issued),
        }
    }
}
