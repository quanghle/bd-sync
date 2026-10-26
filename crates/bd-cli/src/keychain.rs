//! A person's access token kept in the OS keychain (`bd remote login
//! --human`), never in a file.
//!
//! One backend per OS, with no fallback: the Secret Service over D-Bus on
//! Linux, the login Keychain on macOS, Credential Manager on Windows; any
//! other OS is refused. Items use service [`SERVICE`] and account
//! `server:<key>` or `workspace:<key>` ([`account`]), the keys of
//! [`credentials::keys`], each holding a [`HumanEntry`] as JSON.
//!
//! Every operation runs on one long-lived worker thread per [`Bounded`],
//! which builds the store (so zbus's own blocking never runs on a tokio
//! thread) and runs jobs in order, while the caller waits at most its
//! timeout ([`IMPLICIT`] for uses bd makes on its own, [`EXPLICIT`] for
//! `--human` commands). A timeout poisons the [`Bounded`]: later operations
//! fail at once, and the job under way still finishes, in order.
//!
//! Writes hold `credentials.lock` ([`Held`]): each write's job keeps a
//! handle of the lock until it ends, so a write the caller stopped waiting
//! for still holds it, and can never land after a later renewal, login or
//! logout of another process. Reads take no lock.
//!
//! Errors name the store, never a secret. Debug builds read
//! `$BD_TEST_KEYCHAIN` (tests only): a JSON file standing in for the
//! keychain, with each operation logged to `<path>.log`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use bd_core::{Error, Need, Result, Timestamp};
use serde::{Deserialize, Serialize};

use crate::credentials::{self, Gone, Renewal, Scope};
use crate::tokens::{Kind, Role};

/// The service every item is saved under.
pub const SERVICE: &str = "bd";

/// How long bd waits for the keychain when it uses it on its own: the
/// retry after a refusal, publish, renewal.
pub const IMPLICIT: Duration = Duration::from_secs(5);

/// How long a `--human` command waits, as the keychain may ask the person
/// to unlock it.
pub const EXPLICIT: Duration = Duration::from_secs(60);

/// Debug builds only: a JSON file standing in for the keychain in tests.
#[cfg(debug_assertions)]
pub const TEST_VAR: &str = "BD_TEST_KEYCHAIN";

/// Where a person's tokens are kept. Errors name the store, never the secret.
pub trait HumanStore: Send {
    /// The store, for people: `Secret Service`, `macOS Keychain`, ...
    fn name(&self) -> &'static str;
    fn get(&self, account: &str) -> Result<Option<String>>;
    fn set(&self, account: &str, secret: &str) -> Result<()>;
    /// Whether there was an item to delete.
    fn delete(&self, account: &str) -> Result<bool>;
}

/// The account of the item saved for `key` under `scope`.
pub fn account(scope: Scope, key: &str) -> String {
    format!("{}:{key}", scope.as_str())
}

/// The OS keychain bd uses here, or why there is none.
fn native() -> Result<Box<dyn HumanStore>> {
    #[cfg(any(target_os = "linux", target_os = "macos", windows))]
    return Ok(Box::new(native::Native::new()?));
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    return Err(unsupported(std::env::consts::OS));
}

/// `--human` on an OS without a supported keychain.
#[cfg_attr(any(target_os = "linux", target_os = "macos", windows), allow(dead_code))]
fn unsupported(os: &str) -> Error {
    Error::Refused(format!("--human keeps the token in the OS keychain, which bd does not support on {os}"))
}

/// No Secret Service to talk to (Linux).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn no_secret_service(why: &str) -> Error {
    Error::Refused(format!(
        "no Secret Service is reachable on D-Bus ({why}): --human keeps the token only in the OS keychain, never in a \
         file; start one (GNOME Keyring, KWallet, KeePassXC) or use a saved token"
    ))
}

/// A keychain failure, naming the store and never quoting what it holds.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos", windows)), allow(dead_code))]
fn failure(store: &str, e: &keyring_core::Error) -> Error {
    Error::Refused(format!("{store}: {}", describe(e)))
}

/// What went wrong, without what the item holds.
#[cfg_attr(not(any(target_os = "linux", target_os = "macos", windows)), allow(dead_code))]
fn describe(e: &keyring_core::Error) -> String {
    use keyring_core::Error as K;
    match e {
        K::NoStorageAccess(e) => format!("access refused ({e}); unlock it and try again"),
        K::BadEncoding(_) | K::BadDataFormat(..) => "the saved item is not text bd wrote".to_string(),
        K::Ambiguous(items) => format!("{} items match", items.len()),
        e => e.to_string(),
    }
}

/// The message of a keychain error without its `keychain unavailable: `
/// prefix, for callers that say so themselves.
pub fn reason(e: &Error) -> String {
    let text = e.to_string();
    text.strip_prefix("keychain unavailable: ").map(str::to_string).unwrap_or(text)
}

#[cfg(any(target_os = "linux", target_os = "macos", windows))]
mod native {
    use std::sync::Arc;

    use bd_core::Result;
    use keyring_core::CredentialStore;

    use super::{HumanStore, SERVICE, failure};

    #[cfg(target_os = "linux")]
    const NAME: &str = "Secret Service";
    #[cfg(target_os = "macos")]
    const NAME: &str = "macOS Keychain";
    #[cfg(windows)]
    const NAME: &str = "Windows Credential Manager";

    pub(super) struct Native {
        store: Arc<CredentialStore>,
    }

    impl Native {
        pub(super) fn new() -> Result<Native> {
            #[cfg(target_os = "linux")]
            let store: Arc<CredentialStore> = zbus_secret_service_keyring_store::Store::new()
                .map_err(|e| super::no_secret_service(&super::describe(&e)))?;
            #[cfg(target_os = "macos")]
            let store: Arc<CredentialStore> =
                apple_native_keyring_store::keychain::Store::new().map_err(|e| failure(NAME, &e))?;
            #[cfg(windows)]
            let store: Arc<CredentialStore> =
                windows_native_keyring_store::Store::new().map_err(|e| failure(NAME, &e))?;
            Ok(Native { store })
        }

        fn entry(&self, account: &str) -> Result<keyring_core::Entry> {
            self.store.build(SERVICE, account, None).map_err(|e| failure(NAME, &e))
        }
    }

    impl HumanStore for Native {
        fn name(&self) -> &'static str {
            NAME
        }

        fn get(&self, account: &str) -> Result<Option<String>> {
            match self.entry(account)?.get_password() {
                Ok(secret) => Ok(Some(secret)),
                Err(keyring_core::Error::NoEntry) => Ok(None),
                Err(e) => Err(failure(NAME, &e)),
            }
        }

        fn set(&self, account: &str, secret: &str) -> Result<()> {
            self.entry(account)?.set_password(secret).map_err(|e| failure(NAME, &e))
        }

        fn delete(&self, account: &str) -> Result<bool> {
            match self.entry(account)?.delete_credential() {
                Ok(()) => Ok(true),
                Err(keyring_core::Error::NoEntry) => Ok(false),
                Err(e) => Err(failure(NAME, &e)),
            }
        }
    }
}

/// `credentials.lock` held for keychain writes. A write's job keeps a
/// handle, so the lock stays held until the write ends, even when its
/// caller stopped waiting and dropped this one.
pub struct Held(Arc<credentials::Lock>);

/// Take `credentials.lock` for keychain writes, as saving a token in the
/// credentials file does.
pub fn lock() -> Result<Held> {
    lock_at(&credentials::default_path()?, credentials::LOCK_WAIT)
}

/// [`lock`] for the credentials file `path`, waiting up to `wait`.
pub(crate) fn lock_at(path: &std::path::Path, wait: Duration) -> Result<Held> {
    Ok(Held(Arc::new(credentials::lock(path, wait)?)))
}

type Job = Box<dyn FnOnce(&dyn HumanStore) + Send>;

/// A store whose operations run in order on its own worker thread, each
/// waited for at most `timeout`.
pub struct Bounded {
    name: &'static str,
    jobs: Mutex<mpsc::Sender<Job>>,
    timeout: Duration,
    /// An operation did not answer in time: every later one fails at once.
    poisoned: AtomicBool,
}

impl Bounded {
    /// Start the worker, which builds the store with `make`.
    fn spawn<F>(make: F, timeout: Duration) -> Result<Bounded>
    where
        F: FnOnce() -> Result<Box<dyn HumanStore>> + Send + 'static,
    {
        let (jobs, queue) = mpsc::channel::<Job>();
        let (built_tx, built) = mpsc::sync_channel::<Result<&'static str>>(1);
        std::thread::Builder::new()
            .name("bd-keychain".into())
            .spawn(move || {
                let store = match make() {
                    Ok(store) => store,
                    Err(e) => {
                        let _ = built_tx.send(Err(e));
                        return;
                    }
                };
                let _ = built_tx.send(Ok(store.name()));
                for job in queue {
                    job(&*store);
                }
            })
            .map_err(|e| Error::Refused(format!("keychain unavailable: could not start its thread ({e})")))?;
        let name = match built.recv_timeout(timeout) {
            Ok(built) => built?,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                return Err(Error::Refused(format!(
                    "keychain unavailable: the OS keychain did not answer within {}s",
                    timeout.as_secs_f64()
                )));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(Error::Refused("keychain unavailable: its thread stopped".into()));
            }
        };
        Ok(Bounded { name, jobs: Mutex::new(jobs), timeout, poisoned: AtomicBool::new(false) })
    }

    /// The store, for people.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The secret saved under `account`, if any.
    pub fn get(&self, account: &str) -> Result<Option<String>> {
        let account = account.to_string();
        self.run(move |s| s.get(&account))
    }

    /// Save `secret` under `account`, holding `credentials.lock` until the
    /// write ends.
    pub fn set(&self, held: &Held, account: &str, secret: &str) -> Result<()> {
        let (account, secret) = (account.to_string(), secret.to_string());
        self.write(held, move |s| s.set(&account, &secret))
    }

    /// Delete the item under `account`, holding `credentials.lock` until it
    /// is gone; whether there was one.
    pub fn delete(&self, held: &Held, account: &str) -> Result<bool> {
        let account = account.to_string();
        self.write(held, move |s| s.delete(&account))
    }

    /// Run a write, its job keeping `credentials.lock` held until it ends.
    pub fn write<T, F>(&self, held: &Held, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&dyn HumanStore) -> Result<T> + Send + 'static,
    {
        let lock = Arc::clone(&held.0);
        self.run(move |s| {
            let result = f(s);
            drop(lock);
            result
        })
    }

    fn run<T, F>(&self, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&dyn HumanStore) -> Result<T> + Send + 'static,
    {
        let secs = self.timeout.as_secs_f64();
        if self.poisoned.load(Ordering::SeqCst) {
            return Err(Error::Refused(format!(
                "keychain unavailable: an earlier keychain operation did not answer within {secs}s"
            )));
        }
        let (tx, rx) = mpsc::sync_channel(1);
        let job: Job = Box::new(move |s| {
            let _ = tx.send(f(s));
        });
        let stopped = || Error::Refused(format!("keychain unavailable: the {} thread stopped", self.name));
        self.jobs.lock().unwrap_or_else(|p| p.into_inner()).send(job).map_err(|_| stopped())?;
        match rx.recv_timeout(self.timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                self.poisoned.store(true, Ordering::SeqCst);
                Err(Error::Refused(format!("keychain unavailable: the {} did not answer within {secs}s", self.name)))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(stopped()),
        }
    }
}

/// The OS keychain, each operation waited for at most `timeout`. In debug
/// builds `$BD_TEST_KEYCHAIN` names a file standing in for it.
pub fn open(timeout: Duration) -> Result<Arc<Bounded>> {
    #[cfg(debug_assertions)]
    if let Some(path) = std::env::var_os(TEST_VAR).filter(|v| !v.is_empty()) {
        let path = std::path::PathBuf::from(path);
        return Bounded::spawn(move || Ok(Box::new(FileStore { path }) as Box<dyn HumanStore>), timeout).map(Arc::new);
    }
    Bounded::spawn(native, timeout).map(Arc::new)
}

/// A file standing in for the keychain (debug builds, `$BD_TEST_KEYCHAIN`):
/// JSON `{account: secret}`, each operation appended to `<path>.log` as
/// `get|set|delete <account>`; a file reading `unavailable` fails every one.
#[cfg(debug_assertions)]
struct FileStore {
    path: std::path::PathBuf,
}

#[cfg(debug_assertions)]
impl FileStore {
    const NAME: &str = "test keychain";

    fn log(&self, op: &str, account: &str) -> Result<()> {
        use std::io::Write;
        let mut log = self.path.clone().into_os_string();
        log.push(".log");
        let mut file = std::fs::OpenOptions::new().create(true).append(true).open(log)?;
        writeln!(file, "{op} {account}")?;
        Ok(())
    }

    fn load(&self) -> Result<std::collections::BTreeMap<String, String>> {
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Default::default()),
            Err(e) => return Err(e.into()),
        };
        if text.trim() == "unavailable" {
            return Err(Error::Refused(format!("{}: unavailable", Self::NAME)));
        }
        if text.trim().is_empty() {
            return Ok(Default::default());
        }
        serde_json::from_str(&text).map_err(|_| Error::Refused(format!("{}: not a JSON object", Self::NAME)))
    }

    fn save(&self, items: &std::collections::BTreeMap<String, String>) -> Result<()> {
        let text = serde_json::to_string(items).map_err(|e| Error::invalid(e.to_string()))?;
        std::fs::write(&self.path, text)?;
        Ok(())
    }
}

#[cfg(debug_assertions)]
impl HumanStore for FileStore {
    fn name(&self) -> &'static str {
        Self::NAME
    }

    fn get(&self, account: &str) -> Result<Option<String>> {
        self.log("get", account)?;
        Ok(self.load()?.remove(account))
    }

    fn set(&self, account: &str, secret: &str) -> Result<()> {
        self.log("set", account)?;
        let mut items = self.load()?;
        items.insert(account.to_string(), secret.to_string());
        self.save(&items)
    }

    fn delete(&self, account: &str) -> Result<bool> {
        self.log("delete", account)?;
        let mut items = self.load()?;
        let found = items.remove(account).is_some();
        if found {
            self.save(&items)?;
        }
        Ok(found)
    }
}

/// What a keychain item holds: the token, the CA trust it was saved under,
/// and what the server said the token is.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HumanEntry {
    pub token: String,
    /// What the server's certificate was trusted against at login:
    /// [`credentials::SYSTEM_CA`] or `sha256:<hex>`.
    pub ca: String,
    /// From signing in: logging out, or saving another token in its place,
    /// revokes it on its server.
    #[serde(default, skip_serializing_if = "is_false")]
    pub signed_in: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_after: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Timestamp>,
    /// The request id of a refresh sent and not answered yet.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refresh_request: Option<String>,
    pub kind: Kind,
    pub role: Role,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl std::fmt::Debug for HumanEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never the secrets.
        f.debug_struct("HumanEntry")
            .field("ca", &self.ca)
            .field("signed_in", &self.signed_in)
            .field("refresh_after", &self.refresh_after)
            .field("expires_at", &self.expires_at)
            .field("kind", &self.kind)
            .field("role", &self.role)
            .finish_non_exhaustive()
    }
}

impl HumanEntry {
    /// How the token is renewed, if it is.
    pub fn renewal(&self) -> Option<Renewal> {
        match (&self.refresh_token, self.refresh_after, self.expires_at) {
            (Some(refresh_token), Some(refresh_after), Some(expires_at)) => Some(Renewal {
                refresh_token: refresh_token.clone(),
                refresh_after,
                expires_at,
                pending: self.refresh_request.clone(),
            }),
            _ => None,
        }
    }

    pub fn set_renewal(&mut self, renewal: Option<&Renewal>) {
        self.refresh_token = renewal.map(|r| r.refresh_token.clone());
        self.refresh_after = renewal.map(|r| r.refresh_after);
        self.expires_at = renewal.map(|r| r.expires_at);
        self.refresh_request = renewal.and_then(|r| r.pending.clone());
    }
}

/// A person's token found in the keychain, and the item it is saved under.
#[derive(Clone, Debug)]
pub struct Human {
    /// The key of [`credentials::keys`] it is saved for.
    pub key: String,
    pub scope: Scope,
    pub entry: HumanEntry,
}

/// What [`save`] did.
#[derive(Debug)]
pub struct HumanSaveReport {
    pub key: String,
    /// The token saved for the same item before, replaced now.
    pub replaced: Option<Gone>,
    /// The URL's workspace item, removed because it would have hidden the
    /// new server token.
    pub dropped: Option<Gone>,
}

/// The person's token for a workspace URL, if any: its workspace item,
/// else its server's.
pub fn lookup(store: &Bounded, url: &str) -> Result<Option<Human>> {
    let keys = credentials::keys(url)?;
    let items = keys.workspace.map(|k| (k, Scope::Workspace)).into_iter().chain([(keys.server, Scope::Server)]);
    for (key, scope) in items {
        let item = account(scope, &key);
        if let Some(text) = store.get(&item)? {
            return Ok(Some(Human { entry: parse(store.name(), &item, &text)?, key, scope }));
        }
    }
    Ok(None)
}

/// The person's token saved under `key` (a workspace's or a server's).
pub fn lookup_key(store: &Bounded, key: &str) -> Result<Option<Human>> {
    let scope = scope_of(key);
    let item = account(scope, key);
    let Some(text) = store.get(&item)? else { return Ok(None) };
    Ok(Some(Human { entry: parse(store.name(), &item, &text)?, key: key.to_string(), scope }))
}

/// Save `entry` for `url`'s server, or for its workspace only. A server
/// save removes the URL's workspace item, which would hide it.
pub fn save(held: &Held, store: &Bounded, url: &str, scope: Scope, entry: HumanEntry) -> Result<HumanSaveReport> {
    credentials::check_token(&entry.token)?;
    let keys = credentials::keys(url)?;
    let (key, hides) = match scope {
        Scope::Server => (keys.server, keys.workspace),
        Scope::Workspace => {
            (keys.workspace.ok_or_else(|| Error::invalid(format!("{url}: not a workspace URL")))?, None)
        }
    };
    store.write(held, move |s| {
        let item = account(scope, &key);
        let replaced = read_any(s, &item)?.map(|e| gone(key.clone(), e));
        write_entry(s, &item, &entry)?;
        let mut dropped = None;
        if let Some(k) = hides {
            let item = account(Scope::Workspace, &k);
            let old = read_any(s, &item)?;
            if s.delete(&item)? {
                dropped = old.map(|e| gone(k, e));
            }
        }
        Ok(HumanSaveReport { key, replaced, dropped })
    })
}

/// Forget the person's tokens saved for `url`. For a workspace URL: its
/// own item and, unless `workspace_only`, its server's. For a server URL:
/// the server's (its workspaces' items are not listed, so they stay).
pub fn remove(held: &Held, store: &Bounded, url: &str, workspace_only: bool) -> Result<Vec<Gone>> {
    let keys = credentials::keys(url)?;
    if workspace_only && keys.workspace.is_none() {
        return Err(Error::invalid(format!("--workspace-only needs a workspace URL (…/w/<workspace>), not {url}")));
    }
    let mut items = Vec::new();
    if !workspace_only {
        items.push((keys.server, Scope::Server));
    }
    items.extend(keys.workspace.map(|k| (k, Scope::Workspace)));
    store.write(held, move |s| {
        let mut removed = Vec::new();
        for (key, scope) in items {
            let item = account(scope, &key);
            let old = read_any(s, &item)?;
            if s.delete(&item)? {
                removed.extend(old.map(|e| gone(key, e)));
            }
        }
        Ok(removed)
    })
}

/// Replace the token saved under `key`, and how it is renewed (`None`: it
/// is not, any more), keeping its trust, kind, role and origin. Nothing is
/// written when the item is gone.
pub fn renewed(held: &Held, store: &Bounded, key: &str, token: &str, renewal: Option<&Renewal>) -> Result<()> {
    credentials::check_token(token)?;
    let item = account(scope_of(key), key);
    let (token, renewal) = (token.to_string(), renewal.cloned());
    store.write(held, move |s| {
        let Some(text) = s.get(&item)? else { return Ok(()) };
        let mut entry = parse(s.name(), &item, &text)?;
        entry.token = token;
        entry.set_renewal(renewal.as_ref());
        write_entry(s, &item, &entry)
    })
}

/// Which item `key` names: a workspace's (`<server>/w/<name>`) or a server's.
fn scope_of(key: &str) -> Scope {
    match credentials::keys(key) {
        Ok(keys) if keys.workspace.as_deref() == Some(key) => Scope::Workspace,
        _ => Scope::Server,
    }
}

/// An item's entry, never quoting what it holds when it is not one.
fn parse(store: &str, item: &str, text: &str) -> Result<HumanEntry> {
    serde_json::from_str(text).map_err(|_| Error::Refused(format!("{store}: the item {item} is not one bd wrote")))
}

/// The entry under `item`, or `None` when there is none or it is not one
/// bd wrote (replaced or removed all the same, with nothing to revoke).
fn read_any(s: &dyn HumanStore, item: &str) -> Result<Option<HumanEntry>> {
    Ok(s.get(item)?.and_then(|text| serde_json::from_str(&text).ok()))
}

fn write_entry(s: &dyn HumanStore, item: &str, entry: &HumanEntry) -> Result<()> {
    let text = serde_json::to_string(entry).map_err(|e| Error::invalid(e.to_string()))?;
    s.set(item, &text)
}

fn gone(key: String, entry: HumanEntry) -> Gone {
    Gone { key, renewal: entry.renewal(), token: entry.token, ca: entry.ca, signed_in: entry.signed_in }
}

/// Whether this process's stdin is a terminal. There is deliberately no
/// way to pretend it is.
pub fn stdin_is_terminal() -> bool {
    use std::io::IsTerminal;
    std::io::stdin().is_terminal()
}

/// Whether a token of `kind` and `role` has every right in `needs`.
pub fn covers(kind: Kind, role: Role, needs: &[Need]) -> bool {
    needs.iter().all(|need| match need {
        Need::Human => kind == Kind::Human,
        Need::Admin => role == Role::Admin,
    })
}

/// An in-memory keychain for tests here and in `remote`.
#[cfg(test)]
pub(crate) mod testing {
    use std::collections::HashMap;
    use std::sync::atomic::AtomicUsize;

    use super::*;

    pub(crate) type Items = Arc<Mutex<HashMap<String, String>>>;

    /// An in-memory keychain that counts reads.
    pub(crate) struct MemoryStore {
        pub(crate) items: Items,
        pub(crate) reads: Arc<AtomicUsize>,
    }

    impl HumanStore for MemoryStore {
        fn name(&self) -> &'static str {
            "memory keychain"
        }
        fn get(&self, account: &str) -> Result<Option<String>> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            Ok(self.items.lock().unwrap().get(account).cloned())
        }
        fn set(&self, account: &str, secret: &str) -> Result<()> {
            self.items.lock().unwrap().insert(account.into(), secret.into());
            Ok(())
        }
        fn delete(&self, account: &str) -> Result<bool> {
            Ok(self.items.lock().unwrap().remove(account).is_some())
        }
    }

    /// A [`Bounded`] over a [`MemoryStore`] holding `items`, and its count of reads.
    pub(crate) fn memory(items: &Items, timeout: Duration) -> (Bounded, Arc<AtomicUsize>) {
        let reads = Arc::new(AtomicUsize::new(0));
        let store = MemoryStore { items: items.clone(), reads: reads.clone() };
        (Bounded::spawn(move || Ok(Box::new(store) as Box<dyn HumanStore>), timeout).unwrap(), reads)
    }

    /// An entry for `token` trusting `ca`, kind human and role admin.
    pub(crate) fn entry_for(token: &str, ca: &str, renewal: Option<&Renewal>) -> HumanEntry {
        let mut e = HumanEntry {
            token: token.into(),
            ca: ca.into(),
            signed_in: true,
            refresh_token: None,
            refresh_after: None,
            expires_at: None,
            refresh_request: None,
            kind: Kind::Human,
            role: Role::Admin,
        };
        e.set_renewal(renewal);
        e
    }

    /// Put `entry` under `account` as the keychain would hold it.
    pub(crate) fn put(items: &Items, account: &str, entry: &HumanEntry) {
        items.lock().unwrap().insert(account.into(), serde_json::to_string(entry).unwrap());
    }

    /// The entry under `account`, if any.
    pub(crate) fn get(items: &Items, account: &str) -> Option<HumanEntry> {
        items.lock().unwrap().get(account).map(|t| serde_json::from_str(t).unwrap())
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::testing::{Items, MemoryStore, entry_for, get, memory, put};
    use super::*;

    /// A keychain that fails every operation.
    struct FailingStore;

    impl HumanStore for FailingStore {
        fn name(&self) -> &'static str {
            "failing keychain"
        }
        fn get(&self, _: &str) -> Result<Option<String>> {
            Err(failure(self.name(), &keyring_core::Error::NoStorageAccess("locked".into())))
        }
        fn set(&self, _: &str, secret: &str) -> Result<()> {
            Err(failure(self.name(), &keyring_core::Error::BadEncoding(secret.as_bytes().to_vec())))
        }
        fn delete(&self, _: &str) -> Result<bool> {
            Err(failure(self.name(), &keyring_core::Error::PlatformFailure("no D-Bus".into())))
        }
    }

    /// A memory keychain each of whose operations waits for a message on `gate`.
    struct SlowStore {
        inner: MemoryStore,
        gate: mpsc::Receiver<()>,
    }

    impl SlowStore {
        fn wait(&self) {
            let _ = self.gate.recv();
        }
    }

    impl HumanStore for SlowStore {
        fn name(&self) -> &'static str {
            "slow keychain"
        }
        fn get(&self, account: &str) -> Result<Option<String>> {
            self.wait();
            self.inner.get(account)
        }
        fn set(&self, account: &str, secret: &str) -> Result<()> {
            self.wait();
            self.inner.set(account, secret)
        }
        fn delete(&self, account: &str) -> Result<bool> {
            self.wait();
            self.inner.delete(account)
        }
    }

    fn slow(items: &Items, timeout: Duration) -> (Bounded, mpsc::Sender<()>) {
        let (open, gate) = mpsc::channel();
        let inner = MemoryStore { items: items.clone(), reads: Arc::default() };
        let store = SlowStore { inner, gate };
        (Bounded::spawn(move || Ok(Box::new(store) as Box<dyn HumanStore>), timeout).unwrap(), open)
    }

    fn entry() -> HumanEntry {
        let mut renewal = Renewal::new("bdr_refresh".into(), Duration::from_secs(3600));
        renewal.pending = Some("req-1".into());
        entry_for("bdt_secret", credentials::SYSTEM_CA, Some(&renewal))
    }

    #[test]
    fn accounts_name_the_scope_and_key() {
        assert_eq!(account(Scope::Server, "https://h:8443/p"), "server:https://h:8443/p");
        assert_eq!(account(Scope::Workspace, "https://h/w/a"), "workspace:https://h/w/a");
    }

    #[test]
    fn covers_needs_kind_human_and_role_admin() {
        use Need::{Admin, Human};
        let cases = [
            (Kind::Human, Role::Admin, &[Admin, Human][..], true),
            (Kind::Human, Role::Write, &[Human][..], true),
            (Kind::Human, Role::Write, &[Admin][..], false),
            (Kind::Human, Role::Write, &[Admin, Human][..], false),
            (Kind::Agent, Role::Admin, &[Admin][..], true),
            (Kind::Agent, Role::Admin, &[Human][..], false),
            (Kind::Agent, Role::Admin, &[Admin, Human][..], false),
            (Kind::Human, Role::Read, &[][..], true),
        ];
        for (kind, role, needs, expected) in cases {
            assert_eq!(covers(kind, role, needs), expected, "{kind:?} {role:?} {needs:?}");
        }
    }

    #[test]
    fn entries_round_trip_as_json_and_never_show_secrets() {
        let e = entry();
        let json = serde_json::to_string(&e).unwrap();
        let back: HumanEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);
        assert_eq!(back.renewal(), e.renewal());
        assert_eq!(back.renewal().unwrap().pending.as_deref(), Some("req-1"));
        assert!(json.contains(r#""kind":"human""#) && json.contains(r#""role":"admin""#), "{json}");
        let unknown = json.replacen('{', r#"{"extra":1,"#, 1);
        assert!(serde_json::from_str::<HumanEntry>(&unknown).is_err(), "unknown fields are refused");

        let shown = format!("{e:?}");
        assert!(!shown.contains("bdt_") && !shown.contains("bdr_") && !shown.contains("req-1"), "{shown}");
        assert!(shown.contains("Human") && shown.contains("Admin"), "{shown}");

        let mut plain = e.clone();
        plain.set_renewal(None);
        assert!(plain.renewal().is_none() && plain.refresh_token.is_none() && plain.refresh_request.is_none());
    }

    #[test]
    fn a_slow_keychain_is_given_up_on_and_then_poisoned() {
        let items = Items::default();
        let (bounded, open) = slow(&items, Duration::from_millis(20));
        let started = Instant::now();
        let e = bounded.get("server:https://h").unwrap_err();
        assert!(started.elapsed() < Duration::from_millis(500), "{:?}", started.elapsed());
        assert_eq!(e.exit_code(), 2, "{e}");
        assert!(e.to_string().starts_with("keychain unavailable: the slow keychain did not answer"), "{e}");
        assert_eq!(reason(&e), "the slow keychain did not answer within 0.02s");

        let started = Instant::now();
        let e = bounded.get("server:https://h").unwrap_err();
        assert!(started.elapsed() < Duration::from_millis(500), "poisoned: fails at once");
        assert_eq!(e.to_string(), "keychain unavailable: an earlier keychain operation did not answer within 0.02s");
        open.send(()).unwrap();
    }

    #[test]
    fn failures_name_the_store_and_never_the_secret() {
        let dir = tempfile::tempdir().unwrap();
        let held = lock_at(&dir.path().join("credentials.toml"), Duration::from_secs(5)).unwrap();
        let bounded = Bounded::spawn(|| Ok(Box::new(FailingStore) as Box<dyn HumanStore>), EXPLICIT).unwrap();
        for e in [
            bounded.get("server:https://h").unwrap_err(),
            bounded.set(&held, "server:https://h", "bdt_secret").unwrap_err(),
            bounded.delete(&held, "server:https://h").unwrap_err(),
        ] {
            let text = e.to_string();
            assert_eq!(e.exit_code(), 2, "{text}");
            assert!(text.starts_with("failing keychain: "), "{text}");
            assert!(!text.contains("bdt_") && !text.contains("98, 100, 116"), "{text}");
        }

        let e = Bounded::spawn(|| Err(no_secret_service("org.freedesktop.DBus.Error.ServiceUnknown")), EXPLICIT)
            .err()
            .expect("no store");
        assert_eq!(e.exit_code(), 2);
        assert!(e.to_string().starts_with("no Secret Service is reachable on D-Bus (org.freedesktop"), "{e}");
        assert!(e.to_string().contains("never in a file"), "{e}");
    }

    #[test]
    fn other_systems_are_refused() {
        let e = unsupported("freebsd");
        assert_eq!(e.exit_code(), 2);
        assert_eq!(e.to_string(), "--human keeps the token in the OS keychain, which bd does not support on freebsd");
    }

    #[test]
    fn writes_keep_the_lock_until_they_end() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        let items = Items::default();
        let (bounded, open) = slow(&items, Duration::from_millis(20));
        let held = lock_at(&path, Duration::from_secs(5)).unwrap();
        let e = bounded.set(&held, "server:https://h", "first").unwrap_err();
        assert!(e.to_string().contains("did not answer"), "{e}");
        drop(held);
        let e = credentials::lock(&path, Duration::from_millis(10)).err().expect("the write under way holds it");
        assert_eq!(e.exit_code(), 5, "{e}");

        open.send(()).unwrap();
        let held = lock_at(&path, Duration::from_secs(10)).expect("released once the write ended");
        assert_eq!(items.lock().unwrap().get("server:https://h").map(String::as_str), Some("first"));
        let (later, _) = memory(&items, IMPLICIT);
        later.set(&held, "server:https://h", "second").unwrap();
        drop(held);
        assert_eq!(items.lock().unwrap().get("server:https://h").map(String::as_str), Some("second"));
        assert!(bounded.get("server:https://h").is_err(), "still poisoned");
    }

    #[test]
    fn a_remove_after_a_timed_out_save_leaves_no_item() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        let items = Items::default();
        let (bounded, open) = slow(&items, Duration::from_millis(20));
        let held = lock_at(&path, Duration::from_secs(5)).unwrap();
        assert!(bounded.set(&held, "workspace:https://h/w/a", "late").is_err());
        drop(held);
        let release = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            open.send(()).unwrap();
        });
        let (logout, _) = memory(&items, IMPLICIT);
        let held = lock_at(&path, Duration::from_secs(10)).unwrap();
        assert!(logout.delete(&held, "workspace:https://h/w/a").unwrap(), "the late save landed first");
        release.join().unwrap();
        assert!(items.lock().unwrap().is_empty());
    }

    #[test]
    fn reads_take_no_lock_and_are_counted() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("credentials.toml");
        let items = Items::default();
        let (bounded, reads) = memory(&items, IMPLICIT);
        let held = lock_at(&path, Duration::from_secs(5)).unwrap();
        assert_eq!(bounded.get("server:https://h").unwrap(), None);
        bounded.set(&held, "server:https://h", "v").unwrap();
        assert_eq!(bounded.get("server:https://h").unwrap().as_deref(), Some("v"));
        assert!(bounded.delete(&held, "server:https://h").unwrap());
        assert!(!bounded.delete(&held, "server:https://h").unwrap());
        assert_eq!(reads.load(Ordering::SeqCst), 2);
    }

    const WS_URL: &str = "https://bd.example.com/w/proj";
    const SERVER: &str = "https://bd.example.com";
    const WORKSPACE: &str = "https://bd.example.com/w/proj";

    fn held(dir: &tempfile::TempDir) -> Held {
        lock_at(&dir.path().join("credentials.toml"), Duration::from_secs(5)).unwrap()
    }

    #[test]
    fn lookup_prefers_the_workspace_item() {
        let items = Items::default();
        let (store, reads) = memory(&items, IMPLICIT);
        assert!(lookup(&store, WS_URL).unwrap().is_none());
        assert_eq!(reads.load(Ordering::SeqCst), 2, "the workspace item, then the server's");

        put(&items, &account(Scope::Server, SERVER), &entry_for("bdt_server", credentials::SYSTEM_CA, None));
        let found = lookup(&store, WS_URL).unwrap().expect("the server's");
        assert_eq!(
            (found.key.as_str(), found.scope, found.entry.token.as_str()),
            (SERVER, Scope::Server, "bdt_server")
        );
        assert_eq!(reads.load(Ordering::SeqCst), 4, "a miss, then a hit");

        put(&items, &account(Scope::Workspace, WORKSPACE), &entry_for("bdt_ws", "sha256:ab", None));
        let found = lookup(&store, WS_URL).unwrap().expect("the workspace's");
        assert_eq!(
            (found.key.as_str(), found.scope, found.entry.ca.as_str()),
            (WORKSPACE, Scope::Workspace, "sha256:ab")
        );
        assert_eq!(found.entry.token, "bdt_ws");
        assert_eq!(lookup(&store, SERVER).unwrap().expect("a server URL").entry.token, "bdt_server");
        assert!(!format!("{found:?}").contains("bdt_"), "{found:?}");

        items.lock().unwrap().insert(account(Scope::Workspace, WORKSPACE), "not json bdt_x".into());
        let e = lookup(&store, WS_URL).unwrap_err();
        assert_eq!(e.to_string(), format!("memory keychain: the item workspace:{WORKSPACE} is not one bd wrote"));
    }

    #[test]
    fn a_server_save_drops_the_urls_workspace_item() {
        let dir = tempfile::tempdir().unwrap();
        let items = Items::default();
        let (store, _) = memory(&items, IMPLICIT);
        let held = held(&dir);
        let report = save(&held, &store, WS_URL, Scope::Workspace, entry_for("bdt_ws", "system", None)).unwrap();
        assert_eq!(report.key, WORKSPACE);
        assert!(report.replaced.is_none() && report.dropped.is_none());

        let report = save(&held, &store, WS_URL, Scope::Server, entry_for("bdt_one", "system", None)).unwrap();
        assert_eq!(report.key, SERVER);
        assert!(report.replaced.is_none());
        let dropped = report.dropped.expect("the workspace item would hide it");
        assert_eq!((dropped.key.as_str(), dropped.token.as_str(), dropped.signed_in), (WORKSPACE, "bdt_ws", true));
        assert!(get(&items, &account(Scope::Workspace, WORKSPACE)).is_none());

        let report = save(&held, &store, SERVER, Scope::Server, entry_for("bdt_two", "system", None)).unwrap();
        assert_eq!(report.replaced.expect("replaced").token, "bdt_one");
        assert_eq!(get(&items, &account(Scope::Server, SERVER)).unwrap().token, "bdt_two");

        let e = save(&held, &store, SERVER, Scope::Workspace, entry_for("bdt_x", "system", None)).unwrap_err();
        assert!(e.to_string().contains("not a workspace URL"), "{e}");
        let e = save(&held, &store, SERVER, Scope::Server, entry_for("two words", "system", None)).unwrap_err();
        assert_eq!(e.exit_code(), 2);
        assert_eq!(items.lock().unwrap().len(), 1, "nothing saved");
    }

    #[test]
    fn remove_takes_the_items_a_url_names() {
        let dir = tempfile::tempdir().unwrap();
        let items = Items::default();
        let (store, _) = memory(&items, IMPLICIT);
        let held = held(&dir);
        let seed = || {
            put(&items, &account(Scope::Server, SERVER), &entry_for("bdt_server", "system", None));
            put(&items, &account(Scope::Workspace, WORKSPACE), &entry_for("bdt_ws", "system", None));
        };
        let keys = |gone: &[Gone]| gone.iter().map(|g| g.key.clone()).collect::<Vec<_>>();

        seed();
        assert_eq!(keys(&remove(&held, &store, WS_URL, true).unwrap()), [WORKSPACE]);
        assert!(get(&items, &account(Scope::Server, SERVER)).is_some(), "--workspace-only keeps the server's");

        seed();
        assert_eq!(keys(&remove(&held, &store, WS_URL, false).unwrap()), [SERVER, WORKSPACE]);
        assert!(items.lock().unwrap().is_empty());
        assert!(remove(&held, &store, WS_URL, false).unwrap().is_empty(), "nothing left");

        seed();
        assert_eq!(keys(&remove(&held, &store, SERVER, false).unwrap()), [SERVER]);
        assert!(get(&items, &account(Scope::Workspace, WORKSPACE)).is_some(), "a server URL removes its own item");
        assert!(remove(&held, &store, SERVER, true).unwrap_err().to_string().contains("--workspace-only"));
    }

    #[test]
    fn renewals_keep_what_the_item_says_about_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let items = Items::default();
        let (store, _) = memory(&items, IMPLICIT);
        let held = held(&dir);
        let mut first = entry_for("bdt_one", "sha256:ab", None);
        first.role = Role::Write;
        put(&items, &account(Scope::Workspace, WORKSPACE), &first);

        let renewal = Renewal::new("bdr_two".into(), Duration::from_secs(3600));
        renewed(&held, &store, WORKSPACE, "bdt_two", Some(&renewal)).unwrap();
        let now = lookup_key(&store, WORKSPACE).unwrap().expect("kept");
        assert_eq!(now.scope, Scope::Workspace);
        assert_eq!(now.entry.token, "bdt_two");
        assert_eq!(now.entry.renewal(), Some(renewal));
        assert_eq!(
            (now.entry.ca.as_str(), now.entry.kind, now.entry.role, now.entry.signed_in),
            ("sha256:ab", Kind::Human, Role::Write, true)
        );

        renewed(&held, &store, WORKSPACE, "bdt_three", None).unwrap();
        let now = lookup_key(&store, WORKSPACE).unwrap().expect("kept");
        assert_eq!((now.entry.token.as_str(), now.entry.renewal()), ("bdt_three", None));

        assert!(store.delete(&held, &account(Scope::Workspace, WORKSPACE)).unwrap());
        assert!(lookup_key(&store, WORKSPACE).unwrap().is_none(), "gone once deleted");
        renewed(&held, &store, WORKSPACE, "bdt_four", None).unwrap();
        assert!(items.lock().unwrap().is_empty(), "a renewal does not bring back an item logged out of");

        put(&items, &account(Scope::Server, SERVER), &entry_for("bdt_s", "system", None));
        assert_eq!(lookup_key(&store, SERVER).unwrap().expect("the server's").scope, Scope::Server);
        assert!(lookup_key(&store, WORKSPACE).unwrap().is_none(), "a key names one item");
    }

    #[cfg(debug_assertions)]
    #[test]
    fn the_test_keychain_logs_each_operation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("keychain.json");
        let held = lock_at(&dir.path().join("credentials.toml"), Duration::from_secs(5)).unwrap();
        let file = path.clone();
        let store =
            Bounded::spawn(move || Ok(Box::new(FileStore { path: file }) as Box<dyn HumanStore>), EXPLICIT).unwrap();
        assert_eq!(store.get("server:https://h").unwrap(), None);
        store.set(&held, "server:https://h", "v").unwrap();
        assert_eq!(store.get("server:https://h").unwrap().as_deref(), Some("v"));
        assert!(store.delete(&held, "server:https://h").unwrap());
        let log = std::fs::read_to_string(dir.path().join("keychain.json.log")).unwrap();
        assert_eq!(log, "get server:https://h\nset server:https://h\nget server:https://h\ndelete server:https://h\n");

        std::fs::write(&path, "unavailable").unwrap();
        let e = store.get("server:https://h").unwrap_err();
        assert_eq!((e.exit_code(), e.to_string().as_str()), (2, "test keychain: unavailable"));
    }

    /// Needs a real, unlocked keychain: run by a person with `--ignored`.
    #[test]
    #[ignore]
    fn the_native_keychain_keeps_and_forgets_an_item() {
        let dir = tempfile::tempdir().unwrap();
        let held = lock_at(&dir.path().join("credentials.toml"), Duration::from_secs(5)).unwrap();
        let store = Bounded::spawn(native, EXPLICIT).unwrap();
        let account = format!("bd-test:{}", crate::tokens::random_hex(8).unwrap());
        assert_eq!(store.get(&account).unwrap(), None);
        store.set(&held, &account, "bdt_native_test").unwrap();
        assert_eq!(store.get(&account).unwrap().as_deref(), Some("bdt_native_test"));
        assert!(store.delete(&held, &account).unwrap());
        assert_eq!(store.get(&account).unwrap(), None);
        assert!(!store.delete(&held, &account).unwrap());
    }
}
