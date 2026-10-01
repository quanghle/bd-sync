//! Bundles: the playbook files a bd client sends, so `bd serve` runs the
//! playbooks of the client's checkout.
//!
//! The client resolves every reference against its own files, as a local run
//! would: the name or path on the command line, `extends` parents, and the
//! playbooks that steps `expand` (transitively, whatever their conditions). A
//! bundle holds the text of each file it read and how each reference
//! resolved. The server parses, validates and compiles from the bundle alone,
//! with every check and limit of a local run: it never interprets a client's
//! path or reads its own disk for one, and a reference the client did not
//! resolve is an error.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::{Deserialize, Serialize};

use super::loader::{Loader, default_name, is_json, parse_source};
use super::model::Playbook;
use crate::error::{Error, Result};

/// The bundle format this build writes and reads.
pub const BUNDLE_VERSION: u32 = 1;
/// Largest bundle, as JSON text.
pub const MAX_BUNDLE_BYTES: usize = 8 << 20;
/// Most files in one bundle.
pub const MAX_BUNDLE_FILES: usize = 256;
/// Largest file in a bundle. The server parses each one whole (a TOML file
/// takes many times its size in memory while it parses), so this bounds what
/// a client can make it hold.
pub const MAX_BUNDLE_FILE_BYTES: usize = 512 << 10;

/// The playbook files one command needs, and how the client resolved the
/// references between them.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    /// [`BUNDLE_VERSION`].
    pub version: u32,
    /// Each file read, by the client's path to it (shown in errors, and as
    /// the playbook's source).
    pub files: BTreeMap<String, BundleFile>,
    /// How references resolved: by the file holding them (`""` for the
    /// command line), then by reference, the path of the file it names.
    pub refs: BTreeMap<String, BTreeMap<String, String>>,
    /// The command line names a playbook the client found on its own path
    /// rather than in its checkout: the server's playbook of that name, if
    /// it has one, comes first.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub server_first: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleFile {
    /// The name its playbook gets when it does not set one (from the file name).
    pub name: String,
    pub format: Format,
    pub text: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    Toml,
    Json,
}

fn invalid(what: impl std::fmt::Display) -> Error {
    Error::invalid(format!("playbook bundle: {what}"))
}

fn too_large(bytes: usize) -> Error {
    invalid(format!("{bytes} bytes is more than the {} MiB a bundle may hold", MAX_BUNDLE_BYTES >> 20))
}

impl Bundle {
    /// Parse and check a bundle sent by a client.
    pub fn from_json(text: &str) -> Result<Bundle> {
        if text.len() > MAX_BUNDLE_BYTES {
            return Err(too_large(text.len()));
        }
        // The version first, so a newer format fails on it rather than on a field.
        #[derive(Deserialize)]
        struct Head {
            version: Option<u32>,
        }
        let head: Head = serde_json::from_str(text).map_err(invalid)?;
        if head.version != Some(BUNDLE_VERSION) {
            let found = head.version.map_or_else(|| "none".to_string(), |v| v.to_string());
            return Err(invalid(format!(
                "version {found} is not supported (this bd reads version {BUNDLE_VERSION}); run the same bd version on \
                 the client and the server"
            )));
        }
        let bundle: Bundle = serde_json::from_str(text).map_err(invalid)?;
        bundle.check()?;
        Ok(bundle)
    }

    /// The bundle as JSON; fails for one a server would refuse.
    pub fn to_json(&self) -> Result<String> {
        self.check()?;
        let text = serde_json::to_string(self)?;
        if text.len() > MAX_BUNDLE_BYTES {
            return Err(too_large(text.len()));
        }
        Ok(text)
    }

    fn check(&self) -> Result<()> {
        if self.files.len() > MAX_BUNDLE_FILES {
            return Err(invalid(format!("{} files is more than the {MAX_BUNDLE_FILES} allowed", self.files.len())));
        }
        if self.files.contains_key("") {
            return Err(invalid("a file without a path"));
        }
        if let Some((path, file)) = self.files.iter().find(|(_, f)| f.text.len() > MAX_BUNDLE_FILE_BYTES) {
            return Err(invalid(format!(
                "{path}: {} KiB is more than the {} KiB a playbook file sent to a bd server may hold",
                file.text.len() >> 10,
                MAX_BUNDLE_FILE_BYTES >> 10
            )));
        }
        Ok(())
    }
}

impl Loader {
    /// Everything `reference` needs, read as this loader resolves it, for
    /// [`Loader::from_bundle`] on a bd server: the playbook, the files it
    /// extends, and every playbook its steps expand (transitively, whatever
    /// their conditions). Fails where [`Loader::load_from`] would.
    pub fn bundle(&self, reference: &str, relative_to: Option<&Path>) -> Result<Bundle> {
        self.collect(reference, relative_to, true)
    }

    /// Like [`Loader::bundle`], for a playbook the server may not use (it
    /// prefers its own of that name): one that does not load is sent as it is,
    /// to fail on the server only if the server uses it.
    pub fn bundle_lenient(&self, reference: &str, relative_to: Option<&Path>) -> Result<Bundle> {
        self.collect(reference, relative_to, false)
    }

    fn collect(&self, reference: &str, relative_to: Option<&Path>, strict: bool) -> Result<Bundle> {
        let recorded = Arc::new(Mutex::new(Bundle { version: BUNDLE_VERSION, ..Default::default() }));
        let rec = Loader::recording(self.search_paths.clone(), recorded.clone());
        // A playbook that was read but does not load fails a run only if the
        // run uses it, as locally: send it as it is. Anything else (a file
        // that cannot be read, a path that cannot be sent, too many files)
        // fails here, so a bundle is never sent incomplete.
        let load = |path: &Path, lenient: bool| -> Result<Option<Arc<Playbook>>> {
            let loaded = rec.checked(path);
            if lock(&recorded).files.len() > MAX_BUNDLE_FILES {
                return Err(invalid(format!("more than {MAX_BUNDLE_FILES} files to send")));
            }
            match loaded {
                Ok(pb) => Ok(Some(pb)),
                Err(_) if lenient && lock(&recorded).files.contains_key(sendable(path)?) => Ok(None),
                Err(e) => Err(e),
            }
        };
        let root = rec.locate(reference, relative_to)?;
        let mut seen = HashSet::from([root.clone()]);
        let mut queue: Vec<Arc<Playbook>> = load(&root, !strict)?.into_iter().collect();
        while let Some(pb) = queue.pop() {
            for step in pb.all_steps() {
                let Some(target) = &step.expand else { continue };
                let path = rec.locate_ref(target, pb.source.as_deref())?;
                if seen.insert(path.clone()) {
                    queue.extend(load(&path, true)?);
                }
            }
        }
        let bundle = lock(&recorded).clone();
        bundle.check()?;
        Ok(bundle)
    }

    /// A loader that reads only `bundle`'s files and resolves references only
    /// as the client did.
    pub fn from_bundle(bundle: Bundle) -> Result<Loader> {
        bundle.check()?;
        Ok(Loader::of_sources(Sources { bundle }))
    }
}

/// A bundle's files on the server.
#[derive(Debug)]
pub(crate) struct Sources {
    bundle: Bundle,
}

/// A bundle path as its key. Bundle paths come from JSON strings, so they are UTF-8.
fn key_of(path: &Path) -> &str {
    path.to_str().unwrap_or_default()
}

impl Sources {
    /// The file `reference` names, held by the file `from` (`None`: the
    /// command line), as the client resolved it.
    pub(crate) fn resolve(&self, from: Option<&Path>, reference: &str) -> Result<PathBuf> {
        let from = from.map(key_of).unwrap_or_default();
        self.bundle.refs.get(from).and_then(|refs| refs.get(reference)).map(PathBuf::from).ok_or_else(|| {
            Error::not_found("playbook", format!("{reference} (not among the playbook files the client sent)"))
        })
    }

    /// The playbook in the file at `path`, without resolving `extends`.
    pub(crate) fn playbook(&self, path: &Path) -> Result<Playbook> {
        let key = key_of(path);
        let file = self
            .bundle
            .files
            .get(key)
            .ok_or_else(|| Error::invalid(format!("{key}: the client did not send this playbook file")))?;
        parse_source(&file.text, path, &file.name, file.format == Format::Json)
    }
}

/// A client path as it travels: as text.
fn sendable(path: &Path) -> Result<&str> {
    path.to_str().ok_or_else(|| {
        Error::invalid(format!("{}: playbook paths sent to a bd server must be valid UTF-8", path.display()))
    })
}

/// Note that `reference`, held by the file `from` (`None`: the command line), names `path`.
pub(crate) fn record_ref(bundle: &Mutex<Bundle>, from: Option<&Path>, reference: &str, path: &Path) -> Result<()> {
    let from = from.map(sendable).transpose()?.unwrap_or_default().to_string();
    let to = sendable(path)?.to_string();
    lock(bundle).refs.entry(from).or_default().insert(reference.to_string(), to);
    Ok(())
}

/// Note a file read, with its text.
pub(crate) fn record_file(bundle: &Mutex<Bundle>, path: &Path, text: &str) -> Result<()> {
    let key = sendable(path)?.to_string();
    let format = if is_json(path) { Format::Json } else { Format::Toml };
    lock(bundle).files.insert(key, BundleFile { name: default_name(path), format, text: text.to_string() });
    Ok(())
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::playbook::{
        MAX_DEPTH, MAX_INHERITED_BYTES, MAX_LOAD_WORK, MAX_PLANNING_WORK, RunRequest, compile, parse_json, parse_toml,
        to_toml,
    };
    use std::time::{Duration, Instant};

    fn write(dir: &Path, name: &str, text: &str) {
        let path = dir.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, text).unwrap();
    }

    fn request(vars: &[(&str, &str)]) -> RunRequest {
        RunRequest { vars: vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(), ..Default::default() }
    }

    fn key(path: &Path) -> String {
        path.to_str().unwrap().to_string()
    }

    #[test]
    fn a_bundle_loads_and_compiles_exactly_like_the_files() {
        let dir = tempfile::tempdir().unwrap();
        let pbs = dir.path().join("playbooks");
        write(
            &pbs,
            "base.toml",
            "description = \"Base\"\n[vars.target]\ndefault = \"staging\"\n[[steps]]\nid = \"build\"\n\
             [[steps]]\nid = \"deploy\"\ntitle = \"Deploy to {{target}}\"\nneeds = [\"build\"]\n",
        );
        write(
            &pbs,
            "checks.formula.toml",
            "[vars.suite]\nrequired = true\n[[steps]]\nid = \"lint\"\n\
             [[steps]]\nid = \"test\"\ntitle = \"Test {{suite}}\"\nneeds = [\"lint\"]\n[steps.gate]\ntype = \"human\"\n",
        );
        write(&pbs, "parts/extra.json", r#"{"steps": [{"id": "polish", "title": "Polish"}]}"#);
        write(&pbs, "broken.toml", "[[steps]]\nid = \"x\"\nbogus = 1\n");
        write(
            &pbs,
            "service.toml",
            "extends = \"base\"\n[vars.target]\ndefault = \"prod\"\n\
             [vars.extra]\ntype = \"bool\"\ndefault = \"false\"\n[vars.mode]\ndefault = \"normal\"\n\
             [[steps]]\nid = \"verify\"\nneeds = [\"build\"]\nexpand = \"checks\"\n\
             expand_vars = { suite = \"{{target}}-smoke\" }\n\
             [[steps]]\nid = \"deploy\"\ntitle = \"Ship to {{target}}\"\nneeds = [\"verify\"]\n\
             [[steps]]\nid = \"extra\"\nexpand = \"parts/extra.json\"\ncondition = \"{{extra}}\"\n\
             [[steps]]\nid = \"never\"\nexpand = \"broken\"\ncondition = \"{{mode}} == broken\"\n",
        );
        let disk = Loader::new(vec![pbs.clone()]);
        let pb = disk.load("service").unwrap();
        let plans: Vec<serde_json::Value> = ["false", "true"]
            .iter()
            .map(|extra| serde_json::to_value(compile(&pb, &request(&[("extra", extra)]), &disk).unwrap()).unwrap())
            .collect();

        let bundle = disk.bundle("service", None).unwrap();
        let held: Vec<&str> = bundle.files.keys().map(String::as_str).collect();
        let at = |name: &str| key(&pbs.join(name));
        let mut expected = vec![
            at("base.toml"),
            at("broken.toml"),
            at("checks.formula.toml"),
            at("parts/extra.json"),
            at("service.toml"),
        ];
        expected.sort();
        assert_eq!(held, expected, "every file a run may need, even one whose step is left out");
        assert_eq!(bundle.refs[""]["service"], at("service.toml"));
        assert_eq!(bundle.refs[&at("service.toml")]["parts/extra.json"], at("parts/extra.json"));
        assert_eq!(bundle.files[&at("parts/extra.json")].format, Format::Json);
        assert_eq!(bundle.files[&at("checks.formula.toml")].name, "checks");

        // The server never sees the client's disk.
        std::fs::rename(&pbs, dir.path().join("elsewhere")).unwrap();
        let sent = Bundle::from_json(&bundle.to_json().unwrap()).unwrap();
        assert_eq!(sent, bundle);
        let server = Loader::from_bundle(sent).unwrap();
        assert!(server.is_bundle());
        let again = server.load("service").unwrap();
        assert_eq!((to_toml(&again).unwrap(), &again.source), (to_toml(&pb).unwrap(), &pb.source));
        for (extra, plan) in ["false", "true"].iter().zip(&plans) {
            let compiled = compile(&again, &request(&[("extra", extra)]), &server).unwrap();
            assert_eq!(&serde_json::to_value(compiled).unwrap(), plan, "extra={extra}");
        }
        let err = compile(&again, &request(&[("mode", "broken")]), &server).unwrap_err().to_string();
        assert!(err.contains("broken.toml") && err.contains("bogus"), "fails only where a step expands it: {err}");
    }

    fn bundle(files: &[(&str, &str)], refs: &[(&str, &str, &str)]) -> Bundle {
        let mut b = Bundle { version: BUNDLE_VERSION, ..Default::default() };
        for (path, text) in files {
            let name = crate::playbook::name_of(Path::new(path)).unwrap_or_default();
            b.files.insert(path.to_string(), BundleFile { name, format: Format::Toml, text: text.to_string() });
        }
        for (from, reference, to) in refs {
            b.refs.entry(from.to_string()).or_default().insert(reference.to_string(), to.to_string());
        }
        b
    }

    #[test]
    fn a_bundle_resolves_only_what_the_client_sent() {
        let dir = tempfile::tempdir().unwrap();
        let secret = dir.path().join("secret.toml");
        std::fs::write(&secret, "[[steps]]\nid = \"leak\"\n").unwrap();
        let secret = key(&secret);

        // A reference naming a file on the server's disk that the bundle does not hold.
        let server = Loader::from_bundle(bundle(&[], &[("", "secret", &secret)])).unwrap();
        let err = server.load("secret").unwrap_err().to_string();
        assert!(err.contains("did not send"), "{err}");
        for reference in [secret.as_str(), "../../etc/passwd.toml", "/etc/hosts", "other"] {
            let err = server.load(reference).unwrap_err();
            assert_eq!(err.exit_code(), 3, "{reference}: {err}");
            assert!(err.to_string().contains("not among the playbook files the client sent"), "{err}");
        }

        // References inside a file resolve only through the bundle, never through search paths.
        let server = Loader::from_bundle(bundle(
            &[("a.toml", "extends = \"secret\"\n[[steps]]\nid = \"a\"\n")],
            &[("", "a", "a.toml")],
        ))
        .unwrap();
        let err = server.load("a").unwrap_err().to_string();
        assert!(err.contains("secret (not among the playbook files the client sent)"), "{err}");

        let cyclic = Loader::from_bundle(bundle(
            &[
                ("a.toml", "extends = \"b\"\n[[steps]]\nid = \"a\"\n"),
                ("b.toml", "extends = \"a\"\n[[steps]]\nid = \"b\"\n"),
            ],
            &[("", "a", "a.toml"), ("a.toml", "b", "b.toml"), ("b.toml", "a", "a.toml")],
        ))
        .unwrap();
        assert!(cyclic.load("a").unwrap_err().to_string().contains("circular extends"));

        let bad_gate = Loader::from_bundle(bundle(
            &[("g.toml", "[[steps]]\nid = \"merge\"\n[steps.gate]\ntype = \"gh:pr\"\nawait_id = \"main\"\n")],
            &[("", "g", "g.toml")],
        ))
        .unwrap();
        let err = bad_gate.load("g").unwrap_err().to_string();
        assert!(err.contains("g.toml") && err.contains("pull request number"), "{err}");
    }

    #[test]
    fn bundles_have_a_version_and_limits() {
        let err = |text: &str| Bundle::from_json(text).unwrap_err().to_string();
        assert!(err(r#"{"version": 2, "files": {}, "refs": {}, "new": 1}"#).contains("version 2 is not supported"));
        assert!(err(r#"{"files": {}, "refs": {}}"#).contains("version none"));
        assert!(err(r#"{"version": 1, "files": {}, "refs": {}, "new": 1}"#).contains("unknown field"));
        assert!(err("[1]").contains("playbook bundle"));
        assert!(err(&format!("{{\"version\": 1, \"pad\": \"{}\"}}", "x".repeat(MAX_BUNDLE_BYTES))).contains("MiB"));
        assert!(
            err(r#"{"version": 1, "files": {"": {"name": "x", "format": "toml", "text": ""}}, "refs": {}}"#)
                .contains("without a path")
        );

        let names: Vec<String> = (0..=MAX_BUNDLE_FILES).map(|n| format!("p{n}.toml")).collect();
        let files: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), "")).collect();
        let many = bundle(&files, &[]);
        assert!(many.to_json().unwrap_err().to_string().contains("files"));
        assert!(err(&serde_json::to_string(&many).unwrap()).contains("files"));
        let big = bundle(&[("big.toml", &"#".repeat(MAX_BUNDLE_FILE_BYTES + 1))], &[]);
        assert!(big.to_json().unwrap_err().to_string().contains("big.toml"), "the client checks before sending");
        let file = "#".repeat(MAX_BUNDLE_FILE_BYTES);
        let names: Vec<String> =
            (0..MAX_BUNDLE_BYTES / MAX_BUNDLE_FILE_BYTES + 1).map(|n| format!("p{n}.toml")).collect();
        let files: Vec<(&str, &str)> = names.iter().map(|n| (n.as_str(), file.as_str())).collect();
        assert!(bundle(&files, &[]).to_json().unwrap_err().to_string().contains("8 MiB"));
    }

    /// A loader over `(name, text)` files in which every name resolves from
    /// anywhere, like one search directory.
    fn library(files: &[(String, String)]) -> Loader {
        let mut b = Bundle { version: BUNDLE_VERSION, ..Default::default() };
        for (name, text) in files {
            b.files.insert(
                format!("{name}.toml"),
                BundleFile { name: name.clone(), format: Format::Toml, text: text.clone() },
            );
        }
        let contexts: Vec<String> = std::iter::once(String::new()).chain(b.files.keys().cloned()).collect();
        for from in contexts {
            let refs = b.refs.entry(from).or_default();
            for (name, _) in files {
                refs.insert(name.clone(), format!("{name}.toml"));
            }
        }
        Loader::from_bundle(b).unwrap()
    }

    #[test]
    fn a_diamond_of_extends_is_merged_once() {
        // Each level's two files extend both files of the next level: resolving
        // every path separately would take 2^60 merges.
        let levels = 60;
        let mut files =
            vec![("root".to_string(), "extends = [\"l0a\", \"l0b\"]\n[[steps]]\nid = \"go\"\n".to_string())];
        for l in 0..levels {
            for side in ["a", "b"] {
                let text = if l + 1 < levels {
                    format!("extends = [\"l{0}a\", \"l{0}b\"]\n", l + 1)
                } else {
                    format!("[vars.bottom_{side}]\ndefault = \"x\"\n")
                };
                files.push((format!("l{l}{side}"), text));
            }
        }
        let started = Instant::now();
        let pb = library(&files).load("root").unwrap();
        assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
        assert_eq!(pb.vars.keys().collect::<Vec<_>>(), ["bottom_a", "bottom_b"]);

        // Inherited steps and variables are work: a wide fan-out is refused, not ground through.
        let vars: String = (0..150).map(|n| format!("[vars.v{n}]\n")).collect();
        let parents: Vec<String> = (0..200).map(|n| format!("\"p{n}\"")).collect();
        let mut files =
            vec![("root".to_string(), format!("extends = [{}]\n[[steps]]\nid = \"go\"\n", parents.join(", ")))];
        files.extend((0..200).map(|n| (format!("p{n}"), vars.clone())));
        let err = library(&files).load("root").unwrap_err().to_string();
        assert!(err.contains(&format!("more than {MAX_LOAD_WORK} steps and variables")), "{err}");
    }

    #[test]
    fn a_chain_of_extends_shares_what_it_inherits() {
        // 190 files of one large step, each extending the one before (7.6 MB in
        // all): copying what every level inherits would hold 18,145 such steps.
        let text = "x".repeat(40_000);
        let mut files = vec![(
            "l0".to_string(),
            format!("description = \"base\"\n[[steps]]\nid = \"s0\"\ndescription = \"{text}\"\n"),
        )];
        for n in 1..190 {
            let pb = format!("extends = [\"l{}\"]\n[[steps]]\nid = \"s{n}\"\ndescription = \"{text}\"\n", n - 1);
            files.push((format!("l{n}"), pb));
        }
        let loader = library(&files);
        let top = loader.load("l189").unwrap();
        assert_eq!((top.steps.len(), top.description.as_str()), (190, "base"));
        // Each level kept by the loader holds the first file's step itself, not a copy of it.
        let first = loader.checked(Path::new("l0.toml")).unwrap();
        assert!(Arc::ptr_eq(&top.steps[0], &first.steps[0]));
        assert!(Arc::strong_count(&first.steps[0]) > 190, "{}", Arc::strong_count(&first.steps[0]));

        // What a merge does copy is counted: a large description, or many
        // labels, inherited by every level of a chain.
        for (base, levels) in [
            (format!("description = \"{}\"\n", "x".repeat(400_000)), 49),
            (format!("labels = [{}]\n", vec!["\"l\""; 20_000].join(", ")), 30),
        ] {
            let mut files = vec![("c0".to_string(), format!("{base}[[steps]]\nid = \"s\"\n"))];
            files.extend((1..=levels).map(|n| (format!("c{n}"), format!("extends = [\"c{}\"]\n", n - 1))));
            let err = library(&files).load(&format!("c{levels}")).unwrap_err().to_string();
            let limit = format!("copies more than {} MiB of descriptions, titles, labels", MAX_INHERITED_BYTES >> 20);
            assert!(err.contains(&limit), "{err}");
            let half = levels / 2;
            library(&files[..=half]).load(&format!("c{half}")).unwrap();
        }
    }

    #[test]
    fn iterations_a_condition_leaves_out_are_work_too() {
        // 300 iterations, each expanding a playbook whose 2,000-iteration loop
        // a condition always leaves out, with a large variable to copy.
        let inner = format!(
            "[vars.pad]\ndefault = \"{}\"\n[[steps]]\nid = \"skip\"\ncondition = \"0\"\n[steps.loop]\ncount = 2000\n",
            "x".repeat(200_000)
        );
        let outer = "[[steps]]\nid = \"fan\"\nexpand = \"inner\"\n[steps.loop]\ncount = 300\n";
        let loader = library(&[("outer".into(), outer.into()), ("inner".into(), inner)]);
        let pb = loader.load("outer").unwrap();
        let started = Instant::now();
        let err = compile(&pb, &RunRequest::default(), &loader).unwrap_err().to_string();
        assert!(err.contains(&format!("more than {MAX_PLANNING_WORK} units of work")), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10), "{:?}", started.elapsed());
    }

    #[test]
    fn a_client_sends_every_playbook_a_run_may_expand() {
        // One of 30 large playbooks, chosen by a variable, each extending a
        // small base: far more than one command loads, all of it sent.
        let dir = tempfile::tempdir().unwrap();
        let pbs = dir.path().join("playbooks");
        write(&pbs, "base.toml", "[vars.owner]\ndefault = \"ops\"\n[[steps]]\nid = \"prepare\"\n");
        let steps: String = (0..900).map(|n| format!("[[steps]]\nid = \"s{n}\"\nneeds = [\"prepare\"]\n")).collect();
        let mut root = String::from("[vars.pick]\nrequired = true\n");
        for t in 0..30 {
            write(&pbs, &format!("t{t}.toml"), &format!("extends = \"base\"\n{steps}"));
            root.push_str(&format!(
                "[[steps]]\nid = \"run-t{t}\"\nexpand = \"t{t}\"\ncondition = \"{{{{pick}}}} == t{t}\"\n"
            ));
        }
        write(&pbs, "root.toml", &root);
        let disk = Loader::new(vec![pbs.clone()]);
        let bundle = disk.bundle("root", None).unwrap();
        assert_eq!(bundle.files.len(), 32, "the root, every target, and the base");
        for t in 0..30 {
            let target = key(&pbs.join(format!("t{t}.toml")));
            assert_eq!(bundle.refs[&target]["base"], key(&pbs.join("base.toml")), "t{t}");
        }
        let local = compile(&disk.load("root").unwrap(), &request(&[("pick", "t29")]), &disk).unwrap();
        let server = Loader::from_bundle(Bundle::from_json(&bundle.to_json().unwrap()).unwrap()).unwrap();
        let remote = compile(&server.load("root").unwrap(), &request(&[("pick", "t29")]), &server).unwrap();
        assert_eq!(serde_json::to_value(&remote).unwrap(), serde_json::to_value(&local).unwrap());
        assert_eq!(remote.issues.len(), 1 + 1 + 900, "the group, prepare, and the steps");

        // A file that cannot be read is an error, never a gap in the bundle.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let locked = pbs.join("t7.toml");
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
            if std::fs::read(&locked).is_err() {
                let err = disk.bundle("root", None).unwrap_err().to_string();
                assert!(err.contains("t7.toml"), "{err}");
            }
            std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
    }

    #[test]
    fn oversized_files_fail_before_they_are_in_memory() {
        let steps: Vec<String> = (0..15_000).map(|n| format!("{{\"id\":\"s{n}\"}}")).collect();
        let json = format!("{{\"steps\":[{}]}}", steps.join(","));
        let toml: String = (0..10_000).map(|n| format!("[[steps]]\nid = \"s{n}\"\n")).collect();
        for err in
            [parse_json(&json, "big.json", "big").unwrap_err(), parse_toml(&toml, "big.toml", "big").unwrap_err()]
        {
            assert!(err.to_string().contains("more than 2000 steps"), "counted while parsing: {err}");
        }
        let children: Vec<String> = (0..2_001).map(|n| format!("{{\"id\":\"c{n}\"}}")).collect();
        let nested = format!("{{\"steps\":[{{\"id\":\"g\",\"children\":[{}]}}]}}", children.join(","));
        assert!(parse_json(&nested, "n.json", "n").unwrap_err().to_string().contains("more than 2000 steps"));

        // Long text is fine in a file of one's own; a server takes files of a bounded size.
        let wordy = format!("[[steps]]\nid = \"a\"\ndescription = \"{}\"\n", "x".repeat(MAX_BUNDLE_FILE_BYTES));
        assert!(parse_toml(&wordy, "wordy.toml", "wordy").is_ok());
        let err = Loader::from_bundle(bundle(&[("wordy.toml", &wordy)], &[])).unwrap_err().to_string();
        assert!(err.contains("wordy.toml") && err.contains("512 KiB"), "{err}");
    }

    /// A playbook of `levels` steps nested in one another; `innermost` adds to the deepest.
    fn nested(levels: usize, innermost: &str) -> String {
        let mut text = String::new();
        for l in 0..levels {
            let table: Vec<&str> = std::iter::once("steps").chain(std::iter::repeat_n("children", l)).collect();
            text.push_str(&format!("[[{}]]\nid = \"n{l}\"\n", table.join(".")));
        }
        text + innermost
    }

    #[test]
    fn nesting_is_bounded_across_expansions() {
        let err = parse_toml(&nested(MAX_DEPTH + 1, ""), "deep.toml", "deep").unwrap().validate().unwrap_err();
        assert!(err.to_string().contains(&format!("nested more than {MAX_DEPTH} levels")), "{err}");

        let chained = |sizes: &[usize]| -> Vec<(String, String)> {
            sizes
                .iter()
                .enumerate()
                .map(|(n, levels)| {
                    let next = if n + 1 < sizes.len() { format!("expand = \"p{}\"\n", n + 1) } else { String::new() };
                    (format!("p{n}"), nested(*levels, &next))
                })
                .collect()
        };
        let run = |files: Vec<(String, String)>| {
            let loader = library(&files);
            let pb = loader.load("p0").unwrap();
            compile(&pb, &RunRequest::default(), &loader)
        };
        let err = run(chained(&[20, 13])).unwrap_err().to_string();
        assert!(err.contains("more than 32 levels deep, counting expansions"), "{err}");

        // The deepest shape allowed, 8 playbooks deep, fits a server thread's stack.
        let deepest = chained(&[4; 8]);
        let compiled = std::thread::Builder::new()
            .stack_size(2 << 20)
            .spawn(move || run(deepest).map(|plan| plan.issues.len()))
            .unwrap()
            .join()
            .unwrap();
        assert_eq!(compiled.unwrap(), 32);
    }
}
