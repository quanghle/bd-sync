use super::*;
use crate::events::EventQuery;
use crate::{InitOptions, OpenOptions as StoreOptions, Queries, Store};

const PLAYBOOK: &str = "description = \"Ship it\"\n[[steps]]\nid = \"a\"\ntitle = \"A\"\n";
const SKILL: &str = "---\nname: deploy\ndescription: Deploy\n---\nRun it.\n";

fn text(t: &str) -> AgentFile {
    AgentFile { text: Some(t.into()), ..Default::default() }
}

fn link(target: &str) -> AgentFile {
    AgentFile { symlink: Some(target.into()), ..Default::default() }
}

/// A bundle with one playbook and one claude skill.
fn bundle() -> PublishBundle {
    let mut b = PublishBundle::new(vec![Area::Playbooks, Area::Agents]);
    b.playbooks.insert("ship.toml".into(), PLAYBOOK.into());
    b.agents.entry(Harness::Claude).or_default().insert("skills/deploy/SKILL.md".into(), text(SKILL));
    b
}

/// A workspace's `.bd` directory with a database.
fn workspace() -> (tempfile::TempDir, PathBuf, Store) {
    let tmp = tempfile::tempdir().unwrap();
    let db_dir = tmp.path().join(".bd");
    std::fs::create_dir_all(&db_dir).unwrap();
    let init = InitOptions { prefix: "t".into(), id_mode: Default::default() };
    let store = Store::init(&db_dir.join("bd.db"), init, StoreOptions::default()).unwrap();
    (tmp, db_dir, store)
}

fn opts() -> Options {
    Options { wait: Duration::from_millis(50), allow_empty: false }
}

fn publish(db_dir: &Path, store: &mut Store, b: PublishBundle) -> Result<Prepared> {
    let mut p = prepare(db_dir, Source::Bundle(b), &opts())?;
    p.apply()?;
    store.write("publish", "admin", |tx| p.record(tx))?;
    p.finish();
    Ok(p)
}

fn check_err(b: &PublishBundle) -> String {
    b.check().unwrap_err().to_string()
}

fn no_staging(db_dir: &Path) -> bool {
    std::fs::read_dir(db_dir).unwrap().all(|e| !e.unwrap().file_name().to_string_lossy().starts_with(STAGING_PREFIX))
}

fn read(path: &Path) -> String {
    std::fs::read_to_string(path).unwrap()
}

#[test]
fn bundles_round_trip_and_refuse_unknown_fields_and_versions() {
    let b = bundle();
    let json = b.to_json().unwrap();
    assert_eq!(PublishBundle::from_json(&json).unwrap(), b);
    let mut v: serde_json::Value = serde_json::from_str(&json).unwrap();
    v["extra"] = 1.into();
    assert!(PublishBundle::from_json(&v.to_string()).unwrap_err().to_string().contains("unknown field"));
    v.as_object_mut().unwrap().remove("extra");
    v["agents"]["claude"]["skills/deploy/SKILL.md"]["mode"] = "x".into();
    assert!(PublishBundle::from_json(&v.to_string()).unwrap_err().to_string().contains("unknown field"));
    v["version"] = 2.into();
    let e = PublishBundle::from_json(&v.to_string()).unwrap_err().to_string();
    assert!(e.contains("version 2 is not supported"), "{e}");
    let e = PublishBundle::from_json(&serde_json::json!({"version": 1, "areas": ["nope"]}).to_string()).unwrap_err();
    assert_eq!(e.exit_code(), 2, "{e}");
    // An area left out holds nothing.
    let mut only = bundle();
    only.areas = vec![Area::Agents];
    assert!(check_err(&only).contains("holds playbooks files but does not publish playbooks"));
    let mut bad = bundle();
    bad.source.commit = Some("HEAD; rm -rf /".into());
    assert!(check_err(&bad).contains("source commit"));
    let mut both = bundle();
    both.agents
        .get_mut(&Harness::Claude)
        .unwrap()
        .insert("mcp.json".into(), AgentFile { text: Some("{}".into()), symlink: Some("x".into()), executable: false });
    assert!(check_err(&both).contains("exactly one"));
}

#[test]
fn bundle_caps_hold_at_the_limit_and_refuse_past_it() {
    // One file at the per-file limit is fine; one byte more is not.
    let mut b = bundle();
    b.playbooks.insert("big.toml".into(), format!("#{}", "x".repeat(MAX_PUBLISH_FILE_BYTES - 1)));
    b.check().unwrap();
    b.playbooks.insert("big.toml".into(), "x".repeat(MAX_PUBLISH_FILE_BYTES + 1));
    assert!(check_err(&b).contains("playbooks/big.toml: 513 KiB is more than the 512 KiB"), "{}", check_err(&b));

    // Files: the bundle's total and a set's own.
    let mut b = PublishBundle::new(vec![Area::Playbooks]);
    for i in 0..MAX_PUBLISH_FILES {
        b.playbooks.insert(format!("p{i}.toml"), "x".into());
    }
    b.check().unwrap();
    b.playbooks.insert("one-more.toml".into(), "x".into());
    assert!(check_err(&b).contains("1025 files is more than the 1024"));
    let mut b = PublishBundle::new(vec![Area::Agents]);
    let set = b.agents.entry(Harness::Codex).or_default();
    for i in 0..=MAX_SET_FILES {
        set.insert(format!("skills/s{i}/SKILL.md"), text("x"));
    }
    assert!(check_err(&b).contains("agents/codex: 257 files is more than the 256 a set may hold"));

    // A set's text.
    let mut b = PublishBundle::new(vec![Area::Agents]);
    let set = b.agents.entry(Harness::Claude).or_default();
    for i in 0..=(MAX_SET_BYTES / MAX_PUBLISH_FILE_BYTES) {
        set.insert(format!("skills/s{i}/SKILL.md"), text(&"x".repeat(MAX_PUBLISH_FILE_BYTES)));
    }
    assert!(check_err(&b).contains("more than the 8 MiB of text a set may hold"));

    // The JSON as a whole, before it is parsed.
    let huge = format!("{{\"version\": 1, \"pad\": \"{}\"}}", "x".repeat(MAX_PUBLISH_BYTES));
    assert!(PublishBundle::from_json(&huge).unwrap_err().to_string().contains("more than the 16 MiB"));
    // NUL is not text.
    let mut b = bundle();
    b.playbooks.insert("zero.toml".into(), "a\0b".into());
    assert!(check_err(&b).contains("playbooks/zero.toml: holds NUL"), "{}", check_err(&b));
}

#[test]
fn every_path_rule_refuses_before_anything_is_written() {
    let cases = [
        ("../escape.toml", "'..'"),
        ("a/../../escape.toml", "'..'"),
        ("/etc/passwd.toml", "an absolute path"),
        ("a\\b.toml", "a backslash"),
        ("C:/x.toml", "':'"),
        ("C:x.toml", "':'"),
        (".hidden.toml", "starts with '.'"),
        ("dir/.git/x.toml", "starts with '.'"),
        ("./x.toml", "starts with '.'"),
        ("a//b.toml", "an empty component"),
        ("con.toml", "a device name"),
        ("sub/LPT1.toml", "a device name"),
        ("a\nb.toml", "control character"),
        ("a\u{1b}[31m.toml", "control character"),
        ("nul\0.toml", "control character"),
        ("what?.toml", "Windows does not allow"),
        ("trailing ./x.toml", "ends with a space or '.'"),
        ("1/2/3/4/5/6/7/8/9/10/11/12/13.toml", "levels deep"),
        ("", "an empty path"),
    ];
    for (path, why) in cases {
        let mut b = PublishBundle::new(vec![Area::Playbooks]);
        b.playbooks.insert(path.into(), PLAYBOOK.into());
        let e = b.check().unwrap_err();
        assert_eq!(e.exit_code(), 2);
        assert!(e.to_string().contains(why), "{path:?}: {e}");
        assert!(e.to_string().starts_with("playbooks/"), "names the file: {e}");
    }
    let long = format!("{}.toml", "a".repeat(MAX_COMPONENT_BYTES));
    assert!(check_path(&long).unwrap_err().contains("longer than"));
    assert!(check_path(&"a/".repeat(300)).unwrap_err().contains("bytes is more than"));
    let mut b = PublishBundle::new(vec![Area::Playbooks]);
    b.playbooks.insert("README.md".into(), "x".into());
    assert!(check_err(&b).contains("not a playbook file"));
    // Layout: a file that is also a directory, and names apart only in case.
    let mut b = PublishBundle::new(vec![Area::Playbooks]);
    b.playbooks.insert("a.toml".into(), "x".into());
    b.playbooks.insert("a.toml/b.toml".into(), "x".into());
    assert!(check_err(&b).contains("both a file and a directory"));
    let mut b = PublishBundle::new(vec![Area::Playbooks]);
    b.playbooks.insert("Ship.toml".into(), "x".into());
    b.playbooks.insert("ship.toml".into(), "x".into());
    assert!(check_err(&b).contains("differ only in case"));
    // Agent paths too, named under their set.
    let mut b = PublishBundle::new(vec![Area::Agents]);
    b.agents.entry(Harness::Copilot).or_default().insert("skills/../../../x".into(), text("x"));
    assert!(check_err(&b).starts_with("agents/copilot/skills/../../../x: invalid path: '..'"), "{}", check_err(&b));
}

#[test]
fn symlinks_stay_inside_the_agent_sets() {
    let ok = |path: &str, target: &str| {
        let mut b = bundle();
        b.agents.get_mut(&Harness::Claude).unwrap().insert(path.into(), link(target));
        b.check()
    };
    ok("skills/alias", "deploy").unwrap();
    ok("skills/alias/SKILL.md", "../deploy/SKILL.md").unwrap();
    // Another harness's set is inside agents/ too: one skill shared between harnesses.
    ok("skills/x", "../../codex/skills/deploy").unwrap();
    ok("skills/deploy/shared.md", "../../../copilot/shared.md").unwrap();
    for (path, target, why) in [
        ("skills/x", "../../../etc", "leading outside agents/"),
        ("skills/x", "../../../../bd.db", "leading outside agents/"),
        ("skills/x", "/etc/passwd", "an absolute target"),
        ("skills/x", "..\\..\\x", "not '/'-separated"),
        ("skills/x", "C:/x", "an absolute target"),
        ("skills/x", "..", "a set's own directory"),
        ("skills/x", "../..", "leads to agents/"),
        ("skills/x", "", "an empty target"),
        ("skills/x", "a//b", "an empty component"),
        ("skills/x", ".hidden", "hidden name"),
    ] {
        let e = ok(path, target).unwrap_err().to_string();
        assert!(e.contains(why), "{target:?}: {e}");
        assert!(e.starts_with("agents/claude/skills/x: "), "{e}");
    }
    // A symlink on the way to another path would let a write pass through it.
    let mut b = bundle();
    let set = b.agents.get_mut(&Harness::Claude).unwrap();
    set.insert("skills/alias".into(), link("deploy"));
    set.insert("skills/alias/extra.md".into(), text("x"));
    assert!(check_err(&b).contains("both a file and a directory"));
    let mut b = bundle();
    b.agents
        .get_mut(&Harness::Claude)
        .unwrap()
        .insert("skills/x".into(), AgentFile { symlink: Some("deploy".into()), executable: true, text: None });
    assert!(check_err(&b).contains("no executable bit"));
}

#[test]
fn a_publish_mirrors_the_source_records_one_event_and_the_new_revisions() {
    let (_tmp, db_dir, mut store) = workspace();
    // Hidden entries in the areas are left alone.
    std::fs::create_dir_all(db_dir.join("playbooks")).unwrap();
    std::fs::write(db_dir.join("playbooks/.keep"), "x").unwrap();
    std::fs::write(db_dir.join("playbooks/old.toml"), PLAYBOOK).unwrap();

    let mut b = bundle();
    b.source = SourceInfo { commit: Some("ab".repeat(20)), dirty: Some(true) };
    b.playbooks.insert("lib/base.toml".into(), PLAYBOOK.into());
    let set = b.agents.get_mut(&Harness::Claude).unwrap();
    set.insert("skills/deploy/run.sh".into(), AgentFile { executable: true, ..text("#!/bin/sh\n") });
    set.insert("mcp.json".into(), text(r#"{"mcpServers": {"gh": {"command": "npx"}}}"#));
    let p = publish(&db_dir, &mut store, b).unwrap();

    assert_eq!(read(&db_dir.join("playbooks/ship.toml")), PLAYBOOK);
    assert_eq!(read(&db_dir.join("playbooks/lib/base.toml")), PLAYBOOK);
    assert!(!db_dir.join("playbooks/old.toml").exists(), "the server mirrors the source");
    assert!(db_dir.join("playbooks/.keep").exists(), "hidden entries are left alone");
    let set = AgentSet::load(&db_dir.join(AGENTS_DIR), Harness::Claude).unwrap();
    assert_eq!(set.revision, p.revisions[&Harness::Claude]);
    assert_eq!(set.skills["deploy"]["run.sh"].executable, cfg!(unix));
    assert_eq!(set.mcp_servers.keys().collect::<Vec<_>>(), ["gh"]);
    let pb = &p.plans[0];
    assert_eq!((pb.area, pb.added, pb.changed, pb.removed, pb.unchanged), (Area::Playbooks, 2, 0, 1, 0));
    // Once done, no staging directory is left; the old areas are kept.
    drop(p);
    assert!(no_staging(&db_dir));
    assert_eq!(read(&db_dir.join(PREV_DIR).join("playbooks/old.toml")), PLAYBOOK);
    assert!(!db_dir.join(PREV_DIR).join("playbooks/.keep").exists(), "hidden entries are not kept");

    let events = store.read(|r| r.events(&EventQuery { since: Some(0), ..Default::default() })).unwrap().events;
    let published: Vec<_> = events.iter().filter(|e| e.op == PUBLISHED).collect();
    assert_eq!(published.len(), 1);
    let e = published[0];
    assert_eq!((e.actor.as_str(), e.issue_id.as_deref()), ("admin", None));
    let data: Published = serde_json::from_value(e.data.clone()).unwrap();
    assert!(!data.rollback);
    assert_eq!(data.source.commit.as_deref(), Some("ab".repeat(20).as_str()));
    assert_eq!(data.areas[&Area::Playbooks].files["ship.toml"], sha256_hex(PLAYBOOK.as_bytes()));
    assert_eq!(data.areas[&Area::Playbooks].removed, 1);
    assert_eq!(data.areas[&Area::Agents].files["claude/skills/deploy/SKILL.md"], sha256_hex(SKILL.as_bytes()));
    assert_eq!(data.revisions[&Harness::Claude], set.revision);
    let changed: Vec<_> = events.iter().filter(|ev| ev.op == agents::AGENTS_CHANGED).collect();
    assert_eq!(changed.len(), 2, "the claude set and the playbooks changed, the other sets stayed empty");
    assert!(changed.iter().all(|c| c.tx == e.tx), "one transaction");
    assert_eq!(changed[0].data["revision"], set.revision.as_str());
    let playbooks = agents::PlaybookSet::load(&db_dir.join(PLAYBOOKS_DIR)).unwrap();
    assert_eq!(changed[1].data["area"], agents::PLAYBOOKS_AREA);
    assert_eq!(
        changed[1].data["revision"],
        playbooks.revision.as_str(),
        "as `bd agents manifest --playbooks` serves it"
    );
}

#[test]
fn publishing_the_same_source_again_changes_nothing() {
    let (_tmp, db_dir, mut store) = workspace();
    publish(&db_dir, &mut store, bundle()).unwrap();
    let before = scan(&db_dir.join(PLAYBOOKS_DIR)).unwrap();
    let p = publish(&db_dir, &mut store, bundle()).unwrap();
    for plan in &p.plans {
        assert_eq!((plan.added, plan.changed, plan.removed), (0, 0, 0), "{plan:?}");
        assert!(plan.unchanged > 0);
    }
    assert_eq!(scan(&db_dir.join(PLAYBOOKS_DIR)).unwrap(), before);
    let events = store.read(|r| r.events(&EventQuery { since: Some(0), ..Default::default() })).unwrap().events;
    assert_eq!(events.iter().filter(|e| e.op == PUBLISHED).count(), 2);
    assert_eq!(events.iter().filter(|e| e.op == agents::AGENTS_CHANGED).count(), 2, "the revisions did not change");
}

#[test]
fn validation_failures_name_the_file_and_change_nothing() {
    let (_tmp, db_dir, mut store) = workspace();
    publish(&db_dir, &mut store, bundle()).unwrap();
    let before = (scan(&db_dir.join(PLAYBOOKS_DIR)).unwrap(), scan(&db_dir.join(AGENTS_DIR)).unwrap());

    let mut bad_playbook = bundle();
    bad_playbook.playbooks.insert("broken.toml".into(), "[[steps]]\nid = \"a\"\nbogus = 1\n".into());
    let mut bad_skill = bundle();
    bad_skill.agents.get_mut(&Harness::Claude).unwrap().insert("skills/nodoc/README.md".into(), text("x"));
    let mut bad_mcp = bundle();
    bad_mcp.agents.get_mut(&Harness::Claude).unwrap().insert("mcp.json".into(), text(r#"{"hooks": {}}"#));
    let mut missing_parent = bundle();
    missing_parent.playbooks.insert("child.toml".into(), format!("extends = [\"nowhere\"]\n{PLAYBOOK}"));
    for (b, names) in [
        (bad_playbook, "playbooks/broken.toml"),
        (bad_skill, "agents/claude/skills/nodoc: no SKILL.md"),
        (bad_mcp, "agents/claude/mcp.json"),
        (missing_parent, "playbooks/child.toml"),
    ] {
        let e = prepare(&db_dir, Source::Bundle(b), &opts()).err().expect("refused");
        assert_eq!(e.exit_code(), 2, "{e}");
        let msg = e.to_string();
        assert!(msg.contains(names), "{msg}");
        assert!(!msg.contains(STAGING_PREFIX) && !msg.contains(&*db_dir.to_string_lossy()), "no server paths: {msg}");
    }
    assert_eq!((scan(&db_dir.join(PLAYBOOKS_DIR)).unwrap(), scan(&db_dir.join(AGENTS_DIR)).unwrap()), before);
    assert!(no_staging(&db_dir), "staging removed");
}

#[test]
fn playbook_references_stay_in_the_published_tree() {
    let (_tmp, db_dir, _store) = workspace();
    // A file next to the playbooks that a reference could reach.
    std::fs::write(db_dir.join("secret.toml"), PLAYBOOK).unwrap();
    for refs in
        ["extends = [\"../secret.toml\"]", "extends = [\"../../.bd/secret.toml\"]", "extends = [\"/etc/hosts.toml\"]"]
    {
        let mut b = bundle();
        b.playbooks.insert("child.toml".into(), format!("{refs}\n{PLAYBOOK}"));
        let e = prepare(&db_dir, Source::Bundle(b), &opts()).err().expect("refused");
        assert_eq!(e.exit_code(), 2, "{refs}: {e}");
        assert!(e.to_string().contains("playbooks/child.toml"), "{e}");
    }
    // From the staging directory, this one exists: refused for leading outside, never read.
    let mut b = bundle();
    b.playbooks.insert("child.toml".into(), format!("extends = [\"../../secret.toml\"]\n{PLAYBOOK}"));
    let e = prepare(&db_dir, Source::Bundle(b), &opts()).err().expect("refused").to_string();
    assert!(e.contains("playbooks/child.toml") && e.contains("leads outside the playbook directory"), "{e}");
    let mut expands = bundle();
    expands
        .playbooks
        .insert("x.toml".into(), "[[steps]]\nid = \"a\"\ntitle = \"A\"\nexpand = \"../secret.toml\"\n".into());
    let e = prepare(&db_dir, Source::Bundle(expands), &opts()).err().expect("refused");
    assert!(e.to_string().contains("playbooks/x.toml"), "{e}");
    // References inside the tree, by name and by path, are fine.
    let mut fine = bundle();
    fine.playbooks.insert("lib/base.toml".into(), "[[steps]]\nid = \"b\"\ntitle = \"B\"\n".into());
    fine.playbooks.insert("child.toml".into(), "extends = [\"ship\", \"lib/base.toml\"]\n".into());
    prepare(&db_dir, Source::Bundle(fine), &opts()).unwrap();
}

#[test]
fn a_contained_loader_refuses_references_out_of_its_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("playbooks");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(tmp.path().join("secret.toml"), PLAYBOOK).unwrap();
    std::fs::write(dir.join("ship.toml"), PLAYBOOK).unwrap();
    std::fs::write(dir.join("child.toml"), format!("extends = [\"../secret.toml\"]\n{PLAYBOOK}")).unwrap();
    // As before for everyone else.
    Loader::new(vec![dir.clone()]).load("child").unwrap();
    let contained = Loader::new(vec![dir.clone()]).contained();
    assert!(contained.is_contained());
    contained.load("ship").unwrap();
    let e = contained.load("child").unwrap_err().to_string();
    assert!(e.contains("leads outside the playbook directory"), "{e}");
    let listed = contained.list();
    let child = listed.iter().find(|l| l.name == "child").unwrap();
    assert!(child.error.as_deref().unwrap().contains("outside"), "{child:?}");
    // A symlink out of the directory is refused too, and so is a file past the size limit.
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(tmp.path().join("secret.toml"), dir.join("linked.toml")).unwrap();
        assert!(Loader::new(vec![dir.clone()]).load("linked").is_ok());
        let e = Loader::new(vec![dir.clone()]).contained().load("linked").unwrap_err().to_string();
        assert!(e.contains("outside"), "{e}");
    }
    std::fs::write(dir.join("big.toml"), format!("{PLAYBOOK}#{}", "x".repeat(MAX_PUBLISH_FILE_BYTES))).unwrap();
    let e = Loader::new(vec![dir.clone()]).contained().load("big").unwrap_err().to_string();
    assert!(e.contains("more than the 512 KiB"), "{e}");
}

#[test]
fn an_empty_area_is_refused_unless_asked_for() {
    let (_tmp, db_dir, mut store) = workspace();
    publish(&db_dir, &mut store, bundle()).unwrap();
    let mut no_agents = bundle();
    no_agents.agents.clear();
    let e = prepare(&db_dir, Source::Bundle(no_agents.clone()), &opts()).err().unwrap();
    assert_eq!(e.exit_code(), 2);
    assert!(e.to_string().contains("has no agents"), "{e}");
    assert!(db_dir.join("agents/claude/skills/deploy/SKILL.md").exists());
    // Only the other area: agents stay as they are.
    let mut only = no_agents.clone();
    only.areas = vec![Area::Playbooks];
    let p = publish(&db_dir, &mut store, only).unwrap();
    assert!(!p.publishes(Area::Agents) && p.revisions.is_empty());
    drop(p);
    assert!(db_dir.join("agents/claude/skills/deploy/SKILL.md").exists());
    // Asked for: emptied.
    let mut p = prepare(&db_dir, Source::Bundle(no_agents), &Options { allow_empty: true, ..opts() }).unwrap();
    p.apply().unwrap();
    assert!(!db_dir.join("agents/claude").exists());
}

#[test]
fn rollback_restores_the_previous_publish_and_twice_toggles() {
    let (_tmp, db_dir, mut store) = workspace();
    let e = prepare(&db_dir, Source::Rollback { only: None }, &opts()).err().unwrap();
    assert!(e.to_string().contains("nothing to roll back"), "{e}");
    publish(&db_dir, &mut store, bundle()).unwrap();
    let first = (scan(&db_dir.join(PLAYBOOKS_DIR)).unwrap(), scan(&db_dir.join(AGENTS_DIR)).unwrap());
    let mut second = bundle();
    second.playbooks.insert("ship.toml".into(), format!("{PLAYBOOK}# v2\n"));
    second.playbooks.insert("new.toml".into(), PLAYBOOK.into());
    publish(&db_dir, &mut store, second).unwrap();
    let after = (scan(&db_dir.join(PLAYBOOKS_DIR)).unwrap(), scan(&db_dir.join(AGENTS_DIR)).unwrap());
    assert_ne!(first, after);

    let mut back = prepare(&db_dir, Source::Rollback { only: None }, &opts()).unwrap();
    assert!(back.rollback);
    back.apply().unwrap();
    store.write("publish", "admin", |tx| back.record(tx)).unwrap();
    back.finish();
    drop(back);
    assert_eq!((scan(&db_dir.join(PLAYBOOKS_DIR)).unwrap(), scan(&db_dir.join(AGENTS_DIR)).unwrap()), first);

    let mut again = prepare(&db_dir, Source::Rollback { only: None }, &opts()).unwrap();
    again.apply().unwrap();
    again.finish();
    drop(again);
    assert_eq!((scan(&db_dir.join(PLAYBOOKS_DIR)).unwrap(), scan(&db_dir.join(AGENTS_DIR)).unwrap()), after);

    // Only one area.
    let mut playbooks = prepare(&db_dir, Source::Rollback { only: Some(Area::Playbooks) }, &opts()).unwrap();
    assert_eq!(playbooks.plans.len(), 1);
    playbooks.apply().unwrap();
    drop(playbooks);
    assert_eq!(scan(&db_dir.join(PLAYBOOKS_DIR)).unwrap(), first.0);

    let events = store.read(|r| r.events(&EventQuery { since: Some(0), ..Default::default() })).unwrap().events;
    let last: Published =
        serde_json::from_value(events.iter().rfind(|e| e.op == PUBLISHED).unwrap().data.clone()).unwrap();
    assert!(last.rollback);
}

#[test]
fn a_rollback_to_nothing_needs_allow_empty() {
    let (_tmp, db_dir, mut store) = workspace();
    // The first publish keeps empty areas: rolling back to them empties the workspace.
    publish(&db_dir, &mut store, bundle()).unwrap();
    let e = prepare(&db_dir, Source::Rollback { only: None }, &opts()).err().unwrap();
    assert!(e.to_string().contains("the previous publish kept has no"), "{e}");
    let mut p = prepare(&db_dir, Source::Rollback { only: None }, &Options { allow_empty: true, ..opts() }).unwrap();
    p.apply().unwrap();
    assert!(scan(&db_dir.join(PLAYBOOKS_DIR)).unwrap().is_empty());
}

#[test]
fn applying_never_leaves_fewer_files_than_either_tree() {
    let (_tmp, db_dir, mut store) = workspace();
    let mut old = bundle();
    for i in 0..5 {
        old.playbooks.insert(format!("old{i}.toml"), PLAYBOOK.into());
    }
    old.playbooks.insert("dir/gone.toml".into(), PLAYBOOK.into());
    publish(&db_dir, &mut store, old).unwrap();
    let old_files = scan(&db_dir.join(PLAYBOOKS_DIR)).unwrap();

    let mut new = bundle();
    new.playbooks.insert("ship.toml".into(), format!("{PLAYBOOK}# changed\n"));
    for i in 0..5 {
        new.playbooks.insert(format!("new{i}.toml"), PLAYBOOK.into());
    }
    let mut p = prepare(&db_dir, Source::Bundle(new), &opts()).unwrap();
    let new_files = scan(&p.staging.dir.join(PLAYBOOKS_DIR)).unwrap();
    let root = db_dir.join(PLAYBOOKS_DIR);
    let mut steps = 0;
    let mut removing = false;
    p.apply_observed(&mut |changed: &Path| {
        if !changed.starts_with(&root) {
            return Ok(());
        }
        steps += 1;
        let now = scan(&root).unwrap();
        // Every file of either tree is there, as one of its versions, until the removals start.
        let is_new = new_files.iter().any(|(rel, _)| under(&root, rel) == changed);
        if !is_new {
            removing = true;
        }
        for (rel, node) in &new_files {
            if let Some(found) = now.get(rel) {
                let old = old_files.get(rel);
                assert!(found == node || Some(found) == old, "{rel}: neither version");
            } else {
                assert!(!old_files.contains_key(rel), "{rel}: missing");
            }
        }
        if !removing {
            for rel in old_files.keys() {
                assert!(now.contains_key(rel), "{rel} removed before every write was done");
            }
        }
        Ok(())
    })
    .unwrap();
    assert!(steps >= 7, "{steps}");
    assert_eq!(scan(&root).unwrap(), new_files);
}

#[test]
fn an_interrupted_apply_converges_when_published_again() {
    let (_tmp, db_dir, mut store) = workspace();
    publish(&db_dir, &mut store, bundle()).unwrap();
    let first = scan(&db_dir.join(PLAYBOOKS_DIR)).unwrap();
    let kept = || scan(&db_dir.join(PREV_DIR).join(PLAYBOOKS_DIR)).unwrap();
    let mut new = bundle();
    for i in 0..4 {
        new.playbooks.insert(format!("n{i}.toml"), PLAYBOOK.into());
    }
    let mut p = prepare(&db_dir, Source::Bundle(new.clone()), &opts()).unwrap();
    let mut n = 0;
    let area = db_dir.join(PLAYBOOKS_DIR);
    let e = p.apply_observed(&mut |changed| {
        n += usize::from(changed.starts_with(&area));
        if n == 2 { Err(invalid("crash")) } else { Ok(()) }
    });
    assert!(e.is_err());
    drop(p);
    let p = publish(&db_dir, &mut store, new.clone()).unwrap();
    let staged: BTreeSet<&String> = new.playbooks.keys().collect();
    let now = scan(&db_dir.join(PLAYBOOKS_DIR)).unwrap();
    assert_eq!(now.keys().collect::<BTreeSet<_>>(), staged);
    assert!(p.plans[0].files.iter().any(|f| f.status == Status::Unchanged), "some were written before the crash");
    drop(p);
    assert_eq!(kept(), first, "publish.prev keeps the tree from before the interrupted publish, not the mixed one");

    // Applied but never recorded (a crash, a failed write): published again, the kept tree stays.
    let mut third = new.clone();
    third.playbooks.insert("ship.toml".into(), format!("{PLAYBOOK}# v3\n"));
    let mut p = prepare(&db_dir, Source::Bundle(third.clone()), &opts()).unwrap();
    p.apply().unwrap();
    drop(p);
    publish(&db_dir, &mut store, third).unwrap();
    assert_eq!(kept(), now, "the tree before the unrecorded publish");
    let mut back = prepare(&db_dir, Source::Rollback { only: None }, &opts()).unwrap();
    back.apply().unwrap();
    drop(back);
    assert_eq!(scan(&db_dir.join(PLAYBOOKS_DIR)).unwrap(), now);
}

#[test]
fn publishes_take_turns_and_a_held_lock_exits_busy() {
    let (_tmp, db_dir, _store) = workspace();
    let held = prepare(&db_dir, Source::Bundle(bundle()), &opts()).unwrap();
    let e = prepare(&db_dir, Source::Bundle(bundle()), &opts()).err().unwrap();
    assert_eq!((e.exit_code(), e.code()), (5, "busy"), "{e}");
    assert!(e.to_string().contains(LOCK_FILE), "{e}");
    drop(held);
    prepare(&db_dir, Source::Bundle(bundle()), &opts()).unwrap();
}

#[test]
fn staging_left_behind_is_swept_once_old() {
    let (_tmp, db_dir, _store) = workspace();
    let old = db_dir.join(format!("{STAGING_PREFIX}deadbeef"));
    std::fs::create_dir_all(old.join("playbooks")).unwrap();
    std::fs::write(old.join("playbooks/x.toml"), "x").unwrap();
    assert_eq!(sweep(&db_dir, STAGING_MAX_AGE), 0, "a fresh one may be a publish under way");
    assert!(old.exists());
    assert_eq!(sweep(&db_dir, Duration::ZERO), 1);
    assert!(!old.exists());
    // Other entries are never touched.
    std::fs::write(db_dir.join(".publishing-notes"), "x").unwrap();
    assert_eq!(sweep(&db_dir, Duration::ZERO), 0);
    assert!(db_dir.join(".publishing-notes").exists());
}

#[cfg(unix)]
#[test]
fn staging_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let (_tmp, db_dir, _store) = workspace();
    let p = prepare(&db_dir, Source::Bundle(bundle()), &opts()).unwrap();
    let mode = std::fs::metadata(&p.staging.dir).unwrap().permissions().mode();
    assert_eq!(mode & 0o777, 0o700);
}

#[cfg(unix)]
#[test]
fn symlinks_in_the_target_are_replaced_never_followed() {
    use std::os::unix::fs::symlink;
    let (tmp, db_dir, mut store) = workspace();
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    std::fs::write(outside.join("ship.toml"), "precious").unwrap();
    std::fs::write(outside.join("SKILL.md"), "precious").unwrap();
    std::fs::create_dir_all(outside.join("dir")).unwrap();
    std::fs::write(outside.join("dir/keep.md"), "precious").unwrap();
    // A file symlink where a published file goes, a directory symlink where a published directory goes,
    // and one that the source lacks.
    std::fs::create_dir_all(db_dir.join("playbooks")).unwrap();
    symlink(outside.join("ship.toml"), db_dir.join("playbooks/ship.toml")).unwrap();
    std::fs::create_dir_all(db_dir.join("agents/claude/skills")).unwrap();
    symlink(&outside, db_dir.join("agents/claude/skills/deploy")).unwrap();
    symlink(outside.join("dir"), db_dir.join("agents/claude/skills/gone")).unwrap();

    publish(&db_dir, &mut store, bundle()).unwrap();
    assert_eq!(read(&outside.join("ship.toml")), "precious");
    assert_eq!(read(&outside.join("SKILL.md")), "precious");
    assert_eq!(read(&outside.join("dir/keep.md")), "precious");
    let ship = std::fs::symlink_metadata(db_dir.join("playbooks/ship.toml")).unwrap();
    assert!(ship.is_file(), "the link was replaced");
    let deploy = std::fs::symlink_metadata(db_dir.join("agents/claude/skills/deploy")).unwrap();
    assert!(deploy.is_dir(), "a real directory now");
    assert!(!db_dir.join("agents/claude/skills/gone").exists());
    // Kept as links in publish.prev, and restored as links.
    let kept = std::fs::symlink_metadata(db_dir.join(PREV_DIR).join("playbooks/ship.toml")).unwrap();
    assert!(kept.file_type().is_symlink());

    // An area that is itself a symlink is refused, never written through.
    let (tmp2, db2, mut store2) = workspace();
    let elsewhere = tmp2.path().join("elsewhere");
    std::fs::create_dir_all(&elsewhere).unwrap();
    symlink(&elsewhere, db2.join("playbooks")).unwrap();
    let mut only = bundle();
    only.agents.clear();
    only.areas = vec![Area::Playbooks];
    let e = publish(&db2, &mut store2, only).err().unwrap();
    assert!(e.to_string().contains("never writes through"), "{e}");
    assert_eq!(std::fs::read_dir(&elsewhere).unwrap().count(), 0);
}

#[cfg(unix)]
#[test]
fn in_set_symlinks_are_published_as_symlinks() {
    let (_tmp, db_dir, mut store) = workspace();
    let mut b = bundle();
    b.agents.get_mut(&Harness::Claude).unwrap().insert("skills/alias".into(), link("deploy"));
    let p = publish(&db_dir, &mut store, b).unwrap();
    let alias = db_dir.join("agents/claude/skills/alias");
    assert_eq!(std::fs::read_link(&alias).unwrap(), Path::new("deploy"));
    let set = AgentSet::load(&db_dir.join(AGENTS_DIR), Harness::Claude).unwrap();
    assert!(set.skills.contains_key("alias"));
    assert_eq!(p.record_data().areas[&Area::Agents].symlinks["claude/skills/alias"], "deploy");
}

#[test]
fn source_trees_are_read_as_bundles() {
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path();
    std::fs::create_dir_all(src.join("playbooks/lib")).unwrap();
    std::fs::write(src.join("playbooks/ship.toml"), PLAYBOOK).unwrap();
    std::fs::write(src.join("playbooks/lib/base.toml"), PLAYBOOK).unwrap();
    std::fs::write(src.join("playbooks/.gitkeep"), "").unwrap();
    std::fs::create_dir_all(src.join("agents/claude/skills/deploy")).unwrap();
    std::fs::write(src.join("agents/claude/skills/deploy/SKILL.md"), SKILL).unwrap();
    let b = read_tree(src, &Area::ALL).unwrap();
    assert_eq!(b.playbooks.keys().collect::<Vec<_>>(), ["lib/base.toml", "ship.toml"]);
    assert_eq!(b.agents[&Harness::Claude]["skills/deploy/SKILL.md"], text(SKILL));
    let only = read_tree(src, &[Area::Agents]).unwrap();
    assert!(only.playbooks.is_empty() && only.areas == [Area::Agents]);

    std::fs::create_dir_all(src.join("agents/cursor")).unwrap();
    let e = read_tree(src, &Area::ALL).unwrap_err().to_string();
    assert!(e.contains("not a harness's set"), "{e}");
    std::fs::remove_dir(src.join("agents/cursor")).unwrap();
    std::fs::write(src.join("playbooks/huge.toml"), "x".repeat(MAX_PUBLISH_FILE_BYTES + 1)).unwrap();
    let e = read_tree(src, &Area::ALL).unwrap_err().to_string();
    assert!(e.contains("huge.toml: more than the 512 KiB"), "{e}");
    std::fs::remove_file(src.join("playbooks/huge.toml")).unwrap();
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink("ship.toml", src.join("playbooks/alias.toml")).unwrap();
        let e = read_tree(src, &Area::ALL).unwrap_err().to_string();
        assert!(e.contains("a symlink (playbooks/ holds files only)"), "{e}");
        std::fs::remove_file(src.join("playbooks/alias.toml")).unwrap();
        std::os::unix::fs::symlink("deploy", src.join("agents/claude/skills/alias")).unwrap();
        let b = read_tree(src, &Area::ALL).unwrap();
        assert_eq!(b.agents[&Harness::Claude]["skills/alias"], link("deploy"));
    }
}

#[test]
fn dry_runs_compare_without_writing() {
    let (_tmp, db_dir, mut store) = workspace();
    publish(&db_dir, &mut store, bundle()).unwrap();
    let mut b = bundle();
    b.playbooks.insert("ship.toml".into(), format!("{PLAYBOOK}# v2\n"));
    b.playbooks.insert("new.toml".into(), PLAYBOOK.into());
    let p = prepare(&db_dir, Source::Bundle(b), &opts()).unwrap();
    let plan = &p.plans[0];
    let status: Vec<(&str, Status)> = plan.files.iter().map(|f| (f.path.as_str(), f.status)).collect();
    assert_eq!(status, [("new.toml", Status::Added), ("ship.toml", Status::Changed)]);
    let changed = &plan.files[1];
    let (old, new) = p.texts(changed);
    assert_eq!(old.as_deref(), Some(PLAYBOOK));
    assert_eq!(new, Some(format!("{PLAYBOOK}# v2\n")));
    assert_eq!(p.previous[&Harness::Claude], p.revisions[&Harness::Claude]);
    drop(p);
    assert_eq!(read(&db_dir.join("playbooks/ship.toml")), PLAYBOOK, "nothing written");
    assert!(!db_dir.join("playbooks/new.toml").exists());
}

/// Whether names in `dir` are compared without case (APFS and NTFS by default).
fn ignores_case(dir: &Path) -> bool {
    std::fs::write(dir.join("probe-case"), "").unwrap();
    let found = dir.join("PROBE-CASE").exists();
    std::fs::remove_file(dir.join("probe-case")).unwrap();
    found
}

/// The names in `dir`, sorted, without hidden ones.
fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| !n.starts_with('.'))
        .collect();
    names.sort();
    names
}

#[test]
fn case_only_renames_keep_the_entry_where_names_ignore_case() {
    let (_tmp, db_dir, mut store) = workspace();
    if !ignores_case(&db_dir) {
        eprintln!("skipped: names are case-sensitive here (the steps are tested apart)");
        return;
    }
    let mut first = bundle();
    first.playbooks.insert("lib.toml".into(), PLAYBOOK.into());
    first.agents.get_mut(&Harness::Claude).unwrap().insert("skills/deploy/Docs/guide.md".into(), text("guide"));
    publish(&db_dir, &mut store, first).unwrap();

    // The same file renamed in case only, another renamed and changed, and a directory renamed.
    let mut second = PublishBundle::new(vec![Area::Playbooks, Area::Agents]);
    second.playbooks.insert("Ship.toml".into(), PLAYBOOK.into());
    second.playbooks.insert("Lib.toml".into(), format!("{PLAYBOOK}# v2\n"));
    let set = second.agents.entry(Harness::Claude).or_default();
    set.insert("skills/deploy/SKILL.md".into(), text(SKILL));
    set.insert("skills/deploy/docs/guide.md".into(), text("guide v2"));
    let p = publish(&db_dir, &mut store, second).unwrap();
    assert_eq!(names(&db_dir.join(PLAYBOOKS_DIR)), ["Lib.toml", "Ship.toml"]);
    assert_eq!(read(&db_dir.join("playbooks/Ship.toml")), PLAYBOOK);
    assert_eq!(read(&db_dir.join("playbooks/Lib.toml")), format!("{PLAYBOOK}# v2\n"));
    let skill = db_dir.join("agents/claude/skills/deploy");
    assert_eq!(names(&skill), ["SKILL.md", "docs"]);
    assert_eq!(read(&skill.join("docs/guide.md")), "guide v2");
    let set = AgentSet::load(&db_dir.join(AGENTS_DIR), Harness::Claude).unwrap();
    assert_eq!(set.revision, p.revisions[&Harness::Claude]);
}

#[test]
fn publishing_again_unchanged_keeps_the_generation_to_roll_back_to() {
    let (_tmp, db_dir, mut store) = workspace();
    publish(&db_dir, &mut store, bundle()).unwrap();
    let first = scan(&db_dir.join(PLAYBOOKS_DIR)).unwrap();
    let mut second = bundle();
    second.playbooks.insert("ship.toml".into(), format!("{PLAYBOOK}# v2\n"));
    publish(&db_dir, &mut store, second.clone()).unwrap();
    publish(&db_dir, &mut store, second).unwrap();
    let mut back = prepare(&db_dir, Source::Rollback { only: None }, &opts()).unwrap();
    back.apply().unwrap();
    drop(back);
    assert_eq!(scan(&db_dir.join(PLAYBOOKS_DIR)).unwrap(), first, "back to the publish before the changed one");
}

#[test]
fn a_plain_rollback_restores_only_what_the_last_publish_changed() {
    let (_tmp, db_dir, mut store) = workspace();
    publish(&db_dir, &mut store, bundle()).unwrap();
    let playbooks_a = scan(&db_dir.join(PLAYBOOKS_DIR)).unwrap();
    let mut b = PublishBundle::new(vec![Area::Agents]);
    b.agents.entry(Harness::Claude).or_default().insert("skills/deploy/SKILL.md".into(), text(&format!("{SKILL}v2\n")));
    publish(&db_dir, &mut store, b).unwrap();
    let agents_b = scan(&db_dir.join(AGENTS_DIR)).unwrap();
    let mut c = PublishBundle::new(vec![Area::Playbooks]);
    c.playbooks.insert("ship.toml".into(), format!("{PLAYBOOK}# v3\n"));
    publish(&db_dir, &mut store, c).unwrap();

    let mut back = prepare(&db_dir, Source::Rollback { only: None }, &opts()).unwrap();
    assert_eq!(back.plans.iter().map(|p| p.area).collect::<Vec<_>>(), [Area::Playbooks]);
    back.apply().unwrap();
    drop(back);
    assert_eq!(scan(&db_dir.join(PLAYBOOKS_DIR)).unwrap(), playbooks_a);
    assert_eq!(scan(&db_dir.join(AGENTS_DIR)).unwrap(), agents_b, "the agents the last publish left alone stay");
}

#[test]
fn non_ascii_names_and_case_collisions_are_refused() {
    for path in ["caf\u{e9}.toml", "cafe\u{301}.toml", "\u{1f680}/x.toml"] {
        let mut b = PublishBundle::new(vec![Area::Playbooks]);
        b.playbooks.insert(path.into(), PLAYBOOK.into());
        let e = check_err(&b);
        assert!(e.contains("ASCII"), "{path:?}: {e}");
    }
    // A file and a directory apart only in case, and directories apart only in case.
    let mut b = bundle();
    let set = b.agents.get_mut(&Harness::Claude).unwrap();
    set.insert("skills/X".into(), link("deploy"));
    set.insert("skills/x/f.md".into(), text("x"));
    assert!(check_err(&b).contains("differ only in case"), "{}", check_err(&b));
    let mut b = PublishBundle::new(vec![Area::Playbooks]);
    b.playbooks.insert("Lib/a.toml".into(), PLAYBOOK.into());
    b.playbooks.insert("lib/b.toml".into(), PLAYBOOK.into());
    assert!(check_err(&b).contains("differ only in case"), "{}", check_err(&b));
    let mut b = PublishBundle::new(vec![Area::Playbooks]);
    b.playbooks.insert("A.toml".into(), PLAYBOOK.into());
    b.playbooks.insert("a.toml/b.toml".into(), PLAYBOOK.into());
    assert!(check_err(&b).contains("differ only in case"), "{}", check_err(&b));
}

#[test]
fn temp_files_an_interrupted_apply_left_are_swept() {
    let (_tmp, db_dir, mut store) = workspace();
    publish(&db_dir, &mut store, bundle()).unwrap();
    let temps = [
        db_dir.join("playbooks/.ship.toml.publish-0123456789abcdef"),
        db_dir.join("agents/claude/skills/deploy/.SKILL.md.publish-fedcba9876543210"),
    ];
    for t in &temps {
        std::fs::write(t, "half").unwrap();
    }
    std::fs::write(db_dir.join("playbooks/.keep"), "x").unwrap();
    std::fs::write(db_dir.join("playbooks/.notes.publish-draft"), "x").unwrap();
    let p = publish(&db_dir, &mut store, bundle()).unwrap();
    for t in &temps {
        assert!(!t.exists(), "{}", t.display());
    }
    assert!(p.swept >= 2, "{}", p.swept);
    assert!(db_dir.join("playbooks/.keep").exists() && db_dir.join("playbooks/.notes.publish-draft").exists());
}

#[test]
fn apply_errors_name_no_server_paths() {
    let (_tmp, db_dir, mut store) = workspace();
    std::fs::write(db_dir.join(PLAYBOOKS_DIR), "not a directory").unwrap();
    let mut only = bundle();
    only.agents.clear();
    only.areas = vec![Area::Playbooks];
    let e = publish(&db_dir, &mut store, only).err().unwrap().to_string();
    assert!(e.contains("playbooks"), "{e}");
    assert!(!e.contains(&*db_dir.to_string_lossy()) && !e.contains(STAGING_PREFIX), "no server paths: {e}");
}

#[test]
fn where_names_ignore_case_an_entry_spelled_otherwise_is_renamed_never_removed() {
    let file = |h: &str| Node::File { sha256: h.into(), executable: false };
    let tree = |entries: &[(&str, Node)]| -> BTreeMap<String, Node> {
        entries.iter().map(|(p, n)| (p.to_string(), n.clone())).collect()
    };
    let source =
        tree(&[("Ship.toml", file("a")), ("docs", Node::Dir), ("docs/a.md", file("b")), ("x.toml", file("c"))]);
    let target = tree(&[
        ("Docs", Node::Dir),
        ("Docs/a.md", file("old")),
        ("Docs/gone.md", file("d")),
        ("ship.toml", file("a")),
        ("x.toml", file("c")),
    ]);
    let strs = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    // Case-sensitive: other names, other entries; what the source lacks goes.
    let cs = steps(&source, &target, false);
    assert_eq!(cs.writes, strs(&["Ship.toml", "docs", "docs/a.md"]));
    assert!(cs.renames.is_empty());
    assert_eq!(cs.removals, strs(&["ship.toml", "Docs/gone.md", "Docs/a.md", "Docs"]));
    // Ignoring case: the same entries, renamed to the source's spelling; only what the source lacks goes.
    let ci = steps(&source, &target, true);
    assert_eq!(ci.writes, strs(&["docs/a.md"]), "unchanged entries are not written again");
    assert_eq!(ci.renames, [("ship.toml".to_string(), "Ship.toml".to_string()), ("Docs".into(), "docs".into())]);
    assert_eq!(ci.removals, strs(&["Docs/gone.md"]));
}

#[test]
fn git_modes_give_executable_bits_and_symlinks_where_the_file_system_cannot() {
    let out = "100644 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 0\tagents/claude/skills/deploy/SKILL.md\0\
               100755 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 0\tagents/claude/skills/deploy/run.sh\0\
               120000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 0\tagents/codex/skills/deploy\0\
               160000 e69de29bb2d1d6434b8b29ae775ad8c2e48c5391 0\tagents/sub\0";
    let out = out.replace("\0               ", "\0");
    let modes = parse_ls_files(&out);
    assert_eq!(modes.len(), 3, "{modes:?}");
    assert_eq!(modes["agents/claude/skills/deploy/run.sh"], GitMode::Executable);

    // As git checks them out where the file system keeps neither: plain files.
    let tmp = tempfile::tempdir().unwrap();
    let src = tmp.path();
    std::fs::create_dir_all(src.join("agents/claude/skills/deploy")).unwrap();
    std::fs::create_dir_all(src.join("agents/codex/skills")).unwrap();
    std::fs::write(src.join("agents/claude/skills/deploy/SKILL.md"), SKILL).unwrap();
    std::fs::write(src.join("agents/claude/skills/deploy/run.sh"), "#!/bin/sh\n").unwrap();
    std::fs::write(src.join("agents/codex/skills/deploy"), "../../claude/skills/deploy").unwrap();
    let b = read_tree_with(src, &[Area::Agents], Some(&modes)).unwrap();
    assert!(b.agents[&Harness::Claude]["skills/deploy/run.sh"].executable);
    assert!(!b.agents[&Harness::Claude]["skills/deploy/SKILL.md"].executable);
    assert_eq!(b.agents[&Harness::Codex]["skills/deploy"], link("../../claude/skills/deploy"));
    // From the file system alone, the script is not one and the link is text.
    let plain = read_tree(src, &[Area::Agents]).unwrap();
    assert!(plain.agents[&Harness::Codex]["skills/deploy"].text.is_some());
    // A file git does not record: nothing says whether it is a script.
    std::fs::write(src.join("agents/claude/skills/deploy/new.sh"), "#!/bin/sh\n").unwrap();
    let e = read_tree_with(src, &[Area::Agents], Some(&modes)).unwrap_err().to_string();
    assert!(e.contains("new.sh: not recorded by git"), "{e}");
}

#[cfg(unix)]
#[test]
fn links_between_sets_publish_and_links_resolved_out_of_agents_are_refused() {
    let (_tmp, db_dir, mut store) = workspace();
    let mut b = bundle();
    b.agents.entry(Harness::Codex).or_default().insert("skills/deploy".into(), link("../../claude/skills/deploy"));
    publish(&db_dir, &mut store, b.clone()).unwrap();
    let codex = AgentSet::load(&db_dir.join(AGENTS_DIR), Harness::Codex).unwrap();
    assert!(codex.skills.contains_key("deploy"));
    // Rolling back to a tree with such links works too.
    let mut second = b.clone();
    second
        .agents
        .get_mut(&Harness::Claude)
        .unwrap()
        .insert("skills/deploy/SKILL.md".into(), text(&format!("{SKILL}v2\n")));
    publish(&db_dir, &mut store, second).unwrap();
    let mut back = prepare(&db_dir, Source::Rollback { only: None }, &opts()).unwrap();
    back.apply().unwrap();

    // Lexically inside, but through another link it leads out of agents/ (to the staged playbooks).
    drop(back);
    let mut escape = bundle();
    let set = escape.agents.get_mut(&Harness::Claude).unwrap();
    set.insert("skills/deploy/u".into(), link("../../../codex/skills"));
    set.insert("skills/deploy/v".into(), link("u/../../../playbooks"));
    escape.agents.entry(Harness::Codex).or_default().insert("skills/s/SKILL.md".into(), text(SKILL));
    escape.check().unwrap();
    let e = prepare(&db_dir, Source::Bundle(escape), &opts()).err().expect("refused").to_string();
    assert!(e.contains("agents/claude/skills/deploy/v: a symlink leading outside agents/"), "{e}");
}

#[test]
fn a_crash_before_the_apply_marker_keeps_no_other_publishs_areas() {
    let (_tmp, db_dir, mut store) = workspace();
    publish(&db_dir, &mut store, bundle()).unwrap();
    // A publish of the agents alone, finished.
    let mut b = PublishBundle::new(vec![Area::Agents]);
    b.agents.entry(Harness::Claude).or_default().insert("skills/deploy/SKILL.md".into(), text(&format!("{SKILL}v2\n")));
    publish(&db_dir, &mut store, b).unwrap();
    let agents_b = scan(&db_dir.join(AGENTS_DIR)).unwrap();
    // A publish of the playbooks crashes once its copy is kept, before its list and its marker.
    let mut c = PublishBundle::new(vec![Area::Playbooks]);
    c.playbooks.insert("ship.toml".into(), format!("{PLAYBOOK}# v3\n"));
    let mut p = prepare(&db_dir, Source::Bundle(c.clone()), &opts()).unwrap();
    let kept = db_dir.join(PREV_DIR).join(PLAYBOOKS_DIR);
    let e = p.apply_observed(&mut |changed| if changed == kept { Err(invalid("crash")) } else { Ok(()) });
    assert!(e.is_err());
    drop(p);
    assert!(!db_dir.join(PREV_DIR).join(APPLYING).exists(), "no marker beside the agents publish's list");
    let before_c = scan(&db_dir.join(PLAYBOOKS_DIR)).unwrap();
    publish(&db_dir, &mut store, c).unwrap();
    let mut back = prepare(&db_dir, Source::Rollback { only: None }, &opts()).unwrap();
    back.apply().unwrap();
    drop(back);
    assert_eq!(scan(&db_dir.join(PLAYBOOKS_DIR)).unwrap(), before_c);
    assert_eq!(scan(&db_dir.join(AGENTS_DIR)).unwrap(), agents_b, "the finished agents publish is not rolled back");
}

#[test]
fn case_folding_is_ascii_only() {
    let file = Node::File { sha256: "a".into(), executable: false };
    let source: BTreeMap<String, Node> = [("k.toml".to_string(), file.clone())].into();
    // KELVIN SIGN lowercases to 'k' by Unicode rules: a legacy name no file system takes for "k.toml".
    let target: BTreeMap<String, Node> = [("\u{212a}.toml".to_string(), file)].into();
    let ci = steps(&source, &target, true);
    assert_eq!(ci.removals, ["\u{212a}.toml"]);
    assert!(ci.renames.is_empty());
}

#[cfg(unix)]
#[test]
fn an_entry_that_is_the_same_file_as_one_the_source_holds_is_never_removed() {
    // A directory that ignores case where the area's root does not is not seen by the probe; a hard link, under a
    // name no file system folds onto ship.toml, stands in for the second name of one entry.
    let (_tmp, db_dir, mut store) = workspace();
    publish(&db_dir, &mut store, bundle()).unwrap();
    let ship = db_dir.join("playbooks/ship.toml");
    std::fs::hard_link(&ship, db_dir.join("playbooks/alias.toml")).unwrap();
    publish(&db_dir, &mut store, bundle()).unwrap();
    assert_eq!(read(&ship), PLAYBOOK);
    assert!(db_dir.join("playbooks/alias.toml").exists(), "the same file as ship.toml: kept");
}
