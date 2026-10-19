//! `lookup_id`'s seek over case variants against the `LIKE` query it
//! replaced (bd-sync-wfr), kept here as the reference.

use super::*;
use crate::IdMode;
use crate::model::NewIssue;
use crate::store::{InitOptions, OpenOptions, Store};

/// A workspace with prefix `t` (counter ids) holding `ids` in order, each
/// `(id, parent)`.
fn store_with(ids: &[(&str, Option<&str>)]) -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().unwrap();
    let mut store = Store::init(
        &dir.path().join("bd.db"),
        InitOptions { prefix: "t".into(), id_mode: IdMode::Counter },
        OpenOptions::default(),
    )
    .unwrap();
    store
        .write("seed", "alice", |tx| {
            for (id, parent) in ids {
                tx.create_issue(NewIssue {
                    id: Some(id.to_string()),
                    parent: parent.map(str::to_string),
                    ..NewIssue::titled(*id)
                })?;
            }
            Ok(())
        })
        .unwrap();
    (dir, store)
}

/// `lookup_id` as it was before bd-sync-wfr, verbatim: the reference.
fn old_lookup_id(conn: &Connection, input: &str) -> Result<Option<String>> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(None);
    }
    if ids::exists(conn, input)? {
        return Ok(Some(input.to_string()));
    }
    let prefixed = format!("{}-{input}", config::prefix(conn)?);
    if ids::exists(conn, &prefixed)? {
        return Ok(Some(prefixed));
    }
    let mut matches: Vec<String> = Vec::new();
    for candidate in [input, prefixed.as_str()] {
        let mut stmt = conn.prepare_cached("SELECT id FROM issues WHERE id LIKE ?1 ESCAPE '\\' ORDER BY id LIMIT 6")?;
        for row in stmt.query_map([format!("{}%", like_escape(candidate))], |r| r.get::<_, String>(0))? {
            let id = row?;
            if !matches.contains(&id) {
                matches.push(id);
            }
        }
    }
    match matches.len() {
        0 => Ok(None),
        1 => Ok(Some(matches.remove(0))),
        _ => Err(Error::invalid(format!("ambiguous id {input:?}: matches {}", matches.join(", ")))),
    }
}

/// Errors compared by their text, so the ambiguity message and its order
/// count.
fn answer(r: Result<Option<String>>) -> std::result::Result<Option<String>, String> {
    r.map_err(|e| e.to_string())
}

/// Counter ids t-1..t-12 with children t-1.1 and t-2.1, and explicit ids
/// that differ only in case or hold LIKE's wildcards.
fn fixture() -> (tempfile::TempDir, Store) {
    let mut ids: Vec<(String, Option<&str>)> = (1..=12).map(|n| (format!("t-{n}"), None)).collect();
    ids.push(("t-1.1".into(), Some("t-1")));
    ids.push(("t-2.1".into(), Some("t-2")));
    for id in ["PROJ-12", "Mx-Ab3", "t-Ab", "t-ab", "t-a_b", "t-axb", "t-a-b"] {
        ids.push((id.into(), None));
    }
    for n in 1..=4 {
        ids.push((format!("t-Q{n}"), None));
        ids.push((format!("t-q{n}"), None));
    }
    let refs: Vec<(&str, Option<&str>)> = ids.iter().map(|(id, p)| (id.as_str(), *p)).collect();
    store_with(&refs)
}

/// The fixture's inputs other than the NUL and over-long ones.
const INPUTS: &[&str] = &[
    // exact, exact child
    "t-1", "t-1.1", "PROJ-12", "Mx-Ab3", "t-a_b", // partial
    "t-1.", "t-12", "PROJ", "Mx-a", "t-ax", "t-a-", // wrong case
    "proj-12", "PROJ-1", "mx-ab3", "MX-AB", "T-1.1", "T-A_B", "T-AX", // typo
    "t-13", "t-z", "PROJ-13", "x", "t-1.2", // LIKE's wildcards and escape, literal
    "%", "_", "\\", "t-%", "t-_", "t-a_", "t-a%", "t-a\\", "%-1", // short ids without the prefix
    "1", "1.1", "11", "a_b", "ab", "AB", "q1", "Q", "2.", // ambiguous
    "t-", "T-1", "T-AB", "t-q", "t-Q", "t-a", "t", "1.", "q", // empty, whitespace-only, padded
    "", "   ", "\t\n", "  t-1  ", " t-a_ ", " PROJ ", // non-ASCII, matched exactly
    "t-é", "ß",
];

#[test]
fn matches_as_the_like_query_did() {
    let (_dir, store) = fixture();
    let conn = store.connection();
    let long = "a".repeat(2000);
    let too_long = "a".repeat(50_001);
    let mut inputs: Vec<&str> = INPUTS.to_vec();
    inputs.extend(["t-1\0x", "\0", long.as_str(), too_long.as_str()]);
    for input in inputs {
        assert_eq!(
            answer(lookup_id(conn, input)),
            answer(old_lookup_id(conn, input)),
            "input {:?}",
            input.chars().take(40).collect::<String>()
        );
    }

    // Literal expectations, so the comparison cannot pass vacuously.
    assert_eq!(lookup_id(conn, "proj-12").unwrap(), Some("PROJ-12".into()));
    assert_eq!(lookup_id(conn, "t-a_").unwrap(), Some("t-a_b".into()));
    assert_eq!(lookup_id(conn, "a_").unwrap(), Some("t-a_b".into()));
    assert_eq!(lookup_id(conn, "1.1").unwrap(), Some("t-1.1".into()));
    assert_eq!(lookup_id(conn, "%").unwrap(), None);
    assert_eq!(lookup_id(conn, "t-13").unwrap(), None);
    let err = lookup_id(conn, "T-AB").unwrap_err().to_string();
    assert!(err.contains("ambiguous id \"T-AB\": matches t-Ab, t-ab"), "{err}");
    let err = lookup_id(conn, "t-q").unwrap_err().to_string();
    assert!(err.contains("matches t-Q1, t-Q2, t-Q3, t-Q4, t-q1, t-q2"), "{err}");
    let err = lookup_id(conn, &too_long).unwrap_err().to_string();
    assert!(err.contains("pattern too complex"), "{err}");
}

#[test]
fn common_inputs_only_seek() {
    let (_dir, store) = fixture();
    let conn = store.connection();
    for input in INPUTS {
        let input = input.trim();
        for candidate in [input.to_string(), format!("t-{input}")] {
            assert!(case_variants(conn, &candidate).unwrap().is_some(), "{candidate:?} fell back to LIKE");
        }
    }
    assert_eq!(case_variants(conn, "t-1\0x").unwrap(), None);
    assert_eq!(case_variants(conn, &"a".repeat(MAX_WALK_BYTES + 1)).unwrap(), None);

    // The walk keeps only the variants some id starts with.
    let mut ab = case_variants(conn, "T-AB").unwrap().unwrap();
    ab.sort();
    assert_eq!(ab, ["t-Ab", "t-ab"]);
    assert_eq!(case_variants(conn, "t-zz").unwrap(), Some(vec![]));
}

#[test]
fn falls_back_past_the_case_variant_cap() {
    // Every case combination of `abcdef` (64 ids, one per bitmask, each
    // bit uppercasing one letter), plus one id under `abcdef-2`.
    let mut ids: Vec<String> = (0..64u32)
        .map(|mask| {
            let v: String = "abcdef"
                .chars()
                .enumerate()
                .map(|(i, c)| if mask & (1 << i) != 0 { c.to_ascii_uppercase() } else { c })
                .collect();
            format!("{v}-1")
        })
        .collect();
    ids.push("abcdef-2x".into());
    let refs: Vec<(&str, Option<&str>)> = ids.iter().map(|id| (id.as_str(), None)).collect();
    let (_dir, store) = store_with(&refs);
    let conn = store.connection();

    // Past the cap at `f`: the LIKE fallback answers, and finds the one id.
    assert_eq!(case_variants(conn, "ABCDEF-2").unwrap(), None);
    assert_eq!(lookup_id(conn, "ABCDEF-2").unwrap(), Some("abcdef-2x".into()));
    assert_eq!(answer(lookup_id(conn, "ABCDEF-2")), answer(old_lookup_id(conn, "ABCDEF-2")));

    // Ambiguous on the fallback: the first 6 in BINARY order, as before.
    let err = lookup_id(conn, "abcdef").unwrap_err().to_string();
    assert!(err.contains("ambiguous id \"abcdef\": matches ABCDEF-1, ABCDEf-1, ABCDeF-1"), "{err}");
    assert_eq!(answer(lookup_id(conn, "abcdef")), answer(old_lookup_id(conn, "abcdef")));

    // At the cap, not past it: 32 variants of `abcde`, still on the walk.
    assert_eq!(case_variants(conn, "abcde").unwrap().map(|v| v.len()), Some(32));
    assert_eq!(answer(lookup_id(conn, "abcde")), answer(old_lookup_id(conn, "abcde")));
}
