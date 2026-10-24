//! Federation envelope slice: keygen discipline, chain verifiability, and
//! tamper rejection. Each test names the guarantee it protects.

use ed25519_dalek::SigningKey;
use marbles::db::{Db, OutboxRow};
use marbles::federate::{
    GENESIS_PREV, build_chain, keygen, seal_envelope, verify_text,
};
use marbles::types::*;

fn db_with_project() -> Db {
    let db = Db::in_memory().unwrap();
    db.ensure_project("demo", "/tmp/demo", "demo").unwrap();
    db
}

fn new(title: &str) -> NewIssue {
    NewIssue {
        title: title.into(),
        description: String::new(),
        issue_type: "task".into(),
        priority: 2,
        labels: vec![],
        parent: None,
        id: None,
        project: Some("demo".into()),
        available_at: None,
        created_by: Some("tester".into()),
        metadata: None,
        external_ref: None,
    }
}

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&[7u8; 32])
}

fn to_jsonl(envelopes: &[marbles::federate::Envelope]) -> String {
    envelopes
        .iter()
        .map(|env| serde_json::to_string(env).unwrap())
        .collect::<Vec<_>>()
        .join("\n")
}

fn chain_from_db(db: &Db) -> Vec<marbles::federate::Envelope> {
    let rows: Vec<OutboxRow> = db.outbox_log().unwrap();
    build_chain(&rows, &signing_key())
}

#[test]
fn keygen_refuses_overwrite_without_force() {
    let dir = tempfile::tempdir().unwrap();
    let first = keygen(dir.path(), false).unwrap();
    let err = keygen(dir.path(), false).unwrap_err();
    assert!(err.contains("already exists"), "{err}");
    assert!(err.contains("--force"), "{err}");
    let rotated = keygen(dir.path(), true).unwrap();
    assert_ne!(first.peer_id, rotated.peer_id);
    assert_eq!(rotated.secret_path, first.secret_path);
}

#[test]
#[cfg(unix)]
fn keygen_secret_key_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let info = keygen(dir.path(), false).unwrap();
    let mode = std::fs::metadata(&info.secret_path)
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "secret key must be owner-only");
}

#[test]
fn export_chain_is_verifiable_across_create_and_claim() {
    let db = db_with_project();
    let id = db.create(&new("deliver"), 100).unwrap();
    db.claim(
        &ClaimRequest {
            id,
            assignee: "worker".into(),
            actor_kind: ActorKind::Agent,
            ttl_seconds: Some(100),
        },
        110,
    )
    .unwrap();
    let chain = chain_from_db(&db);
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].event, "created");
    assert_eq!(chain[1].event, "claimed");
    assert_eq!(
        chain[0].prev_hash,
        GENESIS_PREV.iter().map(|b| format!("{b:02x}")).collect::<String>()
    );
    assert_eq!(chain[1].prev_hash, chain[0].hash);
    assert_eq!(verify_text(&to_jsonl(&chain)).unwrap(), 2);
}

#[test]
fn verify_accepts_valid_export_in_jsonl_and_array_forms() {
    let db = db_with_project();
    db.create(&new("one"), 100).unwrap();
    db.create(&new("two"), 110).unwrap();
    let chain = chain_from_db(&db);
    assert_eq!(verify_text(&to_jsonl(&chain)).unwrap(), 2);
    let array = serde_json::to_string_pretty(&chain).unwrap();
    assert_eq!(verify_text(&array).unwrap(), 2);
}

#[test]
fn verify_rejects_tampered_payload() {
    let db = db_with_project();
    let id = db.create(&new("deliver"), 100).unwrap();
    db.claim(
        &ClaimRequest {
            id,
            assignee: "worker".into(),
            actor_kind: ActorKind::Agent,
            ttl_seconds: Some(100),
        },
        110,
    )
    .unwrap();
    let mut chain = chain_from_db(&db);
    chain[1].detail = "forged".to_string();
    let err = verify_text(&to_jsonl(&chain)).unwrap_err();
    assert!(err.contains("hash mismatch"), "{err}");
}

#[test]
fn verify_rejects_tampered_signature() {
    let db = db_with_project();
    db.create(&new("one"), 100).unwrap();
    let mut chain = chain_from_db(&db);
    let first = chain[0].signature.chars().next().unwrap();
    let replacement = if first == '0' { '1' } else { '0' };
    chain[0].signature.replace_range(0..1, &replacement.to_string());
    let err = verify_text(&to_jsonl(&chain)).unwrap_err();
    assert!(err.contains("signature invalid"), "{err}");
}

#[test]
fn verify_rejects_tampered_chain_link_even_when_resigned() {
    // Re-signing after breaking the link must not rescue the chain: the link
    // check is independent of the hash and signature checks.
    let db = db_with_project();
    db.create(&new("one"), 100).unwrap();
    db.create(&new("two"), 110).unwrap();
    let mut chain = chain_from_db(&db);
    chain[1].prev_hash = "f".repeat(64);
    seal_envelope(&mut chain[1], &signing_key());
    let err = verify_text(&to_jsonl(&chain)).unwrap_err();
    assert!(err.contains("chain link broken"), "{err}");
}

#[test]
fn since_window_still_verifies_as_anchored_chain() {
    let db = db_with_project();
    db.create(&new("one"), 100).unwrap();
    db.create(&new("two"), 110).unwrap();
    db.create(&new("three"), 120).unwrap();
    let chain = chain_from_db(&db);
    assert_eq!(chain.len(), 3);
    let window: Vec<_> = chain.into_iter().filter(|env| env.seq >= 2).collect();
    assert_eq!(window.len(), 2);
    assert_eq!(window[1].prev_hash, window[0].hash);
    assert_eq!(verify_text(&to_jsonl(&window)).unwrap(), 2);
}
