//! Signed federation envelopes: the envelope layer for gossiping the outbox.
//!
//! This module is transport-free by design. It turns the local writer's outbox
//! rows into a hash-chained, Ed25519-signed JSONL log that any peer can verify
//! offline, and it verifies such logs without touching the database. Moving
//! envelopes between peers (Mycelium gossip, later) is a separate layer, and
//! applying a remote log to a local store is deliberately out of scope here.
//!
//! Envelope shape (one JSON object per line):
//!
//! ```text
//! seq, issue_id, project, occurred_at, event, actor, detail   (outbox row)
//! signer                                                       (hex Ed25519 public key)
//! prev_hash                                                    (hex SHA-256, genesis is 32 zero bytes)
//! hash                                                         (hex SHA-256 over the canonical content above)
//! signature                                                    (hex Ed25519 signature over the hash bytes)
//! ```
//!
//! Verification recomputes each hash, checks each signature against the
//! envelope's own signer key, and checks every link between consecutive
//! envelopes. A log that starts mid-chain is accepted as anchored at its first
//! envelope: its first `prev_hash` cannot be checked without the predecessor,
//! but its hash and signature still can.

use std::path::{Path, PathBuf};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::db::OutboxRow;

/// Schema tag stamped into every envelope and covered by its hash.
pub const SCHEMA: &str = "marbles.federation.envelope/1";

/// `prev_hash` of the first envelope in a writer's log: 32 zero bytes.
pub const GENESIS_PREV: [u8; 32] = [0; 32];

/// Where a writer's federation keypair lives: `$MARBLES_HOME/federate/`.
pub fn key_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("federate")
}

/// Secret seed file. Written with mode 0600; never printed.
pub fn secret_key_path(state_dir: &Path) -> PathBuf {
    key_dir(state_dir).join("key")
}

/// Public key file. The hex inside is also the writer's peer id.
pub fn public_key_path(state_dir: &Path) -> PathBuf {
    key_dir(state_dir).join("key.pub")
}

/// A generated keypair: the peer id plus where each half lives.
#[derive(Debug, Clone)]
pub struct KeypairInfo {
    pub peer_id: String,
    pub secret_path: PathBuf,
    pub public_path: PathBuf,
}

/// Generate the local writer's Ed25519 keypair.
///
/// Refuses to overwrite an existing secret key unless `force` is set, so a
/// rotation is always explicit: overwriting the key orphans every envelope
/// signed with the old one.
pub fn keygen(state_dir: &Path, force: bool) -> Result<KeypairInfo, String> {
    let dir = key_dir(state_dir);
    std::fs::create_dir_all(&dir)
        .map_err(|e| format!("creating {}: {e}", dir.display()))?;
    let secret_path = secret_key_path(state_dir);
    let public_path = public_key_path(state_dir);
    if secret_path.exists() && !force {
        return Err(format!(
            "federation key already exists at {}; re-run with --force to replace it",
            secret_path.display()
        ));
    }
    let mut seed = [0u8; 32];
    getrandom::fill(&mut seed).map_err(|_| "no system randomness".to_string())?;
    let signing = SigningKey::from_bytes(&seed);
    let peer_id = peer_id(&signing);
    std::fs::write(&secret_path, format!("{}\n", hex_encode(&seed)))
        .map_err(|e| format!("writing {}: {e}", secret_path.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&secret_path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("securing {}: {e}", secret_path.display()))?;
    }
    std::fs::write(&public_path, format!("{peer_id}\n"))
        .map_err(|e| format!("writing {}: {e}", public_path.display()))?;
    Ok(KeypairInfo {
        peer_id,
        secret_path,
        public_path,
    })
}

/// Load the local writer's signing key, or explain how to create one.
pub fn load_signing_key(state_dir: &Path) -> Result<SigningKey, String> {
    let path = secret_key_path(state_dir);
    let text = std::fs::read_to_string(&path).map_err(|_| {
        format!(
            "no federation key at {}; run `marbles federate keygen` first",
            path.display()
        )
    })?;
    let seed = hex_decode(text.trim()).map_err(|e| {
        format!(
            "federation key at {} is not valid hex: {e}",
            path.display()
        )
    })?;
    let seed: [u8; 32] = seed.try_into().map_err(|_| {
        format!(
            "federation key at {} is not a 32-byte seed",
            path.display()
        )
    })?;
    Ok(SigningKey::from_bytes(&seed))
}

/// A writer's peer id: the hex of its Ed25519 verifying key.
pub fn peer_id(signing: &SigningKey) -> String {
    hex_encode(signing.verifying_key().as_bytes())
}

/// One signed outbox row. Field order is the serialization order, which is
/// what keeps the hash canonical: serde_json emits struct fields in
/// declaration order.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Envelope {
    pub schema: String,
    pub seq: i64,
    pub issue_id: String,
    pub project: String,
    pub occurred_at: i64,
    pub event: String,
    pub actor: String,
    pub detail: String,
    pub signer: String,
    pub prev_hash: String,
    pub hash: String,
    pub signature: String,
}

/// The content covered by `hash`, in canonical field order. The hash and the
/// signature themselves are never part of what is hashed.
#[derive(Serialize)]
struct Canonical<'a> {
    schema: &'a str,
    seq: i64,
    issue_id: &'a str,
    project: &'a str,
    occurred_at: i64,
    event: &'a str,
    actor: &'a str,
    detail: &'a str,
    signer: &'a str,
    prev_hash: &'a str,
}

fn hash_envelope(env: &Envelope) -> [u8; 32] {
    let canonical = Canonical {
        schema: &env.schema,
        seq: env.seq,
        issue_id: &env.issue_id,
        project: &env.project,
        occurred_at: env.occurred_at,
        event: &env.event,
        actor: &env.actor,
        detail: &env.detail,
        signer: &env.signer,
        prev_hash: &env.prev_hash,
    };
    let bytes = serde_json::to_vec(&canonical).expect("envelope content serializes");
    Sha256::digest(&bytes).into()
}

/// Fill `hash` and `signature` for an envelope whose content fields (including
/// `prev_hash`) are already set. This is the one place hashes are minted, so
/// export and hand-built chains cannot drift apart.
pub fn seal_envelope(env: &mut Envelope, signing: &SigningKey) {
    let hash = hash_envelope(env);
    env.hash = hex_encode(&hash);
    env.signature = hex_encode(&signing.sign(&hash).to_bytes());
}

/// Turn ordered outbox rows into a signed, hash-chained log starting at
/// genesis. Rows must arrive in ascending `seq` order; the chain links each
/// envelope to the hash of the one before it.
pub fn build_chain(rows: &[OutboxRow], signing: &SigningKey) -> Vec<Envelope> {
    let signer = peer_id(signing);
    let mut prev_hash = hex_encode(&GENESIS_PREV);
    rows.iter()
        .map(|row| {
            let mut env = Envelope {
                schema: SCHEMA.to_string(),
                seq: row.seq,
                issue_id: row.issue_id.clone(),
                project: row.project.clone(),
                occurred_at: row.occurred_at,
                event: row.event.clone(),
                actor: row.actor.clone(),
                detail: row.detail.clone(),
                signer: signer.clone(),
                prev_hash: std::mem::take(&mut prev_hash),
                hash: String::new(),
                signature: String::new(),
            };
            seal_envelope(&mut env, signing);
            prev_hash = env.hash.clone();
            env
        })
        .collect()
}

/// Verify a JSONL log: every line must be one envelope, in order. Checks each
/// envelope's hash, each signature against the envelope's own signer key, and
/// every link between consecutive envelopes. Returns the envelope count.
///
/// The input may also be the JSON array form `federate export --json` writes;
/// it is verified in array order. The first envelope's `prev_hash` is an
/// anchor, not a checked link: a log exported with `--since` starts mid-chain,
/// and its first link can only be checked against a predecessor the reader
/// does not have. Its hash and signature are still fully checked.
///
/// This function never touches the database, by construction: it only reads
/// the text it is given.
pub fn verify_text(text: &str) -> Result<usize, String> {
    let trimmed = text.trim();
    if trimmed.starts_with('[') {
        let envelopes: Vec<Envelope> = serde_json::from_str(trimmed)
            .map_err(|e| format!("envelope log: invalid JSON array: {e}"))?;
        return verify_envelopes(&envelopes);
    }
    let mut envelopes = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let envelope: Envelope = serde_json::from_str(line).map_err(|e| {
            format!("envelope {}: invalid JSON: {e}", index + 1)
        })?;
        envelopes.push(envelope);
    }
    verify_envelopes(&envelopes)
}

fn verify_envelopes(envelopes: &[Envelope]) -> Result<usize, String> {
    let mut previous_hash: Option<&str> = None;
    for (index, envelope) in envelopes.iter().enumerate() {
        verify_one(envelope, previous_hash, index + 1)?;
        previous_hash = Some(envelope.hash.as_str());
    }
    Ok(envelopes.len())
}

fn verify_one(
    env: &Envelope,
    previous_hash: Option<&str>,
    line_no: usize,
) -> Result<(), String> {
    let label = format!("envelope {line_no} (seq {})", env.seq);
    if env.schema != SCHEMA {
        return Err(format!(
            "{label}: unknown schema '{}', expected '{SCHEMA}'",
            env.schema
        ));
    }
    let computed = hash_envelope(env);
    if hex_encode(&computed) != env.hash {
        return Err(format!(
            "{label}: hash mismatch; the envelope content was modified after signing"
        ));
    }
    let public = hex_decode(&env.signer)
        .map_err(|_| format!("{label}: signer is not valid hex"))?;
    let public: [u8; 32] = public
        .try_into()
        .map_err(|_| format!("{label}: signer is not a 32-byte Ed25519 public key"))?;
    let verifying = VerifyingKey::from_bytes(&public)
        .map_err(|_| format!("{label}: signer is not a valid Ed25519 public key"))?;
    let signature = hex_decode(&env.signature)
        .map_err(|_| format!("{label}: signature is not valid hex"))?;
    let signature = Signature::from_slice(&signature)
        .map_err(|_| format!("{label}: signature is not a 64-byte Ed25519 signature"))?;
    verifying
        .verify(&computed, &signature)
        .map_err(|_| format!("{label}: signature invalid for this content"))?;
    match previous_hash {
        None => Ok(()),
        Some(prev) if prev == env.prev_hash => Ok(()),
        Some(prev) => Err(format!(
            "{label}: chain link broken: prev_hash {} does not match previous envelope hash {prev}",
            env.prev_hash
        )),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(text: &str) -> Result<Vec<u8>, String> {
    if !text.len().is_multiple_of(2) {
        return Err("odd-length hex".to_string());
    }
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = hex_value(pair[0])?;
        let lo = hex_value(pair[1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_value(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex digit '{}'", byte as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::OutboxRow;

    fn row(seq: i64, event: &str) -> OutboxRow {
        OutboxRow {
            seq,
            issue_id: format!("demo-{seq}"),
            project: "demo".to_string(),
            occurred_at: 100 + seq,
            event: event.to_string(),
            actor: "tester".to_string(),
            detail: format!("{event} detail"),
        }
    }

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&[7u8; 32])
    }

    #[test]
    fn hex_round_trips_and_rejects_junk() {
        assert_eq!(hex_encode(&[0, 171, 255]), "00abff");
        assert_eq!(hex_decode("00abff").unwrap(), vec![0, 171, 255]);
        assert!(hex_decode("00a").is_err());
        assert!(hex_decode("zz").is_err());
    }

    #[test]
    fn genesis_prev_is_32_zero_bytes() {
        assert_eq!(GENESIS_PREV, [0; 32]);
        assert_eq!(hex_encode(&GENESIS_PREV).len(), 64);
    }

    #[test]
    fn sealed_envelope_verifies_and_tampering_breaks_it() {
        let key = signing_key();
        let mut chain = build_chain(&[row(1, "created"), row(2, "claimed")], &key);
        assert_eq!(chain[0].prev_hash, hex_encode(&GENESIS_PREV));
        assert_eq!(chain[1].prev_hash, chain[0].hash);
        let text = chain
            .iter()
            .map(|env| serde_json::to_string(env).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        assert_eq!(verify_text(&text).unwrap(), 2);

        chain[1].detail = "forged".to_string();
        let tampered = chain
            .iter()
            .map(|env| serde_json::to_string(env).unwrap())
            .collect::<Vec<_>>()
            .join("\n");
        let err = verify_text(&tampered).unwrap_err();
        assert!(err.contains("hash mismatch"), "{err}");
    }
}
