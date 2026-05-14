// Self-attestation heartbeat (N6)
// ----------------------------------------------------------------------------
// On startup we generate (or load) an Ed25519 keypair, sealed at rest with
// DPAPI (CurrentUser). Every interval we sign a payload describing:
//   - the SHA-256 of our own running binary
//   - the current event-chain head + count
//   - hostname + timestamp
// The signed heartbeat is appended to the event log. Because the chain is
// hash-linked (N1), tampering with any historical event invalidates every
// later heartbeat too — an external verifier (or a paranoid future-you) can
// replay the chain offline and confirm both Merkle integrity AND that each
// heartbeat was signed by the agent's pinned key at the time it claims.
//
// Threat model coverage:
//   * detect agent binary swap (sha256 changes, future heartbeats stop or
//     come from a different key)
//   * detect agent process kill (heartbeats stop arriving)
//   * detect log tampering (chain breaks, attestations no longer verify)
//
// Honest non-coverage: a sufficiently-privileged attacker can extract the
// DPAPI-sealed private key and forge heartbeats. DPAPI raises the bar (key
// is not in plaintext, not in registry, not exfiltrable by another user),
// but it is not a TPM. v2 candidate: store key inside Windows Hello /
// Microsoft Platform Crypto Provider so it cannot leave the TPM.

use crate::dpapi;
use crate::store::{now_event, Store};
use anyhow::{Context, Result};
use directories::ProjectDirs;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

const HEARTBEAT_SECS: u64 = 300; // 5 min

pub async fn run(store: Arc<Store>) {
    let key = match load_or_create_key() {
        Ok(k) => k,
        Err(e) => {
            tracing::warn!("attestation key init failed: {e:?}");
            return;
        }
    };
    let pub_hex = hex::encode(key.verifying_key().to_bytes());
    let agent_sha = match self_binary_sha256() {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!("attestation: failed to hash own binary: {e:?}");
            return;
        }
    };
    let hostname = hostname_string();

    // One-time pubkey announcement so an external verifier can pin it.
    if let Ok(true) = store.mark_seen("attestation_meta", "pubkey_announced") {
        let _ = store.insert_event(&now_event(
            "attestation",
            "info",
            "attestation_pubkey",
            "Agent attestation public key registered".into(),
            serde_json::json!({
                "ed25519_pubkey_hex": pub_hex,
                "agent_binary_sha256": agent_sha,
                "hostname": hostname,
            }),
        ));
    }

    loop {
        let (chain_count, chain_head) = store.chain_tip().unwrap_or((0, String::new()));
        let payload = serde_json::json!({
            "ts": chrono::Utc::now().to_rfc3339(),
            "agent_binary_sha256": agent_sha,
            "hostname": hostname,
            "chain_count": chain_count,
            "chain_head": chain_head,
        });
        let payload_bytes = payload.to_string();
        let sig = key.sign(payload_bytes.as_bytes());
        let _ = store.insert_event(&now_event(
            "attestation",
            "info",
            "attestation_heartbeat",
            format!("attest tip={} head={}", chain_count, &chain_head.chars().take(12).collect::<String>()),
            serde_json::json!({
                "payload": payload,
                "signature_hex": hex::encode(sig.to_bytes()),
                "ed25519_pubkey_hex": pub_hex,
            }),
        ));
        tokio::time::sleep(Duration::from_secs(HEARTBEAT_SECS)).await;
    }
}

fn data_dir() -> Result<PathBuf> {
    let proj = ProjectDirs::from("cam", "bastion", "bastion")
        .context("could not resolve project dirs")?;
    Ok(proj.data_dir().to_path_buf())
}

fn load_or_create_key() -> Result<SigningKey> {
    let path = data_dir()?.join("agent_key.dpapi");
    if path.exists() {
        let sealed = fs::read(&path)?;
        let plain = dpapi::unseal(&sealed)?;
        anyhow::ensure!(plain.len() == 32, "agent_key.dpapi: bad length");
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&plain);
        return Ok(SigningKey::from_bytes(&bytes));
    }
    let key = SigningKey::generate(&mut OsRng);
    let sealed = dpapi::seal(&key.to_bytes())?;
    fs::write(&path, sealed)?;
    Ok(key)
}

fn self_binary_sha256() -> Result<String> {
    let exe = std::env::current_exe()?;
    let bytes = fs::read(exe)?;
    Ok(hex::encode(Sha256::digest(&bytes)))
}

fn hostname_string() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into())
}
