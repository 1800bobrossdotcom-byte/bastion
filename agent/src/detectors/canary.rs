// Canary tokens (N5)
// ----------------------------------------------------------------------------
// We plant decoy files that look juicy to a credential-harvester or a
// reconnaissance script. Each file embeds an HMAC-SHA256 tag derived from a
// per-install secret + the canary's stable name, so we can later prove a leaked
// blob is one of OUR canaries (and which one).
//
// We DO NOT yet detect read-access (Windows ReadDirectoryChangesW does not
// surface read events without object-access SACL auditing, which needs admin +
// audit policy changes). v1 catches:
//   * file deleted   (ransomware or evidence-eraser)
//   * file modified  (in-place encryption, tampering)
//   * file replaced  (overwrite from outside)
//   * SHA-256 drift on periodic check
//
// v2 (planned): enable per-file SACL via SetSecurityInfo + tail
// Microsoft-Windows-Security-Auditing event 4663 to catch READS too.

use crate::store::{now_event, Store};
use anyhow::{Context, Result};
use directories::ProjectDirs;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const POLL_SECS: u64 = 30;

struct Canary {
    name: &'static str,
    body_template: &'static str,
}

// Names + bodies chosen to look plausibly real but contain only fake values.
// HMAC tag is appended at plant-time.
const CANARIES: &[Canary] = &[
    Canary {
        name: "aws_credentials.bak.txt",
        body_template: "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\nregion = us-east-1\n",
    },
    Canary {
        name: ".env.production.backup",
        body_template: "DATABASE_URL=postgres://prod_user:hunter2@db.internal:5432/prod\nSTRIPE_SECRET_KEY=sk_live_51JEXAMPLE_THIS_IS_FAKE\nJWT_SECRET=do-not-use-this-its-bait\n",
    },
    Canary {
        name: "wallet.dat.old",
        body_template: "# Bitcoin Core wallet backup (legacy format)\n# Encrypted with passphrase: see ~/Documents/keepass.kdbx\n00000000  77 61 6c 6c 65 74 20 62  61 69 74 20 64 6f 20 6e\n00000010  6f 74 20 75 73 65 20 74  68 69 73 20 66 69 6c 65\n",
    },
    Canary {
        name: "vpn_credentials.txt",
        body_template: "host: vpn.corp.internal\nport: 1194\nuser: admin\npass: SuperSecret!42\nmfa_seed: JBSWY3DPEHPK3PXP\n",
    },
    Canary {
        name: "ssh_id_rsa",
        body_template: "-----BEGIN OPENSSH PRIVATE KEY-----\nbThisIsNotARealKeyDoNotImportItIntoSSHAgentItWillNotWork12345==\n-----END OPENSSH PRIVATE KEY-----\n",
    },
];

pub async fn run(store: Arc<Store>) {
    if let Err(e) = setup(&store) {
        tracing::warn!("canary setup failed: {e:?}");
        return;
    }

    loop {
        if let Err(e) = poll_once(&store) {
            tracing::warn!("canary poll error: {e:?}");
        }
        tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

fn data_dir() -> Result<PathBuf> {
    let proj = ProjectDirs::from("cam", "bastion", "bastion")
        .context("could not resolve project dirs")?;
    Ok(proj.data_dir().to_path_buf())
}

fn canary_dir() -> Result<PathBuf> {
    let d = data_dir()?.join("canaries");
    fs::create_dir_all(&d)?;
    Ok(d)
}

/// Per-install 32-byte secret used to HMAC-tag each canary body. Anyone who
/// later finds a leaked canary blob can be proved to have come from this
/// machine without leaking the secret itself (the HMAC is in the file).
fn canary_secret() -> Result<[u8; 32]> {
    let path = data_dir()?.join("canary_key.bin");
    if path.exists() {
        let bytes = fs::read(&path)?;
        if bytes.len() == 32 {
            let mut k = [0u8; 32];
            k.copy_from_slice(&bytes);
            return Ok(k);
        }
    }
    let mut k = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut k);
    fs::write(&path, k)?;
    Ok(k)
}

fn hmac_tag(secret: &[u8; 32], canary_name: &str) -> String {
    // Manual HMAC-SHA256 to avoid pulling in a `hmac` crate dep just for this.
    // ipad/opad standard construction.
    let mut key = [0u8; 64];
    if secret.len() > 64 {
        let h = Sha256::digest(secret);
        key[..32].copy_from_slice(&h);
    } else {
        key[..secret.len()].copy_from_slice(secret);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let inner = {
        let mut h = Sha256::new();
        h.update(ipad);
        h.update(canary_name.as_bytes());
        h.finalize()
    };
    let outer = {
        let mut h = Sha256::new();
        h.update(opad);
        h.update(inner);
        h.finalize()
    };
    hex::encode(outer)
}

fn render_body(secret: &[u8; 32], c: &Canary) -> String {
    let tag = hmac_tag(secret, c.name);
    format!(
        "{}\n# bastion-canary v1 // do not edit // hmac={}\n",
        c.body_template, tag
    )
}

fn sha256_of(p: &Path) -> Result<String> {
    let bytes = fs::read(p)?;
    let h = Sha256::digest(&bytes);
    Ok(hex::encode(h))
}

fn setup(store: &Store) -> Result<()> {
    let secret = canary_secret()?;
    let dir = canary_dir()?;
    let primed = store.mark_seen("canary_meta", "primed")?;

    for c in CANARIES {
        let path = dir.join(c.name);
        if !path.exists() {
            fs::write(&path, render_body(&secret, c))?;
        }
        let sha = sha256_of(&path)?;
        let tag = hmac_tag(&secret, c.name);
        store.register_canary(&path.to_string_lossy(), &sha, &tag)?;
    }

    if primed {
        let _ = store.insert_event(&now_event(
            "canary",
            "info",
            "canary_baseline",
            format!("planted {} canary tokens", CANARIES.len()),
            serde_json::json!({ "dir": dir.to_string_lossy(), "count": CANARIES.len() }),
        ));
    }
    Ok(())
}

pub fn poll_once(store: &Store) -> Result<()> {
    let registered = store.list_canaries()?;
    for (path_s, expected_sha) in registered {
        let path = PathBuf::from(&path_s);
        if !path.exists() {
            // mark_seen so we only alert once per disappearance.
            if store.mark_seen("canary_missing", &path_s)? {
                let _ = store.insert_event(&now_event(
                    "canary",
                    "alert",
                    "canary_deleted",
                    format!("canary token deleted: {}", path.file_name().unwrap_or_default().to_string_lossy()),
                    serde_json::json!({ "path": path_s }),
                ));
            }
            continue;
        }
        // If it reappears after being missing, clear the dedup marker so a
        // future deletion alerts again. (Best-effort; harmless if it fails.)
        let _ = store.mark_seen("canary_missing_clear", &path_s);

        let actual_sha = match sha256_of(&path) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if actual_sha != expected_sha {
            let key = format!("{path_s}|{actual_sha}");
            if store.mark_seen("canary_modified", &key)? {
                let _ = store.insert_event(&now_event(
                    "canary",
                    "alert",
                    "canary_modified",
                    format!("canary token modified: {}", path.file_name().unwrap_or_default().to_string_lossy()),
                    serde_json::json!({
                        "path": path_s,
                        "expected_sha256": expected_sha,
                        "actual_sha256": actual_sha,
                    }),
                ));
            }
        }
    }
    Ok(())
}
