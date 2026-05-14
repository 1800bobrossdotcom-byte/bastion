// Registry decoys (N7)
// ----------------------------------------------------------------------------
// We plant convincingly-named credential-looking values under our own subkey
//   HKCU\Software\Bastion\Decoys\Credentials\
// Each value embeds an HMAC-SHA256 tag derived from a per-install secret so a
// leaked decoy can be tied back to this machine.
//
// Why this catches things: many credential-stealers (RedLine, Vidar, Raccoon,
// generic "infostealer" families) recursively walk HKCU/HKLM grepping for
// keywords like "token", "password", "key", "vpn". The decoys look exactly
// like what they want. v1 detects when a decoy is *modified or deleted*, which
// catches:
//   * cleanup-after-exfil (attacker erases collected creds to hide tracks)
//   * any tool that "rotates" or overwrites discovered creds
//   * accidental or curious user edits (rare; log as info)
//
// v1 cannot detect pure reads without SACL + Object Access auditing (admin
// required). Documented as v2.

use crate::store::{now_event, Store};
use anyhow::{Context, Result};
use directories::ProjectDirs;
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;

const POLL_SECS: u64 = 60;
const SUBKEY: &str = r"HKCU\Software\Bastion\Decoys\Credentials";

struct Decoy {
    name: &'static str,
    /// Plausible-shape value template, HMAC tag will be appended.
    body: &'static str,
}

const DECOYS: &[Decoy] = &[
    Decoy { name: "aws_session_token",   body: "FQoGZXIvYXdzEPj//////////wEaDExampleSessionTokenForBastionDecoy" },
    Decoy { name: "azure_refresh_token", body: "0.AXoAExampleAzureRefreshTokenJWTShape.eyJhbGciOiJIUzI1NiJ9" },
    Decoy { name: "vpn_password",        body: "Vpn!Pass-2026-Decoy" },
    Decoy { name: "mfa_seed_b32",        body: "JBSWY3DPEHPK3PXP" },
    Decoy { name: "service_account_key", body: "{\"type\":\"service_account\",\"private_key\":\"-----BEGIN PRIVATE KEY-----\\nDecoy\\n-----END PRIVATE KEY-----\"}" },
];

pub async fn run(store: Arc<Store>) {
    if let Err(e) = setup(&store).await {
        tracing::warn!("registry_decoy setup failed: {e:?}");
        return;
    }
    loop {
        if let Err(e) = poll_once(&store).await {
            tracing::warn!("registry_decoy poll error: {e:?}");
        }
        tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

fn data_dir() -> Result<PathBuf> {
    let proj = ProjectDirs::from("cam", "bastion", "bastion")
        .context("could not resolve project dirs")?;
    Ok(proj.data_dir().to_path_buf())
}

fn decoy_secret() -> Result<[u8; 32]> {
    let path = data_dir()?.join("decoy_key.bin");
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

fn hmac_tag(secret: &[u8; 32], decoy_name: &str) -> String {
    let mut key = [0u8; 64];
    key[..32].copy_from_slice(secret);
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let inner = {
        let mut h = Sha256::new();
        h.update(ipad);
        h.update(decoy_name.as_bytes());
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

fn render_value(secret: &[u8; 32], d: &Decoy) -> String {
    format!("{}::bastion-decoy::{}", d.body, hmac_tag(secret, d.name))
}

async fn reg_add(name: &str, value: &str) -> Result<()> {
    // /f = force overwrite, /v = value name, /d = data, /t REG_SZ
    let status = Command::new("reg")
        .args(["add", SUBKEY, "/v", name, "/t", "REG_SZ", "/d", value, "/f"])
        .status()
        .await?;
    anyhow::ensure!(status.success(), "reg add failed for {name}");
    Ok(())
}

async fn reg_query_all() -> Result<HashMap<String, String>> {
    let out = Command::new("reg").args(["query", SUBKEY]).output().await?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut map = HashMap::new();
    for line in text.lines() {
        // Format: "    name    REG_SZ    value"
        let trimmed = line.trim_start();
        if trimmed.is_empty() || trimmed.starts_with("HKEY_") {
            continue;
        }
        // Split on REG_SZ / REG_EXPAND_SZ etc.
        for ty in ["REG_SZ", "REG_EXPAND_SZ", "REG_MULTI_SZ"] {
            if let Some(idx) = trimmed.find(ty) {
                let name = trimmed[..idx].trim().to_string();
                let value = trimmed[idx + ty.len()..].trim().to_string();
                if !name.is_empty() {
                    map.insert(name, value);
                }
                break;
            }
        }
    }
    Ok(map)
}

async fn setup(store: &Store) -> Result<()> {
    let secret = decoy_secret()?;
    let primed = store.mark_seen("decoy_meta", "primed")?;

    for d in DECOYS {
        let value = render_value(&secret, d);
        reg_add(d.name, &value).await?;
    }

    // Snapshot expected values into the canaries table (re-using its
    // (path, sha256, hmac) shape with path = "registry://<key>/<name>").
    for d in DECOYS {
        let expected = render_value(&secret, d);
        let sha = hex::encode(Sha256::digest(expected.as_bytes()));
        let path = format!("registry://{SUBKEY}/{}", d.name);
        store.register_canary(&path, &sha, &hmac_tag(&secret, d.name))?;
    }

    if primed {
        let _ = store.insert_event(&now_event(
            "decoy",
            "info",
            "decoy_baseline",
            format!("planted {} registry decoys under {SUBKEY}", DECOYS.len()),
            serde_json::json!({ "subkey": SUBKEY, "count": DECOYS.len() }),
        ));
    }
    Ok(())
}

async fn poll_once(store: &Store) -> Result<()> {
    let secret = decoy_secret()?;
    let live = reg_query_all().await.unwrap_or_default();

    for d in DECOYS {
        let expected_value = render_value(&secret, d);
        let expected_sha = hex::encode(Sha256::digest(expected_value.as_bytes()));

        match live.get(d.name) {
            None => {
                if store.mark_seen("decoy_missing", d.name)? {
                    let _ = store.insert_event(&now_event(
                        "decoy",
                        "alert",
                        "decoy_deleted",
                        format!("registry decoy deleted: {}", d.name),
                        serde_json::json!({ "subkey": SUBKEY, "name": d.name }),
                    ));
                }
            }
            Some(actual) => {
                let actual_sha = hex::encode(Sha256::digest(actual.as_bytes()));
                if actual_sha != expected_sha {
                    let key = format!("{}|{actual_sha}", d.name);
                    if store.mark_seen("decoy_modified", &key)? {
                        let _ = store.insert_event(&now_event(
                            "decoy",
                            "alert",
                            "decoy_modified",
                            format!("registry decoy modified: {}", d.name),
                            serde_json::json!({
                                "subkey": SUBKEY,
                                "name": d.name,
                                "expected_sha256": expected_sha,
                                "actual_sha256": actual_sha,
                            }),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}
