// Quarantine vault
// ----------------------------------------------------------------------------
// Active-response primitive. Given a path, we:
//   1. Read the file's bytes (if user has read access — no privilege escalation).
//   2. Compute SHA-256.
//   3. Write the bytes verbatim to `<data_dir>/vault/<id>.bin` (NOT deleted —
//      preserved as evidence).
//   4. Write a sealed manifest `<id>.json` recording original path, sha256,
//      size, mtime, reason, who/when.
//   5. Best-effort delete the original. If the delete fails (file in use,
//      permission denied), we leave the vault copy in place and report the
//      partial action — the user can retry from the dashboard.
//
// This is "soft delete + evidence preservation", not destruction. Anyone who
// later needs the file can copy it back from the vault. The chain log records
// every quarantine, so even if the vault is tampered with later, the merkle
// chain catches it.
//
// We DO NOT encrypt vault contents at rest in v1 (DPAPI is per-user; the
// vault is already inside the per-user data dir which inherits user-only ACLs).
// v2 could DPAPI-seal each .bin if needed.

use crate::store::{now_event, Store};
use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize)]
pub struct QuarantineRecord {
    pub vault_id: String,
    pub original_path: String,
    pub sha256: String,
    pub size: u64,
    pub original_deleted: bool,
    pub reason: String,
}

fn vault_dir() -> Result<PathBuf> {
    let proj = ProjectDirs::from("cam", "bastion", "bastion")
        .context("could not resolve project dirs")?;
    let d = proj.data_dir().join("vault");
    fs::create_dir_all(&d)?;
    Ok(d)
}

fn new_id() -> String {
    use rand::RngCore;
    let mut buf = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Quarantine a single file. Returns the vault record.
///
/// Best-effort delete: if the original cannot be removed (e.g. file in use by
/// another process), `original_deleted=false` and the caller can decide to
/// kill the holding process and retry.
pub fn quarantine_file(store: &Store, path: &Path, reason: &str) -> Result<QuarantineRecord> {
    let path_s = path.to_string_lossy().to_string();

    // Refuse to quarantine paths inside our own data dir — would let an
    // attacker prompt us to evict our own evidence.
    if let Some(proj) = ProjectDirs::from("cam", "bastion", "bastion") {
        if path.starts_with(proj.data_dir()) {
            anyhow::bail!("refusing to quarantine path inside agent data dir");
        }
    }

    let bytes = fs::read(path).with_context(|| format!("read failed: {}", path_s))?;
    let size = bytes.len() as u64;
    let sha = hex::encode(Sha256::digest(&bytes));

    let id = new_id();
    let dir = vault_dir()?;
    let bin_path = dir.join(format!("{}.bin", id));
    let manifest_path = dir.join(format!("{}.json", id));

    fs::write(&bin_path, &bytes)?;

    let mtime = fs::metadata(path)
        .and_then(|m| m.modified())
        .map(|t| {
            let dt: chrono::DateTime<chrono::Utc> = t.into();
            dt.to_rfc3339()
        })
        .unwrap_or_default();

    let manifest = serde_json::json!({
        "vault_id": id,
        "original_path": path_s,
        "sha256": sha,
        "size": size,
        "mtime": mtime,
        "quarantined_at": chrono::Utc::now().to_rfc3339(),
        "reason": reason,
    });
    fs::write(&manifest_path, serde_json::to_vec_pretty(&manifest)?)?;

    let original_deleted = match fs::remove_file(path) {
        Ok(_) => true,
        Err(e) => {
            tracing::warn!("quarantine: original delete failed for {path_s}: {e}");
            false
        }
    };

    let _ = store.insert_event(&now_event(
        "response",
        if original_deleted { "alert" } else { "warn" },
        "file_quarantined",
        format!(
            "quarantined {} ({})",
            path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or(path_s.clone()),
            if original_deleted { "deleted" } else { "copy retained, original NOT removed" }
        ),
        serde_json::json!({
            "vault_id": id,
            "original_path": path_s,
            "sha256": sha,
            "size": size,
            "original_deleted": original_deleted,
            "reason": reason,
        }),
    ));

    Ok(QuarantineRecord {
        vault_id: id,
        original_path: path_s,
        sha256: sha,
        size,
        original_deleted,
        reason: reason.to_string(),
    })
}

/// Restore a vault entry to a chosen path. Refuses to overwrite an existing
/// file (caller must remove first).
pub fn restore(store: &Store, vault_id: &str, dest: &Path) -> Result<()> {
    let dir = vault_dir()?;
    let bin = dir.join(format!("{}.bin", vault_id));
    let manifest = dir.join(format!("{}.json", vault_id));
    if !bin.exists() || !manifest.exists() {
        anyhow::bail!("vault entry not found: {vault_id}");
    }
    if dest.exists() {
        anyhow::bail!("destination already exists: {}", dest.display());
    }
    fs::copy(&bin, dest)?;
    let _ = store.insert_event(&now_event(
        "response",
        "info",
        "file_restored",
        format!("restored {} → {}", vault_id, dest.display()),
        serde_json::json!({ "vault_id": vault_id, "dest": dest.to_string_lossy() }),
    ));
    Ok(())
}

/// List every quarantined item recorded in the vault. Each entry is the raw
/// manifest JSON written at quarantine time. Used by /api/quarantine/list so
/// the dashboard can render a "Removed Items" panel.
pub fn list_vault() -> Result<Vec<serde_json::Value>> {
    let dir = vault_dir()?;
    let mut out: Vec<serde_json::Value> = Vec::new();
    let entries = match fs::read_dir(&dir) {
        Ok(it) => it,
        Err(_) => return Ok(out),
    };
    for ent in entries.flatten() {
        let p = ent.path();
        if p.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let Ok(text) = fs::read_to_string(&p) else { continue };
        let Ok(mut v) = serde_json::from_str::<serde_json::Value>(&text) else { continue };
        // Annotate whether the .bin still exists in the vault.
        if let Some(id) = v.get("vault_id").and_then(|x| x.as_str()).map(|s| s.to_string()) {
            let bin_exists = dir.join(format!("{}.bin", id)).exists();
            v.as_object_mut().map(|o| o.insert("vault_bin_exists".into(), serde_json::Value::Bool(bin_exists)));
        }
        out.push(v);
    }
    // Newest-first by quarantined_at when present.
    out.sort_by(|a, b| {
        let ka = a.get("quarantined_at").and_then(|x| x.as_str()).unwrap_or("");
        let kb = b.get("quarantined_at").and_then(|x| x.as_str()).unwrap_or("");
        kb.cmp(ka)
    });
    Ok(out)
}
