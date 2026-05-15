// Real-time scan-on-write
// ----------------------------------------------------------------------------
// Watches the user's drop directories (Downloads, Desktop, Documents) using
// the same `notify` recommended-watcher backend Windows uses internally
// (ReadDirectoryChangesW). On every Create event we:
//
//   1. Skip directories, oversize files, and our own data dir.
//   2. Read the file, compute SHA-256.
//   3. Check the MalwareBazaar hash blocklist.
//   4. On hit:
//        a. emit a `malware_hash_match` ALERT event,
//        b. call `quarantine::quarantine_file()` to vault + delete the
//           original (best-effort — file may be in use, in which case the
//           vault copy is preserved as evidence and the user is alerted).
//
// This delivers the two AV-table rows BASTION used to lose:
//   * "Signature AV scan-on-write database"   (via MalwareBazaar)
//   * "Real-time auto-block of malicious file" (via auto-quarantine)
//
// Honest scope:
//   * We watch user-writable drop dirs by default. We deliberately do NOT
//     watch C:\Windows or Program Files because we don't have permission to
//     hash most files there and Defender already covers that surface.
//   * Hash-only matching catches commodity malware (the kind that lands in
//     Downloads). Polymorphic / re-packed samples need behavioural detection,
//     which the rest of BASTION provides.

use crate::hashlist;
use crate::quarantine;
use crate::store::{now_event, Store};
use anyhow::Result;
use directories::{ProjectDirs, UserDirs};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
// Tiny grace before we hash — many downloaders create then write asynchronously,
// so we'd race the writer if we hashed on the very first Create event.
const HASH_DELAY_MS: u64 = 750;

fn watched_dirs() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Some(u) = UserDirs::new() {
        if let Some(p) = u.download_dir() { v.push(p.to_path_buf()); }
        if let Some(p) = u.desktop_dir()  { v.push(p.to_path_buf()); }
        if let Some(p) = u.document_dir() { v.push(p.to_path_buf()); }
    }
    v
}

fn agent_data_dir() -> Option<PathBuf> {
    ProjectDirs::from("cam", "bastion", "bastion").map(|p| p.data_dir().to_path_buf())
}

fn looks_skippable(p: &Path) -> bool {
    // Browser temp partials + our own vault — never hash.
    if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
        if name.ends_with(".crdownload")
            || name.ends_with(".part")
            || name.ends_with(".tmp")
            || name.starts_with('~')
        {
            return true;
        }
    }
    if let Some(dd) = agent_data_dir() {
        if p.starts_with(&dd) { return true; }
    }
    false
}

fn sha256_of(p: &Path) -> Result<(String, u64)> {
    let meta = std::fs::metadata(p)?;
    let size = meta.len();
    if size == 0 || size > MAX_FILE_BYTES {
        anyhow::bail!("size out of range: {} bytes", size);
    }
    let bytes = std::fs::read(p)?;
    Ok((hex::encode(Sha256::digest(&bytes)), size))
}

pub async fn run(store: Arc<Store>) {
    let dirs = watched_dirs();
    if dirs.is_empty() {
        tracing::warn!("scan_on_write: no user dirs resolvable, detector idle");
        return;
    }

    // Bridge notify's std-thread callback into a tokio channel.
    let (tx, mut rx) = mpsc::unbounded_channel::<Event>();
    let mut watcher: RecommendedWatcher = match RecommendedWatcher::new(
        move |res: notify::Result<Event>| {
            if let Ok(ev) = res {
                let _ = tx.send(ev);
            }
        },
        Config::default().with_poll_interval(Duration::from_secs(2)),
    ) {
        Ok(w) => w,
        Err(e) => {
            tracing::warn!("scan_on_write: watcher init failed: {e:?}");
            return;
        }
    };

    let mut watching = Vec::new();
    for d in &dirs {
        if !d.exists() { continue; }
        match watcher.watch(d, RecursiveMode::Recursive) {
            Ok(_) => watching.push(d.clone()),
            Err(e) => tracing::warn!("scan_on_write: watch {} failed: {e:?}", d.display()),
        }
    }
    if watching.is_empty() {
        tracing::warn!("scan_on_write: no dirs watchable, detector idle");
        return;
    }
    let _ = store.insert_event(&now_event(
        "scan_on_write",
        "info",
        "watcher_started",
        format!("realtime scan armed on {} dir(s)", watching.len()),
        serde_json::json!({
            "dirs": watching.iter().map(|p| p.display().to_string()).collect::<Vec<_>>(),
        }),
    ));

    while let Some(ev) = rx.recv().await {
        let creates: Vec<PathBuf> = match ev.kind {
            EventKind::Create(_) => ev.paths,
            EventKind::Modify(notify::event::ModifyKind::Name(_)) => ev.paths,
            _ => continue,
        };

        for path in creates {
            if !path.is_file() { continue; }
            if looks_skippable(&path) { continue; }

            // Hash on a worker so the watcher loop never blocks on large files.
            let store_c = store.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(HASH_DELAY_MS)).await;
                if !path.is_file() { return; }
                let (sha, size) = match sha256_of(&path) {
                    Ok(v) => v,
                    Err(_) => return,
                };
                if !hashlist::is_blocked(&sha) { return; }

                let path_s = path.to_string_lossy().to_string();
                let _ = store_c.insert_event(&now_event(
                    "scan_on_write",
                    "alert",
                    "malware_hash_match",
                    format!(
                        "MalwareBazaar hash match: {}",
                        path.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_else(|| path_s.clone()),
                    ),
                    serde_json::json!({
                        "path": path_s,
                        "sha256": sha,
                        "size": size,
                        "source": "abuse.ch/MalwareBazaar",
                    }),
                ));

                match quarantine::quarantine_file(&store_c, &path, "malware_hash_match (MalwareBazaar)") {
                    Ok(rec) => tracing::info!("scan_on_write: auto-quarantined {} (vault {})", path_s, rec.vault_id),
                    Err(e) => tracing::warn!("scan_on_write: quarantine failed for {path_s}: {e:?}"),
                }
            });
        }
    }
}
