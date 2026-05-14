// File-integrity monitor (FIM)
// ----------------------------------------------------------------------------
// Maintains a SHA-256 baseline for a small, surgical set of high-value files
// where any change is meaningful: the system hosts file plus the user and
// system startup folders. Emits:
//   * file_added    (new file in a watched dir)
//   * file_modified (sha256 drift on a baselined file)
//   * file_deleted  (baselined file disappeared)
//
// We deliberately DO NOT watch huge volatile trees. FIM is for places where
// every change is a question worth asking.

use crate::store::{now_event, Store};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

const POLL_SECS: u64 = 120;
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

fn watched_files() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(sysroot) = std::env::var("SystemRoot") {
        v.push(PathBuf::from(sysroot).join("System32\\drivers\\etc\\hosts"));
    }
    v
}

fn watched_dirs() -> Vec<PathBuf> {
    let mut v = Vec::new();
    if let Ok(appdata) = std::env::var("APPDATA") {
        v.push(PathBuf::from(appdata).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup"));
    }
    if let Ok(programdata) = std::env::var("ProgramData") {
        v.push(PathBuf::from(programdata).join("Microsoft\\Windows\\Start Menu\\Programs\\StartUp"));
    }
    v
}

fn sha256_of(p: &Path) -> Result<(String, u64)> {
    let meta = fs::metadata(p)?;
    let size = meta.len();
    if size > MAX_FILE_BYTES {
        return Ok((format!("oversize:{}", size), size));
    }
    let bytes = fs::read(p)?;
    let h = Sha256::digest(&bytes);
    Ok((hex::encode(h), size))
}

fn mtime_of(p: &Path) -> String {
    fs::metadata(p)
        .and_then(|m| m.modified())
        .map(|t| {
            let dt: chrono::DateTime<chrono::Utc> = t.into();
            dt.to_rfc3339()
        })
        .unwrap_or_default()
}

pub async fn run(store: Arc<Store>) {
    loop {
        if let Err(e) = poll_once(&store) {
            tracing::warn!("fim poll error: {e:?}");
        }
        tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

pub fn poll_once(store: &Store) -> Result<()> {
    for f in watched_files() {
        check_file(store, &f)?;
    }
    for d in watched_dirs() {
        check_dir(store, &d)?;
    }
    Ok(())
}

fn check_file(store: &Store, path: &Path) -> Result<()> {
    let path_s = path.to_string_lossy().to_string();
    if !path.exists() {
        if store.fim_get(&path_s)?.is_some() {
            store.fim_delete(&path_s).ok();
            let _ = store.insert_event(&now_event(
                "fim",
                "alert",
                "file_deleted",
                format!("watched file deleted: {}", path_s),
                serde_json::json!({ "path": path_s }),
            ));
        }
        return Ok(());
    }

    let (sha, size) = match sha256_of(path) {
        Ok(v) => v,
        Err(_) => return Ok(()),
    };
    let mtime = mtime_of(path);

    match store.fim_get(&path_s)? {
        None => {
            store.fim_upsert(&path_s, &sha, size as i64, &mtime)?;
            if store.mark_seen("fim_first_seen", &path_s)? {
                let _ = store.insert_event(&now_event(
                    "fim",
                    "info",
                    "file_baseline",
                    format!("baselined: {}", path_s),
                    serde_json::json!({ "path": path_s, "sha256": sha, "size": size }),
                ));
            }
        }
        Some((prev_sha, _, _)) if prev_sha != sha => {
            store.fim_upsert(&path_s, &sha, size as i64, &mtime)?;
            let _ = store.insert_event(&now_event(
                "fim",
                "alert",
                "file_modified",
                format!("watched file changed: {}", path_s),
                serde_json::json!({
                    "path": path_s,
                    "prev_sha256": prev_sha,
                    "sha256": sha,
                    "size": size,
                    "mtime": mtime
                }),
            ));
        }
        _ => {}
    }
    Ok(())
}

fn check_dir(store: &Store, dir: &Path) -> Result<()> {
    if !dir.exists() {
        return Ok(());
    }
    let dir_s = dir.to_string_lossy().to_string();

    // First time we ever scan this dir → silently baseline everything; no
    // "added" events for files that pre-date bastion's installation.
    let dir_first_scan = store.mark_seen("fim_dir_primed", &dir_s)?;

    let mut current: Vec<PathBuf> = Vec::new();
    for entry in fs::read_dir(dir)?.flatten() {
        let p = entry.path();
        if p.is_file() {
            current.push(p);
        }
    }
    let current_set: std::collections::HashSet<String> =
        current.iter().map(|p| p.to_string_lossy().to_string()).collect();

    // Deletions: paths in baseline under this dir that no longer exist.
    for prev in store.fim_paths_under(&format!("{}\\", dir_s))? {
        if !current_set.contains(&prev) {
            store.fim_delete(&prev).ok();
            let _ = store.insert_event(&now_event(
                "fim",
                "alert",
                "file_deleted",
                format!("startup file deleted: {}", prev),
                serde_json::json!({ "path": prev, "dir": dir_s }),
            ));
        }
    }

    // Adds + modifications.
    for p in current {
        let path_s = p.to_string_lossy().to_string();
        let (sha, size) = match sha256_of(&p) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let mtime = mtime_of(&p);
        match store.fim_get(&path_s)? {
            None => {
                store.fim_upsert(&path_s, &sha, size as i64, &mtime)?;
                if !dir_first_scan {
                    let _ = store.insert_event(&now_event(
                        "fim",
                        "warn",
                        "file_added",
                        format!("new startup file: {}", path_s),
                        serde_json::json!({
                            "path": path_s,
                            "dir": dir_s,
                            "sha256": sha,
                            "size": size
                        }),
                    ));
                }
            }
            Some((prev_sha, _, _)) if prev_sha != sha => {
                store.fim_upsert(&path_s, &sha, size as i64, &mtime)?;
                let _ = store.insert_event(&now_event(
                    "fim",
                    "alert",
                    "file_modified",
                    format!("startup file changed: {}", path_s),
                    serde_json::json!({
                        "path": path_s,
                        "prev_sha256": prev_sha,
                        "sha256": sha,
                        "size": size,
                        "mtime": mtime
                    }),
                ));
            }
            _ => {}
        }
    }
    Ok(())
}
