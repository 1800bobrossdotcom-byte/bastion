// Real-time scan-on-write (drop-directory watcher).
// ----------------------------------------------------------------------------
// User-mode file watcher (notify / ReadDirectoryChangesW) on the typical
// drop dirs: Downloads, Desktop, Documents. Every CREATE / RENAME event
// is funnelled into `scan_engine::scan_path` which handles hash lookup,
// quarantine, and event emission. Compare with `detectors::etw_file` which
// covers all file opens system-wide but needs admin to start its ETW trace.
//
// Honest scope:
//   * We watch user-writable drop dirs by default. We deliberately do NOT
//     watch C:\Windows or Program Files because we don't have permission to
//     hash most files there and Defender already covers that surface.
//   * Hash-only matching catches commodity malware (the kind that lands in
//     Downloads). Polymorphic / re-packed samples need behavioural detection,
//     which the rest of BASTION provides.

use crate::scan_engine;
use crate::store::{now_event, Store};
use directories::UserDirs;
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;

// Tiny grace before we hash — many downloaders create then write
// asynchronously, so we'd race the writer if we hashed on the very first
// Create event.
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
            // Hash on a worker so the watcher loop never blocks on large files.
            let store_c = store.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(HASH_DELAY_MS)).await;
                if !path.is_file() { return; }
                let _ = tokio::task::spawn_blocking(move || {
                    let _ = scan_engine::scan_path(&store_c, &path, "scan_on_write");
                })
                .await;
            });
        }
    }
}
