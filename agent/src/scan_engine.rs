// Shared scan-and-respond engine.
// ----------------------------------------------------------------------------
// Single chokepoint for "given a file path, decide if it's malicious and act".
// Callers today:
//   * detectors::scan_on_write   (notify / ReadDirectoryChangesW — drop dirs)
//   * detectors::etw_file        (ETW Microsoft-Windows-Kernel-File — all opens, needs admin)
// Callers in the near future:
//   * amsi-provider              (in-proc COM provider — script/macro buffers + paths)
//   * minifilter daemon bridge   (kernel-mode IRP_MJ_CREATE shim over named pipe — Path B)
//
// All paths converge here so:
//   1. Detection logic (hashlist match, future YARA, future heuristics) lives
//      in one place.
//   2. Quarantine + event emission is consistent (one "malware_hash_match"
//      record per file regardless of which sensor surfaced it).
//   3. We can dedupe across sensors — ETW + notify will both fire on the same
//      Downloads write; we only want one scan + one event.
//
// Honest scope: hash-based matching only for now. Polymorphic samples
// (re-packed, AES-wrapped) bypass hash matching by design — they are caught
// by the behavioural detectors (proc_fp, process_lineage, autoruns, dns).

use crate::hashlist;
use crate::quarantine;
use crate::store::{now_event, Store};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
const DEDUPE_WINDOW: Duration = Duration::from_secs(30);

fn dedupe() -> &'static Mutex<HashMap<PathBuf, Instant>> {
    static M: OnceLock<Mutex<HashMap<PathBuf, Instant>>> = OnceLock::new();
    M.get_or_init(|| Mutex::new(HashMap::new()))
}

fn already_scanned_recently(path: &Path) -> bool {
    let mut m = dedupe().lock().unwrap();
    let now = Instant::now();
    // GC stale entries opportunistically so the map stays bounded.
    m.retain(|_, t| now.duration_since(*t) < DEDUPE_WINDOW * 4);
    if let Some(t) = m.get(path) {
        if now.duration_since(*t) < DEDUPE_WINDOW {
            return true;
        }
    }
    m.insert(path.to_path_buf(), now);
    false
}

pub fn looks_skippable(p: &Path) -> bool {
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
    if let Some(dd) = directories::ProjectDirs::from("cam", "bastion", "bastion")
        .map(|p| p.data_dir().to_path_buf())
    {
        if p.starts_with(&dd) {
            return true;
        }
    }
    false
}

pub fn sha256_of(p: &Path) -> anyhow::Result<(String, u64)> {
    let meta = std::fs::metadata(p)?;
    let size = meta.len();
    if size == 0 || size > MAX_FILE_BYTES {
        anyhow::bail!("size out of range: {} bytes", size);
    }
    let bytes = std::fs::read(p)?;
    Ok((hex::encode(Sha256::digest(&bytes)), size))
}

/// Scan a single path. `source` is the detector name that triggered the
/// scan (e.g. "scan_on_write", "etw_file", "amsi"). Returns Ok(true) if a
/// hash match was found and the file was quarantined (or quarantine was
/// attempted — vault copy is preserved even when delete fails).
pub fn scan_path(store: &Arc<Store>, path: &Path, source: &'static str) -> anyhow::Result<bool> {
    if !path.is_file() {
        return Ok(false);
    }
    if looks_skippable(path) {
        return Ok(false);
    }
    if already_scanned_recently(path) {
        return Ok(false);
    }

    let (sha, size) = sha256_of(path)?;
    if !hashlist::is_blocked(&sha) {
        return Ok(false);
    }

    let path_s = path.to_string_lossy().to_string();
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| path_s.clone());

    let _ = store.insert_event(&now_event(
        source,
        "alert",
        "malware_hash_match",
        format!("MalwareBazaar hash match: {name}"),
        serde_json::json!({
            "path": path_s,
            "sha256": sha,
            "size": size,
            "source": "abuse.ch/MalwareBazaar",
            "trigger": source,
        }),
    ));

    let reason = format!("malware_hash_match (MalwareBazaar via {source})");
    match quarantine::quarantine_file(store, path, &reason) {
        Ok(rec) => {
            tracing::info!(
                "scan_engine[{}]: auto-quarantined {} (vault {})",
                source,
                path_s,
                rec.vault_id
            );
        }
        Err(e) => {
            tracing::warn!("scan_engine[{}]: quarantine failed for {}: {:?}", source, path_s, e);
        }
    }
    Ok(true)
}
