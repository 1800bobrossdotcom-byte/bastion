// N4 — Process behavioral fingerprint.
//
// For each running process we compute a stable fingerprint over
// (parent_exe, exe_basename, sorted_arg_token_set). The set-of-tokens
// approach (vs a hash of the raw arg string) means flag order and
// noisy values like timestamps don't blow up the fingerprint, while
// genuinely new behavior (a new flag like --execute) does.
//
// First sweep silently primes. Subsequent sweeps emit warn
// `proc_fp_novel` when an exe we've seen before runs with a fingerprint
// we've NEVER seen before. New exes are skipped (process_lineage covers
// genuinely new binaries).

use crate::store::{now_event, Store};
use anyhow::Result;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{ProcessRefreshKind, RefreshKind, System};

const POLL_SECS: u64 = 90;

pub async fn run(store: Arc<Store>) {
    let primed = matches!(store.mark_seen("proc_fp_meta", "primed"), Ok(false));
    loop {
        if let Err(e) = sweep(&store, primed).await {
            tracing::warn!("proc_fp sweep: {e:#}");
        }
        tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

async fn sweep(store: &Arc<Store>, primed: bool) -> Result<()> {
    let mut sys = System::new_with_specifics(
        RefreshKind::new().with_processes(ProcessRefreshKind::everything()),
    );
    sys.refresh_processes();

    // Build pid -> exe basename map for parent lookup.
    let mut pid_exe: HashMap<u32, String> = HashMap::new();
    for (pid, p) in sys.processes() {
        let exe = exe_basename(p.exe().and_then(|p| p.to_str()).unwrap_or(""));
        if !exe.is_empty() {
            pid_exe.insert(pid.as_u32(), exe);
        }
    }

    for (pid, p) in sys.processes() {
        let exe_path = p.exe().and_then(|p| p.to_str()).unwrap_or("");
        let exe = exe_basename(exe_path);
        if exe.is_empty() { continue; }
        let parent = p
            .parent()
            .and_then(|pp| pid_exe.get(&pp.as_u32()).cloned())
            .unwrap_or_else(|| "?".into());

        let cmd: Vec<String> = p.cmd().iter().cloned().collect();
        let mut tokens: Vec<String> = cmd
            .iter()
            .skip(1) // arg0 is the exe path itself
            .map(|s| s.to_ascii_lowercase())
            .filter(|s| !s.is_empty() && s.len() < 200)
            .collect();
        tokens.sort();
        tokens.dedup();

        let mut h = Sha256::new();
        h.update(parent.to_ascii_lowercase().as_bytes());
        h.update(b"|");
        h.update(exe.to_ascii_lowercase().as_bytes());
        h.update(b"|");
        for t in &tokens {
            h.update(t.as_bytes());
            h.update(b"\x1f");
        }
        let fp = hex::encode(&h.finalize()[..12]);

        let known_exe_count = store.proc_fp_count_for(&exe).unwrap_or(0);
        let is_new_pair = store.proc_fp_seen(&exe, &fp).unwrap_or(false);

        // Suppress emission if user has explicitly trusted this fingerprint
        // OR the whole exe (e.g. "trust chrome.exe").
        if store.fp_is_trusted(&fp).unwrap_or(false) { continue; }
        if store.exe_is_trusted(&exe).unwrap_or(false) { continue; }

        if primed && is_new_pair && known_exe_count > 0 {
            // The exe is familiar but this combination of (parent + arg-bag) is new.
            let _ = store.insert_event(&now_event(
                "proc_fp",
                "warn",
                "proc_fp_novel",
                format!("{exe}: novel fingerprint (parent={parent})"),
                serde_json::json!({
                    "pid": pid.as_u32(),
                    "exe": exe,
                    "parent": parent,
                    "fp": fp,
                    "tokens": tokens,
                    "path": exe_path,
                    "known_fingerprints": known_exe_count,
                }),
            ));
        }
    }
    Ok(())
}

fn exe_basename(path: &str) -> String {
    let p = path.replace('/', "\\");
    p.rsplit('\\').next().unwrap_or("").to_ascii_lowercase()
}