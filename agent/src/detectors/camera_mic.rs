// Camera/Mic access detector.
//
// Windows records app camera/mic usage in:
//   HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam
//   HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone
// Each app subkey has a `LastUsedTimeStart` (FILETIME, REG_QWORD).
// We poll, and any new (app, kind, timestamp) triple emits an event.

use crate::store::{now_event, Store};
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;

const POLL_SECS: u64 = 30;
const BASES: &[(&str, &str)] = &[
    ("webcam",     r"HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam"),
    ("microphone", r"HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\microphone"),
];

pub async fn run(store: Arc<Store>) {
    let primed = matches!(store.mark_seen("cammic_meta", "primed"), Ok(false));
    loop {
        for (kind, base) in BASES {
            if let Err(e) = scan(&store, kind, base, primed).await {
                tracing::warn!("camera_mic {kind}: {e:#}");
            }
        }
        tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

async fn scan(store: &Arc<Store>, kind: &str, base: &str, primed: bool) -> Result<()> {
    // /s = recursive. We get LastUsedTimeStart values per app subkey.
    let out = Command::new("reg").args(["query", base, "/s", "/v", "LastUsedTimeStart"]).output().await?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut current_key = String::new();
    for line in text.lines() {
        let trimmed = line.trim_end();
        if trimmed.starts_with("HKEY_") {
            current_key = trimmed.to_string();
        } else if trimmed.contains("LastUsedTimeStart") && trimmed.contains("REG_QWORD") {
            // "    LastUsedTimeStart    REG_QWORD    0x1d..."
            let value = trimmed.split_whitespace().last().unwrap_or("0").to_string();
            if value == "0x0" {
                continue;
            }
            let app = current_key.rsplit('\\').next().unwrap_or("?").to_string();
            let key = format!("{kind}|{app}|{value}");
            let is_new = store.mark_seen("cammic", &key)?;
            if is_new && primed {
                let event_kind: &str = if (*kind).eq("webcam") { "camera_used" } else { "microphone_used" };
                let ev = now_event(
                    "camera_mic",
                    "warn",
                    event_kind,
                    format!("{kind} used by {app}"),
                    serde_json::json!({ "kind": kind, "app": app, "filetime_hex": value }),
                );
                store.insert_event(&ev)?;
            }
        }
    }
    Ok(())
}
