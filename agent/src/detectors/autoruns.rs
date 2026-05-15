// Autoruns detector.
//
// Watches the most-abused persistence locations:
//   HKCU\Software\Microsoft\Windows\CurrentVersion\Run
//   HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
//   HKLM\Software\Microsoft\Windows\CurrentVersion\Run
//   HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
//   Scheduled tasks  (via `schtasks /Query /FO CSV /NH`)
//   Services         (via `sc query type= service state= all`)
//
// For each entry we mark_seen() with a stable key. New entries -> alert.

use crate::store::{now_event, Store};
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;

const POLL_SECS: u64 = 60;

const REG_KEYS: &[(&str, &str)] = &[
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
    ("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
];

pub async fn run(store: Arc<Store>) {
    // Prime baseline: on first run, mark everything as seen but emit only one
    // info event so we don't spam alerts for stuff that was already there.
    let primed = matches!(store.mark_seen("autoruns_meta", "primed"), Ok(false));
    if !primed {
        let _ = store.insert_event(&now_event(
            "autoruns",
            "info",
            "baseline",
            "Autoruns baseline established".into(),
            serde_json::json!({}),
        ));
    }

    loop {
        if let Err(e) = scan_all(&store, primed).await {
            tracing::warn!("autoruns: {e:#}");
        }
        tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

/// Run all three autorun scans (registry / scheduled tasks / services) once.
/// Exposed so the pre-boot scan rollup can drive a synchronous sweep at startup.
pub async fn scan_all(store: &Arc<Store>, primed: bool) -> Result<()> {
    if let Err(e) = scan_registry(store, primed).await {
        tracing::warn!("autoruns/registry: {e:#}");
    }
    if let Err(e) = scan_tasks(store, primed).await {
        tracing::warn!("autoruns/tasks: {e:#}");
    }
    if let Err(e) = scan_services(store, primed).await {
        tracing::warn!("autoruns/services: {e:#}");
    }
    Ok(())
}

async fn scan_registry(store: &Arc<Store>, primed: bool) -> Result<()> {
    for (hive, sub) in REG_KEYS {
        let path = format!("{hive}\\{sub}");
        let out = Command::new("reg").args(["query", &path]).output().await?;
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            // Lines look like:  "    Name    REG_SZ    Value"
            let line = line.trim();
            if line.is_empty() || line.starts_with("HKEY_") || line.starts_with("End of search") {
                continue;
            }
            if !(line.contains("REG_SZ") || line.contains("REG_EXPAND_SZ")) {
                continue;
            }
            let key = format!("{path}|{line}");
            let is_new = store.mark_seen("autoruns_reg", &key)?;
            if is_new && primed {
                let ev = now_event(
                    "autoruns",
                    "alert",
                    "new_registry_autorun",
                    format!("New autorun in {path}"),
                    serde_json::json!({ "hive": hive, "subkey": sub, "entry": line }),
                );
                store.insert_event(&ev)?;
            }
        }
    }
    Ok(())
}

async fn scan_tasks(store: &Arc<Store>, primed: bool) -> Result<()> {
    let out = Command::new("schtasks").args(["/Query", "/FO", "CSV", "/NH"]).output().await?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let key = line.to_string();
        let is_new = store.mark_seen("autoruns_task", &key)?;
        if is_new && primed {
            let ev = now_event(
                "autoruns",
                "alert",
                "new_scheduled_task",
                "New scheduled task".into(),
                serde_json::json!({ "csv": line }),
            );
            store.insert_event(&ev)?;
        }
    }
    Ok(())
}

async fn scan_services(store: &Arc<Store>, primed: bool) -> Result<()> {
    let out = Command::new("sc").args(["query", "type=", "service", "state=", "all"]).output().await?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let line = line.trim();
        if let Some(name) = line.strip_prefix("SERVICE_NAME:") {
            let key = name.trim().to_string();
            let is_new = store.mark_seen("autoruns_svc", &key)?;
            if is_new && primed {
                let ev = now_event(
                    "autoruns",
                    "alert",
                    "new_service",
                    format!("New service registered: {}", key),
                    serde_json::json!({ "service": key }),
                );
                store.insert_event(&ev)?;
            }
        }
    }
    Ok(())
}
