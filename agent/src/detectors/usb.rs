// USB device insertion detector.
//
// Polls `Get-PnpDevice -PresentOnly` filtered to USB-related classes,
// fingerprinting each device by InstanceId. First sweep silently primes
// the seen-set; subsequent sweeps emit warn `usb_inserted` for any new
// fingerprint and info `usb_removed` when one disappears (helps catch
// brief data-exfil sticks). Mass-storage devices are upgraded to alert
// because they're the obvious malware/exfil vector.
//
// Why poll instead of subscribing to WM_DEVICECHANGE: that needs a
// window message pump, which we don't have in a console agent. Polling
// every 15s is cheap.

use crate::store::{now_event, Store};
use anyhow::Result;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::process::Command;

const POLL_SECS: u64 = 15;

pub async fn run(store: Arc<Store>) {
    let primed = matches!(store.mark_seen("usb_meta", "primed"), Ok(false));
    let last_seen: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));

    loop {
        match enumerate().await {
            Ok(devs) => {
                let mut prev = last_seen.lock().unwrap();
                let current: HashSet<String> = devs.iter().map(|d| d.instance_id.clone()).collect();

                if primed {
                    for dev in &devs {
                        if !prev.contains(&dev.instance_id) {
                            let is_storage = dev.class.eq_ignore_ascii_case("USB")
                                && (dev.friendly.to_ascii_lowercase().contains("storage")
                                    || dev.friendly.to_ascii_lowercase().contains("disk"))
                                || dev.class.eq_ignore_ascii_case("DiskDrive");
                            let severity = if is_storage { "alert" } else { "warn" };
                            let _ = store.insert_event(&now_event(
                                "usb",
                                severity,
                                "usb_inserted",
                                format!("USB attached: {}", dev.friendly),
                                serde_json::json!({
                                    "instance_id": dev.instance_id,
                                    "friendly": dev.friendly,
                                    "class": dev.class,
                                    "storage": is_storage,
                                }),
                            ));
                        }
                    }
                    for old in prev.difference(&current) {
                        let _ = store.insert_event(&now_event(
                            "usb",
                            "info",
                            "usb_removed",
                            format!("USB removed: {}", old),
                            serde_json::json!({ "instance_id": old }),
                        ));
                    }
                }
                *prev = current;
            }
            Err(e) => tracing::warn!("usb enumerate failed: {e:#}"),
        }
        tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

struct UsbDev {
    instance_id: String,
    friendly: String,
    class: String,
}

async fn enumerate() -> Result<Vec<UsbDev>> {
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-PnpDevice -PresentOnly | Where-Object { $_.InstanceId -like 'USB*' -or $_.InstanceId -like 'USBSTOR*' } | Select-Object InstanceId,FriendlyName,Class | ConvertTo-Csv -NoTypeInformation",
        ])
        .output()
        .await?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut devs = Vec::new();
    for (i, line) in text.lines().enumerate() {
        if i == 0 { continue; } // header
        let cols: Vec<&str> = line.split("\",\"").collect();
        if cols.len() < 3 { continue; }
        let instance_id = cols[0].trim_start_matches('"').to_string();
        let friendly = cols[1].to_string();
        let class = cols[2].trim_end_matches('"').to_string();
        if instance_id.is_empty() { continue; }
        devs.push(UsbDev { instance_id, friendly, class });
    }
    Ok(devs)
}
