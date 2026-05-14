// Defender + Firewall event log aggregator.
//
// Polls Windows event log channels via `wevtutil qe` for high-signal
// events. Bookmarks the last RecordId per channel in the `seen` table
// so a restart never floods.
//
// Channels:
//   * Microsoft-Windows-Windows Defender/Operational
//       1006/1116 malware detected           -> alert
//       1007/1117 action taken               -> warn
//       1015      suspicious behavior        -> warn
//       5001      real-time protection OFF   -> alert
//       5004/5007 config changed             -> warn
//   * Microsoft-Windows-Windows Firewall With Advanced Security/Firewall
//       2003      firewall setting changed   -> alert
//       2004/2005 rule added/changed         -> warn
//       2006      rule deleted               -> warn
//       2009      GPO load failed            -> alert
//       2010      profile changed            -> warn
//
// wevtutil works without admin for the Operational channels above.

use crate::store::{now_event, Store};
use anyhow::Result;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;

const POLL_SECS: u64 = 60;

struct Channel {
    name: &'static str,
    source: &'static str,
    interesting: &'static [u32],
    alert_ids: &'static [u32],
}

const CHANNELS: &[Channel] = &[
    Channel {
        name: "Microsoft-Windows-Windows Defender/Operational",
        source: "defender",
        interesting: &[1006, 1007, 1015, 1116, 1117, 5001, 5004, 5007],
        alert_ids: &[1006, 1116, 5001],
    },
    Channel {
        name: "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall",
        source: "firewall",
        interesting: &[2003, 2004, 2005, 2006, 2009, 2010],
        alert_ids: &[2003, 2009],
    },
];

pub async fn run(store: Arc<Store>) {
    for ch in CHANNELS {
        if let Err(e) = prime(&store, ch).await {
            tracing::warn!("eventlog prime {}: {e:#}", ch.source);
        }
    }
    loop {
        for ch in CHANNELS {
            if let Err(e) = poll(&store, ch).await {
                tracing::warn!("eventlog poll {}: {e:#}", ch.source);
            }
        }
        tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

/// Force one poll cycle across every channel (used by /api/scan/run).
pub async fn scan_now(store: &Arc<Store>) -> Result<()> {
    for ch in CHANNELS {
        if let Err(e) = poll(store, ch).await {
            tracing::warn!("eventlog scan_now {}: {e:#}", ch.source);
        }
    }
    Ok(())
}

async fn prime(store: &Arc<Store>, ch: &Channel) -> Result<()> {
    let out = Command::new("wevtutil")
        .args(["qe", ch.name, "/c:1", "/rd:true", "/f:text"])
        .output()
        .await?;
    let text = String::from_utf8_lossy(&out.stdout);
    if let Some(rid) = parse_record_id(&text) {
        store.set_highwater(&format!("{}|hw", ch.source), rid)?;
    }
    Ok(())
}

async fn poll(store: &Arc<Store>, ch: &Channel) -> Result<()> {
    let key = format!("{}|hw", ch.source);
    let last = store.get_highwater(&key)?.unwrap_or(0);
    let xpath = format!("*[System[EventRecordID > {}]]", last);
    let out = Command::new("wevtutil")
        .arg("qe")
        .arg(ch.name)
        .arg(format!("/q:{}", xpath))
        .args(["/c:50", "/rd:true", "/f:text"])
        .output()
        .await?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        if stderr.contains("not found") || stderr.contains("disabled") || stderr.contains("denied") {
            return Ok(());
        }
    }

    let text = String::from_utf8_lossy(&out.stdout);
    let mut new_high = last;
    for raw in split_events(&text) {
        let Some(rid) = parse_record_id(&raw) else { continue };
        if rid <= last { continue; }
        if rid > new_high { new_high = rid; }
        let Some(eid) = parse_event_id(&raw) else { continue };
        if !ch.interesting.contains(&eid) { continue; }
        let severity = if ch.alert_ids.contains(&eid) { "alert" } else { "warn" };
        let summary = first_message_line(&raw)
            .unwrap_or_else(|| format!("{} event {}", ch.source, eid));
        let _ = store.insert_event(&now_event(
            ch.source,
            severity,
            &format!("evt_{}", eid),
            summary,
            serde_json::json!({
                "channel": ch.name,
                "event_id": eid,
                "record_id": rid,
            }),
        ));
    }
    if new_high > last {
        store.set_highwater(&key, new_high)?;
    }
    Ok(())
}

fn split_events(text: &str) -> Vec<String> {
    let mut events: Vec<String> = Vec::new();
    let mut cur = String::new();
    for line in text.lines() {
        if line.starts_with("Event[") && !cur.is_empty() {
            events.push(std::mem::take(&mut cur));
        }
        cur.push_str(line);
        cur.push('\n');
    }
    if !cur.trim().is_empty() { events.push(cur); }
    events
}

fn parse_record_id(raw: &str) -> Option<u64> {
    for line in raw.lines() {
        if let Some(rest) = line.trim().strip_prefix("Record ID:") {
            return rest.trim().parse::<u64>().ok();
        }
    }
    None
}

fn parse_event_id(raw: &str) -> Option<u32> {
    for line in raw.lines() {
        if let Some(rest) = line.trim().strip_prefix("Event ID:") {
            return rest.trim().parse::<u32>().ok();
        }
    }
    None
}

fn first_message_line(raw: &str) -> Option<String> {
    let mut in_desc = false;
    for line in raw.lines() {
        if in_desc {
            let t = line.trim();
            if !t.is_empty() {
                return Some(t.chars().take(180).collect());
            }
        }
        if line.trim().starts_with("Description:") {
            in_desc = true;
        }
    }
    None
}
