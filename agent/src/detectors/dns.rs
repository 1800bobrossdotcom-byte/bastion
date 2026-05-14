// DNS detector — polls the Windows DNS client cache and runs each freshly
// observed name through the DGA scorer (N3). Anything that scores
// "suspicious" emits a warn event with the entropy details.
//
// Why poll Get-DnsClientCache instead of ETW: the DNS-Client/Operational
// channel is disabled by default on Windows and enabling it requires admin
// + a registry/group-policy flip. Get-DnsClientCache works for any user
// out of the box. v2 candidate: detect when the operational channel IS
// enabled and prefer it (sub-second resolution, captures all queries even
// after the cache TTL has expired).
//
// Honest limitations:
//   * cache entries TTL out — we may miss short-lived lookups between polls.
//   * only sees what the local resolver cached; queries that bypass the
//     stub resolver (custom DoH, raw UDP) are invisible.
//   * the heuristic flags random-looking strings, not "known-bad" — pair
//     with a future blocklist (URLhaus / abuse.ch) for high-confidence hits.

use crate::blocklist;
use crate::dga;
use crate::store::{now_event, Store};
use anyhow::Result;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;

const POLL_SECS: u64 = 60;

pub async fn run(store: Arc<Store>) {
    // First sweep: prime the seen-set silently so a cold start doesn't
    // pageyou with everything currently cached.
    let primed = store.mark_seen("dns_meta", "primed").unwrap_or(true);
    let initial = read_cache().await.unwrap_or_default();
    if primed {
        let _ = store.insert_event(&now_event(
            "dns",
            "info",
            "dns_baseline",
            format!("dns cache primed with {} entries", initial.len()),
            serde_json::json!({ "count": initial.len() }),
        ));
    }
    for name in initial {
        let _ = store.mark_seen("dns_seen", &name);
    }

    loop {
        if let Err(e) = poll_once(&store).await {
            tracing::warn!("dns poll error: {e:?}");
        }
        tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

async fn poll_once(store: &Store) -> Result<()> {
    let names = read_cache().await?;
    for name in names {
        let new = store.mark_seen("dns_seen", &name)?;
        if !new {
            continue;
        }
        // URLhaus match takes priority — it's a known-bad signal, not a heuristic.
        if blocklist::is_blocked(&name) {
            let _ = store.insert_event(&now_event(
                "dns",
                "alert",
                "dns_blocklist_hit",
                format!("URLhaus match: {name}"),
                serde_json::json!({ "host": name, "source": "urlhaus" }),
            ));
            continue;
        }
        let s = dga::score(&name);
        if s.suspicious {
            let _ = store.insert_event(&now_event(
                "dns",
                "warn",
                "dns_suspicious",
                format!("suspicious lookup: {name} (entropy {:.2})", s.entropy),
                serde_json::json!({
                    "host": name,
                    "sld": s.sld,
                    "entropy": s.entropy,
                    "vowel_ratio": s.vowel_ratio,
                    "length": s.length,
                    "reason": s.reason,
                }),
            ));
        }
    }
    Ok(())
}

async fn read_cache() -> Result<HashSet<String>> {
    let out = Command::new("powershell")
        .args([
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Get-DnsClientCache | Select-Object -ExpandProperty Name",
        ])
        .output()
        .await?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut set = HashSet::new();
    for line in text.lines() {
        let n = line.trim().to_ascii_lowercase();
        if n.is_empty() || !n.contains('.') {
            continue;
        }
        let n = n.trim_end_matches('.').to_string();
        if n.ends_with(".in-addr.arpa") || n.ends_with(".ip6.arpa") {
            continue;
        }
        set.insert(n);
    }
    Ok(set)
}
