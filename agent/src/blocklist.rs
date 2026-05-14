// URLhaus host blocklist (abuse.ch).
//
// Downloads https://urlhaus.abuse.ch/downloads/hostfile/ once every
// REFRESH_HOURS, caches to <data_dir>/urlhaus.hosts (line-delimited
// "0.0.0.0 hostname" pairs from upstream — we only keep the hostname).
//
// The DNS detector calls `is_blocked()` on every newly observed lookup
// and upgrades the event severity to alert when matched.
//
// Failure modes are silent (returns empty set) — refusing to start the
// agent because abuse.ch is unreachable would be worse than degrading
// to "DGA-only" mode.

use anyhow::{Context, Result};
use directories::ProjectDirs;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

const URL: &str = "https://urlhaus.abuse.ch/downloads/hostfile/";
const REFRESH_HOURS: u64 = 12;
const REFRESH: Duration = Duration::from_secs(REFRESH_HOURS * 3600);

static HOSTS: RwLock<Option<HashSet<String>>> = RwLock::new(None);

fn cache_path() -> Result<PathBuf> {
    let proj = ProjectDirs::from("cam", "bastion", "bastion")
        .context("ProjectDirs")?;
    Ok(proj.data_dir().join("urlhaus.hosts"))
}

fn parse(text: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // upstream format: "0.0.0.0 hostname"
        let host = line.split_whitespace().nth(1).unwrap_or(line).trim().to_ascii_lowercase();
        if host.is_empty() || !host.contains('.') || host == "0.0.0.0" {
            continue;
        }
        out.insert(host);
    }
    out
}

fn load_from_disk() -> Option<HashSet<String>> {
    let p = cache_path().ok()?;
    let text = std::fs::read_to_string(&p).ok()?;
    let set = parse(&text);
    if set.is_empty() { None } else { Some(set) }
}

fn cache_age() -> Option<Duration> {
    let p = cache_path().ok()?;
    let m = std::fs::metadata(&p).ok()?;
    let mtime = m.modified().ok()?;
    SystemTime::now().duration_since(mtime).ok()
}

fn build_client() -> Option<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .user_agent("bastion-agent/0.1")
        .build()
        .ok()
}

/// Force a one-shot blocklist refresh (used by /api/scan/run). Returns the
/// number of hosts loaded after the refresh attempt.
pub async fn refresh_now() -> Result<usize> {
    let client = build_client().context("reqwest client build failed")?;
    let set = fetch(&client).await?;
    let n = set.len();
    if let Ok(p) = cache_path() {
        if let Some(parent) = p.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let body = set.iter().cloned().collect::<Vec<_>>().join("\n");
        let _ = std::fs::write(&p, body);
    }
    *HOSTS.write().unwrap() = Some(set);
    Ok(n)
}

pub async fn refresh_loop() {
    // Warm from disk on startup (no network needed).
    if let Some(set) = load_from_disk() {
        let n = set.len();
        *HOSTS.write().unwrap() = Some(set);
        tracing::info!("urlhaus: warmed {n} hosts from disk cache");
    }

    loop {
        let need_refresh = match cache_age() {
            Some(age) => age > REFRESH,
            None => true,
        };

        if need_refresh {
            match refresh_now().await {
                Ok(n) => tracing::info!("urlhaus: refreshed {n} hosts"),
                Err(e) => tracing::warn!("urlhaus: refresh failed: {e:?}"),
            }
        }

        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}

async fn fetch(client: &reqwest::Client) -> Result<HashSet<String>> {
    let res = client.get(URL).send().await?;
    anyhow::ensure!(res.status().is_success(), "urlhaus HTTP {}", res.status());
    let text = res.text().await?;
    Ok(parse(&text))
}

/// Returns true if the host (or any of its parent labels) is on the URLhaus list.
pub fn is_blocked(host: &str) -> bool {
    let guard = HOSTS.read().unwrap();
    let Some(set) = guard.as_ref() else { return false };
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if set.contains(&h) { return true; }
    // Match parent labels too — a.b.evil.com hits "evil.com".
    let mut rest = h.as_str();
    while let Some(idx) = rest.find('.') {
        rest = &rest[idx + 1..];
        if rest.contains('.') && set.contains(rest) {
            return true;
        }
    }
    false
}

pub fn loaded_count() -> usize {
    HOSTS.read().unwrap().as_ref().map(|s| s.len()).unwrap_or(0)
}
