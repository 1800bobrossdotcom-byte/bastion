// Network indicator blocklist — URLhaus + OpenPhish feeds merged.
//
//   URLhaus  (abuse.ch):  https://urlhaus.abuse.ch/downloads/hostfile/
//                         hosts-file format "0.0.0.0 hostname".
//   OpenPhish: https://openphish.com/feed.txt
//                         one full URL per line; we extract the hostname.
//
// Both feeds are merged into a single HashSet so the DNS detector — which
// calls `is_blocked()` on every freshly observed lookup — gets phishing
// AND malware C2 in one check. Failure of either feed is non-fatal: we
// degrade to whatever loaded successfully.

use anyhow::{Context, Result};
use directories::ProjectDirs;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

const URLHAUS_URL:   &str = "https://urlhaus.abuse.ch/downloads/hostfile/";
const OPENPHISH_URL: &str = "https://openphish.com/feed.txt";
const REFRESH_HOURS: u64 = 12;
const REFRESH: Duration = Duration::from_secs(REFRESH_HOURS * 3600);

static HOSTS: RwLock<Option<HashSet<String>>> = RwLock::new(None);

fn cache_path() -> Result<PathBuf> {
    let proj = ProjectDirs::from("cam", "bastion", "bastion")
        .context("ProjectDirs")?;
    Ok(proj.data_dir().join("urlhaus.hosts"))
}

// URLhaus hosts-file parser.
fn parse_urlhaus(text: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let host = line.split_whitespace().nth(1).unwrap_or(line).trim().to_ascii_lowercase();
        if host.is_empty() || !host.contains('.') || host == "0.0.0.0" {
            continue;
        }
        out.insert(host);
    }
    out
}

// OpenPhish full-URL parser — extract the host component (between the // and the next /).
fn parse_openphish(text: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let after_scheme = match line.find("://") {
            Some(i) => &line[i + 3..],
            None => line,
        };
        let host_part = after_scheme.split('/').next().unwrap_or(after_scheme);
        // strip user:pass@ and :port if present
        let host_part = host_part.rsplit('@').next().unwrap_or(host_part);
        let host = host_part.split(':').next().unwrap_or(host_part).to_ascii_lowercase();
        if !host.is_empty() && host.contains('.') {
            out.insert(host);
        }
    }
    out
}

// Disk cache stores hostnames one per line, source-agnostic. Read back the same way.
fn parse(text: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for line in text.lines() {
        let h = line.trim().to_ascii_lowercase();
        if !h.is_empty() && !h.starts_with('#') && h.contains('.') {
            out.insert(h);
        }
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

async fn fetch_and_parse(client: &reqwest::Client, url: &str, parser: fn(&str) -> HashSet<String>) -> Result<HashSet<String>> {
    let res = client.get(url).send().await?;
    anyhow::ensure!(res.status().is_success(), "{url} HTTP {}", res.status());
    let text = res.text().await?;
    Ok(parser(&text))
}

/// Force a one-shot blocklist refresh (used by /api/scan/run). Returns the
/// number of hosts loaded after the refresh attempt (URLhaus + OpenPhish merged).
pub async fn refresh_now() -> Result<usize> {
    let client = build_client().context("reqwest client build failed")?;

    let urlhaus_set = fetch_and_parse(&client, URLHAUS_URL, parse_urlhaus).await
        .unwrap_or_else(|e| { tracing::warn!("urlhaus fetch failed: {e:?}"); HashSet::new() });
    let openphish_set = fetch_and_parse(&client, OPENPHISH_URL, parse_openphish).await
        .unwrap_or_else(|e| { tracing::warn!("openphish fetch failed: {e:?}"); HashSet::new() });

    let mut set = urlhaus_set;
    set.extend(openphish_set);
    if set.is_empty() {
        anyhow::bail!("both blocklist feeds returned empty");
    }

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
        tracing::info!("blocklist: warmed {n} hosts from disk cache");
    }

    loop {
        let need_refresh = match cache_age() {
            Some(age) => age > REFRESH,
            None => true,
        };

        if need_refresh {
            match refresh_now().await {
                Ok(n) => tracing::info!("blocklist: refreshed {n} hosts (urlhaus + openphish)"),
                Err(e) => tracing::warn!("blocklist: refresh failed: {e:?}"),
            }
        }

        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
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
