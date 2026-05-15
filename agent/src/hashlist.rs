// MalwareBazaar SHA256 hash blocklist (abuse.ch).
//
// Pulls https://bazaar.abuse.ch/export/txt/sha256/recent/ — the "last 60
// days, ~50k samples" feed — and caches it to <data_dir>/mbazaar.sha256.
// The scan-on-write detector calls `is_blocked()` on the hash of every
// freshly-created file in user-writable drop dirs and triggers a
// quarantine on hit.
//
// We deliberately use the recent feed (not the 700k full feed) because:
//   * recent samples are what end users actually encounter today,
//   * the full feed is an 80MB zip on every refresh — would burn data,
//   * detection-first is fine; we are not trying to be ClamAV.
//
// Failure modes are silent (degrades to "no signatures loaded") — refusing
// to start because abuse.ch is unreachable would be worse than running
// without the hashlist layer.

use anyhow::{Context, Result};
use directories::ProjectDirs;
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::RwLock;
use std::time::{Duration, SystemTime};

const URL: &str = "https://bazaar.abuse.ch/export/txt/sha256/recent/";
const REFRESH_HOURS: u64 = 6;
const REFRESH: Duration = Duration::from_secs(REFRESH_HOURS * 3600);

static HASHES: RwLock<Option<HashSet<String>>> = RwLock::new(None);

fn cache_path() -> Result<PathBuf> {
    let proj = ProjectDirs::from("cam", "bastion", "bastion")
        .context("ProjectDirs")?;
    Ok(proj.data_dir().join("mbazaar.sha256"))
}

fn parse(text: &str) -> HashSet<String> {
    let mut out = HashSet::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }
        // Lines are pure 64-char hex sha256 (one per line).
        if line.len() == 64 && line.chars().all(|c| c.is_ascii_hexdigit()) {
            out.insert(line.to_ascii_lowercase());
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
        .timeout(Duration::from_secs(120))
        .user_agent("bastion-agent/0.2")
        .build()
        .ok()
}

/// Force a one-shot hashlist refresh (used by /api/scan/run). Returns the
/// number of hashes loaded after the refresh attempt.
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
    *HASHES.write().unwrap() = Some(set);
    Ok(n)
}

pub async fn refresh_loop() {
    if let Some(set) = load_from_disk() {
        let n = set.len();
        *HASHES.write().unwrap() = Some(set);
        tracing::info!("mbazaar: warmed {n} hashes from disk cache");
    }

    loop {
        let need_refresh = match cache_age() {
            Some(age) => age > REFRESH,
            None => true,
        };

        if need_refresh {
            match refresh_now().await {
                Ok(n) => tracing::info!("mbazaar: refreshed {n} hashes"),
                Err(e) => tracing::warn!("mbazaar: refresh failed: {e:?}"),
            }
        }

        tokio::time::sleep(Duration::from_secs(3600)).await;
    }
}

async fn fetch(client: &reqwest::Client) -> Result<HashSet<String>> {
    let res = client.get(URL).send().await?;
    anyhow::ensure!(res.status().is_success(), "mbazaar HTTP {}", res.status());
    let text = res.text().await?;
    Ok(parse(&text))
}

/// Returns true if the SHA-256 hex digest is a known-bad sample.
pub fn is_blocked(sha256_hex: &str) -> bool {
    let guard = HASHES.read().unwrap();
    let Some(set) = guard.as_ref() else { return false };
    set.contains(&sha256_hex.to_ascii_lowercase())
}

pub fn loaded_count() -> usize {
    HASHES.read().unwrap().as_ref().map(|s| s.len()).unwrap_or(0)
}
