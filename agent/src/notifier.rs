// Outbound notifier — pushes new alert/warn events to a user-controlled
// ntfy.sh topic. Also sends a low-priority heartbeat every 6h so the user
// can notice silence.
//
// Config: write a single line containing the ntfy topic name to
//   %APPDATA%\bastion\bastion\data\ntfy.txt
// e.g.   bastion-myname-39d2
// Pick something unguessable — anyone who knows the topic can read your
// alerts AND publish to it. Treat it like a shared secret.
//
// This is fire-and-forget: failures are logged but never crash the agent.
// We track the last pushed event id in memory only (resets on restart and
// fast-forwards to current head, so a restart never floods the phone with
// historical alerts).

use crate::store::Store;
use anyhow::{Context, Result};
use directories::ProjectDirs;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

const POLL_SECS: u64 = 10;
const HEARTBEAT_SECS: u64 = 6 * 3600; // 6h
const MAX_PER_TICK: i64 = 50;

pub async fn run(store: Arc<Store>) {
    let topic = match read_topic() {
        Ok(Some(t)) => Some(t),
        Ok(None) => {
            tracing::info!("notifier: no ntfy.txt — outbound push disabled (toasts still fire)");
            None
        }
        Err(e) => {
            tracing::warn!("notifier: failed to read ntfy.txt: {e:?}");
            None
        }
    };

    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .user_agent("bastion-agent/0.1")
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!("notifier: reqwest build failed: {e:?}");
            return;
        }
    };
    let url = topic.as_ref().map(|t| format!("https://ntfy.sh/{t}"));

    // Fast-forward: don't backfill past alerts on startup.
    let mut last_id = store.chain_tip().map(|(id, _)| id).unwrap_or(0);
    let mut last_heartbeat = Instant::now();

    // Initial "agent online" message so the user can confirm wiring works.
    if let Some(u) = &url {
        let (_count, head) = store.chain_tip().unwrap_or((0, String::new()));
        let _ = post(
            &client,
            u,
            "BASTION online",
            &format!("agent up · chain head {}", head.chars().take(12).collect::<String>()),
            1,
            Some("white_check_mark"),
        )
        .await;
    }

    loop {
        match store.events_after(last_id, MAX_PER_TICK) {
            Ok(rows) => {
                for ev in rows {
                    if let Some(id) = ev.id {
                        last_id = id;
                    }
                    if ev.severity != "alert" && ev.severity != "warn" {
                        continue;
                    }
                    let title = format!("BASTION {} {}", ev.severity.to_uppercase(), ev.source);
                    let priority = if ev.severity == "alert" { 4 } else { 3 };
                    let tag = if ev.severity == "alert" { "rotating_light" } else { "warning" };
                    if let Some(u) = &url {
                        if let Err(e) = post(&client, u, &title, &ev.summary, priority, Some(tag)).await {
                            tracing::warn!("notifier: push failed: {e:?}");
                        }
                    }
                    // Local Windows toast (best-effort, only on alert to avoid spam).
                    if ev.severity == "alert" {
                        if let Err(e) = crate::toast::show(&title, &ev.summary).await {
                            tracing::debug!("toast failed: {e:?}");
                        }
                    }
                }
            }
            Err(e) => tracing::warn!("notifier: events_after error: {e:?}"),
        }

        if last_heartbeat.elapsed() >= Duration::from_secs(HEARTBEAT_SECS) {
            last_heartbeat = Instant::now();
            if let Some(u) = &url {
                let (count2, head2) = store.chain_tip().unwrap_or((0, String::new()));
                let _ = post(
                    &client,
                    u,
                    "BASTION heartbeat",
                    &format!("alive · {} events · head {}", count2, head2.chars().take(12).collect::<String>()),
                    1,
                    Some("hourglass_flowing_sand"),
                )
                .await;
            }
        }

        tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

async fn post(
    client: &reqwest::Client,
    url: &str,
    title: &str,
    body: &str,
    priority: u8,
    tag: Option<&str>,
) -> Result<()> {
    let mut req = client
        .post(url)
        .header("Title", title)
        .header("Priority", priority.to_string())
        .body(body.to_string());
    if let Some(t) = tag {
        req = req.header("Tags", t);
    }
    let res = req.send().await.context("ntfy POST failed")?;
    anyhow::ensure!(res.status().is_success(), "ntfy returned HTTP {}", res.status());
    Ok(())
}

fn read_topic() -> Result<Option<String>> {
    let path = config_path()?;
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(&path)?;
    let topic = raw.lines().next().unwrap_or("").trim().to_string();
    if topic.is_empty() {
        Ok(None)
    } else {
        Ok(Some(topic))
    }
}

fn config_path() -> Result<PathBuf> {
    let proj = ProjectDirs::from("cam", "bastion", "bastion")
        .context("could not resolve project dirs")?;
    Ok(proj.data_dir().join("ntfy.txt"))
}
