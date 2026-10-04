mod api;
mod ai_manager;
mod blocklist;
mod config;
mod detectors;
mod dga;
#[cfg(windows)]
mod dpapi;
// DPAPI is Windows-only; elsewhere the agent still builds (for CI and tests)
// and attestation reports that key sealing is unavailable.
#[cfg(not(windows))]
mod dpapi {
    pub fn seal(_: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("DPAPI is only available on Windows")
    }
    pub fn unseal(_: &[u8]) -> anyhow::Result<Vec<u8>> {
        anyhow::bail!("DPAPI is only available on Windows")
    }
}
mod forensic;
mod hashlist;
mod maintenance;
mod notifier;
mod quarantine;
mod scan_engine;
mod store;
mod toast;

use anyhow::Result;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    // `bastion-agent maint ...` runs a one-shot maintenance command and exits.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("maint") {
        return maintenance::cli::run(&args[1..]).await;
    }

    let cfg = config::Config::load_or_init()?;
    tracing::info!("bastion-agent starting");
    tracing::info!("data dir: {}", cfg.data_dir.display());
    tracing::info!("API token: {}", cfg.token);
    tracing::info!("dashboard should send header: Authorization: Bearer {}", cfg.token);

    let store = Arc::new(store::Store::open(&cfg.db_path())?);
    store.init_schema()?;

    // Pre-boot integrity rollup. Runs ONCE synchronously before steady-state
    // detectors so any persistence drift (registry/services/tasks/hosts file)
    // surfaces in the first event the dashboard sees on this boot.
    detectors::boot_scan::run(store.clone()).await;

    // Spawn detectors. Each detector pushes Events into the store.
    detectors::spawn_all(store.clone());

    // Network indicator blocklist refresh (URLhaus + OpenPhish, background;
    // warms from disk cache).
    tokio::spawn(blocklist::refresh_loop());

    // MalwareBazaar SHA256 hashlist refresh (background; powers scan-on-write).
    tokio::spawn(hashlist::refresh_loop());

    // Outbound notifier (ntfy.sh push + Windows toast). No-op for ntfy if data/ntfy.txt is absent.
    tokio::spawn(notifier::run(store.clone()));

    // HTTP API for the dashboard.
    api::serve(cfg, store).await?;
    Ok(())
}
