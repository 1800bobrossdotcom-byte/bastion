mod api;
mod blocklist;
mod config;
mod detectors;
mod dga;
#[cfg(windows)]
mod dpapi;
mod forensic;
mod notifier;
mod quarantine;
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

    let cfg = config::Config::load_or_init()?;
    tracing::info!("bastion-agent starting");
    tracing::info!("data dir: {}", cfg.data_dir.display());
    tracing::info!("API token: {}", cfg.token);
    tracing::info!("dashboard should send header: Authorization: Bearer {}", cfg.token);

    let store = Arc::new(store::Store::open(&cfg.db_path())?);
    store.init_schema()?;

    // Spawn detectors. Each detector pushes Events into the store.
    detectors::spawn_all(store.clone());

    // URLhaus blocklist refresh (background; warms from disk cache).
    tokio::spawn(blocklist::refresh_loop());

    // Outbound notifier (ntfy.sh push + Windows toast). No-op for ntfy if data/ntfy.txt is absent.
    tokio::spawn(notifier::run(store.clone()));

    // HTTP API for the dashboard.
    api::serve(cfg, store).await?;
    Ok(())
}
