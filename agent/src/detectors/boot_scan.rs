// Pre-boot / startup integrity rollup
// ----------------------------------------------------------------------------
// Runs ONCE at agent startup, synchronously, before the steady-state polling
// detectors begin emitting. Performs a full integrity sweep of the high-value
// persistence surfaces:
//
//   * FIM:      hosts file + Startup folders (delta vs sha256 baseline)
//   * Autoruns: registry Run/RunOnce + scheduled tasks + services
//
// Then emits a single `pre_boot_scan` event summarising the result. If any
// drift was detected, the individual fim/autoruns detectors will already have
// emitted their per-item alerts during the sweep \u2014 the rollup gives the
// dashboard a single line to surface as "this just happened on boot".
//
// To deliver the AV-table row "Pre-boot rootkit scan", run BASTION as a
// scheduled task at boot/logon (the v0.2 installer wires this; see
// installer/scripts). The rollup event will then fire before the user has
// any chance to interact with a freshly compromised box.
//
// Honest scope: we do not touch UEFI, MBR, or kernel-mode rootkits \u2014 those
// require ring-0 access we deliberately don't take. We catch the persistence
// outcome those rootkits ultimately have to land in (autoruns, scheduled
// tasks, services, hosts file). That is where the user-visible damage lives.

use crate::detectors::{autoruns, fim};
use crate::store::{now_event, Store};
use std::sync::Arc;
use std::time::Instant;

pub async fn run(store: Arc<Store>) {
    let started = Instant::now();
    tracing::info!("pre_boot_scan: starting one-shot integrity sweep");

    let mut errors: Vec<String> = Vec::new();
    let events_before = store.event_count().unwrap_or(0);

    // FIM sweep \u2014 baseline drift on hosts file + Startup folders.
    if let Err(e) = fim::poll_once(&store) {
        errors.push(format!("fim: {e:#}"));
    }

    // Autoruns sweep — registry + tasks + services. We prime the baseline
    // here on first run (so steady-state autoruns::run() sees primed=true
    // and behaves correctly without re-spamming).
    let autoruns_primed = matches!(store.mark_seen("autoruns_meta", "primed"), Ok(false));
    if let Err(e) = autoruns::scan_all(&store, autoruns_primed).await {
        errors.push(format!("autoruns: {e:#}"));
    }

    let events_after = store.event_count().unwrap_or(events_before);
    let drift = events_after.saturating_sub(events_before);
    let elapsed_ms = started.elapsed().as_millis() as u64;

    let (severity, summary) = if !errors.is_empty() {
        (
            "warn",
            format!("pre-boot scan completed with {} error(s)", errors.len()),
        )
    } else if drift > 0 {
        (
            "alert",
            format!("pre-boot scan: {drift} persistence drift event(s) detected"),
        )
    } else {
        (
            "info",
            "pre-boot scan: no persistence drift, integrity clean".to_string(),
        )
    };

    let _ = store.insert_event(&now_event(
        "pre_boot_scan",
        severity,
        "rollup",
        summary,
        serde_json::json!({
            "elapsed_ms": elapsed_ms,
            "drift_events": drift,
            "errors": errors,
            "covered": ["hosts_file", "startup_folders", "registry_run", "scheduled_tasks", "services"],
        }),
    ));

    tracing::info!("pre_boot_scan: done in {elapsed_ms}ms ({drift} drift events, {} errors)", errors.len());
}
