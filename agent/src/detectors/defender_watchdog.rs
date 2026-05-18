// Defender Watchdog — second-opinion surveillance of Microsoft Defender itself.
//
// Microsoft Defender is the dominant Windows AV, but it has one structural
// blind spot: it can't credibly alarm on its own degradation. If an attacker
// (or an over-helpful "speed-up your PC" script) disables real-time
// protection, turns off tamper protection, or — far more commonly post-
// breach — drops a sweeping exclusion path like `C:\` or `*.exe`, Defender
// will dutifully stop scanning and report itself as "healthy".
//
// This detector polls Defender's *configuration state* (not its event log;
// that's the job of `defender.rs`) on a slow cadence and emits alerts when:
//
//   * RealTimeProtectionEnabled flips off
//   * TamperProtection flips off
//   * BehaviorMonitor flips off
//   * IOAV (scan downloads) flips off
//   * On-access protection flips off
//   * AntiMalware service stops
//   * Signature age exceeds 7d (warn) / 14d (alert)
//   * MAPS (cloud-delivered protection) is disabled
//   * A NEW exclusion appears (path / extension / process / IP).
//     Each exclusion is fingerprinted via `store.mark_seen` so the
//     baseline doesn't flood, and any addition later is flagged.
//
// Detect-only. We never re-enable Defender or remove exclusions — the
// user (or their EDR) owns that call. Source = `defender_watchdog`.

use crate::store::{now_event, Store};
use std::sync::Arc;
use std::time::Duration;

const POLL_SECS: u64 = 60;
const SIG_WARN_DAYS: u64 = 7;
const SIG_ALERT_DAYS: u64 = 14;

#[cfg(not(windows))]
pub async fn run(_store: Arc<Store>) {
    // Defender is Windows-only.
}

#[cfg(windows)]
pub async fn run(store: Arc<Store>) {
    use serde_json::json;

    // In-memory state for transition detection. `None` until first
    // successful poll. We only emit alerts when a watched boolean
    // *transitions* from healthy→degraded, plus one initial alert on
    // the very first poll if it's already degraded.
    let mut prev: Option<DefenderState> = None;
    let mut first_run = true;

    loop {
        match poll_state().await {
            Ok(state) => {
                // --- Configuration drift ---------------------------------
                emit_transitions(&store, prev.as_ref(), &state, first_run);

                // --- Signature freshness ---------------------------------
                check_sig_age(&store, &state);

                // --- New exclusions --------------------------------------
                check_exclusions(&store, &state, first_run);

                if first_run {
                    // Single baseline event so the dashboard has a row
                    // showing "watchdog is online and Defender looked X
                    // at startup". Repeat snapshots would be noise.
                    let _ = store.insert_event(&now_event(
                        "defender_watchdog",
                        "info",
                        "baseline",
                        format!(
                            "Defender baseline: RTP={} TP={} BM={} sigAge={}d exclusions={}",
                            yn(state.rtp),
                            yn(state.tamper),
                            yn(state.behavior),
                            state.sig_age_days,
                            state.exclusion_paths.len()
                                + state.exclusion_processes.len()
                                + state.exclusion_extensions.len()
                                + state.exclusion_ips.len(),
                        ),
                        json!({
                            "real_time_protection": state.rtp,
                            "tamper_protection": state.tamper,
                            "behavior_monitor": state.behavior,
                            "ioav": state.ioav,
                            "on_access": state.on_access,
                            "am_service": state.am_service,
                            "signature_age_days": state.sig_age_days,
                            "maps_reporting": state.maps_reporting,
                            "exclusion_paths": state.exclusion_paths,
                            "exclusion_processes": state.exclusion_processes,
                            "exclusion_extensions": state.exclusion_extensions,
                            "exclusion_ips": state.exclusion_ips,
                        }),
                    ));
                }

                prev = Some(state);
                first_run = false;
            }
            Err(e) => {
                // Defender not installed, third-party AV displaced it,
                // or PowerShell unavailable. Log once and back off.
                if first_run {
                    let _ = store.insert_event(&now_event(
                        "defender_watchdog",
                        "info",
                        "unavailable",
                        format!("Defender state unavailable: {e}"),
                        serde_json::json!({ "error": e.to_string() }),
                    ));
                    first_run = false;
                }
            }
        }

        // Use a slow cadence — Defender state changes are rare and
        // PowerShell startup is expensive.
        tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

// --------- Windows-only implementation details --------------------------

#[cfg(windows)]
#[derive(Debug, Clone)]
struct DefenderState {
    rtp: bool,
    tamper: bool,
    behavior: bool,
    ioav: bool,
    on_access: bool,
    am_service: bool,
    sig_age_days: u64,
    maps_reporting: u32,
    exclusion_paths: Vec<String>,
    exclusion_processes: Vec<String>,
    exclusion_extensions: Vec<String>,
    exclusion_ips: Vec<String>,
}

#[cfg(windows)]
fn yn(b: bool) -> &'static str {
    if b { "on" } else { "OFF" }
}

#[cfg(windows)]
async fn poll_state() -> anyhow::Result<DefenderState> {
    use anyhow::Context;
    use tokio::process::Command;

    // Single PowerShell invocation that emits both cmdlet outputs as a
    // tagged JSON object. Cheaper than two spawns and keeps the snapshot
    // consistent (no drift between the two reads).
    let script = r#"
$ErrorActionPreference = 'Stop'
$s = Get-MpComputerStatus
$p = Get-MpPreference
[pscustomobject]@{
  status = @{
    RealTimeProtectionEnabled  = [bool]$s.RealTimeProtectionEnabled
    IsTamperProtected          = [bool]$s.IsTamperProtected
    BehaviorMonitorEnabled     = [bool]$s.BehaviorMonitorEnabled
    IoavProtectionEnabled      = [bool]$s.IoavProtectionEnabled
    OnAccessProtectionEnabled  = [bool]$s.OnAccessProtectionEnabled
    AMServiceEnabled           = [bool]$s.AMServiceEnabled
    AntivirusSignatureAge      = [int]$s.AntivirusSignatureAge
  }
  prefs = @{
    MAPSReporting       = [int]$p.MAPSReporting
    ExclusionPath       = @($p.ExclusionPath)
    ExclusionProcess    = @($p.ExclusionProcess)
    ExclusionExtension  = @($p.ExclusionExtension)
    ExclusionIpAddress  = @($p.ExclusionIpAddress)
  }
} | ConvertTo-Json -Compress -Depth 4
"#;

    let out = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .await
        .context("spawn powershell")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        anyhow::bail!("Get-MpComputerStatus failed: {stderr}");
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    let v: serde_json::Value = serde_json::from_str(stdout.trim())
        .with_context(|| format!("parse Defender JSON: {stdout}"))?;

    let s = &v["status"];
    let p = &v["prefs"];

    let str_array = |val: &serde_json::Value| -> Vec<String> {
        val.as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };

    Ok(DefenderState {
        rtp: s["RealTimeProtectionEnabled"].as_bool().unwrap_or(false),
        tamper: s["IsTamperProtected"].as_bool().unwrap_or(false),
        behavior: s["BehaviorMonitorEnabled"].as_bool().unwrap_or(false),
        ioav: s["IoavProtectionEnabled"].as_bool().unwrap_or(false),
        on_access: s["OnAccessProtectionEnabled"].as_bool().unwrap_or(false),
        am_service: s["AMServiceEnabled"].as_bool().unwrap_or(false),
        sig_age_days: s["AntivirusSignatureAge"].as_u64().unwrap_or(0),
        maps_reporting: p["MAPSReporting"].as_u64().unwrap_or(0) as u32,
        exclusion_paths: str_array(&p["ExclusionPath"]),
        exclusion_processes: str_array(&p["ExclusionProcess"]),
        exclusion_extensions: str_array(&p["ExclusionExtension"]),
        exclusion_ips: str_array(&p["ExclusionIpAddress"]),
    })
}

#[cfg(windows)]
fn emit_transitions(
    store: &Arc<Store>,
    prev: Option<&DefenderState>,
    cur: &DefenderState,
    first_run: bool,
) {
    use serde_json::json;

    // Helper closure: alert when current is degraded AND either
    // this is the first run OR the previous state was healthy.
    let flag = |healthy: bool,
                    prev_healthy: bool,
                    kind: &'static str,
                    severity: &'static str,
                    summary: &str| {
        let transitioned = !healthy && (first_run || prev_healthy);
        if transitioned {
            let _ = store.insert_event(&now_event(
                "defender_watchdog",
                severity,
                kind,
                summary.to_string(),
                json!({ "first_run": first_run }),
            ));
        }
    };

    let p_rtp = prev.map(|s| s.rtp).unwrap_or(true);
    flag(
        cur.rtp,
        p_rtp,
        "rtp_disabled",
        "alert",
        "Defender real-time protection is OFF",
    );

    let p_tp = prev.map(|s| s.tamper).unwrap_or(true);
    flag(
        cur.tamper,
        p_tp,
        "tamper_protection_off",
        "alert",
        "Defender Tamper Protection is OFF — an attacker (or PUA) can now silently change settings",
    );

    let p_bm = prev.map(|s| s.behavior).unwrap_or(true);
    flag(
        cur.behavior,
        p_bm,
        "behavior_monitor_off",
        "alert",
        "Defender Behavior Monitor is OFF",
    );

    let p_io = prev.map(|s| s.ioav).unwrap_or(true);
    flag(
        cur.ioav,
        p_io,
        "ioav_off",
        "warn",
        "Defender IOAV (scan downloaded files) is OFF",
    );

    let p_oa = prev.map(|s| s.on_access).unwrap_or(true);
    flag(
        cur.on_access,
        p_oa,
        "on_access_off",
        "alert",
        "Defender on-access protection is OFF",
    );

    let p_svc = prev.map(|s| s.am_service).unwrap_or(true);
    flag(
        cur.am_service,
        p_svc,
        "am_service_disabled",
        "alert",
        "Defender AntiMalware service is not running",
    );

    let p_maps = prev.map(|s| s.maps_reporting).unwrap_or(1);
    let cur_maps_on = cur.maps_reporting > 0;
    let prev_maps_on = p_maps > 0;
    flag(
        cur_maps_on,
        prev_maps_on,
        "maps_disabled",
        "warn",
        "Defender cloud-delivered protection (MAPS) is disabled",
    );
}

#[cfg(windows)]
fn check_sig_age(store: &Arc<Store>, cur: &DefenderState) {
    use serde_json::json;
    let kind = if cur.sig_age_days >= SIG_ALERT_DAYS {
        Some(("signatures_stale", "alert"))
    } else if cur.sig_age_days >= SIG_WARN_DAYS {
        Some(("signatures_aging", "warn"))
    } else {
        None
    };
    if let Some((k, sev)) = kind {
        // Dedupe per integer-day bucket so we don't re-fire every minute.
        let key = format!("sig_age_{}", cur.sig_age_days);
        match store.mark_seen("defender_watchdog_sig", &key) {
            Ok(true) => {
                let _ = store.insert_event(&now_event(
                    "defender_watchdog",
                    sev,
                    k,
                    format!(
                        "Defender signatures are {} days old",
                        cur.sig_age_days
                    ),
                    json!({ "age_days": cur.sig_age_days }),
                ));
            }
            _ => {}
        }
    }
}

#[cfg(windows)]
fn check_exclusions(store: &Arc<Store>, cur: &DefenderState, first_run: bool) {
    use serde_json::json;

    // Each (scope, value) is fingerprinted in the seen table. On first
    // run we mark everything seen WITHOUT emitting alerts — that's the
    // baseline; alerting on pre-existing exclusions would be noise.
    // After the baseline, any newly-seen entry is a real config change.
    let buckets: &[(&str, &Vec<String>, &str, &str)] = &[
        ("defender_excl_path",      &cur.exclusion_paths,      "exclusion_added_path",      "alert"),
        ("defender_excl_process",   &cur.exclusion_processes,  "exclusion_added_process",   "alert"),
        ("defender_excl_extension", &cur.exclusion_extensions, "exclusion_added_extension", "alert"),
        ("defender_excl_ip",        &cur.exclusion_ips,        "exclusion_added_ip",        "alert"),
    ];

    for (scope, list, kind, severity) in buckets {
        for entry in list.iter() {
            match store.mark_seen(scope, entry) {
                Ok(true) if !first_run => {
                    let _ = store.insert_event(&now_event(
                        "defender_watchdog",
                        severity,
                        kind,
                        format!("Defender exclusion added: {entry}"),
                        json!({ "scope": scope, "value": entry }),
                    ));
                }
                _ => {}
            }
        }
    }
}
