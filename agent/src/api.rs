use crate::{config::Config, store::Store};
use anyhow::Result;
use axum::{
    extract::{Query, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};

#[derive(Clone)]
struct AppState {
    store: Arc<Store>,
    token: String,
}

pub async fn serve(cfg: Config, store: Arc<Store>) -> Result<()> {
    let state = AppState { store, token: cfg.token.clone() };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_headers(Any)
        .allow_methods(Any);

    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/events", get(events))
        .route("/api/chain/verify", get(verify_chain))
        .route("/api/respond/kill-pid", post(respond_kill_pid))
        .route("/api/respond/quarantine", post(respond_quarantine))
        .route("/api/quarantine/list", get(quarantine_list))
        .route("/api/scan/run", post(scan_run))
        .route("/api/trust/list", get(trust_list))
        .route("/api/trust/fp", post(trust_fp))
        .route("/api/trust/exe", post(trust_exe))
        .route("/api/trust/untrust", post(untrust))
        .route("/api/forensic/export", post(forensic_export))
        .route("/api/perf/audit", get(perf_audit))
        .route("/api/perf/apply", post(perf_apply))
        .with_state(state)
        .layer(cors);

    let listener = tokio::net::TcpListener::bind(&cfg.bind).await?;
    tracing::info!("api listening on http://{}", cfg.bind);
    axum::serve(listener, app).await?;
    Ok(())
}

fn check_auth(headers: &HeaderMap, token: &str) -> Result<(), StatusCode> {
    let h = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    let expected = format!("Bearer {token}");
    if h == expected { Ok(()) } else { Err(StatusCode::UNAUTHORIZED) }
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "ok": true }))
}

#[derive(Deserialize)]
struct EventsQuery {
    limit: Option<i64>,
}

async fn events(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<EventsQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    let limit = q.limit.unwrap_or(200).clamp(1, 5000);
    let evs = s.store.recent_events(limit).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(evs))
}

async fn verify_chain(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    let status = s.store.verify_chain().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(status))
}

// ---- response endpoints ----

#[derive(Deserialize)]
struct KillPidBody {
    pid: u32,
    reason: Option<String>,
}

async fn respond_kill_pid(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<KillPidBody>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    let reason = body.reason.unwrap_or_else(|| "manual kill from dashboard".to_string());

    // Refuse to kill our own process.
    if body.pid == std::process::id() {
        return Err(StatusCode::BAD_REQUEST);
    }

    // taskkill /F /PID <pid>. Errors propagated as 500 with detail in body.
    let out = tokio::process::Command::new("taskkill")
        .args(["/F", "/PID", &body.pid.to_string()])
        .output()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let ok = out.status.success();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();

    let _ = s.store.insert_event(&crate::store::now_event(
        "response",
        if ok { "alert" } else { "warn" },
        "process_killed",
        format!("kill pid {} {}", body.pid, if ok { "OK" } else { "FAILED" }),
        serde_json::json!({
            "pid": body.pid,
            "ok": ok,
            "reason": reason,
            "stdout": stdout.trim(),
            "stderr": stderr.trim(),
        }),
    ));

    Ok(Json(serde_json::json!({
        "ok": ok,
        "stdout": stdout,
        "stderr": stderr,
    })))
}

#[derive(Deserialize)]
struct QuarantineBody {
    path: String,
    reason: Option<String>,
}

async fn respond_quarantine(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<QuarantineBody>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    let reason = body.reason.unwrap_or_else(|| "manual quarantine from dashboard".to_string());
    let path = std::path::PathBuf::from(&body.path);

    // Run on a blocking task — file I/O.
    let store = s.store.clone();
    let res = tokio::task::spawn_blocking(move || {
        crate::quarantine::quarantine_file(&store, &path, &reason)
    })
    .await
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match res {
        Ok(rec) => Ok(Json(serde_json::to_value(&rec).unwrap())),
        Err(e) => {
            let _ = s.store.insert_event(&crate::store::now_event(
                "response",
                "warn",
                "quarantine_failed",
                format!("quarantine failed: {}", body.path),
                serde_json::json!({ "path": body.path, "error": e.to_string() }),
            ));
            Err(StatusCode::BAD_REQUEST)
        }
    }
}

async fn forensic_export(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    let store = s.store.clone();
    let res = tokio::task::spawn_blocking(move || crate::forensic::export(&store))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    match res {
        Ok(path) => {
            let path_s = path.display().to_string();
            let size = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            let _ = s.store.insert_event(&crate::store::now_event(
                "response",
                "info",
                "forensic_export",
                format!("forensic bundle written ({} bytes)", size),
                serde_json::json!({ "path": path_s, "bytes": size }),
            ));
            Ok(Json(serde_json::json!({ "ok": true, "path": path_s, "bytes": size })))
        }
        Err(e) => {
            tracing::warn!("forensic export failed: {e:#}");
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

// List the quarantine vault. Returns each manifest with `vault_bin_exists`.
async fn quarantine_list(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    let res = tokio::task::spawn_blocking(crate::quarantine::list_vault)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(res))
}

// Ad-hoc full sweep. Synchronously runs:
//   * URLhaus blocklist refresh
//   * FIM (hosts file + Startup folders) one-shot poll
//   * Canary token integrity check
//   * Defender + Firewall event-log poll cycle
// Emits a `scan_started` and `scan_complete` info event so the dashboard sees
// the run in the chain log. Returns a structured per-stage report.
async fn scan_run(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;

    let started = std::time::Instant::now();
    // Capture chain tip so we can count exactly which events were emitted by
    // this scan (any new events with id > before_id came from this sweep).
    let (before_id, _) = s
        .store
        .chain_tip()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let _ = s.store.insert_event(&crate::store::now_event(
        "response",
        "info",
        "scan_started",
        "manual full scan kicked off from dashboard".to_string(),
        serde_json::json!({}),
    ));

    // URLhaus refresh — async.
    let blocklist_count = match crate::blocklist::refresh_now().await {
        Ok(n) => Some(n),
        Err(e) => {
            tracing::warn!("scan_run: blocklist refresh failed: {e:#}");
            None
        }
    };

    // FIM + canary are blocking I/O.
    let store_for_blocking = s.store.clone();
    let _ = tokio::task::spawn_blocking(move || {
        if let Err(e) = crate::detectors::fim::poll_once(&store_for_blocking) {
            tracing::warn!("scan_run: fim poll failed: {e:#}");
        }
        if let Err(e) = crate::detectors::canary::poll_once(&store_for_blocking) {
            tracing::warn!("scan_run: canary poll failed: {e:#}");
        }
    })
    .await;

    // Defender + firewall — async (wevtutil).
    let _ = crate::detectors::defender::scan_now(&s.store).await;

    // Tally what each stage actually produced by reading the events the scan
    // appended to the chain. Group by source.
    let new_events = s
        .store
        .events_after(before_id, 5000)
        .unwrap_or_default();
    let mut by_source: std::collections::HashMap<String, serde_json::Map<String, serde_json::Value>> =
        std::collections::HashMap::new();
    let mut total_alerts = 0u64;
    let mut total_warns = 0u64;
    for ev in &new_events {
        if ev.source == "response" { continue; } // skip our own scan_started/scan_complete
        let bucket = by_source.entry(ev.source.clone()).or_default();
        let total = bucket.get("total").and_then(|v| v.as_u64()).unwrap_or(0) + 1;
        bucket.insert("total".into(), serde_json::json!(total));
        let key = format!("sev_{}", ev.severity);
        let n = bucket.get(&key).and_then(|v| v.as_u64()).unwrap_or(0) + 1;
        bucket.insert(key, serde_json::json!(n));
        if ev.severity == "alert" { total_alerts += 1; }
        if ev.severity == "warn" { total_warns += 1; }
    }

    // Stage coverage: what we *checked* (not just what we found).
    // FIM: count of currently-baselined paths.
    // Canaries: count of registered canaries.
    // proc_fp: count of distinct exes seen historically (proxy for coverage).
    let fim_baselined = s
        .store
        .fim_paths_under("")
        .map(|v| v.len())
        .unwrap_or(0);
    let canaries_planted = s
        .store
        .list_canaries()
        .map(|v| v.len())
        .unwrap_or(0);

    let report = serde_json::json!({
        "ok": true,
        "elapsed_ms": started.elapsed().as_millis() as u64,
        "stages": {
            "urlhaus": {
                "hosts_loaded": blocklist_count,
                "status": if blocklist_count.is_some() { "ok" } else { "failed" },
            },
            "fim": {
                "baselined_paths": fim_baselined,
                "new_findings": by_source.get("fim").and_then(|b| b.get("total")).cloned().unwrap_or(serde_json::json!(0)),
            },
            "canary": {
                "planted": canaries_planted,
                "new_findings": by_source.get("canary").and_then(|b| b.get("total")).cloned().unwrap_or(serde_json::json!(0)),
            },
            "defender": {
                "new_events": by_source.get("defender").and_then(|b| b.get("total")).cloned().unwrap_or(serde_json::json!(0)),
            },
            "firewall": {
                "new_events": by_source.get("firewall").and_then(|b| b.get("total")).cloned().unwrap_or(serde_json::json!(0)),
            },
        },
        "new_alerts": total_alerts,
        "new_warns": total_warns,
        "new_events_total": new_events.iter().filter(|e| e.source != "response").count(),
    });

    let _ = s.store.insert_event(&crate::store::now_event(
        "response",
        "info",
        "scan_complete",
        format!(
            "manual scan: {} new events ({} alert, {} warn) in {}ms",
            report["new_events_total"], total_alerts, total_warns, report["elapsed_ms"]
        ),
        report.clone(),
    ));

    Ok(Json(report))
}

// ---- trust list (smart suppression of known-good processes) ----

#[derive(Deserialize)]
struct TrustFpBody {
    fp: String,
    exe: String,
    reason: Option<String>,
}

async fn trust_fp(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TrustFpBody>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    let reason = body.reason.unwrap_or_else(|| "trusted from dashboard".into());
    s.store
        .trust_fp(&body.fp, &body.exe, &reason)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let _ = s.store.insert_event(&crate::store::now_event(
        "response",
        "info",
        "fp_trusted",
        format!("trusted fp {} ({})", &body.fp[..body.fp.len().min(12)], body.exe),
        serde_json::json!({ "fp": body.fp, "exe": body.exe, "reason": reason }),
    ));
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Deserialize)]
struct TrustExeBody {
    exe: String,
    reason: Option<String>,
}

async fn trust_exe(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TrustExeBody>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    let reason = body.reason.unwrap_or_else(|| "bulk-trusted from dashboard".into());
    s.store
        .trust_exe(&body.exe, &reason)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let _ = s.store.insert_event(&crate::store::now_event(
        "response",
        "info",
        "exe_trusted",
        format!("trusted all fps for {}", body.exe),
        serde_json::json!({ "exe": body.exe, "reason": reason }),
    ));
    Ok(Json(serde_json::json!({ "ok": true })))
}

#[derive(Deserialize)]
struct UntrustBody {
    fp: Option<String>,
    exe: Option<String>,
}

async fn untrust(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<UntrustBody>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    if let Some(fp) = body.fp.as_deref() {
        s.store.untrust_fp(fp).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    if let Some(exe) = body.exe.as_deref() {
        s.store.untrust_exe(exe).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    }
    Ok(Json(serde_json::json!({ "ok": true })))
}

async fn trust_list(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    let fps = s
        .store
        .list_trusted_fp()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let exes = s
        .store
        .list_trusted_exe()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let fps_json: Vec<_> = fps
        .into_iter()
        .map(|(fp, exe, reason, added_at)| {
            serde_json::json!({ "fp": fp, "exe": exe, "reason": reason, "added_at": added_at })
        })
        .collect();
    let exes_json: Vec<_> = exes
        .into_iter()
        .map(|(exe, reason, added_at)| {
            serde_json::json!({ "exe": exe, "reason": reason, "added_at": added_at })
        })
        .collect();
    Ok(Json(serde_json::json!({ "fps": fps_json, "exes": exes_json })))
}

// ---- perf audit ----

async fn perf_audit(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    let report = crate::detectors::perf::audit()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(report))
}

#[derive(Deserialize)]
struct PerfApplyBody {
    fix_command: String,
}

async fn perf_apply(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PerfApplyBody>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;

    // Re-audit and confirm the supplied fix_command was actually generated
    // by perf::audit() right now. This is the only thing standing between
    // arbitrary client input and PowerShell execution — do not relax it.
    let report = crate::detectors::perf::audit()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let matched = report.findings.iter().find(|f| {
        f.fix_command.as_deref() == Some(body.fix_command.as_str())
    });
    let Some(finding) = matched else {
        tracing::warn!("perf_apply: rejected unknown fix_command (len={})", body.fix_command.len());
        return Err(StatusCode::FORBIDDEN);
    };

    let outcome = crate::detectors::perf::apply_fix(&body.fix_command, finding.requires_admin)
        .await
        .map_err(|e| {
            tracing::error!("perf_apply: execution failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    // Audit-chain the action so it shows up in the event stream.
    let _ = s.store.insert_event(&crate::store::now_event(
        "response",
        if outcome.ok { "alert" } else { "warn" },
        "perf.fix.applied",
        format!(
            "perf fix {} ({}): {}",
            finding.id,
            if outcome.launched_elevated { "elevated" } else { "user" },
            if outcome.ok { "OK" } else { "FAILED" },
        ),
        serde_json::json!({
            "id": finding.id,
            "category": finding.category,
            "title": finding.title,
            "requires_admin": finding.requires_admin,
            "launched_elevated": outcome.launched_elevated,
            "ok": outcome.ok,
            "exit_code": outcome.exit_code,
        }),
    ));

    Ok(Json(outcome))
}
