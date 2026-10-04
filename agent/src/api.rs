use crate::{config::Config, store::Store};
use anyhow::Result;
use axum::{
    extract::{Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::Response,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::Deserialize;
use rand::RngCore;
use std::sync::Arc;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

#[derive(Clone)]
struct AppState {
    store: Arc<Store>,
    token: String,
}

pub async fn serve(cfg: Config, store: Arc<Store>) -> Result<()> {
    let state = AppState { store, token: cfg.token.clone() };

    // Only the dashboard may make cross-origin calls: the hosted console at
    // bastion.quest (which the desktop app also loads), the Tauri shell, and
    // local dev servers. A random website the user visits gets no CORS
    // grant, so the browser won't let it read responses.
    let cors = CorsLayer::new()
        .allow_origin(AllowOrigin::predicate(|origin: &HeaderValue, _| is_local_origin(origin)))
        .allow_headers(Any)
        .allow_methods(Any);

    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/events", get(events))
        .route("/api/why/event/:id", get(why_event))
        .route("/api/connectors", get(connectors_list))
        .route("/api/connectors/sentinel", post(sentinel_save))
        .route("/api/connectors/sentinel/pull", post(sentinel_pull))
        .route("/api/connectors/sentinel/auth-status", get(sentinel_auth_status))
        .route("/api/connectors/sentinel/ingest", post(sentinel_ingest))
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
        .route("/api/maint/overview", get(maint_overview))
        .route("/api/maint/junk/scan", get(maint_junk_scan))
        .route("/api/maint/junk/clean", post(maint_junk_clean))
        .route("/api/maint/large-files", get(maint_large_files))
        .route("/api/maint/programs", get(maint_programs))
        .route("/api/maint/programs/uninstall", post(maint_uninstall))
        .route("/api/maint/health", get(maint_health))
        .route("/api/maint/health/apply", post(maint_health_apply))
        .route("/api/triage", get(triage_list))
        .route("/api/triage/resolve", post(triage_resolve))
        .route("/api/triage/unresolve", post(triage_unresolve))
        .with_state(state)
        .layer(cors)
        .layer(middleware::from_fn(reject_foreign_host));

    let listener = tokio::net::TcpListener::bind(&cfg.bind).await?;
    tracing::info!("api listening on http://{}", cfg.bind);
    axum::serve(listener, app).await?;
    Ok(())
}

fn check_auth(headers: &HeaderMap, token: &str) -> Result<(), StatusCode> {
    let h = headers.get("authorization").and_then(|v| v.to_str().ok()).unwrap_or("");
    let expected = format!("Bearer {token}");
    if constant_time_eq(h.as_bytes(), expected.as_bytes()) { Ok(()) } else { Err(StatusCode::UNAUTHORIZED) }
}

/// Compare without an early exit so response timing doesn't leak how much
/// of the token a guess got right.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn is_loopback_host(host: &str) -> bool {
    // Strip the port; bracketed IPv6 keeps its brackets.
    let name = if host.starts_with('[') {
        host.split(']').next().map(|h| format!("{h}]")).unwrap_or_default()
    } else {
        host.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or_else(|| host.to_string())
    };
    matches!(name.to_ascii_lowercase().as_str(), "127.0.0.1" | "localhost" | "[::1]")
}

/// Exact origins allowed besides loopback dev servers.
const DASHBOARD_ORIGINS: &[&str] = &[
    "https://bastion.quest",
    "https://www.bastion.quest",
    "tauri://localhost",
    "http://tauri.localhost",
    "https://tauri.localhost",
];

fn is_local_origin(origin: &HeaderValue) -> bool {
    let Ok(o) = origin.to_str() else { return false };
    let o = o.to_ascii_lowercase();
    if DASHBOARD_ORIGINS.contains(&o.as_str()) {
        return true;
    }
    match o.strip_prefix("http://").or_else(|| o.strip_prefix("https://")) {
        Some(rest) if !rest.contains('/') => is_loopback_host(rest),
        _ => false,
    }
}

/// DNS-rebinding guard: a hostile page can point its own domain at
/// 127.0.0.1, which makes the browser treat our API as same-origin. The Host
/// header still carries the attacker's name, so anything that isn't a
/// loopback name is refused before it reaches a handler.
async fn reject_foreign_host(req: Request, next: Next) -> Result<Response, StatusCode> {
    let host = req.headers().get("host").and_then(|v| v.to_str().ok()).unwrap_or("");
    if !is_loopback_host(host) {
        tracing::warn!("api: rejected request with non-loopback Host header");
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(req).await)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loopback_hosts() {
        for h in ["127.0.0.1:7878", "localhost:7878", "LOCALHOST", "[::1]:7878"] {
            assert!(is_loopback_host(h), "{h}");
        }
        for h in ["evil.com", "evil.com:7878", "127.0.0.1.evil.com:7878", "", "localhost.evil.com"] {
            assert!(!is_loopback_host(h), "{h}");
        }
    }

    #[test]
    fn local_origins_only() {
        let ok = |s: &str| is_local_origin(&HeaderValue::from_str(s).unwrap());
        assert!(ok("http://localhost:3000"));
        assert!(ok("http://127.0.0.1:7878"));
        assert!(ok("tauri://localhost"));
        assert!(ok("https://tauri.localhost"));
        assert!(ok("https://bastion.quest"));
        assert!(!ok("https://bastion.quest.evil.com"));
        assert!(!ok("http://bastion.quest"));
        assert!(!ok("https://evil.com"));
        assert!(!ok("http://localhost.evil.com"));
        assert!(!ok("http://127.0.0.1.nip.io"));
        assert!(!ok("null"));
    }

    #[test]
    fn token_compare() {
        assert!(constant_time_eq(b"Bearer abc", b"Bearer abc"));
        assert!(!constant_time_eq(b"Bearer abd", b"Bearer abc"));
        assert!(!constant_time_eq(b"Bearer ab", b"Bearer abc"));
    }
}

async fn health() -> impl IntoResponse {
    // Unauthenticated on purpose: the console uses it to show which agent
    // build it is talking to before a token has been pasted.
    Json(serde_json::json!({ "ok": true, "version": env!("CARGO_PKG_VERSION") }))
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

async fn why_event(
    Path(id): Path<i64>,
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    let Some(ev) = s
        .store
        .event_by_id(id)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    else {
        return Err(StatusCode::NOT_FOUND);
    };

    let why = crate::ai_manager::explain_event(&ev).await;
    Ok(Json(why))
}

async fn verify_chain(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    let status = s.store.verify_chain().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(status))
}

async fn connectors_list(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    let connectors = s
        .store
        .list_connectors()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(connectors))
}

#[derive(Deserialize)]
struct SentinelSaveBody {
    name: Option<String>,
    enabled: Option<bool>,
    auth_mode: Option<String>,
    tenant_id: Option<String>,
    subscription_id: Option<String>,
    resource_group: Option<String>,
    workspace_name: Option<String>,
    notes: Option<String>,
}

async fn sentinel_save(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SentinelSaveBody>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    let secret = s
        .store
        .connector_by_kind("sentinel")
        .ok()
        .flatten()
        .map(|c| c.secret)
        .unwrap_or_else(|| {
            let mut buf = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut buf);
            hex::encode(buf)
        });
    let config = serde_json::json!({
        "auth_mode": body.auth_mode.unwrap_or_else(|| "azure_cli".to_string()),
        "tenant_id": body.tenant_id,
        "subscription_id": body.subscription_id,
        "resource_group": body.resource_group,
        "workspace_name": body.workspace_name,
        "notes": body.notes,
    });
    let name = body.name.unwrap_or_else(|| "Microsoft Sentinel".to_string());
    let enabled = body.enabled.unwrap_or(true);
    s.store
        .upsert_connector("sentinel", &name, enabled, &secret, &config.to_string())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({
        "ok": true,
        "kind": "sentinel",
        "name": name,
        "enabled": enabled,
        "secret": secret,
        "config": config,
        "ingest_url": "http://127.0.0.1:7878/api/connectors/sentinel/ingest"
    })))
}

#[derive(Deserialize)]
struct SentinelPullBody {
    top: Option<u32>,
}

async fn sentinel_pull(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SentinelPullBody>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    let Some(connector) = s
        .store
        .connector_by_kind("sentinel")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    else {
        return Err(StatusCode::NOT_FOUND);
    };
    if !connector.enabled {
        return Err(StatusCode::FORBIDDEN);
    }

    let cfg: serde_json::Value = serde_json::from_str(&connector.config_json)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let subscription_id = cfg
        .get("subscription_id")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let resource_group = cfg
        .get("resource_group")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(StatusCode::BAD_REQUEST)?;
    let workspace_name = cfg
        .get("workspace_name")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(StatusCode::BAD_REQUEST)?;

    let token = azure_management_access_token().await.map_err(|e| {
        tracing::warn!("sentinel pull auth failed: {e}");
        StatusCode::SERVICE_UNAVAILABLE
    })?;

    let top = body.top.unwrap_or(20).clamp(1, 100);
    let url = format!(
        "https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}/providers/Microsoft.SecurityInsights/incidents?api-version=2024-01-01-preview&$top={top}"
    );
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(20))
        .build()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let resp = client
        .get(url)
        .bearer_auth(token)
        .send()
        .await
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Ok(Json(serde_json::json!({
            "ok": false,
            "status": status.as_u16(),
            "message": body,
            "pulled": 0,
            "ingested": 0,
            "items": serde_json::Value::Array(Vec::new()),
        })));
    }

    let payload: serde_json::Value = resp.json().await.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    let items = payload
        .get("value")
        .and_then(serde_json::Value::as_array)
        .cloned()
        .unwrap_or_default();
    let mut ingested = 0u64;
    let mut preview = Vec::new();

    for item in items.iter().take(top as usize) {
        let title = item
            .get("properties")
            .and_then(|p| p.get("title"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("Sentinel incident");
        let sev = item
            .get("properties")
            .and_then(|p| p.get("severity"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("informational");
        let status = item
            .get("properties")
            .and_then(|p| p.get("status"))
            .and_then(serde_json::Value::as_str)
            .unwrap_or("");
        let incident_id = item
            .get("name")
            .and_then(serde_json::Value::as_str)
            .or_else(|| item.get("id").and_then(serde_json::Value::as_str))
            .map(ToOwned::to_owned);
        let summary = format!("Sentinel incident pull: {title}");
        let details = serde_json::json!({
            "incident_id": incident_id,
            "status": status,
            "title": title,
            "severity": sev,
            "source": "sentinel-pull",
            "workspace": workspace_name,
            "resource_group": resource_group,
            "subscription_id": subscription_id,
            "raw": item,
        });
        let _ = s.store.insert_event(&crate::store::now_event(
            "sentinel",
            match sev.to_ascii_lowercase().as_str() {
                "high" | "critical" => "alert",
                "medium" | "low" => "warn",
                _ => "info",
            },
            "incident_pull",
            summary,
            details,
        ));
        ingested += 1;
        preview.push(serde_json::json!({
            "title": title,
            "severity": sev,
            "status": status,
        }));
    }

    Ok(Json(serde_json::json!({
        "ok": true,
        "pulled": items.len(),
        "ingested": ingested,
        "mode": cfg.get("auth_mode").and_then(serde_json::Value::as_str).unwrap_or("azure_cli"),
        "items": preview,
    })))
}

async fn sentinel_auth_status(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;

    let Some(connector) = s
        .store
        .connector_by_kind("sentinel")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    else {
        return Ok(Json(serde_json::json!({
            "configured": false,
            "az_available": false,
            "workspace_reachable": false,
            "message": "connector not configured",
        })));
    };

    let mut az_available = false;
    let output = tokio::process::Command::new("az")
        .args(["account", "show", "--output", "json"])
        .output()
        .await;

    let account_info = match output {
        Ok(o) if o.status.success() => {
            az_available = true;
            serde_json::from_slice::<serde_json::Value>(&o.stdout).ok()
        }
        _ => None,
    };

    let mut workspace_reachable = false;
    if az_available {
        let token = match azure_management_access_token().await {
            Ok(t) => t,
            Err(_) => String::new(),
        };
        if !token.is_empty() {
            let cfg: serde_json::Value =
                serde_json::from_str(&connector.config_json).unwrap_or(serde_json::json!({}));
            let subscription_id = cfg
                .get("subscription_id")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let resource_group = cfg
                .get("resource_group")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");
            let workspace_name = cfg
                .get("workspace_name")
                .and_then(serde_json::Value::as_str)
                .unwrap_or("");

            if !subscription_id.is_empty() && !resource_group.is_empty() && !workspace_name.is_empty() {
                let url = format!(
                    "https://management.azure.com/subscriptions/{subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.OperationalInsights/workspaces/{workspace_name}?api-version=2021-06-01"
                );
                let client = reqwest::Client::builder()
                    .timeout(std::time::Duration::from_secs(5))
                    .build()
                    .ok();
                if let Some(c) = client {
                    let resp = c.get(url).bearer_auth(&token).send().await;
                    workspace_reachable = resp.map(|r| r.status().is_success()).unwrap_or(false);
                }
            }
        }
    };

    let user = account_info
        .as_ref()
        .and_then(|acc| acc.get("user"))
        .and_then(|u| u.get("name"))
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);
    let subscription = account_info
        .as_ref()
        .and_then(|acc| acc.get("name"))
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned);

    Ok(Json(serde_json::json!({
        "configured": true,
        "az_available": az_available,
        "workspace_reachable": workspace_reachable,
        "user": user,
        "subscription": subscription,
        "message": match (az_available, workspace_reachable) {
            (false, _) => "Azure CLI not available or not logged in. Run: az login",
            (true, false) => "Azure CLI ready, but workspace not reachable. Check credentials and config.",
            (true, true) => "Ready to pull incidents.",
        }
    })))
}

async fn azure_management_access_token() -> Result<String, String> {
    if let Ok(token) = std::env::var("BASTION_AZURE_ACCESS_TOKEN") {
        let token = token.trim().to_string();
        if !token.is_empty() {
            return Ok(token);
        }
    }

    let output = tokio::process::Command::new("az")
        .args([
            "account",
            "get-access-token",
            "--resource",
            "https://management.azure.com/",
            "--query",
            "accessToken",
            "-o",
            "tsv",
        ])
        .output()
        .await
        .map_err(|e| format!("failed to run az CLI: {e}"))?;

    if !output.status.success() {
        return Err(format!(
            "az CLI returned {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }

    let token = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if token.is_empty() {
        return Err("az CLI returned an empty access token".to_string());
    }
    Ok(token)
}

#[derive(Deserialize)]
struct SentinelIncidentBody {
    title: String,
    severity: Option<String>,
    incident_id: Option<String>,
    status: Option<String>,
    description: Option<String>,
    tactic: Option<String>,
    technique: Option<String>,
    entity: Option<String>,
}

async fn sentinel_ingest(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SentinelIncidentBody>,
) -> Result<impl IntoResponse, StatusCode> {
    let secret = headers
        .get("x-bastion-connector-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let Some(connector) = s
        .store
        .connector_by_kind("sentinel")
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
    else {
        return Err(StatusCode::NOT_FOUND);
    };
    if !connector.enabled || connector.secret != secret {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let sev = body.severity.clone().unwrap_or_else(|| "info".to_string());
    let summary = format!("Sentinel incident: {}", body.title);
    let details = serde_json::json!({
        "incident_id": body.incident_id,
        "status": body.status,
        "description": body.description,
        "tactic": body.tactic,
        "technique": body.technique,
        "entity": body.entity,
        "connector": "sentinel",
    });
    let _ = s.store.insert_event(&crate::store::now_event(
        "sentinel",
        &sev,
        "incident_ingest",
        summary,
        details,
    ));
    Ok(Json(serde_json::json!({"ok": true})))
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

// ---- maintenance (cleanup / programs / health) ----

async fn maint_overview(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    Ok(Json(crate::maintenance::overview().await))
}

async fn maint_junk_scan(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    Ok(Json(crate::maintenance::junk::scan().await))
}

async fn maint_junk_clean(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::maintenance::junk::CleanRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    // Only category ids cross the wire; junk::clean re-resolves every path
    // from its own definitions, so the client can't aim it elsewhere.
    let report = crate::maintenance::junk::clean(&body).await;
    if !report.dry_run {
        let failed = report.results.iter().filter(|r| !r.ok).count();
        let _ = s.store.insert_event(&crate::store::now_event(
            "response",
            if failed == 0 { "info" } else { "warn" },
            "maint.junk.cleaned",
            format!("junk cleanup freed {:.2} GB across {} categories", report.freed_gb, report.results.len()),
            serde_json::json!({
                "freed_bytes": report.freed_bytes,
                "results": report.results.iter().map(|r| serde_json::json!({
                    "id": r.id, "ok": r.ok, "method": r.method,
                    "deleted_files": r.deleted_files, "freed_bytes": r.freed_bytes, "failed_files": r.failed_files,
                })).collect::<Vec<_>>(),
            }),
        ));
    }
    Ok(Json(report))
}

#[derive(Deserialize)]
struct LargeFilesQuery {
    min_mb: Option<u64>,
    limit: Option<usize>,
}

async fn maint_large_files(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<LargeFilesQuery>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    let min_mb = q.min_mb.unwrap_or(500).max(10);
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    Ok(Json(crate::maintenance::junk::large_files(min_mb, limit).await))
}

async fn maint_programs(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    Ok(Json(crate::maintenance::programs::list().await))
}

async fn maint_uninstall(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<crate::maintenance::programs::UninstallRequest>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    let outcome = crate::maintenance::programs::uninstall(&body).await;
    let _ = s.store.insert_event(&crate::store::now_event(
        "response",
        if outcome.ok { "info" } else { "warn" },
        "maint.program.uninstall",
        format!("uninstall {} ({}): {}", outcome.name, outcome.id, if outcome.ok { "launched" } else { "FAILED" }),
        serde_json::json!({ "id": outcome.id, "name": outcome.name, "ok": outcome.ok, "message": outcome.message }),
    ));
    Ok(Json(outcome))
}

async fn maint_health(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    Ok(Json(crate::maintenance::health::audit().await))
}

async fn maint_health_apply(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<PerfApplyBody>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;

    // Same allowlist rule as perf_apply: the command must be one that a
    // fresh health audit produced right now. Do not relax.
    let report = crate::maintenance::health::audit().await;
    let Some(finding) = report.findings.iter().find(|f| f.fix_command.as_deref() == Some(body.fix_command.as_str())) else {
        tracing::warn!("maint_health_apply: rejected unknown fix_command (len={})", body.fix_command.len());
        return Err(StatusCode::FORBIDDEN);
    };

    let outcome = crate::detectors::perf::apply_fix(&body.fix_command, finding.requires_admin)
        .await
        .map_err(|e| {
            tracing::error!("maint_health_apply: execution failed: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;

    let _ = s.store.insert_event(&crate::store::now_event(
        "response",
        if outcome.ok { "info" } else { "warn" },
        "maint.health.fix",
        format!(
            "health fix {} ({}): {}",
            finding.id,
            if outcome.launched_elevated { "elevated" } else { "user" },
            if outcome.ok { "OK" } else { "FAILED" },
        ),
        serde_json::json!({
            "id": finding.id,
            "title": finding.title,
            "requires_admin": finding.requires_admin,
            "ok": outcome.ok,
            "exit_code": outcome.exit_code,
        }),
    ));
    Ok(Json(outcome))
}

#[derive(Deserialize)]
struct TriageBody {
    ids: Vec<i64>,
    #[serde(default)]
    note: String,
}

async fn triage_list(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    let ids = s.store.triage_list().map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({ "ids": ids })))
}

async fn triage_resolve(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TriageBody>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    let n = s
        .store
        .triage_resolve(&body.ids, &body.note)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({ "ok": true, "applied": n })))
}

async fn triage_unresolve(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<TriageBody>,
) -> Result<impl IntoResponse, StatusCode> {
    check_auth(&headers, &s.token)?;
    let n = s
        .store
        .triage_unresolve(&body.ids)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(Json(serde_json::json!({ "ok": true, "applied": n })))
}
