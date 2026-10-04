// Machine maintenance: junk cleanup, installed-program review, and an
// overall health check for the Windows box Bastion runs on.
//
// Same posture as `detectors::perf`:
//   * scans are read-only and safe to call repeatedly
//   * every mutating action is identified by an id/command that the agent
//     itself produced in a fresh scan — the client never supplies a path
//     or a command string that is executed as-is
//   * admin-only work is launched through UAC (perf::apply_fix) so the
//     agent itself never needs to run elevated
//
// Submodules:
//   junk     - temp files, caches, crash dumps, update leftovers, recycle bin
//   programs - installed Win32 + Store apps, bloat flags, uninstall launcher
//   health   - disk SMART, pending reboot, update age, event-log errors,
//              battery wear, TRIM, component store / SFC fixes
//   cli      - `bastion-agent maint ...` for use without the dashboard

pub mod cli;
pub mod health;
pub mod junk;
pub mod programs;

use base64::Engine;
use serde::Serialize;
use std::time::Duration;
use tokio::process::Command;

/// Run a PowerShell script (passed via -EncodedCommand so no quoting games)
/// and return stdout. `None` on spawn failure, timeout, or non-Windows.
pub(crate) async fn ps(script: &str, timeout: Duration) -> Option<String> {
    let utf16: Vec<u8> = script.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
    let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
    let fut = Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", &encoded])
        .kill_on_drop(true)
        .output();
    let out = tokio::time::timeout(timeout, fut).await.ok()?.ok()?;
    Some(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Run a PowerShell script whose last output is `ConvertTo-Json -Compress`.
pub(crate) async fn ps_json(script: &str, timeout: Duration) -> Option<serde_json::Value> {
    let out = ps(script, timeout).await?;
    serde_json::from_str(out.trim()).ok()
}

/// Is the agent process itself elevated? Decides whether admin-only cleanup
/// runs in-process or through a UAC prompt.
pub(crate) async fn is_elevated() -> bool {
    if !cfg!(windows) { return false; }
    ps(
        "([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)",
        Duration::from_secs(15),
    )
    .await
    .map(|s| s.trim().eq_ignore_ascii_case("true"))
    .unwrap_or(false)
}

/// Quote a string as a PowerShell single-quoted literal.
pub(crate) fn ps_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "''"))
}

#[derive(Debug, Serialize)]
pub struct Overview {
    pub elapsed_ms: u128,
    /// 0-100, higher is healthier.
    pub score: u32,
    pub grade: &'static str,
    pub health: health::HealthReport,
    pub junk: junk::JunkScan,
}

/// Health check + junk scan in parallel, rolled into a single score.
pub async fn overview() -> Overview {
    let started = std::time::Instant::now();
    let (health, junk) = tokio::join!(health::audit(), junk::scan());
    let score = score(&health.findings, junk.total_bytes);
    Overview {
        elapsed_ms: started.elapsed().as_millis(),
        score,
        grade: match score {
            90..=100 => "excellent",
            75..=89 => "good",
            55..=74 => "fair",
            _ => "needs attention",
        },
        health,
        junk,
    }
}

fn score(findings: &[crate::detectors::perf::Finding], junk_bytes: u64) -> u32 {
    let mut s: i64 = 100;
    for f in findings {
        s -= match f.severity {
            "critical" => 25,
            "warn" => 10,
            "opportunity" => 3,
            _ => 0,
        };
    }
    // 1 point per reclaimable GB, capped so junk alone can't sink the score.
    s -= ((junk_bytes / (1024 * 1024 * 1024)) as i64).min(10);
    s.clamp(0, 100) as u32
}

pub(crate) fn gb(bytes: u64) -> f64 {
    bytes as f64 / 1024.0 / 1024.0 / 1024.0
}
