// Machine health check.
//
// One PowerShell round-trip gathers everything (disk SMART/reliability,
// pending reboot, last update, startup load, 7-day System event-log errors,
// TRIM, battery wear), then findings are built in Rust using the same
// `Finding` shape as the perf audit so the dashboard can render both with
// one component and `apply` goes through the same allowlist + UAC path.

use crate::detectors::perf::Finding;
use serde::Serialize;
use std::time::{Duration, Instant};
use sysinfo::Disks;

#[derive(Debug, Serialize)]
pub struct HealthReport {
    pub elapsed_ms: u128,
    pub findings: Vec<Finding>,
    pub disks: Vec<serde_json::Value>,
    pub event_top: Vec<serde_json::Value>,
}

const PROBE_SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$disks = @(Get-PhysicalDisk | ForEach-Object {
  $r = $_ | Get-StorageReliabilityCounter
  [pscustomobject]@{
    name = [string]$_.FriendlyName; media = [string]$_.MediaType; bus = [string]$_.BusType
    health = [string]$_.HealthStatus; op = [string]($_.OperationalStatus -join ',')
    size_gb = [math]::Round($_.Size / 1GB); wear = $r.Wear; temp_c = $r.Temperature
    read_errors = $r.ReadErrorsUncorrected; power_on_hours = $r.PowerOnHours
  }
})
$reboot = @()
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending') { $reboot += 'servicing' }
if (Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired') { $reboot += 'windows update' }
if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager').PendingFileRenameOperations) { $reboot += 'pending file renames' }
$hf = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
$updDays = if ($hf) { [int]((Get-Date) - $hf.InstalledOn).TotalDays } else { $null }
$startup = @(Get-CimInstance Win32_StartupCommand).Count
$ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; Level = 1, 2; StartTime = (Get-Date).AddDays(-7) } -MaxEvents 2000)
$top = @($ev | Group-Object ProviderName | Sort-Object Count -Descending | Select-Object -First 8 | ForEach-Object { [pscustomobject]@{ provider = $_.Name; count = $_.Count } })
$unexpected = @($ev | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-Kernel-Power' -and $_.Id -eq 41 }).Count
$diskErr = @($ev | Where-Object { $_.ProviderName -in @('disk', 'Ntfs', 'Microsoft-Windows-Ntfs', 'stornvme', 'storahci', 'iaStorA', 'iaStorAC', 'volmgr') }).Count
$whea = @($ev | Where-Object { $_.ProviderName -eq 'Microsoft-Windows-WHEA-Logger' }).Count
$trim = (fsutil behavior query DisableDeleteNotify | Out-String)
$bFull = (Get-CimInstance -Namespace root\wmi -ClassName BatteryFullChargedCapacity | Select-Object -First 1).FullChargedCapacity
$bDesign = (Get-CimInstance -Namespace root\wmi -ClassName BatteryStaticData | Select-Object -First 1).DesignedCapacity
[pscustomobject]@{
  disks = $disks; reboot = $reboot; last_update_days = $updDays; startup = $startup
  event_errors = $ev.Count; event_top = $top; unexpected_shutdowns = $unexpected
  disk_errors = $diskErr; whea = $whea; trim = $trim; battery_full = $bFull; battery_design = $bDesign
} | ConvertTo-Json -Depth 4 -Compress
"#;

fn finding(
    id: &'static str,
    category: &'static str,
    severity: &'static str,
    title: impl Into<String>,
    current: impl Into<String>,
    recommended: impl Into<String>,
    fix: Option<&str>,
    requires_admin: bool,
) -> Finding {
    Finding {
        id,
        category,
        severity,
        title: title.into(),
        current: current.into(),
        recommended: recommended.into(),
        fix_command: fix.map(str::to_string),
        requires_admin,
    }
}

fn arr(v: &serde_json::Value) -> Vec<serde_json::Value> {
    match v {
        serde_json::Value::Array(a) => a.clone(),
        serde_json::Value::Null => Vec::new(),
        other => vec![other.clone()],
    }
}

pub async fn audit() -> HealthReport {
    let started = Instant::now();
    let probe = super::ps_json(PROBE_SCRIPT, Duration::from_secs(120)).await.unwrap_or(serde_json::Value::Null);
    let mut f = Vec::new();

    // --- storage: system drive free space -----------------------------
    let system_drive = std::env::var("SystemDrive").unwrap_or_else(|_| "C:".into());
    let disks = Disks::new_with_refreshed_list();
    let mut sys_free_pct = 100.0;
    if let Some(d) = disks.iter().find(|d| {
        d.mount_point().to_string_lossy().to_ascii_uppercase().starts_with(&system_drive.to_ascii_uppercase())
    }) {
        let total = d.total_space().max(1);
        sys_free_pct = d.available_space() as f64 / total as f64 * 100.0;
        f.push(finding(
            "storage.system_free", "storage",
            if sys_free_pct < 5.0 { "critical" } else if sys_free_pct < 10.0 { "warn" } else if sys_free_pct < 20.0 { "opportunity" } else { "ok" },
            format!("Free space on {system_drive}"),
            format!("{:.0} GB free of {:.0} GB ({:.0}%)", super::gb(d.available_space()), super::gb(total), sys_free_pct),
            ">20% free — Windows Update, the page file and SSD wear-levelling all need headroom. Run the junk cleaner and review large files.",
            None, false,
        ));
    }

    // --- storage: physical disk health --------------------------------
    let disk_list = arr(&probe["disks"]);
    for d in &disk_list {
        let name = d["name"].as_str().unwrap_or("disk");
        let health = d["health"].as_str().unwrap_or("Unknown");
        let wear = d["wear"].as_u64();
        let temp = d["temp_c"].as_u64().filter(|&t| t > 0);
        let read_err = d["read_errors"].as_u64().unwrap_or(0);
        let sev = if health.eq_ignore_ascii_case("Unhealthy") { "critical" }
            else if health.eq_ignore_ascii_case("Warning") || wear.unwrap_or(0) >= 80 || read_err > 0 { "warn" }
            else if wear.unwrap_or(0) >= 50 || temp.unwrap_or(0) >= 65 { "opportunity" }
            else { "ok" };
        let mut cur = format!("{health} · {} {}", d["media"].as_str().unwrap_or(""), d["bus"].as_str().unwrap_or(""));
        if let Some(w) = wear { cur.push_str(&format!(" · {w}% worn")); }
        if let Some(t) = temp { cur.push_str(&format!(" · {t}°C")); }
        if read_err > 0 { cur.push_str(&format!(" · {read_err} uncorrected read errors")); }
        f.push(finding(
            "storage.disk_health", "storage", sev,
            format!("Drive health: {name}"),
            cur,
            "Healthy, <50% wear, no uncorrected errors. Back up now if a drive reports Warning/Unhealthy.",
            Some("Get-PhysicalDisk | Get-StorageReliabilityCounter | Format-List DeviceId,Wear,Temperature,ReadErrorsTotal,ReadErrorsUncorrected,WriteErrorsTotal,PowerOnHours | Out-String"),
            true,
        ));
    }

    let disk_errors = probe["disk_errors"].as_u64().unwrap_or(0);
    if disk_errors > 0 {
        f.push(finding(
            "storage.disk_errors", "storage", "warn",
            "Disk / file-system errors in the event log",
            format!("{disk_errors} disk or NTFS errors in the last 7 days"),
            "Check the drive and cable; run an online file-system scan.",
            Some("chkdsk.exe $env:SystemDrive /scan"),
            true,
        ));
    }

    // --- storage: TRIM ------------------------------------------------
    let trim = probe["trim"].as_str().unwrap_or("");
    if trim.contains("NTFS DisableDeleteNotify = 1") {
        f.push(finding(
            "storage.trim", "storage", "warn",
            "SSD TRIM is disabled",
            "NTFS DisableDeleteNotify = 1",
            "Enable TRIM so the SSD can reclaim freed blocks and keep write speed up.",
            Some("fsutil behavior set DisableDeleteNotify 0"),
            true,
        ));
    }

    f.push(finding(
        "storage.optimize", "storage", "info",
        "Optimize system drive",
        "on demand",
        "Runs TRIM on SSDs or defrag on HDDs (Windows picks the right one).",
        Some("Optimize-Volume -DriveLetter $env:SystemDrive.Substring(0,1) -Verbose 4>&1 | Out-String"),
        true,
    ));

    f.push(finding(
        "storage.component_store", "storage", if sys_free_pct < 15.0 { "opportunity" } else { "info" },
        "Clean up Windows component store (WinSxS)",
        "on demand",
        "Removes superseded update components. Typically frees 1–5 GB; takes a few minutes.",
        Some("Dism.exe /Online /Cleanup-Image /StartComponentCleanup"),
        true,
    ));

    // --- storage: hibernation file ------------------------------------
    let hiberfil = std::path::PathBuf::from(format!("{system_drive}\\hiberfil.sys"));
    if let Ok(m) = std::fs::metadata(&hiberfil) {
        let gb = super::gb(m.len());
        if gb >= 4.0 {
            f.push(finding(
                "storage.hibernation", "storage", if sys_free_pct < 15.0 { "opportunity" } else { "info" },
                "Hibernation file",
                format!("hiberfil.sys is {gb:.1} GB"),
                "Desktops that never hibernate can turn it off to reclaim the space (also disables Fast Startup).",
                Some("powercfg /hibernate off"),
                true,
            ));
        }
    }

    // --- system: pending reboot ---------------------------------------
    let reboot: Vec<String> = arr(&probe["reboot"]).iter().filter_map(|v| v.as_str().map(str::to_string)).collect();
    f.push(finding(
        "system.pending_reboot", "system",
        if reboot.is_empty() { "ok" } else { "warn" },
        "Pending restart",
        if reboot.is_empty() { "none".to_string() } else { format!("required by: {}", reboot.join(", ")) },
        "Restart so pending updates and file replacements finish installing.",
        if reboot.is_empty() { None } else { Some("Restart-Computer -Force") },
        true,
    ));

    // --- system: update recency ---------------------------------------
    if let Some(days) = probe["last_update_days"].as_i64() {
        f.push(finding(
            "system.updates", "system",
            if days > 60 { "warn" } else if days > 35 { "opportunity" } else { "ok" },
            "Windows Update",
            format!("last update installed {days} days ago"),
            "Monthly security updates should land within ~30 days.",
            Some("Start-Process 'ms-settings:windowsupdate'"),
            false,
        ));
    }

    // --- system: startup load -----------------------------------------
    if let Some(n) = probe["startup"].as_u64() {
        f.push(finding(
            "system.startup_items", "system",
            if n > 25 { "warn" } else if n > 15 { "opportunity" } else { "ok" },
            "Programs that start with Windows",
            format!("{n} startup entries"),
            "Fewer than ~15. Disable what you don't need in Task Manager > Startup apps (Bastion's autoruns detector flags new ones).",
            Some("Start-Process taskmgr -ArgumentList '/0 /startup'"),
            false,
        ));
    }

    // --- system: stability / integrity --------------------------------
    let unexpected = probe["unexpected_shutdowns"].as_u64().unwrap_or(0);
    let whea = probe["whea"].as_u64().unwrap_or(0);
    let event_errors = probe["event_errors"].as_u64().unwrap_or(0);
    if unexpected > 0 {
        f.push(finding(
            "system.unexpected_shutdowns", "system", if unexpected >= 3 { "warn" } else { "opportunity" },
            "Unexpected shutdowns",
            format!("{unexpected} in the last 7 days (Kernel-Power 41)"),
            "Usually power loss, a hard reset, overheating or an unstable driver/overclock.",
            None, false,
        ));
    }
    if whea > 0 {
        f.push(finding(
            "hardware.whea", "hardware", "warn",
            "Hardware errors reported (WHEA)",
            format!("{whea} in the last 7 days"),
            "CPU, memory or PCIe errors. Revert overclocks / XMP, update BIOS, run Windows Memory Diagnostic.",
            Some("Start-Process mdsched.exe"),
            true,
        ));
    }
    f.push(finding(
        "system.integrity", "system",
        if unexpected + whea + disk_errors > 0 || event_errors > 200 { "opportunity" } else { "info" },
        "System file integrity",
        format!("{event_errors} System-log errors in the last 7 days"),
        "Repair the component store and system files (DISM then SFC). Takes 10–20 minutes.",
        Some("Dism.exe /Online /Cleanup-Image /RestoreHealth; sfc.exe /scannow"),
        true,
    ));

    // --- battery ------------------------------------------------------
    if let (Some(full), Some(design)) = (probe["battery_full"].as_u64(), probe["battery_design"].as_u64()) {
        if design > 0 {
            let pct = (full as f64 / design as f64 * 100.0).min(100.0);
            f.push(finding(
                "hardware.battery", "hardware",
                if pct < 60.0 { "warn" } else if pct < 80.0 { "opportunity" } else { "ok" },
                "Battery health",
                format!("{pct:.0}% of design capacity"),
                "Below ~80% runtime drops noticeably; below 60% consider a replacement.",
                Some("powercfg /batteryreport /output \"$env:USERPROFILE\\battery-report.html\"; Start-Process \"$env:USERPROFILE\\battery-report.html\""),
                false,
            ));
        }
    }

    HealthReport {
        elapsed_ms: started.elapsed().as_millis(),
        findings: f,
        disks: disk_list,
        event_top: arr(&probe["event_top"]),
    }
}
