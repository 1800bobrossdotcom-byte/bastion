// Installed programs: Win32 (registry Uninstall keys) + Store / AppX apps.
//
// The list flags commonly-unwanted preinstalls, large installs and stale
// installs so the user can decide what to remove. Uninstall is by id only:
// the agent re-lists programs, finds the id, and launches *that program's
// own* registered uninstaller (exactly what Settings > Apps does). Nothing
// is removed silently — Win32 uninstallers show their normal UI.

use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub struct Program {
    /// `win32:<hive>:<key>` or `appx:<PackageFullName>`.
    pub id: String,
    /// win32 | appx
    pub kind: &'static str,
    pub name: String,
    pub version: String,
    pub publisher: String,
    /// YYYY-MM-DD when known.
    pub install_date: Option<String>,
    pub size_mb: Option<u64>,
    pub location: String,
    pub uninstallable: bool,
    /// bloatware | large | stale
    pub flags: Vec<&'static str>,
    #[serde(skip)]
    uninstall: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ProgramsReport {
    pub elapsed_ms: u128,
    pub total: usize,
    pub flagged_bloatware: usize,
    pub total_size_gb: f64,
    pub programs: Vec<Program>,
}

#[derive(Debug, Deserialize)]
pub struct UninstallRequest {
    pub id: String,
    /// Must be true — guards against a stray/replayed request.
    #[serde(default)]
    pub confirm: bool,
}

#[derive(Debug, Serialize)]
pub struct UninstallOutcome {
    pub ok: bool,
    pub id: String,
    pub name: String,
    pub message: String,
}

const LIST_SCRIPT: &str = r#"
$ErrorActionPreference = 'SilentlyContinue'
$keys = @(
  @{ h = 'HKLM';   p = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' },
  @{ h = 'HKLM32'; p = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' },
  @{ h = 'HKCU';   p = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' }
)
$win32 = foreach ($k in $keys) {
  Get-ItemProperty -Path $k.p | Where-Object { $_.DisplayName -and -not $_.SystemComponent -and -not $_.ParentKeyName -and -not $_.ReleaseType } | ForEach-Object {
    [pscustomobject]@{
      hive = $k.h; key = $_.PSChildName; name = [string]$_.DisplayName; version = [string]$_.DisplayVersion
      publisher = [string]$_.Publisher; install_date = [string]$_.InstallDate; size_kb = $_.EstimatedSize
      uninstall = [string]$_.UninstallString; location = [string]$_.InstallLocation
    }
  }
}
$appx = Get-AppxPackage | Where-Object { -not $_.IsFramework -and -not $_.NonRemovable -and $_.SignatureKind -ne 'System' } | ForEach-Object {
  [pscustomobject]@{ name = [string]$_.Name; full = [string]$_.PackageFullName; version = [string]$_.Version; publisher = [string]$_.Publisher; location = [string]$_.InstallLocation }
}
[pscustomobject]@{ win32 = @($win32); appx = @($appx) } | ConvertTo-Json -Depth 3 -Compress
"#;

/// Lower-cased substrings of DisplayName for well-known PUPs / trialware.
const WIN32_BLOAT: &[&str] = &[
    "mcafee", "norton security", "norton 360", "wildtangent", "booking.com", "candy crush",
    "ask toolbar", "conduit", "babylon toolbar", "driver booster", "driver support", "pc optimizer",
    "reimage", "segurazo", "web companion", "advanced systemcare", "pc app store", "onelaunch",
    "wave browser", "shift browser", "dropbox promotion", "expressvpn trial",
];

/// AppX package-name prefixes Windows ships that most people never use.
const APPX_BLOAT: &[&str] = &[
    "Microsoft.BingNews", "Microsoft.BingWeather", "Microsoft.BingSearch", "Microsoft.GetHelp",
    "Microsoft.Getstarted", "Microsoft.MicrosoftSolitaireCollection", "Microsoft.MicrosoftOfficeHub",
    "Microsoft.People", "Microsoft.MixedReality.Portal", "Microsoft.SkypeApp", "Microsoft.WindowsFeedbackHub",
    "Microsoft.549981C3F5F10", "Microsoft.ZuneVideo", "Microsoft.Microsoft3DViewer", "Microsoft.Print3D",
    "Microsoft.OneConnect", "Clipchamp.Clipchamp", "king.com.", "Disney.", "Facebook.", "AmazonVideo.",
    "SpotifyAB.SpotifyMusic", "BytedancePte.", "Microsoft.MicrosoftJournal",
];

const LARGE_MB: u64 = 2048;
const STALE_DAYS: i64 = 365 * 2;

pub async fn list() -> ProgramsReport {
    let started = std::time::Instant::now();
    let mut programs = Vec::new();
    if let Some(v) = super::ps_json(LIST_SCRIPT, Duration::from_secs(90)).await {
        programs.extend(parse_win32(&v["win32"]));
        programs.extend(parse_appx(&v["appx"]));
    }
    programs.sort_by(|a, b| {
        b.flags.contains(&"bloatware").cmp(&a.flags.contains(&"bloatware"))
            .then(b.size_mb.unwrap_or(0).cmp(&a.size_mb.unwrap_or(0)))
            .then(a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
    let total_mb: u64 = programs.iter().filter_map(|p| p.size_mb).sum();
    ProgramsReport {
        elapsed_ms: started.elapsed().as_millis(),
        total: programs.len(),
        flagged_bloatware: programs.iter().filter(|p| p.flags.contains(&"bloatware")).count(),
        total_size_gb: total_mb as f64 / 1024.0,
        programs,
    }
}

fn as_array(v: &serde_json::Value) -> Vec<serde_json::Value> {
    match v {
        serde_json::Value::Array(a) => a.clone(),
        serde_json::Value::Null => Vec::new(),
        // PowerShell 5.1 sometimes unwraps single-element arrays.
        other => vec![other.clone()],
    }
}

fn s(v: &serde_json::Value, k: &str) -> String {
    v[k].as_str().unwrap_or("").trim().to_string()
}

fn parse_install_date(raw: &str) -> Option<chrono::NaiveDate> {
    chrono::NaiveDate::parse_from_str(raw, "%Y%m%d").ok()
        .or_else(|| chrono::NaiveDate::parse_from_str(raw, "%m/%d/%Y").ok())
        .or_else(|| chrono::NaiveDate::parse_from_str(raw, "%Y-%m-%d").ok())
}

fn parse_win32(v: &serde_json::Value) -> Vec<Program> {
    let today = chrono::Local::now().date_naive();
    let mut seen = std::collections::HashSet::new();
    as_array(v).iter().filter_map(|p| {
        let name = s(p, "name");
        if name.is_empty() { return None; }
        let version = s(p, "version");
        // Same product often registers under both 32- and 64-bit views.
        if !seen.insert((name.to_lowercase(), version.clone())) { return None; }
        let date = parse_install_date(&s(p, "install_date"));
        let size_mb = p["size_kb"].as_u64().map(|kb| kb / 1024).filter(|&mb| mb > 0);
        let uninstall = Some(s(p, "uninstall")).filter(|u| !u.is_empty());
        let lname = name.to_lowercase();
        let mut flags = Vec::new();
        if WIN32_BLOAT.iter().any(|b| lname.contains(b)) { flags.push("bloatware"); }
        if size_mb.unwrap_or(0) >= LARGE_MB { flags.push("large"); }
        if date.map(|d| (today - d).num_days() > STALE_DAYS).unwrap_or(false) { flags.push("stale"); }
        Some(Program {
            id: format!("win32:{}:{}", s(p, "hive"), s(p, "key")),
            kind: "win32",
            name,
            version,
            publisher: s(p, "publisher"),
            install_date: date.map(|d| d.to_string()),
            size_mb,
            location: s(p, "location"),
            uninstallable: uninstall.is_some(),
            flags,
            uninstall,
        })
    }).collect()
}

fn parse_appx(v: &serde_json::Value) -> Vec<Program> {
    as_array(v).iter().filter_map(|p| {
        let pkg = s(p, "name");
        let full = s(p, "full");
        if pkg.is_empty() || !valid_package_full_name(&full) { return None; }
        let mut flags = Vec::new();
        if APPX_BLOAT.iter().any(|b| pkg.starts_with(b)) { flags.push("bloatware"); }
        Some(Program {
            id: format!("appx:{full}"),
            kind: "appx",
            name: pkg,
            version: s(p, "version"),
            publisher: s(p, "publisher").split(',').next().unwrap_or("").trim_start_matches("CN=").to_string(),
            install_date: None,
            size_mb: None,
            location: s(p, "location"),
            uninstallable: true,
            flags,
            uninstall: None,
        })
    }).collect()
}

fn valid_package_full_name(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '~'))
}

/// Split an UninstallString into (exe, args). Handles quoted and unquoted
/// paths, and turns `MsiExec.exe /I{GUID}` (modify) into `/X{GUID}` (remove).
pub(crate) fn split_command(cmd: &str) -> Option<(String, String)> {
    let cmd = cmd.trim();
    let (exe, rest) = if let Some(stripped) = cmd.strip_prefix('"') {
        let end = stripped.find('"')?;
        (stripped[..end].to_string(), stripped[end + 1..].trim().to_string())
    } else {
        let lower = cmd.to_ascii_lowercase();
        match lower.find(".exe") {
            Some(i) => (cmd[..i + 4].to_string(), cmd[i + 4..].trim().to_string()),
            None => match cmd.split_once(' ') {
                Some((e, r)) => (e.to_string(), r.trim().to_string()),
                None => (cmd.to_string(), String::new()),
            },
        }
    };
    if exe.is_empty() { return None; }
    let is_msi = exe.to_ascii_lowercase().trim_end_matches(".exe").ends_with("msiexec");
    let args = if is_msi {
        let a = rest.replace("/I{", "/X{").replace("/i{", "/X{");
        if a.contains("/X{") || a.contains("/x{") { a } else { rest }
    } else {
        rest
    };
    Some((exe, args))
}

pub async fn uninstall(req: &UninstallRequest) -> UninstallOutcome {
    let fail = |name: &str, msg: &str| UninstallOutcome { ok: false, id: req.id.clone(), name: name.into(), message: msg.into() };
    if !req.confirm {
        return fail("", "confirm must be true");
    }
    // Re-list and resolve the id against what is actually installed right now.
    let report = list().await;
    let Some(p) = report.programs.into_iter().find(|p| p.id == req.id) else {
        return fail("", "program not found (already removed?)");
    };

    let script = match p.kind {
        "appx" => {
            let full = req.id.trim_start_matches("appx:");
            if !valid_package_full_name(full) { return fail(&p.name, "invalid package name"); }
            format!("try {{ Remove-AppxPackage -Package '{full}' -ErrorAction Stop; 'ok' }} catch {{ 'err: ' + $_.Exception.Message }}")
        }
        _ => {
            let Some((exe, args)) = p.uninstall.as_deref().and_then(split_command) else {
                return fail(&p.name, "no uninstaller registered for this program");
            };
            // Start-Process goes through ShellExecute, so uninstallers whose
            // manifest requires admin get the normal UAC prompt.
            let arg_part = if args.is_empty() { String::new() } else { format!(" -ArgumentList {}", super::ps_quote(&args)) };
            format!(
                "try {{ Start-Process -FilePath {}{} -ErrorAction Stop; 'ok' }} catch {{ 'err: ' + $_.Exception.Message }}",
                super::ps_quote(&exe), arg_part
            )
        }
    };

    let out = super::ps(&script, Duration::from_secs(300)).await.unwrap_or_default();
    let ok = out.trim() == "ok";
    UninstallOutcome {
        ok,
        id: p.id,
        name: p.name,
        message: if !ok {
            out.trim().to_string()
        } else if p.kind == "appx" {
            "removed".into()
        } else {
            "uninstaller launched — follow its prompts to finish".into()
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_quoted_and_unquoted() {
        assert_eq!(
            split_command(r#""C:\Program Files\Foo\unins000.exe" /SILENT"#),
            Some((r"C:\Program Files\Foo\unins000.exe".into(), "/SILENT".into()))
        );
        assert_eq!(
            split_command(r"C:\Program Files\Bar\uninstall.exe --remove"),
            Some((r"C:\Program Files\Bar\uninstall.exe".into(), "--remove".into()))
        );
    }

    #[test]
    fn msiexec_modify_becomes_remove() {
        let (exe, args) = split_command("MsiExec.exe /I{12345678-1234-1234-1234-123456789012}").unwrap();
        assert_eq!(exe, "MsiExec.exe");
        assert_eq!(args, "/X{12345678-1234-1234-1234-123456789012}");
    }

    #[test]
    fn flags_bloat_and_dedupes() {
        let v = serde_json::json!([
            { "hive": "HKLM", "key": "a", "name": "McAfee LiveSafe", "version": "1", "install_date": "20200101", "size_kb": 4_000_000 },
            { "hive": "HKLM32", "key": "a", "name": "McAfee LiveSafe", "version": "1" },
            { "hive": "HKCU", "key": "b", "name": "Visual Studio Code", "version": "1.90" }
        ]);
        let ps = parse_win32(&v);
        assert_eq!(ps.len(), 2);
        assert!(ps[0].flags.contains(&"bloatware"));
        assert!(ps[0].flags.contains(&"large"));
        assert!(ps[0].flags.contains(&"stale"));
        assert!(ps[1].flags.is_empty());
    }

    #[test]
    fn rejects_suspicious_appx_names() {
        assert!(valid_package_full_name("Microsoft.BingNews_4.55.62231.0_x64__8wekyb3d8bbwe"));
        assert!(!valid_package_full_name("foo'; Remove-Item C:\\ -Recurse; '"));
    }
}
