// ASR (Attack Surface Reduction) detector — Bastion's behavioural-rules engine.
// ----------------------------------------------------------------------------
// Inspired by Microsoft Defender's ASR rules (the things hardly anyone enables
// because they live behind Intune / Group Policy and admins are afraid of
// breakage). We ship them turned-on with sane defaults and visible alerts, and
// the user can quiet a rule from the dashboard if it's noisy in their workflow.
//
// v1 scope: detect-and-alert only. We do NOT kill processes from a rule match
// yet — that needs a confidence calibration window first. The operator console
// already gives the user a one-click [kill pid] on every event row, so an ASR
// alert is one click away from "alert + response" today.
//
// Each rule returns Option<AsrHit { rule_id, severity, reason }>. The detector
// dedupes by PID so the same offending process doesn't fire every 3s.
//
// Rules implemented in v1 (all command-line / parent-child shape matching,
// no kernel hooks, no WinAPI dependencies beyond what sysinfo already uses):
//
//   1. office_spawns_scripting_host    Office app -> powershell/cmd/wscript/mshta/regsvr32
//   2. script_host_spawns_lolbin       cmd/powershell -> certutil/bitsadmin/installutil/msbuild
//   3. browser_spawns_scripting_host   chrome/edge/firefox -> powershell/cmd/wscript/mshta
//   4. mshta_remote_url                mshta launched with http(s):// in cmdline
//   5. certutil_remote_download        certutil + -urlcache / -split / -f
//   6. powershell_encoded_or_hidden    powershell -enc / -encodedcommand / -w hidden / -nop
//   7. rundll32_no_args                rundll32 with empty or single-arg cmdline (DLL side-loading)
//   8. wmiprvse_spawns_shell           wmiprvse.exe -> powershell/cmd (remote WMI exec)
//
// Things explicitly deferred to v2 (need a bit more infrastructure):
//   * LSASS handle open by non-MS-signed process (needs NtQuerySystemInformation
//     SystemHandleInformation + OpenProcessToken signer lookup).
//   * Script host writing .exe into %TEMP% / %APPDATA% (needs to correlate
//     scan_engine events back to the writer PID).
//   * Persistence write (Run-key / scheduled task) within N seconds of a
//     suspicious spawn (needs cross-detector event correlation).

use crate::store::{now_event, Store};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{Pid, System};

const POLL_SECS: u64 = 3;
const DEDUPE_MAX: usize = 4096;

struct AsrHit {
    rule_id: &'static str,
    severity: &'static str, // "alert" | "warn" | "info"
    reason: String,
}

pub async fn run(store: Arc<Store>) {
    let mut sys = System::new();
    let mut seen: HashSet<(Pid, &'static str)> = HashSet::new();
    // Boot-time grace: don't fire on the first sweep because every running
    // PID looks "new" to us and we'd swamp the console.
    let mut first_pass = true;

    loop {
        sys.refresh_processes();

        for (child_pid, child) in sys.processes() {
            let Some(parent_pid) = child.parent() else { continue };
            let Some(parent) = sys.process(parent_pid) else { continue };

            let child_name  = exe_basename(child).to_ascii_lowercase();
            let parent_name = exe_basename(parent).to_ascii_lowercase();
            if child_name.is_empty() { continue; }

            let cmd_join = child.cmd().join(" ");
            let cmd_lc   = cmd_join.to_ascii_lowercase();

            let hits = [
                rule_office_spawns_scripting_host(&parent_name, &child_name),
                rule_script_host_spawns_lolbin(&parent_name, &child_name, &cmd_lc),
                rule_browser_spawns_scripting_host(&parent_name, &child_name),
                rule_mshta_remote_url(&child_name, &cmd_lc),
                rule_certutil_remote_download(&child_name, &cmd_lc),
                rule_powershell_encoded_or_hidden(&child_name, &cmd_lc),
                rule_rundll32_no_args(&child_name, child.cmd()),
                rule_wmiprvse_spawns_shell(&parent_name, &child_name),
            ];

            for hit in hits.into_iter().flatten() {
                let key = (*child_pid, hit.rule_id);
                if !seen.insert(key) { continue; }
                if first_pass { continue; } // suppress baseline noise

                let summary = format!("ASR/{}: {}", hit.rule_id, hit.reason);
                let _ = store.insert_event(&now_event(
                    "asr",
                    hit.severity,
                    hit.rule_id,
                    summary,
                    serde_json::json!({
                        "rule_id":     hit.rule_id,
                        "parent_pid":  parent_pid.as_u32(),
                        "parent_exe":  parent_name,
                        "child_pid":   child_pid.as_u32(),
                        "child_exe":   child_name,
                        "child_cmdline": cmd_join,
                    }),
                ));
            }
        }

        // Keep the dedupe set bounded so a long-running agent doesn't grow
        // unbounded. We don't need eviction order — any PID we forget will
        // simply re-alert once, which is fine for our cadence.
        if seen.len() > DEDUPE_MAX {
            seen.clear();
        }
        first_pass = false;
        tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

fn exe_basename(p: &sysinfo::Process) -> String {
    p.exe()
        .and_then(|e| e.file_name())
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_else(|| p.name().to_string())
}

// ---------------------------------------------------------------------------
// Rules. Each is a pure function — easy to unit-test, easy to disable.
// ---------------------------------------------------------------------------

const OFFICE_APPS: &[&str] = &[
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe",
    "msaccess.exe", "mspub.exe", "visio.exe", "onenote.exe",
];

const SCRIPTING_HOSTS: &[&str] = &[
    "powershell.exe", "pwsh.exe", "cmd.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
    "regsvr32.exe", "rundll32.exe",
];

const BROWSERS: &[&str] = &[
    "chrome.exe", "msedge.exe", "firefox.exe", "brave.exe", "opera.exe", "vivaldi.exe",
];

const LOLBINS_DOWNLOADERS: &[&str] = &[
    "certutil.exe", "bitsadmin.exe", "installutil.exe", "msbuild.exe",
    "csc.exe", "regasm.exe", "regsvcs.exe", "msxsl.exe", "ieexec.exe",
];

fn rule_office_spawns_scripting_host(parent: &str, child: &str) -> Option<AsrHit> {
    if OFFICE_APPS.contains(&parent) && SCRIPTING_HOSTS.contains(&child) {
        return Some(AsrHit {
            rule_id: "office_spawns_scripting_host",
            severity: "alert",
            reason: format!("Office app `{parent}` spawned `{child}` — classic macro-loader pattern"),
        });
    }
    None
}

fn rule_script_host_spawns_lolbin(parent: &str, child: &str, cmd_lc: &str) -> Option<AsrHit> {
    let script_hosts: &[&str] = &["powershell.exe", "pwsh.exe", "cmd.exe", "wscript.exe", "cscript.exe"];
    if !script_hosts.contains(&parent) || !LOLBINS_DOWNLOADERS.contains(&child) {
        return None;
    }
    // Bump severity only when the lolbin's cmdline looks downloader-shaped.
    let downloader_shape = cmd_lc.contains("http://")
        || cmd_lc.contains("https://")
        || cmd_lc.contains("-urlcache")
        || cmd_lc.contains("-split")
        || cmd_lc.contains("-decode");
    Some(AsrHit {
        rule_id: "script_host_spawns_lolbin",
        severity: if downloader_shape { "alert" } else { "warn" },
        reason: format!("`{parent}` spawned LOLBin `{child}`"),
    })
}

fn rule_browser_spawns_scripting_host(parent: &str, child: &str) -> Option<AsrHit> {
    if BROWSERS.contains(&parent) && SCRIPTING_HOSTS.contains(&child) {
        return Some(AsrHit {
            rule_id: "browser_spawns_scripting_host",
            severity: "alert",
            reason: format!("Browser `{parent}` spawned `{child}` — exploit / drive-by indicator"),
        });
    }
    None
}

fn rule_mshta_remote_url(child: &str, cmd_lc: &str) -> Option<AsrHit> {
    if child == "mshta.exe" && (cmd_lc.contains("http://") || cmd_lc.contains("https://")) {
        return Some(AsrHit {
            rule_id: "mshta_remote_url",
            severity: "alert",
            reason: "mshta.exe launched against a remote URL".into(),
        });
    }
    None
}

fn rule_certutil_remote_download(child: &str, cmd_lc: &str) -> Option<AsrHit> {
    if child == "certutil.exe"
        && (cmd_lc.contains("-urlcache") || cmd_lc.contains("-split")
            || cmd_lc.contains("http://") || cmd_lc.contains("https://"))
    {
        return Some(AsrHit {
            rule_id: "certutil_remote_download",
            severity: "alert",
            reason: "certutil.exe used as a remote downloader".into(),
        });
    }
    None
}

fn rule_powershell_encoded_or_hidden(child: &str, cmd_lc: &str) -> Option<AsrHit> {
    if child != "powershell.exe" && child != "pwsh.exe" {
        return None;
    }
    let encoded = cmd_lc.contains(" -enc ") || cmd_lc.contains(" -encodedcommand ")
        || cmd_lc.contains(" -e ") || cmd_lc.contains("/enc ");
    let hidden  = cmd_lc.contains(" -w hidden") || cmd_lc.contains(" -windowstyle hidden");
    let nopolicy = cmd_lc.contains(" -nop") || cmd_lc.contains(" -noprofile")
        || cmd_lc.contains(" -ep bypass") || cmd_lc.contains(" -executionpolicy bypass");
    let flags = [encoded, hidden, nopolicy].iter().filter(|b| **b).count();
    if flags == 0 { return None; }
    Some(AsrHit {
        rule_id: "powershell_encoded_or_hidden",
        severity: if encoded || flags >= 2 { "alert" } else { "warn" },
        reason: format!("powershell launched with stealth flags (encoded={encoded} hidden={hidden} nopolicy={nopolicy})"),
    })
}

fn rule_rundll32_no_args(child: &str, cmd: &[String]) -> Option<AsrHit> {
    if child != "rundll32.exe" { return None; }
    // Legit rundll32 always has at least DLL,Function — i.e. 2 args after exe.
    if cmd.len() <= 1 {
        return Some(AsrHit {
            rule_id: "rundll32_no_args",
            severity: "warn",
            reason: "rundll32.exe invoked with no arguments (DLL side-load or proxy exec)".into(),
        });
    }
    None
}

fn rule_wmiprvse_spawns_shell(parent: &str, child: &str) -> Option<AsrHit> {
    let shells: &[&str] = &["powershell.exe", "pwsh.exe", "cmd.exe"];
    if parent == "wmiprvse.exe" && shells.contains(&child) {
        return Some(AsrHit {
            rule_id: "wmiprvse_spawns_shell",
            severity: "alert",
            reason: format!("wmiprvse.exe spawned `{child}` — likely remote WMI execution"),
        });
    }
    None
}
