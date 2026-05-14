// Process lineage detector (N2)
// ----------------------------------------------------------------------------
// We treat process spawns as a directed graph: edges (parent_exe -> child_exe).
// During a baseline window we silently learn the set of "normal" edges. After
// baseline, any never-before-seen edge fires an event.
//
// Severity is assigned by a small ruleset that targets known LOLBin spawn
// chains: e.g. winword.exe -> powershell.exe is a near-certain attack
// indicator (Office macros do not legitimately do this in a default office
// install). Lower-confidence novel edges are emitted as `info` so the dashboard
// still shows them but they don't pageyou.
//
// Limitation (honest): polling-based, so processes that live <5s may be missed
// between snapshots. v2 candidate: hook the WMI Win32_ProcessStartTrace event
// class via a `wmic process call create ...` watcher or a windows-rs ETW
// session for sub-second resolution.

use crate::store::{now_event, Store};
use std::sync::Arc;
use std::time::{Duration, Instant};
use sysinfo::System;

const POLL_SECS: u64 = 5;
const BASELINE_SECS: u64 = 90;

pub async fn run(store: Arc<Store>) {
    let baseline_until = Instant::now() + Duration::from_secs(BASELINE_SECS);
    let already_primed = store.mark_seen("lineage_meta", "primed").map(|n| !n).unwrap_or(false);
    let mut emitted_baseline_event = already_primed;
    let mut sys = System::new();

    loop {
        sys.refresh_processes();
        let in_baseline = Instant::now() < baseline_until && !already_primed;

        for (child_pid, child_proc) in sys.processes() {
            let parent_pid = match child_proc.parent() {
                Some(p) => p,
                None => continue,
            };
            let parent_proc = match sys.process(parent_pid) {
                Some(p) => p,
                None => continue,
            };

            let child_name = exe_basename(child_proc);
            let parent_name = exe_basename(parent_proc);
            if child_name.is_empty() || parent_name.is_empty() {
                continue;
            }

            let edge = format!("{parent_name}->{child_name}");
            let is_new = match store.mark_seen("proc_edge", &edge) {
                Ok(b) => b,
                Err(_) => continue,
            };

            if is_new && !in_baseline {
                let severity = severity_for_edge(&parent_name, &child_name);
                let summary = format!("novel spawn edge: {parent_name} -> {child_name}");
                let details = serde_json::json!({
                    "parent_exe": parent_name,
                    "child_exe": child_name,
                    "parent_pid": parent_pid.as_u32(),
                    "child_pid": child_pid.as_u32(),
                    "child_cmdline": child_proc.cmd().join(" "),
                });
                let _ = store.insert_event(&now_event("lineage", severity, "novel_edge", summary, details));
            }
        }

        if !emitted_baseline_event && Instant::now() >= baseline_until {
            emitted_baseline_event = true;
            let _ = store.insert_event(&now_event(
                "lineage",
                "info",
                "lineage_baseline",
                "Process lineage baseline established".into(),
                serde_json::json!({ "baseline_secs": BASELINE_SECS }),
            ));
        }

        tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

fn exe_basename(p: &sysinfo::Process) -> String {
    p.exe()
        .and_then(|path| path.file_name())
        .and_then(|s| s.to_str())
        .map(|s| s.to_lowercase())
        .unwrap_or_else(|| p.name().to_lowercase())
}

/// Heuristic severity for a never-before-seen (parent -> child) edge.
/// Drawn from public LOLBin / MITRE ATT&CK literature, kept conservative.
fn severity_for_edge(parent: &str, child: &str) -> &'static str {
    const HIGH_RISK_CHILDREN: &[&str] = &[
        "powershell.exe",
        "pwsh.exe",
        "cmd.exe",
        "wscript.exe",
        "cscript.exe",
        "mshta.exe",
        "rundll32.exe",
        "regsvr32.exe",
        "certutil.exe",
        "bitsadmin.exe",
        "msbuild.exe",
        "installutil.exe",
        "regasm.exe",
        "regsvcs.exe",
    ];
    const OFFICE_PARENTS: &[&str] = &[
        "winword.exe",
        "excel.exe",
        "powerpnt.exe",
        "outlook.exe",
        "visio.exe",
        "msaccess.exe",
    ];
    const BROWSER_PARENTS: &[&str] = &[
        "chrome.exe",
        "msedge.exe",
        "firefox.exe",
        "brave.exe",
        "opera.exe",
    ];

    // Office or browser spawning a shell / scripting host = textbook macro/exploit chain.
    if (OFFICE_PARENTS.contains(&parent) || BROWSER_PARENTS.contains(&parent))
        && HIGH_RISK_CHILDREN.contains(&child)
    {
        return "alert";
    }
    // Shell spawning shell across host types still suspicious.
    if (parent == "powershell.exe" || parent == "pwsh.exe" || parent == "cmd.exe")
        && HIGH_RISK_CHILDREN.contains(&child)
    {
        return "warn";
    }
    // wmic / mshta spawning anything = warn (rarely used legitimately).
    if parent == "wmic.exe" || parent == "mshta.exe" {
        return "warn";
    }
    "info"
}
