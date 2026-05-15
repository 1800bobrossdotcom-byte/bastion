// AI / dev workload performance audit.
//
// Read-only sweep of the Windows box that surfaces the things that
// actually matter for local LLM inference, model training, big builds,
// and IDE responsiveness. Each finding includes:
//   * severity: ok | info | opportunity | warn | critical
//   * a `fix_command` string the user can paste into an elevated
//     PowerShell to apply the suggested change (we never apply
//     automatically — perf tuning is the user's call).
//
// Categories covered:
//   power      - active power plan
//   gpu        - NVIDIA driver/VRAM/utilization, HAGS toggle
//   memory     - total / avail RAM, page file
//   disk       - free space + filesystem per drive
//   defender   - real-time exclusions for known dev/AI dirs
//   wsl        - .wslconfig memory cap
//   process    - top CPU/RAM consumers, chrome subprocess flood
//   uptime     - days since boot (long uptime hides driver/fw updates)
//
// Designed to complete in well under 2 seconds on a cold cache.
// No state is persisted; this is a snapshot endpoint, not a detector
// that emits events into the chain.

use anyhow::Result;
use serde::Serialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Instant;
use sysinfo::{Disks, MemoryRefreshKind, ProcessRefreshKind, RefreshKind, System};
use tokio::process::Command;

#[derive(Debug, Serialize)]
pub struct PerfAudit {
    pub elapsed_ms: u128,
    pub host: HostInfo,
    pub findings: Vec<Finding>,
    pub gpu: Option<GpuInfo>,
    pub top_cpu: Vec<ProcSample>,
    pub top_mem: Vec<ProcSample>,
}

#[derive(Debug, Serialize)]
pub struct HostInfo {
    pub os_name: String,
    pub os_version: String,
    pub kernel: String,
    pub cpu_brand: String,
    pub cpu_cores_physical: usize,
    pub cpu_cores_logical: usize,
    pub mem_total_gb: f64,
    pub mem_used_gb: f64,
    pub mem_avail_gb: f64,
    pub uptime_hours: f64,
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub id: &'static str,
    pub category: &'static str,
    pub severity: &'static str, // ok | info | opportunity | warn | critical
    pub title: String,
    pub current: String,
    pub recommended: String,
    pub fix_command: Option<String>,
    /// True when the fix mutates HKLM, system services, or other admin-only state.
    /// The dashboard renders an [elevate] badge and the apply endpoint launches
    /// the command via UAC (Start-Process -Verb RunAs).
    pub requires_admin: bool,
}

#[derive(Debug, Serialize)]
pub struct ApplyOutcome {
    pub launched_elevated: bool,
    pub ok: bool,
    pub exit_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct GpuInfo {
    pub name: String,
    pub driver_version: String,
    pub vram_total_mb: u64,
    pub vram_used_mb: u64,
    pub vram_free_mb: u64,
    pub utilization_pct: u32,
    pub temperature_c: u32,
}

#[derive(Debug, Clone, Serialize)]
pub struct ProcSample {
    pub pid: u32,
    pub name: String,
    pub cpu_pct: f32,
    pub mem_mb: u64,
}

pub async fn audit() -> Result<PerfAudit> {
    let started = Instant::now();
    let mut findings: Vec<Finding> = Vec::new();

    // --- sysinfo snapshot (do this once, share across checks) ----------
    let mut sys = System::new_with_specifics(
        RefreshKind::new()
            .with_memory(MemoryRefreshKind::everything())
            .with_cpu(sysinfo::CpuRefreshKind::everything())
            .with_processes(ProcessRefreshKind::everything()),
    );
    // Two refresh ticks 250ms apart so cpu_usage is not all zeros.
    sys.refresh_all();
    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
    sys.refresh_processes();
    sys.refresh_cpu();

    let mem_total_gb = sys.total_memory() as f64 / 1024.0 / 1024.0 / 1024.0;
    let mem_avail_gb = sys.available_memory() as f64 / 1024.0 / 1024.0 / 1024.0;
    let mem_used_gb = mem_total_gb - mem_avail_gb;
    let uptime_hours = System::uptime() as f64 / 3600.0;

    let host = HostInfo {
        os_name: System::name().unwrap_or_else(|| "Windows".into()),
        os_version: System::os_version().unwrap_or_default(),
        kernel: System::kernel_version().unwrap_or_default(),
        cpu_brand: sys.cpus().first().map(|c| c.brand().to_string()).unwrap_or_default(),
        cpu_cores_physical: sys.physical_core_count().unwrap_or(0),
        cpu_cores_logical: sys.cpus().len(),
        mem_total_gb,
        mem_used_gb,
        mem_avail_gb,
        uptime_hours,
    };

    // --- memory finding -----------------------------------------------
    let mem_pct_avail = if mem_total_gb > 0.0 { (mem_avail_gb / mem_total_gb) * 100.0 } else { 0.0 };
    findings.push(Finding {
        id: "memory.available",
        category: "memory",
        severity: if mem_pct_avail < 10.0 { "critical" }
                  else if mem_pct_avail < 20.0 { "warn" }
                  else if mem_pct_avail < 35.0 { "opportunity" }
                  else { "ok" },
        title: "RAM headroom".into(),
        current: format!("{:.1} GB free of {:.1} GB ({:.0}%)", mem_avail_gb, mem_total_gb, mem_pct_avail),
        recommended: ">35% free for comfortable LLM inference + IDE".into(),
        fix_command: None,
        requires_admin: false,
    });

    // --- uptime finding -----------------------------------------------
    findings.push(Finding {
        id: "uptime.days",
        category: "uptime",
        severity: if uptime_hours > 14.0 * 24.0 { "warn" }
                  else if uptime_hours > 7.0 * 24.0 { "opportunity" }
                  else { "ok" },
        title: "Days since boot".into(),
        current: format!("{:.1} h ({:.1} d)", uptime_hours, uptime_hours / 24.0),
        recommended: "reboot weekly so driver/firmware/Defender updates apply".into(),
        fix_command: Some("Restart-Computer -Force".into()),
        requires_admin: true,
    });

    // --- top processes ------------------------------------------------
    let mut procs: Vec<ProcSample> = sys.processes().iter().map(|(pid, p)| ProcSample {
        pid: pid.as_u32(),
        name: p.name().to_string(),
        cpu_pct: p.cpu_usage(),
        mem_mb: p.memory() / 1024 / 1024,
    }).collect();

    let mut top_cpu = procs.clone();
    top_cpu.sort_by(|a, b| b.cpu_pct.partial_cmp(&a.cpu_pct).unwrap_or(std::cmp::Ordering::Equal));
    top_cpu.truncate(8);

    procs.sort_by(|a, b| b.mem_mb.cmp(&a.mem_mb));
    let top_mem: Vec<_> = procs.iter().take(8).cloned().collect();

    // --- chrome subprocess flood -------------------------------------
    let chrome_count = sys.processes().values()
        .filter(|p| {
            let n = p.name().to_ascii_lowercase();
            n == "chrome.exe" || n == "msedge.exe" || n == "brave.exe"
        })
        .count();
    let chrome_mem_mb: u64 = sys.processes().values()
        .filter(|p| {
            let n = p.name().to_ascii_lowercase();
            n == "chrome.exe" || n == "msedge.exe" || n == "brave.exe"
        })
        .map(|p| p.memory() / 1024 / 1024)
        .sum();
    findings.push(Finding {
        id: "process.browser_flood",
        category: "process",
        severity: if chrome_count > 80 { "warn" }
                  else if chrome_count > 40 { "opportunity" }
                  else { "ok" },
        title: "Browser subprocess footprint".into(),
        current: format!("{chrome_count} chromium-based procs holding {chrome_mem_mb} MB"),
        recommended: "close idle tabs / use The Great Suspender; offload research to a separate profile when running a model".into(),
        fix_command: Some("Get-Process chrome,msedge,brave -ErrorAction SilentlyContinue | Sort-Object WS -Descending | Select-Object -First 20 Name,Id,@{n='MB';e={[int]($_.WorkingSet/1MB)}} | Format-Table -AutoSize | Out-String".into()),
        requires_admin: false,
    });

    // --- disks --------------------------------------------------------
    let disks = Disks::new_with_refreshed_list();
    for d in &disks {
        let total = d.total_space();
        let avail = d.available_space();
        if total == 0 { continue; }
        let pct = (avail as f64 / total as f64) * 100.0;
        let total_gb = total as f64 / 1024.0 / 1024.0 / 1024.0;
        let avail_gb = avail as f64 / 1024.0 / 1024.0 / 1024.0;
        let mount = d.mount_point().to_string_lossy().to_string();
        findings.push(Finding {
            id: "disk.free",
            category: "disk",
            severity: if pct < 5.0 { "critical" }
                      else if pct < 15.0 { "warn" }
                      else if pct < 25.0 { "opportunity" }
                      else { "ok" },
            title: format!("Disk free on {mount}"),
            current: format!("{:.0} GB free of {:.0} GB ({:.0}%)", avail_gb, total_gb, pct),
            recommended: ">25% free; SSDs slow dramatically when full and hugepage allocs for models will fail".into(),
            fix_command: Some(format!("Start-Process cleanmgr -ArgumentList '/d {}' ", mount.trim_end_matches('\\'))),
            requires_admin: false,
        });
    }

    // --- power plan ---------------------------------------------------
    let power = run_capture("powercfg", &["/getactivescheme"]).await.unwrap_or_default();
    // Output: "Power Scheme GUID: 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c  (High performance)"
    let plan_name = power
        .split('(')
        .nth(1)
        .and_then(|s| s.split(')').next())
        .unwrap_or("unknown")
        .to_string();
    let is_high = plan_name.to_lowercase().contains("high performance")
        || plan_name.to_lowercase().contains("ultimate");
    findings.push(Finding {
        id: "power.plan",
        category: "power",
        severity: if is_high { "ok" } else { "opportunity" },
        title: "Active power plan".into(),
        current: plan_name.clone(),
        recommended: "High performance or Ultimate Performance — Balanced parks cores under sustained AI load".into(),
        fix_command: Some(
            "# Activate Ultimate Performance (creates the plan if missing):\n\
             powercfg -duplicatescheme e9a42b02-d5df-448d-aa00-03f14749eb61 | Out-Null;\n\
             $g = (powercfg -list | Select-String 'Ultimate Performance').ToString().Split()[3];\n\
             powercfg -setactive $g".into()
        ),
        requires_admin: true,
    });

    // --- HAGS (Hardware-Accelerated GPU Scheduling) -------------------
    let hags = run_capture("reg", &[
        "query",
        "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers",
        "/v", "HwSchMode",
    ]).await.unwrap_or_default();
    // Looks for "0x2" in the value line.
    let hags_on = hags.contains("0x2");
    findings.push(Finding {
        id: "gpu.hags",
        category: "gpu",
        severity: if hags_on { "ok" } else { "opportunity" },
        title: "Hardware-Accelerated GPU Scheduling".into(),
        current: if hags_on { "ON".into() } else { "OFF".into() },
        recommended: "ON — reduces dispatch latency for CUDA/DirectML workloads".into(),
        fix_command: Some(
            "# Requires admin + reboot:\n\
             Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\GraphicsDrivers' -Name HwSchMode -Value 2 -Type DWord".into()
        ),
        requires_admin: true,
    });

    // --- nvidia-smi ----------------------------------------------------
    let gpu = nvidia_smi().await;
    if let Some(g) = &gpu {
        let vram_pct_used = if g.vram_total_mb > 0 {
            (g.vram_used_mb as f64 / g.vram_total_mb as f64) * 100.0
        } else { 0.0 };
        findings.push(Finding {
            id: "gpu.vram",
            category: "gpu",
            severity: if vram_pct_used > 90.0 { "warn" }
                      else if vram_pct_used > 75.0 { "opportunity" }
                      else { "ok" },
            title: format!("VRAM on {}", g.name),
            current: format!("{} MB used / {} MB ({:.0}%)", g.vram_used_mb, g.vram_total_mb, vram_pct_used),
            recommended: "<75% — leaves headroom for KV cache growth on local LLMs".into(),
            fix_command: Some("nvidia-smi --query-compute-apps=pid,process_name,used_memory --format=csv".into()),
            requires_admin: false,
        });
        if g.temperature_c > 0 {
            findings.push(Finding {
                id: "gpu.temp",
                category: "gpu",
                severity: if g.temperature_c >= 85 { "warn" }
                          else if g.temperature_c >= 78 { "opportunity" }
                          else { "ok" },
                title: "GPU temperature".into(),
                current: format!("{}°C", g.temperature_c),
                recommended: "<78°C sustained — above that, NVIDIA boost clocks step down (less tokens/sec)".into(),
                fix_command: None,
                requires_admin: false,
            });
        }
    } else {
        findings.push(Finding {
            id: "gpu.nvidia_present",
            category: "gpu",
            severity: "info",
            title: "NVIDIA GPU".into(),
            current: "nvidia-smi not found or no NVIDIA GPU detected".into(),
            recommended: "for local LLM inference an NVIDIA GPU with ≥8 GB VRAM unlocks 7B-class models at usable speed".into(),
            fix_command: None,
            requires_admin: false,
        });
    }

    // --- Defender exclusions for dev / AI dirs ------------------------
    let exclusions = run_capture("powershell", &[
        "-NoProfile", "-NonInteractive", "-Command",
        "(Get-MpPreference).ExclusionPath -join \";\"",
    ]).await.unwrap_or_default();
    let excl_lower: Vec<String> = exclusions
        .split(';')
        .map(|s| s.trim().to_ascii_lowercase())
        .filter(|s| !s.is_empty())
        .collect();

    let home = std::env::var("USERPROFILE").unwrap_or_default();
    let mut candidates: Vec<(String, &'static str)> = Vec::new();
    let push = |v: &mut Vec<(String, &'static str)>, p: PathBuf, why: &'static str| {
        if p.exists() { v.push((p.to_string_lossy().to_string(), why)); }
    };
    let homep = PathBuf::from(&home);
    push(&mut candidates, homep.join(".cargo"),                        "Rust build cache");
    push(&mut candidates, homep.join(".rustup"),                       "Rust toolchains");
    push(&mut candidates, homep.join("AppData\\Local\\pnpm"),         "pnpm store");
    push(&mut candidates, homep.join("AppData\\Roaming\\npm-cache"),  "npm cache");
    push(&mut candidates, homep.join(".cache\\huggingface"),          "Hugging Face model cache");
    push(&mut candidates, homep.join(".cache\\torch"),                "PyTorch hub cache");
    push(&mut candidates, homep.join("AppData\\Local\\ollama"),       "Ollama model store");
    push(&mut candidates, homep.join("AppData\\Local\\nv"),           "NVIDIA shader cache");
    push(&mut candidates, homep.join("bastion"),                       "Bastion repo (cargo target)");
    push(&mut candidates, homep.join("coachkit-app"),                  "Coachkit repo (.next + node_modules)");
    push(&mut candidates, homep.join("faraday-app"),                   "Faraday repo (.next + node_modules)");
    push(&mut candidates, homep.join("clasp"),                          "Clasp repo (.next)");

    let missing: Vec<(String, &'static str)> = candidates.into_iter()
        .filter(|(p, _)| !excl_lower.iter().any(|e| {
            // Defender stores trailing-slash inconsistently; normalize.
            let pl = p.to_ascii_lowercase();
            e == &pl || e == &format!("{pl}\\") || pl.starts_with(&format!("{e}\\"))
        }))
        .collect();

    if missing.is_empty() {
        findings.push(Finding {
            id: "defender.exclusions",
            category: "defender",
            severity: "ok",
            title: "Defender real-time exclusions".into(),
            current: format!("{} dev paths covered", excl_lower.len()),
            recommended: "covered".into(),
            fix_command: None,
            requires_admin: false,
        });
    } else {
        let preview = missing.iter().take(4)
            .map(|(p, why)| format!("{p} ({why})"))
            .collect::<Vec<_>>().join("; ");
        let cmd = missing.iter()
            .map(|(p, _)| format!("Add-MpPreference -ExclusionPath \"{p}\""))
            .collect::<Vec<_>>().join("; ");
        findings.push(Finding {
            id: "defender.exclusions",
            category: "defender",
            severity: if missing.len() >= 4 { "warn" } else { "opportunity" },
            title: "Defender real-time scan slows dev/AI workloads".into(),
            current: format!("{} unexcluded dev paths: {}", missing.len(), preview),
            recommended: "exclude build/model caches — biggest single speedup for cargo, npm, pip, HF downloads".into(),
            fix_command: Some(format!("# Run elevated:\n{cmd}")),
            requires_admin: true,
        });
    }

    // --- WSL .wslconfig memory cap ------------------------------------
    let wslconfig = homep.join(".wslconfig");
    let wsl_present = run_capture("wsl", &["--status"]).await
        .map(|s| !s.trim().is_empty() && !s.to_lowercase().contains("not found"))
        .unwrap_or(false);
    if wsl_present {
        let cfg_text = std::fs::read_to_string(&wslconfig).unwrap_or_default();
        let has_mem_cap = cfg_text.lines().any(|l| l.trim().to_lowercase().starts_with("memory="));
        findings.push(Finding {
            id: "wsl.memory_cap",
            category: "wsl",
            severity: if has_mem_cap { "ok" } else { "opportunity" },
            title: "WSL2 memory cap (.wslconfig)".into(),
            current: if cfg_text.is_empty() { "no .wslconfig".into() }
                     else if has_mem_cap { "memory= set".into() }
                     else { ".wslconfig exists but no memory= line".into() },
            recommended: format!("cap WSL2 at ~{}GB so it can't steal RAM from your AI workload", (mem_total_gb * 0.5).round() as u64),
            fix_command: Some(format!(
                "@\"\n[wsl2]\nmemory={}GB\nprocessors={}\nswap=0\n\"@ | Out-File -Encoding ASCII $env:USERPROFILE\\.wslconfig",
                (mem_total_gb * 0.5).round() as u64,
                (host.cpu_cores_logical / 2).max(2)
            )),
            requires_admin: false,
        });
    }

    // --- aggregate severity-based summary -----------------------------
    let mut severity_counts: HashMap<&str, u32> = HashMap::new();
    for f in &findings {
        *severity_counts.entry(f.severity).or_insert(0) += 1;
    }
    tracing::info!(
        "perf audit: {} findings ({} critical, {} warn, {} opportunity, {} ok)",
        findings.len(),
        severity_counts.get("critical").unwrap_or(&0),
        severity_counts.get("warn").unwrap_or(&0),
        severity_counts.get("opportunity").unwrap_or(&0),
        severity_counts.get("ok").unwrap_or(&0),
    );

    Ok(PerfAudit {
        elapsed_ms: started.elapsed().as_millis(),
        host,
        findings,
        gpu,
        top_cpu,
        top_mem,
    })
}

async fn run_capture(cmd: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(cmd).args(args).output().await?;
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

async fn nvidia_smi() -> Option<GpuInfo> {
    let out = Command::new("nvidia-smi")
        .args([
            "--query-gpu=name,driver_version,memory.total,memory.used,memory.free,utilization.gpu,temperature.gpu",
            "--format=csv,noheader,nounits",
        ])
        .output().await.ok()?;
    if !out.status.success() { return None; }
    let line = String::from_utf8_lossy(&out.stdout).lines().next()?.to_string();
    let parts: Vec<&str> = line.split(',').map(|s| s.trim()).collect();
    if parts.len() < 7 { return None; }
    Some(GpuInfo {
        name: parts[0].to_string(),
        driver_version: parts[1].to_string(),
        vram_total_mb: parts[2].parse().unwrap_or(0),
        vram_used_mb: parts[3].parse().unwrap_or(0),
        vram_free_mb: parts[4].parse().unwrap_or(0),
        utilization_pct: parts[5].parse().unwrap_or(0),
        temperature_c: parts[6].parse().unwrap_or(0),
    })
}

/// Execute one of the audit's `fix_command` strings.
///
/// IMPORTANT: the caller MUST first verify `fix_command` exists in a freshly
/// produced `audit()` result before calling this — that membership check is
/// the security boundary that prevents arbitrary command execution. This
/// function trusts its input.
///
/// When `requires_admin` is true the user's script is written to a temp
/// .ps1 and a wrapper .ps1 invokes it, capturing stdout/stderr to temp
/// files plus the real exit code. The wrapper is launched via
/// `Start-Process -Verb RunAs -Wait -WindowStyle Hidden` so the agent
/// blocks on the elevated child, then reads the captured output back so
/// the dashboard can display the actual result. If the user declines UAC
/// the launcher fails fast and we report it.
pub async fn apply_fix(fix_command: &str, requires_admin: bool) -> Result<ApplyOutcome> {
    if requires_admin {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let tmpdir = std::env::temp_dir();
        let user_script = tmpdir.join(format!("bastion-fix-{nonce}.ps1"));
        let wrapper_script = tmpdir.join(format!("bastion-fix-{nonce}-wrap.ps1"));
        let out_file = tmpdir.join(format!("bastion-fix-{nonce}.out"));
        let err_file = tmpdir.join(format!("bastion-fix-{nonce}.err"));
        let exit_file = tmpdir.join(format!("bastion-fix-{nonce}.exit"));

        std::fs::write(&user_script, fix_command)?;

        // PowerShell single-quoted strings need '' to escape a literal '.
        let q = |p: &std::path::Path| p.to_string_lossy().replace('\'', "''");
        let user_q = q(&user_script);
        let out_q = q(&out_file);
        let err_q = q(&err_file);
        let exit_q = q(&exit_file);

        // Wrapper: invoke the user script, capture all streams, write
        // stdout/stderr/exit to dedicated files. Always exits 0 itself
        // so the launcher's exit code reflects ShellExecute, not the
        // user fix's return code (we read the real one from $exit_q).
        let wrapper = format!(
            "$ErrorActionPreference = 'Continue'\r\n\
             $stdout = ''\r\n\
             $stderr = ''\r\n\
             $code = 0\r\n\
             try {{\r\n\
                 $stdout = (& '{user_q}' 2>&1 | Out-String)\r\n\
                 if ($null -ne $LASTEXITCODE) {{ $code = $LASTEXITCODE }}\r\n\
             }} catch {{\r\n\
                 $stderr = ($_ | Out-String)\r\n\
                 $code = 1\r\n\
             }}\r\n\
             [System.IO.File]::WriteAllText('{out_q}', $stdout)\r\n\
             [System.IO.File]::WriteAllText('{err_q}', $stderr)\r\n\
             [System.IO.File]::WriteAllText('{exit_q}', $code.ToString())\r\n"
        );
        std::fs::write(&wrapper_script, wrapper)?;

        let wrap_q = q(&wrapper_script);
        // Launcher: non-elevated PS that fires UAC and waits for the
        // elevated child to exit. Hidden window so the user sees only
        // the UAC prompt, not a stray console flash.
        let launcher = format!(
            "$p = Start-Process powershell -Verb RunAs -PassThru -Wait -WindowStyle Hidden \
             -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-File','{wrap_q}'); \
             if ($p) {{ exit $p.ExitCode }} else {{ exit 1 }}"
        );
        let launcher_out = Command::new("powershell")
            .args(["-NoProfile", "-WindowStyle", "Hidden", "-Command", &launcher])
            .output().await?;

        let launcher_ok = launcher_out.status.success();
        let launcher_stderr = String::from_utf8_lossy(&launcher_out.stderr).into_owned();

        // Try to read captured output regardless — if the elevated child
        // got far enough to write any of these, we want to surface them.
        let stdout_s = std::fs::read_to_string(&out_file).unwrap_or_default();
        let stderr_s = std::fs::read_to_string(&err_file).unwrap_or_default();
        let exit_s = std::fs::read_to_string(&exit_file).ok();
        let real_exit = exit_s.as_deref().and_then(|s| s.trim().parse::<i32>().ok());

        // Best-effort cleanup.
        let _ = std::fs::remove_file(&user_script);
        let _ = std::fs::remove_file(&wrapper_script);
        let _ = std::fs::remove_file(&out_file);
        let _ = std::fs::remove_file(&err_file);
        let _ = std::fs::remove_file(&exit_file);

        if real_exit.is_some() {
            // Wrapper ran end-to-end — trust its captured exit code.
            let code = real_exit.unwrap();
            let ok = code == 0;
            Ok(ApplyOutcome {
                launched_elevated: true,
                ok,
                exit_code: Some(code),
                stdout: stdout_s,
                stderr: stderr_s,
                message: if ok { "fix applied".into() } else { format!("fix returned non-zero exit code {code}") },
            })
        } else {
            // Wrapper never wrote the exit file — UAC declined or the
            // elevated process couldn't start.
            let msg = if launcher_ok {
                "elevated process started but did not complete (no output captured)".to_string()
            } else {
                "UAC declined or failed to launch elevated PowerShell".to_string()
            };
            Ok(ApplyOutcome {
                launched_elevated: true,
                ok: false,
                exit_code: launcher_out.status.code(),
                stdout: stdout_s,
                stderr: if stderr_s.is_empty() { launcher_stderr } else { stderr_s },
                message: msg,
            })
        }
    } else {
        let out = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", fix_command])
            .output().await?;
        Ok(ApplyOutcome {
            launched_elevated: false,
            ok: out.status.success(),
            exit_code: out.status.code(),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
            message: "executed".into(),
        })
    }
}
