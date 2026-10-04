// Junk / debris cleanup.
//
// Each category is a fixed, agent-defined set of directories (resolved from
// environment variables at scan time). The clean endpoint accepts category
// *ids* only and re-resolves the paths itself, so a client can never point
// the deleter at an arbitrary directory.
//
// Safety rules applied to every file category:
//   * only the *contents* of a root are deleted, never the root itself
//   * symlinks / junctions are skipped and never descended into
//   * files modified within `min_age_hours` are left alone (in-use temp
//     files from running installers, open browser sessions, etc.)
//   * locked / permission-denied files are counted as `failed`, not errors

use crate::detectors::perf::ApplyOutcome;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};
use walkdir::WalkDir;

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    /// Plain file deletion under the category's roots.
    Files,
    /// Emptied with Clear-RecycleBin so Explorer's view stays consistent.
    RecycleBin,
    /// Sized and reported, but removal is left to Windows' own tooling.
    ReportOnly,
}

#[derive(Debug, Clone)]
struct Target {
    dir: PathBuf,
    /// When set, only files directly in `dir` whose name starts with this
    /// prefix (case-insensitive) are considered.
    file_prefix: Option<&'static str>,
}

#[derive(Debug, Clone)]
struct CategoryDef {
    id: &'static str,
    title: &'static str,
    description: &'static str,
    kind: Kind,
    requires_admin: bool,
    /// Pre-ticked in the dashboard / used by `clean` with no ids.
    default_selected: bool,
    min_age_hours: u64,
    targets: Vec<Target>,
}

#[derive(Debug, Serialize)]
pub struct JunkCategory {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub kind: Kind,
    pub requires_admin: bool,
    pub default_selected: bool,
    pub min_age_hours: u64,
    pub paths: Vec<String>,
    /// Reclaimable (old enough) files / bytes.
    pub files: u64,
    pub bytes: u64,
    /// Files present but too recent to touch.
    pub recent_files: u64,
    pub recent_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct JunkScan {
    pub elapsed_ms: u128,
    /// Sum of reclaimable bytes across cleanable categories.
    pub total_bytes: u64,
    pub total_gb: f64,
    pub categories: Vec<JunkCategory>,
}

#[derive(Debug, Deserialize)]
pub struct CleanRequest {
    /// Category ids to clean. Empty = every `default_selected` category.
    #[serde(default)]
    pub ids: Vec<String>,
    /// Count what would be removed without deleting anything.
    #[serde(default)]
    pub dry_run: bool,
}

#[derive(Debug, Serialize)]
pub struct CleanResult {
    pub id: String,
    pub ok: bool,
    /// native | elevated | recycle_bin | skipped
    pub method: &'static str,
    pub deleted_files: u64,
    pub freed_bytes: u64,
    pub failed_files: u64,
    pub message: String,
}

#[derive(Debug, Serialize)]
pub struct CleanReport {
    pub dry_run: bool,
    pub elapsed_ms: u128,
    pub freed_bytes: u64,
    pub freed_gb: f64,
    pub results: Vec<CleanResult>,
}

// ---------------------------------------------------------------------------
// category definitions

fn env_path(var: &str) -> Option<PathBuf> {
    std::env::var_os(var).filter(|v| !v.is_empty()).map(PathBuf::from)
}

fn dir(p: PathBuf) -> Target {
    Target { dir: p, file_prefix: None }
}

/// Chromium keeps one folder per profile ("Default", "Profile 1", ...)
/// under `User Data`; each has its own caches.
fn chromium_caches(user_data: &Path) -> Vec<Target> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(user_data) else { return out };
    for e in rd.flatten() {
        let p = e.path();
        if !p.is_dir() { continue; }
        for sub in ["Cache", "Code Cache", "GPUCache", "Service Worker\\CacheStorage"] {
            let c = p.join(sub);
            if c.is_dir() { out.push(dir(c)); }
        }
    }
    for sub in ["ShaderCache", "GrShaderCache"] {
        let c = user_data.join(sub);
        if c.is_dir() { out.push(dir(c)); }
    }
    out
}

fn firefox_caches(profiles: &Path) -> Vec<Target> {
    let Ok(rd) = std::fs::read_dir(profiles) else { return Vec::new() };
    rd.flatten()
        .map(|e| e.path().join("cache2"))
        .filter(|p| p.is_dir())
        .map(dir)
        .collect()
}

fn categories() -> Vec<CategoryDef> {
    let mut v = Vec::new();
    let local = env_path("LOCALAPPDATA");
    let roaming = env_path("APPDATA");
    let windir = env_path("SystemRoot").or_else(|| env_path("WINDIR"));
    let progdata = env_path("ProgramData");
    let home = env_path("USERPROFILE");

    let mut add = |id, title, description, kind, requires_admin, default_selected, min_age_hours, targets: Vec<Target>| {
        let targets: Vec<Target> = targets.into_iter().filter(|t| is_safe_root(&t.dir) && t.dir.is_dir()).collect();
        if !targets.is_empty() {
            v.push(CategoryDef { id, title, description, kind, requires_admin, default_selected, min_age_hours, targets });
        }
    };

    // %TEMP% is user-controlled; only trust it if it actually looks like a temp dir.
    let temp = env_path("TEMP").filter(|t| {
        t.file_name().map(|n| n.to_string_lossy().to_ascii_lowercase()).is_some_and(|n| n.contains("temp") || n.contains("tmp"))
    });
    if let Some(t) = temp.or_else(|| local.as_ref().map(|l| l.join("Temp"))) {
        add("user_temp", "User temp files",
            "Leftovers from installers, updaters and apps in your %TEMP% folder.",
            Kind::Files, false, true, 24, vec![dir(t)]);
    }
    if let Some(w) = &windir {
        add("windows_temp", "Windows temp files",
            "System-wide temp folder (C:\\Windows\\Temp).",
            Kind::Files, true, true, 24, vec![dir(w.join("Temp"))]);
        add("windows_update_cache", "Windows Update download cache",
            "Already-installed update payloads. Windows re-downloads anything it still needs.",
            Kind::Files, true, true, 72, vec![dir(w.join("SoftwareDistribution\\Download"))]);
        add("delivery_optimization", "Delivery Optimization cache",
            "Update chunks cached for peer-to-peer sharing with other PCs.",
            Kind::Files, true, true, 72,
            vec![dir(w.join("ServiceProfiles\\NetworkService\\AppData\\Local\\Microsoft\\Windows\\DeliveryOptimization\\Cache"))]);
        add("system_crash_dumps", "System crash dumps",
            "Blue-screen minidumps. Keep them if you are still diagnosing a crash.",
            Kind::Files, true, true, 72, vec![dir(w.join("Minidump")), dir(w.join("LiveKernelReports"))]);
        add("windows_logs", "Old Windows setup / servicing logs",
            "CBS and DISM logs older than a week.",
            Kind::Files, true, false, 24 * 7, vec![dir(w.join("Logs\\CBS")), dir(w.join("Logs\\DISM"))]);
    }
    if let Some(l) = &local {
        add("user_crash_dumps", "App crash dumps",
            "Memory dumps written when applications crash.",
            Kind::Files, false, true, 24, vec![dir(l.join("CrashDumps"))]);
        add("thumbnail_cache", "Thumbnail cache",
            "Explorer thumbnail database. Rebuilt automatically as you browse folders.",
            Kind::Files, false, false, 0,
            vec![Target { dir: l.join("Microsoft\\Windows\\Explorer"), file_prefix: Some("thumbcache_") }]);
        let mut browser = Vec::new();
        browser.extend(chromium_caches(&l.join("Google\\Chrome\\User Data")));
        browser.extend(chromium_caches(&l.join("Microsoft\\Edge\\User Data")));
        browser.extend(chromium_caches(&l.join("BraveSoftware\\Brave-Browser\\User Data")));
        browser.extend(chromium_caches(&l.join("Vivaldi\\User Data")));
        browser.extend(firefox_caches(&l.join("Mozilla\\Firefox\\Profiles")));
        add("browser_cache", "Browser caches",
            "Chrome / Edge / Brave / Vivaldi / Firefox page, code and GPU caches. Logins, history and bookmarks are untouched. Close browsers first for best results.",
            Kind::Files, false, true, 0, browser);
        add("shader_cache", "GPU shader caches",
            "DirectX / NVIDIA / AMD compiled shaders. Games may stutter briefly while they rebuild.",
            Kind::Files, false, false, 0,
            vec![dir(l.join("D3DSCache")), dir(l.join("NVIDIA\\DXCache")), dir(l.join("NVIDIA\\GLCache")), dir(l.join("AMD\\DxCache")), dir(l.join("AMD\\DxcCache"))]);
        add("dev_caches", "Developer package caches",
            "npm, pip, Yarn, NuGet and Go download caches. Safe, but the next install re-downloads packages.",
            Kind::Files, false, false, 24,
            vec![dir(l.join("npm-cache")), dir(l.join("pip\\Cache")), dir(l.join("Yarn\\Cache")),
                 dir(l.join("NuGet\\v3-cache")), dir(l.join("go-build"))]
                .into_iter()
                .chain(roaming.as_ref().map(|r| dir(r.join("npm-cache"))))
                .chain(home.as_ref().map(|h| dir(h.join(".cargo\\registry\\cache"))))
                .collect());
    }
    let mut wer = Vec::new();
    if let Some(l) = &local {
        wer.push(dir(l.join("Microsoft\\Windows\\WER\\ReportArchive")));
        wer.push(dir(l.join("Microsoft\\Windows\\WER\\ReportQueue")));
    }
    add("user_error_reports", "Windows Error Reporting (user)",
        "Queued and archived crash reports for your account.",
        Kind::Files, false, true, 24, wer);
    if let Some(p) = &progdata {
        add("system_error_reports", "Windows Error Reporting (system)",
            "Queued and archived crash reports for system components.",
            Kind::Files, true, true, 24,
            vec![dir(p.join("Microsoft\\Windows\\WER\\ReportArchive")), dir(p.join("Microsoft\\Windows\\WER\\ReportQueue"))]);
    }

    // Recycle bin: one $Recycle.Bin\<SID> folder per fixed drive.
    if let Some(sid) = current_sid() {
        // Only local disks sysinfo knows about — probing every letter can
        // stall on disconnected network drives.
        let bins: Vec<Target> = sysinfo::Disks::new_with_refreshed_list()
            .iter()
            .filter(|d| !d.is_removable())
            .map(|d| dir(d.mount_point().join("$Recycle.Bin").join(&sid)))
            .collect();
        add("recycle_bin", "Recycle Bin",
            "Files you have already deleted. Emptying it is permanent.",
            Kind::RecycleBin, false, false, 0, bins);
    }

    if let Some(w) = &windir {
        let sys_root = w.parent().map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("C:\\"));
        add("windows_old", "Previous Windows installation (Windows.old)",
            "Kept for ~10 days after a feature update so you can roll back. Remove it via Settings > System > Storage > Temporary files once you're happy with the update.",
            Kind::ReportOnly, true, false, 0, vec![dir(sys_root.join("Windows.old"))]);
    }
    v
}

/// Refuse roots that are a drive root, a top-level folder, or one of the
/// well-known profile / system directories themselves — a misconfigured
/// environment variable must never turn into "delete everything in C:\Users\me".
fn is_safe_root(p: &Path) -> bool {
    if !p.is_absolute() || p.components().count() < 3 { return false; }
    let norm = |q: &Path| q.to_string_lossy().trim_end_matches(['\\', '/']).to_ascii_lowercase();
    let pn = norm(p);
    !["USERPROFILE", "LOCALAPPDATA", "APPDATA", "SystemRoot", "WINDIR", "ProgramData", "ProgramFiles", "ProgramFiles(x86)", "HOME"]
        .iter()
        .filter_map(|v| env_path(v))
        .any(|q| norm(&q) == pn)
}

fn current_sid() -> Option<String> {
    if !cfg!(windows) { return None; }
    // `whoami /user /fo csv /nh` -> "host\user","S-1-5-21-..."
    let out = std::process::Command::new("whoami").args(["/user", "/fo", "csv", "/nh"]).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout);
    let sid = s.trim().rsplit(',').next()?.trim_matches('"').to_string();
    sid.starts_with("S-1-").then_some(sid)
}

// ---------------------------------------------------------------------------
// walking

#[derive(Default)]
struct Tally {
    files: u64,
    bytes: u64,
    recent_files: u64,
    recent_bytes: u64,
    failed: u64,
}

fn is_old_enough(meta: &std::fs::Metadata, min_age: Duration) -> bool {
    if min_age.is_zero() { return true; }
    let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
    SystemTime::now().duration_since(modified).map(|age| age >= min_age).unwrap_or(false)
}

/// Walk a target. When `delete` is set, eligible files are removed and empty
/// (old enough) subdirectories are pruned afterwards. The root is never removed.
fn walk_target(t: &Target, min_age: Duration, delete: bool, tally: &mut Tally) {
    let mut walker = WalkDir::new(&t.dir).min_depth(1).follow_links(false);
    if t.file_prefix.is_some() {
        walker = walker.max_depth(1);
    }
    let prefix = t.file_prefix.map(|p| p.to_ascii_lowercase());

    for entry in walker.into_iter().filter_entry(|e| !e.path_is_symlink()).flatten() {
        if !entry.file_type().is_file() { continue; }
        if let Some(p) = &prefix {
            if !entry.file_name().to_string_lossy().to_ascii_lowercase().starts_with(p.as_str()) { continue; }
        }
        let Ok(meta) = entry.metadata() else { continue };
        let len = meta.len();
        if !is_old_enough(&meta, min_age) {
            tally.recent_files += 1;
            tally.recent_bytes += len;
            continue;
        }
        if delete {
            if remove_file_forced(entry.path(), &meta) {
                tally.files += 1;
                tally.bytes += len;
            } else {
                tally.failed += 1;
            }
        } else {
            tally.files += 1;
            tally.bytes += len;
        }
    }

    if delete && t.file_prefix.is_none() {
        // Prune now-empty directories, deepest first. remove_dir fails on
        // non-empty dirs, which is exactly what we want.
        for entry in WalkDir::new(&t.dir).min_depth(1).follow_links(false).contents_first(true)
            .into_iter().filter_entry(|e| !e.path_is_symlink()).flatten()
        {
            if !entry.file_type().is_dir() { continue; }
            if let Ok(meta) = entry.metadata() {
                if is_old_enough(&meta, min_age) {
                    let _ = std::fs::remove_dir(entry.path());
                }
            }
        }
    }
}

fn remove_file_forced(path: &Path, meta: &std::fs::Metadata) -> bool {
    if std::fs::remove_file(path).is_ok() { return true; }
    // Read-only files refuse deletion on Windows; clear the bit and retry.
    let mut perms = meta.permissions();
    if perms.readonly() {
        #[allow(clippy::permissions_set_readonly_false)]
        perms.set_readonly(false);
        if std::fs::set_permissions(path, perms).is_ok() {
            return std::fs::remove_file(path).is_ok();
        }
    }
    false
}

fn measure(def: &CategoryDef) -> JunkCategory {
    let mut tally = Tally::default();
    let min_age = Duration::from_secs(def.min_age_hours * 3600);
    for t in &def.targets {
        walk_target(t, min_age, false, &mut tally);
    }
    JunkCategory {
        id: def.id,
        title: def.title,
        description: def.description,
        kind: def.kind,
        requires_admin: def.requires_admin,
        default_selected: def.default_selected,
        min_age_hours: def.min_age_hours,
        paths: def.targets.iter().map(|t| t.dir.to_string_lossy().into_owned()).collect(),
        files: tally.files,
        bytes: tally.bytes,
        recent_files: tally.recent_files,
        recent_bytes: tally.recent_bytes,
    }
}

// ---------------------------------------------------------------------------
// public API

pub async fn scan() -> JunkScan {
    let started = Instant::now();
    let defs = tokio::task::spawn_blocking(categories).await.unwrap_or_default();
    let handles: Vec<_> = defs
        .into_iter()
        .map(|d| tokio::task::spawn_blocking(move || measure(&d)))
        .collect();
    let mut categories = Vec::new();
    for h in handles {
        if let Ok(c) = h.await { categories.push(c); }
    }
    categories.sort_by(|a, b| b.bytes.cmp(&a.bytes));
    let total_bytes = categories.iter().filter(|c| c.kind != Kind::ReportOnly).map(|c| c.bytes).sum();
    tracing::info!("junk scan: {:.2} GB reclaimable across {} categories", super::gb(total_bytes), categories.len());
    JunkScan {
        elapsed_ms: started.elapsed().as_millis(),
        total_bytes,
        total_gb: super::gb(total_bytes),
        categories,
    }
}

pub async fn clean(req: &CleanRequest) -> CleanReport {
    let started = Instant::now();
    let defs = tokio::task::spawn_blocking(categories).await.unwrap_or_default();
    let selected: Vec<CategoryDef> = if req.ids.is_empty() {
        defs.iter().filter(|d| d.default_selected).cloned().collect()
    } else {
        defs.iter().filter(|d| req.ids.iter().any(|id| id == d.id)).cloned().collect()
    };

    let mut results = Vec::new();
    for id in &req.ids {
        if !defs.iter().any(|d| d.id == id) {
            results.push(CleanResult {
                id: id.clone(), ok: false, method: "skipped", deleted_files: 0, freed_bytes: 0, failed_files: 0,
                message: "unknown category or nothing to clean on this machine".into(),
            });
        }
    }

    let elevated = if selected.iter().any(|d| d.requires_admin) { super::is_elevated().await } else { false };
    let browsers = if selected.iter().any(|d| d.id == "browser_cache") { running_browsers() } else { Vec::new() };

    // Admin categories are batched into one script so the user sees a
    // single UAC prompt, not one per category.
    let needs_uac: Vec<CategoryDef> = if req.dry_run || elevated {
        Vec::new()
    } else {
        selected.iter().filter(|d| d.kind == Kind::Files && d.requires_admin).cloned().collect()
    };
    if !needs_uac.is_empty() {
        results.extend(clean_elevated(&needs_uac).await);
    }

    for def in selected {
        if needs_uac.iter().any(|d| d.id == def.id) { continue; }
        let r = match def.kind {
            Kind::ReportOnly => CleanResult {
                id: def.id.into(), ok: false, method: "skipped", deleted_files: 0, freed_bytes: 0, failed_files: 0,
                message: "report-only: remove via Settings > System > Storage > Temporary files".into(),
            },
            _ if req.dry_run => {
                let m = tokio::task::spawn_blocking({ let d = def.clone(); move || measure(&d) }).await;
                let (files, bytes) = m.map(|m| (m.files, m.bytes)).unwrap_or((0, 0));
                CleanResult {
                    id: def.id.into(), ok: true, method: "dry_run", deleted_files: files, freed_bytes: bytes, failed_files: 0,
                    message: format!("would remove {files} files ({:.2} GB)", super::gb(bytes)),
                }
            }
            Kind::RecycleBin => empty_recycle_bin(&def).await,
            Kind::Files if def.id == "browser_cache" && !browsers.is_empty() => CleanResult {
                id: def.id.into(), ok: false, method: "skipped", deleted_files: 0, freed_bytes: 0, failed_files: 0,
                message: format!("close {} first — clearing a live browser's cache can corrupt it", browsers.join(", ")),
            },
            Kind::Files => clean_native(def).await,
        };
        results.push(r);
    }

    let freed_bytes = results.iter().map(|r| r.freed_bytes).sum();
    CleanReport {
        dry_run: req.dry_run,
        elapsed_ms: started.elapsed().as_millis(),
        freed_bytes,
        freed_gb: super::gb(freed_bytes),
        results,
    }
}

async fn clean_native(def: CategoryDef) -> CleanResult {
    let id = def.id;
    let res = tokio::task::spawn_blocking(move || {
        let mut tally = Tally::default();
        let min_age = Duration::from_secs(def.min_age_hours * 3600);
        for t in &def.targets {
            walk_target(t, min_age, true, &mut tally);
        }
        tally
    })
    .await;
    match res {
        Ok(t) => CleanResult {
            id: id.into(),
            ok: true,
            method: "native",
            deleted_files: t.files,
            freed_bytes: t.bytes,
            failed_files: t.failed,
            message: if t.failed > 0 {
                format!("{} files were in use or locked and were left in place", t.failed)
            } else {
                "cleaned".into()
            },
        },
        Err(e) => CleanResult {
            id: id.into(), ok: false, method: "native", deleted_files: 0, freed_bytes: 0, failed_files: 0,
            message: format!("cleanup task failed: {e}"),
        },
    }
}

fn running_browsers() -> Vec<String> {
    let sys = sysinfo::System::new_with_specifics(
        sysinfo::RefreshKind::new().with_processes(sysinfo::ProcessRefreshKind::new()),
    );
    let mut found: Vec<String> = sys
        .processes()
        .values()
        .filter_map(|p| {
            let n = p.name().to_ascii_lowercase();
            ["chrome.exe", "msedge.exe", "brave.exe", "vivaldi.exe", "firefox.exe"]
                .contains(&n.as_str())
                .then(|| n.trim_end_matches(".exe").to_string())
        })
        .collect();
    found.sort();
    found.dedup();
    found
}

/// Build the PowerShell equivalent of `walk_target(delete=true)` for admin
/// categories. Paths come only from `categories()`, never from the client.
/// Directories are pruned with Directory.Delete(non-recursive), which throws
/// on non-empty dirs — Remove-Item would instead block on a confirm prompt.
/// Emits one `id=<id> freed=<n> deleted=<n> failed=<n>` line per category.
fn elevated_script(defs: &[CategoryDef]) -> String {
    let mut script = String::from(
        "function Clean-Dir($d, $cutoff) {\r\n\
           Get-ChildItem -LiteralPath $d -Force -ErrorAction SilentlyContinue | ForEach-Object {\r\n\
             if ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) { return }\r\n\
             if ($_.PSIsContainer) {\r\n\
               Clean-Dir $_.FullName $cutoff\r\n\
               if ($_.LastWriteTime -lt $cutoff) { try { [IO.Directory]::Delete($_.FullName, $false) } catch { } }\r\n\
             } elseif ($_.LastWriteTime -lt $cutoff) {\r\n\
               $len = $_.Length\r\n\
               try { Remove-Item -LiteralPath $_.FullName -Force -ErrorAction Stop; $script:freed += $len; $script:n++ } catch { $script:fail++ }\r\n\
             }\r\n\
           }\r\n\
         }\r\n",
    );
    for def in defs {
        let roots = def.targets.iter().map(|t| super::ps_quote(&t.dir.to_string_lossy())).collect::<Vec<_>>().join(",");
        script.push_str(&format!(
            "$script:freed = [int64]0; $script:n = 0; $script:fail = 0\r\n\
             $cutoff = (Get-Date).AddHours(-{age})\r\n\
             foreach ($r in @({roots})) {{ if (Test-Path -LiteralPath $r) {{ Clean-Dir $r $cutoff }} }}\r\n\
             Write-Output \"id={id} freed=$($script:freed) deleted=$($script:n) failed=$($script:fail)\"\r\n",
            roots = roots,
            age = def.min_age_hours,
            id = def.id,
        ));
    }
    script
}

async fn clean_elevated(defs: &[CategoryDef]) -> Vec<CleanResult> {
    let script = elevated_script(defs);
    match crate::detectors::perf::apply_fix(&script, true).await {
        Ok(out) => defs.iter().map(|d| outcome_to_result(d.id, &out)).collect(),
        Err(e) => defs.iter().map(|d| CleanResult {
            id: d.id.into(), ok: false, method: "elevated", deleted_files: 0, freed_bytes: 0, failed_files: 0,
            message: format!("could not launch elevated cleanup: {e}"),
        }).collect(),
    }
}

fn outcome_to_result(id: &str, out: &ApplyOutcome) -> CleanResult {
    let line = out.stdout.lines().find(|l| l.split_whitespace().next() == Some(&format!("id={id}")));
    let field = |k: &str| -> u64 {
        line.unwrap_or("")
            .split_whitespace()
            .find_map(|kv| kv.strip_prefix(k).and_then(|v| v.strip_prefix('=')))
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    };
    let failed = field("failed");
    let ok = out.ok && line.is_some();
    CleanResult {
        id: id.into(),
        ok,
        method: "elevated",
        deleted_files: field("deleted"),
        freed_bytes: field("freed"),
        failed_files: failed,
        message: if !out.ok {
            out.message.clone()
        } else if line.is_none() {
            "elevated cleanup did not report a result for this category".into()
        } else if failed > 0 {
            format!("{failed} files were in use or locked and were left in place")
        } else {
            "cleaned (elevated)".into()
        },
    }
}

async fn empty_recycle_bin(def: &CategoryDef) -> CleanResult {
    let before = tokio::task::spawn_blocking({ let d = def.clone(); move || measure(&d) }).await.ok();
    let out = super::ps(
        "try { Clear-RecycleBin -Force -ErrorAction Stop; 'ok' } catch { 'err: ' + $_.Exception.Message }",
        Duration::from_secs(300),
    )
    .await
    .unwrap_or_default();
    let ok = out.trim() == "ok";
    CleanResult {
        id: def.id.into(),
        ok,
        method: "recycle_bin",
        deleted_files: if ok { before.as_ref().map(|b| b.files).unwrap_or(0) } else { 0 },
        freed_bytes: if ok { before.as_ref().map(|b| b.bytes).unwrap_or(0) } else { 0 },
        failed_files: 0,
        message: if ok { "recycle bin emptied".into() } else { out.trim().to_string() },
    }
}

// ---------------------------------------------------------------------------
// large files (report only)

#[derive(Debug, Serialize)]
pub struct LargeFile {
    pub path: String,
    pub size_mb: u64,
    pub modified_days_ago: Option<u64>,
}

#[derive(Debug, Serialize)]
pub struct LargeFilesReport {
    pub root: String,
    pub min_mb: u64,
    pub files: Vec<LargeFile>,
    pub downloads_bytes: u64,
    pub downloads_old_bytes: u64,
}

/// Biggest files in the user profile (excluding AppData, which the junk
/// categories already cover) plus how much of Downloads is >90 days old.
/// Report only: deciding what to delete here is the user's call.
pub async fn large_files(min_mb: u64, limit: usize) -> LargeFilesReport {
    let home = env_path("USERPROFILE").or_else(|| env_path("HOME")).unwrap_or_default();
    tokio::task::spawn_blocking(move || {
        let min_bytes = min_mb * 1024 * 1024;
        let now = SystemTime::now();
        let age_days = |m: &std::fs::Metadata| {
            m.modified().ok().and_then(|t| now.duration_since(t).ok()).map(|d| d.as_secs() / 86400)
        };
        let mut files: Vec<LargeFile> = WalkDir::new(&home)
            .min_depth(1)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                !e.path_is_symlink()
                    && !(e.depth() == 1 && e.file_name().eq_ignore_ascii_case("AppData"))
                    && !e.file_name().eq_ignore_ascii_case("node_modules")
                    && !e.file_name().eq_ignore_ascii_case(".git")
            })
            .flatten()
            .filter(|e| e.file_type().is_file())
            .filter_map(|e| {
                let m = e.metadata().ok()?;
                (m.len() >= min_bytes).then(|| LargeFile {
                    path: e.path().to_string_lossy().into_owned(),
                    size_mb: m.len() / 1024 / 1024,
                    modified_days_ago: age_days(&m),
                })
            })
            .collect();
        files.sort_by(|a, b| b.size_mb.cmp(&a.size_mb));
        files.truncate(limit);

        let (mut downloads_bytes, mut downloads_old_bytes) = (0u64, 0u64);
        for e in WalkDir::new(home.join("Downloads")).follow_links(false).into_iter()
            .filter_entry(|e| !e.path_is_symlink()).flatten()
        {
            if !e.file_type().is_file() { continue; }
            if let Ok(m) = e.metadata() {
                downloads_bytes += m.len();
                if age_days(&m).unwrap_or(0) > 90 { downloads_old_bytes += m.len(); }
            }
        }

        LargeFilesReport {
            root: home.to_string_lossy().into_owned(),
            min_mb,
            files,
            downloads_bytes,
            downloads_old_bytes,
        }
    })
    .await
    .unwrap_or_else(|_| LargeFilesReport { root: String::new(), min_mb, files: vec![], downloads_bytes: 0, downloads_old_bytes: 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("bastion-junk-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn deletes_contents_but_keeps_root() {
        let root = tmpdir("root");
        std::fs::create_dir_all(root.join("a/b")).unwrap();
        std::fs::write(root.join("x.tmp"), b"12345").unwrap();
        std::fs::write(root.join("a/b/y.tmp"), b"123").unwrap();
        let mut t = Tally::default();
        walk_target(&dir(root.clone()), Duration::ZERO, true, &mut t);
        assert_eq!((t.files, t.bytes, t.failed), (2, 8, 0));
        assert!(root.is_dir());
        assert_eq!(std::fs::read_dir(&root).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn respects_min_age() {
        let root = tmpdir("age");
        std::fs::write(root.join("fresh.tmp"), b"hello").unwrap();
        let mut t = Tally::default();
        walk_target(&dir(root.clone()), Duration::from_secs(3600), true, &mut t);
        assert_eq!((t.files, t.recent_files, t.recent_bytes), (0, 1, 5));
        assert!(root.join("fresh.tmp").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn prefix_filter_is_shallow() {
        let root = tmpdir("prefix");
        std::fs::create_dir_all(root.join("sub")).unwrap();
        std::fs::write(root.join("thumbcache_1.db"), b"1").unwrap();
        std::fs::write(root.join("iconcache.db"), b"1").unwrap();
        std::fs::write(root.join("sub/thumbcache_2.db"), b"1").unwrap();
        let mut t = Tally::default();
        walk_target(&Target { dir: root.clone(), file_prefix: Some("thumbcache_") }, Duration::ZERO, true, &mut t);
        assert_eq!(t.files, 1);
        assert!(root.join("iconcache.db").exists());
        assert!(root.join("sub/thumbcache_2.db").exists());
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn never_follows_symlinks() {
        let root = tmpdir("link");
        let outside = tmpdir("outside");
        std::fs::write(outside.join("keep.txt"), b"precious").unwrap();
        std::os::unix::fs::symlink(&outside, root.join("link")).unwrap();
        let mut t = Tally::default();
        walk_target(&dir(root.clone()), Duration::ZERO, true, &mut t);
        assert!(outside.join("keep.txt").exists());
        let _ = std::fs::remove_dir_all(&root);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn parses_elevated_output() {
        let out = ApplyOutcome {
            launched_elevated: true, ok: true, exit_code: Some(0),
            stdout: "id=windows_temp freed=2048 deleted=3 failed=1\r\nid=windows_update_cache freed=10 deleted=1 failed=0\r\n".into(),
            stderr: String::new(), message: String::new(),
        };
        let r = outcome_to_result("windows_temp", &out);
        assert_eq!((r.freed_bytes, r.deleted_files, r.failed_files, r.ok), (2048, 3, 1, true));
        let r = outcome_to_result("windows_update_cache", &out);
        assert_eq!((r.freed_bytes, r.deleted_files), (10, 1));
        let r = outcome_to_result("system_crash_dumps", &out);
        assert!(!r.ok);
    }

    #[test]
    fn rejects_shallow_roots() {
        assert!(!is_safe_root(Path::new("/")));
        assert!(!is_safe_root(Path::new("relative/dir/here")));
        if let Some(h) = env_path("HOME").or_else(|| env_path("USERPROFILE")) {
            assert!(!is_safe_root(&h));
        }
    }
}
