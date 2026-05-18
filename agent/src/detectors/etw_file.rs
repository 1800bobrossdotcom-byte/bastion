// ETW Microsoft-Windows-Kernel-File real-time file-open consumer.
// ----------------------------------------------------------------------------
// This is Path A of the real-time scan story (see roadmap on bastion.quest).
//
// What it does: subscribes to the kernel ETW provider that emits an event for
// every IRP_MJ_CREATE — i.e. every file open across the system. On each event
// we resolve the NT-namespace path to a regular DOS path and hand it to
// `scan_engine::scan_path`, the same chokepoint `scan_on_write` uses.
//
// Why this is bigger than scan_on_write:
//   * scan_on_write only covers Downloads/Desktop/Documents via notify.
//   * ETW kernel-file fires before the write completes on ANY volume,
//     including process-spawned drops anywhere on disk.
//
// Why this requires admin:
//   * Starting an ETW trace session needs SeSystemProfilePrivilege. Bastion
//     installed as a normal user does NOT have this — we detect that and
//     emit an informational event explaining how to enable it (run elevated
//     or install Bastion as a LocalSystem service). No crash, no retry loop.
//
// Path B (kernel-mode minifilter) will replace this with the same scan engine
// being called from a signed driver — no rewrite of `scan_engine.rs` needed,
// just a new caller. That's the whole reason `scan_engine` exists.

#![cfg(windows)]

use crate::scan_engine;
use crate::store::{now_event, Store};
use ferrisetw::parser::Parser;
use ferrisetw::provider::Provider;
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::UserTrace;
use ferrisetw::EventRecord;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::mpsc;

// Microsoft-Windows-Kernel-File provider GUID.
const KERNEL_FILE_GUID: &str = "EDD08927-9CC4-4E65-B970-C2560FB5C289";
// Event ID 12 = Create (manifest-based "KERNEL_FILE_TASK_CREATE").
const EVT_CREATE: u16 = 12;

pub async fn run(store: Arc<Store>) {
    if !is_elevated() {
        let _ = store.insert_event(&now_event(
            "etw_file",
            "info",
            "etw_unavailable",
            "ETW real-time file telemetry not started — agent is not elevated.".into(),
            serde_json::json!({
                "reason": "needs_admin",
                "fix": "run Bastion as Administrator, or install as a service running LocalSystem",
                "fallback": "drop-dir scanner (scan_on_write) remains active",
            }),
        ));
        return;
    }

    // Channel: ETW callback thread (sync) -> tokio worker tasks.
    let (tx, mut rx) = mpsc::unbounded_channel::<PathBuf>();

    let provider = Provider::by_guid(KERNEL_FILE_GUID)
        .add_callback(move |record: &EventRecord, schema_locator: &SchemaLocator| {
            if record.event_id() != EVT_CREATE {
                return;
            }
            let Ok(schema) = schema_locator.event_schema(record) else { return; };
            let parser = Parser::create(record, &schema);
            let Ok(name) = parser.try_parse::<String>("FileName") else { return; };
            if let Some(dos) = nt_path_to_dos(&name) {
                let _ = tx.send(dos);
            }
        })
        .build();

    // start_and_process spawns the consumer thread internally.
    let trace = match UserTrace::new()
        .named("Bastion-Kernel-File".to_string())
        .enable(provider)
        .start_and_process()
    {
        Ok(t) => t,
        Err(e) => {
            let _ = store.insert_event(&now_event(
                "etw_file",
                "warn",
                "etw_start_failed",
                format!("ETW trace failed to start: {e:?}"),
                serde_json::json!({ "error": format!("{e:?}") }),
            ));
            return;
        }
    };

    let _ = store.insert_event(&now_event(
        "etw_file",
        "info",
        "etw_started",
        "ETW real-time file telemetry armed (system-wide on-access scan).".into(),
        serde_json::json!({ "provider": "Microsoft-Windows-Kernel-File" }),
    ));

    // Keep the trace alive for the lifetime of this task.
    let _keep_alive = trace;

    while let Some(path) = rx.recv().await {
        let store_c = store.clone();
        tokio::task::spawn_blocking(move || {
            let _ = scan_engine::scan_path(&store_c, &path, "etw_file");
        });
    }
}

fn is_elevated() -> bool {
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

    unsafe {
        let mut token = Default::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elev = TOKEN_ELEVATION::default();
        let mut sz = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elev as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut sz,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elev.TokenIsElevated != 0
    }
}

/// Convert an NT-namespace path (\Device\HarddiskVolumeN\Users\...) into a
/// DOS path (C:\Users\...). Returns None if no drive letter maps. Already-DOS
/// paths pass through unchanged.
fn nt_path_to_dos(nt: &str) -> Option<PathBuf> {
    use windows::core::PCWSTR;
    use windows::Win32::Storage::FileSystem::QueryDosDeviceW;

    if !nt.starts_with(r"\Device\") {
        return Some(PathBuf::from(nt));
    }

    for letter in b'A'..=b'Z' {
        let drv: Vec<u16> = format!("{}:", letter as char)
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut target = vec![0u16; 1024];
        let n = unsafe { QueryDosDeviceW(PCWSTR(drv.as_ptr()), Some(&mut target)) };
        if n == 0 {
            continue;
        }
        let end = target.iter().position(|&c| c == 0).unwrap_or(target.len());
        let target_s = String::from_utf16_lossy(&target[..end]);
        if let Some(rest) = nt.strip_prefix(target_s.as_str()) {
            return Some(PathBuf::from(format!("{}:{}", letter as char, rest)));
        }
    }
    None
}
