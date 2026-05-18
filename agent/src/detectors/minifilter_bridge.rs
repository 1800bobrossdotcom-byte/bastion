// User-mode bridge for the BastionFilter kernel minifilter (Path B).
// ----------------------------------------------------------------------------
// Opens the filter communication port `\BastionPort` exposed by
// BastionFilter.sys and runs a GetMessage / ReplyMessage loop. For each
// IRP_MJ_CREATE the driver shipped up, we:
//
//   1. Convert the NT-namespace path to DOS form (same helper as etw_file).
//   2. Call `scan_engine::scan_path(..., "minifilter")`.
//   3. If it quarantined the file, reply BLOCK. Otherwise reply ALLOW.
//
// Driver fails open after 2 s if we don't reply, so a hang here never wedges
// the filesystem — worst case is a few opens slip through.
//
// If the driver isn't installed, `FilterConnectCommunicationPort` returns
// ERROR_FILE_NOT_FOUND. We emit one `minifilter_unavailable` info event and
// exit the task — no retry storm.

#![cfg(windows)]

use crate::scan_engine;
use crate::store::{now_event, Store};
use std::path::PathBuf;
use std::sync::Arc;

// Mirror of BASTION_NOTIFY / BASTION_REPLY from driver/BastionFilter.h.
// Keep these in sync.
const BASTION_MAX_PATH_WCHARS: usize = 1024;

#[repr(C)]
#[derive(Copy, Clone)]
struct BastionNotify {
    process_id: u32,
    path_bytes: u32,
    path_buffer: [u16; BASTION_MAX_PATH_WCHARS],
}

#[repr(C)]
#[derive(Copy, Clone)]
struct BastionReply {
    verdict: u32,
}

const VERDICT_ALLOW: u32 = 0;
const VERDICT_BLOCK: u32 = 1;

pub async fn run(store: Arc<Store>) {
    // The driver-control APIs (FilterConnectCommunicationPort,
    // FilterGetMessage, FilterReplyMessage) live in fltlib.dll — they aren't
    // part of the base windows-rs feature set. Until we add the
    // `Win32_Storage_InstallableFileSystems` feature + link fltlib, the
    // bridge stays a scaffold that announces itself and exits cleanly.

    let _ = store.insert_event(&now_event(
        "minifilter_bridge",
        "info",
        "minifilter_bridge_scaffold",
        "Kernel minifilter bridge present but inactive — driver not yet signed/loaded.".into(),
        serde_json::json!({
            "status": "scaffold",
            "next_steps": [
                "build BastionFilter.sys with WDK",
                "test-sign for dev (bcdedit /set testsigning on)",
                "load with `sc start BastionFilter`",
                "add Win32_Storage_InstallableFileSystems to windows crate features",
                "wire FilterConnectCommunicationPort / FilterGetMessage loop",
            ],
        }),
    ));

    // Sketch of the eventual loop, kept as commented pseudo-code so the next
    // hands-on session has a starting point:
    //
    //   let h = FilterConnectCommunicationPort(L"\\BastionPort", ...)?;
    //   loop {
    //       let mut msg: FILTER_MESSAGE_HEADER + BastionNotify;
    //       FilterGetMessage(h, &mut msg, sizeof(msg), null)?;
    //       let path = nt_path_to_dos(utf16_to_string(&msg.path_buffer[..n]))?;
    //       let blocked = scan_engine::scan_path(&store, &path, "minifilter")?;
    //       let reply = BastionReply { verdict: if blocked { VERDICT_BLOCK } else { VERDICT_ALLOW } };
    //       FilterReplyMessage(h, &msg.header.message_id, &reply, sizeof(reply))?;
    //   }

    // Reference unused items so the compiler doesn't warn while the bridge
    // is a scaffold.
    let _ = (
        std::mem::size_of::<BastionNotify>(),
        std::mem::size_of::<BastionReply>(),
        VERDICT_ALLOW,
        VERDICT_BLOCK,
        PathBuf::new(),
        scan_engine::looks_skippable,
    );
}
