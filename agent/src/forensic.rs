// Forensic export bundle.
//
// Builds a zip containing:
//   * events.csv         — all events (id,ts,severity,source,kind,summary,details_json)
//   * chain.json         — verify_chain() output
//   * manifest.json      — counts, head hash, generated_at, agent_version
//   * vault/*.json       — quarantine manifests (NOT the .bin payloads — those stay
//                          on disk; user can opt in to including them later)
//
// Saved to <data_dir>/exports/bastion-<utc>.zip and the path returned to
// the caller. We deliberately exclude:
//   * agent_key.dpapi (private key — never leave the box)
//   * token.txt (API bearer)
//   * vault/*.bin (raw quarantined bytes; could re-detonate malware on the
//      analyst's machine if they unzip carelessly)

use crate::store::Store;
use anyhow::{Context, Result};
use chrono::Utc;
use directories::ProjectDirs;
use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use zip::write::SimpleFileOptions;

pub fn export(store: &Arc<Store>) -> Result<PathBuf> {
    let proj = ProjectDirs::from("cam", "bastion", "bastion").context("ProjectDirs")?;
    let data_dir = proj.data_dir().to_path_buf();
    let exports = data_dir.join("exports");
    fs::create_dir_all(&exports)?;

    let stamp = Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
    let zip_path = exports.join(format!("bastion-{}.zip", stamp));
    let f = fs::File::create(&zip_path)?;
    let mut zip = zip::ZipWriter::new(f);
    let opts: SimpleFileOptions = SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);

    // events.csv
    let events = store.recent_events(100_000)?;
    zip.start_file("events.csv", opts)?;
    writeln!(zip, "id,ts,severity,source,kind,summary,details_json")?;
    for e in &events {
        writeln!(
            zip,
            "{},{},{},{},{},{},{}",
            e.id.unwrap_or(0),
            csv_field(&e.ts.to_rfc3339()),
            csv_field(&e.severity),
            csv_field(&e.source),
            csv_field(&e.kind),
            csv_field(&e.summary),
            csv_field(&e.details_json),
        )?;
    }

    // chain.json
    let chain = store.verify_chain()?;
    zip.start_file("chain.json", opts)?;
    zip.write_all(serde_json::to_string_pretty(&chain)?.as_bytes())?;

    // manifest.json
    let (tip_id, head) = store.chain_tip().unwrap_or((0, String::new()));
    let manifest = serde_json::json!({
        "generated_at": Utc::now().to_rfc3339(),
        "agent_version": env!("CARGO_PKG_VERSION"),
        "events_total": events.len(),
        "tip_event_id": tip_id,
        "chain_head": head,
        "chain_ok": chain.ok,
        "excluded": ["agent_key.dpapi", "token.txt", "vault/*.bin"],
    });
    zip.start_file("manifest.json", opts)?;
    zip.write_all(serde_json::to_string_pretty(&manifest)?.as_bytes())?;

    // vault/*.json (manifests only)
    let vault = data_dir.join("vault");
    if vault.exists() {
        for entry in fs::read_dir(&vault)? {
            let entry = entry?;
            let p = entry.path();
            if p.extension().and_then(|e| e.to_str()) == Some("json") {
                if let Ok(bytes) = fs::read(&p) {
                    if let Some(name) = p.file_name().and_then(|n| n.to_str()) {
                        zip.start_file(format!("vault/{}", name), opts)?;
                        zip.write_all(&bytes)?;
                    }
                }
            }
        }
    }

    zip.finish()?;
    Ok(zip_path)
}

fn csv_field(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}
