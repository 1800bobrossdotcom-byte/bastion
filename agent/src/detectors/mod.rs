use crate::store::Store;
use std::sync::Arc;

pub mod attestation;
pub mod autoruns;
pub mod boot_scan;
pub mod camera_mic;
pub mod canary;
pub mod defender;
pub mod dns;
#[cfg(windows)]
pub mod etw_file;
pub mod fim;
#[cfg(windows)]
pub mod minifilter_bridge;
pub mod perf;
pub mod proc_fp;
pub mod process_lineage;
pub mod process_net;
pub mod registry_decoy;
pub mod scan_on_write;
pub mod usb;

pub fn spawn_all(store: Arc<Store>) {
    tokio::spawn(process_net::run(store.clone()));
    tokio::spawn(process_lineage::run(store.clone()));
    tokio::spawn(autoruns::run(store.clone()));
    tokio::spawn(camera_mic::run(store.clone()));
    tokio::spawn(canary::run(store.clone()));
    tokio::spawn(registry_decoy::run(store.clone()));
    tokio::spawn(attestation::run(store.clone()));
    tokio::spawn(defender::run(store.clone()));
    tokio::spawn(dns::run(store.clone()));
    tokio::spawn(fim::run(store.clone()));
    tokio::spawn(proc_fp::run(store.clone()));
    tokio::spawn(scan_on_write::run(store.clone()));
    #[cfg(windows)]
    tokio::spawn(etw_file::run(store.clone()));
    #[cfg(windows)]
    tokio::spawn(minifilter_bridge::run(store.clone()));
    tokio::spawn(usb::run(store.clone()));
}
