// Process + network detector.
//
// Approach: every POLL_SECS, walk all running processes via sysinfo and call
// `netstat -ano` to enumerate TCP connections (kept simple to avoid a windows
// IpHelper FFI dance for v0.1). For each (pid, exe, remote_ip:port) tuple
// where remote is not loopback / RFC1918 / link-local, we register a "seen"
// key. If unseen -> emit alert event.
//
// This catches: malware reaching out to a C2, a new app phoning home, a fresh
// process making outbound connections you didn't expect.

use crate::store::{now_event, Store};
use anyhow::Result;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use sysinfo::{Pid, System};
use tokio::process::Command;

const POLL_SECS: u64 = 15;

pub async fn run(store: Arc<Store>) {
    loop {
        if let Err(e) = tick(&store).await {
            tracing::warn!("process_net tick error: {e:#}");
        }
        tokio::time::sleep(Duration::from_secs(POLL_SECS)).await;
    }
}

async fn tick(store: &Arc<Store>) -> Result<()> {
    let mut sys = System::new();
    sys.refresh_processes();

    let conns = netstat_tcp().await?;
    let mut by_pid: HashMap<u32, Vec<(IpAddr, u16)>> = HashMap::new();
    for c in conns {
        by_pid.entry(c.pid).or_default().push((c.remote_ip, c.remote_port));
    }

    for (pid, remotes) in by_pid {
        let proc = sys.process(Pid::from_u32(pid));
        let exe = proc
            .and_then(|p| p.exe().map(|e| e.display().to_string()))
            .unwrap_or_else(|| "<unknown>".into());
        let name = proc.map(|p| p.name().to_string()).unwrap_or_else(|| "<unknown>".into());

        for (ip, port) in remotes {
            if !is_internet(ip) {
                continue;
            }
            let key = format!("{exe}|{ip}:{port}");
            if store.mark_seen("proc_net", &key)? {
                let summary = format!("{name} ({pid}) -> {ip}:{port}");
                let details = serde_json::json!({
                    "pid": pid, "name": name, "exe": exe,
                    "remote_ip": ip.to_string(), "remote_port": port,
                });
                let ev = now_event("process_net", "warn", "new_outbound_connection", summary, details);
                store.insert_event(&ev)?;
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
struct Conn {
    pid: u32,
    remote_ip: IpAddr,
    remote_port: u16,
}

async fn netstat_tcp() -> Result<Vec<Conn>> {
    let out = Command::new("netstat").args(["-ano", "-p", "TCP"]).output().await?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut conns = Vec::new();
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // TCP   local   remote   STATE   pid
        if cols.len() < 5 || !cols[0].eq_ignore_ascii_case("TCP") {
            continue;
        }
        if cols[3] != "ESTABLISHED" {
            continue;
        }
        let Some((ip_str, port_str)) = split_addr(cols[2]) else { continue };
        let Ok(ip) = ip_str.parse::<IpAddr>() else { continue };
        let Ok(port) = port_str.parse::<u16>() else { continue };
        let Ok(pid) = cols[4].parse::<u32>() else { continue };
        conns.push(Conn { pid, remote_ip: ip, remote_port: port });
    }
    Ok(conns)
}

fn split_addr(s: &str) -> Option<(String, String)> {
    // IPv6 form: [::1]:443  ; IPv4: 1.2.3.4:443
    if let Some(rest) = s.strip_prefix('[') {
        let end = rest.find(']')?;
        let ip = &rest[..end];
        let port = rest[end + 1..].strip_prefix(':')?;
        return Some((ip.to_string(), port.to_string()));
    }
    let i = s.rfind(':')?;
    Some((s[..i].to_string(), s[i + 1..].to_string()))
}

fn is_internet(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            !(v.is_loopback() || v.is_private() || v.is_link_local() || v.is_unspecified() || v.is_multicast())
        }
        IpAddr::V6(v) => {
            !(v.is_loopback() || v.is_unspecified() || v.is_multicast()
              || (v.segments()[0] & 0xfe00) == 0xfc00 // ULA
              || (v.segments()[0] & 0xffc0) == 0xfe80) // link-local
        }
    }
}
