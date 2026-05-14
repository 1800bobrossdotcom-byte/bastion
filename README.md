# Bastion

Local, user-mode defensive monitoring agent for your own Windows machine.

## What it does

- **Process + network**: snapshots running processes and their outbound TCP connections, alerts on new processes connecting to the internet for the first time.
- **Autoruns**: watches `Run` / `RunOnce` registry keys, scheduled tasks, and services for new entries.
- **File integrity (FIM)**: SHA-256 baseline of chosen directories (e.g. `C:\Windows\System32` subset, your dev tree), alerts on modification.
- **Camera / mic access**: polls `HKCU\Software\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore` last-used timestamps.
- **USB**: alerts on new USB device class GUIDs being attached.
- **DNS**: tails Microsoft-Windows-DNS-Client/Operational events, optionally cross-references domains against threat-intel feeds.
- **Defender + Firewall**: aggregates Windows Defender and Windows Firewall events into one timeline.

All events go to a local SQLite store. A Next.js dashboard on `http://127.0.0.1:7878` reads them via a bearer-token-protected JSON API on the agent.

## What it does NOT do

- Detect or block nation-state spyware (Pegasus, Predator, etc.). That requires kernel drivers, ETW providers signed by Microsoft, and a SOC.
- "Hack back" or run offensive tooling.
- Replace Windows Defender, an EDR, or a real firewall.

It's a **monitoring + alerting** tool that surfaces things commodity malware and noisy spyware do, so you notice them.

## Run

```powershell
cd agent
cargo run --release
```

Agent listens on `127.0.0.1:7878`. Token is generated on first run and printed to stdout + saved at `%APPDATA%\bastion\token.txt`.
