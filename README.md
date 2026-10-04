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

## Machine maintenance (cleanup + health)

Bastion also includes a cleanup and machine-health tool. Use it from the dashboard API or directly from a terminal:

```powershell
bastion-agent maint                 # health score + reclaimable junk summary
bastion-agent maint scan            # junk by category (temp, update cache, browser caches, dumps, ...)
bastion-agent maint clean           # dry run of the recommended set
bastion-agent maint clean --yes     # actually clean the recommended set
bastion-agent maint clean --yes browser_cache shader_cache   # specific categories
bastion-agent maint health          # disk SMART/wear, pending reboot, update age, event-log errors, battery
bastion-agent maint programs        # installed Win32 + Store apps, flagged bloatware / large / stale
bastion-agent maint large 1000      # biggest files (>= 1000 MB) in your profile, plus Downloads age
# add --json to any command for raw output
```

**Junk categories:** user + Windows temp, Windows Update download cache, Delivery Optimization cache, crash dumps, Windows Error Reporting queues, browser caches (Chrome/Edge/Brave/Vivaldi/Firefox), thumbnail cache, GPU shader caches, developer package caches (npm/pip/Yarn/NuGet/Go/cargo), old CBS/DISM logs, Recycle Bin. `Windows.old` is sized but left to Windows' own Storage settings.

**Safety rules:** only the contents of fixed, agent-defined folders are deleted (never the folder itself, never a path from the client); symlinks/junctions are never followed; recently modified files are left alone (24–72 h depending on category); locked files are skipped; browser caches are skipped while that browser is running. Admin-only categories are batched into a single UAC prompt. Uninstall launches the program's own registered uninstaller (or `Remove-AppxPackage` for Store apps) — nothing is removed silently. Every clean, uninstall and health fix is written to the tamper-evident event chain.

API (bearer token, same as the rest):

| Method | Path | Body / query |
|---|---|---|
| GET | `/api/maint/overview` | — |
| GET | `/api/maint/junk/scan` | — |
| POST | `/api/maint/junk/clean` | `{ "ids": ["user_temp", ...], "dry_run": false }` (empty `ids` = recommended set) |
| GET | `/api/maint/large-files` | `?min_mb=500&limit=50` |
| GET | `/api/maint/programs` | — |
| POST | `/api/maint/programs/uninstall` | `{ "id": "win32:HKLM:{GUID}", "confirm": true }` |
| GET | `/api/maint/health` | — |
| POST | `/api/maint/health/apply` | `{ "fix_command": "<exact string from /api/maint/health>" }` |

## What it does NOT do

- Detect or block nation-state spyware (Pegasus, Predator, etc.). That requires kernel drivers, ETW providers signed by Microsoft, and a SOC.
- "Hack back" or run offensive tooling.
- Replace Windows Defender, an EDR, or a real firewall.

It's a **monitoring + alerting** tool that surfaces things commodity malware and noisy spyware do, so you notice them.

## Security

See [SECURITY.md](SECURITY.md) for the threat model, privileges, network destinations, API protections and release-integrity status. Report vulnerabilities privately via GitHub → Security → Report a vulnerability.

## Run

```powershell
cd agent
cargo run --release
```

Agent listens on `127.0.0.1:7878`. Token is generated on first run and printed to stdout + saved at `%APPDATA%\bastion\token.txt`.
