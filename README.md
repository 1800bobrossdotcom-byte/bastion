# Bastion

**Microsoft Defender protects your machine. Bastion watches the gaps.**

A local, user-mode defensive sensor for your own Windows machine. It runs *alongside* Defender, not instead of it, and gives you an independent view of what is happening: detections, the evidence behind them, and a tamper-evident record of both. No telemetry leaves the device by default.

Live console: [bastion.quest](https://bastion.quest) · Security model: [SECURITY.md](SECURITY.md) · Releases: [GitHub Releases](https://github.com/1800bobrossdotcom-byte/bastion/releases)

## What it does

Every item below is in `agent/src/`. Items marked *scaffold* are in the tree but not built into releases.

**Watching Defender**
- **Defender Watchdog** (`detectors/defender_watchdog.rs`): alerts when real-time protection, tamper protection, behaviour monitoring or cloud protection is switched off, signatures go stale, or a new exclusion appears. Detect-only.
- **Defender + Firewall events** (`detectors/defender.rs`): high-signal Defender and Windows Firewall log events in one timeline.

**Detection**
- **Behavioural rules** (`detectors/asr.rs`): eight ASR-style rules. Office or a browser spawning a script host, a script host spawning a LOLBin, encoded/hidden PowerShell, `mshta` with a remote URL, `certutil` downloads, WMI spawning a shell, bare `rundll32`. Alert-only.
- **Scan-on-write** (`detectors/scan_on_write.rs`, `scan_engine.rs`): files landing in Downloads / Desktop / Documents are hashed and checked against the MalwareBazaar SHA-256 feed. Hits are quarantined.
- **On-access file events** (`detectors/etw_file.rs`): `Microsoft-Windows-Kernel-File` ETW consumer feeding the same scan engine. If ETW is unavailable, the drop-directory watcher keeps running on its own.
- **DNS** (`detectors/dns.rs`, `blocklist.rs`, `dga.rs`): DNS-Client events checked against URLhaus + OpenPhish, plus a DGA-likeness score.
- **Process + network** (`detectors/process_net.rs`, `process_lineage.rs`, `proc_fp.rs`): first-time outbound connections, parent-chain lineage, and process fingerprints (parent, binary, argument shape).

**Persistence + integrity**
- **Autoruns** (`detectors/autoruns.rs`): Run/RunOnce keys, scheduled tasks, services.
- **File integrity** (`detectors/fim.rs`): SHA-256 baselines for the hosts file, Startup folder and chosen directories.
- **Startup sweep** (`detectors/boot_scan.rs`): full persistence + FIM rollup once at agent start.

**Tripwires + privacy**
- **Canary files** (`detectors/canary.rs`): HMAC-tagged decoys (fake cloud credentials, `.env`, wallet). Any touch alerts.
- **Registry decoys** (`detectors/registry_decoy.rs`): credential-looking values under `HKCU\Software\Bastion\Decoys`.
- **Camera / microphone** (`detectors/camera_mic.rs`): per-app last-used timestamps from the Windows capability ledger.
- **USB** (`detectors/usb.rs`): new device insertions.

**Evidence layer**
- **Hash-chained event store** (`store.rs`): every event is chained to the previous one in local SQLite. `/api/chain/verify` reports the first break. Tamper-*evident*, not tamper-proof.
- **Triage state is separate**: resolving an event marks it in its own table and never edits the chain.
- **Quarantine vault** (`quarantine.rs`): the file is copied to the vault with a SHA-256 manifest *before* the original is deleted.
- **Forensic export** (`forensic.rs`): a zip of all events, the chain-verification result, a manifest with the head hash, and the quarantine manifests. The zip itself is not signed yet.
- **Self-attestation** (`detectors/attestation.rs`): an Ed25519 heartbeat signed with a DPAPI-sealed key.

**Response + integrations (opt-in)**
- One-click kill PID and quarantine from the console.
- ntfy push + Windows toasts (`notifier.rs`), Microsoft Sentinel incident bridge (`api.rs`), optional AI "why" explanations (`ai_manager.rs`). These are advisory text only; a model can never take an action.

*Scaffolds, not shipped:* kernel minifilter (`driver/`, `detectors/minifilter_bridge.rs`) and AMSI provider (`agent/amsi-provider/`). Both need production code signing before Windows will load them.

The agent exposes a bearer-token-protected JSON API on `127.0.0.1:7878`. The console at bastion.quest (also what the desktop app opens) talks to it from your browser.

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

## Verifying a release

Releases are built by [`.github/workflows/release.yml`](.github/workflows/release.yml) on GitHub's runners, from the tagged commit. The installer's bundled agent is the one built in that same run. Each release carries `SHA256SUMS.txt`, a CycloneDX SBOM and a Sigstore-signed build-provenance attestation:

```powershell
Get-FileHash .\BASTION_<version>_x64-setup.exe -Algorithm SHA256   # compare with SHA256SUMS.txt
gh attestation verify .\BASTION_<version>_x64-setup.exe -R 1800bobrossdotcom-byte/bastion
```

Installers are not Authenticode-signed yet; see [SECURITY.md](SECURITY.md).

## Run

```powershell
cd agent
cargo run --release
```

Agent listens on `127.0.0.1:7878`. The API token is generated on first run, printed to stdout and saved at `%APPDATA%\bastion\bastion\data\token.txt`. That file is a plain file protected by your user profile's permissions, not DPAPI-sealed; only the attestation signing key is DPAPI-sealed.
