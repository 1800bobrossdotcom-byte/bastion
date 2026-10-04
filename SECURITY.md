# Bastion security

Bastion runs with a lot of access to your machine, so you should be able to check what it does before you trust it. This page sets out what it touches, what it sends, how it protects itself, and what is not finished yet.

## Reporting a vulnerability

Use **GitHub → Security → Report a vulnerability** on this repository (private advisory). Please do not open a public issue for anything exploitable. Expect an acknowledgement within 7 days. Fixes are credited in the changelog unless you ask otherwise.

## What Bastion is (and is not)

A local, user-mode monitoring and response agent that runs **alongside Microsoft Defender**. It does not replace Defender, an EDR or a firewall. It cannot stop malware that already has SYSTEM or kernel access: such malware can tamper with the agent, its database and the OS underneath it. The event chain is **tamper-evident, not tamper-proof**.

## Threat model

| In scope | Out of scope |
|---|---|
| Commodity malware and noisy spyware running as your user | Kernel rootkits, bootkits, firmware implants |
| Persistence changes (Run keys, services, tasks, hosts file, Startup) | An attacker who already has SYSTEM / admin |
| A malicious website trying to drive the local API from your browser | Nation-state targeted implants (Pegasus-class) |
| Silent edits to Bastion's own event history | Physical access with disk-level tampering |

## Privileges

- The agent runs as **your user**, non-elevated. The installer registers a per-user logon scheduled task (`RunLevel Limited`). There is no Windows service and no driver.
- Anything that needs admin (perf fixes, health repairs, cleaning system temp/update caches) goes through a **normal UAC prompt** per action. Bastion never silently elevates.
- `driver/` (kernel minifilter) and `agent/amsi-provider/` are **scaffolds, not shipped**.

## Local API (`127.0.0.1:7878`)

- Bound to loopback only.
- Every endpoint except `/api/health` requires `Authorization: Bearer <token>`. The token is 256 random bits, generated on first run and stored in the per-user data dir. It is compared in constant time.
- **Browser isolation:** CORS is granted only to `localhost` / `127.0.0.1` origins and the Tauri shell. Requests whose `Host` header is not a loopback name are refused (DNS-rebinding guard).
- **No client-supplied commands are executed.** Perf and health fixes run only if the exact command string was produced by a fresh audit on the agent. Junk cleanup takes category ids, not paths, and re-resolves every folder itself. Uninstall takes an id and launches that program's own registered uninstaller.
- Quarantine resolves the real path first (`..`, case, short names, links). It refuses directories, the agent's data dir, and the agent's own binary. Quarantined files are **copied to the vault before deletion** and kept as evidence.

## Network destinations

Nothing leaves the machine except the following. The first three are on by default; everything else is opt-in.

| Destination | Why | Default |
|---|---|---|
| `urlhaus.abuse.ch` | Malicious-domain blocklist | on |
| `openphish.com` | Phishing-domain feed | on |
| `bazaar.abuse.ch` | Malware SHA-256 list for scan-on-write | on |
| `ntfy.sh` | Push alerts | only if `data/ntfy.txt` exists |
| `management.azure.com` | Microsoft Sentinel bridge | only if you configure it |
| `BASTION_OPENHUMAN_URL` | Optional AI "why" explanation | only if set |

No telemetry, analytics, crash reporting or licence check.

## AI "why" explanations

Explanations are **advisory text only**. A detector produces the event and evidence, and a person decides what to do. No model output can kill a process, quarantine a file or change a setting. The external AI bridge is off unless `BASTION_OPENHUMAN_URL` is set. When it is set, the selected event's summary and details are sent to that URL. Set `BASTION_AI_MANAGER_MODE=heuristic` or `off` to keep explanations fully local.

## Data at rest

Events live in a local SQLite database in your per-user data dir (`%APPDATA%\bastion\bastion\data\`). Each event is hash-chained to the previous one; `/api/chain/verify` recomputes the chain and reports the first break. The agent's signing key is sealed with Windows DPAPI.

## Release integrity — current state

Being explicit about what is **not done yet**:

- [x] Source is public.
- [x] SHA-256 of the installer is published on the download page.
- [ ] Authenticode-signed installer
- [ ] Reproducible builds
- [ ] Signed provenance (cosign / SLSA)
- [ ] SBOM and automated dependency audit (`cargo audit`) in CI
- [ ] Independent security review

Until those are done, build from source if you need to be certain the binary matches the code:

```powershell
git clone https://github.com/1800bobrossdotcom-byte/bastion
cd bastion\agent
cargo build --release
```
