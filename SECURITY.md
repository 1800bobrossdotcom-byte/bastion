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

## Security assumptions

Bastion's guarantees hold only while these are true:

- The Windows kernel and the signed Microsoft components it relies on (ETW, DPAPI, Defender) are not compromised.
- The attacker does not already have SYSTEM or administrator rights.
- The Bastion binary on disk is the one that was released (verify it, see below).
- The signed-in user is trusted; Bastion protects that user, not against them.
- The bastion.quest deployment that hosts the console is not compromised, because it holds the API token in browser storage.

## Privileges

- The agent runs as **your user**, non-elevated. The installer registers a per-user logon scheduled task (`RunLevel Limited`). There is no Windows service and no driver.
- Anything that needs admin (perf fixes, health repairs, cleaning system temp/update caches) goes through a **normal UAC prompt** per action. Bastion never silently elevates.
- `driver/` (kernel minifilter) and `agent/amsi-provider/` are **scaffolds, not shipped**.

## Local API (`127.0.0.1:7878`)

- Bound to loopback only.
- Every endpoint except `/api/health` (which returns only `ok` and the agent version) requires `Authorization: Bearer <token>`. The token is 256 random bits, generated on first run and stored in the per-user data dir. It is compared in constant time.
- **Browser isolation:** CORS is granted only to the dashboard: `https://bastion.quest` (the hosted console, which the desktop app also loads), the Tauri shell, and `localhost` / `127.0.0.1` dev servers. The bearer token is kept in that dashboard's browser storage, so the bastion.quest deployment is part of the trust boundary. Requests whose `Host` header is not a loopback name are refused (DNS-rebinding guard).
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

What is done, and what is not done yet. The checked items apply from v0.4.0 on; earlier releases were built by hand.

- [x] Source is public.
- [x] Releases are built on GitHub's runners from the tagged commit (`.github/workflows/release.yml`). The installer's bundled agent is built in the same run, never taken from a committed binary.
- [x] `SHA256SUMS.txt` attached to every release.
- [x] CycloneDX SBOM attached to every release.
- [x] Sigstore-signed build provenance (`gh attestation verify <file> -R 1800bobrossdotcom-byte/bastion`).
- [x] `cargo audit` (RustSec) runs in CI and fails the build on any advisory.
- [ ] Authenticode-signed installer (needs a code-signing certificate)
- [ ] Reproducible builds (bit-for-bit)
- [ ] Independent security review

Until the open items are done, you can also build from source:

```powershell
git clone https://github.com/1800bobrossdotcom-byte/bastion
cd bastion\agent
cargo build --release
```
