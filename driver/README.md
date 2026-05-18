# BastionFilter — kernel-mode minifilter (Path B)

On-access file scanner that runs as a Windows file-system filter driver.
Every `IRP_MJ_CREATE` (file open) is shipped up to the user-mode `bastion-agent`
over a filter communication port; the agent decides allow / block; the driver
honours the verdict.

This is **Path B** from the roadmap on https://bastion.quest. Path A (ETW +
AMSI, user-mode) is already shipped. Both share `agent/src/scan_engine.rs` —
the driver does NOT make scan decisions of its own.

## Why a driver at all (since Path A exists)

| capability                              | Path A (ETW/AMSI) | Path B (this) |
| --------------------------------------- | ----------------- | ------------- |
| see file opens system-wide              | yes (admin)       | yes           |
| see opens during early boot             | partial           | yes           |
| **prevent** the open (return STATUS_ACCESS_DENIED) | no | yes |
| works without elevation                 | no                | yes (service) |
| requires signed binary                  | no                | yes           |

Path B is the only way to *stop* a malicious write before the writer's handle
is valid. ETW only tells us after the fact.

## Files

- `BastionFilter.c`   — driver entry, IRP_MJ_CREATE pre/post callbacks, FltSendMessage to user-mode.
- `BastionFilter.h`   — shared `BASTION_NOTIFY` / `BASTION_REPLY` packet layout (mirrored in Rust).
- `BastionFilter.inf` — install metadata. **Altitude 385201 is temporary** (Activity Monitor range); production altitude must be allocated by Microsoft.

## Build (developer machine)

Prerequisites:
- Visual Studio 2022 with **Desktop development with C++**.
- **Windows Driver Kit (WDK)** matching the Windows SDK installed by VS.
  `winget install --id Microsoft.WindowsWDK`
- Spectre-mitigated runtime libraries (offered as an optional VS component).

Once installed, create a new VS solution from the WDK template:
`File → New → Project → Filter Driver: Filesystem Mini-Filter`, then replace
the generated `.c` / `.h` / `.inf` with the files in this folder. Build x64
Release. Output: `BastionFilter.sys`, `BastionFilter.inf`, `BastionFilter.cat`.

(Reason we don't ship a `.vcxproj` here: VS-generated projects encode absolute
paths to your WDK install. The C source is what matters; the project file is
trivial to regenerate.)

## Test-sign for local development

```powershell
# 1) Enable test-signing on the dev box (reboot required).
bcdedit /set testsigning on
Restart-Computer

# 2) Generate a self-signed test cert.
$cert = New-SelfSignedCertificate -Type CodeSigning `
  -Subject "CN=Bastion Test Signing" `
  -CertStoreLocation Cert:\LocalMachine\My `
  -KeyUsage DigitalSignature -KeySpec Signature `
  -KeyExportPolicy Exportable -HashAlgorithm SHA256

# 3) Sign the .sys and .cat.
$tp = $cert.Thumbprint
signtool sign /v /fd SHA256 /sha1 $tp BastionFilter.sys
inf2cat /driver:. /os:10_x64
signtool sign /v /fd SHA256 /sha1 $tp BastionFilter.cat

# 4) Install (right-click .inf → Install) or:
RUNDLL32.EXE SETUPAPI.DLL,InstallHinfSection DefaultInstall 132 .\BastionFilter.inf

# 5) Load.
sc start BastionFilter
fltmc                # should list BastionFilter at altitude 385201
```

## Production signing (the long path)

1. **EV code-signing certificate** from a Microsoft-trusted CA (Sectigo,
   DigiCert, GlobalSign). Hardware token, ~$300-700/yr, identity verification
   takes 1-2 weeks.
2. Sign the .sys + .cat with EV cert + cross-signed timestamp.
3. *(Optional but recommended for kernel)* **Attestation signing** via
   Microsoft Partner Center (https://partner.microsoft.com/dashboard/hardware)
   — submit the signed package; Microsoft re-signs with their kernel-mode CA
   so the driver loads on Secure-Booted machines without `testsigning`.
4. Allocate a permanent **altitude** in the FSFilter Anti-Virus range
   (320000-329999) by emailing `filteraltitudes@microsoft.com` with the INF
   and a brief description. Update `BastionFilter.inf` accordingly.

Estimated calendar time: 4-8 weeks from "cert ordered" to "loaded on a stock
Win11 box". This is why Path A ships first.

## Communication protocol

User-mode side: `agent/src/detectors/minifilter_bridge.rs` opens
`\\.\BastionPort` via `FilterConnectCommunicationPort` and pumps a
`GetMessage` / `ReplyMessage` loop. For each `BASTION_NOTIFY` it converts the
NT path to DOS, calls `scan_engine::scan_path(..., "minifilter")`, and replies
with `BASTION_VERDICT_BLOCK` if the scan engine quarantined the file.

If user-mode isn't running, the driver **fails open** (2-second timeout, then
allow) — the filesystem must never wedge if the agent crashes.
