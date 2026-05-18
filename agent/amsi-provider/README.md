# bastion-amsi-provider

In-process COM `IAntimalwareProvider` DLL. Loaded by every AMSI client on the
machine (PowerShell, Office macros, WSH, .NET assemblies, MSIL loaders) so
Bastion can see and decide on script / macro / managed-code buffers before
they execute.

## Status

Scaffold only. The DLL builds as a `cdylib` and exports the standard
in-proc COM entry points (`DllMain`, `DllGetClassObject`,
`DllCanUnloadNow`, `DllRegisterServer`, `DllUnregisterServer`) but the
COM vtable is not yet wired.

## How it will work

1. Host process (e.g. `powershell.exe`) calls AMSI.
2. AMSI loads every DLL registered under
   `HKLM\SOFTWARE\Microsoft\AMSI\Providers\{guid}` — including this one.
3. `IAntimalwareProvider2::Scan` is called with a content buffer + type.
4. This DLL forwards the buffer over the local named pipe
   `\\.\pipe\bastion-scan` to the running `bastion-agent`.
5. The agent's `scan_engine` decides clean / suspicious / blocked.
6. Result is returned to AMSI; AMSI returns it to the host; the host
   decides whether to execute.

## Why it's a separate crate

AMSI providers MUST be DLLs. The agent binary is an EXE. They share the
`scan_engine` logic via the named-pipe IPC, not by linking together.

## Why the DLL must be signed

Since Windows 10 1903, AMSI clients silently refuse to load unsigned
provider DLLs. Trusted Signing (~$9.99/mo) is the cheapest production
path; for dev / lab use, `bcdedit /set testsigning on` works.

## Build

```
cargo build --release -p bastion-amsi-provider
```

Output: `target/release/bastion_amsi.dll`.
