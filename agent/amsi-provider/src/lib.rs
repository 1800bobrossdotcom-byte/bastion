// bastion-amsi-provider
// ----------------------------------------------------------------------------
// Scaffold for the AMSI in-process COM provider DLL.
//
// STATUS: scaffold only. The DLL builds (cdylib) but the COM vtable is not
// yet wired. The reason this crate exists separately from `bastion-agent`:
//
//   * AMSI providers MUST be DLLs (cdylib) — they are LoadLibrary'd into
//     every AMSI client process (PowerShell, Office, WSH, .NET, etc.). An
//     agent EXE cannot register itself as an AMSI provider.
//   * The DLL must be Authenticode-signed by a CA Windows trusts, otherwise
//     AMSI clients silently refuse to load it (since Win10 1903).
//   * Registration: a HKLM\SOFTWARE\Classes\CLSID\{guid}\InprocServer32
//     entry pointing at this DLL, plus a HKLM\SOFTWARE\Microsoft\AMSI\
//     Providers\{guid} entry — all REG_SZ. See install/register-amsi.ps1
//     (to be added) for the install script.
//
// IPC: when this DLL is loaded into a host process (e.g. powershell.exe),
// it MUST NOT do heavy work in-proc — that would slow every PowerShell
// invocation. Instead it opens a named pipe to the Bastion agent
// (`\\.\pipe\bastion-scan`) and forwards the buffer + content-type
// (script, exe, etc.). The agent's `scan_engine` does the actual work and
// replies with AMSI_RESULT_CLEAN / AMSI_RESULT_BLOCKED_BY_ADMIN_START / etc.
//
// Roadmap:
//   1. [done]   crate scaffold + DllMain + DllGetClassObject signatures
//   2. [next]   IClassFactory + IAntimalwareProvider2 vtable
//   3.          named-pipe client to bastion-agent
//   4.          install/uninstall PowerShell scripts
//   5.          Azure Trusted Signing pipeline (~$9.99/mo) -> signed release

#![cfg(windows)]
#![allow(non_snake_case)]

use std::ffi::c_void;
use windows::core::{GUID, HRESULT};
use windows::Win32::Foundation::{BOOL, HMODULE, S_FALSE, S_OK};

// {arbitrary-but-stable-CLSID} — generated 2026-05-18, replace before signing
// release builds so each tenant gets its own. Format: BA571000-0000-...
pub const CLSID_BASTION_AMSI: GUID = GUID::from_u128(0xBA571000_0000_4000_8000_000000BA5710u128);

#[no_mangle]
pub extern "system" fn DllMain(_hinst: HMODULE, _reason: u32, _reserved: *mut c_void) -> BOOL {
    BOOL(1)
}

#[no_mangle]
pub extern "system" fn DllGetClassObject(
    _rclsid: *const GUID,
    _riid: *const GUID,
    _ppv: *mut *mut c_void,
) -> HRESULT {
    // TODO(amsi): return an IClassFactory for CLSID_BASTION_AMSI that
    // manufactures IAntimalwareProvider2 instances which forward to the
    // bastion-agent named pipe.
    let _ = (S_OK, S_FALSE);
    windows::Win32::Foundation::CLASS_E_CLASSNOTAVAILABLE
}

#[no_mangle]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    S_OK
}

#[no_mangle]
pub extern "system" fn DllRegisterServer() -> HRESULT {
    // TODO(amsi): write HKLM\SOFTWARE\Classes\CLSID\{guid}\InprocServer32
    // and HKLM\SOFTWARE\Microsoft\AMSI\Providers\{guid}. For now the
    // PowerShell installer (install/register-amsi.ps1) does this manually.
    S_OK
}

#[no_mangle]
pub extern "system" fn DllUnregisterServer() -> HRESULT {
    S_OK
}
