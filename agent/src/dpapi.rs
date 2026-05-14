// Tiny DPAPI wrapper. Seal/unseal byte blobs against the CurrentUser scope.
// Sealed blobs are only decryptable by the same Windows user on the same
// machine — good enough for an at-rest agent key.
//
// We do NOT pass entropy or a UI prompt. CRYPTPROTECT_UI_FORBIDDEN ensures
// the call cannot ever pop a dialog.

#![cfg(windows)]

use anyhow::{Context, Result};
use windows::core::PCWSTR;
use windows::Win32::Foundation::HLOCAL;
use windows::Win32::Security::Cryptography::{
    CryptProtectData, CryptUnprotectData, CRYPTPROTECT_UI_FORBIDDEN, CRYPT_INTEGER_BLOB,
};
use windows::Win32::Foundation::LocalFree;

pub fn seal(plaintext: &[u8]) -> Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: plaintext.len() as u32,
        pbData: plaintext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    unsafe {
        CryptProtectData(
            &input as *const _,
            PCWSTR::null(),
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output as *mut _,
        )
        .context("CryptProtectData failed")?;
    }
    let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        let _ = LocalFree(HLOCAL(output.pbData as _));
    }
    Ok(bytes)
}

pub fn unseal(ciphertext: &[u8]) -> Result<Vec<u8>> {
    let input = CRYPT_INTEGER_BLOB {
        cbData: ciphertext.len() as u32,
        pbData: ciphertext.as_ptr() as *mut u8,
    };
    let mut output = CRYPT_INTEGER_BLOB { cbData: 0, pbData: std::ptr::null_mut() };
    unsafe {
        CryptUnprotectData(
            &input as *const _,
            None,
            None,
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output as *mut _,
        )
        .context("CryptUnprotectData failed")?;
    }
    let bytes = unsafe { std::slice::from_raw_parts(output.pbData, output.cbData as usize).to_vec() };
    unsafe {
        let _ = LocalFree(HLOCAL(output.pbData as _));
    }
    Ok(bytes)
}
