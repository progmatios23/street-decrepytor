//! On-demand UAC elevation.
//!
//! A debugger must run at least as privileged as its target: a process that
//! demands `requireAdministrator` cannot be spawned, let alone debugged, from a
//! non-elevated parent. Rather than demanding admin for *every* invocation —
//! which would be hostile to the ordinary case of analysing a normal binary —
//! elevation is requested only when the target actually needs it, and only once.
//!
//! The child is marked with an environment variable so it does not try to
//! elevate again, which would otherwise loop.

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Security::{
    GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

/// Set in the elevated child so it does not attempt to elevate again.
pub const ELEVATED_MARKER: &str = "STREET_ELEVATED";

/// True when the current process is running with an elevated token.
pub fn is_elevated() -> bool {
    unsafe {
        let mut token = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut ret = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut core::ffi::c_void),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut ret,
        )
        .is_ok();
        let _ = CloseHandle(token);
        ok && elevation.TokenIsElevated != 0
    }
}

/// True when this process is the elevated child of a previous invocation.
pub fn already_relaunched() -> bool {
    std::env::var(ELEVATED_MARKER).is_ok()
}

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(std::iter::once(0)).collect()
}

/// Relaunch this executable elevated, passing the current arguments through.
///
/// Returns `Ok(())` when the elevated child was started — the caller should
/// then exit without doing any work, because the child will. Returns `Err` when
/// the user declines the UAC prompt or the launch fails.
pub fn relaunch_elevated() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;

    // Rebuild the argument tail, quoting each argument. The target path may
    // contain spaces, so this cannot be skipped.
    let mut params = String::new();
    for (i, a) in std::env::args().skip(1).enumerate() {
        if i > 0 {
            params.push(' ');
        }
        params.push('"');
        params.push_str(&a.replace('"', "\\\""));
        params.push('"');
    }

    let file_w = wide(exe.as_os_str());
    let op_w = wide(OsStr::new("runas"));
    let params_w = wide(OsStr::new(&params));

    let r = unsafe {
        ShellExecuteW(
            None,
            PCWSTR(op_w.as_ptr()),
            PCWSTR(file_w.as_ptr()),
            PCWSTR(params_w.as_ptr()),
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };

    // ShellExecuteW returns a pseudo-HINSTANCE; <= 32 is an error code.
    let code = r.0 as usize;
    if code <= 32 {
        return Err(format!(
            "elevation was refused or failed (ShellExecuteW returned {code}). \
             Accept the UAC prompt, or run street from an already-elevated prompt."
        ));
    }
    Ok(())
}

/// Ensure elevation for a run, relaunching if needed.
///
/// Returns `Ok(true)` when the caller should **stop** — an elevated child was
/// started and will do the work.
pub fn ensure_elevated(reason: &str) -> Result<bool, String> {
    if is_elevated() {
        return Ok(false);
    }
    if already_relaunched() {
        // We are the child and still not elevated: the user declined.
        return Err(format!(
            "still not elevated after relaunch — {reason}. \
             Accept the UAC prompt, or run street from an elevated prompt."
        ));
    }
    eprintln!("street: {reason}");
    eprintln!("street: relaunching elevated — accept the UAC prompt");
    relaunch_elevated()?;
    Ok(true)
}
