//! x64dbg plugin ABI. Pack(16) on x64 as in `_plugins.h`.

#![allow(non_camel_case_types)]

use std::ffi::c_void;

pub const PLUG_SDKVERSION: i32 = 1;

#[repr(C, align(16))]
pub struct PlugInit {
    pub plugin_handle: i32,
    pub sdk_version: i32,
    pub plugin_version: i32,
    pub plugin_name: [u8; 256],
}

#[repr(C, align(16))]
pub struct PlugSetup {
    pub hwnd_dlg: *mut c_void,
    pub h_menu: i32,
    pub h_menu_disasm: i32,
    pub h_menu_dump: i32,
    pub h_menu_stack: i32,
    pub h_menu_graph: i32,
    pub h_menu_memmap: i32,
    pub h_menu_symmod: i32,
}

#[repr(C)]
pub struct PlugCbMenuEntry {
    pub h_entry: i32,
}

pub type CbPluginCommand = unsafe extern "C" fn(argc: i32, argv: *mut *mut i8) -> bool;

#[derive(Default)]
pub struct HostFns {
    pub menuadd: Option<unsafe extern "C" fn(i32, *const i8) -> i32>,
    pub menuaddentry: Option<unsafe extern "C" fn(i32, i32, *const i8) -> bool>,
    pub menuaddseparator: Option<unsafe extern "C" fn(i32) -> bool>,
    pub menuentrysethotkey: Option<unsafe extern "C" fn(i32, i32, *const i8)>,
    pub registercommand: Option<unsafe extern "C" fn(i32, *const i8, CbPluginCommand, bool) -> bool>,
    pub logputs: Option<unsafe extern "C" fn(*const i8)>,
}

#[cfg(windows)]
pub fn resolve() -> HostFns {
    use std::ptr::null_mut;
    use windows::core::PCSTR;
    use windows::Win32::System::LibraryLoader::{GetModuleHandleW, GetProcAddress};
    use windows::core::w;

    unsafe {
        let mut h = GetModuleHandleW(w!("x64dbg.dll")).unwrap_or(windows::Win32::Foundation::HMODULE(null_mut()));
        if h.0.is_null() {
            h = GetModuleHandleW(w!("x32dbg.dll")).unwrap_or_default();
        }
        if h.0.is_null() {
            h = GetModuleHandleW(None).unwrap_or_default();
        }
        let gp = |name: &[u8]| GetProcAddress(h, PCSTR(name.as_ptr()));
        HostFns {
            menuadd: gp(b"_plugin_menuadd\0").map(|p| std::mem::transmute(p)),
            menuaddentry: gp(b"_plugin_menuaddentry\0").map(|p| std::mem::transmute(p)),
            menuaddseparator: gp(b"_plugin_menuaddseparator\0").map(|p| std::mem::transmute(p)),
            menuentrysethotkey: gp(b"_plugin_menuentrysethotkey\0").map(|p| std::mem::transmute(p)),
            registercommand: gp(b"_plugin_registercommand\0").map(|p| std::mem::transmute(p)),
            logputs: gp(b"_plugin_logputs\0").map(|p| std::mem::transmute(p)),
        }
    }
}

#[cfg(not(windows))]
pub fn resolve() -> HostFns {
    HostFns::default()
}
