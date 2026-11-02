//! pluginit / plugsetup / plugstop / CBMENUENTRY

use crate::abi::{PlugCbMenuEntry, PlugInit, PlugSetup, PLUG_SDKVERSION};
use crate::commands::COMMAND_SET;
use crate::menus::{MenuSlot, MENU_SET};
use crate::{PLUGIN_NAME, PLUGIN_VERSION};
use std::ffi::CString;
use std::sync::Mutex;

static HANDLE: Mutex<i32> = Mutex::new(0);

fn log_line(msg: &str) {
    let fns = crate::abi::resolve();
    if let Some(lp) = fns.logputs {
        if let Ok(c) = CString::new(msg) {
            unsafe { lp(c.as_ptr()) };
        }
    }
}

#[no_mangle]
pub extern "C" fn pluginit(init: *mut PlugInit) -> bool {
    if init.is_null() {
        return false;
    }
    unsafe {
        (*init).sdk_version = PLUG_SDKVERSION;
        (*init).plugin_version = PLUGIN_VERSION;
        let name = PLUGIN_NAME.as_bytes();
        let n = name.len().min(255);
        (&mut (*init).plugin_name)[..n].copy_from_slice(&name[..n]);
        (*init).plugin_name[n] = 0u8;
        if let Ok(mut h) = HANDLE.lock() {
            *h = (*init).plugin_handle;
        }
    }
    true
}

#[no_mangle]
pub extern "C" fn plugstop() -> bool {
    true
}

#[no_mangle]
pub extern "C" fn plugsetup(setup: *mut PlugSetup) {
    if setup.is_null() {
        return;
    }
    let s = unsafe { &*setup };
    let fns = crate::abi::resolve();
    let handle = HANDLE.lock().map(|h| *h).unwrap_or(0);

    let parent = |slot: MenuSlot| match slot {
        MenuSlot::Plugin => s.h_menu,
        MenuSlot::Disasm => s.h_menu_disasm,
        MenuSlot::Dump => s.h_menu_dump,
        MenuSlot::Stack => s.h_menu_stack,
        MenuSlot::Graph => s.h_menu_graph,
        MenuSlot::Memmap => s.h_menu_memmap,
        MenuSlot::Symmod => s.h_menu_symmod,
    };

    if let Some(add) = fns.menuaddentry {
        let mut last_slot: Option<MenuSlot> = None;
        for e in MENU_SET {
            if last_slot != Some(e.slot) {
                if let Some(sep) = fns.menuaddseparator {
                    if last_slot.is_some() {
                        unsafe { sep(parent(e.slot)) };
                    }
                }
                last_slot = Some(e.slot);
            }
            if let Ok(title) = CString::new(e.title) {
                unsafe { add(parent(e.slot), e.id, title.as_ptr()) };
            }
            if let (Some(hk), Some(sethk)) = (e.hotkey, fns.menuentrysethotkey) {
                if let Ok(h) = CString::new(hk) {
                    unsafe { sethk(handle, e.id, h.as_ptr()) };
                }
            }
        }
    }

    if let Some(reg) = fns.registercommand {
        for c in COMMAND_SET {
            if let Ok(n) = CString::new(c.name) {
                unsafe {
                    reg(handle, n.as_ptr(), cmd_stub, c.debugonly);
                }
            }
        }
    }
    log_line("[Street] v2 native C motor + MCP menus ready");
}

#[no_mangle]
pub extern "C" fn CBMENUENTRY(_cb: i32, info: *mut PlugCbMenuEntry) {
    if info.is_null() {
        return;
    }
    let id = unsafe { (*info).h_entry };
    if let Some(e) = MENU_SET.iter().find(|m| m.id == id) {
        log_line(&format!("[Street] menu {} → {}", e.title.replace('&', ""), e.command));
    }
}

unsafe extern "C" fn cmd_stub(argc: i32, argv: *mut *mut i8) -> bool {
    let name = if argc > 0 && !argv.is_null() {
        unsafe { std::ffi::CStr::from_ptr(*argv) }
            .to_string_lossy()
            .into_owned()
    } else {
        "street".into()
    };
    log_line(&format!("[Street] cmd {name} — use companion `street` CLI / MCP for full lift"));
    true
}
