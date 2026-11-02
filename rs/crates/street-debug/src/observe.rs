//! No-debugger runner. CreateProcess without DEBUG_PROCESS, wait until `.text`
//! fills, RPM the image, list modules. Themida / Hyperion kill a debugger;
//! this path does not attach one.
//!
//! A dump with `.text` Shannon >= 4 is `runtime_dump`, not a cipher decrypt.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use street_core::entropy::shannon;
use street_core::sha256_bytes;
use windows::core::{PCWSTR, PWSTR};
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::ReadProcessMemory;
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, MODULEENTRY32W, TH32CS_SNAPMODULE,
    TH32CS_SNAPMODULE32,
};
use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
use windows::Win32::System::Threading::{
    CreateProcessW, OpenProcess, PROCESS_INFORMATION, PROCESS_QUERY_INFORMATION,
    PROCESS_VM_READ, STARTUPINFOW,
};

const MEM_COMMIT: u32 = 0x1000;
const PAGE_NOACCESS: u32 = 0x01;
const PAGE_GUARD: u32 = 0x100;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserveOptions {
    pub out_dir: PathBuf,
    pub seconds: u64,
    pub image_base: u64,
    pub text_rva: u64,
    pub text_size: u64,
    pub image_size: u64,
}

impl Default for ObserveOptions {
    fn default() -> Self {
        Self {
            out_dir: PathBuf::from("output/observe"),
            seconds: 40,
            image_base: 0x140000000,
            text_rva: 0x1000,
            text_size: 0x10000,
            image_size: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObserveReport {
    pub pid: u32,
    pub unpacked: bool,
    pub text_h: f64,
    pub image_bytes: u64,
    pub image_sha256: String,
    pub modules: Vec<String>,
    pub note: String,
}

pub fn run_observe(exe: &str, opts: &ObserveOptions) -> Result<ObserveReport, String> {
    fs::create_dir_all(&opts.out_dir).map_err(|e| e.to_string())?;
    let wide: Vec<u16> = exe.encode_utf16().chain(std::iter::once(0)).collect();
    let cwd = std::path::Path::new(exe)
        .parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();
    let cwd_wide: Vec<u16> = cwd.encode_utf16().chain(std::iter::once(0)).collect();
    let mut si = STARTUPINFOW::default();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessW(
            PCWSTR(wide.as_ptr()),
            PWSTR::null(),
            None,
            None,
            false,
            windows::Win32::System::Threading::CREATE_NEW_CONSOLE,
            None,
            PCWSTR(cwd_wide.as_ptr()),
            &si,
            &mut pi,
        )
        .map_err(|e| format!("CreateProcessW: {e}"))?;
    }
    let pid = pi.dwProcessId;
    let hp = unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
            .map_err(|e| format!("OpenProcess: {e}"))?
    };

    let text_va = opts.image_base.saturating_add(opts.text_rva);
    let probe_len = opts.text_size.min(0x10000) as usize;
    let deadline = Instant::now() + Duration::from_secs(opts.seconds.max(1));
    let mut text_h = 0.0;
    let mut unpacked = false;
    let mut log = String::new();
    while Instant::now() < deadline {
        if process_gone(hp) {
            log.push_str("target exited before unpack\n");
            break;
        }
        let probe = rpm(hp, text_va, probe_len);
        text_h = shannon(&probe);
        let nz = probe.iter().filter(|b| **b != 0).count();
        log.push_str(&format!("text_h={text_h:.3} nz={nz}\n"));
        if text_h >= 4.0 && nz > probe_len / 8 {
            unpacked = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(300));
    }

    let img_size = if opts.image_size > 0 {
        opts.image_size as usize
    } else {
        remote_image_size(hp, opts.image_base).unwrap_or(0x200000)
    };
    let mut image = Vec::new();
    for _ in 0..8 {
        if process_gone(hp) {
            log.push_str("process gone before image read\n");
            break;
        }
        image = rpm(hp, opts.image_base, img_size);
        if image.len() >= 0x200 && image[0] == b'M' && image[1] == b'Z' {
            break;
        }
        log.push_str(&format!("image read short len={}\n", image.len()));
        std::thread::sleep(Duration::from_millis(200));
    }
    let mz = image.len() >= 2 && image[0] == b'M' && image[1] == b'Z';
    if !mz {
        unpacked = false;
        log.push_str("image is not a PE — probe entropy is not a runtime_dump\n");
    }
    let sha = sha256_bytes(&image);
    let img_path = opts.out_dir.join("image.bin");
    fs::write(&img_path, &image).map_err(|e| e.to_string())?;

    let modules = list_modules(pid);
    let mut md = String::new();
    md.push_str("# observe — no debugger\n\n");
    md.push_str(&format!("pid={pid}\nunpacked={unpacked}\ntext_h={text_h:.3}\n"));
    md.push_str(&format!("image_bytes={}\nsha256={sha}\n\n", image.len()));
    md.push_str("## modules\n\n");
    for m in &modules {
        md.push_str(m);
        md.push('\n');
    }
    md.push_str("\n## probe\n\n```\n");
    md.push_str(&log);
    md.push_str("```\n");
    md.push_str(
        "\nruntime_dump=true only when unpacked=true. No cipher claim.\n\
         Debugger was not attached. IDA: load image.bin as binary, base = image_base.\n",
    );
    fs::write(opts.out_dir.join("OBSERVE.md"), md).ok();
    let report = ObserveReport {
        pid,
        unpacked,
        text_h,
        image_bytes: image.len() as u64,
        image_sha256: sha,
        modules,
        note: "no DEBUG_PROCESS".into(),
    };
    fs::write(
        opts.out_dir.join("OBSERVE.json"),
        serde_json::to_string_pretty(&report).unwrap_or_default(),
    )
    .ok();

    unsafe {
        let _ = CloseHandle(hp);
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
    }
    Ok(report)
}

fn process_gone(hp: HANDLE) -> bool {
    unsafe {
        let mut code = 0u32;
        if windows::Win32::System::Threading::GetExitCodeProcess(hp, &mut code).is_err() {
            return true;
        }
        code != 259 // STILL_ACTIVE
    }
}

fn rpm(hp: HANDLE, addr: u64, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    let mut got = 0usize;
    let chunk = 0x10000usize;
    while got < len {
        let n = (len - got).min(chunk);
        let mut read = 0usize;
        let ok = unsafe {
            ReadProcessMemory(
                hp,
                (addr + got as u64) as *const _,
                out[got..got + n].as_mut_ptr() as *mut _,
                n,
                Some(&mut read),
            )
            .is_ok()
        };
        if !ok || read == 0 {
            break;
        }
        got += read;
        if read < n {
            break;
        }
    }
    out.truncate(got);
    out
}

fn remote_image_size(hp: HANDLE, base: u64) -> Option<usize> {
    let hdr = rpm(hp, base, 0x400);
    if hdr.len() < 0x40 || hdr[0] != b'M' || hdr[1] != b'Z' {
        return None;
    }
    let e_lfanew = u32::from_le_bytes(hdr[0x3c..0x40].try_into().ok()?) as usize;
    if e_lfanew + 0x58 >= hdr.len() {
        return None;
    }
    let size = u32::from_le_bytes(hdr[e_lfanew + 0x50..e_lfanew + 0x54].try_into().ok()?);
    if size == 0 || size > 0x2000_0000 {
        return None;
    }
    let _ = unsafe {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        VirtualQueryEx(
            hp,
            Some(base as *const _),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    let _ = (PAGE_NOACCESS, PAGE_GUARD, MEM_COMMIT);
    Some(size as usize)
}

fn list_modules(pid: u32) -> Vec<String> {
    let mut out = Vec::new();
    unsafe {
        let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if snap.is_err() {
            return out;
        }
        let snap = snap.unwrap();
        let mut me = MODULEENTRY32W::default();
        me.dwSize = std::mem::size_of::<MODULEENTRY32W>() as u32;
        if Module32FirstW(snap, &mut me).is_ok() {
            loop {
                let name = String::from_utf16_lossy(
                    &me.szModule[..me.szModule.iter().position(|c| *c == 0).unwrap_or(me.szModule.len())],
                );
                let path = String::from_utf16_lossy(
                    &me.szExePath[..me.szExePath.iter().position(|c| *c == 0).unwrap_or(me.szExePath.len())],
                );
                out.push(format!(
                    "{name} base={:#x} size={:#x} {path}",
                    me.modBaseAddr as u64, me.modBaseSize
                ));
                if Module32NextW(snap, &mut me).is_err() {
                    break;
                }
            }
        }
        let _ = CloseHandle(snap);
    }
    out
}
