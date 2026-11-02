use crate::DebugSnapshot;
use std::collections::HashMap;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use crate::live::read_mem;
use street_disasm::disassemble;
use street_kernel::KernelClient;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, GetThreadContext, ReadProcessMemory, SetThreadContext, WaitForDebugEvent,
    WriteProcessMemory, CONTEXT, CONTEXT_CONTROL_AMD64, CONTEXT_INTEGER_AMD64,
    CREATE_THREAD_DEBUG_EVENT, DEBUG_EVENT, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
    LOAD_DLL_DEBUG_EVENT,
};
use windows::Win32::System::Memory::{
    VirtualProtectEx, PAGE_EXECUTE_READWRITE, PAGE_GUARD, PAGE_PROTECTION_FLAGS,
};
use windows::Win32::System::Threading::{
    CreateProcessW, ResumeThread, DEBUG_ONLY_THIS_PROCESS, PROCESS_INFORMATION, STARTUPINFOW,
};

const EXCEPTION_BREAKPOINT: i32 = 0x8000_0003u32 as i32;
const EXCEPTION_SINGLE_STEP: i32 = 0x8000_0004u32 as i32;
const EXCEPTION_GUARD_PAGE: i32 = 0x8000_0001u32 as i32;

pub enum DbgCmd {
    Run,
    Step,
    Pause,
    SoftBp(u64),
    Quit,
}

pub struct Debugger {
    pub snap: Arc<Mutex<DebugSnapshot>>,
    tx: std::sync::mpsc::Sender<DbgCmd>,
    _th: JoinHandle<()>,
}

impl Debugger {
    pub fn spawn(path: &str) -> Result<Self, String> {
        let snap = Arc::new(Mutex::new(DebugSnapshot::default()));
        let (tx, rx) = std::sync::mpsc::channel();
        let path = path.to_string();
        let snap2 = snap.clone();
        let th = thread::spawn(move || {
            if let Err(e) = debug_loop(&path, snap2, rx) {
                // swallow into snapshot log if possible
                let _ = e;
            }
        });
        Ok(Self { snap, tx, _th: th })
    }

    pub fn cmd(&self, c: DbgCmd) {
        let _ = self.tx.send(c);
    }

    pub fn snapshot(&self) -> DebugSnapshot {
        self.snap.lock().map(|g| g.clone()).unwrap_or_default()
    }
}

struct Bp {
    orig: u8,
}

fn debug_loop(
    path: &str,
    snap: Arc<Mutex<DebugSnapshot>>,
    rx: std::sync::mpsc::Receiver<DbgCmd>,
) -> Result<(), String> {
    let kernel = KernelClient::open();
    let mut wide: Vec<u16> = OsStr::new(path).encode_wide().collect();
    wide.push(0);
    let mut si = STARTUPINFOW::default();
    si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
    let mut pi = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessW(
            PCWSTR(wide.as_ptr()),
            windows::core::PWSTR::null(),
            None,
            None,
            false,
            DEBUG_ONLY_THIS_PROCESS,
            None,
            None,
            &si,
            &mut pi,
        )
        .map_err(|e| e.to_string())?;
    }
    let hproc = pi.hProcess;
    let mut hthread = pi.hThread;
    let pid = pi.dwProcessId;
    let mut tid = pi.dwThreadId;
    {
        let mut s = snap.lock().unwrap();
        s.pid = pid;
        s.tid = tid;
        s.kernel = kernel.present();
        s.log.push(format!("spawn pid={pid} kernel={}", kernel.present()));
        s.last_event = "create".into();
    }

    let mut bps: HashMap<u64, Bp> = HashMap::new();
    let mut running = false;
    let mut image_base = 0u64;
    let mut stepping = false;
    // Address whose 0xCC must be re-inserted after a single-step past a
    // breakpoint we temporarily removed.
    let mut rearm: Option<u64> = None;

    // Live-dump state: regions already captured, module list, output root.
    // Injection candidates are dumped the first time they are observed.
    let mut live = LiveState {
        modules: Vec::new(),
        seen: std::collections::HashSet::new(),
        root: std::path::PathBuf::from("output")
            .join("livedump")
            .join(pid.to_string()),
        started: std::time::Instant::now(),
    };

    loop {
        while let Ok(c) = rx.try_recv() {
            match c {
                DbgCmd::Quit => {
                    unsafe {
                        let _ = CloseHandle(pi.hThread);
                        let _ = CloseHandle(pi.hProcess);
                    }
                    return Ok(());
                }
                DbgCmd::Run => {
                    running = true;
                    stepping = false;
                    unsafe {
                        let _ = ContinueDebugEvent(pid, tid, DBG_CONTINUE);
                    }
                }
                DbgCmd::Step => {
                    stepping = true;
                    running = true;
                    set_trap(hthread, true);
                    unsafe {
                        let _ = ContinueDebugEvent(pid, tid, DBG_CONTINUE);
                    }
                }
                DbgCmd::Pause => {
                    running = false;
                }
                DbgCmd::SoftBp(addr) => {
                    if let Some(b) = read_u8(hproc, addr, pid, &kernel) {
                        write_u8(hproc, addr, 0xCC);
                        bps.insert(addr, Bp { orig: b });
                        log(&snap, &format!("bp 0x{addr:x}"));
                    } else {
                        // Refuse to arm rather than write 0xCC over a byte we
                        // could not read — the restore would corrupt it.
                        log(&snap, &format!("bp 0x{addr:x} FAILED (unreadable)"));
                    }
                }
            }
        }

        let mut ev = DEBUG_EVENT::default();
        let got = unsafe { WaitForDebugEvent(&mut ev, 80).is_ok() };
        if !got {
            continue;
        }
        pid_tid(&ev, &mut tid);
        let mut cont = DBG_CONTINUE;
        match ev.dwDebugEventCode {
            windows::Win32::System::Diagnostics::Debug::CREATE_PROCESS_DEBUG_EVENT => {
                unsafe {
                    let info = ev.u.CreateProcessInfo;
                    image_base = info.lpBaseOfImage as u64;
                    hthread = info.hThread;
                    let _ = ResumeThread(info.hThread);
                    // PAGE_GUARD on virtual-only is applied by host after classify; here we tag base
                    install_guard_text(hproc, image_base, &snap);
                }
                log(&snap, &format!("image_base=0x{image_base:x}"));
                refresh(&snap, hproc, hthread, pid, tid, image_base, &kernel, false);
                auto_scan_dump(&snap, hproc, pid, &kernel, &mut live);
                running = false; // pause at system BP like x64dbg
            }
            EXCEPTION_DEBUG_EVENT => {
                let code = unsafe { ev.u.Exception.ExceptionRecord.ExceptionCode.0 };
                let addr = unsafe { ev.u.Exception.ExceptionRecord.ExceptionAddress as u64 };
                if code == EXCEPTION_BREAKPOINT {
                    if let Some(bp) = bps.get(&addr) {
                        let orig = bp.orig;
                        // Remove the trap, rewind RIP so the original
                        // instruction actually executes, then single-step in
                        // order to re-arm. Without the rewind the instruction
                        // under the breakpoint would be skipped entirely.
                        write_u8(hproc, addr, orig);
                        step_back_rip(hthread);
                        set_trap(hthread, true);
                        rearm = Some(addr);
                        log(&snap, &format!("bp hit 0x{addr:x}"));
                    } else {
                        // System breakpoint at process start — nothing to rewind.
                        log(&snap, &format!("bp hit 0x{addr:x} (system)"));
                    }
                    refresh(&snap, hproc, hthread, pid, tid, image_base, &kernel, true);
                    running = false;
                    continue; // hold the event: wait for Run/Step
                } else if code == EXCEPTION_SINGLE_STEP {
                    set_trap(hthread, false);
                    if let Some(a) = rearm.take() {
                        write_u8(hproc, a, 0xCC);
                        log(&snap, &format!("bp re-armed 0x{a:x}"));
                        refresh(&snap, hproc, hthread, pid, tid, image_base, &kernel, true);
                        // This trap was ours, not a user Step — resume so one
                        // Run gets past the breakpoint.
                        running = true;
                        unsafe {
                            let _ = ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                        }
                        continue;
                    }
                    refresh(&snap, hproc, hthread, pid, tid, image_base, &kernel, true);
                    running = false;
                    stepping = false;
                    continue;
                } else if code == EXCEPTION_GUARD_PAGE {
                    log(&snap, &format!("OEP/guard 0x{addr:x}"));
                    refresh(&snap, hproc, hthread, pid, tid, image_base, &kernel, true);
                    // OEP is where a packer has finished unpacking — the most
                    // valuable moment to capture the now-live .text.
                    auto_scan_dump(&snap, hproc, pid, &kernel, &mut live);
                    running = false;
                    continue;
                } else {
                    cont = DBG_EXCEPTION_NOT_HANDLED;
                    log(&snap, &format!("ex 0x{code:x} @ 0x{addr:x}"));
                }
            }
            LOAD_DLL_DEBUG_EVENT => {
                let base = unsafe { ev.u.LoadDll.lpBaseOfDll as u64 };
                // Refresh first: the newly loaded module is only in the list
                // after the snapshot is retaken.
                live.modules = crate::live::enumerate_user_modules(pid);
                let name = live
                    .modules
                    .iter()
                    .find(|m| m.base == base)
                    .map(|m| m.name.clone())
                    .unwrap_or_else(|| format!("0x{base:x}"));
                log(&snap, &format!("dll 0x{base:x} {name}"));
                auto_scan_dump(&snap, hproc, pid, &kernel, &mut live);
            }
            CREATE_THREAD_DEBUG_EVENT => {
                let start = unsafe { ev.u.CreateThread.lpStartAddress }
                    .map(|f| f as usize as u64)
                    .unwrap_or(0);
                log(&snap, &format!("thread tid={tid} start=0x{start:x}"));
                // A thread whose start address is not inside a mapped image is a
                // strong remote-injection signal — scan immediately.
                auto_scan_dump(&snap, hproc, pid, &kernel, &mut live);
            }
            EXIT_PROCESS_DEBUG_EVENT => {
                log(&snap, "process exit");
                refresh(&snap, hproc, hthread, pid, tid, image_base, &kernel, false);
                unsafe {
                    let _ = ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                }
                return Ok(());
            }
            _ => {}
        }
        if running {
            unsafe {
                let _ = ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
            }
        } else {
            // hold the event: x64dbg pauses. We already continued only on Run.
            // If we don't continue, WaitForDebugEvent blocks the process — good pause.
            // Store pending? For simplicity continue on pause after refresh except we already returned on BP.
            unsafe {
                let _ = ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
            }
        }
        let _ = stepping;
        let _ = hthread;
    }
}

fn pid_tid(ev: &DEBUG_EVENT, tid: &mut u32) {
    *tid = ev.dwThreadId;
}

fn log(snap: &Arc<Mutex<DebugSnapshot>>, m: &str) {
    if let Ok(mut s) = snap.lock() {
        s.log.push(m.into());
        if s.log.len() > 400 {
            let n = s.log.len() - 300;
            s.log.drain(0..n);
        }
        s.last_event = m.into();
    }
}

fn refresh(
    snap: &Arc<Mutex<DebugSnapshot>>,
    hproc: HANDLE,
    hthread: HANDLE,
    pid: u32,
    tid: u32,
    image_base: u64,
    kernel: &KernelClient,
    at_rip: bool,
) {
    let mut ctx = CONTEXT::default();
    ctx.ContextFlags = CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64;
    let ok = unsafe { GetThreadContext(hthread, &mut ctx).is_ok() };
    let rip = if ok { ctx.Rip } else { 0 };
    let mut cpu = Vec::new();
    if at_rip || rip != 0 {
        let mut buf = [0u8; 64];
        read_mem(hproc, pid, rip, &mut buf, kernel);
        let d = disassemble(&buf, rip, street_core::Arch::X64, false, 12);
        cpu = d
            .instructions
            .iter()
            .map(|i| format!("{:x}: {} {}", i.addr, i.mnemonic, i.op_str))
            .collect();
    }
    let mut dump = vec![0u8; 256];
    let dump_base = if ok { ctx.Rsp } else { image_base };
    read_mem(hproc, pid, dump_base, &mut dump, kernel);
    if let Ok(mut s) = snap.lock() {
        s.pid = pid;
        s.tid = tid;
        s.image_base = image_base;
        s.kernel = kernel.present();
        if ok {
            s.rip = ctx.Rip;
            s.rsp = ctx.Rsp;
            s.rax = ctx.Rax;
            s.rcx = ctx.Rcx;
            s.rdx = ctx.Rdx;
            s.rbx = ctx.Rbx;
            s.rbp = ctx.Rbp;
            s.rsi = ctx.Rsi;
            s.rdi = ctx.Rdi;
            s.r8 = ctx.R8;
            s.r9 = ctx.R9;
        }
        s.cpu = cpu;
        s.dump = dump;
        s.dump_base = dump_base;
        s.running = false;
    }
}

fn read_u8(hproc: HANDLE, addr: u64, pid: u32, kernel: &KernelClient) -> Option<u8> {
    let mut b = [0u8; 1];
    // Distinguish "the byte is 0x00" from "the read failed". Returning a
    // fabricated 0x00 here would be written back to the target on breakpoint
    // restore, silently corrupting the instruction.
    if read_mem(hproc, pid, addr, &mut b, kernel) == 1 {
        Some(b[0])
    } else {
        None
    }
}

/// Rewind RIP by one byte so the instruction under a removed 0xCC re-executes.
/// The CPU advances RIP past the `int3` before reporting the exception.
fn step_back_rip(hthread: HANDLE) {
    let mut ctx = CONTEXT::default();
    ctx.ContextFlags = CONTEXT_CONTROL_AMD64;
    unsafe {
        if GetThreadContext(hthread, &mut ctx).is_ok() {
            ctx.Rip = ctx.Rip.wrapping_sub(1);
            let _ = SetThreadContext(hthread, &ctx);
        }
    }
}

fn write_u8(hproc: HANDLE, addr: u64, v: u8) {
    let b = [v];
    let mut n = 0usize;
    unsafe {
        let _ = WriteProcessMemory(hproc, addr as *mut _, b.as_ptr().cast(), 1, Some(&mut n));
    }
}

fn set_trap(hthread: HANDLE, on: bool) {
    let mut ctx = CONTEXT::default();
    ctx.ContextFlags = CONTEXT_CONTROL_AMD64;
    unsafe {
        if GetThreadContext(hthread, &mut ctx).is_ok() {
            if on {
                ctx.EFlags |= 0x100;
            } else {
                ctx.EFlags &= !0x100;
            }
            let _ = SetThreadContext(hthread, &ctx);
        }
    }
}

fn install_guard_text(hproc: HANDLE, base: u64, snap: &Arc<Mutex<DebugSnapshot>>) {
    // Guard first 0x1000 of .text guess (base+0x1000). Real section walk needs RPM of headers.
    let mut hdr = [0u8; 0x400];
    let mut n = 0usize;
    let ok = unsafe {
        ReadProcessMemory(hproc, base as *const _, hdr.as_mut_ptr().cast(), hdr.len(), Some(&mut n)).is_ok()
    };
    if !ok {
        return;
    }
    let Ok(img) = street_core::pe::parse_pe(&hdr) else {
        return;
    };
    for sec in &img.sections {
        if sec.virtual_only() && sec.vsize > 0 {
            let va = base + sec.va as u64;
            let sz = sec.vsize.max(0x1000) as usize;
            let mut old = PAGE_PROTECTION_FLAGS(0);
            let ok = unsafe {
                VirtualProtectEx(
                    hproc,
                    va as *const _,
                    sz,
                    PAGE_EXECUTE_READWRITE | PAGE_GUARD,
                    &mut old,
                )
                .is_ok()
            };
            if ok {
                log(snap, &format!("guard {} @ 0x{va:x}", sec.name));
            }
        }
    }
}

/// Mutable state for the live-dump scanner. Kept in one struct so the call
/// sites stay readable.
struct LiveState {
    modules: Vec<crate::live::UserModule>,
    /// Keyed on `(base, size)` so a region reallocated at the same base, or one
    /// extended in place, is not silently dropped as already-seen.
    seen: std::collections::HashSet<(u64, u64)>,
    root: std::path::PathBuf,
    started: std::time::Instant,
}

/// Scan the target for private executable regions and dump any that are new.
///
/// This is the "dump everything injected or downloaded" path: a region that is
/// private + executable and was absent at the previous scan was, by
/// construction, created at runtime — by the target itself, by a packer, or by
/// an external injector writing into the process.
fn auto_scan_dump(
    snap: &Arc<Mutex<DebugSnapshot>>,
    hproc: HANDLE,
    pid: u32,
    kernel: &KernelClient,
    live: &mut LiveState,
) {
    if live.modules.is_empty() {
        live.modules = crate::live::enumerate_user_modules(pid);
    }
    // Publish the module list to the snapshot — the field existed but was never
    // populated, so the UI had no way to show what was loaded.
    if let Ok(mut s) = snap.lock() {
        s.modules = live
            .modules
            .iter()
            .map(|m| format!("{:x} {}", m.base, m.name))
            .collect();
    }
    let regions = crate::live::scan_regions(hproc, pid, kernel, &live.modules);
    // Clone the root so the capture context does not borrow `live`, which the
    // loop mutates through `live.seen`.
    let root = live.root.clone();
    let ctx = crate::live::CaptureCtx {
        hproc,
        pid,
        kernel,
        root: &root,
        max_region: 8 * 1024 * 1024,
    };
    let mut idx = live.seen.len();
    for r in regions.iter().filter(|r| r.kind.is_injection_candidate()) {
        if r.size < 0x40 || !live.seen.insert((r.base, r.size)) {
            continue;
        }
        let first_seen = live.started.elapsed().as_millis() as u64;
        if let Some(a) = ctx.dump_region(r, idx, first_seen) {
            idx += 1;
            log(
                snap,
                &format!(
                    "DUMP 0x{:x} size=0x{:x} H={:.2} pe={}{} -> {}",
                    a.base,
                    a.size,
                    a.entropy,
                    a.pe,
                    if a.partial { " PARTIAL" } else { "" },
                    a.file
                ),
            );
        }
    }
}
