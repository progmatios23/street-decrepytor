//! Live execution tracing — API call, module, thread and child-process events.
//!
//! Runs a target under the debugger and records what it calls, from initial
//! load through to shellcode execution. The observable surface from user mode
//! is the **API call**: syscalls themselves are not directly visible, and
//! direct-syscall stubs bypass the DLLs entirely.
//!
//! Mechanism: resolve the target's Import Address Table at runtime, breakpoint
//! the resolved function addresses, and on each hit record the arguments plus
//! the caller. Because the caller's return address is on the stack at entry, we
//! can tell whether a call came from inside a mapped image or from a private
//! executable region — which is the shellcode-execution signal.
//!
//! Honesty (CRITICAL.md, docs/LIVE_DUMP.md): a trace records what was observed.
//! An incomplete or empty trace declares itself incomplete via the `Coverage`
//! block; it never reads as "the target did nothing".

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use street_kernel::KernelClient;
use windows::Win32::Foundation::{CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, GetThreadContext, SetThreadContext, WaitForDebugEvent, WriteProcessMemory,
    CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, CONTEXT, CONTEXT_CONTROL_AMD64,
    CONTEXT_DEBUG_REGISTERS_AMD64, CONTEXT_INTEGER_AMD64, DEBUG_EVENT, DebugActiveProcessStop,
    EXCEPTION_DEBUG_EVENT,
    EXIT_PROCESS_DEBUG_EVENT,
    LOAD_DLL_DEBUG_EVENT,
};
use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
use windows::Win32::System::Threading::{
    CreateProcessW, OpenThread, ResumeThread, TerminateProcess, DEBUG_ONLY_THIS_PROCESS,
    PROCESS_INFORMATION, STARTUPINFOW, THREAD_GET_CONTEXT, THREAD_SET_CONTEXT,
    THREAD_SUSPEND_RESUME,
};

use crate::live::{enumerate_user_modules, read_mem, Coverage, UserModule};

const EXCEPTION_BREAKPOINT: i32 = 0x8000_0003u32 as i32;
const EXCEPTION_SINGLE_STEP: i32 = 0x8000_0004u32 as i32;

// ---------------------------------------------------------------------------
// API categorisation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApiCategory {
    Memory,
    Module,
    Process,
    File,
    Network,
    Registry,
    Crypto,
    Sync,
    /// Dialogs and window management. An unexpected `MessageBox` from a binary
    /// that has no UI is a strong signal, and its text is often the only
    /// human-readable explanation of why the program stopped.
    Ui,
    /// Calls whose normal use is debugger or sandbox detection.
    AntiDebug,
    Other,
}

impl ApiCategory {
    pub fn label(self) -> &'static str {
        match self {
            ApiCategory::Memory => "memory",
            ApiCategory::Module => "module",
            ApiCategory::Process => "process",
            ApiCategory::File => "file",
            ApiCategory::Network => "network",
            ApiCategory::Registry => "registry",
            ApiCategory::Crypto => "crypto",
            ApiCategory::Sync => "sync",
            ApiCategory::Ui => "ui",
            ApiCategory::AntiDebug => "anti_debug",
            ApiCategory::Other => "other",
        }
    }

    /// Categories traced by default.
    ///
    /// A 45 MB packed binary resolves a very large import surface; tracing all
    /// of it is neither useful nor survivable. The default set is the one that
    /// answers "what is this binary doing".
    ///
    /// `Ui` and `AntiDebug` are included deliberately. Leaving them out — as an
    /// earlier revision did, by lumping them into `Other` — meant the tracer
    /// missed the single most informative event a protector produces: the
    /// anti-debug dialog. The unusual calls are exactly the ones worth seeing.
    pub fn default_traced(self) -> bool {
        !matches!(self, ApiCategory::Other)
    }

    /// Arming priority, lowest first.
    ///
    /// The breakpoint budget is finite and a large module like `ntdll` alone
    /// exports more candidates than the whole budget. Without ordering, ntdll
    /// consumes it and `user32`'s dialog APIs are never armed — which is
    /// precisely how an anti-debug `MessageBox` went unrecorded on the first
    /// attempt. The high-signal categories are therefore armed first.
    pub fn priority(self) -> u8 {
        match self {
            ApiCategory::AntiDebug => 0,
            ApiCategory::Ui => 1,
            ApiCategory::Process => 2,
            ApiCategory::Memory => 3,
            ApiCategory::Module => 4,
            ApiCategory::Network => 5,
            ApiCategory::File => 6,
            ApiCategory::Registry => 7,
            ApiCategory::Crypto => 8,
            ApiCategory::Sync => 9,
            ApiCategory::Other => 10,
        }
    }
}

/// Map an imported function to a category by name. Heuristic and deliberately
/// conservative: an unrecognised name is `Other`, which is not traced by
/// default rather than being silently mislabelled.
pub fn classify_api(dll: &str, func: &str) -> ApiCategory {
    let f = func.to_ascii_lowercase();
    let d = dll.to_ascii_lowercase();

    // Anti-debug names are specific enough to check first, so they do not fall
    // into a broader bucket. Deliberately excluded: GetTickCount and
    // QueryPerformanceCounter — every program calls those, and classifying them
    // as detection would flood the trace with noise.
    if f.contains("isdebuggerpresent")
        || f.contains("checkremotedebuggerpresent")
        || f.contains("ntqueryinformationprocess")
        || f.contains("ntsetinformationthread")
        || f.contains("ntqueryobject")
        || f.contains("outputdebugstring")
        || f.contains("blockinput")
        || f.contains("findwindow")
    {
        return ApiCategory::AntiDebug;
    }
    // Dialogs. An unexpected MessageBox from a binary with no UI is a signal,
    // and its text is often the only readable explanation of what happened.
    if f.contains("messagebox")
        || f.contains("dialogbox")
        || f.contains("createwindow")
        || f.contains("showwindow")
        || f.contains("setwindowtext")
    {
        return ApiCategory::Ui;
    }

    if f.contains("virtualalloc")
        || f.contains("virtualprotect")
        || f.contains("virtualfree")
        || f.contains("writeprocessmemory")
        || f.contains("readprocessmemory")
        || f.contains("mapviewoffile")
        || f.contains("createfilemapping")
        || f.contains("allocatevirtualmemory")
        || f.contains("protectvirtualmemory")
        || f.contains("ntmapviewofsection")
        || f.contains("virtualquery")
    {
        return ApiCategory::Memory;
    }
    if f.contains("loadlibrary")
        || f.contains("getprocaddress")
        || f.contains("freelibrary")
        || f.contains("ldrloaddll")
        || f.contains("ldrgetprocedureaddress")
    {
        return ApiCategory::Module;
    }
    if f.contains("createprocess")
        || f.contains("openprocess")
        || f.contains("createremotethread")
        || f.contains("createthread")
        || f.contains("resumethread")
        || f.contains("suspendthread")
        || f.contains("terminateprocess")
        || f.contains("ntcreatethreadex")
        || f.contains("queueuserapc")
        || f.contains("setthreadcontext")
        || f.contains("wow64setthreadcontext")
    {
        return ApiCategory::Process;
    }
    if f.contains("createfile")
        || f.contains("writefile")
        || f.contains("readfile")
        || f.contains("deletefile")
        || f.contains("movefile")
        || f.contains("copyfile")
        || f.contains("setfilepointer")
        || f.contains("findfirstfile")
        || f.contains("createdirectory")
        || f.contains("ntcreatefile")
        || f.contains("ntwritefile")
    {
        return ApiCategory::File;
    }
    if f.contains("internetopen")
        || f.contains("internetconnect")
        || f.contains("internetreadfile")
        || f.contains("httpopenrequest")
        || f.contains("httpsendrequest")
        || f.contains("winhttp")
        || f.contains("wsastartup")
        || f.contains("wsasocket")
        || f.contains("getaddrinfo")
        || f.contains("dnsquery")
    {
        return ApiCategory::Network;
    }
    // Bare socket verbs only when the DLL is a socket library — `send`/`recv`
    // appear in unrelated DLLs.
    if (d.contains("ws2_32") || d.contains("wsock32"))
        && (f == "connect" || f == "send" || f == "recv" || f == "sendto" || f == "recvfrom")
    {
        return ApiCategory::Network;
    }
    if f.contains("regcreatekey")
        || f.contains("regsetvalue")
        || f.contains("regopenkey")
        || f.contains("regdeletekey")
        || f.contains("ntopenkey")
        || f.contains("ntsetvaluekey")
    {
        return ApiCategory::Registry;
    }
    if f.starts_with("crypt") || f.starts_with("bcrypt") || f.contains("ncrypt") {
        return ApiCategory::Crypto;
    }
    if f.contains("createmutex")
        || f.contains("createevent")
        || f.contains("waitforsingleobject")
        || f.contains("createsemaphore")
    {
        return ApiCategory::Sync;
    }
    ApiCategory::Other
}

// ---------------------------------------------------------------------------
// Runtime IAT walk
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IatSlot {
    pub dll: String,
    pub function: String,
    pub iat_addr: u64,
    pub target_addr: u64,
    pub category: ApiCategory,
}

fn rd_u16(hproc: HANDLE, pid: u32, addr: u64, k: &KernelClient) -> Option<u16> {
    let mut b = [0u8; 2];
    if read_mem(hproc, pid, addr, &mut b, k) == 2 {
        Some(u16::from_le_bytes(b))
    } else {
        None
    }
}

fn rd_u32(hproc: HANDLE, pid: u32, addr: u64, k: &KernelClient) -> Option<u32> {
    let mut b = [0u8; 4];
    if read_mem(hproc, pid, addr, &mut b, k) == 4 {
        Some(u32::from_le_bytes(b))
    } else {
        None
    }
}

fn rd_u64(hproc: HANDLE, pid: u32, addr: u64, k: &KernelClient) -> Option<u64> {
    let mut b = [0u8; 8];
    if read_mem(hproc, pid, addr, &mut b, k) == 8 {
        Some(u64::from_le_bytes(b))
    } else {
        None
    }
}

/// Read a NUL-terminated string from a **trusted** location — the import
/// directory of a mapped image, whose RVAs are bounded by the loader. Not for
/// arbitrary register arguments: use `safe_preview` for those.
fn rd_cstr(hproc: HANDLE, pid: u32, addr: u64, max: usize, k: &KernelClient) -> Option<String> {
    let mut buf = vec![0u8; max];
    let n = read_mem(hproc, pid, addr, &mut buf, k);
    if n == 0 {
        return None;
    }
    buf.truncate(n);
    let end = buf.iter().position(|&c| c == 0).unwrap_or(buf.len());
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&buf[..end]).to_string())
}

/// What an argument pointer points at, when it is safe to look.
///
/// A readable pointer to non-printable bytes is still evidence — a key, a blob,
/// a decrypted buffer — so it is reported as bounded hex rather than discarded.
/// `None` is reserved for memory that genuinely cannot be read.
#[derive(Debug, Clone)]
pub struct Preview {
    /// A clean printable-ASCII run, when the bytes are text.
    pub text: Option<String>,
    /// Bounded hex of the same span — always present when the read succeeded.
    pub hex: String,
}

/// The number of bytes that may safely be read starting at `addr`, bounded by
/// both `max` and the end of the containing region.
///
/// A register argument can be anything: an integer that happens to look like an
/// address, a handle, a length, or a pointer into uncommitted, guarded or
/// unreadable memory. Dereferencing it blindly can fault the tracer or splice
/// bytes from an unrelated region into the log. This gate is what makes "safe to
/// read" a decidable question rather than a guess.
fn safe_span(hproc: HANDLE, addr: u64, max: usize) -> Option<usize> {
    const MEM_COMMIT: u32 = 0x1000;
    const PAGE_NOACCESS: u32 = 0x01;
    const PAGE_GUARD: u32 = 0x100;

    // Values below the minimum user address are never pointers.
    if addr < 0x1_0000 {
        return None;
    }
    let mut mbi = MEMORY_BASIC_INFORMATION::default();
    let n = unsafe {
        VirtualQueryEx(
            hproc,
            Some(addr as *const _),
            &mut mbi,
            std::mem::size_of::<MEMORY_BASIC_INFORMATION>(),
        )
    };
    if n == 0 || mbi.State.0 != MEM_COMMIT {
        return None;
    }
    let prot = mbi.Protect.0;
    if prot & PAGE_NOACCESS != 0 || prot & PAGE_GUARD != 0 {
        return None;
    }
    // Never read past the end of the region the pointer starts in.
    let region_end = (mbi.BaseAddress as u64).saturating_add(mbi.RegionSize as u64);
    let span = (max as u64).min(region_end.saturating_sub(addr));
    if span < 4 {
        return None;
    }
    Some(span as usize)
}

/// Read a bounded UTF-16 string under the same safety gate as `safe_preview`.
///
/// `MessageBoxW` and its relatives take wide strings, and a protector's dialog
/// text is frequently the only human-readable statement of why a program
/// stopped — the anti-debug message being the canonical example.
fn safe_preview_wide(
    hproc: HANDLE,
    pid: u32,
    addr: u64,
    max_chars: usize,
    kernel: &KernelClient,
) -> Option<String> {
    let span = safe_span(hproc, addr, max_chars * 2)?;
    let mut buf = vec![0u8; span];
    let got = read_mem(hproc, pid, addr, &mut buf, kernel);
    if got < 8 {
        return None;
    }
    buf.truncate(got);
    let units: Vec<u16> = buf
        .chunks(2)
        .filter(|c| c.len() == 2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    let end = units.iter().position(|&c| c == 0).unwrap_or(units.len());
    if end < 3 {
        return None;
    }
    let s = String::from_utf16_lossy(&units[..end]);
    let t = s.trim();
    if t.len() < 3 || t.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(t.to_string())
}

/// Extract the text and caption from a `MessageBox`-family call.
///
/// Signature is `MessageBoxA/W(hWnd, lpText, lpCaption, uType)`, so under the
/// x64 fastcall convention the text is in RDX and the caption in R8 — indices 1
/// and 2 of the captured argument vector.
fn message_box_text(
    hproc: HANDLE,
    pid: u32,
    func: &str,
    args: &[u64],
    kernel: &KernelClient,
) -> Option<String> {
    let wide = func.to_ascii_lowercase().ends_with('w');
    let text_ptr = args.get(1).copied().unwrap_or(0);
    let caption_ptr = args.get(2).copied().unwrap_or(0);

    let text = if wide {
        safe_preview_wide(hproc, pid, text_ptr, 260, kernel)
    } else {
        safe_preview(hproc, pid, text_ptr, 260, kernel).and_then(|p| p.text)
    };
    let caption = if wide {
        safe_preview_wide(hproc, pid, caption_ptr, 128, kernel)
    } else {
        safe_preview(hproc, pid, caption_ptr, 128, kernel).and_then(|p| p.text)
    };

    match (text, caption) {
        (Some(t), Some(c)) => Some(format!("\"{t}\" [{c}]")),
        (Some(t), None) => Some(format!("\"{t}\"")),
        _ => None,
    }
}

/// Read a bounded preview of what an argument points at — but only when it is
/// safe to.
///
/// A register argument can be anything: an integer that happens to look like an
/// address, a handle, a length, or a pointer into uncommitted, guarded or
/// unreadable memory. Dereferencing it blindly can fault the tracer or splice
/// bytes from an unrelated region into the log. The read is therefore gated on
/// `VirtualQueryEx`: the target must be committed, readable, not guarded, and
/// the whole bounded span must lie inside a single region.
fn safe_preview(
    hproc: HANDLE,
    pid: u32,
    addr: u64,
    max: usize,
    kernel: &KernelClient,
) -> Option<Preview> {
    let span = safe_span(hproc, addr, max)?;

    let mut buf = vec![0u8; span];
    let got = read_mem(hproc, pid, addr, &mut buf, kernel);
    if got == 0 {
        return None;
    }
    buf.truncate(got);

    // Bounded hex is available whenever the read succeeded. A pointer to a key,
    // a decrypted blob or a packed buffer is evidence even when it is not text,
    // so it is recorded rather than discarded.
    let hex: String = buf.iter().take(32).map(|b| format!("{b:02x}")).collect();

    // Text only when there is a terminator inside the span AND the run is
    // printable ASCII. A pointer argument is frequently a handle, a module base
    // or an address, and lossy decoding of arbitrary bytes can look like a
    // string — a module base previewed as "MZ" is noise, not evidence.
    let text = buf
        .iter()
        .position(|&c| c == 0)
        .filter(|&end| end >= 4 && buf[..end].iter().all(|b| (0x20..0x7f).contains(b)))
        .map(|end| String::from_utf8_lossy(&buf[..end]).to_string());

    Some(Preview { text, hex })
}

/// Open the faulting thread for context access. Caller must close the handle.
fn open_thread(tid: u32) -> HANDLE {
    unsafe {
        OpenThread(
            THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME,
            false,
            tid,
        )
        .unwrap_or(HANDLE(std::ptr::null_mut()))
    }
}

/// Diagnostic for the IAT walk. An empty result must be explicable: "the image
/// has no imports" and "the walk could not read the headers" look identical
/// from the outside otherwise.
pub fn iat_diag(hproc: HANDLE, pid: u32, base: u64, kernel: &KernelClient) -> String {
    let e = match rd_u32(hproc, pid, base + 0x3C, kernel) {
        Some(v) => v as u64,
        None => return format!("e_lfanew unreadable at base+0x3C (base=0x{base:x})"),
    };
    let nth = base + e;
    let sig = rd_u32(hproc, pid, nth, kernel);
    let opt = nth + 0x18;
    let magic = rd_u16(hproc, pid, opt, kernel);
    let is_64 = magic == Some(0x20B);
    let dd = if is_64 { opt + 0x70 } else { opt + 0x60 };
    let imp = rd_u32(hproc, pid, dd + 8, kernel);
    let size = rd_u32(hproc, pid, dd + 12, kernel);
    format!(
        "e_lfanew=0x{e:x} sig={sig:?} magic={magic:?} pe32plus={is_64} \
         import_rva={imp:?} import_size={size:?}"
    )
}

/// The VA of the image's declared entry point, read from the live header.
fn entry_va_of(hproc: HANDLE, pid: u32, base: u64, kernel: &KernelClient) -> Option<u64> {
    let e = rd_u32(hproc, pid, base + 0x3C, kernel)? as u64;
    let aep = rd_u32(hproc, pid, base + e + 0x18 + 16, kernel)?;
    Some(base + aep as u64)
}

/// Probe what is **actually mapped** at the target's entry point.
///
/// A packed binary can point `AddressOfEntryPoint` at memory that is not
/// executable code at load time — or at bytes that differ from what the section
/// table implies. Reading the bytes from the live process, rather than from the
/// file on disk, is the only way to tell which. This turns "the entry looks
/// encrypted on disk" into an observation instead of an inference.
pub fn entry_probe(hproc: HANDLE, pid: u32, base: u64, kernel: &KernelClient) -> String {
    let e = match rd_u32(hproc, pid, base + 0x3C, kernel) {
        Some(v) => v as u64,
        None => return "entry probe: e_lfanew unreadable".into(),
    };
    let opt = base + e + 0x18;
    let aep = match rd_u32(hproc, pid, opt + 16, kernel) {
        Some(v) => v,
        None => return "entry probe: AddressOfEntryPoint unreadable".into(),
    };
    let va = base + aep as u64;
    let mut buf = [0u8; 16];
    let n = read_mem(hproc, pid, va, &mut buf, kernel);
    let hex = buf[..n.min(16)]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(" ");
    format!(
        "entry probe: AddressOfEntryPoint=0x{aep:x} va=0x{va:x} read={n}/16 bytes=[{hex}]"
    )
}

/// Walk a loaded module's **export** directory and return `(name, address)` for
/// each named export.
///
/// This exists because arming only from the main image's IAT is not enough. A
/// packed binary typically imports almost nothing statically and resolves
/// everything at runtime with `LoadLibraryA` + `GetProcAddress`; its IAT is a
/// bootstrap stub with a handful of slots. Arming by export instead means a
/// traced API is caught no matter how the target obtained its address —
/// `GetProcAddress`, a manual map, or a delay-load thunk.
pub fn read_exports(
    hproc: HANDLE,
    pid: u32,
    base: u64,
    kernel: &KernelClient,
    max: usize,
) -> Vec<(String, u64)> {
    let mut out = Vec::new();

    let e_lfanew = match rd_u32(hproc, pid, base + 0x3C, kernel) {
        Some(v) => v as u64,
        None => return out,
    };
    let opt = base + e_lfanew + 0x18;
    let magic = match rd_u16(hproc, pid, opt, kernel) {
        Some(m) => m,
        None => return out,
    };
    let is_64 = magic == 0x20B;
    let dd = if is_64 { opt + 0x70 } else { opt + 0x60 };

    let exp_rva = match rd_u32(hproc, pid, dd, kernel) {
        Some(v) if v != 0 => v as u64,
        _ => return out,
    };
    let dir = base + exp_rva;

    let num_names = match rd_u32(hproc, pid, dir + 0x18, kernel) {
        Some(v) => v as u64,
        None => return out,
    };
    let addr_funcs = match rd_u32(hproc, pid, dir + 0x1C, kernel) {
        Some(v) => v as u64,
        None => return out,
    };
    let addr_names = match rd_u32(hproc, pid, dir + 0x20, kernel) {
        Some(v) => v as u64,
        None => return out,
    };
    let addr_ord = match rd_u32(hproc, pid, dir + 0x24, kernel) {
        Some(v) => v as u64,
        None => return out,
    };

    for i in 0..num_names.min(max as u64) {
        let name_rva = match rd_u32(hproc, pid, base + addr_names + i * 4, kernel) {
            Some(v) => v as u64,
            None => break,
        };
        let name = match rd_cstr(hproc, pid, base + name_rva, 128, kernel) {
            Some(n) => n,
            None => continue,
        };
        let ordinal = match rd_u16(hproc, pid, base + addr_ord + i * 2, kernel) {
            Some(v) => v as u64,
            None => break,
        };
        // Export address table entries are 4-byte RVAs in both PE32 and PE32+,
        // so there is no 32/64 branch to make here.
        let func_rva = rd_u32(hproc, pid, base + addr_funcs + ordinal * 4, kernel);
        let Some(rva) = func_rva else { continue };
        if rva == 0 {
            continue;
        }
        // Forwarded exports point inside the export directory, not at code.
        if (rva as u64) >= exp_rva && (rva as u64) < exp_rva + 0x10000 {
            continue;
        }
        out.push((name, base + rva as u64));
    }
    out
}

/// Walk the loaded image's import directory in the target's memory.
///
/// The image is mapped, so directory RVAs are direct offsets from the module
/// base — no file-offset translation is involved. `OriginalFirstThunk` still
/// holds the name RVAs (the loader rewrites `FirstThunk`), so names come from
/// the ILT and resolved addresses from the IAT.
pub fn read_iat(
    hproc: HANDLE,
    pid: u32,
    base: u64,
    kernel: &KernelClient,
    max_slots: usize,
) -> Vec<IatSlot> {
    let mut out = Vec::new();

    let e_lfanew = match rd_u32(hproc, pid, base + 0x3C, kernel) {
        Some(v) => v as u64,
        None => return out,
    };
    let nth = base + e_lfanew;
    if rd_u32(hproc, pid, nth, kernel) != Some(0x0000_4550) {
        return out;
    }
    let opt = nth + 0x18;
    // Magic is a u16. Reading it as a u32 drags in the two following bytes
    // (MajorLinkerVersion/MinorLinkerVersion) and the comparison always fails.
    let magic = match rd_u16(hproc, pid, opt, kernel) {
        Some(m) => m,
        None => return out,
    };
    let is_64 = magic == 0x20B;
    // DataDirectory starts at +0x70 (PE32+) or +0x60 (PE32).
    let dd = if is_64 { opt + 0x70 } else { opt + 0x60 };
    let import_rva = match rd_u32(hproc, pid, dd + 8, kernel) {
        Some(v) => v as u64,
        None => return out,
    };
    if import_rva == 0 {
        return out;
    }

    let mut desc = base + import_rva;
    for _ in 0..512 {
        if out.len() >= max_slots {
            break;
        }
        let oft = match rd_u32(hproc, pid, desc, kernel) {
            Some(v) => v as u64,
            None => break,
        };
        let name_rva = match rd_u32(hproc, pid, desc + 12, kernel) {
            Some(v) => v as u64,
            None => break,
        };
        let ft = match rd_u32(hproc, pid, desc + 16, kernel) {
            Some(v) => v as u64,
            None => break,
        };
        if oft == 0 && name_rva == 0 && ft == 0 {
            break;
        }
        let dll = rd_cstr(hproc, pid, base + name_rva, 128, kernel)
            .unwrap_or_else(|| "unknown.dll".into());

        let step = if is_64 { 8u64 } else { 4u64 };
        // Names come from the ILT when present, otherwise from the IAT (which
        // still holds name RVAs for modules the loader has not processed).
        let name_table = if oft != 0 { base + oft } else { base + ft };
        let iat_table = base + ft;

        for i in 0..2048u64 {
            if out.len() >= max_slots {
                break;
            }
            let ent = name_table + i * step;
            let raw = if is_64 {
                match rd_u64(hproc, pid, ent, kernel) {
                    Some(v) => v,
                    None => break,
                }
            } else {
                match rd_u32(hproc, pid, ent, kernel) {
                    Some(v) => v as u64,
                    None => break,
                }
            };
            if raw == 0 {
                break;
            }
            let ordinal_bit = if is_64 { 1u64 << 63 } else { 1u64 << 31 };
            let function = if raw & ordinal_bit != 0 {
                format!("#{}", raw & 0xFFFF)
            } else {
                let hint_rva = raw & 0xFFFF_FFFF;
                rd_cstr(hproc, pid, base + hint_rva + 2, 128, kernel)
                    .unwrap_or_else(|| format!("rva_{hint_rva:#x}"))
            };

            let iat_addr = iat_table + i * step;
            let target_addr = if is_64 {
                rd_u64(hproc, pid, iat_addr, kernel).unwrap_or(0)
            } else {
                rd_u32(hproc, pid, iat_addr, kernel).unwrap_or(0) as u64
            };
            if target_addr == 0 {
                continue;
            }

            let category = classify_api(&dll, &function);
            out.push(IatSlot {
                dll: dll.clone(),
                function,
                iat_addr,
                target_addr,
                category,
            });
        }
        desc += 20;
    }
    out
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEvent {
    /// Monotonic sequence number — the ordering authority.
    pub seq: u64,
    /// Milliseconds since process start (monotonic).
    pub ts_ms: u64,
    /// Absolute time, RFC3339.
    pub wall_ts: String,
    pub tid: u32,
    pub kind: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Raw register/stack arguments in order (RCX, RDX, R8, R9, then stack).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<u64>,
    /// A bounded, safe preview of the first argument when it looks like a
    /// readable string. Absent when the pointer could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arg_preview: Option<String>,
    /// Bounded hex of the same span, present whenever the pointer was readable
    /// but the bytes are not text — a key, a blob, a decrypted buffer. Absent
    /// only when the memory itself could not be read.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arg_preview_hex: Option<String>,
    /// The caller's return address.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller: Option<u64>,
    /// `image:<module>+0x..` or `private_exec` — the latter is the
    /// shellcode-execution signal.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caller_region: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl TraceEvent {
    fn new(seq: u64, ts_ms: u64, tid: u32, kind: &str) -> Self {
        Self {
            seq,
            ts_ms,
            wall_ts: wall_clock(),
            tid,
            kind: kind.into(),
            module: None,
            function: None,
            category: None,
            args: Vec::new(),
            arg_preview: None,
            arg_preview_hex: None,
            caller: None,
            caller_region: None,
            detail: None,
        }
    }
}

/// Absolute timestamp without pulling in a date library.
fn wall_clock() -> String {
    // SystemTime -> seconds since epoch; formatted as an ISO-8601 UTC string.
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = d.as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (h, m, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days as i64 + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if month <= 2 { y + 1 } else { y };
    format!("{year:04}-{month:02}-{day:02}T{h:02}:{m:02}:{s:02}Z")
}

// ---------------------------------------------------------------------------
// Options and report
// ---------------------------------------------------------------------------

/// A failure that prevents a trace from starting.
///
/// Deliberately a distinct type rather than a degenerate `TraceReport`. These
/// are **pre-run** failures: no debug event was ever received, so none of the
/// in-run verdicts — anti-tamper exit, truncated, observed-empty — can apply to
/// them. Collapsing them into a short report would let a manifest problem be
/// misread as the target detecting the debugger, which is exactly the confusion
/// the honesty contract exists to prevent.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TraceError {
    /// `CreateProcessW` failed — the target never ran.
    SpawnFailed {
        /// Raw Win32 error code (740 = ERROR_ELEVATION_REQUIRED).
        os_error: u32,
        /// The OS reported that elevation is required.
        elevation_required: bool,
        message: String,
    },
    /// The trace log could not be created.
    OutputNotWritable { path: String, message: String },
}

/// `ERROR_ELEVATION_REQUIRED`.
pub const ERROR_ELEVATION_REQUIRED: u32 = 740;

impl std::fmt::Display for TraceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TraceError::SpawnFailed {
                os_error,
                elevation_required,
                message,
            } => {
                write!(f, "spawn failed (os error {os_error}): {message}")?;
                if *elevation_required {
                    write!(
                        f,
                        "\nThe target's embedded manifest requests \
                         `requestedExecutionLevel level='requireAdministrator'`, so it cannot be \
                         spawned — let alone traced — from a non-elevated process.\n\
                         Options: run street from an elevated prompt, or trace in an isolated VM.\n\
                         Note: a target that demands elevation usually expects to load a driver, \
                         open a protected process, or write to a privileged location, so its \
                         behaviour under a non-elevated trace would not be representative anyway."
                    )?;
                }
                Ok(())
            }
            TraceError::OutputNotWritable { path, message } => {
                write!(f, "cannot write trace log to {path}: {message}")
            }
        }
    }
}

impl std::error::Error for TraceError {}

#[derive(Debug, Clone)]
pub struct TraceOptions {
    pub out_dir: PathBuf,
    pub seconds: u64,
    /// Hard cap on recorded events. A packed target can emit a very large
    /// number of calls; the cap is what keeps the run survivable.
    pub max_events: usize,
    /// Cap on traced IAT slots read from the image.
    pub max_slots: usize,
    /// Cap on breakpoints actually armed. Every armed breakpoint is a trap that
    /// fires on every call, so this is the real cost control.
    pub max_armed: usize,
    /// Trace only these categories. Empty = the default set.
    pub categories: Vec<ApiCategory>,
    /// Hide the debugger from the target.
    ///
    /// A commercial packer asks the kernel whether it is being debugged before
    /// it decrypts anything, and refuses to run when the answer is yes. Being
    /// present is therefore not enough — the trace has to be invisible. This
    /// sanitises the PEB and answers the debugger-detection queries on the
    /// target's behalf.
    /// Arm the entry point with a hardware breakpoint instead of a software one.
    ///
    /// A software breakpoint is a byte written into the target. This target
    /// finds that byte and writes the original back — caught in the act, the
    /// entry's first byte went from the `0xCC` we planted back to `0xE8` a few
    /// hundred milliseconds after the entry ran. A hardware breakpoint lives in
    /// DR0 and writes nothing, so there is nothing to detect and nothing to
    /// repair.
    pub stealth: bool,
    /// Use DR0 for the entry point rather than an int3. Requires `stealth`.
    pub hw_entry: bool,
    /// Arm an entry breakpoint at all.
    ///
    /// Turning this off, together with `max_armed = 0`, gives the pure control
    /// case: a debugger attached with **no** breakpoint anywhere and no byte
    /// written to the target. If a target still reacts to being traced under
    /// those conditions, the reaction is to the debug object itself and not to
    /// anything the tracer patched.
    pub entry_bp: bool,
}

impl Default for TraceOptions {
    fn default() -> Self {
        Self {
            out_dir: PathBuf::from("output").join("trace"),
            seconds: 30,
            max_events: 20_000,
            max_slots: 1_500,
            // Raised from 256: a process with 19 loaded modules offers far more
            // than 256 candidate exports, and the cap was being spent on ntdll
            // before the high-signal categories were reached.
            max_armed: 512,
            categories: Vec::new(),
            stealth: true,
            hw_entry: true,
            entry_bp: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceReport {
    pub exe: String,
    pub pid: u32,
    pub image_base: u64,
    pub duration_ms: u64,
    pub exit_code: Option<u32>,
    pub events: usize,
    /// The event cap was reached — the trace is incomplete.
    pub truncated: bool,
    pub iat_slots_found: usize,
    pub functions_traced: usize,
    pub breakpoints_armed: usize,
    pub bp_hits: u64,
    /// API calls whose caller was NOT inside any mapped image.
    pub calls_from_private_memory: usize,
    /// Direct `syscall` sites in the target image, read statically before the
    /// spawn. Non-zero means the API trace will systematically under-report,
    /// because those calls never reach a DLL export and so never hit a
    /// breakpoint. This is what makes an empty trace explicable.
    pub target_direct_syscall_sites: usize,
    /// The target's embedded manifest demands elevation.
    pub target_requires_elevation: bool,
    /// The unpacked image, captured the moment the declared entry ran and
    /// diffed against the file on disk. Sections that differ are decrypted
    /// content, written to `unpacked/`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_dump: Option<crate::live::ImageDumpReport>,
    pub modules: Vec<UserModule>,
    pub per_category: HashMap<String, usize>,
    pub notes: Vec<String>,
    pub coverage: Coverage,
}

impl TraceReport {
    /// A run is *conclusive* only if it completed and captured something. This
    /// is the success predicate the CLI reports.
    pub fn succeeded(&self) -> bool {
        !self.truncated && self.events > 0
    }

    /// True when the target looks like it detected the debugger and bailed out.
    ///
    /// Deliberately **corroborated**: any one of these conditions alone is weak
    /// evidence, but together they are the signature of an anti-tamper bail-out.
    /// A short trace is not by itself proof of detection, so this returns a
    /// suspicion the report states, never a conclusion.
    pub fn looks_like_antitamper_exit(&self) -> bool {
        self.exit_code.is_some()
            && self.duration_ms < 1_500
            && self.bp_hits == 0
            && self.events <= 3
    }
}

// ---------------------------------------------------------------------------
// Runner
// ---------------------------------------------------------------------------

pub fn run_trace(exe: &str, opts: &TraceOptions) -> Result<TraceReport, TraceError> {
    let kernel = KernelClient::open();
    let started = Instant::now();
    let mut notes: Vec<String> = Vec::new();
    let mut events: Vec<TraceEvent> = Vec::new();
    let mut seq: u64 = 0;
    let mut truncated = false;
    let mut bp_hits: u64 = 0;
    let mut calls_from_private: usize = 0;

    let mut wide: Vec<u16> = std::os::windows::ffi::OsStrExt::encode_wide(std::ffi::OsStr::new(exe))
        .collect();
    wide.push(0);

    // Read the target once, before spawning, to record the static facts that
    // bound what any trace can see. Doing this first is what turns an empty
    // trace from a mystery into an explained result.
    let static_profile = std::fs::read(exe)
        .ok()
        .map(|d| street_core::exec_profile::analyze(&d));

    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    let spawned = unsafe {
        CreateProcessW(
            windows::core::PCWSTR(wide.as_ptr()),
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
    };
    if let Err(e) = spawned {
        // A spawn failure is its own verdict, and it carries whatever the static
        // profile already told us — so the report is informative rather than
        // just "it did not start".
        let hr = e.code().0 as u32;
        let os_error = hr & 0xFFFF;
        let extra = static_profile
            .as_ref()
            .map(|p| {
                let mut bits: Vec<String> = Vec::new();
                if let Some(l) = &p.requested_execution_level {
                    bits.push(format!("manifest requestedExecutionLevel={l}"));
                }
                if p.direct_syscall_sites > 0 {
                    bits.push(format!(
                        "{} direct syscall stub(s) ({} stock-shaped) — an API trace would \
                         under-report it",
                        p.direct_syscall_sites, p.direct_syscall_stub_shaped
                    ));
                }
                if bits.is_empty() {
                    String::new()
                } else {
                    format!("\nStatic profile: {}.", bits.join("; "))
                }
            })
            .unwrap_or_default();
        return Err(TraceError::SpawnFailed {
            os_error,
            elevation_required: os_error == ERROR_ELEVATION_REQUIRED,
            message: format!("{}{extra}", e.message()),
        });
    }

    let hproc = pi.hProcess;
    let pid = pi.dwProcessId;
    let mut image_base = 0u64;
    // The image's declared entry point. A breakpoint is armed here; whether it
    // is ever hit is the decisive test of whether the process executes its
    // declared entry or something else happens instead.
    let mut entry_va: u64 = 0;
    // Diagnostic readback of the byte at the entry breakpoint after each sweep.
    let mut entry_bp_probe: Option<String> = None;
    // Breakpoint hits whose captured "original" byte was itself 0xCC.
    let mut double_arm_hits: u64 = 0;
    // Hits where OpenThread failed, forcing the breakpoint to be dropped.
    let mut thread_handle_failures: u64 = 0;
    // Debugger-detection queries answered on the target's behalf.
    let mut spoofed_calls: u64 = 0;
    // Whether the PEB was successfully sanitised.
    let mut peb_sanitised: Option<String> = None;
    // Captured when the declared entry runs, i.e. once the packer has finished
    // decrypting in place. This is the unpacked plaintext.
    let mut image_dump: Option<crate::live::ImageDumpReport> = None;
    let mut modules: Vec<UserModule> = Vec::new();
    let mut exit_code: Option<u32> = None;
    let mut iat_slots_found = 0usize;
    let mut functions_traced = 0usize;
    let mut iat_fail_diag: Option<String> = None;
    let mut armed: HashMap<u64, (u8, String, String)> = HashMap::new(); // addr -> (orig, dll, func)
    // Modules whose export tables have already been walked. Without this the
    // 10k-odd exports of a normal process would be re-read every arming cycle.
    let mut scanned_modules: std::collections::HashSet<u64> = std::collections::HashSet::new();
    // Per-function emission caps. A packer can call NtProtectVirtualMemory tens
    // of thousands of times; without a cap one hot API consumes the whole event
    // budget and the interesting events — the anti-debug check, the dialog —
    // never get recorded at all.
    let mut per_func: HashMap<String, usize> = HashMap::new();
    let mut suppressed: HashMap<String, usize> = HashMap::new();
    const PER_FUNC_CAP: usize = 64;
    // One pending re-arm per *thread*, not one globally. A thread must
    // single-step before it runs on, so at most one address is pending per
    // thread. A single shared slot lost an address whenever two threads hit
    // breakpoints before either single-stepped: the second overwrote the first,
    // the first was never re-armed, and that breakpoint went silently dead.
    let mut rearm: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();
    // Re-arm eagerly: the first attempt happens before the loader has published
    // the module list, so it finds nothing. Arming is retried on every module
    // load and on the system breakpoint, which is the last moment before user
    // code runs.
    let mut force_arm = true;

    let root = opts.out_dir.join(pid.to_string());
    let _ = fs::create_dir_all(&root);
    let jsonl_path = root.join("EVENTS.jsonl");
    let mut jsonl = fs::File::create(&jsonl_path).map_err(|e| TraceError::OutputNotWritable {
        path: jsonl_path.display().to_string(),
        message: e.to_string(),
    })?;

    let deadline = started + Duration::from_secs(opts.seconds);
    let mut last_arm = Instant::now();
    // Best image-dump score seen so far. The dump is taken repeatedly because a
    // packer's entry point is often its own stub, which decrypts *after* the
    // entry runs — so a single dump at the entry captures the image still
    // packed. Only the most-decrypted snapshot is kept.
    let mut best_dump_score: Option<u64> = None;
    let mut last_dump = Instant::now();
    // Highest count of private executable regions observed so far.
    let mut private_regions_seen: usize = 0;
    // The declared entry point has executed. Anything the process maps after
    // this is not one of its own imports.
    let mut entry_hit_seen = false;
    // The system ntdll was excluded from arming.
    let mut ntdll_skipped = false;
    // Base of the system's own ntdll, so a remapped copy can be told apart from
    // it despite sharing the name.
    let mut system_ntdll_base: Option<u64> = None;
    // Modules registered from LOAD_DLL events that the loader list omits.
    let mut mapped_modules: Vec<UserModule> = Vec::new();
    // The entry point is guarded by DR0 instead of an int3.
    let mut hw_entry_armed = false;
    let mut per_category: HashMap<String, usize> = HashMap::new();

    let push = |events: &mut Vec<TraceEvent>,
                jsonl: &mut fs::File,
                truncated: &mut bool,
                ev: TraceEvent,
                max: usize| {
        if events.len() >= max {
            *truncated = true;
            return;
        }
        if let Ok(line) = serde_json::to_string(&ev) {
            let _ = writeln!(jsonl, "{line}");
        }
        events.push(ev);
    };

    while Instant::now() < deadline {
        let mut ev = DEBUG_EVENT::default();
        let got = unsafe { WaitForDebugEvent(&mut ev, 100).is_ok() };
        let at = started.elapsed().as_millis() as u64;

        if got {
            let tid = ev.dwThreadId;
            // How this event is continued. Exceptions we did not cause are
            // handed back to the process rather than marked handled.
            let mut cont = DBG_CONTINUE;
            match ev.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    let info = unsafe { ev.u.CreateProcessInfo };
                    image_base = info.lpBaseOfImage as u64;
                    unsafe {
                        let _ = ResumeThread(info.hThread);
                    }
                    modules = enumerate_user_modules(pid);
            merge_mapped_modules(&mut modules, &mapped_modules);
                    let mut e = TraceEvent::new(seq, at, tid, "process_start");
                    seq += 1;
                    e.detail = Some(format!("image_base=0x{image_base:x} pid={pid}"));
                    push(&mut events, &mut jsonl, &mut truncated, e, opts.max_events);

                    // What is actually mapped at the entry point? For a packed
                    // target this is the difference between "the entry is
                    // ciphertext" and "the entry is code", and it can only be
                    // answered from the live process.
                    let probe = entry_probe(hproc, pid, image_base, &kernel);
                    let mut p = TraceEvent::new(seq, at, tid, "entry_probe");
                    seq += 1;
                    p.detail = Some(probe.clone());
                    push(&mut events, &mut jsonl, &mut truncated, p, opts.max_events);
                    notes.push(probe);

                    // Arm a breakpoint on the entry point itself. Whether it is
                    // ever hit is the decisive test of whether the process
                    // executes its declared entry or something else happens.
                    entry_va = entry_va_of(hproc, pid, image_base, &kernel).unwrap_or(0);

                    // Arm the entry with DR0 rather than an int3 when asked.
                    // The thread is still frozen by this debug event, so the
                    // register is in place before any user code can run.
                    if opts.stealth && opts.hw_entry && opts.entry_bp && entry_va != 0 {
                        let ok = set_hw_exec_breakpoint(info.hThread, entry_va);
                        hw_entry_armed = ok;
                        let mut s = TraceEvent::new(seq, at, tid, "entry_bp_mode");
                        seq += 1;
                        s.detail = Some(if ok {
                            format!(
                                "hardware (DR0=0x{entry_va:x}) — no byte written to the target"
                            )
                        } else {
                            "hardware breakpoint FAILED to arm; falling back to int3".to_string()
                        });
                        push(&mut events, &mut jsonl, &mut truncated, s, opts.max_events);
                    }

                    // Hide before the target runs any of its own code: the
                    // loader has already stamped the PEB, and the first thing a
                    // packer does is read it.
                    if opts.stealth {
                        match target_peb(hproc) {
                            Some(peb) => {
                                let r = sanitize_peb(hproc, pid, peb, &kernel);
                                let msg = match &r {
                                    Ok(()) => format!("peb=0x{peb:x} sanitised"),
                                    Err(e) => format!("peb=0x{peb:x} FAILED ({e})"),
                                };
                                let mut s = TraceEvent::new(seq, at, tid, "stealth_peb");
                                seq += 1;
                                s.detail = Some(msg.clone());
                                push(&mut events, &mut jsonl, &mut truncated, s, opts.max_events);
                                peb_sanitised = Some(msg);
                            }
                            None => {
                                let msg = "PEB could not be located".to_string();
                                let mut s = TraceEvent::new(seq, at, tid, "stealth_peb");
                                seq += 1;
                                s.detail = Some(msg.clone());
                                push(&mut events, &mut jsonl, &mut truncated, s, opts.max_events);
                                peb_sanitised = Some(msg);
                            }
                        }
                    }
                }
                LOAD_DLL_DEBUG_EVENT => {
                    let base = unsafe { ev.u.LoadDll.lpBaseOfDll } as u64;
                    modules = enumerate_user_modules(pid);
            merge_mapped_modules(&mut modules, &mapped_modules);
                    let mut name = modules
                        .iter()
                        .find(|m| m.base == base)
                        .map(|m| m.name.clone())
                        .unwrap_or_else(|| format!("0x{base:x}"));

                    // A manually mapped image is absent from the loader list, so
                    // register it here or it will never be scanned for exports —
                    // and it is precisely the image the process goes on to call.
                    if base != 0 && !modules.iter().any(|m| m.base == base) {
                        if let Some((n, size)) = mapped_module_identity(hproc, pid, base, &kernel) {
                            name = n.clone();
                            let um = crate::live::UserModule {
                                base,
                                size,
                                name: n,
                                path: String::new(),
                            };
                            modules.push(um.clone());
                            mapped_modules.push(um);
                        }
                    }

                    let mut e = TraceEvent::new(seq, at, tid, "module_load");
                    seq += 1;
                    e.module = Some(name.clone());
                    e.detail = Some(format!("base=0x{base:x}"));
                    push(&mut events, &mut jsonl, &mut truncated, e, opts.max_events);

                    // A module that appears *after* the entry point is not one of
                    // the process's own imports: the loader finished those before
                    // the entry ran. This is exactly where a packer puts its
                    // decrypted payload — on vector.exe a module materialised at
                    // 0x21b4d8f0000, an address with no relation to the file on
                    // disk, while the original image's sections stayed packed.
                    // Capture the mapped image while it is still there.
                    if entry_hit_seen && base != 0 {
                        if let Some(n) = crate::live::dump_module_memory(
                            hproc, pid, base, &name, &root, &kernel,
                        ) {
                            let mut d = TraceEvent::new(seq, at, tid, "module_captured");
                            seq += 1;
                            d.module = Some(name);
                            d.detail =
                                Some(format!("base=0x{base:x} — captured {n} bytes"));
                            push(&mut events, &mut jsonl, &mut truncated, d, opts.max_events);
                        }
                    }

                    // A new module means new resolvable import targets.
                    force_arm = true;
                }
                CREATE_THREAD_DEBUG_EVENT => {
                    let start = unsafe { ev.u.CreateThread.lpStartAddress }
                        .map(|f| f as usize as u64)
                        .unwrap_or(0);
                    let mut e = TraceEvent::new(seq, at, tid, "thread_start");
                    seq += 1;
                    e.detail = Some(format!("tid={tid} start=0x{start:x}"));
                    push(&mut events, &mut jsonl, &mut truncated, e, opts.max_events);

                    // DR0 is per-thread: a thread created later carries no
                    // breakpoint of its own, so it has to be given one.
                    if hw_entry_armed && entry_va != 0 {
                        let hthread = unsafe { ev.u.CreateThread.hThread };
                        if !hthread.is_invalid() {
                            let _ = set_hw_exec_breakpoint(hthread, entry_va);
                        }
                    }
                }
                EXCEPTION_DEBUG_EVENT => {
                    let code = unsafe { ev.u.Exception.ExceptionRecord.ExceptionCode.0 };
                    let addr = unsafe { ev.u.Exception.ExceptionRecord.ExceptionAddress as u64 };
                    if code == EXCEPTION_BREAKPOINT {
                        if let Some((orig, dll, func)) = armed.get(&addr).cloned() {
                            let ht = open_thread(tid);
                            if !ht.is_invalid() {
                            // Set when this call was answered by the stealth
                            // layer rather than allowed to execute.
                            let mut spoof_note: Option<String> = None;
                            if orig != 0xCC {
                                // Stealth: if this is the target asking whether
                                // it is being debugged, answer it here. The real
                                // body must never run — that is the whole point.
                                spoof_note = if opts.stealth {
                                    spoof_debug_query(
                                        hproc,
                                        pid,
                                        ht,
                                        &func.to_ascii_lowercase(),
                                        &kernel,
                                    )
                                } else {
                                    None
                                };

                                if spoof_note.is_some() {
                                    spoofed_calls += 1;
                                } else {
                                    // Remove the trap so the real body runs, rewind
                                    // RIP (the CPU advanced past the int3), then
                                    // single-step in order to re-arm.
                                    let b = [orig];
                                    let mut n = 0usize;
                                    unsafe {
                                        let _ = WriteProcessMemory(
                                            hproc,
                                            addr as *mut _,
                                            b.as_ptr().cast(),
                                            1,
                                            Some(&mut n),
                                        );
                                    }
                                    step_back_rip(ht);
                                    set_trap(ht, true);
                                    rearm.insert(tid, addr);
                                }
                            } else {
                                // Poisoned entry: the byte recorded as "the
                                // original" is itself 0xCC, so restoring it
                                // would leave the trap in place and rewinding
                                // RIP would re-execute it forever. That is a
                                // livelock, not a trace. Run on past the trap
                                // and do not schedule a re-arm — it is already
                                // armed.
                                double_arm_hits += 1;
                            }
                            bp_hits += 1;
                            if orig == 0xCC && double_arm_hits <= 3 {
                                eprintln!(
                                    "[poisoned breakpoint {double_arm_hits}] addr=0x{addr:x} \
                                     tid={tid} {dll}!{func} — left armed, ran past it"
                                );
                            }

                                // Read caller + args while the frame is intact:
                                // RSP still points at the return address.
                                let mut ctx = CONTEXT {
                                    ContextFlags: CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64,
                                    ..Default::default()
                                };
                                let ok = unsafe { GetThreadContext(ht, &mut ctx).is_ok() };
                                unsafe {
                                    let _ = CloseHandle(ht);
                                }
                                if ok {
                                    let ret = rd_u64(hproc, pid, ctx.Rsp, &kernel).unwrap_or(0);
                                    let mut region = classify_caller(ret, &modules);
                                    // "Outside every module" is only meaningful
                                    // if the module list is actually complete.
                                    // It is read from the target's PEB while the
                                    // target runs, so a loader update in flight
                                    // can hand back a list momentarily missing a
                                    // DLL — which turned sixteen ntdll callers
                                    // into phantom "executed from private
                                    // memory" signals on vector.exe. Re-read the
                                    // list once before believing the verdict.
                                    if region.as_deref() == Some("private_exec") {
                                        modules = enumerate_user_modules(pid);
            merge_mapped_modules(&mut modules, &mapped_modules);
                                        region = classify_caller(ret, &modules);
                                    }
                                    if region.as_deref() == Some("private_exec") {
                                        calls_from_private += 1;
                                    }
                                    let args = vec![ctx.Rcx, ctx.Rdx, ctx.R8, ctx.R9];
                                    let preview = safe_preview(hproc, pid, ctx.Rcx, 96, &kernel);
                                    let cat = classify_api(&dll, &func);

                                    // Rate-limit per function so one hot API
                                    // cannot starve the rest of the trace.
                                    let key = format!("{dll}!{func}");
                                    let seen = per_func.entry(key.clone()).or_insert(0);
                                    let emit = *seen < PER_FUNC_CAP;
                                    if emit {
                                        *seen += 1;
                                    } else {
                                        *suppressed.entry(key.clone()).or_insert(0) += 1;
                                    }
                                    *per_category.entry(cat.label().to_string()).or_insert(0) += 1;

                                    if emit {
                                        let mut e = TraceEvent::new(seq, at, tid, "api_call");
                                        seq += 1;
                                        e.module = Some(dll.clone());
                                        e.function = Some(func.clone());
                                        e.category = Some(cat.label().to_string());
                                        e.args = args;
                                        if let Some(p) = preview {
                                            e.arg_preview = p.text;
                                            e.arg_preview_hex = Some(p.hex);
                                        }
                                        e.caller = Some(ret);
                                        e.caller_region = region.clone();
                                        if region.as_deref() == Some("private_exec") {
                                            e.detail = Some(
                                                "CALL FROM PRIVATE EXECUTABLE MEMORY".into(),
                                            );
                                        }
                                        // A spoofed call is the headline fact
                                        // about the event, so it wins over the
                                        // generic region note.
                                        if let Some(note) = &spoof_note {
                                            e.detail = Some(format!(
                                                "SPOOFED {note} — the real call was not executed"
                                            ));
                                        }
                                        // A dialog's text is often the only
                                        // readable statement of why the program
                                        // stopped. Capture it, do not just note
                                        // that a call happened.
                                        if cat == ApiCategory::Ui
                                            && func.to_ascii_lowercase().contains("messagebox")
                                        {
                                            if let Some(msg) = message_box_text(
                                                hproc, pid, &func, &e.args, &kernel,
                                            ) {
                                                e.detail = Some(format!("DIALOG {msg}"));
                                            }
                                        }
                                        push(
                                            &mut events,
                                            &mut jsonl,
                                            &mut truncated,
                                            e,
                                            opts.max_events,
                                        );
                                    }

                                    // The decisive observation: the process
                                    // reached its declared entry point.
                                    if addr == entry_va {
                                        entry_hit_seen = true;
                                        // The process has proved it can reach
                                        // this point, so the budget may now be
                                        // spent: re-sweep on the next pass.
                                        force_arm = true;
                                        let mut h = TraceEvent::new(seq, at, tid, "entry_hit");
                                        seq += 1;
                                        h.caller = Some(ret);
                                        h.caller_region = region.clone();
                                        h.detail = Some(format!(
                                            "declared entry point executed at 0x{addr:x}"
                                        ));
                                        push(
                                            &mut events,
                                            &mut jsonl,
                                            &mut truncated,
                                            h,
                                            opts.max_events,
                                        );

                                        // The packer has finished decrypting by the
                                        // time the declared entry runs. Dump the image
                                        // and diff it against the file to capture the
                                        // plaintext — this is the unpacking step.
                                        if image_dump.is_none() {
                                            if let Some(d) = crate::live::dump_image_diff(
                                                hproc,
                                                pid,
                                                image_base,
                                                Path::new(exe),
                                                &root,
                                                &kernel,
                                            ) {
                                                let mut de =
                                                    TraceEvent::new(seq, at, tid, "image_dump");
                                                seq += 1;
                                                de.detail = Some(format!(
                                                    "{} section(s) differ, {} bytes — {}",
                                                    d.changed_sections,
                                                    d.total_changed_bytes,
                                                    d.note
                                                ));
                                                push(
                                                    &mut events,
                                                    &mut jsonl,
                                                    &mut truncated,
                                                    de,
                                                    opts.max_events,
                                                );
                                                notes.push(format!("unpacked image: {}", d.note));
                                                best_dump_score = Some(
                                                    d.total_changed_bytes
                                                        + (d.materialised_sections as u64) * (1 << 40),
                                                );
                                                image_dump = Some(d);
                                            }
                                        }
                                    }

                                    // Separate, explicit shellcode-execution signal.
                                    if region.as_deref() == Some("private_exec") {
                                        let mut s =
                                            TraceEvent::new(seq, at, tid, "exec_in_private_memory");
                                        seq += 1;
                                        s.function = Some(func.clone());
                                        s.caller = Some(ret);
                                        s.caller_region = region;
                                        s.detail =
                                            Some(format!("{dll}!{func} called from 0x{ret:x}"));
                                        push(
                                            &mut events,
                                            &mut jsonl,
                                            &mut truncated,
                                            s,
                                            opts.max_events,
                                        );
                                    }
                                }
                            } else {
                                // open_thread failed. Without a handle we cannot
                                // rewind RIP or single-step, so the trap would
                                // stay in memory while the target resumes at
                                // addr+1 — silently skipping the first
                                // instruction of the function on every call.
                                // For a syscall stub that means a skipped
                                // `mov r10, rcx` and a wrong syscall number.
                                // Restore the original byte and drop the
                                // breakpoint: losing an event is recoverable,
                                // corrupting execution is not.
                                let b = [orig];
                                let mut n = 0usize;
                                unsafe {
                                    let _ = WriteProcessMemory(
                                        hproc,
                                        addr as *mut _,
                                        b.as_ptr().cast(),
                                        1,
                                        Some(&mut n),
                                    );
                                }
                                armed.remove(&addr);
                                thread_handle_failures += 1;
                            }
                            // Deliberately fall through to the ContinueDebugEvent at
                            // the bottom of the loop. Holding the event here would
                            // freeze the target — the trap we just armed would never
                            // get a chance to fire.
                        } else if hw_entry_armed && entry_va != 0 && addr == entry_va {
                            // Hardware breakpoint on the entry point. Nothing was
                            // written into the target, so there is no byte to
                            // restore and no RIP to rewind — the instruction at
                            // `addr` has not executed yet.
                            entry_hit_seen = true;
                            force_arm = true;
                            hw_entry_armed = false;
                            let ht = open_thread(tid);
                            if !ht.is_invalid() {
                                clear_hw_exec_breakpoint(ht);
                                unsafe {
                                    let _ = CloseHandle(ht);
                                }
                            }
                            let mut h = TraceEvent::new(seq, at, tid, "entry_hit");
                            seq += 1;
                            h.detail = Some(format!(
                                "declared entry point executed at 0x{addr:x} \
                                 (hardware breakpoint — nothing written to the target)"
                            ));
                            push(&mut events, &mut jsonl, &mut truncated, h, opts.max_events);
                        } else {
                            // Not one of ours: the loader's initial system
                            // breakpoint. Arm here — it is the last point before
                            // any user code runs.
                            force_arm = true;
                        }
                    } else if code == EXCEPTION_SINGLE_STEP {
                        // A hardware execution breakpoint raises #DB, which
                        // Windows reports as a *single step* — not as a
                        // breakpoint exception. That is why a DR0 hit on the
                        // entry point arrives here and not in the branch above.
                        let was_entry = hw_entry_armed && entry_va != 0 && addr == entry_va;
                        if was_entry {
                            entry_hit_seen = true;
                            force_arm = true;
                            hw_entry_armed = false;
                            let mut h = TraceEvent::new(seq, at, tid, "entry_hit");
                            seq += 1;
                            h.caller = Some(addr);
                            h.detail = Some(format!(
                                "declared entry point executed at 0x{addr:x} \
                                 (hardware breakpoint — nothing written to the target)"
                            ));
                            push(&mut events, &mut jsonl, &mut truncated, h, opts.max_events);
                        }
                        let ht = open_thread(tid);
                        if !ht.is_invalid() {
                            set_trap(ht, false);
                            if was_entry {
                                // Disarm DR0 so the entry is not re-trapped if
                                // control ever returns to it.
                                let _ = clear_hw_exec_breakpoint(ht);
                            }
                            unsafe {
                                let _ = CloseHandle(ht);
                            }
                        }
                        if let Some(a) = rearm.remove(&tid) {
                            let b = [0xCCu8];
                            let mut n = 0usize;
                            unsafe {
                                let _ = WriteProcessMemory(
                                    hproc,
                                    a as *mut _,
                                    b.as_ptr().cast(),
                                    1,
                                    Some(&mut n),
                                );
                            }
                        }
                    } else {
                        let mut e = TraceEvent::new(seq, at, tid, "exception");
                        seq += 1;
                        e.caller = Some(addr);
                        e.detail = Some(format!("code=0x{code:x}"));
                        push(&mut events, &mut jsonl, &mut truncated, e, opts.max_events);
                        // Hand it back to the process. Continuing with
                        // DBG_CONTINUE would tell the OS the fault was handled,
                        // so the same instruction would re-execute and fault
                        // again — an infinite exception storm instead of a
                        // process that dies once.
                        cont = DBG_EXCEPTION_NOT_HANDLED;
                    }
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    let code = unsafe { ev.u.ExitProcess.dwExitCode };
                    exit_code = Some(code);

                    // Last chance to capture the image: at exit the process is
                    // still mapped, and whatever decryption happened during the
                    // run has happened by now.
                    if image_base != 0 {
                        let staging = root.join("snapshot");
                        if let Some(d) = crate::live::dump_image_diff(
                            hproc,
                            pid,
                            image_base,
                            Path::new(exe),
                            &staging,
                            &kernel,
                        ) {
                            let score = d.total_changed_bytes
                                + (d.materialised_sections as u64) * (1u64 << 40);
                            if best_dump_score.is_none_or(|b| score > b) {
                                promote_unpacked(
                                    &staging.join("unpacked"),
                                    &root.join("unpacked"),
                                );
                                // No point recording the new best: the loop
                                // breaks immediately below.
                                let mut s =
                                    TraceEvent::new(seq, at, tid, "image_snapshot_final");
                                seq += 1;
                                s.detail = Some(format!(
                                    "changed_sections={} materialised={} bytes={} — new best",
                                    d.changed_sections,
                                    d.materialised_sections,
                                    d.total_changed_bytes
                                ));
                                push(
                                    &mut events,
                                    &mut jsonl,
                                    &mut truncated,
                                    s,
                                    opts.max_events,
                                );
                                image_dump = Some(d);
                            }
                        }
                    }

                    let mut e = TraceEvent::new(seq, at, tid, "process_exit");
                    e.detail = Some(format!("exit_code={code}"));
                    push(&mut events, &mut jsonl, &mut truncated, e, opts.max_events);
                    unsafe {
                        let _ = ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE);
                    }
                    break;
                }
                _ => {}
            }
            unsafe {
                let _ = ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, cont);
            }
        }

        // Arm breakpoints once the process is up, and re-arm on every module
        // load and system breakpoint. The short fallback interval catches
        // delay-loaded and GetProcAddress-resolved targets.
        if image_base != 0 && (force_arm || last_arm.elapsed() >= Duration::from_millis(250)) {
            force_arm = false;
            last_arm = Instant::now();
            modules = enumerate_user_modules(pid);
            merge_mapped_modules(&mut modules, &mapped_modules);
            let slots = read_iat(hproc, pid, image_base, &kernel, opts.max_slots);
            iat_slots_found = slots.len();
            if slots.is_empty() {
                iat_fail_diag = Some(iat_diag(hproc, pid, image_base, &kernel));
            }
            let mut new_arms = 0usize;

            // Keep the pre-entry footprint tiny, then expand once the entry has
            // run. Measured on vector.exe: 8 armed breakpoints reach the entry
            // point every time, 512 never do — the process hangs before its own
            // entry, 0 exceptions, still alive at the 35 s timeout. The budget
            // is therefore spent in two stages, and the expensive stage only
            // starts once the process has proved it can get that far.
            let cap = if entry_hit_seen {
                opts.max_armed
            } else {
                opts.max_armed.min(PRE_ENTRY_ARM_CAP)
            };

            for s in &slots {
                if !opts.categories.is_empty() {
                    if !opts.categories.contains(&s.category) {
                        continue;
                    }
                } else if !s.category.default_traced() {
                    continue;
                }
                if armed.contains_key(&s.target_addr) {
                    continue;
                }
                if armed.len() >= cap {
                    break;
                }
                // Skip addresses outside any mapped module — a resolved target
                // in private memory is not something we should patch blindly.
                if !in_any_module(s.target_addr, &modules) {
                    continue;
                }
                let mut orig = [0u8; 1];
                if read_mem(hproc, pid, s.target_addr, &mut orig, &kernel) != 1 {
                    continue;
                }
                if orig[0] == 0xCC {
                    continue;
                }
                let b = [0xCCu8];
                let mut n = 0usize;
                let ok = unsafe {
                    windows::Win32::System::Diagnostics::Debug::WriteProcessMemory(
                        hproc,
                        s.target_addr as *mut _,
                        b.as_ptr().cast(),
                        1,
                        Some(&mut n),
                    )
                    .is_ok()
                };
                if ok {
                    armed.insert(s.target_addr, (orig[0], s.dll.clone(), s.function.clone()));
                    new_arms += 1;
                }
            }
            // Arm by **export**, not only by the main image's IAT.
            //
            // A packed binary imports almost nothing statically and resolves
            // everything at runtime, so its IAT is a bootstrap stub. But the
            // function it ends up calling is the same DLL export either way, so
            // arming exports catches GetProcAddress-resolved calls too.
            // The entry point is armed **first**, before the export sweep can
            // consume the budget. It is the decisive test of whether the process
            // executes its declared entry, and it is also the moment the packer
            // has finished decrypting — so the image dump is taken there.
            if opts.entry_bp && entry_va != 0 && !hw_entry_armed && !armed.contains_key(&entry_va) {
                let mut orig = [0u8; 1];
                if read_mem(hproc, pid, entry_va, &mut orig, &kernel) == 1 {
                    let b = [0xCCu8];
                    let mut n = 0usize;
                    let ok = unsafe {
                        WriteProcessMemory(
                            hproc,
                            entry_va as *mut _,
                            b.as_ptr().cast(),
                            1,
                            Some(&mut n),
                        )
                        .is_ok()
                    };
                    if ok {
                        armed.insert(entry_va, (orig[0], "<entry>".into(), "<entry>".into()));
                        new_arms += 1;
                    }
                }
            }

            // Diagnostic: confirm the entry breakpoint is actually present in
            // the target's memory at the moment the sweep finishes. If the byte
            // reads back as something other than 0xCC, something restored it.
            if entry_va != 0 {
                let mut rb = [0u8; 1];
                let got = read_mem(hproc, pid, entry_va, &mut rb, &kernel);
                entry_bp_probe = Some(format!(
                    "entry_va=0x{entry_va:x} read={got} byte=0x{:02x}",
                    rb[0]
                ));
            }

            // Collect candidates from every loaded module, then arm in priority
            // order rather than module order.
            let mut candidates: Vec<(u8, u64, String, String)> = Vec::new();
            for m in modules.iter() {
                if !scanned_modules.insert(m.base) {
                    continue;
                }
                // Do not patch the system's own ntdll.
                //
                // vector.exe checksums ntdll and, finding it modified, maps a
                // fresh copy of it straight from disk and calls that instead.
                // Measured: the copy it mapped at 0x17bac970000 has a .text
                // byte-identical to C:\Windows\System32\ntdll.dll (0 of 92,928
                // 16-byte blocks differ, same TimeDateStamp). Two consequences,
                // both bad: every breakpoint placed in the original is bypassed,
                // and the remap tells the packer it is being analysed. It is the
                // remapped copy that deserves instrumentation — and that arrives
                // as a module with its own base, scanned in its own right.
                if m.name.to_ascii_lowercase().contains("ntdll") {
                    // Skip the system's own copy — but only that one. The target
                    // maps a fresh copy of ntdll and calls *that* instead; the
                    // copy is what deserves instrumentation, and it carries the
                    // same name, so identity has to be by base and not by name.
                    let is_system = match system_ntdll_base {
                        None => {
                            system_ntdll_base = Some(m.base);
                            true
                        }
                        Some(b) => b == m.base,
                    };
                    if is_system {
                        ntdll_skipped = true;
                        continue;
                    }
                }
                for (name, addr) in read_exports(hproc, pid, m.base, &kernel, 4096) {
                    if armed.contains_key(&addr) {
                        continue;
                    }
                    let cat = classify_api(&m.name, &name);
                    let wanted = if opts.categories.is_empty() {
                        cat.default_traced()
                    } else {
                        opts.categories.contains(&cat)
                    };
                    if !wanted {
                        continue;
                    }
                    candidates.push((cat.priority(), addr, m.name.clone(), name));
                }
            }
            candidates.sort_by_key(|c| c.0);
            // Alias exports (`NtX`/`ZwX`) share one address; arming both poisons
            // the saved original byte and livelocks the target.
            let candidates = dedup_candidates_by_addr(candidates);

            for (_, addr, dll, name) in candidates {
                if armed.len() >= cap {
                    break;
                }
                // Two export names can share one address: ntdll exports every
                // Nt* function twice, as `NtX` and `ZwX`. Both land in the same
                // candidate batch, so the check made at collection time cannot
                // see the other one yet. Without this re-check the second name
                // arms the address a second time, reading back the 0xCC the
                // first one just wrote and storing it as "the original byte".
                // Restoring 0xCC over 0xCC leaves the trap in place, the thread
                // steps back onto it, and the target livelocks — which is
                // exactly what happens on a plain notepad with 60 breakpoints.
                if armed.contains_key(&addr) {
                    continue;
                }
                let mut orig = [0u8; 1];
                if read_mem(hproc, pid, addr, &mut orig, &kernel) != 1 {
                    continue;
                }
                // Belt and braces: if the byte is already a trap, this address
                // is owned by another name. Arming it again would poison `orig`.
                if orig[0] == 0xCC {
                    continue;
                }
                let b = [0xCCu8];
                let mut n = 0usize;
                let ok = unsafe {
                    WriteProcessMemory(hproc, addr as *mut _, b.as_ptr().cast(), 1, Some(&mut n))
                        .is_ok()
                };
                if ok {
                    armed.insert(addr, (orig[0], dll, name));
                    new_arms += 1;
                }
            }

            functions_traced = armed.len();
            if new_arms > 0 {
                let mut e = TraceEvent::new(seq, started.elapsed().as_millis() as u64, 0, "trace_armed");
                seq += 1;
                e.detail = Some(format!(
                    "iat_slots={iat_slots_found} armed={functions_traced} (+{new_arms}){}",
                    match &entry_bp_probe {
                        Some(p) => format!(" | {p}"),
                        None => String::new(),
                    }
                ));
                push(&mut events, &mut jsonl, &mut truncated, e, opts.max_events);
            }
        }

        // Snapshot the image repeatedly and keep the most-decrypted one.
        //
        // The entry point is not necessarily the end of the unpacking: for a
        // packer the entry is its own stub, which decrypts and only then jumps
        // to the real code. A single dump taken at the entry therefore captures
        // the image still packed — which is exactly what happened on the first
        // run against vector.exe. Snapshotting on a timer and keeping the
        // largest difference means the captured image is the most-decrypted one
        // observed, whenever during the run that happened to be.
        if image_base != 0 && last_dump.elapsed() >= Duration::from_millis(250) {
            last_dump = Instant::now();
            let staging = root.join("snapshot");
            if let Some(d) = crate::live::dump_image_diff(
                hproc,
                pid,
                image_base,
                Path::new(exe),
                &staging,
                &kernel,
            ) {
                // Private executable memory is where a packer's plaintext lands
                // when it does not decrypt in place, so capture it alongside the
                // image rather than assuming the image tells the whole story.
                let priv_regions = crate::live::dump_private_exec_regions(
                    hproc,
                    pid,
                    &staging,
                    &kernel,
                    &modules,
                );
                if !priv_regions.is_empty() {
                    let total: usize = priv_regions.iter().map(|(_, n, _)| n).sum();
                    if priv_regions.len() > private_regions_seen {
                        private_regions_seen = priv_regions.len();
                        let mut e = TraceEvent::new(
                            seq,
                            started.elapsed().as_millis() as u64,
                            0,
                            "private_exec_regions",
                        );
                        seq += 1;
                        e.detail = Some(format!(
                            "{} region(s), {} bytes: {}",
                            priv_regions.len(),
                            total,
                            priv_regions
                                .iter()
                                .map(|(b, n, k)| format!("0x{b:x}({n},{k})"))
                                .collect::<Vec<_>>()
                                .join(" ")
                        ));
                        push(&mut events, &mut jsonl, &mut truncated, e, opts.max_events);
                    }
                }

                // The same sweep, for regions that are read/write *right now*.
                // A packer that stages plaintext and flips the page executable
                // afterwards is invisible to the executable sweep above.
                let staged = crate::live::dump_private_staging_regions(
                    hproc,
                    pid,
                    &staging,
                    &kernel,
                    &modules,
                    0x10000,
                    32 << 20,
                );
                let staged_pe: Vec<_> = staged.iter().filter(|s| s.looks_like_pe).collect();
                if !staged_pe.is_empty() {
                    let mut e = TraceEvent::new(
                        seq,
                        started.elapsed().as_millis() as u64,
                        0,
                        "private_staging_pe",
                    );
                    seq += 1;
                    e.detail = Some(format!(
                        "{} read/write region(s) open with a PE image: {}",
                        staged_pe.len(),
                        staged_pe
                            .iter()
                            .map(|s| format!(
                                "0x{:x}({}{}B,ent{:.2})",
                                s.base,
                                s.size,
                                if s.complete { "" } else { " head-only " },
                                s.entropy
                            ))
                            .collect::<Vec<_>>()
                            .join(" ")
                    ));
                    push(&mut events, &mut jsonl, &mut truncated, e, opts.max_events);
                }

                // A section that materialised from nothing is unambiguous
                // decryption; raw byte churn may just be relocations. Weight the
                // former above any amount of the latter.
                let score =
                    d.total_changed_bytes + (d.materialised_sections as u64) * (1u64 << 40);
                if best_dump_score.is_none_or(|b| score > b) {
                    promote_unpacked(&staging.join("unpacked"), &root.join("unpacked"));
                    best_dump_score = Some(score);
                    let mut e = TraceEvent::new(
                        seq,
                        started.elapsed().as_millis() as u64,
                        0,
                        "image_snapshot",
                    );
                    seq += 1;
                    e.detail = Some(format!(
                        "changed_sections={} materialised={} bytes={} — new best",
                        d.changed_sections, d.materialised_sections, d.total_changed_bytes
                    ));
                    push(&mut events, &mut jsonl, &mut truncated, e, opts.max_events);
                    image_dump = Some(d);
                }
            }
        }

        if truncated {
            // Emit a sentinel line so a consumer reading the JSONL stream can
            // never mistake a capped log for a complete one.
            let mut gap =
                TraceEvent::new(seq, started.elapsed().as_millis() as u64, 0, "trace_gap");
            gap.detail = Some(format!(
                "event cap of {} reached — the trace is INCOMPLETE from here",
                opts.max_events
            ));
            if let Ok(line) = serde_json::to_string(&gap) {
                let _ = writeln!(jsonl, "{line}");
            }
            notes.push(format!(
                "event cap of {} reached — the trace is INCOMPLETE, later calls were not recorded",
                opts.max_events
            ));
            break;
        }
    }

    let duration_ms = started.elapsed().as_millis() as u64;
    if exit_code.is_none() {
        notes.push(format!(
            "window of {}s closed with the target still running — trace is a prefix, not a complete run",
            opts.seconds
        ));
        unsafe {
            let _ = TerminateProcess(hproc, 0);
        }
    }
    if armed.is_empty() {
        notes.push(
            "no breakpoints were armed — the target may have no resolvable imports yet, or the \
             image was still unpacking. An empty trace here is not evidence of inactivity."
                .into(),
        );
    }
    if functions_traced == 0 {
        let d = iat_fail_diag
            .as_deref()
            .map(|s| format!(" — IAT walk diagnostic: {s}"))
            .unwrap_or_default();
        notes.push(format!(
            "no traced imports resolved from the main image{d}. An empty trace is not evidence \
             of inactivity."
        ));
    }

    if !suppressed.is_empty() {
        let mut v: Vec<(&String, &usize)> = suppressed.iter().collect();
        v.sort_by(|a, b| b.1.cmp(a.1));
        let top: Vec<String> = v
            .iter()
            .take(8)
            .map(|(k, n)| format!("{k} ×{n}"))
            .collect();
        notes.push(format!(
            "event rate limit: {} call(s) beyond {PER_FUNC_CAP} per function were counted in \
             `per_category` but not recorded individually. Most frequent: {}",
            suppressed.values().sum::<usize>(),
            top.join(", ")
        ));
    }

    // The most consequential blind spot, stated unconditionally. A target that
    // issues `syscall` directly never reaches the DLL export, so it never hits a
    // breakpoint — and packed/anti-tamper targets are exactly the ones that do
    // this. Declaring it on every run is what keeps a short trace honest.
    let target_syscall_sites = static_profile
        .as_ref()
        .map(|p| p.direct_syscall_sites)
        .unwrap_or(0);
    let target_requires_elevation = static_profile
        .as_ref()
        .map(|p| p.requires_elevation)
        .unwrap_or(false);

    if target_syscall_sites > 0 {
        notes.push(format!(
            "the target contains {target_syscall_sites} direct syscall stub(s) in its executable \
             sections (a `0F 05` preceded by a bounded `mov eax, <ssn>`, not a bare byte pair). \
             Calls made that way bypass the DLL exports entirely and will NOT appear in this \
             trace — expect it to under-report by an unknown margin."
        ));
    }
    if ntdll_skipped {
        notes.push(
            "ntdll_not_armed: the system ntdll was deliberately left unpatched. This target \
             checksums it and, on finding it modified, maps a fresh copy of ntdll from disk and \
             calls that instead — which bypasses any breakpoint placed in the original. Expect \
             direct ntdll calls to be missing from this trace unless a remapped ntdll was itself \
             instrumented."
                .to_string(),
        );
    }
    if spoofed_calls > 0 {
        notes.push(format!(
            "stealth: answered {spoofed_calls} debugger-detection quer(ies) on the target's \
             behalf. Those calls did NOT execute — their real bodies would have reported that a \
             debugger is present, which is what makes a packer refuse to decrypt. A trace \
             containing spoofed calls describes the target's behaviour under a hidden debugger, \
             not its behaviour unmodified."
        ));
    }
    if let Some(p) = &peb_sanitised {
        notes.push(format!("stealth: {p}"));
    }
    if thread_handle_failures > 0 {
        notes.push(format!(
            "breakpoints_dropped: {thread_handle_failures} hit(s) could not open the faulting \
             thread, so the trap was removed and the breakpoint abandoned rather than left in \
             memory to skip the function's first instruction on every subsequent call. Some calls \
             to those functions are missing from this trace."
        ));
    }
    if double_arm_hits > 0 {
        notes.push(format!(
            "breakpoint_poisoning: {double_arm_hits} hit(s) landed on an address whose recorded \
             original byte was itself 0xCC. Those traps were left in place and run past rather than \
             restored — restoring would re-execute the trap forever. This means two export names \
             share the address and the second arm overwrote the first's saved byte."
        ));
    }
    notes.push(
        "direct_syscall_blind_spot: APIs invoked by a `syscall` instruction rather than through \
         the DLL exports are NOT traced — they never reach the breakpoint. For a packed or \
         anti-tamper target this is the primary reason a trace can under-report."
            .into(),
    );

    // Detach instead of simply exiting when the target is still alive.
    //
    // Windows kills a debuggee whose debugger goes away. That is what made the
    // window closing "close everything": a target sitting in a modal dialog was
    // torn down the instant the trace window ended, taking the dialog and the
    // process with it. Detaching first leaves the target running, so a dialog
    // that is waiting for a click still gets one.
    if exit_code.is_none() {
        let detached = unsafe { DebugActiveProcessStop(pid).is_ok() };
        notes.push(if detached {
            "detached at the end of the window rather than exiting — the target was still running, \
             and a debugger that exits kills its target. The process has been left alive."
                .to_string()
        } else {
            "the trace window closed while the target was still running and detaching failed; the \
             target will be terminated with this process."
                .to_string()
        });
    }

    let _ = jsonl.flush();
    unsafe {
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
    }

    // Coverage mirrors the sibling feature: declare what was and was not
    // observable, so an empty trace never reads as "nothing happened".
    let mut coverage = Coverage::for_run(events.len(), 0, false);
    coverage.memory_regions = crate::live::MechanismCoverage {
        instrumented: true,
        status: if events.is_empty() { "observed_none".into() } else { "observed".into() },
        note: format!("{} trace events recorded", events.len()),
    };
    coverage.network_http = crate::live::MechanismCoverage {
        instrumented: true,
        status: "api_level_only".into(),
        note: "network observed only as WinHTTP/WinINet/WSA API calls — the payload bytes are \
               not captured"
            .into(),
    };
    coverage.filesystem_writes = crate::live::MechanismCoverage {
        instrumented: true,
        status: "api_level_only".into(),
        note: "file activity observed only as CreateFile/WriteFile API calls — the written \
               content is not captured"
            .into(),
    };
    coverage.child_processes = crate::live::MechanismCoverage {
        instrumented: false,
        status: "not_observable".into(),
        note: "DEBUG_ONLY_THIS_PROCESS — child processes are not debugged".into(),
    };
    coverage.kernel_drivers = crate::live::MechanismCoverage {
        instrumented: false,
        status: "not_observable".into(),
        note: "kernel-mode activity is not traced".into(),
    };

    Ok(TraceReport {
        exe: exe.to_string(),
        pid,
        image_base,
        duration_ms,
        exit_code,
        events: events.len(),
        truncated,
        iat_slots_found,
        functions_traced,
        breakpoints_armed: armed.len(),
        bp_hits,
        calls_from_private_memory: calls_from_private,
        target_direct_syscall_sites: target_syscall_sites,
        target_requires_elevation,
        image_dump,
        modules,
        per_category,
        notes,
        coverage,
    })
}

fn set_trap(hthread: HANDLE, on: bool) {
    let mut ctx = CONTEXT {
        ContextFlags: CONTEXT_CONTROL_AMD64,
        ..Default::default()
    };
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

#[repr(C)]
#[derive(Default, Clone, Copy)]
struct ProcessBasicInformation {
    exit_status: i32,
    peb_base_address: u64,
    affinity_mask: u64,
    base_priority: i32,
    unique_process_id: u64,
    inherited_from_unique_process_id: u64,
}

extern "system" {
    fn NtQueryInformationProcess(
        process_handle: HANDLE,
        information_class: u32,
        information: *mut core::ffi::c_void,
        information_length: u32,
        return_length: *mut u32,
    ) -> i32;
}

/// The target's PEB, which holds the tell-tales the loader leaves behind when a
/// process is created under a debugger.
fn target_peb(hproc: HANDLE) -> Option<u64> {
    let mut pbi = ProcessBasicInformation::default();
    let status = unsafe {
        NtQueryInformationProcess(
            hproc,
            0, // ProcessBasicInformation
            (&mut pbi as *mut ProcessBasicInformation).cast(),
            std::mem::size_of::<ProcessBasicInformation>() as u32,
            std::ptr::null_mut(),
        )
    };
    if status == 0 && pbi.peb_base_address != 0 {
        Some(pbi.peb_base_address)
    } else {
        None
    }
}

/// Erase the debugger's fingerprints from the target's PEB.
///
/// The loader sets `BeingDebugged` and the heap-debug bits of `NtGlobalFlag`
/// at process creation. Both are ordinary fields in the target's own memory, so
/// they can simply be corrected — no hooking involved. `IsDebuggerPresent`
/// reads exactly `BeingDebugged`, so this defeats it outright.
fn sanitize_peb(hproc: HANDLE, pid: u32, peb: u64, kernel: &KernelClient) -> Result<(), String> {
    let mut n = 0usize;

    // PEB+0x02 BeingDebugged
    let zero = [0u8];
    let ok_debugged = unsafe {
        WriteProcessMemory(
            hproc,
            (peb + 0x02) as *mut _,
            zero.as_ptr().cast(),
            1,
            Some(&mut n),
        )
        .is_ok()
    };

    // PEB+0xBC NtGlobalFlag. Clear only the three heap-debug bits the loader
    // sets (TAIL_CHECK | FREE_CHECK | VALIDATE_PARAMETERS) and leave the rest
    // of the field alone — the heap reads this too, and zeroing it wholesale
    // changes heap behaviour rather than just hiding the debugger.
    let mut gf = [0u8; 4];
    let mut ok_flag = false;
    if read_mem(hproc, pid, peb + 0xBC, &mut gf, kernel) == 4 {
        let cleaned = (u32::from_le_bytes(gf) & !0x70u32).to_le_bytes();
        ok_flag = unsafe {
            WriteProcessMemory(
                hproc,
                (peb + 0xBC) as *mut _,
                cleaned.as_ptr().cast(),
                4,
                Some(&mut n),
            )
            .is_ok()
        };
    }

    if ok_debugged && ok_flag {
        Ok(())
    } else {
        Err(format!("BeingDebugged={ok_debugged} NtGlobalFlag={ok_flag}"))
    }
}

/// Breakpoints armed before the target's entry point has run.
///
/// Kept deliberately small. Instrumentation is not free for the target: every
/// armed trap is a byte patched into a DLL, and a target that checks or is
/// slowed by those patches can fail to reach its own entry point. On vector.exe
/// the difference is absolute — 8 armed reaches the entry, 512 never does.
const PRE_ENTRY_ARM_CAP: usize = 24;

/// What to answer for a `PROCESSINFOCLASS` query, or `None` if the call is not
/// a debugger-detection query and must be allowed to run.
///
/// Returns `(status, value, value_width_bytes, label)`.
fn debug_query_lie(class: u32) -> Option<(i32, u64, usize, &'static str)> {
    const STATUS_PORT_NOT_SET: i32 = 0xC000_0353u32 as i32;
    match class {
        // A debugger owns a non-zero debug port. Report none.
        7 => Some((0, 0, 8, "ProcessDebugPort=0")),
        // A clean process gets STATUS_PORT_NOT_SET rather than a handle.
        30 => Some((
            STATUS_PORT_NOT_SET,
            0,
            8,
            "ProcessDebugObjectHandle=STATUS_PORT_NOT_SET",
        )),
        // 1 is NoDebugInherit, i.e. "not being debugged".
        31 => Some((0, 1, 4, "ProcessDebugFlags=1")),
        _ => None,
    }
}

/// Answer a debugger-detection query on the target's behalf.
///
/// Returns a description of the lie told, or `None` when the call is not a
/// debugger-detection query and must be allowed to run.
///
/// This does not hook anything: the caller has already trapped the call, and
/// the function's body is skipped by returning straight to its caller with a
/// fabricated `NTSTATUS`. The trap is left armed, so every later call is
/// answered the same way.
fn spoof_debug_query(
    hproc: HANDLE,
    pid: u32,
    ht: HANDLE,
    func_lc: &str,
    kernel: &KernelClient,
) -> Option<String> {
    if !func_lc.contains("ntqueryinformationprocess") {
        return None;
    }
    let mut ctx = CONTEXT {
        ContextFlags: CONTEXT_CONTROL_AMD64 | CONTEXT_INTEGER_AMD64,
        ..Default::default()
    };
    if unsafe { GetThreadContext(ht, &mut ctx) }.is_err() {
        return None;
    }

    // x64: RCX=handle, RDX=class, R8=buffer, R9=length.
    let class = ctx.Rdx as u32;
    let buf = ctx.R8;

    let (status, value, width, label) = debug_query_lie(class)?;

    if buf != 0 {
        let mut n = 0usize;
        let bytes = (value as u32).to_le_bytes();
        unsafe {
            let _ = WriteProcessMemory(
                hproc,
                buf as *mut _,
                bytes.as_ptr().cast(),
                width,
                Some(&mut n),
            );
        }
    }

    // Return to the caller: RAX carries the fabricated status and RIP the
    // return address, so the real body never executes.
    let ret = rd_u64(hproc, pid, ctx.Rsp, kernel).unwrap_or(0);
    if ret == 0 {
        return None;
    }
    ctx.Rax = status as u64;
    ctx.Rip = ret;
    ctx.Rsp = ctx.Rsp.wrapping_add(8);
    if unsafe { SetThreadContext(ht, &ctx) }.is_err() {
        return None;
    }
    Some(label.to_string())
}

/// Copy a snapshot's captured sections over `unpacked/`.
///
/// `unpacked/` must hold the most-decrypted image seen, not the most recent
/// one, so each new snapshot is staged elsewhere and only promoted when it
/// beats the current best.
fn promote_unpacked(from: &Path, to: &Path) {
    let Ok(entries) = std::fs::read_dir(from) else {
        return;
    };
    let _ = std::fs::create_dir_all(to);
    for e in entries.flatten() {
        let src = e.path();
        if src.is_file() {
            if let Some(name) = src.file_name() {
                let _ = std::fs::copy(&src, to.join(name));
            }
        }
    }
}

/// Re-attach modules the loader list does not know about.
///
/// `enumerate_user_modules` reads the PEB loader list, and it is re-run at
/// several points in the loop — each time silently dropping any module that was
/// registered from a LOAD_DLL event but never entered the loader list. A
/// manually mapped image is exactly that, so without this it is scanned once and
/// then forgotten, and the copy of ntdll the target actually calls stays
/// uninstrumented.
fn merge_mapped_modules(modules: &mut Vec<UserModule>, mapped: &[UserModule]) {
    for m in mapped {
        if !modules.iter().any(|x| x.base == m.base) {
            modules.push(m.clone());
        }
    }
}

/// Identify a mapped image that the loader list does not know about.
///
/// A manually mapped copy of a DLL never appears in the PEB loader list, so
/// `enumerate_user_modules` cannot see it — which means it is never scanned for
/// exports and never instrumented, even though it is exactly what the process
/// goes on to call. On vector.exe a fresh copy of ntdll is mapped at a random
/// high address and the loader list never mentions it; the LOAD_DLL debug event
/// is the only notice it gives. Read the name from its export directory and the
/// size from its optional header so it can be treated like any other module.
fn mapped_module_identity(
    hproc: HANDLE,
    pid: u32,
    base: u64,
    kernel: &KernelClient,
) -> Option<(String, u64)> {
    let mut hdr = [0u8; 0x1000];
    if read_mem(hproc, pid, base, &mut hdr, kernel) < 0x100 || &hdr[0..2] != b"MZ" {
        return None;
    }
    let e = u32::from_le_bytes([hdr[0x3C], hdr[0x3D], hdr[0x3E], hdr[0x3F]]) as usize;
    if e + 0x100 > hdr.len() || &hdr[e..e + 4] != b"PE\x00\x00" {
        return None;
    }
    let opt = e + 0x18;
    let soi =
        u32::from_le_bytes([hdr[opt + 0x38], hdr[opt + 0x39], hdr[opt + 0x3A], hdr[opt + 0x3B]])
            as u64;
    // Data directory 0 is the export table.
    let dd = opt + 0x70;
    let exp_rva =
        u32::from_le_bytes([hdr[dd], hdr[dd + 1], hdr[dd + 2], hdr[dd + 3]]) as u64;

    let mut name = format!("0x{base:x}");
    if exp_rva != 0 {
        // IMAGE_EXPORT_DIRECTORY.Name is a u32 RVA at offset 0x0C.
        if let Some(n) = rd_cstr(hproc, pid, base + exp_rva + 0x0C, 128, kernel) {
            if !n.is_empty() {
                name = n;
            }
        }
    }
    Some((name, soi))
}

/// Arm DR0 as an execution breakpoint on `addr`, for one thread.
///
/// Hardware breakpoints are per-thread, so this has to be applied to every
/// thread that could reach the address — the main thread, plus any created
/// later. Nothing is written into the target's memory, which is the whole
/// point: a target that checksums its own code finds nothing.
fn set_hw_exec_breakpoint(hthread: HANDLE, addr: u64) -> bool {
    let mut ctx = CONTEXT {
        ContextFlags: CONTEXT_DEBUG_REGISTERS_AMD64,
        ..Default::default()
    };
    unsafe {
        if GetThreadContext(hthread, &mut ctx).is_err() {
            return false;
        }
        ctx.Dr0 = addr;
        // L0 (bit 0) enables local breakpoint 0; RW0 (bits 16-17) = 00 means
        // execute; LEN0 (bits 18-19) = 00 means one byte. Clear those bits
        // first so a leftover RW/LEN from someone else cannot change the sense.
        ctx.Dr7 = (ctx.Dr7 & !0xF_0000) | 0x1;
        SetThreadContext(hthread, &ctx).is_ok()
    }
}

/// Disarm DR0 for one thread.
fn clear_hw_exec_breakpoint(hthread: HANDLE) -> bool {
    let mut ctx = CONTEXT {
        ContextFlags: CONTEXT_DEBUG_REGISTERS_AMD64,
        ..Default::default()
    };
    unsafe {
        if GetThreadContext(hthread, &mut ctx).is_err() {
            return false;
        }
        ctx.Dr0 = 0;
        ctx.Dr7 &= !0x1;
        SetThreadContext(hthread, &ctx).is_ok()
    }
}

fn step_back_rip(hthread: HANDLE) {
    let mut ctx = CONTEXT {
        ContextFlags: CONTEXT_CONTROL_AMD64,
        ..Default::default()
    };
    unsafe {
        if GetThreadContext(hthread, &mut ctx).is_ok() {
            ctx.Rip = ctx.Rip.wrapping_sub(1);
            let _ = SetThreadContext(hthread, &ctx);
        }
    }
}

/// Collapse candidates that share an address, keeping the first.
///
/// ntdll exports most system calls twice — `NtProtectVirtualMemory` and
/// `ZwProtectVirtualMemory` are different names for one address. Both survive
/// the "already armed?" check at collection time because neither is armed yet,
/// so both reach the arming loop. Arming the second one reads back the 0xCC the
/// first just wrote and records *that* as the saved original byte. On the next
/// hit the "restore" writes 0xCC over 0xCC, the rewind puts RIP back on the
/// trap, and the target spins forever instead of executing.
///
/// The caller sorts by priority first, so the surviving name is the
/// highest-priority one.
fn dedup_candidates_by_addr(
    cands: Vec<(u8, u64, String, String)>,
) -> Vec<(u8, u64, String, String)> {
    let mut seen = std::collections::HashSet::new();
    let mut out = Vec::with_capacity(cands.len());
    for c in cands {
        if seen.insert(c.1) {
            out.push(c);
        }
    }
    out
}

fn in_any_module(addr: u64, modules: &[UserModule]) -> bool {
    modules
        .iter()
        .any(|m| addr >= m.base && addr < m.base + m.size)
}

/// Classify a caller address: inside an image, or in private executable memory.
fn classify_caller(addr: u64, modules: &[UserModule]) -> Option<String> {
    if addr == 0 {
        return None;
    }
    for m in modules {
        if addr >= m.base && addr < m.base + m.size {
            return Some(format!("image:{}+0x{:x}", m.name, addr - m.base));
        }
    }
    Some("private_exec".into())
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

pub fn summary_md(r: &TraceReport) -> String {
    let mut s = String::new();
    s.push_str(&format!("# live trace — {} (pid {})\n\n", r.exe, r.pid));
    s.push_str(&format!("- image base: `0x{:x}`\n", r.image_base));
    s.push_str(&format!("- observed for: {} ms\n", r.duration_ms));
    s.push_str(&format!(
        "- exit: {}\n",
        match r.exit_code {
            Some(c) => format!("code {c}"),
            None => "still running when the window closed".into(),
        }
    ));
    s.push_str(&format!("- IAT slots resolved: {}\n", r.iat_slots_found));
    s.push_str(&format!("- functions traced: **{}**\n", r.functions_traced));
    s.push_str(&format!("- breakpoint hits: **{}**\n", r.bp_hits));
    s.push_str(&format!("- events recorded: **{}**{}\n", r.events, if r.truncated { " (TRUNCATED)" } else { "" }));
    s.push_str(&format!(
        "- calls from private executable memory: **{}**\n",
        r.calls_from_private_memory
    ));

    if r.calls_from_private_memory > 0 {
        s.push_str(
            "\n> **Shellcode execution observed.** API calls originated from addresses outside \
             every mapped module, i.e. from private executable memory.\n",
        );
    }

    if r.target_direct_syscall_sites > 0 {
        s.push_str(&format!(
            "\n> ⚠️ **This trace under-reports the target.** It contains {} direct syscall \
             site(s) in its executable sections; those calls bypass the DLL exports entirely and \
             never reach a breakpoint. Absence of API events is expected, not evidence of \
             inactivity.\n",
            r.target_direct_syscall_sites
        ));
    }

    if r.looks_like_antitamper_exit() {
        s.push_str(
            "\n> ⚠️ **Possible anti-tamper early exit.** The target exited within 3s, resolved \
             breakpoints, and made no observable API calls. This is consistent with debugger \
             detection — treat this trace as inconclusive, not as evidence of inactivity.\n",
        );
    }

    let blind = r.coverage.blind_spots();
    if !blind.is_empty() {
        s.push_str(&format!(
            "\n> **Not observed by this run:** {}.\n",
            blind.join(", ")
        ));
    }

    if !r.per_category.is_empty() {
        s.push_str("\n## Calls by category\n\n| Category | Calls |\n|---|---|\n");
        let mut cats: Vec<_> = r.per_category.iter().collect();
        cats.sort_by(|a, b| b.1.cmp(a.1));
        for (k, v) in cats {
            s.push_str(&format!("| `{k}` | {v} |\n"));
        }
    }
    s
}

pub fn report_md(r: &TraceReport) -> String {
    let mut s = summary_md(r);
    s.push_str("\n---\n\n## Modules loaded\n\n| base | size | module |\n|---|---|---|\n");
    for m in &r.modules {
        s.push_str(&format!("| `0x{:x}` | {} | `{}` |\n", m.base, m.size, m.name));
    }

    s.push_str("\n## Coverage — what this run could and could not observe\n\n");
    s.push_str("| Mechanism | Instrumented | Status | Note |\n|---|---|---|---|\n");
    for (name, m) in [
        ("api_calls", &r.coverage.memory_regions),
        ("network_http", &r.coverage.network_http),
        ("filesystem_writes", &r.coverage.filesystem_writes),
        ("child_processes", &r.coverage.child_processes),
        ("kernel_drivers", &r.coverage.kernel_drivers),
    ] {
        s.push_str(&format!(
            "| `{name}` | {} | `{}` | {} |\n",
            if m.instrumented { "yes" } else { "**no**" },
            m.status,
            m.note
        ));
    }

    if !r.notes.is_empty() {
        s.push_str("\n## Notes\n\n");
        for n in &r.notes {
            s.push_str(&format!("- {n}\n"));
        }
    }

    s.push_str("\n---\n\n> A trace records **observed API calls**. Syscalls are not directly visible from user mode, and direct-syscall stubs bypass the DLLs entirely — those calls do not appear here. An empty trace is not evidence that the target did nothing.\n");
    s
}

/// Resolve a path for display.
pub fn display_path(p: &Path) -> String {
    p.display().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mod_at(base: u64, size: u64, name: &str) -> UserModule {
        UserModule {
            base,
            size,
            name: name.into(),
            path: String::new(),
        }
    }

    fn base_report() -> TraceReport {
        TraceReport {
            exe: "t.exe".into(),
            pid: 1,
            image_base: 0x1400_0000,
            duration_ms: 1000,
            exit_code: None,
            events: 10,
            truncated: false,
            iat_slots_found: 0,
            functions_traced: 0,
            breakpoints_armed: 0,
            bp_hits: 0,
            calls_from_private_memory: 0,
            target_direct_syscall_sites: 0,
            target_requires_elevation: false,
            image_dump: None,
            modules: vec![],
            per_category: HashMap::new(),
            notes: vec![],
            coverage: Coverage::for_run(10, 0, false),
        }
    }

    #[test]
    fn memory_apis_are_categorised() {
        assert_eq!(classify_api("KERNEL32.dll", "VirtualAlloc"), ApiCategory::Memory);
        assert_eq!(classify_api("KERNEL32.dll", "VirtualProtect"), ApiCategory::Memory);
        assert_eq!(
            classify_api("ntdll.dll", "NtAllocateVirtualMemory"),
            ApiCategory::Memory
        );
        assert_eq!(
            classify_api("KERNEL32.dll", "WriteProcessMemory"),
            ApiCategory::Memory
        );
    }

    #[test]
    fn injection_primitives_are_categorised() {
        assert_eq!(
            classify_api("KERNEL32.dll", "CreateRemoteThread"),
            ApiCategory::Process
        );
        assert_eq!(classify_api("KERNEL32.dll", "OpenProcess"), ApiCategory::Process);
        assert_eq!(classify_api("ntdll.dll", "NtCreateThreadEx"), ApiCategory::Process);
    }

    #[test]
    fn network_and_file_are_distinguished() {
        assert_eq!(classify_api("WINHTTP.dll", "WinHttpOpen"), ApiCategory::Network);
        assert_eq!(classify_api("WININET.dll", "InternetOpenA"), ApiCategory::Network);
        assert_eq!(classify_api("WS2_32.dll", "connect"), ApiCategory::Network);
        assert_eq!(classify_api("KERNEL32.dll", "CreateFileW"), ApiCategory::File);
        assert_eq!(classify_api("KERNEL32.dll", "WriteFile"), ApiCategory::File);
    }

    #[test]
    fn bare_socket_verbs_only_count_inside_socket_dlls() {
        assert_eq!(classify_api("WS2_32.dll", "send"), ApiCategory::Network);
        // `send` in an unrelated DLL is not a socket call.
        assert_ne!(classify_api("SOMELIB.dll", "send"), ApiCategory::Network);
    }

    #[test]
    fn unknown_api_is_other_and_not_traced_by_default() {
        let c = classify_api("foo.dll", "DoSomethingCustom");
        assert_eq!(c, ApiCategory::Other);
        assert!(!c.default_traced());
    }

    #[test]
    fn every_known_category_is_traced_by_default() {
        for c in [
            ApiCategory::Memory,
            ApiCategory::Module,
            ApiCategory::Process,
            ApiCategory::File,
            ApiCategory::Network,
            ApiCategory::Registry,
            ApiCategory::Crypto,
            ApiCategory::Sync,
        ] {
            assert!(c.default_traced(), "{c:?} should be traced by default");
        }
    }

    #[test]
    fn caller_inside_a_module_is_attributed_to_the_image() {
        let mods = vec![mod_at(0x1000, 0x1000, "a.exe")];
        assert_eq!(
            classify_caller(0x1234, &mods).as_deref(),
            Some("image:a.exe+0x234")
        );
    }

    #[test]
    fn caller_outside_every_module_is_the_shellcode_signal() {
        let mods = vec![mod_at(0x1000, 0x1000, "a.exe")];
        assert_eq!(
            classify_caller(0x9000_0000, &mods).as_deref(),
            Some("private_exec")
        );
    }

    #[test]
    fn caller_of_zero_is_unattributed() {
        let mods: Vec<UserModule> = vec![];
        assert_eq!(classify_caller(0, &mods), None);
    }

    #[test]
    fn a_capped_trace_is_never_a_success() {
        let mut r = base_report();
        r.events = 500;
        r.truncated = true;
        assert!(!r.succeeded(), "a truncated trace must not read as success");
    }

    #[test]
    fn an_empty_trace_is_never_a_success() {
        let mut r = base_report();
        r.events = 0;
        assert!(!r.succeeded());
    }

    #[test]
    fn antitamper_heuristic_requires_corroboration() {
        let mut r = base_report();
        r.exit_code = Some(1);
        r.duration_ms = 200;
        r.bp_hits = 0;
        r.events = 2;
        assert!(r.looks_like_antitamper_exit());

        // A long run that made no calls is not the same signature.
        r.duration_ms = 30_000;
        assert!(!r.looks_like_antitamper_exit());

        // Neither is a short run that did make calls.
        r.duration_ms = 200;
        r.bp_hits = 50;
        assert!(!r.looks_like_antitamper_exit());
    }

    #[test]
    fn elevation_failure_is_its_own_verdict_with_the_os_code() {
        let e = TraceError::SpawnFailed {
            os_error: ERROR_ELEVATION_REQUIRED,
            elevation_required: true,
            message: "The requested operation requires elevation.".into(),
        };
        let s = e.to_string();
        assert!(s.contains("740"), "the raw OS error must be reported");
        assert!(s.contains("requireAdministrator"));
    }

    #[test]
    fn a_non_elevation_spawn_failure_does_not_claim_elevation() {
        let e = TraceError::SpawnFailed {
            os_error: 2,
            elevation_required: false,
            message: "The system cannot find the file specified.".into(),
        };
        assert!(!e.to_string().contains("requireAdministrator"));
    }

    #[test]
    fn output_failure_names_the_path() {
        let e = TraceError::OutputNotWritable {
            path: r"C:\out\EVENTS.jsonl".into(),
            message: "access denied".into(),
        };
        let s = e.to_string();
        assert!(s.contains("EVENTS.jsonl"));
        assert!(s.contains("access denied"));
    }

    /// ntdll exports each system call under two names at one address. Arming
    /// both saved the trap byte as "the original", which made the target
    /// re-execute its own breakpoint forever — a plain notepad reached its
    /// entry point 0 times out of 4 runs because of this.
    #[test]
    fn alias_exports_collapse_to_one_candidate() {
        let cands = vec![
            (0u8, 0x1000u64, "ntdll.dll".into(), "NtProtectVirtualMemory".into()),
            (0u8, 0x1000u64, "ntdll.dll".into(), "ZwProtectVirtualMemory".into()),
            (1u8, 0x2000u64, "kernel32.dll".into(), "CreateFileW".into()),
        ];
        let out = dedup_candidates_by_addr(cands);
        assert_eq!(out.len(), 2, "the two aliases must collapse into one");
        assert_eq!(out[0].1, 0x1000);
        assert_eq!(
            out[0].3, "NtProtectVirtualMemory",
            "the first name for an address is the one kept"
        );
        assert_eq!(out[1].1, 0x2000, "distinct addresses are untouched");
    }

    #[test]
    fn dedup_preserves_every_distinct_address() {
        let cands = vec![
            (0u8, 0x10u64, "a".into(), "a".into()),
            (0u8, 0x20u64, "b".into(), "b".into()),
            (0u8, 0x30u64, "c".into(), "c".into()),
        ];
        assert_eq!(dedup_candidates_by_addr(cands).len(), 3);
    }

    /// The three queries a packer uses to decide whether it is being watched.
    /// Getting any of these wrong is the difference between a clean run and the
    /// target refusing to decrypt.
    #[test]
    fn debug_detection_queries_are_answered_with_a_lie() {
        // ProcessDebugPort: a debugger owns a non-zero port.
        let (status, value, width, _) = debug_query_lie(7).expect("port must be answered");
        assert_eq!(status, 0, "port query returns STATUS_SUCCESS");
        assert_eq!(value, 0, "port must read as zero, i.e. no debugger");
        assert_eq!(width, 8);

        // ProcessDebugObjectHandle: a clean process gets STATUS_PORT_NOT_SET.
        let (status, value, width, _) = debug_query_lie(30).expect("handle must be answered");
        assert_eq!(
            status, 0xC000_0353u32 as i32,
            "a clean process gets STATUS_PORT_NOT_SET, not success"
        );
        assert_eq!(value, 0);
        assert_eq!(width, 8);

        // ProcessDebugFlags: 1 means NoDebugInherit, i.e. not debugged.
        let (status, value, width, _) = debug_query_lie(31).expect("flags must be answered");
        assert_eq!(status, 0);
        assert_eq!(value, 1, "0 would mean 'being debugged'");
        assert_eq!(width, 4, "ProcessDebugFlags is a ULONG, not a u64");
    }

    /// Only the debugger-detection classes may be intercepted. Answering
    /// anything else would silently corrupt a legitimate query.
    #[test]
    fn non_debug_queries_are_left_alone() {
        for class in [0u32, 1, 2, 3, 6, 8, 9, 26, 29, 32, 34, 36, 51, 60, 0xFFFF] {
            assert!(
                debug_query_lie(class).is_none(),
                "PROCESSINFOCLASS {class} must not be spoofed"
            );
        }
    }
}
