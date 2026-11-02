//! Live memory reconnaissance for the debug host.
//!
//! x64dbg-shaped "dump everything": walk the target's virtual address space,
//! classify every committed region, flag injected/downloaded shellcode (private
//! committed executable pages that are *not* backed by a PE on disk), dump the
//! bytes to disk with provenance, and capture the kernel drivers the target
//! loads.
//!
//! Honesty contract (CRITICAL.md): a dumped region is raw bytes captured from a
//! live process. `pe=true` means the bytes parse as a PE. Nothing here claims a
//! decrypt — an unpacked `.text` is a `runtime_dump` transform, not a cipher.

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use street_core::entropy::shannon;
use street_core::sha256_bytes;
use street_kernel::KernelClient;
use windows::core::PWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Diagnostics::Debug::{
    ContinueDebugEvent, WaitForDebugEvent, CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT,
    DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT,
};
use windows::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, Module32FirstW, Module32NextW, Thread32First, Thread32Next,
    MODULEENTRY32W, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPTHREAD, THREADENTRY32,
};
use windows::Win32::System::Memory::{VirtualQueryEx, MEMORY_BASIC_INFORMATION};
use windows::Win32::System::ProcessStatus::{
    EnumDeviceDrivers, GetDeviceDriverBaseNameW, GetDeviceDriverFileNameW,
};
use windows::Win32::System::Threading::{
    CreateProcessW, OpenThread, ResumeThread, SuspendThread, TerminateProcess,
    DEBUG_ONLY_THIS_PROCESS, PROCESS_INFORMATION, STARTUPINFOW, THREAD_SUSPEND_RESUME,
};

// ---------------------------------------------------------------------------
// Raw page constants.
//
// Declared numerically rather than imported so the module does not depend on
// which `Win32_System_Memory` constants the windows crate happens to re-export.
// ---------------------------------------------------------------------------

const MEM_COMMIT: u32 = 0x1000;
const MEM_PRIVATE: u32 = 0x20000;
const MEM_MAPPED: u32 = 0x40000;
const MEM_IMAGE: u32 = 0x1000_0000;

const PROT_EXEC_MASK: u32 = 0xF0; // 0x10|0x20|0x40|0x80
const PROT_WRITE_MASK: u32 = 0x0C | 0xC0; // RW|WRITECOPY|EXEC_RW|EXEC_WC
const PAGE_GUARD_BIT: u32 = 0x100;

/// Upper bound of x64 user address space. `GetSystemInfo` lives behind a
/// windows feature this crate does not enable, and the bound is architecturally
/// fixed, so it is a constant here.
const USER_MAX: u64 = 0x0000_7FFF_FFFF_0000;

const PAGE_SIZE: u64 = 0x1000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RegionKind {
    /// Backed by a PE image on disk (a loaded module).
    Image,
    /// Section / file mapping, not an image.
    Mapped,
    /// Private + executable: classic injected shellcode.
    PrivateExec,
    /// Private + RWX: shellcode or a JIT that flips protection.
    PrivateRwx,
    /// Private, not executable.
    Private,
}

impl RegionKind {
    pub fn is_injection_candidate(self) -> bool {
        matches!(self, RegionKind::PrivateExec | RegionKind::PrivateRwx)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemRegion {
    pub base: u64,
    pub size: u64,
    pub protect: u32,
    pub kind: RegionKind,
    pub executable: bool,
    pub writable: bool,
    pub guard: bool,
    /// Populated for `Image` regions from the Toolhelp module list.
    pub module: Option<String>,
    /// Shannon entropy of a bounded sample (executable regions only).
    pub entropy: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DumpArtifact {
    pub base: u64,
    pub size: u64,
    pub kind: RegionKind,
    /// Path relative to the dump root.
    pub file: String,
    pub sha256: String,
    pub entropy: f64,
    /// Bytes begin with `MZ`.
    pub mz: bool,
    /// Bytes parse as a PE.
    pub pe: bool,
    pub is_64: bool,
    pub strings: Vec<String>,
    pub disasm_head: Vec<String>,
    pub note: String,
    /// `true` when the region exceeded `max_region` and only a prefix was
    /// captured. A partial capture is NOT a complete dump and must never be
    /// read as one — the sha256 covers the prefix only.
    pub partial: bool,
    /// The full region size as reported by `VirtualQueryEx`, before the cap.
    /// Equal to `size` when the capture is complete.
    pub region_size: u64,
    /// Milliseconds into the run when this region was first observed.
    pub first_seen_ms: u64,
}

/// Whether a given mechanism was instrumented for this run, and what the result
/// of looking through it was.
///
/// This exists so that "we looked and found nothing" can never be confused with
/// "we could not look". Those two states carry completely different amounts of
/// information, and collapsing them produces false confidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MechanismCoverage {
    pub instrumented: bool,
    /// `observed_none` · `not_observable` · `window_closed` · `delta_only`
    pub status: String,
    pub note: String,
}

impl MechanismCoverage {
    fn not_observable(note: &str) -> Self {
        Self {
            instrumented: false,
            status: "not_observable".into(),
            note: note.into(),
        }
    }

    fn observed(count: usize) -> Self {
        Self {
            instrumented: true,
            status: if count == 0 { "observed_none".into() } else { "observed".into() },
            note: if count == 0 {
                "instrumented and sampled for the whole window; nothing matched".into()
            } else {
                format!("{count} region(s) captured")
            },
        }
    }
}

/// Declares, for every mechanism, whether this run was able to look at it.
///
/// Always emitted. A report with zero artifacts and no coverage block is
/// indistinguishable from a clean bill of health, which is the failure this
/// type exists to prevent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Coverage {
    pub memory_regions: MechanismCoverage,
    pub network_http: MechanismCoverage,
    pub filesystem_writes: MechanismCoverage,
    pub child_processes: MechanismCoverage,
    pub kernel_drivers: MechanismCoverage,
    pub scan_mode: String,
    pub scan_interval_ms: u64,
    /// Polling cannot see a region created, used and freed between two scans.
    pub missed_between_scans: bool,
}

impl Coverage {
    pub fn for_run(artifacts: usize, interval_ms: u64, driver_enum_ok: bool) -> Self {
        Self {
            memory_regions: MechanismCoverage::observed(artifacts),
            network_http: MechanismCoverage::not_observable(
                "no WinHTTP / WinINet / ws2_32 / ETW instrumentation — the HTTP body and \
                 any download are not observed",
            ),
            filesystem_writes: MechanismCoverage::not_observable(
                "no minifilter / ReadDirectoryChangesW / NtWriteFile hook — file drops are \
                 not observed",
            ),
            child_processes: MechanismCoverage::not_observable(
                "target spawned DEBUG_ONLY_THIS_PROCESS — child processes are not debugged",
            ),
            kernel_drivers: MechanismCoverage {
                instrumented: driver_enum_ok,
                status: if driver_enum_ok { "delta_only".into() } else { "not_observable".into() },
                note: if driver_enum_ok {
                    "delta across the run window; no PID attribution".into()
                } else {
                    "EnumDeviceDrivers returned nothing — driver delta is meaningless".into()
                },
            },
            scan_mode: "polling".into(),
            scan_interval_ms: interval_ms,
            missed_between_scans: true,
        }
    }

    /// True when every mechanism carries an explicit declaration.
    pub fn is_complete(&self) -> bool {
        !self.memory_regions.status.is_empty()
            && !self.network_http.status.is_empty()
            && !self.filesystem_writes.status.is_empty()
            && !self.child_processes.status.is_empty()
            && !self.kernel_drivers.status.is_empty()
    }

    /// Mechanisms that were never instrumented, for use in report wording.
    pub fn blind_spots(&self) -> Vec<&'static str> {
        let mut v = Vec::new();
        if !self.network_http.instrumented {
            v.push("network traffic (HTTP downloads)");
        }
        if !self.filesystem_writes.instrumented {
            v.push("file-system writes (file drops)");
        }
        if !self.child_processes.instrumented {
            v.push("child processes");
        }
        v
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KernelModule {
    pub base: u64,
    pub name: String,
    /// NT-style image path from `GetDeviceDriverFileNameW`, e.g.
    /// `\SystemRoot\System32\drivers\foo.sys` or `\??\C:\...`. Empty when the
    /// driver publishes no file name (a memory-only image).
    #[serde(default)]
    pub path: String,
}

/// A kernel driver image captured from a live run.
///
/// Provenance is explicit because the two sources mean different things:
/// `disk` is the file as shipped, `kernel_memory` is the image as it exists in
/// the kernel right now — which is the only copy available for a driver that
/// was mapped from memory and never had a file, or whose file was dropped and
/// deleted before the window closed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DriverArtifact {
    pub name: String,
    pub base: u64,
    /// NT image path as reported by the loader.
    pub nt_path: String,
    /// Resolved filesystem path, when the NT path could be mapped.
    pub fs_path: Option<String>,
    /// `disk` · `kernel_memory` · `disk+kernel_memory` · `failed`
    pub source: String,
    /// Relative path of the captured file under the dump root.
    pub file: Option<String>,
    pub size: u64,
    pub sha256: String,
    pub entropy: f64,
    pub mz: bool,
    pub pe: bool,
    pub is_64: bool,
    pub strings: Vec<String>,
    /// Present in the "before" snapshot and absent after — the driver unloaded.
    pub unloaded: bool,
    pub note: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserModule {
    pub base: u64,
    pub size: u64,
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveEvent {
    pub at_ms: u64,
    pub kind: String,
    pub detail: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiveDumpReport {
    pub exe: String,
    pub pid: u32,
    pub image_base: u64,
    pub kernel_driver_available: bool,
    pub duration_ms: u64,
    /// Committed regions at the **final** scan — a point-in-time inventory, not
    /// a cumulative count. A region that appeared and died mid-run shows up in
    /// `artifacts` but not here. Use `artifacts.len()` as the authority.
    pub region_count: usize,
    /// Executable-private regions at the final scan. Same caveat as above.
    pub shellcode_region_count: usize,
    /// Kernel drivers present before the target started.
    pub kernel_drivers_before: Vec<KernelModule>,
    /// Drivers present after — diff against `before` to see what the target loaded.
    pub kernel_drivers_after: Vec<KernelModule>,
    /// Drivers that appeared while the target ran.
    pub kernel_drivers_loaded: Vec<KernelModule>,
    /// Drivers that were present before the target started and gone after —
    /// loaded-and-unloaded inside the window, or unloaded by the target.
    #[serde(default)]
    pub kernel_drivers_unloaded: Vec<KernelModule>,
    /// Bytes captured for the drivers that appeared during the run.
    #[serde(default)]
    pub driver_artifacts: Vec<DriverArtifact>,
    /// The entry point's first `call`, followed to its target — the packer's
    /// decryptor stub, captured rather than merely named.
    #[serde(default)]
    pub entry_call: Option<EntryCallCapture>,
    pub modules: Vec<UserModule>,
    pub artifacts: Vec<DumpArtifact>,
    pub events: Vec<LiveEvent>,
    pub notes: Vec<String>,
    /// What this run could and could not observe. Always present.
    pub coverage: Coverage,
}

#[derive(Debug, Clone)]
pub struct LiveDumpOptions {
    pub out_dir: PathBuf,
    pub seconds: u64,
    pub scan_interval_ms: u64,
    /// Skip regions larger than this (avoid filling the disk).
    pub max_region: usize,
    /// Ignore executable regions smaller than this (noise floor).
    pub min_shellcode: usize,
}

impl Default for LiveDumpOptions {
    fn default() -> Self {
        Self {
            out_dir: PathBuf::from("output").join("livedump"),
            seconds: 20,
            scan_interval_ms: 500,
            max_region: 8 * 1024 * 1024,
            min_shellcode: 0x40,
        }
    }
}

// ---------------------------------------------------------------------------
// Memory access — RPM first, kernel CR3 walk as fallback
// ---------------------------------------------------------------------------

/// Read `buf.len()` bytes from `addr` in `pid`. Tries `ReadProcessMemory`
/// first; if that fails or returns short, falls back to the kernel client's
/// physical walk. Returns the number of bytes actually filled.
pub fn read_mem(
    hproc: HANDLE,
    pid: u32,
    addr: u64,
    buf: &mut [u8],
    kernel: &KernelClient,
) -> usize {
    if addr == 0 || buf.is_empty() {
        return 0;
    }
    let mut n = 0usize;
    let ok = unsafe {
        windows::Win32::System::Diagnostics::Debug::ReadProcessMemory(
            hproc,
            addr as *const _,
            buf.as_mut_ptr().cast(),
            buf.len(),
            Some(&mut n),
        )
        .is_ok()
    };
    if ok && n > 0 {
        return n;
    }
    if let Some(k) = kernel.read_virtual(pid, addr, buf.len() as u32) {
        let m = k.len().min(buf.len());
        buf[..m].copy_from_slice(&k[..m]);
        return m;
    }
    0
}

/// Read up to `max` bytes, stopping early on a short/failed read.
fn read_capped(
    hproc: HANDLE,
    pid: u32,
    addr: u64,
    want: usize,
    max: usize,
    kernel: &KernelClient,
) -> Vec<u8> {
    let len = want.min(max);
    let mut buf = vec![0u8; len];
    let got = read_mem(hproc, pid, addr, &mut buf, kernel);
    buf.truncate(got);
    buf
}

// ---------------------------------------------------------------------------
// Region enumeration and classification
// ---------------------------------------------------------------------------

/// Classify a committed region from its page protection and memory type.
///
/// The injection test is: private memory (not backed by a file) that is
/// executable. `MEM_IMAGE` is always a real module, and `MEM_MAPPED` is a file
/// or section mapping, so neither is shellcode however executable it looks.
pub fn classify_kind(protect: u32, ty: u32) -> RegionKind {
    let executable = protect & PROT_EXEC_MASK != 0;
    let writable = protect & PROT_WRITE_MASK != 0;
    match ty {
        MEM_IMAGE => RegionKind::Image,
        MEM_MAPPED => RegionKind::Mapped,
        MEM_PRIVATE => {
            if executable && writable {
                RegionKind::PrivateRwx
            } else if executable {
                RegionKind::PrivateExec
            } else {
                RegionKind::Private
            }
        }
        _ => RegionKind::Private,
    }
}

/// Capture a module's in-memory image.
///
/// A packer that does not decrypt in place has to put its plaintext somewhere.
/// The common answer is to map a fresh image — reflectively, or through the
/// loader — at an address that has nothing to do with the file on disk. That
/// image never appears in a diff of the original file, so it has to be captured
/// where it is actually mapped.
///
/// The size comes from the mapped PE header, not from a module list, so this
/// works for images the loader was never told about.
///
/// Returns the number of bytes captured.
pub fn dump_module_memory(
    hproc: HANDLE,
    pid: u32,
    base: u64,
    name: &str,
    out_dir: &Path,
    kernel: &KernelClient,
) -> Option<usize> {
    // PE headers first: e_lfanew at +0x3C, SizeOfImage at OptionalHeader+0x38.
    let mut hdr = [0u8; 0x1000];
    if read_mem(hproc, pid, base, &mut hdr, kernel) < 0x100 {
        return None;
    }
    if &hdr[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes([hdr[0x3C], hdr[0x3D], hdr[0x3E], hdr[0x3F]]) as usize;
    if e_lfanew + 0x60 > hdr.len() {
        return None;
    }
    if &hdr[e_lfanew..e_lfanew + 4] != b"PE\x00\x00" {
        return None;
    }
    let opt = e_lfanew + 0x18;
    let magic = u16::from_le_bytes([hdr[opt], hdr[opt + 1]]);
    // SizeOfImage sits at the same offset in both PE32 and PE32+.
    let soi = u32::from_le_bytes([
        hdr[opt + 0x38],
        hdr[opt + 0x39],
        hdr[opt + 0x3A],
        hdr[opt + 0x3B],
    ]) as u64;
    if magic != 0x20B && magic != 0x10B {
        return None;
    }
    if soi == 0 || soi > (512u64 << 20) {
        return None;
    }

    let mut buf = vec![0u8; soi as usize];
    let got = read_mem(hproc, pid, base, &mut buf, kernel);
    if got == 0 {
        return None;
    }
    buf.truncate(got);

    let dir = out_dir.join("modules");
    if fs::create_dir_all(&dir).is_err() {
        return None;
    }
    let safe: String = name
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() || c == '.' || c == '_' { c } else { '_' })
        .collect();
    let path = dir.join(format!("{base:016x}_{safe}.bin"));
    if fs::write(&path, &buf).is_err() {
        return None;
    }
    Some(got)
}

/// Dump every private executable region to disk.
///
/// A packer is not obliged to decrypt in place. Diffing the main image against
/// the file only finds plaintext written back into a section; a packer that
/// decrypts into a fresh allocation and runs from there leaves the image
/// untouched, and the payload is invisible to that comparison. Private
/// executable memory is where such a payload lands, so it is captured directly
/// rather than inferred.
///
/// Returns `(base, bytes_captured, label)` for each region written.
pub fn dump_private_exec_regions(
    hproc: HANDLE,
    pid: u32,
    out_dir: &Path,
    kernel: &KernelClient,
    modules: &[UserModule],
) -> Vec<(u64, usize, String)> {
    let dir = out_dir.join("private");
    let mut out = Vec::new();
    for r in scan_regions(hproc, pid, kernel, modules) {
        if !matches!(r.kind, RegionKind::PrivateExec | RegionKind::PrivateRwx) {
            continue;
        }
        // Skip implausible sizes: a multi-gigabyte reservation is not payload,
        // and reading it would stall the debugger.
        if r.size == 0 || r.size > (256u64 << 20) {
            continue;
        }
        let mut buf = vec![0u8; r.size as usize];
        let got = read_mem(hproc, pid, r.base, &mut buf, kernel);
        if got == 0 {
            continue;
        }
        buf.truncate(got);
        if fs::create_dir_all(&dir).is_err() {
            continue;
        }
        let label = kind_label(r.kind);
        let path = dir.join(format!("{:016x}_{label}.bin", r.base));
        if fs::write(&path, &buf).is_err() {
            continue;
        }
        out.push((r.base, got, label.to_string()));
    }
    out
}

/// True when a buffer opens like a mapped PE image.
///
/// Deliberately strict. A heap block that happens to start with `MZ` is not a
/// payload, so the signature has to resolve to a real `PE\0\0` inside the
/// buffer before the region is treated as an image.
pub fn looks_like_mapped_pe(buf: &[u8]) -> bool {
    if buf.len() < 0x40 || &buf[0..2] != b"MZ" {
        return false;
    }
    let e = u32::from_le_bytes(buf[0x3C..0x40].try_into().unwrap_or([0; 4])) as usize;
    e + 4 <= buf.len() && &buf[e..e + 4] == b"PE\0\0"
}

/// A private, writable, non-executable region — where a packer stages plaintext
/// before flipping the page executable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StagingRegion {
    pub base: u64,
    pub size: u64,
    pub protect: u32,
    pub captured: u64,
    /// The whole region was read. False means only the head was kept.
    pub complete: bool,
    /// The head is a PE image, which is what a manual map leaves behind.
    pub looks_like_pe: bool,
    pub entropy: f64,
    pub file: Option<String>,
}

/// Capture private, writable, **non-executable** regions.
///
/// [`dump_private_exec_regions`] only sees regions that are executable *right
/// now*. A packer that decrypts into a fresh allocation and flips the page to
/// executable afterwards is invisible to it — at the moment of capture the page
/// is still read/write. This closes that window.
///
/// Reading every private RW region in full would mean dumping the process heap,
/// so each candidate contributes at most `head_bytes`, and only a region whose
/// head is a PE image is captured whole. `budget` caps the total bytes written.
pub fn dump_private_staging_regions(
    hproc: HANDLE,
    pid: u32,
    out_dir: &Path,
    kernel: &KernelClient,
    modules: &[UserModule],
    head_bytes: usize,
    budget: usize,
) -> Vec<StagingRegion> {
    let dir = out_dir.join("staging");
    let mut out = Vec::new();
    let mut spent = 0usize;

    for r in scan_regions(hproc, pid, kernel, modules) {
        if r.kind != RegionKind::Private || !r.writable {
            continue;
        }
        // A page-sized floor keeps the heap's small blocks out; the ceiling
        // keeps a multi-gigabyte reservation from stalling the read.
        if r.size < 0x1000 || r.size > (256u64 << 20) {
            continue;
        }
        if spent >= budget {
            break;
        }

        let head_len = (head_bytes as u64).min(r.size) as usize;
        let mut head = vec![0u8; head_len];
        let got = read_mem(hproc, pid, r.base, &mut head, kernel);
        if got == 0 {
            continue;
        }
        head.truncate(got);

        // A region that opens like an image is captured whole — that is the
        // manual-map case, and truncating it would lose the sections.
        let pe = looks_like_mapped_pe(&head);
        let (buf, complete) = if pe && (r.size as usize) <= budget.saturating_sub(spent) {
            let mut full = vec![0u8; r.size as usize];
            let n = read_mem(hproc, pid, r.base, &mut full, kernel);
            full.truncate(n);
            (full, true)
        } else {
            (head, false)
        };

        spent += buf.len();
        if fs::create_dir_all(&dir).is_err() {
            continue;
        }
        let label = if pe { "pe" } else { "rw" };
        let name = format!("{:016x}_{label}.bin", r.base);
        let file = if fs::write(dir.join(&name), &buf).is_ok() {
            Some(format!("staging/{name}"))
        } else {
            None
        };

        out.push(StagingRegion {
            base: r.base,
            size: r.size,
            protect: r.protect,
            captured: buf.len() as u64,
            complete,
            looks_like_pe: pe,
            entropy: shannon(&buf),
            file,
        });
    }
    out
}

pub fn scan_regions(
    hproc: HANDLE,
    pid: u32,
    kernel: &KernelClient,
    modules: &[UserModule],
) -> Vec<MemRegion> {
    let mut out = Vec::new();
    let mut addr: u64 = 0;
    let mbi_size = std::mem::size_of::<MEMORY_BASIC_INFORMATION>();

    while addr < USER_MAX {
        let mut mbi = MEMORY_BASIC_INFORMATION::default();
        let written = unsafe {
            VirtualQueryEx(
                hproc,
                Some(addr as *const _),
                &mut mbi,
                mbi_size,
            )
        };
        if written == 0 {
            break;
        }

        let raw_base = mbi.BaseAddress as u64;
        let base = if raw_base == 0 { addr } else { raw_base };
        let size = mbi.RegionSize as u64;

        // A zero-size region would spin forever; step a page and move on.
        if size == 0 {
            addr = addr.saturating_add(PAGE_SIZE);
            continue;
        }

        if mbi.State.0 == MEM_COMMIT {
            let prot = mbi.Protect.0;
            let executable = prot & PROT_EXEC_MASK != 0;
            let writable = prot & PROT_WRITE_MASK != 0;
            let guard = prot & PAGE_GUARD_BIT != 0;

            let kind = classify_kind(prot, mbi.Type.0);

            let module = if kind == RegionKind::Image {
                modules
                    .iter()
                    .find(|m| m.base == base)
                    .map(|m| m.name.clone())
            } else {
                None
            };

            // Entropy only for executable memory — that is where injected code
            // lives, and it keeps the scan cheap.
            let entropy = if executable && size >= 0x200 {
                let sample = read_capped(hproc, pid, base, 0x4000, 0x4000, kernel);
                if sample.len() >= 0x200 {
                    Some(shannon(&sample))
                } else {
                    None
                }
            } else {
                None
            };

            out.push(MemRegion {
                base,
                size,
                protect: prot,
                kind,
                executable,
                writable,
                guard,
                module,
                entropy,
            });
        }

        let next = base.saturating_add(size);
        addr = if next > addr { next } else { addr.saturating_add(PAGE_SIZE) };
    }

    out
}

// ---------------------------------------------------------------------------
// Entry-call follow — capture the decryptor instead of naming it
// ---------------------------------------------------------------------------

/// The entry point's first call, resolved and followed to its target.
///
/// A packer's entry is a stub whose first act is to call the code that does the
/// real work. For `vector.exe` the entry's first instruction is
/// `call rel32(+0x15AF97)`, and that target — the decryptor — was recorded as an
/// unknown on 2026-09-20 and never followed. This resolves it inside the live
/// process and captures the bytes at the destination, so the decryptor becomes
/// an artifact on disk rather than a note in a report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntryCallCapture {
    pub entry_va: u64,
    /// Head of the entry bytes, hex.
    pub entry_bytes: String,
    /// Address of the first `call`.
    pub call_va: u64,
    /// The `rel32` destination of that call.
    pub target_va: u64,
    pub size: u64,
    pub file: Option<String>,
    pub sha256: String,
    pub entropy: f64,
    pub mz: bool,
    pub pe: bool,
    pub disasm_head: Vec<String>,
    pub note: String,
}

fn hex_head(b: &[u8], n: usize) -> String {
    let mut s = String::new();
    for (i, byte) in b.iter().take(n).enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

/// Resolve the entry point from the **mapped** headers and follow its first
/// `call rel32`.
///
/// The headers are read from the live process rather than the file on disk,
/// because the file may be unreadable (on-access AV block) while the process
/// runs fine.
pub fn capture_entry_call(
    hproc: HANDLE,
    pid: u32,
    image_base: u64,
    out_dir: &Path,
    kernel: &KernelClient,
    max_region: usize,
) -> Option<EntryCallCapture> {
    let mut hdr = vec![0u8; 0x1000];
    let got = read_mem(hproc, pid, image_base, &mut hdr, kernel);
    if got < 0x40 || &hdr[0..2] != b"MZ" {
        return None;
    }
    let e_lfanew = u32::from_le_bytes([hdr[0x3C], hdr[0x3D], hdr[0x3E], hdr[0x3F]]) as usize;
    if e_lfanew + 0x2C > got || &hdr[e_lfanew..e_lfanew + 4] != b"PE\0\0" {
        return None;
    }
    // OptionalHeader.AddressOfEntryPoint sits at e_lfanew + 0x28 for both PE32
    // and PE32+ — the field precedes the 32/64-bit divergence.
    let entry_rva = u32::from_le_bytes([
        hdr[e_lfanew + 0x28],
        hdr[e_lfanew + 0x29],
        hdr[e_lfanew + 0x2A],
        hdr[e_lfanew + 0x2B],
    ]);
    if entry_rva == 0 {
        return None;
    }
    let entry_va = image_base + entry_rva as u64;

    let mut head = vec![0u8; 64];
    let n = read_mem(hproc, pid, entry_va, &mut head, kernel);
    if n == 0 {
        return None;
    }
    head.truncate(n);

    let d = street_disasm::disassemble(&head, entry_va, street_core::Arch::X64, false, 16);
    let call = d.instructions.iter().find(|i| i.is_call && i.target.is_some())?;
    let call_va = call.addr;
    let target_va = call.target?;

    let mut out = EntryCallCapture {
        entry_va,
        entry_bytes: hex_head(&head, 16),
        call_va,
        target_va,
        size: 0,
        file: None,
        sha256: String::new(),
        entropy: 0.0,
        mz: false,
        pe: false,
        disasm_head: Vec::new(),
        note: String::new(),
    };

    let mut buf = vec![0u8; max_region.min(0x40000)];
    let got = read_mem(hproc, pid, target_va, &mut buf, kernel);
    if got == 0 {
        out.note = "call target is not readable from the live process".into();
        return Some(out);
    }
    buf.truncate(got);

    let dir = out_dir.join("entry_call");
    let _ = fs::create_dir_all(&dir);
    let rel = format!("entry_call/decryptor_0x{target_va:x}.bin");
    if fs::write(out_dir.join(&rel), &buf).is_ok() {
        out.file = Some(rel);
    }
    out.size = buf.len() as u64;
    out.sha256 = sha256_bytes(&buf);
    out.entropy = shannon(&buf);
    out.mz = buf.len() >= 2 && &buf[0..2] == b"MZ";
    out.pe = street_core::pe::parse_pe(&buf).is_ok();

    let dis = street_disasm::disassemble(
        &buf[..buf.len().min(0x200)],
        target_va,
        street_core::Arch::X64,
        false,
        24,
    );
    out.disasm_head = dis
        .instructions
        .iter()
        .map(|i| format!("0x{:x}: {} {}", i.addr, i.mnemonic, i.op_str))
        .collect();
    if out.disasm_head.is_empty() {
        out.note = "target captured but did not decode as code".into();
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Kernel drivers
// ---------------------------------------------------------------------------

/// Enumerate loaded kernel drivers via `EnumDeviceDrivers`.
///
/// Snapshot this before and after the target runs; the difference is what the
/// target caused to be loaded.
pub fn enumerate_kernel_modules() -> Vec<KernelModule> {
    let mut needed = 0u32;
    unsafe {
        let _ = EnumDeviceDrivers(std::ptr::null_mut(), 0, &mut needed);
    }
    if needed == 0 {
        return Vec::new();
    }

    let slots = needed as usize / std::mem::size_of::<*mut core::ffi::c_void>();
    if slots == 0 {
        return Vec::new();
    }

    let mut bases: Vec<*mut core::ffi::c_void> = vec![std::ptr::null_mut(); slots];
    let mut got = 0u32;
    let ok = unsafe {
        EnumDeviceDrivers(bases.as_mut_ptr(), needed, &mut got)
    };
    if ok.is_err() {
        return Vec::new();
    }

    let n = (got as usize / std::mem::size_of::<*mut core::ffi::c_void>()).min(slots);
    let mut out = Vec::with_capacity(n);
    for b in bases.into_iter().take(n) {
        let mut name = [0u16; 260];
        let len = unsafe { GetDeviceDriverBaseNameW(b as *const _, &mut name) };
        let name = wide_to_string(&name[..(len as usize).min(name.len())]);
        if name.is_empty() {
            continue;
        }
        let mut path = [0u16; 260];
        let plen = unsafe { GetDeviceDriverFileNameW(b as *const _, &mut path) };
        let path = wide_to_string(&path[..(plen as usize).min(path.len())]);
        out.push(KernelModule { base: b as u64, name, path });
    }
    out
}

/// Drivers present in `after` that were not in `before`, matched by name.
pub fn diff_kernel_modules(before: &[KernelModule], after: &[KernelModule]) -> Vec<KernelModule> {
    let known: std::collections::HashSet<&str> =
        before.iter().map(|m| m.name.as_str()).collect();
    after
        .iter()
        .filter(|m| !known.contains(m.name.as_str()))
        .cloned()
        .collect()
}

/// Drivers present in `before` that are gone from `after`, matched by name.
///
/// A driver that appears and then unloads inside the observation window is the
/// common shape for a protector that loads its anti-debug component, does its
/// work, and detaches. Reporting only the "loaded" delta would miss it entirely.
pub fn diff_kernel_modules_unloaded(
    before: &[KernelModule],
    after: &[KernelModule],
) -> Vec<KernelModule> {
    let now: std::collections::HashSet<&str> = after.iter().map(|m| m.name.as_str()).collect();
    before
        .iter()
        .filter(|m| !now.contains(m.name.as_str()))
        .cloned()
        .collect()
}

/// Map an NT image path from `GetDeviceDriverFileNameW` to a filesystem path.
///
/// The loader reports paths in one of a few NT forms; only the ones that map to
/// a real drive letter are resolvable from user mode. `\Device\HarddiskVolumeN\`
/// requires a volume query that is not worth doing here, so it is reported as
/// unresolvable rather than guessed at.
pub fn resolve_driver_path(nt_path: &str) -> Option<PathBuf> {
    if nt_path.is_empty() {
        return None;
    }
    // `\??\C:\Windows\...`
    if let Some(rest) = nt_path.strip_prefix(r"\??\") {
        return Some(PathBuf::from(rest));
    }
    // `\SystemRoot\System32\drivers\foo.sys`
    if let Some(rest) = nt_path.strip_prefix(r"\SystemRoot\") {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        return Some(PathBuf::from(root).join(rest.replace('/', r"\")));
    }
    // `\Device\...` — not resolvable without a volume lookup.
    None
}

/// Capture a kernel driver image, preferring the file on disk and falling back
/// to the mapped image in kernel memory.
///
/// The kernel-memory path reads through `\\.\StreetKernel` `READ_VIRTUAL` using
/// the System process (pid 4) CR3. The kernel half of the system address space
/// is what a loaded driver lives in, and it is the only copy that exists for a
/// driver mapped from memory with no file behind it.
pub fn extract_driver(
    km: &KernelModule,
    out_dir: &Path,
    kernel: &KernelClient,
    max_region: usize,
) -> DriverArtifact {
    let mut art = DriverArtifact {
        name: km.name.clone(),
        base: km.base,
        nt_path: km.path.clone(),
        fs_path: None,
        source: "failed".into(),
        file: None,
        size: 0,
        sha256: String::new(),
        entropy: 0.0,
        mz: false,
        pe: false,
        is_64: false,
        strings: Vec::new(),
        unloaded: false,
        note: String::new(),
    };

    let mut notes: Vec<String> = Vec::new();
    let mut sources: Vec<&str> = Vec::new();

    // ── 1. the file on disk ────────────────────────────────────────────────
    let mut disk_bytes: Option<Vec<u8>> = None;
    if let Some(fs) = resolve_driver_path(&km.path) {
        art.fs_path = Some(fs.display().to_string());
        match fs::read(&fs) {
            Ok(b) => disk_bytes = Some(b),
            Err(e) => notes.push(format!("disk read of {} failed: {e}", fs.display())),
        }
    } else if km.path.is_empty() {
        notes.push("driver publishes no image path — memory-only image".into());
    } else {
        notes.push(format!("NT path {} is not resolvable from user mode", km.path));
    }

    // ── 2. the mapped image in kernel memory ───────────────────────────────
    let mut mem_bytes: Option<Vec<u8>> = None;
    if kernel.present() {
        if let Some(hdr) = kernel.read_virtual(4, km.base, 0x1000) {
            if hdr.len() >= 0x40 && &hdr[0..2] == b"MZ" {
                let e_lfanew = u32::from_le_bytes([hdr[0x3C], hdr[0x3D], hdr[0x3E], hdr[0x3F]]) as usize;
                if e_lfanew + 0x58 <= hdr.len() && &hdr[e_lfanew..e_lfanew + 4] == b"PE\0\0" {
                    let size_of_image =
                        u32::from_le_bytes([
                            hdr[e_lfanew + 0x50],
                            hdr[e_lfanew + 0x51],
                            hdr[e_lfanew + 0x52],
                            hdr[e_lfanew + 0x53],
                        ]) as usize;
                    let want = size_of_image.min(max_region).max(0x1000);
                    mem_bytes = kernel.read_virtual(4, km.base, want as u32);
                    if mem_bytes.is_none() {
                        notes.push("kernel-memory image read failed (CR3 walk)".into());
                    }
                } else {
                    notes.push("kernel memory at base does not parse as a PE".into());
                }
            } else {
                notes.push("kernel read at base returned no MZ header".into());
            }
        } else {
            notes.push("StreetKernel READ_VIRTUAL unavailable for this base".into());
        }
    } else {
        notes.push("StreetKernel not loaded — kernel-memory extraction unavailable".into());
    }

    // ── 3. pick what to persist ────────────────────────────────────────────
    let drv_dir = out_dir.join("drivers");
    let _ = fs::create_dir_all(&drv_dir);

    let mut persisted: Option<(Vec<u8>, String)> = None;
    if let Some(b) = disk_bytes.clone() {
        sources.push("disk");
        let rel = format!("drivers/{}.sys", km.name);
        if fs::write(out_dir.join(&rel), &b).is_ok() {
            art.file = Some(rel);
        }
        persisted = Some((b, "disk".into()));
    }
    if let Some(b) = mem_bytes.clone() {
        sources.push("kernel_memory");
        let rel = format!("drivers/{}.mem.bin", km.name);
        if fs::write(out_dir.join(&rel), &b).is_ok() {
            art.file = Some(match art.file.take() {
                Some(prev) => format!("{prev} + {rel}"),
                None => rel,
            });
        }
        if persisted.is_none() {
            persisted = Some((b, "kernel_memory".into()));
        }
    }

    if sources.is_empty() {
        art.note = notes.join("; ");
        return art;
    }
    art.source = sources.join("+");
    art.note = notes.join("; ");

    // Analyse the preferred copy (disk wins for metadata, memory wins when the
    // file was not readable).
    if let Some((bytes, _)) = persisted {
        art.size = bytes.len() as u64;
        art.sha256 = street_core::sha256_bytes(&bytes);
        art.entropy = shannon(&bytes[..bytes.len().min(1 << 20)]);
        art.mz = bytes.len() >= 2 && &bytes[0..2] == b"MZ";
        if let Ok(pe) = street_core::pe::parse_pe(&bytes) {
            art.pe = true;
            art.is_64 = pe.is_64;
        }
        art.strings = harvest_strings(&bytes, 24);
    }
    art
}

// ---------------------------------------------------------------------------
// User modules
// ---------------------------------------------------------------------------

pub fn enumerate_user_modules(pid: u32) -> Vec<UserModule> {
    let mut out = Vec::new();
    let snap = unsafe {
        CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid)
    };
    let Ok(snap) = snap else {
        return out;
    };

    let mut me = MODULEENTRY32W {
        dwSize: std::mem::size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };

    let mut ok = unsafe { Module32FirstW(snap, &mut me) }.is_ok();
    while ok {
        out.push(UserModule {
            base: me.modBaseAddr as u64,
            size: me.modBaseSize as u64,
            name: wide_to_string(&me.szModule),
            path: wide_to_string(&me.szExePath),
        });
        ok = unsafe { Module32NextW(snap, &mut me) }.is_ok();
    }

    unsafe {
        let _ = CloseHandle(snap);
    }
    out
}

// ---------------------------------------------------------------------------
// Thread suspension
//
// Every scan in this module runs *after* `ContinueDebugEvent`, while the target
// is executing. Reading the PEB loader chain or walking the address space while
// the target mutates it produces transient, wrong answers — the documented
// cause of 16 ntdll callers being mislabelled as executing from private memory.
// Suspending the target's threads for the duration of a scan removes the race.
// ---------------------------------------------------------------------------

/// RAII guard that resumes every thread it suspended, including on early return
/// or panic. Leaving a target's threads suspended would hang the process.
pub struct ThreadSuspendGuard {
    handles: Vec<HANDLE>,
}

impl Drop for ThreadSuspendGuard {
    fn drop(&mut self) {
        for h in self.handles.drain(..) {
            unsafe {
                let _ = ResumeThread(h);
                let _ = CloseHandle(h);
            }
        }
    }
}

/// Suspend every thread owned by `pid`.
///
/// A failure to open a single thread is not fatal — the remaining threads are
/// still suspended, and the guard resumes exactly the set it obtained.
pub fn suspend_process_threads(pid: u32) -> ThreadSuspendGuard {
    let mut handles: Vec<HANDLE> = Vec::new();
    let snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) };
    let Ok(snap) = snap else {
        return ThreadSuspendGuard { handles };
    };

    let mut te = THREADENTRY32 {
        dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };

    let mut ok = unsafe { Thread32First(snap, &mut te) }.is_ok();
    while ok {
        if te.th32OwnerProcessID == pid {
            if let Ok(h) = unsafe { OpenThread(THREAD_SUSPEND_RESUME, false, te.th32ThreadID) } {
                if !h.is_invalid() {
                    unsafe {
                        let _ = SuspendThread(h);
                    }
                    handles.push(h);
                }
            }
        }
        ok = unsafe { Thread32Next(snap, &mut te) }.is_ok();
    }

    unsafe {
        let _ = CloseHandle(snap);
    }
    ThreadSuspendGuard { handles }
}

fn wide_to_string(w: &[u16]) -> String {
    let end = w.iter().position(|&c| c == 0).unwrap_or(w.len());
    String::from_utf16_lossy(&w[..end])
}

// ---------------------------------------------------------------------------
// Dumping
// ---------------------------------------------------------------------------

/// Context shared by every capture in a run. Bundled so the capture call site
/// stays readable and the region-specific arguments stay distinct.
pub struct CaptureCtx<'a> {
    pub hproc: HANDLE,
    pub pid: u32,
    pub kernel: &'a KernelClient,
    pub root: &'a Path,
    pub max_region: usize,
}

/// How one image section differs between memory and the file on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SectionDiff {
    pub name: String,
    pub va: u64,
    pub size: u64,
    /// Bytes that differ from the file image **in this snapshot**.
    pub changed_bytes: u64,
    pub changed_pct: f64,
    /// Raw size on disk — 0 means the section had no file backing at all.
    pub disk_raw_size: u32,
    /// The section had **no file backing**, so every byte present in memory was
    /// produced at runtime. This is unambiguous decryption, unlike a section
    /// that merely differs because of relocations, IAT binding or TLS writes.
    pub was_virtual_only: bool,
    /// Where the captured section was written, when it changed.
    pub file: Option<String>,
    /// Bytes this snapshot added to the accumulated capture that no earlier
    /// snapshot had seen plaintext for. Zero on the first snapshot.
    #[serde(default)]
    pub merged_bytes: u64,
    /// Bytes held in the accumulated capture that this snapshot did **not** see
    /// differing — the block was re-encrypted, or a later snapshot simply
    /// missed it. These are only ever kept, never overwritten.
    #[serde(default)]
    pub carried_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageDumpReport {
    pub image_base: u64,
    pub image_size: u64,
    pub sections: Vec<SectionDiff>,
    pub changed_sections: usize,
    /// Sections that had no file backing and now hold data — unambiguous
    /// decryption, as opposed to relocation or IAT modification.
    pub materialised_sections: usize,
    pub total_changed_bytes: u64,
    /// Bytes newly contributed by this snapshot to the accumulated capture.
    #[serde(default)]
    pub merged_bytes: u64,
    /// Bytes retained in the accumulated capture from earlier snapshots even
    /// though this one did not see them differ.
    #[serde(default)]
    pub carried_bytes: u64,
    /// How many snapshots have contributed to `unpacked/` so far.
    #[serde(default)]
    pub snapshots_accumulated: u32,
    pub note: String,
}

/// Dump the main image's committed sections and report which differ from the
/// file on disk.
///
/// This is the practical unpacking path. A packer decrypts its sections **in
/// place**, so once it has run, the memory image differs from the file. Diffing
/// the two says exactly what was decrypted and where — without needing to
/// reverse the decryption algorithm at all. Sections that were virtual-only on
/// disk (raw size 0) and now hold data are the plaintext.
pub fn dump_image_diff(
    hproc: HANDLE,
    pid: u32,
    image_base: u64,
    file_path: &Path,
    out_dir: &Path,
    kernel: &KernelClient,
) -> Option<ImageDumpReport> {
    let disk = fs::read(file_path).ok()?;
    let img = street_core::pe::parse_pe(&disk).ok()?;

    let unpacked = out_dir.join("unpacked");
    let _ = fs::create_dir_all(&unpacked);

    let mut sections = Vec::new();
    let mut total_changed = 0u64;

    for sec in &img.sections {
        let size = sec.vsize.max(sec.raw_size) as u64;
        if size == 0 || size > 64 * 1024 * 1024 {
            continue;
        }
        let va = image_base + sec.va as u64;
        let mut mem = vec![0u8; size as usize];
        let got = read_mem(hproc, pid, va, &mut mem, kernel);
        if got == 0 {
            continue;
        }
        mem.truncate(got);

        // The file image of the same section, zero-padded to the virtual size.
        let mut disk_sec = vec![0u8; mem.len()];
        let raw = street_core::pe::section_bytes(&disk, sec);
        let n = raw.len().min(disk_sec.len());
        disk_sec[..n].copy_from_slice(&raw[..n]);

        let changed = mem
            .iter()
            .zip(disk_sec.iter())
            .filter(|(a, b)| a != b)
            .count() as u64;

        let pct = if mem.is_empty() {
            0.0
        } else {
            changed as f64 * 100.0 / mem.len() as f64
        };

        let mut file = None;
        let mut merged = 0u64;
        let mut carried = 0u64;
        // Only capture sections that actually differ — that is the decrypted
        // content, and writing every section would bury it.
        if changed > 0 {
            let safe: String = sec
                .name
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() || c == '.' { c } else { '_' })
                .collect();
            let name = format!("{safe}_{:x}.bin", sec.va);
            let path = unpacked.join(&name);

            // Accumulate rather than overwrite.
            //
            // A packer is not obliged to decrypt everything at once. Themida
            // decrypts block by block, just in time, and re-encrypts as it
            // goes — so any single snapshot holds only the blocks that happened
            // to be plaintext at that instant, and the next snapshot may hold a
            // completely different handful. The union across snapshots is what
            // turns those fragments into an image.
            //
            // The accumulator is stored as the file image with every byte ever
            // seen plaintext overlaid, so an untouched byte is byte-identical
            // to disk and the delta is self-describing.
            let mut acc = match fs::read(&path) {
                Ok(prev) if prev.len() == mem.len() => prev,
                _ => disk_sec.clone(),
            };
            let (m, c) = fold_snapshot(&mut acc, &disk_sec, &mem);
            merged = m;
            carried = c;
            if fs::write(&path, &acc).is_ok() {
                file = Some(format!("unpacked/{name}"));
            }
            total_changed += changed;
        }

        sections.push(SectionDiff {
            name: sec.name.clone(),
            va,
            size: mem.len() as u64,
            changed_bytes: changed,
            changed_pct: pct,
            disk_raw_size: sec.raw_size,
            was_virtual_only: sec.raw_size == 0,
            file,
            merged_bytes: merged,
            carried_bytes: carried,
        });
    }

    let changed_sections = sections.iter().filter(|s| s.changed_bytes > 0).count();
    // Sections that had no file backing are the unambiguous decryption signal.
    // The rest may simply be relocations, IAT binding or TLS writes.
    let materialised_sections = sections
        .iter()
        .filter(|s| s.was_virtual_only && s.changed_bytes > 0)
        .count();
    // The image size as mapped: the highest section end. `LoadedImage` does not
    // carry SizeOfImage directly.
    let image_size = img
        .sections
        .iter()
        .map(|s| s.va as u64 + s.vsize.max(s.raw_size) as u64)
        .max()
        .unwrap_or(0);
    let merged_total: u64 = sections.iter().map(|s| s.merged_bytes).sum();
    let carried_total: u64 = sections.iter().map(|s| s.carried_bytes).sum();
    let snapshots = bump_snapshot_count(&unpacked);

    let note = if changed_sections == 0 && carried_total == 0 {
        "no section differs from the file image — the target has not decrypted in place, or the \
         dump was taken too early"
            .to_string()
    } else if changed_sections == 0 {
        format!(
            "this snapshot saw nothing differ, but the accumulated capture already holds \
             {carried_total} byte(s) from earlier snapshots. A target that re-encrypts after use \
             leaves each individual snapshot empty — only the union has content."
        )
    } else if materialised_sections > 0 {
        format!(
            "{materialised_sections} section(s) had NO file backing and now hold data — that is \
             decrypted content, captured to `unpacked/`. {changed_sections} section(s) differ in \
             total; the remainder may be relocations or IAT binding rather than decryption."
        )
    } else {
        format!(
            "{changed_sections} section(s) differ from the file image, but none of them were \
             virtual-only on disk — consistent with relocations or IAT binding rather than \
             decryption. Captured to `unpacked/` for inspection."
        )
    };

    // Snapshot N of a just-in-time decryptor holds a different handful of
    // blocks than snapshot N-1. Say so, and say how much of the accumulated
    // capture this snapshot had not seen before — that is the number that
    // decides whether more snapshots are worth taking.
    let note = if snapshots > 1 {
        format!(
            "{note} Accumulated across {snapshots} snapshot(s): this one contributed \
             {merged_total} new byte(s) and carried {carried_total} byte(s) already captured by \
             an earlier snapshot."
        )
    } else {
        note
    };

    Some(ImageDumpReport {
        image_base,
        image_size,
        sections,
        changed_sections,
        materialised_sections,
        total_changed_bytes: total_changed,
        merged_bytes: merged_total,
        carried_bytes: carried_total,
        snapshots_accumulated: snapshots,
        note,
    })
}

/// Fold one snapshot into the accumulated capture.
///
/// `disk` is the file image, `snap` is what memory looked like at this instant,
/// and `acc` is the running union — seeded from `disk`, so any byte still equal
/// to its on-disk value means "never yet seen plaintext".
///
/// A byte seen differing is always written through. A byte the snapshot agrees
/// with disk on is **never** cleared from `acc`: either the block was
/// re-encrypted after use, or this snapshot simply missed the window, and in
/// both cases the earlier reading is the only evidence we have.
///
/// Returns `(newly_merged, carried)`.
fn fold_snapshot(acc: &mut [u8], disk: &[u8], snap: &[u8]) -> (u64, u64) {
    let n = acc.len().min(disk.len()).min(snap.len());
    let (mut merged, mut carried) = (0u64, 0u64);
    for i in 0..n {
        if snap[i] != disk[i] {
            if acc[i] == disk[i] {
                merged += 1;
            }
            acc[i] = snap[i];
        } else if acc[i] != disk[i] {
            carried += 1;
        }
    }
    (merged, carried)
}

/// Increment and return the snapshot counter kept beside the accumulated
/// captures.
///
/// Lives on disk so the count survives across runs: running the target twice
/// into the same output directory keeps accumulating, and the report says how
/// many snapshots the capture now rests on.
fn bump_snapshot_count(unpacked: &Path) -> u32 {
    #[derive(serde::Serialize, serde::Deserialize, Default)]
    struct State {
        snapshots: u32,
    }
    let path = unpacked.join("ACCUMULATOR.json");
    let mut st: State = fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default();
    st.snapshots = st.snapshots.saturating_add(1);
    let _ = fs::write(&path, serde_json::to_vec_pretty(&st).unwrap_or_default());
    st.snapshots
}

impl CaptureCtx<'_> {
    /// Capture a region to disk and describe it. Returns `None` if the region
    /// could not be read at all.
    ///
    /// If the region is larger than `max_region` only a prefix is captured, and
    /// the artifact is marked `partial: true` — a truncated dump that reports
    /// itself as complete is worse than no dump at all.
    pub fn dump_region(
        &self,
        region: &MemRegion,
        index: usize,
        first_seen_ms: u64,
    ) -> Option<DumpArtifact> {
        let hproc = self.hproc;
        let pid = self.pid;
        let kernel = self.kernel;
        let root = self.root;
        let max_region = self.max_region;
        let want = (region.size as usize).min(max_region);
        let bytes = read_capped(hproc, pid, region.base, want, max_region, kernel);
        if bytes.is_empty() {
            return None;
        }
        let partial = (region.size as usize) > max_region;

    let dir = root.join("regions");
    let _ = fs::create_dir_all(&dir);

    let kind_tag = match region.kind {
        RegionKind::PrivateExec => "exec",
        RegionKind::PrivateRwx => "rwx",
        RegionKind::Image => "img",
        RegionKind::Mapped => "map",
        RegionKind::Private => "priv",
    };
    let file_name = format!("{index:04}_{:012x}_{kind_tag}.bin", region.base);
    let path = dir.join(&file_name);
    if fs::write(&path, &bytes).is_err() {
        return None;
    }

    let sha = sha256_bytes(&bytes);
    let mz = bytes.len() >= 2 && &bytes[0..2] == b"MZ";
    let parsed = if mz { street_core::pe::parse_pe(&bytes).ok() } else { None };
    let pe = parsed.is_some();
    let is_64 = parsed.as_ref().map(|i| i.is_64).unwrap_or(false);

    let entropy = shannon(&bytes);
    let strings = harvest_strings(&bytes, 24);

    let head = &bytes[..bytes.len().min(64)];
    let d = street_disasm::disassemble(head, region.base, street_core::Arch::X64, false, 10);
    let disasm_head = d
        .instructions
        .iter()
        .map(|i| format!("{:x}: {} {}", i.addr, i.mnemonic, i.op_str))
        .collect::<Vec<_>>();

    // The note states what was observed, not what it means. A private
    // executable region is a fact; calling it "injected" is the analyst's
    // inference, and a benign JIT produces the same observable.
    let note = if partial {
        format!(
            "PARTIAL capture: region is {} bytes, only the first {} were read — \
             sha256 covers the prefix only",
            region.size,
            bytes.len()
        )
    } else if pe {
        "captured bytes parse as a PE — treat as runtime_dump, not a cipher decrypt".to_string()
    } else if region.kind == RegionKind::PrivateRwx {
        "private RWX region observed — shellcode or JIT; attribution is an inference".to_string()
    } else {
        "private executable region observed — attribution to injection is an inference, not a finding"
            .to_string()
    };

    Some(DumpArtifact {
        base: region.base,
        size: bytes.len() as u64,
        kind: region.kind,
        file: format!("regions/{file_name}"),
        sha256: sha,
        entropy,
        mz,
        pe,
        is_64,
        strings,
        disasm_head,
        note,
        partial,
        region_size: region.size,
        first_seen_ms,
    })
    }
}

fn harvest_strings(data: &[u8], max: usize) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    for &b in data {
        if (0x20..0x7f).contains(&b) {
            cur.push(b as char);
        } else {
            if cur.len() >= 6 {
                out.push(std::mem::take(&mut cur));
                if out.len() >= max {
                    return out;
                }
            } else {
                cur.clear();
            }
        }
    }
    if cur.len() >= 6 && out.len() < max {
        out.push(cur);
    }
    out
}

// ---------------------------------------------------------------------------
// Headless live-dump runner
// ---------------------------------------------------------------------------

/// Spawn `exe` under the debugger, let it run for `opts.seconds`, and dump
/// every newly appearing executable private region (injected / downloaded
/// shellcode) plus the kernel-driver delta.
pub fn run_live_dump(exe: &str, opts: &LiveDumpOptions) -> Result<LiveDumpReport, String> {
    let kernel = KernelClient::open();
    let mut events: Vec<LiveEvent> = Vec::new();
    let mut notes: Vec<String> = Vec::new();
    let started = Instant::now();

    let drivers_before = enumerate_kernel_modules();
    // If the enumeration itself failed there is nothing to diff, and an empty
    // delta must not be presented as "no driver was loaded".
    let driver_enum_ok = !drivers_before.is_empty();
    if !driver_enum_ok {
        notes.push(
            "kernel driver enumeration returned nothing (needs a full-access token); \
             driver delta will be empty"
                .into(),
        );
    }

    let mut wide: Vec<u16> = std::ffi::OsStr::new(exe)
        .encode_wide_collect();
    wide.push(0);

    let si = STARTUPINFOW {
        cb: std::mem::size_of::<STARTUPINFOW>() as u32,
        ..Default::default()
    };
    let mut pi = PROCESS_INFORMATION::default();
    unsafe {
        CreateProcessW(
            windows::core::PCWSTR(wide.as_ptr()),
            PWSTR::null(),
            None,
            None,
            false,
            DEBUG_ONLY_THIS_PROCESS,
            None,
            None,
            &si,
            &mut pi,
        )
        .map_err(|e| format!("CreateProcessW: {e}"))?;
    }

    let hproc = pi.hProcess;
    let pid = pi.dwProcessId;
    let mut image_base = 0u64;
    // Keyed on (base, size), not base alone: a region freed and reallocated at
    // the same base — or a payload extended in place — is a different capture,
    // and base-only keying would silently drop it as already-seen.
    let mut seen: std::collections::HashSet<(u64, u64)> = std::collections::HashSet::new();
    let mut artifacts: Vec<DumpArtifact> = Vec::new();
    let mut modules: Vec<UserModule> = Vec::new();
    let mut last_scan = Instant::now();
    let mut exited = false;
    // Last successful scan. Re-querying after the process is gone would return
    // an empty address space and under-report the region inventory.
    let mut last_regions: Vec<MemRegion> = Vec::new();
    // Every driver name seen at any point in the window, sampled on the scan
    // tick. A before/after diff alone cannot see a driver that loaded and
    // unloaded inside the window — which is the common shape for a protector's
    // anti-debug component. This union closes that hole.
    let mut drivers_seen: std::collections::BTreeMap<String, KernelModule> =
        std::collections::BTreeMap::new();
    for km in &drivers_before {
        drivers_seen.insert(km.name.clone(), km.clone());
    }
    // The entry's first call, followed once the image is up and re-captured at
    // the end of the window (later means more of the image is decrypted).
    let mut entry_call: Option<EntryCallCapture> = None;

    let root = opts.out_dir.join(pid.to_string());
    let _ = fs::create_dir_all(&root);

    let ctx = CaptureCtx {
        hproc,
        pid,
        kernel: &kernel,
        root: &root,
        max_region: opts.max_region,
    };

    let deadline = started + Duration::from_secs(opts.seconds);

    while !exited && Instant::now() < deadline {
        let mut ev = DEBUG_EVENT::default();
        let got = unsafe { WaitForDebugEvent(&mut ev, 100).is_ok() };
        if got {
            let at = started.elapsed().as_millis() as u64;
            match ev.dwDebugEventCode {
                CREATE_PROCESS_DEBUG_EVENT => {
                    let info = unsafe { ev.u.CreateProcessInfo };
                    image_base = info.lpBaseOfImage as u64;
                    unsafe {
                        let _ = ResumeThread(info.hThread);
                    }
                    modules = enumerate_user_modules(pid);
                    events.push(LiveEvent {
                        at_ms: at,
                        kind: "create_process".into(),
                        detail: format!("image_base=0x{image_base:x} modules={}", modules.len()),
                    });
                }
                LOAD_DLL_DEBUG_EVENT => {
                    let base = unsafe { ev.u.LoadDll.lpBaseOfDll } as u64;
                    // Retake the snapshot so the new module is resolvable.
                    modules = enumerate_user_modules(pid);
                    let name = modules
                        .iter()
                        .find(|m| m.base == base)
                        .map(|m| m.name.clone())
                        .unwrap_or_else(|| format!("0x{base:x}"));
                    events.push(LiveEvent {
                        at_ms: at,
                        kind: "load_dll".into(),
                        detail: name,
                    });
                }
                CREATE_THREAD_DEBUG_EVENT => {
                    let start = unsafe { ev.u.CreateThread.lpStartAddress }
                        .map(|f| f as usize as u64)
                        .unwrap_or(0);
                    let tid = ev.dwThreadId;
                    events.push(LiveEvent {
                        at_ms: at,
                        kind: "create_thread".into(),
                        detail: format!("tid={tid} start=0x{start:x}"),
                    });
                }
                EXIT_PROCESS_DEBUG_EVENT => {
                    events.push(LiveEvent {
                        at_ms: at,
                        kind: "exit_process".into(),
                        detail: format!("exit_code={}", unsafe { ev.u.ExitProcess.dwExitCode }),
                    });
                    unsafe {
                        let _ = ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, windows::Win32::Foundation::DBG_CONTINUE);
                    }
                    exited = true;
                    break;
                }
                _ => {}
            }
            unsafe {
                let _ = ContinueDebugEvent(
                    ev.dwProcessId,
                    ev.dwThreadId,
                    windows::Win32::Foundation::DBG_CONTINUE,
                );
            }
        }

        if last_scan.elapsed() >= Duration::from_millis(opts.scan_interval_ms) {
            last_scan = Instant::now();
            // Freeze the target for the whole snapshot: the loader chain, the
            // region map and the dumped bytes are all read while nothing is
            // mutating them. The guard resumes every thread it suspended.
            let _susp = suspend_process_threads(pid);
            if modules.is_empty() {
                modules = enumerate_user_modules(pid);
            }
            let regions = scan_regions(hproc, pid, &kernel, &modules);
            for r in &regions {
                if !r.kind.is_injection_candidate() {
                    continue;
                }
                if (r.size as usize) < opts.min_shellcode {
                    continue;
                }
                if !seen.insert((r.base, r.size)) {
                    continue;
                }
                let idx = artifacts.len();
                let first_seen = started.elapsed().as_millis() as u64;
                if let Some(a) = ctx.dump_region(r, idx, first_seen) {
                    events.push(LiveEvent {
                        at_ms: started.elapsed().as_millis() as u64,
                        kind: "shellcode_dump".into(),
                        detail: format!(
                            "0x{:x} size=0x{:x} H={:.2} pe={} -> {}",
                            a.base, a.size, a.entropy, a.pe, a.file
                        ),
                    });
                    artifacts.push(a);
                }
            }
            last_regions = regions;

            // Same tick, sample the kernel module list. A driver that loads and
            // unloads inside the window never shows up in a before/after diff;
            // the union does.
            for km in enumerate_kernel_modules() {
                drivers_seen.entry(km.name.clone()).or_insert(km);
            }

            // Follow the entry's first call once the image is mapped. Done
            // inside the freeze so the captured bytes are from a stopped target.
            if entry_call.is_none() && image_base != 0 {
                entry_call =
                    capture_entry_call(hproc, pid, image_base, &root, &kernel, opts.max_region);
            }
        }
    }

    // Resolve module names after the run. At LOAD_DLL time the loader has not
    // necessarily published the module to the Toolhelp snapshot yet, so the
    // name is looked up from the final, complete module list instead.
    {
        let by_base: std::collections::HashMap<u64, String> =
            modules.iter().map(|m| (m.base, m.name.clone())).collect();
        for e in events.iter_mut() {
            if e.kind != "load_dll" {
                continue;
            }
            let parsed = e
                .detail
                .strip_prefix("0x")
                .and_then(|h| u64::from_str_radix(h, 16).ok());
            if let Some(base) = parsed {
                if let Some(n) = by_base.get(&base) {
                    e.detail = format!("{n} (0x{base:x})");
                }
            }
        }
    }

    let drivers_after = enumerate_kernel_modules();
    // `appeared` is the union of every sample, so it includes a driver that
    // loaded and unloaded inside the window. A strict before/after diff would
    // report that driver as never having existed.
    let after_names: std::collections::HashSet<&str> =
        drivers_after.iter().map(|m| m.name.as_str()).collect();
    let appeared: Vec<KernelModule> = drivers_seen
        .values()
        .filter(|m| !drivers_before.iter().any(|b| b.name == m.name))
        .cloned()
        .collect();
    let unloaded: Vec<KernelModule> = drivers_seen
        .values()
        .filter(|m| !after_names.contains(m.name.as_str()))
        .cloned()
        .collect();

    // Extract every driver that appeared during the run: the file on disk when
    // it is readable, and the mapped image out of kernel memory as well. The
    // memory copy is the only one that exists for a driver mapped from memory,
    // and it is the copy that shows what the target actually executed.
    let mut driver_artifacts: Vec<DriverArtifact> = Vec::new();
    for km in &appeared {
        let a = extract_driver(km, &root, &kernel, opts.max_region);
        events.push(LiveEvent {
            at_ms: started.elapsed().as_millis() as u64,
            kind: "driver_extract".into(),
            detail: format!(
                "{} base=0x{:x} source={} size={} -> {}",
                a.name,
                a.base,
                a.source,
                a.size,
                a.file.clone().unwrap_or_else(|| "(not captured)".into())
            ),
        });
        driver_artifacts.push(a);
    }

    if !exited {
        notes.push(format!(
            "timeout after {}s — target was still running when the dump window closed",
            opts.seconds
        ));
        // Capture the address space one last time *before* killing the target;
        // querying afterwards yields nothing.
        last_regions = scan_regions(hproc, pid, &kernel, &modules);
        // Re-follow the entry call: the later capture sees more of the image
        // after the packer has run its stub.
        if image_base != 0 {
            if let Some(c) = capture_entry_call(hproc, pid, image_base, &root, &kernel, opts.max_region)
            {
                entry_call = Some(c);
            }
        }
        unsafe {
            let _ = TerminateProcess(hproc, 0);
        }
    }
    if artifacts.is_empty() {
        notes.push(
            "observed_none for memory_regions: no private executable region appeared in the \
             window. This is NOT a clean bill of health — see the `coverage` block for the \
             mechanisms that were never instrumented (network traffic, file-system writes, \
             child processes)."
                .into(),
        );
    }

    // Persist the last region inventory so the run is auditable even when
    // nothing was dumped.
    let regions = last_regions;
    let _ = fs::write(
        root.join("REGIONS.json"),
        serde_json::to_string_pretty(&regions).unwrap_or_default(),
    );

    unsafe {
        let _ = CloseHandle(pi.hThread);
        let _ = CloseHandle(pi.hProcess);
    }

    let shellcode_region_count = regions
        .iter()
        .filter(|r| r.kind.is_injection_candidate())
        .count();

    let artifact_count = artifacts.len();
    Ok(LiveDumpReport {
        exe: exe.to_string(),
        pid,
        image_base,
        kernel_driver_available: kernel.present(),
        duration_ms: started.elapsed().as_millis() as u64,
        region_count: regions.len(),
        shellcode_region_count,
        kernel_drivers_before: drivers_before,
        kernel_drivers_after: drivers_after,
        kernel_drivers_loaded: appeared,
        kernel_drivers_unloaded: unloaded,
        driver_artifacts,
        entry_call,
        modules,
        artifacts,
        events,
        notes,
        coverage: Coverage::for_run(artifact_count, opts.scan_interval_ms, driver_enum_ok),
    })
}

/// Small helper so the runner does not need `OsStrExt` imported at call sites.
trait EncodeWideCollect {
    fn encode_wide_collect(&self) -> Vec<u16>;
}

impl EncodeWideCollect for std::ffi::OsStr {
    fn encode_wide_collect(&self) -> Vec<u16> {
        use std::os::windows::ffi::OsStrExt;
        self.encode_wide().collect()
    }
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

fn kind_label(k: RegionKind) -> &'static str {
    match k {
        RegionKind::Image => "image",
        RegionKind::Mapped => "mapped",
        RegionKind::PrivateExec => "private-exec",
        RegionKind::PrivateRwx => "private-rwx",
        RegionKind::Private => "private",
    }
}

/// Short console summary.
pub fn summary_md(r: &LiveDumpReport) -> String {
    let mut s = String::new();
    s.push_str(&format!("# live dump — {} (pid {})\n\n", r.exe, r.pid));
    s.push_str(&format!("- image base: `0x{:x}`\n", r.image_base));
    s.push_str(&format!(
        "- kernel driver: {}\n",
        if r.kernel_driver_available {
            "`\\\\.\\StreetKernel` open (CR3 walk available)"
        } else {
            "absent — usermode `ReadProcessMemory` only"
        }
    ));
    s.push_str(&format!("- observed for: {} ms\n", r.duration_ms));
    s.push_str(&format!(
        "- committed regions: **{}** ({} executable-private)\n",
        r.region_count, r.shellcode_region_count
    ));
    s.push_str(&format!("- modules: {}\n", r.modules.len()));
    s.push_str(&format!("- **artifacts dumped: {}**\n", r.artifacts.len()));
    s.push_str(&format!(
        "- kernel drivers that appeared during the run: **{}**\n",
        r.kernel_drivers_loaded.len()
    ));
    if !r.driver_artifacts.is_empty() {
        let captured = r
            .driver_artifacts
            .iter()
            .filter(|d| d.file.is_some())
            .count();
        s.push_str(&format!(
            "- driver images captured: **{}** of {} ({} from kernel memory)\n",
            captured,
            r.driver_artifacts.len(),
            r.driver_artifacts
                .iter()
                .filter(|d| d.source.contains("kernel_memory"))
                .count()
        ));
    }
    if !r.kernel_drivers_unloaded.is_empty() {
        s.push_str(&format!(
            "- drivers unloaded during the run: **{}**\n",
            r.kernel_drivers_unloaded.len()
        ));
    }
    if let Some(ec) = &r.entry_call {
        s.push_str(&format!(
            "- entry call followed: `0x{:x}` → `0x{:x}` ({} B, H={:.2}, pe={})\n",
            ec.call_va, ec.target_va, ec.size, ec.entropy, ec.pe
        ));
    }

    // The single most important line in the report: what this run could not see.
    let blind = r.coverage.blind_spots();
    if !blind.is_empty() {
        s.push_str(&format!(
            "\n> **Not observed by this run:** {}. An empty artifact list does **not** mean \
             nothing happened — it means no private executable region was seen. Network \
             traffic and file drops are invisible to this tool by design.\n",
            blind.join(", ")
        ));
    }

    if !r.artifacts.is_empty() {
        s.push_str(
            "\n| base | size | kind | H | PE | file | partial |\n|---|---|---|---|---|---|---|\n",
        );
        for a in &r.artifacts {
            s.push_str(&format!(
                "| `0x{:x}` | {} | {} | {:.2} | {} | `{}` | {} |\n",
                a.base,
                a.size,
                kind_label(a.kind),
                a.entropy,
                a.pe,
                a.file,
                if a.partial { "**YES**" } else { "no" }
            ));
        }
    }
    s
}

/// Full report written next to the dumped regions.
pub fn report_md(r: &LiveDumpReport) -> String {
    let mut s = summary_md(r);
    s.push_str("\n---\n\n");

    s.push_str("## Dumped artifacts\n\n");
    if r.artifacts.is_empty() {
        s.push_str("_Nothing matched the injection-candidate filter in this window._\n\n");
    }
    for (i, a) in r.artifacts.iter().enumerate() {
        s.push_str(&format!(
            "### {i}. `0x{:x}` — {} bytes, {}\n\n",
            a.base,
            a.size,
            kind_label(a.kind)
        ));
        s.push_str(&format!("- sha256: `{}`\n", a.sha256));
        s.push_str(&format!("- entropy: {:.3}\n", a.entropy));
        s.push_str(&format!("- MZ: {} · PE: {} · x64: {}\n", a.mz, a.pe, a.is_64));
        s.push_str(&format!("- file: `{}`\n", a.file));
        s.push_str(&format!("- first observed: {} ms into the run\n", a.first_seen_ms));
        if a.partial {
            s.push_str(&format!(
                "- ⚠️ **PARTIAL**: region was {} bytes, captured {} bytes. \
                 The sha256 covers the prefix only.\n",
                a.region_size, a.size
            ));
        } else {
            s.push_str(&format!("- complete capture: {} bytes\n", a.region_size));
        }
        s.push_str(&format!("- note: {}\n", a.note));
        if !a.disasm_head.is_empty() {
            s.push_str("\n```asm\n");
            for l in &a.disasm_head {
                s.push_str(l);
                s.push('\n');
            }
            s.push_str("```\n");
        }
        if !a.strings.is_empty() {
            s.push_str("\nStrings:\n\n```\n");
            for l in &a.strings {
                s.push_str(l);
                s.push('\n');
            }
            s.push_str("```\n");
        }
        s.push('\n');
    }

    s.push_str("## Kernel drivers loaded during the run\n\n");
    if r.kernel_drivers_loaded.is_empty() {
        s.push_str("_No new kernel driver appeared while the target ran._\n\n");
    } else {
        s.push_str("| base | driver | image path |\n|---|---|---|\n");
        for d in &r.kernel_drivers_loaded {
            s.push_str(&format!(
                "| `0x{:x}` | `{}` | `{}` |\n",
                d.base,
                d.name,
                if d.path.is_empty() { "(none published)" } else { d.path.as_str() }
            ));
        }
        s.push('\n');
    }
    if !r.kernel_drivers_unloaded.is_empty() {
        s.push_str("Drivers that were present before the target ran and gone afterwards:\n\n");
        s.push_str("| base | driver |\n|---|---|\n");
        for d in &r.kernel_drivers_unloaded {
            s.push_str(&format!("| `0x{:x}` | `{}` |\n", d.base, d.name));
        }
        s.push('\n');
    }
    if !r.driver_artifacts.is_empty() {
        s.push_str("### Extracted driver images\n\n");
        s.push_str(
            "`disk` is the file as shipped; `kernel_memory` is the image read out of the \
             kernel through `READ_VIRTUAL` (System CR3) — the only copy that exists for a \
             driver mapped from memory with no file behind it.\n\n",
        );
        s.push_str("| driver | source | size | entropy | PE | sha256 | file |\n");
        s.push_str("|---|---|---|---|---|---|---|\n");
        for d in &r.driver_artifacts {
            s.push_str(&format!(
                "| `{}` | `{}` | {} | {:.2} | {} | `{}` | `{}` |\n",
                d.name,
                d.source,
                d.size,
                d.entropy,
                d.pe,
                if d.sha256.is_empty() { "-".into() } else { d.sha256[..16].to_string() },
                d.file.clone().unwrap_or_else(|| "(not captured)".into())
            ));
        }
        s.push('\n');
        for d in &r.driver_artifacts {
            if !d.note.is_empty() {
                s.push_str(&format!("- `{}`: {}\n", d.name, d.note));
            }
        }
        s.push('\n');
    }
    s.push_str(&format!(
        "Driver counts: before {} → after {}.\n\n",
        r.kernel_drivers_before.len(),
        r.kernel_drivers_after.len()
    ));

    if let Some(ec) = &r.entry_call {
        s.push_str("## Entry call — the packer's first hop\n\n");
        s.push_str(&format!(
            "- entry `0x{:x}` · bytes `{}`\n",
            ec.entry_va, ec.entry_bytes
        ));
        s.push_str(&format!(
            "- first call at `0x{:x}` → target `0x{:x}`\n",
            ec.call_va, ec.target_va
        ));
        s.push_str(&format!(
            "- captured {} bytes, H={:.2}, mz={}, pe={} → `{}`\n",
            ec.size,
            ec.entropy,
            ec.mz,
            ec.pe,
            ec.file.clone().unwrap_or_else(|| "(not captured)".into())
        ));
        if !ec.sha256.is_empty() {
            s.push_str(&format!("- sha256 `{}`\n", ec.sha256));
        }
        if !ec.note.is_empty() {
            s.push_str(&format!("- note: {}\n", ec.note));
        }
        if !ec.disasm_head.is_empty() {
            s.push_str("\n```asm\n");
            for line in ec.disasm_head.iter().take(16) {
                s.push_str(line);
                s.push('\n');
            }
            s.push_str("```\n");
        }
        s.push('\n');
    }

    s.push_str("## Loaded modules\n\n");
    s.push_str("| base | size | module | path |\n|---|---|---|---|\n");
    for m in &r.modules {
        s.push_str(&format!(
            "| `0x{:x}` | {} | `{}` | `{}` |\n",
            m.base, m.size, m.name, m.path
        ));
    }
    s.push('\n');

    s.push_str("## Event timeline\n\n");
    s.push_str("| t (ms) | event | detail |\n|---|---|---|\n");
    for e in &r.events {
        s.push_str(&format!("| {} | `{}` | {} |\n", e.at_ms, e.kind, e.detail));
    }
    s.push('\n');

    s.push_str("## Coverage — what this run could and could not observe\n\n");
    s.push_str(
        "`observed_none` is positive evidence of absence. `not_observable` carries **zero** \
         information — it means the tool has no instrumentation for that mechanism at all.\n\n",
    );
    s.push_str("| Mechanism | Instrumented | Status | Note |\n|---|---|---|---|\n");
    for (name, m) in [
        ("memory_regions", &r.coverage.memory_regions),
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
    s.push_str(&format!(
        "\nScan mode: `{}` every {} ms. A region created, used and freed between two scans is \
         missed (`missed_between_scans: {}`).\n\n",
        r.coverage.scan_mode, r.coverage.scan_interval_ms, r.coverage.missed_between_scans
    ));

    if !r.notes.is_empty() {
        s.push_str("## Notes\n\n");
        for n in &r.notes {
            s.push_str(&format!("- {n}\n"));
        }
        s.push('\n');
    }

    s.push_str("---\n\n> Dumped regions are raw bytes captured from a live process. ");
    s.push_str("`pe=true` means the bytes parse as a PE image (a `runtime_dump`), not that a cipher was broken.\n");
    s
}

/// Verify the report obeys the non-detection contract.
///
/// Returns `Err` when the report would mislead an analyst. This is the
/// meta-test from the validation plan: it fails if the tool ever regresses into
/// presenting an empty result as a clean bill of health.
pub fn check_honesty(r: &LiveDumpReport) -> Result<(), String> {
    if !r.coverage.is_complete() {
        return Err("coverage block is incomplete — a mechanism has no status".into());
    }
    if r.artifacts.is_empty() && r.coverage.blind_spots().is_empty() {
        return Err(
            "empty result with no blind-spot declaration — would read as a clean result".into(),
        );
    }
    for a in &r.artifacts {
        if a.partial && !a.note.contains("PARTIAL") {
            return Err(format!(
                "artifact at 0x{:x} is a partial capture but its note does not say so",
                a.base
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn image_region_is_never_injection() {
        // A real module is executable but backed by a file — not shellcode.
        assert_eq!(classify_kind(0x20, MEM_IMAGE), RegionKind::Image);
        assert!(!classify_kind(0x20, MEM_IMAGE).is_injection_candidate());
    }

    #[test]
    fn private_exec_is_injection() {
        assert_eq!(classify_kind(0x20, MEM_PRIVATE), RegionKind::PrivateExec);
        assert!(classify_kind(0x20, MEM_PRIVATE).is_injection_candidate());
    }

    #[test]
    fn private_rwx_is_injection() {
        assert_eq!(classify_kind(0x40, MEM_PRIVATE), RegionKind::PrivateRwx);
        assert!(classify_kind(0x40, MEM_PRIVATE).is_injection_candidate());
    }

    #[test]
    fn private_data_is_not_injection() {
        // RW but not executable.
        assert_eq!(classify_kind(0x04, MEM_PRIVATE), RegionKind::Private);
        assert!(!classify_kind(0x04, MEM_PRIVATE).is_injection_candidate());
    }

    #[test]
    fn executable_mapping_is_not_private_shellcode() {
        assert_eq!(classify_kind(0x20, MEM_MAPPED), RegionKind::Mapped);
        assert!(!classify_kind(0x20, MEM_MAPPED).is_injection_candidate());
    }

    #[test]
    fn kernel_driver_diff_reports_only_new_drivers() {
        let before = vec![KernelModule {
            base: 0x1000,
            name: "ntoskrnl.exe".into(),
            path: String::new(),
        }];
        let after = vec![
            KernelModule {
                base: 0x1000,
                name: "ntoskrnl.exe".into(),
                path: String::new(),
            },
            KernelModule {
                base: 0x2000,
                name: "suspect.sys".into(),
                path: r"\SystemRoot\System32\drivers\suspect.sys".into(),
            },
        ];
        let delta = diff_kernel_modules(&before, &after);
        assert_eq!(delta.len(), 1);
        assert_eq!(delta[0].name, "suspect.sys");
    }

    #[test]
    fn kernel_driver_diff_is_empty_when_nothing_loaded() {
        let same = vec![KernelModule {
            base: 1,
            name: "ntoskrnl.exe".into(),
            path: String::new(),
        }];
        assert!(diff_kernel_modules(&same, &same).is_empty());
    }

    #[test]
    fn nt_driver_paths_resolve_to_the_filesystem() {
        let sysroot = resolve_driver_path(r"\SystemRoot\System32\drivers\foo.sys").unwrap();
        assert!(sysroot.to_string_lossy().ends_with(r"System32\drivers\foo.sys"));

        let dosdev = resolve_driver_path(r"\??\C:\Windows\System32\drivers\bar.sys").unwrap();
        assert_eq!(dosdev, PathBuf::from(r"C:\Windows\System32\drivers\bar.sys"));

        // A `\Device\` path needs a volume query — reported as unresolvable
        // rather than guessed at, and an empty path is a memory-only image.
        assert!(resolve_driver_path(r"\Device\HarddiskVolume3\x.sys").is_none());
        assert!(resolve_driver_path("").is_none());
    }

    #[test]
    fn unloaded_diff_reports_drivers_that_disappeared() {
        let before = vec![
            KernelModule { base: 1, name: "ntoskrnl.exe".into(), path: String::new() },
            KernelModule { base: 2, name: "gone.sys".into(), path: String::new() },
        ];
        let after = vec![KernelModule {
            base: 1,
            name: "ntoskrnl.exe".into(),
            path: String::new(),
        }];
        let un = diff_kernel_modules_unloaded(&before, &after);
        assert_eq!(un.len(), 1);
        assert_eq!(un[0].name, "gone.sys");
        // Symmetry: a driver still present must not be reported as unloaded.
        assert!(diff_kernel_modules_unloaded(&after, &after).is_empty());
    }

    #[test]
    fn extract_driver_captures_the_file_when_the_path_resolves() {
        let dir = std::env::temp_dir().join(format!("street_drv_{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let fake = dir.join("fake.sys");
        std::fs::write(&fake, b"MZfake-driver-body").unwrap();

        let km = KernelModule {
            base: 0x1000,
            name: "fake.sys".into(),
            path: format!(r"\??\{}", fake.display()),
        };
        // `open()` finds no `\\.\StreetKernel` in a test process, so the
        // kernel-memory path is correctly skipped and the disk copy is used.
        let kc = KernelClient::open();
        let a = extract_driver(&km, &dir, &kc, 1 << 20);
        assert!(a.source.contains("disk"), "source was {}", a.source);
        assert!(a.file.is_some(), "no file captured");
        assert!(a.mz);
        assert!(!a.sha256.is_empty());
        assert!(a.fs_path.is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn string_harvest_enforces_minimum_length() {
        let data = b"\x00abc\x00longer_string_here\x00";
        let found = harvest_strings(data, 10);
        assert!(found.iter().any(|s| s == "longer_string_here"));
        assert!(!found.iter().any(|s| s == "abc"));
    }

    #[test]
    fn wide_to_string_stops_at_nul() {
        let w: Vec<u16> = "ntdll.dll"
            .encode_utf16()
            .chain(std::iter::once(0))
            .chain("trailing".encode_utf16())
            .collect();
        assert_eq!(wide_to_string(&w), "ntdll.dll");
    }

    #[test]
    fn observed_none_is_not_the_same_as_not_observable() {
        let cov = Coverage::for_run(0, 500, true);
        // Memory WAS looked at and nothing matched. That is information.
        assert!(cov.memory_regions.instrumented);
        assert_eq!(cov.memory_regions.status, "observed_none");
        // Network was NEVER looked at. That is not the same statement.
        assert!(!cov.network_http.instrumented);
        assert_eq!(cov.network_http.status, "not_observable");
    }

    #[test]
    fn empty_run_declares_its_blind_spots() {
        let cov = Coverage::for_run(0, 500, true);
        let blind = cov.blind_spots();
        assert!(blind.contains(&"network traffic (HTTP downloads)"));
        assert!(blind.contains(&"file-system writes (file drops)"));
        assert!(blind.contains(&"child processes"));
        assert!(cov.is_complete(), "every mechanism must carry a status");
    }

    #[test]
    fn failed_driver_enumeration_is_not_reported_as_no_drivers_loaded() {
        // If EnumDeviceDrivers returns nothing we cannot diff, so the delta is
        // meaningless — reporting an empty delta would read as "clean".
        let cov = Coverage::for_run(0, 500, false);
        assert!(!cov.kernel_drivers.instrumented);
        assert_eq!(cov.kernel_drivers.status, "not_observable");
    }

    #[test]
    fn captures_flip_memory_status_to_observed() {
        let cov = Coverage::for_run(2, 500, true);
        assert_eq!(cov.memory_regions.status, "observed");
        assert!(cov.memory_regions.note.contains('2'));
    }

    #[test]
    fn polling_mode_declares_that_scans_can_be_missed() {
        let cov = Coverage::for_run(0, 500, true);
        assert_eq!(cov.scan_mode, "polling");
        assert_eq!(cov.scan_interval_ms, 500);
        assert!(cov.missed_between_scans);
    }

    #[test]
    fn honesty_check_rejects_a_report_that_would_read_as_clean() {
        // A report with no artifacts and no declared blind spots is the exact
        // failure the contract exists to prevent.
        let mut cov = Coverage::for_run(0, 500, true);
        cov.network_http = MechanismCoverage {
            instrumented: true,
            status: "observed_none".into(),
            note: "pretend we can see the network".into(),
        };
        cov.filesystem_writes = MechanismCoverage {
            instrumented: true,
            status: "observed_none".into(),
            note: "pretend we can see the disk".into(),
        };
        cov.child_processes = MechanismCoverage {
            instrumented: true,
            status: "observed_none".into(),
            note: "pretend we follow children".into(),
        };
        assert!(cov.blind_spots().is_empty());

        let report = LiveDumpReport {
            exe: "x.exe".into(),
            pid: 1,
            image_base: 0,
            kernel_driver_available: false,
            duration_ms: 100,
            region_count: 0,
            shellcode_region_count: 0,
            kernel_drivers_before: vec![],
            kernel_drivers_after: vec![],
            kernel_drivers_loaded: vec![],
            kernel_drivers_unloaded: vec![],
            driver_artifacts: vec![],
            entry_call: None,
            modules: vec![],
            artifacts: vec![],
            events: vec![],
            notes: vec![],
            coverage: cov,
        };
        assert!(
            check_honesty(&report).is_err(),
            "an empty result claiming full coverage must be rejected"
        );
    }

    #[test]
    fn honesty_check_accepts_an_honest_empty_report() {
        let report = LiveDumpReport {
            exe: "x.exe".into(),
            pid: 1,
            image_base: 0,
            kernel_driver_available: false,
            duration_ms: 100,
            region_count: 0,
            shellcode_region_count: 0,
            kernel_drivers_before: vec![],
            kernel_drivers_after: vec![],
            kernel_drivers_loaded: vec![],
            kernel_drivers_unloaded: vec![],
            driver_artifacts: vec![],
            entry_call: None,
            modules: vec![],
            artifacts: vec![],
            events: vec![],
            notes: vec![],
            coverage: Coverage::for_run(0, 500, true),
        };
        assert!(check_honesty(&report).is_ok());
    }

    // ── snapshot accumulation ───────────────────────────────────────────────
    //
    // The behaviour that matters: a just-in-time decryptor leaves a different
    // handful of blocks plaintext in every snapshot, so the capture has to be
    // the union and must never be cleared.

    #[test]
    fn first_snapshot_merges_every_differing_byte() {
        let disk = [0u8; 8];
        let mut acc = disk;
        let snap = [0, 0, 0xAA, 0xBB, 0, 0, 0, 0];
        let (merged, carried) = fold_snapshot(&mut acc, &disk, &snap);
        assert_eq!(merged, 2);
        assert_eq!(carried, 0);
        assert_eq!(acc[2], 0xAA);
        assert_eq!(acc[3], 0xBB);
    }

    #[test]
    fn a_byte_the_next_snapshot_agrees_with_disk_on_is_kept() {
        let disk = [0u8; 4];
        let mut acc = disk;

        // Snapshot 1 reveals plaintext at byte 1.
        let (m1, _) = fold_snapshot(&mut acc, &disk, &[0, 0x11, 0, 0]);
        assert_eq!(m1, 1);

        // Snapshot 2 shows byte 1 back at its on-disk value — re-encrypted, or
        // simply missed. Either way the earlier reading is the only evidence.
        let (m2, c2) = fold_snapshot(&mut acc, &disk, &disk);
        assert_eq!(m2, 0);
        assert_eq!(c2, 1);
        assert_eq!(acc[1], 0x11, "a re-encrypted byte must not be cleared");
    }

    #[test]
    fn successive_snapshots_union_into_the_whole_image() {
        // Sixteen blocks of sixteen bytes; the "decryptor" reveals exactly one
        // block per snapshot and re-encrypts everything else.
        let disk = vec![0u8; 256];
        let mut acc = disk.clone();

        let mut total_merged = 0u64;
        for block in 0..16usize {
            let mut snap = disk.clone();
            for i in 0..16 {
                snap[block * 16 + i] = 0x40 + block as u8;
            }
            let (m, c) = fold_snapshot(&mut acc, &disk, &snap);
            total_merged += m;
            // Only the first snapshot sees no carried bytes; every later one
            // must carry all the blocks already banked.
            assert_eq!(c, (block as u64) * 16);
        }

        assert_eq!(total_merged, 256, "the union should cover every byte");
        assert_eq!(acc, {
            let mut want = vec![0u8; 256];
            for block in 0..16usize {
                for i in 0..16 {
                    want[block * 16 + i] = 0x40 + block as u8;
                }
            }
            want
        });
    }

    #[test]
    fn resampling_the_same_value_does_not_double_count() {
        let disk = [0u8; 4];
        let mut acc = disk;
        let snap = [0, 0x77, 0, 0];
        assert_eq!(fold_snapshot(&mut acc, &disk, &snap).0, 1, "first sighting banks it");
        assert_eq!(fold_snapshot(&mut acc, &disk, &snap).0, 0, "already banked");
        assert_eq!(fold_snapshot(&mut acc, &disk, &snap).0, 0, "still banked");
        assert_eq!(acc[1], 0x77);

        // `carried` measures the other direction: bytes this snapshot agrees
        // with disk on, while the accumulator holds something else. Re-seeing
        // the plaintext byte is not a carry — it is a re-merge of zero.
        assert_eq!(fold_snapshot(&mut acc, &disk, &snap).1, 0);
        let (_, carried) = fold_snapshot(&mut acc, &disk, &disk);
        assert_eq!(carried, 1, "the snapshot lost sight of the banked byte");
    }

    #[test]
    fn mismatched_lengths_fold_only_the_common_prefix() {
        let disk = [0u8; 8];
        let mut acc = disk;
        // A truncated read must not panic or misindex.
        let (m, _) = fold_snapshot(&mut acc, &disk, &[0, 0x01, 0, 0]);
        assert_eq!(m, 1);
        assert_eq!(acc[1], 0x01);
    }

    #[test]
    fn snapshot_counter_persists_beside_the_capture() {
        let dir = std::env::temp_dir().join(format!("street-acc-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        assert_eq!(bump_snapshot_count(&dir), 1);
        assert_eq!(bump_snapshot_count(&dir), 2);
        assert_eq!(bump_snapshot_count(&dir), 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── staging-region PE detection ─────────────────────────────────────────
    //
    // The check decides whether a read/write region gets captured whole, so it
    // has to reject the heap without rejecting a real manual map.

    fn fake_pe_at(e_lfanew: usize, total: usize) -> Vec<u8> {
        let mut b = vec![0u8; total];
        b[0] = b'M';
        b[1] = b'Z';
        if e_lfanew + 4 <= total {
            b[0x3C..0x40].copy_from_slice(&(e_lfanew as u32).to_le_bytes());
            b[e_lfanew..e_lfanew + 4].copy_from_slice(b"PE\0\0");
        }
        b
    }

    #[test]
    fn a_mapped_pe_is_recognised() {
        assert!(looks_like_mapped_pe(&fake_pe_at(0x80, 0x200)));
        assert!(looks_like_mapped_pe(&fake_pe_at(0xF8, 0x200)));
    }

    #[test]
    fn a_heap_block_that_starts_with_mz_is_not_a_pe() {
        let mut b = vec![0u8; 0x200];
        b[0] = b'M';
        b[1] = b'Z';
        // No e_lfanew, so no PE signature anywhere.
        assert!(!looks_like_mapped_pe(&b));
    }

    #[test]
    fn a_truncated_head_is_not_a_pe() {
        // e_lfanew points past the end of the buffer we actually read.
        let mut b = fake_pe_at(0x80, 0x200);
        b[0x3C..0x40].copy_from_slice(&0x4000u32.to_le_bytes());
        assert!(!looks_like_mapped_pe(&b));
        assert!(!looks_like_mapped_pe(b"MZ"));
        assert!(!looks_like_mapped_pe(&[]));
    }

    #[test]
    fn an_mz_header_with_a_non_pe_signature_is_rejected() {
        let mut b = fake_pe_at(0x80, 0x200);
        b[0x80..0x84].copy_from_slice(b"NE\0\0"); // OS/2 — not our case
        assert!(!looks_like_mapped_pe(&b));
    }
}
