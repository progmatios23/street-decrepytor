#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# language: Python 3, file: emul_injector.py, target: umi injector_dumped Unicorn
# Gap close: rewrite IAT → stubs, real heap, fake Roblox snapshot, inject API log.
# *do NOT execute at live DLL VAs — remap injector IAT slots to STUB_BASE*
import sys, os, re, struct, json, traceback
from collections import Counter, defaultdict
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from unicorn import Uc, UcError, UC_ARCH_X86, UC_MODE_64, UC_PROT_ALL
from unicorn import (
    UC_HOOK_CODE,
    UC_HOOK_MEM_READ_UNMAPPED,
    UC_HOOK_MEM_WRITE_UNMAPPED,
    UC_HOOK_MEM_FETCH_UNMAPPED,
    UC_HOOK_MEM_FETCH_PROT,
    UC_MEM_FETCH_UNMAPPED,
    UC_MEM_FETCH_PROT,
)
from unicorn.x86_const import (
    UC_X86_REG_RAX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RBX, UC_X86_REG_R8, UC_X86_REG_R9,
    UC_X86_REG_RSP, UC_X86_REG_RBP, UC_X86_REG_RIP, UC_X86_REG_GS_BASE,
    UC_X86_REG_RSI, UC_X86_REG_RDI, UC_X86_REG_R12, UC_X86_REG_R13, UC_X86_REG_R14,
)

ROOT = Path(__file__).resolve().parents[1]
# prefer Street-decrepytor dump; fall back to local umi-dumpp
CANDIDATE_VADS = [
    Path(r"D:\Street-decrepytor\output\dumps\umi_injector\spawn\vad"),
    Path(r"D:\Street-decrepytor\output\runtime\validate_injector\spawn_dump\vad"),
    ROOT / "output" / "umi-dumpp" / "runtime" / "validate_injector" / "spawn_dump" / "vad",
]
CANDIDATE_META = [
    Path(r"D:\Street-decrepytor\output\dumps\umi_injector\spawn\injector_dumped.exe.meta.json"),
    Path(r"D:\Street-decrepytor\output\runtime\validate_injector\spawn_dump\injector_dumped.exe.meta.json"),
    ROOT / "output" / "umi-dumpp" / "runtime" / "validate_injector" / "spawn_dump" / "injector_dumped.exe.meta.json",
]
CANDIDATE_DUMP = [
    Path(r"D:\Street-decrepytor\output\dumps\umi_injector\spawn\injector_dumped.exe"),
    Path(r"D:\Street-decrepytor\output\runtime\validate_injector\spawn_dump\injector_dumped.exe"),
    ROOT / "output" / "umi-dumpp" / "runtime" / "validate_injector" / "spawn_dump" / "injector_dumped.exe",
]
IMG_BASE = 0x7FF732E70000
MAIN = 0x7FF732E744BA  # C++ main that calls validate / inject
VALIDATE_FN = IMG_BASE + 0x1FFDF9
INJECT_FN = IMG_BASE + 0x308858  # real call target from main (doc 0x307858 was off-by)
EARLY_CMP_JNE = IMG_BASE + 0x44F6   # jne that early-exits when argv/ctx empty
FORCE_CONTINUE_AT = IMG_BASE + 0x4576
VALIDATE_CALL_SITE = IMG_BASE + 0x4713  # setup right before validate
STACK_BASE = 0x0000010000000000
STACK_SIZE = 0x00400000
PEB_BASE = 0x0000020000000000
TEB_BASE = 0x0000020000010000
STUB_BASE = 0x0000030000000000
STUB_STRIDE = 0x100
HEAP_BASE = 0x0000040000000000
HEAP_SIZE = 0x04000000  # 64 MB fake heap
FAKE_MOD_BASE = 0x0000050000000000

# PROCESSENTRY32W layout (Win10 x64): dwSize@0, th32ProcessID@8, szExeFile@44 (WCHAR[260])
PE32_SIZE = 568
PE32_PID_OFF = 8
PE32_EXE_OFF = 44
TH32CS_SNAPPROCESS = 0x00000002
INVALID_HANDLE = 0xFFFFFFFFFFFFFFFF

INJECT_WATCH = {
    "OpenProcess", "CreateRemoteThread", "CreateRemoteThreadEx", "NtCreateThreadEx",
    "RtlCreateUserThread", "QueueUserAPC", "NtQueueApcThread", "NtQueueApcThreadEx",
    "WriteProcessMemory", "NtWriteVirtualMemory", "VirtualAllocEx", "NtAllocateVirtualMemory",
    "VirtualProtectEx", "NtProtectVirtualMemory", "NtMapViewOfSection", "NtCreateSection",
    "NtUnmapViewOfSection", "LoadLibraryA", "LoadLibraryW", "LoadLibraryExW",
    "GetProcAddress", "LdrLoadDll", "CreateToolhelp32Snapshot", "Process32FirstW",
    "Process32NextW", "Thread32First", "Thread32Next", "SuspendThread", "ResumeThread",
    "SetThreadContext", "GetThreadContext", "NtSetContextThread", "NtGetContextThread",
}


def pick_existing(cands):
    for p in cands:
        if p and Path(p).exists():
            return Path(p)
    return None


def align_down(x, a=0x1000):
    return x & ~(a - 1)


def align_up(x, a=0x1000):
    return (x + a - 1) & ~(a - 1)


class FakeHeap:
    def __init__(self, mu: Uc, base: int, size: int):
        self.mu = mu
        self.base = base
        self.size = size
        self.cur = base + 0x1000
        self.mu.mem_map(base, size, UC_PROT_ALL)
        self.mu.mem_write(base, b"\x00" * min(0x1000, size))

    def alloc(self, nbytes: int) -> int:
        nbytes = max(int(nbytes), 1)
        nbytes = align_up(nbytes, 0x10)
        if self.cur + nbytes >= self.base + self.size:
            # wrap soft — still return something non-null
            self.cur = self.base + 0x2000
        ptr = self.cur
        self.cur += nbytes
        try:
            self.mu.mem_write(ptr, b"\x00" * nbytes)
        except UcError:
            pass
        return ptr


class RobloxWorld:
    """CreateToolhelp32Snapshot / Process32* / OpenProcess stubs that expose fake RobloxPlayerBeta."""

    def __init__(self):
        self.snap_handle = 0x9999
        self.proc_handle = 0xABCD1234
        self.pid = 0x3039  # 12345
        self.name = "RobloxPlayerBeta.exe"
        self.enum_state = {}  # handle -> index
        self.procs = [
            {"pid": 4, "name": "System"},
            {"pid": self.pid, "name": self.name},
            {"pid": 1000, "name": "explorer.exe"},
        ]

    def fill_pe32(self, mu: Uc, addr: int, idx: int) -> int:
        if idx < 0 or idx >= len(self.procs):
            return 0
        p = self.procs[idx]
        blob = bytearray(PE32_SIZE)
        struct.pack_into("<I", blob, 0, PE32_SIZE)
        struct.pack_into("<I", blob, PE32_PID_OFF, p["pid"])
        name_u16 = (p["name"] + "\x00").encode("utf-16le")
        blob[PE32_EXE_OFF:PE32_EXE_OFF + len(name_u16)] = name_u16
        mu.mem_write(addr, bytes(blob))
        return 1


def read_cstr(mu: Uc, addr: int, wide=False, maxlen=512) -> str:
    if not addr:
        return ""
    try:
        if wide:
            raw = bytes(mu.mem_read(addr, maxlen * 2))
            # stop at aligned UTF-16 NUL (even offset)
            out = []
            for i in range(0, len(raw) - 1, 2):
                if raw[i] == 0 and raw[i + 1] == 0:
                    break
                out.append(raw[i:i + 2])
            return b"".join(out).decode("utf-16le", errors="replace")
        raw = bytes(mu.mem_read(addr, maxlen))
        return raw.split(b"\x00")[0].decode("latin-1", errors="replace")
    except UcError:
        return ""


def main():
    vad = pick_existing(CANDIDATE_VADS)
    meta_path = pick_existing(CANDIDATE_META)
    dump_path = pick_existing(CANDIDATE_DUMP)
    if not vad:
        print("FATAL: no VAD dir found")
        return 2
    print(f"VAD={vad}")
    print(f"meta={meta_path}")
    print(f"dump={dump_path}")

    meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path else {}
    iat_sample = (meta.get("iat") or {}).get("resolved_sample") or []

    mu = Uc(UC_ARCH_X86, UC_MODE_64)

    # ---- map ALL VAD pieces: injector image + heap objects + real system PE
    # headers (the hash resolver walks the export directory) ----
    regions = []
    for fn in os.listdir(vad):
        m = re.match(r"vad_([0-9a-f]+)_sz([0-9a-f]+)(_X)?(_PE)?\.bin$", fn, re.I)
        if not m:
            continue
        base = int(m.group(1), 16)
        sz = int(m.group(2), 16)
        regions.append((base, sz, vad / fn))
    regions.sort()
    print(f"all regions: {len(regions)}")

    mu.mem_map(align_down(IMG_BASE), 0x1600000, UC_PROT_ALL)
    mu.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_ALL)
    mu.mem_map(PEB_BASE, 0x10000, UC_PROT_ALL)
    mu.mem_map(TEB_BASE, 0x3000, UC_PROT_ALL)
    mu.mem_map(STUB_BASE, 0x200000, UC_PROT_ALL)
    mu.mem_map(FAKE_MOD_BASE, 0x200000, UC_PROT_ALL)

    for base, sz, path in regions:
        data = path.read_bytes()
        pg = align_down(base)
        try:
            mu.mem_map(pg, align_up(sz, 0x1000), UC_PROT_ALL)
        except UcError:
            pass  # already mapped (image/stack/peb/teb/stub/fake)
        try:
            mu.mem_write(base, data[:sz])
        except UcError as e:
            print(f"  warn write {base:#x}: {e}")
    print("image loaded")

    heap = FakeHeap(mu, HEAP_BASE, HEAP_SIZE)
    world = RobloxWorld()
    calls_log = []
    inject_hits = []
    guard_hits = []
    rip_hits = defaultdict(int)
    stub_by_addr = {}
    stub_by_name = {}
    gp_modules = {}  # handle -> {name: stub_addr}

    def add_stub(name: str) -> int:
        if name in stub_by_name:
            return stub_by_name[name]
        addr = STUB_BASE + len(stub_by_addr) * STUB_STRIDE
        stub_by_addr[addr] = name
        stub_by_name[name] = addr
        mu.mem_write(addr, b"\xC3")  # ret — code hook fills RAX first
        return addr

    # core + inject surface stubs
    stub_names = [
        # CRT / prologue
        "FlsAlloc", "FlsGetValue", "FlsSetValue", "FlsFree",
        "InitializeCriticalSectionEx", "InitializeCriticalSection", "EnterCriticalSection",
        "LeaveCriticalSection", "DeleteCriticalSection",
        "AreFileApisANSI", "CompareStringEx", "EnumSystemLocalesEx",
        "GetDateFormatEx", "GetLocaleInfoEx", "GetTimeFormatEx",
        "GetUserDefaultLocaleName", "IsValidLocaleName", "LCMapStringEx",
        "LCIDToLocaleName", "LocaleNameToLCID",
        "SetConsoleTitleA", "IsWindowVisible", "BCryptGetProperty",
        "GetModuleHandleA", "GetModuleHandleW", "GetModuleHandleExW",
        "LoadLibraryA", "LoadLibraryW", "LoadLibraryExW", "FreeLibrary",
        "GetProcAddress", "FatalExit", "ExitProcess", "TerminateProcess", "ExitThread",
        "RtlAllocateHeap", "RtlFreeHeap", "HeapAlloc", "HeapFree", "HeapReAlloc", "HeapSize",
        "GetProcessHeap", "malloc", "calloc", "realloc", "free",
        "memcpy", "memmove", "memset", "strlen", "wcslen",
        "GetLastError", "SetLastError", "GetCurrentProcess", "GetCurrentProcessId",
        "GetCurrentThread", "GetCurrentThreadId", "Sleep", "SleepEx",
        "GetTickCount", "GetTickCount64", "QueryPerformanceCounter",
        "CloseHandle", "DuplicateHandle",
        "GetStdHandle", "WriteConsoleA", "WriteConsoleW", "GetConsoleMode",
        "MultiByteToWideChar", "WideCharToMultiByte",
        "GetModuleFileNameA", "GetModuleFileNameW",
        "MessageBoxA", "MessageBoxW", "MessageBoxTimeoutA",
        # process enum / inject
        "CreateToolhelp32Snapshot", "Process32FirstW", "Process32NextW",
        "Process32First", "Process32Next",
        "Thread32First", "Thread32Next", "Module32FirstW", "Module32NextW",
        "OpenProcess", "OpenThread",
        "VirtualAlloc", "VirtualAllocEx", "VirtualFree", "VirtualFreeEx",
        "VirtualProtect", "VirtualProtectEx",
        "ReadProcessMemory", "WriteProcessMemory",
        "CreateRemoteThread", "CreateRemoteThreadEx",
        "QueueUserAPC", "NtQueueApcThread", "NtQueueApcThreadEx",
        "NtCreateThreadEx", "RtlCreateUserThread",
        "NtAllocateVirtualMemory", "NtProtectVirtualMemory", "NtWriteVirtualMemory",
        "NtReadVirtualMemory", "NtMapViewOfSection", "NtCreateSection",
        "NtUnmapViewOfSection", "NtOpenProcess", "NtClose",
        "SuspendThread", "ResumeThread", "GetThreadContext", "SetThreadContext",
        "NtGetContextThread", "NtSetContextThread",
        "WaitForSingleObject", "WaitForSingleObjectEx", "GetExitCodeThread",
        "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "GetFileSize",
        "CreateFileMappingW", "MapViewOfFile", "UnmapViewOfFile",
        "EnumProcessModules", "EnumProcessModulesEx", "GetModuleBaseNameA", "GetModuleBaseNameW",
        "K32EnumProcessModules", "K32GetModuleBaseNameW",
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugStringA", "OutputDebugStringW",
        "GetSystemTimeAsFileTime", "GetLocalTime",
        "RtlInitUnicodeString", "LdrLoadDll", "LdrGetProcedureAddress",
    ]
    for n in stub_names:
        add_stub(n)

    # ---- rewrite injector IAT slots to OUR stubs (critical) ----
    rewritten = []
    live_to_name = {}
    for ent in iat_sample:
        off = int(ent["off"], 16) if isinstance(ent["off"], str) else int(ent["off"])
        val = int(ent["val"], 16) if isinstance(ent["val"], str) else int(ent["val"])
        sym = ent.get("sym") or ""
        name = sym.split("!")[-1] if "!" in sym else sym
        if not name:
            continue
        stub = add_stub(name)
        live_to_name[val] = name
        slot_va = IMG_BASE + off
        try:
            mu.mem_write(slot_va, struct.pack("<Q", stub))
            rewritten.append({"slot": hex(slot_va), "name": name, "stub": hex(stub), "was": hex(val)})
        except UcError as e:
            print(f"  IAT rewrite fail {slot_va:#x} {name}: {e}")

    # patch EVERY qword in the image that still holds a live resolved VA
    patched_ptrs = 0
    try:
        img = bytes(mu.mem_read(IMG_BASE, 0x1600000))
    except UcError:
        img = b""
    if img and live_to_name:
        blob = bytearray(img)
        for live, name in live_to_name.items():
            stub = stub_by_name[name]
            needle = struct.pack("<Q", live)
            start = 0
            while True:
                p = blob.find(needle, start)
                if p < 0:
                    break
                blob[p:p + 8] = struct.pack("<Q", stub)
                patched_ptrs += 1
                start = p + 8
        if patched_ptrs:
            mu.mem_write(IMG_BASE, bytes(blob))
    print(f"IAT slots rewritten: {len(rewritten)}; absolute ptr patches: {patched_ptrs}")

    # map live DLL entry points as trampolines → our stubs (belt + suspenders)
    for live, name in live_to_name.items():
        stub = stub_by_name[name]
        pg = align_down(live)
        try:
            mu.mem_map(pg, 0x1000, UC_PROT_ALL)
        except UcError:
            pass
        # mov rax, imm64; jmp rax
        tramp = b"\x48\xB8" + struct.pack("<Q", stub) + b"\xFF\xE0"
        try:
            mu.mem_write(live, tramp)
        except UcError as e:
            print(f"  trampoline fail {live:#x}: {e}")
        # do NOT put live in stub_by_addr — only the STUB_BASE target handles the API.
        # live trampoline is real mov/jmp bytes the CPU executes.
    # also seed a GetProcAddress table for inject APIs
    for n in INJECT_WATCH:
        add_stub(n)

    # ---- bulk-map system DLL exports at DUMP bases → stubs ----
    def map_pe_exports(pe_path: str, dump_base: int, limit: int = 4096) -> int:
        try:
            import pefile as _pefile
            pe = _pefile.PE(pe_path)
        except Exception as e:
            print(f"  export map skip {pe_path}: {e}")
            return 0
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return 0
        n = 0
        for e in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if not e.name or n >= limit:
                continue
            name = e.name.decode(errors="replace")
            live = dump_base + e.address
            stub = add_stub(name)
            live_to_name[live] = name
            pg = align_down(live)
            try:
                mu.mem_map(pg, 0x1000, UC_PROT_ALL)
            except UcError:
                pass
            tramp = b"\x48\xB8" + struct.pack("<Q", stub) + b"\xFF\xE0"
            try:
                mu.mem_write(live, tramp)
            except UcError:
                pass
            # live stays trampoline-only; stub_by_addr hits STUB_BASE
            n += 1
        return n

    n_ntdll = map_pe_exports(r"C:\Windows\System32\ntdll.dll", 0x7FFD5CFB0000)
    n_k32 = map_pe_exports(r"C:\Windows\System32\kernel32.dll", 0x7FFD5B0E0000)
    n_kb = map_pe_exports(r"C:\Windows\System32\KernelBase.dll", 0x7FFD5ACB0000)
    print(f"export trampolines: ntdll={n_ntdll} k32={n_k32} kb={n_kb}")

    # ---- fill system range with INT3 so real system code never executes ----
    # then re-write export trampolines so only EXPORTED calls land on stubs.
    sys_ranges = [
        (0x7FFD5CFB0000, 0x100000),  # ntdll
        (0x7FFD5B0E0000, 0x100000),  # kernel32
        (0x7FFD5ACB0000, 0x100000),  # KernelBase
    ]
    for sbase, ssize in sys_ranges:
        pg = align_down(sbase)
        for a in range(pg, pg + ssize, 0x1000):
            try:
                mu.mem_write(a, b"\xCC" * 0x1000)
            except UcError:
                pass
    # re-apply trampolines (mov rax, imm64; jmp rax) at every mapped live export
    for live, name in live_to_name.items():
        stub = stub_by_name.get(name)
        if stub is None:
            continue
        tramp = b"\x48\xB8" + struct.pack("<Q", stub) + b"\xFF\xE0"
        try:
            mu.mem_write(live, tramp)
        except UcError:
            pass
    print(f"system range INT3-filled; {len(live_to_name)} export trampolines re-applied")

    # ---- force main past early-exit (patch jne → jmp) ----
    try:
        jne_bytes = bytes(mu.mem_read(EARLY_CMP_JNE, 6))
        print(f"early jne bytes @ {EARLY_CMP_JNE:#x}: {jne_bytes.hex()}")
        if jne_bytes[0] == 0x75:  # short jne
            mu.mem_write(EARLY_CMP_JNE, bytes([0xEB, jne_bytes[1]]))
            print("  patched short jne → jmp")
        elif jne_bytes[0:2] == b"\x0f\x85":
            mu.mem_write(EARLY_CMP_JNE, b"\x90\xE9" + jne_bytes[2:6])
            print("  patched near jne → jmp")
        else:
            rel = FORCE_CONTINUE_AT - (EARLY_CMP_JNE + 5)
            mu.mem_write(EARLY_CMP_JNE, b"\xE9" + struct.pack("<i", rel))
            print(f"  forced jmp to {FORCE_CONTINUE_AT:#x}")
    except UcError as e:
        print(f"  early-exit patch failed: {e}")

    # ---- CRT memset AVX guard: forc,ar caminho SSE ----
    # 0x7ff732ebab36: cmp dword ptr [rip+0x1853b], 3 ; jb 0x7ff732ebad20
    # __isa_available no dump indica CPU AVX2; unicorn nao decodifica vinsertf128.
    try:
        mu.mem_write(0x7ff732ebab3d, b"\xE9" + struct.pack("<i", 0x7ff732ebad20 - (0x7ff732ebab3d + 5)))
        print("  patched memset AVX check -> forced SSE path")
    except UcError as e:
        print(f"  memset AVX patch failed: {e}")

    # ---- PEB / TEB ----
    # TEB.ProcessEnvironmentBlock = TEB+0x60 → PEB
    mu.mem_write(TEB_BASE + 0x30, struct.pack("<Q", TEB_BASE))  # Self
    mu.mem_write(TEB_BASE + 0x60, struct.pack("<Q", PEB_BASE))
    mu.mem_write(PEB_BASE + 0x2, b"\x00")  # BeingDebugged
    mu.mem_write(PEB_BASE + 0x68, b"\x00\x00\x00\x00")  # NtGlobalFlag
    process_heap = heap.alloc(0x100)
    mu.mem_write(PEB_BASE + 0x30, struct.pack("<Q", process_heap))
    mu.mem_write(PEB_BASE + 0x18, struct.pack("<Q", PEB_BASE + 0x2000))  # Ldr
    try:
        mu.reg_write(UC_X86_REG_GS_BASE, TEB_BASE)
    except UcError:
        # older unicorn: try MSR path via reg write alternate
        pass

    # ---- API handlers ----
    last_error = 0

    def handle_api(name: str) -> int | None:
        nonlocal last_error
        rcx = mu.reg_read(UC_X86_REG_RCX)
        rdx = mu.reg_read(UC_X86_REG_RDX)
        r8 = mu.reg_read(UC_X86_REG_R8)
        r9 = mu.reg_read(UC_X86_REG_R9)
        calls_log.append(name)
        if name == "main_ret":
            print("  [MAIN-RETURNED] main completou limpo - parando emulacao")
            # ultimos enderecos da imagem executados (tail do fluxo INJECT)
            img_tail = [a for a, _ in trace_hist if IMG_BASE <= a < IMG_BASE + 0x800000][-12:]
            print("  image tail:", " ".join(f"{a:#x}" for a in img_tail))
            mu.emu_stop()
            return 0
        if name in INJECT_WATCH:
            inject_hits.append({
                "api": name,
                "rcx": hex(rcx), "rdx": hex(rdx), "r8": hex(r8), "r9": hex(r9),
                "rip": hex(mu.reg_read(UC_X86_REG_RIP)),
            })
            print(f"  !! INJECT-SURFACE {name} rcx={rcx:#x} rdx={rdx:#x} r8={r8:#x} r9={r9:#x}")

        # heap
        if name in ("RtlAllocateHeap", "HeapAlloc"):
            # RtlAllocateHeap(Heap, Flags, Size) — size in r8
            sz = r8 if name == "RtlAllocateHeap" else r8
            ptr = heap.alloc(sz or 0x40)
            print(f"  [API] {name} size={sz:#x} -> {ptr:#x}")
            # dump payload-sized buffers for the other agent
            if sz in (0x1127, 4391) or sz >= 0x1000:
                try:
                    out_dir = ROOT / "output" / "emu_injector"
                    out_dir.mkdir(parents=True, exist_ok=True)
                    blob = bytes(mu.mem_read(ptr, min(int(sz), 0x20000)))
                    path = out_dir / f"heap_{ptr:#x}_sz{sz:#x}.bin"
                    path.write_bytes(blob)
                    print(f"  [DUMP] heap buffer -> {path} ({len(blob)} bytes)")
                    # also snapshot later via registry
                    heap._dumps = getattr(heap, "_dumps", [])
                    heap._dumps.append({"ptr": hex(ptr), "size": hex(sz), "path": str(path)})
                except Exception as e:
                    print(f"  [DUMP] fail: {e}")
            return ptr
        if name in ("malloc", "calloc"):
            sz = rcx if name == "malloc" else (rcx * max(rdx, 1))
            ptr = heap.alloc(sz or 0x40)
            print(f"  [API] {name} size={sz:#x} -> {ptr:#x}")
            return ptr
        if name == "realloc":
            ptr = heap.alloc(rdx or 0x40)
            return ptr
        if name in ("HeapFree", "RtlFreeHeap", "free"):
            return 1
        if name == "GetProcessHeap":
            return process_heap
        if name == "HeapReAlloc":
            return heap.alloc(r9 or 0x40)
        if name == "HeapSize":
            return 0x40

        # critical sections — the inject enters/leaves CS around its work
        if name in ("RtlEnterCriticalSection", "RtlLeaveCriticalSection", "RtlTryEnterCriticalSection",
                    "EnterCriticalSection", "LeaveCriticalSection", "TryEnterCriticalSection"):
            print(f"  [API] {name} cs@{rcx:#x}")
            return 1 if name in ("RtlTryEnterCriticalSection", "TryEnterCriticalSection") else 0

        # modules / gpa
        if name in ("GetModuleHandleA", "GetModuleHandleW"):
            if rcx == 0:
                return IMG_BASE
            n = read_cstr(mu, rcx, wide=(name.endswith("W")))
            print(f"  [API] {name}('{n}')")
            if not n:
                return IMG_BASE
            low = n.lower()
            if "kernel32" in low:
                return FAKE_MOD_BASE + 0x1000
            if "ntdll" in low:
                return FAKE_MOD_BASE + 0x2000
            if "user32" in low:
                return FAKE_MOD_BASE + 0x3000
            h = add_stub(f"mod:{n}")  # unlikely
            return FAKE_MOD_BASE + 0x4000
        if name in ("LoadLibraryA", "LoadLibraryW", "LoadLibraryExW"):
            n = read_cstr(mu, rcx, wide=("W" in name))
            print(f"  [API] {name}('{n}')")
            handle = FAKE_MOD_BASE + 0x5000 + (len(gp_modules) * 0x1000)
            gp_modules[handle] = {}
            # pre-fill common exports for this module
            for exp in stub_by_name:
                gp_modules[handle][exp] = stub_by_name[exp]
            return handle
        if name == "GetProcAddress":
            if rdx < 0x10000:
                stub = add_stub(f"ord_{rdx}")
                print(f"  [API] GetProcAddress(ord={rdx}) -> {stub:#x}")
                return stub
            n = read_cstr(mu, rdx, wide=False)
            print(f"  [API] GetProcAddress('{n}')")
            if not n:
                return 0
            if n in stub_by_name:
                return stub_by_name[n]
            return add_stub(n)
        if name in ("LdrGetProcedureAddress", "LdrGetProcedureAddressForCaller"):
            # x64: rcx=Module, rdx=PANSI_STRING, r8=Ordinal, r9=*OutAddr
            # ForCaller may put *Out on stack — write both r9 and [rsp+0x28]
            ansi = rdx
            ordinal = r8 & 0xFFFF
            out_ptr = r9
            rsp = mu.reg_read(UC_X86_REG_RSP)
            proc_name = ""
            if ansi:
                try:
                    length = struct.unpack("<H", bytes(mu.mem_read(ansi, 2)))[0]
                    buf = struct.unpack("<Q", bytes(mu.mem_read(ansi + 8, 8)))[0]
                    if buf and 0 < length < 512:
                        proc_name = bytes(mu.mem_read(buf, length)).decode("latin-1", errors="replace")
                except Exception:
                    proc_name = read_cstr(mu, ansi, wide=False)
            # common CRT delay-load ordinals → real names when possible
            ORD_MAP = {
                1: "DisableThreadLibraryCalls",
                2: "GetLastError",
                3: "SetLastError",
                14: "HeapAlloc",
                15: "HeapFree",
                16: "GetProcessHeap",
                17: "HeapReAlloc",
                18: "HeapSize",
            }
            if not proc_name and ordinal:
                proc_name = ORD_MAP.get(ordinal, f"ord_{ordinal}")
            stub = stub_by_name.get(proc_name) or add_stub(proc_name or "LdrUnknown")
            # if r9 is null, 4th arg may already have been spilled — scan stack for plausible *out
            try:
                ret_addr = struct.unpack("<Q", bytes(mu.mem_read(rsp, 8)))[0]
            except UcError:
                ret_addr = 0
            print(
                f"  [API] {name}('{proc_name}' ord={ordinal}) mod={rcx:#x} "
                f"r8={r8:#x} r9={out_ptr:#x} ret={ret_addr:#x} -> {stub:#x}"
            )
            # write stub into EVERY plausible out slot: r9, broad stack window,
            # and RBX (the CRT init tail does `mov rax, rbx; ret`)
            targets = []
            if out_ptr and out_ptr > 0x10000:
                targets.append(out_ptr)
            for off in range(0x00, 0x90, 8):
                targets.append(rsp + off)
            for off in range(0x08, 0x80, 8):
                targets.append(rsp - off)
            for p in targets:
                try:
                    mu.mem_write(p, struct.pack("<Q", stub))
                except UcError:
                    pass
            # dump the caller's next instructions to see how it reads the result
            try:
                from capstone import Cs, CS_ARCH_X86, CS_MODE_64
                _cd = bytes(mu.mem_read(ret_addr, 48))
                _md = Cs(CS_ARCH_X86, CS_MODE_64)
                print("    caller after Ldr:")
                for _ins in _md.disasm(_cd, ret_addr):
                    print(f"      {_ins.address:#x}: {_ins.mnemonic} {_ins.op_str}")
                    if _ins.address > ret_addr + 0x2f:
                        break
            except Exception as _e:
                print(f"    caller dump fail: {_e}")
            mu.reg_write(UC_X86_REG_RBX, stub)
            mu.reg_write(UC_X86_REG_RAX, 0)  # STATUS_SUCCESS
            return 0  # STATUS_SUCCESS
        # Roblox world
        if name == "CreateToolhelp32Snapshot":
            flags = rcx & 0xFFFFFFFF
            print(f"  [API] CreateToolhelp32Snapshot flags={flags:#x}")
            world.enum_state[world.snap_handle] = -1
            return world.snap_handle
        if name in ("Process32FirstW", "Process32First"):
            pe_addr = rdx
            world.enum_state[rcx] = 0
            ok = world.fill_pe32(mu, pe_addr, 0)
            print(f"  [API] {name} -> {world.procs[0]['name']} ok={ok}")
            return ok
        if name in ("Process32NextW", "Process32Next"):
            idx = world.enum_state.get(rcx, 0) + 1
            world.enum_state[rcx] = idx
            ok = world.fill_pe32(mu, rdx, idx)
            nm = world.procs[idx]["name"] if ok else "<end>"
            print(f"  [API] {name} -> {nm} ok={ok}")
            return ok
        if name == "OpenProcess":
            access, pid = rcx, r8 & 0xFFFFFFFF
            print(f"  [API] OpenProcess access={access:#x} pid={pid}")
            if pid == world.pid or pid == 0x3039:
                return world.proc_handle
            # also accept any non-zero as success to keep going
            if pid:
                return world.proc_handle
            last_error = 87
            return 0
        if name in ("Thread32First", "Thread32Next"):
            # minimal THREADENTRY32: mark owner pid = roblox
            te = bytearray(28)
            struct.pack_into("<I", te, 0, 28)
            struct.pack_into("<I", te, 12, world.pid)  # th32OwnerProcessID approx
            struct.pack_into("<I", te, 8, 0x777)  # th32ThreadID
            try:
                mu.mem_write(rdx, bytes(te))
            except UcError:
                pass
            if name == "Thread32Next":
                return 0
            return 1

        # inject primitives — succeed and log
        if name in ("VirtualAllocEx", "VirtualAlloc"):
            sz = r8 if name == "VirtualAllocEx" else rdx
            ptr = heap.alloc(sz or 0x1000)
            print(f"  [API] {name} size={sz:#x} -> {ptr:#x}")
            return ptr
        if name in ("NtAllocateVirtualMemory",):
            # (ProcessHandle, *BaseAddress, ZeroBits, *RegionSize, …)
            try:
                sz = struct.unpack("<Q", bytes(mu.mem_read(r9, 8)))[0]
            except Exception:
                sz = 0x1000
            ptr = heap.alloc(sz or 0x1000)
            try:
                mu.mem_write(rdx, struct.pack("<Q", ptr))
            except UcError:
                pass
            return 0  # STATUS_SUCCESS
        if name in ("WriteProcessMemory", "NtWriteVirtualMemory"):
            print(f"  [API] {name} dest={rdx:#x} src={r8:#x}")
            return 1 if not name.startswith("Nt") else 0
        if name in ("ReadProcessMemory", "NtReadVirtualMemory"):
            return 1 if not name.startswith("Nt") else 0
        if name in ("VirtualProtect", "VirtualProtectEx", "NtProtectVirtualMemory"):
            return 1 if not name.startswith("Nt") else 0
        if name in ("CreateRemoteThread", "CreateRemoteThreadEx"):
            print(f"  [API] {name} start={r8:#x}")
            return 0x1111
        if name in ("NtCreateThreadEx", "RtlCreateUserThread"):
            print(f"  [API] {name}")
            return 0
        if name in ("QueueUserAPC", "NtQueueApcThread", "NtQueueApcThreadEx"):
            print(f"  [API] {name} func={rcx:#x} thread={rdx:#x}")
            return 1 if name == "QueueUserAPC" else 0
        if name in ("NtMapViewOfSection", "NtCreateSection", "NtUnmapViewOfSection"):
            print(f"  [API] {name}")
            if name == "NtMapViewOfSection":
                try:
                    mu.mem_write(r8, struct.pack("<Q", heap.alloc(0x10000)))
                except Exception:
                    pass
            return 0
        if name == "CloseHandle":
            return 1
        if name == "GetCurrentProcess":
            return 0xFFFFFFFFFFFFFFFF
        if name in ("GetCurrentProcessId",):
            return 0x2222
        if name in ("GetCurrentThreadId", "GetCurrentThread"):
            return 0x5678 if "Id" in name else 0xFFFFFFFE
        if name in ("Sleep", "SleepEx"):
            return 0
        if name in ("GetTickCount",):
            return 0x12345678
        if name in ("GetTickCount64",):
            return 0x123456789
        if name in ("SetConsoleTitleA", "IsWindowVisible"):
            return 1
        if name in ("MessageBoxA", "MessageBoxW", "MessageBoxTimeoutA"):
            title = read_cstr(mu, rdx if name.endswith("A") else rdx, wide=name.endswith("W"))
            print(f"  [API] {name} '{title}'")
            return 1
        if name in ("GetLastError",):
            return last_error
        if name in ("SetLastError",):
            last_error = rcx & 0xFFFFFFFF
            return 0
        if name in ("FatalExit", "ExitProcess", "TerminateProcess", "ExitThread"):
            print(f"  >>> {name} — stopping emu")
            mu.emu_stop()
            return 0
        if name in ("FlsAlloc", "TlsAlloc"):
            return 1
        if name in ("FlsGetValue", "TlsGetValue"):
            return 0
        if name in ("FlsSetValue", "TlsSetValue", "InitializeCriticalSectionEx",
                    "InitializeCriticalSection", "InitializeCriticalSectionAndSpinCount",
                    "RtlInitializeCriticalSection", "RtlEnterCriticalSection",
                    "EnterCriticalSection", "LeaveCriticalSection", "RtlLeaveCriticalSection"):
            return 1
        if name in ("EncodePointer", "DecodePointer"):
            return rcx  # identity
        if name in ("LoadLibraryExW", "LoadLibraryExA"):
            n = read_cstr(mu, rcx, wide=name.endswith("W"))
            print(f"  [API] {name}('{n}')")
            handle = FAKE_MOD_BASE + 0x5000 + (len(gp_modules) * 0x1000)
            gp_modules[handle] = {exp: stub_by_name[exp] for exp in stub_by_name}
            return handle
        if name in ("AreFileApisANSI", "IsValidLocaleName"):
            return 1
        if name.startswith("Get") and name.endswith("Ex"):
            return 1
        if name in ("CompareStringEx", "LCMapStringEx"):
            return 2  # CSTR_EQUAL-ish
        if name in ("MultiByteToWideChar", "WideCharToMultiByte"):
            # return required size / copied
            return max(int(r9), 1) if r9 else 1
        if name in ("GetModuleFileNameA", "GetModuleFileNameW"):
            path = r"C:\Users\ggles\AppData\Roaming\umi\bin\injector.exe"
            try:
                if name.endswith("W"):
                    mu.mem_write(rdx, (path + "\x00").encode("utf-16le"))
                else:
                    mu.mem_write(rdx, (path + "\x00").encode("ascii"))
            except UcError:
                pass
            return len(path)
        if name in ("GetSystemDirectoryA", "GetSystemDirectoryW"):
            path = r"C:\Windows\System32"
            try:
                if name.endswith("W"):
                    mu.mem_write(rcx, (path + "\x00").encode("utf-16le"))
                else:
                    mu.mem_write(rcx, (path + "\x00").encode("ascii"))
            except UcError:
                pass
            return len(path)
        if name in ("BCryptGetProperty", "BCryptSetProperty"):
            # NTSTATUS BCryptGetProperty(hObject, pszProperty, pbOutput, cbOutput, *pcbResult, flags)
            # r9=cbOutput; pcbResult at [rsp+0x28]
            prop = read_cstr(mu, rdx, wide=True) if rdx else ""
            pb = r8
            cb = r9 & 0xFFFFFFFF
            rsp = mu.reg_read(UC_X86_REG_RSP)
            try:
                pcb = struct.unpack("<Q", bytes(mu.mem_read(rsp + 0x28, 8)))[0]
            except UcError:
                pcb = 0
            # SHA256 defaults matching CNG
            prop_clean = "".join(ch for ch in prop if ch.isprintable()).strip("\x00")
            props = {
                "ObjectLength": 0x188,       # CNG SHA256 object; matches VALIDATE cfg
                "HashDigestLength": 32,
                "AlgorithmName": "SHA256",
                "HashBlockLength": 64,
                "PaddingSchemes": 0,
            }
            val = props.get(prop_clean)
            if val is None:
                for k, v in props.items():
                    if k.lower() in prop_clean.lower() or prop_clean.lower() in k.lower():
                        val = v
                        break
            if val is None:
                val = 32 if cb >= 4 else 0
            prop = prop_clean or prop
            written = 0
            try:
                if isinstance(val, str):
                    blob = (val + "\x00").encode("utf-16le")
                    written = len(blob)
                    if pb and cb >= written:
                        mu.mem_write(pb, blob)
                else:
                    written = 4
                    if pb and cb >= 4:
                        mu.mem_write(pb, struct.pack("<I", int(val) & 0xFFFFFFFF))
                if pcb and pcb > 0x10000:
                    mu.mem_write(pcb, struct.pack("<I", written))
            except UcError as e:
                print(f"  [API] BCryptGetProperty write fail: {e}")
            print(f"  [API] BCryptGetProperty('{prop}') -> {val!r} pcb={written} STATUS_SUCCESS")
            return 0
        if name in ("BCryptOpenAlgorithmProvider",):
            # (BCRYPT_ALG_HANDLE *ph, LPCWSTR alg, LPCWSTR impl, ULONG flags)
            h = heap.alloc(0x40)
            if rcx and rcx > 0x10000:
                try:
                    mu.mem_write(rcx, struct.pack("<Q", h))
                except UcError:
                    pass
            print(f"  [API] BCryptOpenAlgorithmProvider -> handle {h:#x}")
            return 0
        if name in ("BCryptCreateHash", "BCryptHashData", "BCryptFinishHash", "BCryptDestroyHash",
                    "BCryptCloseAlgorithmProvider", "BCryptGenRandom", "BCryptDuplicateHash"):
            # FinishHash: write 32-byte digest to pbOutput if present
            if name == "BCryptFinishHash" and rdx and r8 >= 32:
                try:
                    mu.mem_write(rdx, b"\xA5" * 32)
                except UcError:
                    pass
            if name == "BCryptCreateHash" and rcx and rcx > 0x10000:
                try:
                    mu.mem_write(rcx, struct.pack("<Q", heap.alloc(0x80)))
                except UcError:
                    pass
            print(f"  [API] {name} -> STATUS_SUCCESS")
            return 0
        # GetHashInterface (bcryptprimitives) — REAL contract:
        #   NTSTATUS GetHashInterface(PVOID unused, PCWSTR pszAlgId, PVOID *ppIface)
        #   RAX = NTSTATUS (0 = success). *r8 = pointer to static-shaped table.
        #   table+0x00 = BCRYPT_INTERFACE_VERSION {2,0} as QWORD 2
        #   table+0x08.. = function pointers (OpenAlgorithmProvider, etc.)
        # Our old bug returned the pointer IN RAX → VALIDATE saw garbage / NOT_SUPPORTED.
        if name == "GetHashInterface":
            alg = read_cstr(mu, rdx, wide=True) if rdx else ""
            out_ptr = r8
            iface = heap.alloc(0x80)
            # version major=2 minor=0
            mu.mem_write(iface, struct.pack("<Q", 2))
            # method slots → stubs that return STATUS_SUCCESS (0)
            for slot in range(0x08, 0x80, 8):
                stub = add_stub(f"hashfn_{slot:#x}")
                # ensure handler returns 0 (NTSTATUS), not default 1
                mu.mem_write(iface + slot, struct.pack("<Q", stub))
            if out_ptr and out_ptr > 0x10000:
                try:
                    mu.mem_write(out_ptr, struct.pack("<Q", iface))
                except UcError as e:
                    print(f"  [API] GetHashInterface out-write fail {out_ptr:#x}: {e}")
            print(
                f"  [API] GetHashInterface alg='{alg}' out*{out_ptr:#x}={iface:#x} "
                f"version=2 -> STATUS_SUCCESS"
            )
            return 0  # NTSTATUS
        if name.startswith("hashfn_"):
            # CNG hash provider methods — succeed silently
            print(f"  [API] {name} rcx={rcx:#x} rdx={rdx:#x} r8={r8:#x} -> STATUS_SUCCESS")
            # some methods write handles to *out; if r8 looks like out-ptr, seed a fake handle
            if r8 and 0x10000 < r8 < 0x00007FFFFFFFFFFF:
                try:
                    # only write if destination looks like empty pointer slot
                    cur = struct.unpack("<Q", bytes(mu.mem_read(r8, 8)))[0]
                    if cur == 0:
                        h = heap.alloc(0x40)
                        mu.mem_write(r8, struct.pack("<Q", h))
                except UcError:
                    pass
            return 0
        if name in ("WaitForSingleObject", "WaitForSingleObjectEx"):
            return 0  # WAIT_OBJECT_0
        if name in ("ResumeThread", "SuspendThread"):
            return 1
        if name in ("IsDebuggerPresent", "CheckRemoteDebuggerPresent"):
            return 0
        if name == "NtQueryInformationProcess":
            return 0

        # ---- string comparisons: dump + return EQUAL so validate passes ----
        if name in ("_wcsicmp", "wcsicmp", "lstrcmpiW", "RtlCompareUnicodeString",
                    "RtlEqualUnicodeString", "strcmp", "strncmp", "_stricmp", "wcscmp", "wcsncmp"):
            try:
                if name in ("RtlCompareUnicodeString", "RtlEqualUnicodeString"):
                    # rcx,rdx = PUNICODE_STRING
                    def _us(p):
                        ln = struct.unpack("<H", bytes(mu.mem_read(p, 2)))[0]
                        buf = struct.unpack("<Q", bytes(mu.mem_read(p + 8, 8)))[0]
                        return bytes(mu.mem_read(buf, min(ln, 256))).decode("utf-16-le", errors="replace")
                    s1, s2 = _us(rcx), _us(rdx)
                else:
                    s1 = read_cstr(mu, rcx, wide=("w" in name.lower()))
                    s2 = read_cstr(mu, rdx, wide=("w" in name.lower()))
                print(f"  [API] {name} '{s1}' vs '{s2}' -> EQUAL(forced)")
            except Exception as _e:
                print(f"  [API] {name} (dump fail {_e}) -> EQUAL(forced)")
            return 0
        if name in ("memcmp", "RtlCompareMemory"):
            print(f"  [API] {name} len={r8:#x} -> EQUAL(forced)")
            return 0

        # default success
        print(f"  [API] {name} rcx={rcx:#x} rdx={rdx:#x}")
        if name == "dispatch_guard":
            return 0
        if name.startswith("Get") and not name.startswith("GetProc"):
            return heap.alloc(0x100)  # interface/object getters — non-null object
        return 1

    trace_hist = []
    xfer_hist = []
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        md.detail = False
    except Exception:
        md = None

    def on_code(uc, address, size, _user):
        rip_hits[address] += 1
        trace_hist.append((address, size))
        if len(trace_hist) > 5000:
            del trace_hist[0]
        # VAIT validation checkpoint — main's test after VALIDATE returns
        if address == 0x7ff732e74748:
            _eax = uc.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF
            _rsp = uc.reg_read(UC_X86_REG_RSP)
            try:
                _cfg = struct.unpack("<Q", bytes(uc.mem_read(_rsp + 0x58, 8)))[0]
            except UcError:
                _cfg = 0
            print("  [CHECKPOINT] main@74748 (pos-VALIDATE) eax=%08x rax=%#x cfg[rsp+58]=%#x rbx=%#x" % (
                _eax, uc.reg_read(UC_X86_REG_RAX), _cfg,
                uc.reg_read(UC_X86_REG_RBX)))
            # EMU_FORCE_VALIDATE=1 → always force (legacy). Default=0 → natural only.
            force = os.environ.get("EMU_FORCE_VALIDATE", "0") == "1"
            if (_eax & 0xFFFFFFFF) < 0x80000000 and _eax == 0:
                print(f"  [CHECKPOINT] VALIDATE NATURAL SUCCESS eax=0 cfg={_cfg:#x}")
            elif force:
                uc.reg_write(UC_X86_REG_RAX, 0)
                print(f"  [CHECKPOINT] VALIDATE failed ({_eax:#x}) — FORCED eax=0 (EMU_FORCE_VALIDATE=1)")
                if _cfg == 0:
                    try:
                        uc.mem_write(_rsp + 0x58, struct.pack("<Q", 0x40000001100))
                        print("  [CHECKPOINT] seeded cfg obj 0x40000001100 into [rsp+0x58]")
                    except UcError:
                        pass
            else:
                print(
                    f"  [CHECKPOINT] VALIDATE NATURAL FAIL eax={_eax:#x} cfg={_cfg:#x} "
                    f"(no force — set EMU_FORCE_VALIDATE=1 to bypass)"
                )
        # INJECT return checkpoint — status do INJECT fn ao voltar pro main
        if address == 0x7ff732e74848:
            print("  [CHECKPOINT] main@74848 (pos-INJECT) eax=%08x rax=%#x rbx=%#x rcx=%#x rdx=%#x" % (
                uc.reg_read(UC_X86_REG_RAX) & 0xFFFFFFFF,
                uc.reg_read(UC_X86_REG_RAX),
                uc.reg_read(UC_X86_REG_RBX),
                uc.reg_read(UC_X86_REG_RCX),
                uc.reg_read(UC_X86_REG_RDX)))
        # ---- generalize corrupt call-ind / jmp-rax repair (item 2) ----
        try:
            _ob = bytes(uc.mem_read(address, 6))
            if len(_ob) >= 6 and _ob[0] == 0xFF and _ob[1] == 0x15:
                # call qword ptr [rip+disp32]
                _disp = struct.unpack_from("<i", _ob, 2)[0]
                _slot = address + 6 + _disp
                _ptr = struct.unpack("<Q", bytes(uc.mem_read(_slot, 8)))[0]
                _bad = (
                    _ptr < 0x100000
                    or (_ptr & 0xFF00000000000000) != 0
                    or (0x100000 <= _ptr < 0x7FF000000000 and _ptr not in stub_by_addr)
                )
                if _bad:
                    _fix = (
                        stub_by_name.get("BCryptGetProperty")
                        or stub_by_name.get("RtlLeaveCriticalSection")
                        or stub_by_name.get("GetProcAddress")
                        or STUB_BASE
                    )
                    uc.mem_write(_slot, struct.pack("<Q", _fix))
                    print(f"  [CALL-IND] {address:#x} corrupt {_ptr:#x} -> stub {_fix:#x} (slot {_slot:#x})")
            if len(_ob) >= 2 and _ob[0] == 0xFF and _ob[1] == 0xE0:
                # jmp rax
                _rax = uc.reg_read(UC_X86_REG_RAX)
                if _rax < 0x100000 or (_rax & 0xFF00000000000000) != 0:
                    _fix = stub_by_name.get("BCryptGetProperty") or STUB_BASE
                    uc.reg_write(UC_X86_REG_RAX, _fix)
                    print(f"  [JMP-RAX] {address:#x} garbage rax={_rax:#x} -> stub {_fix:#x}")
        except Exception:
            pass
        if address == 0x7ffd5aaa9760:
            _rax = uc.reg_read(UC_X86_REG_RAX)
            print(f"  [JMPRAX-9760] rax={_rax:#x} rbx={uc.reg_read(UC_X86_REG_RBX):#x} rcx={uc.reg_read(UC_X86_REG_RCX):#x} r8={uc.reg_read(UC_X86_REG_R8):#x} r9={uc.reg_read(UC_X86_REG_R9):#x} rsp={uc.reg_read(UC_X86_REG_RSP):#x}")
        # cheap transfer detection: opcode pre-check, then capstone for the target
        try:
            b = bytes(uc.mem_read(address, min(size + 6, 16)))
            if b and b[0] in (0xE8, 0xE9, 0xEB, 0xC3, 0xC2, 0xFF) or (b and b[0] == 0x0F and len(b) > 1 and 0x80 <= b[1] <= 0x8F) or (b and 0x70 <= b[0] <= 0x7F):
                insn = list(md.disasm(b, address, 1))
                if insn and insn[0].mnemonic in ("call", "jmp", "ret", "je", "jne", "jz", "jnz", "ja", "jae", "jb", "jbe", "jg", "jge", "jl", "jle", "js", "jns", "jo", "jno", "jp", "jnp", "loop"):
                    xfer_hist.append((address, insn[0].mnemonic, insn[0].op_str, size))
                    if len(xfer_hist) > 50:
                        del xfer_hist[0]
                    if insn[0].mnemonic == "jmp" and insn[0].op_str == "rax":
                        rax = uc.reg_read(UC_X86_REG_RAX)
                        rbx = uc.reg_read(UC_X86_REG_RBX)
                        extra = ""
                        if address == 0x7ff732eba260:
                            try:
                                vt = struct.unpack("<Q", bytes(uc.mem_read(0x7ff732ebd640, 0x30)))
                                extra = " vt1=%#x" % vt[1]
                            except Exception:
                                pass
                            try:
                                obj0 = struct.unpack("<Q", bytes(uc.mem_read(rbx, 8)))[0]
                                extra += " [rbx]=%#x" % obj0
                            except Exception:
                                extra += " [rbx]=?"
                            # ---- DISPATCH GUARD: garbage target -> route to a
                            # returning stub so the walker keeps going ----
                            unsafe = rax < 0x100000
                            if not unsafe:
                                try:
                                    uc.mem_read(rax, 1)
                                except UcError:
                                    unsafe = True
                            if unsafe:
                                try:
                                    n0 = struct.unpack("<Q", bytes(uc.mem_read(rbx, 8)))[0]
                                    n8 = struct.unpack("<Q", bytes(uc.mem_read(rbx + 8, 8)))[0]
                                    n10 = struct.unpack("<Q", bytes(uc.mem_read(rbx + 0x10, 8)))[0]
                                    nxt = struct.unpack("<Q", bytes(uc.mem_read(rbx, 8)))[0]
                                    print(f"  [DISPATCH-GUARD] thunk rax={rax:#x} node={rbx:#x} "
                                          f"[node]={n0:#x} [node+8]={n8:#x} [node+0x10]={n10:#x}")
                                except Exception:
                                    print(f"  [DISPATCH-GUARD] thunk rax={rax:#x} node={rbx:#x} (node read fail)")
                                guard_stub = stub_by_name.get("dispatch_guard")
                                if guard_stub is None:
                                    guard_stub = add_stub("dispatch_guard")
                                uc.reg_write(UC_X86_REG_RAX, guard_stub)
                                guard_hits.append({"rax": rax, "node": rbx})
                        print(f"  [JMP-RAX] {address:#x} rax={rax:#x} rbx={rbx:#x}{extra}")
        except Exception:
            pass
        name = stub_by_addr.get(address)
        if not name:
            if address == VALIDATE_FN:
                print(f"  >> hit VALIDATE fn {address:#x}")
            if address == INJECT_FN:
                print(f"  >> hit INJECT fn {address:#x}")
                # dump params: rcx (config obj), rdx (str), r8, r9
                _rcx = uc.reg_read(UC_X86_REG_RCX)
                _rdx = uc.reg_read(UC_X86_REG_RDX)
                _r8 = uc.reg_read(UC_X86_REG_R8)
                _r9 = uc.reg_read(UC_X86_REG_R9)
                print(f"     INJECT params: rcx={_rcx:#x} rdx={_rdx:#x} r8={_r8:#x} r9={_r9:#x}")
                try:
                    if _rcx and _rcx < 0x700000000000:
                        _b = bytes(uc.mem_read(_rcx, 0x80))
                        print(f"     [rcx]={_b.hex()}")
                except Exception:
                    pass
                try:
                    if _rdx and _rdx < 0x700000000000:
                        _s = read_cstr(uc, _rdx, wide=False)
                        print(f"     rdx str: '{_s}'")
                except Exception:
                    pass
            return
        # stub body is a single C3 (ret). Set RAX, let CPU execute ret.
        result = handle_api(name)
        if result is not None:
            uc.reg_write(UC_X86_REG_RAX, result & 0xFFFFFFFFFFFFFFFF)

    def on_unmapped(uc, access, address, size, value, _user):
        pg = align_down(address)
        try:
            uc.mem_map(pg, 0x1000, UC_PROT_ALL)
            uc.mem_write(pg, b"\x00" * 0x1000)
        except UcError:
            pass
        if access in (UC_MEM_FETCH_UNMAPPED, UC_MEM_FETCH_PROT):
            # runaway RIP into low / nonsense space — stop, don't map forever
            if address < 0x100000 or (0x100000 <= address < 0x700000000000 and address < IMG_BASE):
                print(f"  [FETCH-RUNAWAY] rip-ish fetch @ {address:#x} — stopping")
                calls_log.append(f"runaway@{address:#x}")
                print("  regs: rax=%x rcx=%x rdx=%x r8=%x r9=%x rsp=%x rbx=%x" % (
                    uc.reg_read(UC_X86_REG_RAX), uc.reg_read(UC_X86_REG_RCX),
                    uc.reg_read(UC_X86_REG_RDX), uc.reg_read(UC_X86_REG_R8),
                    uc.reg_read(UC_X86_REG_R9), uc.reg_read(UC_X86_REG_RSP),
                    uc.reg_read(UC_X86_REG_RBX)))
                print("  trace (last 100):")
                low_start = None
                try:
                    _cd_hist = []
                    for _a, _sz in trace_hist:
                        _cd_hist.append(f"{_a:#x}")
                    # achar a transicao normal->baixo
                    joined = " -> ".join(_cd_hist)
                    print("   " + joined[-2000:])
                    print(f"  hist={len(_cd_hist)} low_start={low_start}")
                    print("  first5:", _cd_hist[:5])
                    print("  last5:", _cd_hist[-5:])
                    # transicao exata: ultimo endereco normal antes do low walk
                    for idx, _a in enumerate(_cd_hist):
                        try:
                            _v = int(_a, 16)
                        except ValueError:
                            continue
                        if _v < 0x100000:
                            low_start = idx
                            break
                    print(f"  hist={len(_cd_hist)} low_start={low_start}")
                    if low_start is not None and low_start > 0:
                        print("  TRANSICAO:")
                        for _a in _cd_hist[max(0, low_start - 10):low_start + 3]:
                            print(f"    {_a}")
                    else:
                        print("  TRANSICAO(baixa):", _cd_hist[max(0, (low_start or 1) - 10):(low_start or 1) + 3])
                except Exception as _e:
                    print(f"   trace fail {_e}")
                if xfer_hist:
                    print("  transfers (last 30):")
                    for _a, _m, _op, _sz in xfer_hist[-30:]:
                        print(f"    {_a:#x}: {_m} {_op}")
                try:
                    uc.emu_stop()
                except Exception:
                    pass
                return False
            name = live_to_name.get(address)
            if not name:
                for live, nm in live_to_name.items():
                    if abs(live - address) < 0x200:
                        name = nm
                        break
            if name:
                stub = stub_by_name[name]
                tramp = b"\x48\xB8" + struct.pack("<Q", stub) + b"\xFF\xE0"
                try:
                    uc.mem_write(address, tramp)
                except UcError:
                    uc.mem_write(address, b"\xC3")
                print(f"  [FETCH→STUB] {name} @ {address:#x}")
            else:
                try:
                    uc.mem_write(address, b"\xC3")
                except UcError:
                    pass
                uc.reg_write(UC_X86_REG_RAX, 1)  # non-null — avoid garbage null-pointer calls
                calls_log.append(f"sys@{address:#x}")
                print(f"  [FETCH-STUB] sys@{address:#x}")
        return True
    def on_intr(uc, intno, _user):
        rip = uc.reg_read(UC_X86_REG_RIP)
        if intno == 3 and 0x7FFC00000000 <= rip < 0x7FFE00000000:
            # INT3 within a system region: route DIRECTLY to the API stub.
            best = None
            for live in sorted(live_to_name):
                if live <= rip < live + 0x1000:
                    best = live
                    break
            if best is None:
                for live in sorted(live_to_name):
                    if live <= rip:
                        best = live
            if best is not None and best in live_to_name:
                nm = live_to_name[best]
                print(f"  [INTR→API] {nm} @ {rip:#x} (nearest {best:#x})")
                result = handle_api(nm)
                if result is not None:
                    uc.reg_write(UC_X86_REG_RAX, result & 0xFFFFFFFFFFFFFFFF)
                # pop return address and continue at caller — the caller did `call`
                try:
                    rsp = uc.reg_read(UC_X86_REG_RSP)
                    ret = struct.unpack("<Q", bytes(uc.mem_read(rsp, 8)))[0]
                    uc.reg_write(UC_X86_REG_RSP, rsp + 8)
                    uc.reg_write(UC_X86_REG_RIP, ret)
                except UcError:
                    uc.reg_write(UC_X86_REG_RIP, rip + 1)
                return True
        print(f"  [INTR] intno={intno} rip={rip:#x} — skip 1 insn")
        uc.reg_write(UC_X86_REG_RIP, rip + 1)
        return True

    mu.hook_add(UC_HOOK_CODE, on_code)
    mu.hook_add(
        UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED | UC_HOOK_MEM_FETCH_PROT,
        on_unmapped,
    )
    try:
        from unicorn import UC_HOOK_INTR
        mu.hook_add(UC_HOOK_INTR, on_intr)
    except Exception:
        pass
    # ---- entry state ----
    rsp = STACK_BASE + STACK_SIZE - 0x1000
    # start at the validate setup (0x74713) — skips CRT static-init bootstrap.
    # main frame: lea rbp, [rsp-0x1f0]; sub rsp, 0x2f0
    ENTRY = IMG_BASE + 0x4713
    rbp_val = rsp - 0x1F0
    mu.reg_write(UC_X86_REG_RSP, rsp)
    mu.reg_write(UC_X86_REG_RBP, rbp_val)
    mu.reg_write(UC_X86_REG_R12, 0)
    mu.reg_write(UC_X86_REG_RSI, 0)
    mu.reg_write(UC_X86_REG_R14, 0)
    # locals cleared by the setup block itself; seed a few as defense
    for off in (0x58, 0x78, 0x70, 0x40, 0x50, 0x60):
        try:
            mu.mem_write(rsp + off, b"\x00" * 8)
        except UcError:
            pass
    try:
        mu.mem_write(rbp_val + 0x240, b"\x00" * 8)
        mu.mem_write(rbp_val + 0x248, b"\x00" * 8)
    except UcError:
        pass
    mu.reg_write(UC_X86_REG_RIP, ENTRY)

    # main's epilogue: add rsp,0x2f0; pop r15..rbp; ret
    #   the ret pops [entry_rsp + 0x328] — seed a valid return so the
    #   completed main returns cleanly instead of crashing to 0x0.
    main_ret_stub = add_stub("main_ret")
    try:
        mu.mem_write(rsp + 0x328, struct.pack("<Q", main_ret_stub))
    except UcError:
        pass

    print(f"=== emulate ENTRY {ENTRY:#x} (skip CRT prologue) validate={VALIDATE_FN:#x} inject={INJECT_FN:#x} ===")
    err = None
    try:
        mu.emu_start(ENTRY, 0xDEADBEEFDEADBEEF, count=50_000_000, timeout=60_000_000)  # 60s
    except UcError as e:
        err = str(e)
        print(f"ERRO unicorn: {e} @ rip={mu.reg_read(UC_X86_REG_RIP):#x}")
        traceback.print_exc()

    rip = mu.reg_read(UC_X86_REG_RIP)
    print(f"\nemulation stopped rip={rip:#x}")
    print(f"API calls: {len(calls_log)}")
    for name, c in Counter(calls_log).most_common(40):
        print(f"  {name} x{c}")
    print(f"\nINJECT-SURFACE hits: {len(inject_hits)}")
    for h in inject_hits[:40]:
        print(f"  {h}")

    # milestone coverage
    print("\nmilestones:")
    print(f"  VALIDATE executed: {rip_hits.get(VALIDATE_FN, 0)}")
    print(f"  INJECT executed:   {rip_hits.get(INJECT_FN, 0)}")

    out_dir = ROOT / "output" / "emu_injector"
    out_dir.mkdir(parents=True, exist_ok=True)
    # re-dump tracked heap buffers post-run (catch decrypt-in-place)
    heap_dumps = []
    for d in getattr(heap, "_dumps", []) or []:
        try:
            ptr = int(d["ptr"], 16)
            sz = int(d["size"], 16)
            blob = bytes(mu.mem_read(ptr, min(sz, 0x20000)))
            path = out_dir / f"heap_final_{ptr:#x}_sz{sz:#x}.bin"
            path.write_bytes(blob)
            nz = sum(1 for b in blob if b)
            heap_dumps.append({
                "ptr": d["ptr"], "size": d["size"], "path": str(path),
                "nonzero": nz, "sha256_16": __import__("hashlib").sha256(blob).hexdigest()[:16],
            })
            print(f"  [DUMP-FINAL] {path.name} nonzero={nz}/{len(blob)}")
        except Exception as e:
            print(f"  [DUMP-FINAL] fail {d}: {e}")
    report = {
        "main": hex(MAIN),
        "validate_fn": hex(VALIDATE_FN),
        "inject_fn": hex(INJECT_FN),
        "stopped_rip": hex(rip),
        "error": err,
        "iat_rewritten": rewritten,
        "api_counts": Counter(calls_log).most_common(),
        "inject_hits": inject_hits,
        "validate_hits": rip_hits.get(VALIDATE_FN, 0),
        "inject_fn_hits": rip_hits.get(INJECT_FN, 0),
        "technique_guess": _guess_technique(inject_hits),
        "heap_dumps": heap_dumps,
        "validate_natural": any("NATURAL SUCCESS" in x for x in [] ),  # filled below via log scan
    }
    (out_dir / "EMU_REPORT.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    lines = [
        "# Injector Unicorn emu report",
        "",
        f"- stopped rip: `{hex(rip)}`",
        f"- error: `{err}`",
        f"- VALIDATE hits: **{rip_hits.get(VALIDATE_FN, 0)}**",
        f"- INJECT fn hits: **{rip_hits.get(INJECT_FN, 0)}**",
        f"- technique guess: **{report['technique_guess']}**",
        "",
        "## Inject-surface API order",
        "",
    ]
    for h in inject_hits:
        lines.append(f"- `{h['api']}` rcx={h['rcx']} rdx={h['rdx']} r8={h['r8']}")
    lines += ["", "## Top APIs", ""]
    for name, c in Counter(calls_log).most_common(30):
        lines.append(f"- `{name}` × {c}")
    (out_dir / "EMU_REPORT.md").write_text("\n".join(lines), encoding="utf-8")
    print(f"\nwrote {out_dir / 'EMU_REPORT.md'}")

    # ---- coverage: quais enderecos do injector executaram (range da imagem) ----
    img_hits = [(a, c) for a, c in rip_hits.items() if IMG_BASE <= a < IMG_BASE + 0x800000]
    if img_hits:
        img_hits.sort()
        print(f"\ncoverage: {len(img_hits)} enderecos distintos no range da imagem")
        pages = {}
        for a, c in img_hits:
            pg = (a // 0x1000) * 0x1000
            pages.setdefault(pg, []).append((a, c))
        for pg in sorted(pages):
            addrs = pages[pg]
            lo, hi = addrs[0][0], addrs[-1][0]
            total = sum(c for _, c in addrs)
            print(f"  page {pg:#x}: {len(addrs)} addrs ({lo:#x}..{hi:#x}) hits={total}")
    return 0


def _guess_technique(hits: list) -> str:
    names = [h["api"] for h in hits]
    if any(n.startswith("QueueUserAPC") or "Apc" in n or "APC" in n for n in names):
        return "APC (QueueUserAPC / NtQueueApcThread)"
    if any(n in ("NtCreateThreadEx", "RtlCreateUserThread") for n in names):
        return "NtCreateThreadEx / RtlCreateUserThread"
    if any(n.startswith("CreateRemoteThread") for n in names):
        return "CreateRemoteThread"
    if any(n in ("NtMapViewOfSection", "NtCreateSection") for n in names):
        return "section map (manual-map / NtMapViewOfSection)"
    if any(n in ("WriteProcessMemory", "NtWriteVirtualMemory") for n in names) and any(
        n in ("VirtualAllocEx", "NtAllocateVirtualMemory") for n in names
    ):
        return "classic write+alloc (thread start unresolved yet)"
    if not names:
        return "unknown — inject surface not reached"
    return "partial — saw: " + ", ".join(dict.fromkeys(names))


if __name__ == "__main__":
    raise SystemExit(main())
