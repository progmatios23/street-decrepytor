# language: Python 3, file: antidebug.py
# Anti-anti-debug plan generation + optional PEB patch helpers (Windows)
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from street_decrepytor.core.artifact import ArtifactProfile

# Maps detection → neutralization (ScyllaHide-class). What it defeats / what still catches.
NEUTRALIZATIONS = [
    {
        "detect": "PEB.BeingDebugged",
        "neutralize": "set PEB.BeingDebugged = 0 in target",
        "defeats": "IsDebuggerPresent / direct PEB read",
        "caught_by": "kernel debugger checks, direct NtQuery SystemKernelDebugger",
    },
    {
        "detect": "NtGlobalFlag (PEB)",
        "neutralize": "clear FLG_HEAP_* debug flags on PEB.NtGlobalFlag",
        "defeats": "heap flag heuristics",
        "caught_by": "cross-check with NtQueryInformationProcess",
    },
    {
        "detect": "NtQueryInformationProcess(ProcessDebugPort/Object/Flags)",
        "neutralize": "hook/filter return to zero",
        "defeats": "user-mode QIP checks",
        "caught_by": "direct syscall with spoofed stubs, HVCI path",
    },
    {
        "detect": "HW breakpoints (Dr0-Dr7)",
        "neutralize": "clear DRx on CONTEXT / hide from GetThreadContext",
        "defeats": "HWBP probes",
        "caught_by": "instrumentation callbacks",
    },
    {
        "detect": "RDTSC timing",
        "neutralize": "scale TSC delta or avoid single-step over checks",
        "defeats": "naive timing loops",
        "caught_by": "multi-counter correlation (QPC + TSC + thread time)",
    },
    {
        "detect": "int 2d / icebp",
        "neutralize": "exception filter swallow",
        "defeats": "old Olly-style checks",
        "caught_by": "veh chain integrity",
    },
]


def stage_antidebug_plan(profile: ArtifactProfile, out_dir: Path) -> dict[str, Any]:
    path = Path(profile.path)
    data = path.read_bytes()[: 8 << 20]
    findings = []
    checks = [
        (b"IsDebuggerPresent", "api_IsDebuggerPresent"),
        (b"CheckRemoteDebuggerPresent", "api_CheckRemoteDebuggerPresent"),
        (b"NtQueryInformationProcess", "api_NtQueryInformationProcess"),
        (b"OutputDebugString", "api_OutputDebugString"),
        (b"QueryPerformanceCounter", "api_QPC"),
        (b"GetTickCount", "api_GetTickCount"),
    ]
    for needle, tag in checks:
        if needle in data:
            findings.append(tag)
    # PEB access pattern x64: 65 48 8B 04 25 60 00 00 00 = mov rax, gs:[0x60]
    if b"\x65\x48\x8b\x04\x25\x60\x00\x00\x00" in data or b"\x65\x48\x8b\x0c\x25\x60\x00\x00\x00" in data:
        findings.append("peb_gs60_direct")

    report = {
        "static_hits": findings,
        "neutralizations": NEUTRALIZATIONS,
        "recommended_order": [n["detect"] for n in NEUTRALIZATIONS],
        "interop": ["ScyllaHide", "Themidie", "x64dbg TitanHide", "Street dynamic PEB patch"],
    }
    (out_dir / "antidebug_plan.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report


def patch_peb_being_debugged(pid: int) -> dict[str, Any]:
    """
    Best-effort PEB.BeingDebugged clear via Read/WriteProcessMemory.
    *Requires same-bitness privileges; fails closed if APIs unavailable.*
    """
    if sys.platform != "win32":
        return {"ok": False, "error": "windows_only"}
    try:
        import ctypes
        from ctypes import wintypes

        PROCESS_ALL = 0x1F0FFF
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        ntdll = ctypes.WinDLL("ntdll", use_last_error=True)

        class PROCESS_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("Reserved1", ctypes.c_void_p),
                ("PebBaseAddress", ctypes.c_void_p),
                ("Reserved2", ctypes.c_void_p * 2),
                ("UniqueProcessId", ctypes.POINTER(ctypes.c_ulong)),
                ("Reserved3", ctypes.c_void_p),
            ]

        handle = k32.OpenProcess(PROCESS_ALL, False, pid)
        if not handle:
            return {"ok": False, "error": f"OpenProcess failed {ctypes.get_last_error()}"}

        pbi = PROCESS_BASIC_INFORMATION()
        ret_len = ctypes.c_ulong()
        status = ntdll.NtQueryInformationProcess(handle, 0, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret_len))
        if status != 0:
            k32.CloseHandle(handle)
            return {"ok": False, "error": f"NtQIP status={status}"}

        peb = pbi.PebBaseAddress
        # BeingDebugged at PEB+0x02
        flag = ctypes.c_ubyte(0)
        written = ctypes.c_size_t()
        ok = k32.WriteProcessMemory(handle, ctypes.c_void_p(peb + 2), ctypes.byref(flag), 1, ctypes.byref(written))
        # x64 PEB.NtGlobalFlag @ 0xBC — clear heap-debug bits Themida often reads
        ng = ctypes.c_ulong(0)
        w2 = ctypes.c_size_t()
        ok2 = k32.WriteProcessMemory(handle, ctypes.c_void_p(peb + 0xBC), ctypes.byref(ng), 4, ctypes.byref(w2))
        k32.CloseHandle(handle)
        return {
            "ok": bool(ok),
            "peb": hex(peb) if peb else None,
            "pid": pid,
            "being_debugged_cleared": bool(ok),
            "ntglobalflag_cleared": bool(ok2),
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}
