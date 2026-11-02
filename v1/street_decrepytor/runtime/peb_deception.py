# language: Python 3, file: runtime/peb_deception.py
# R3 — PEB Deception Detection: dual-read API vs raw RPM
from __future__ import annotations

import ctypes
import struct  # PEB field unpack
from typing import Any

from street_decrepytor.runtime.common import Finding, clamp01, open_process, read_process_memory


ProcessBasicInformation = 0
ProcessDebugPort = 7
ProcessDebugObjectHandle = 30
ProcessDebugFlags = 31


def _nt_query_debug_port(pid: int) -> dict[str, Any]:
    """API-path (potentially hooked) debug-related queries."""
    ntdll = ctypes.WinDLL("ntdll")
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    PROCESS_QUERY_INFORMATION = 0x0400
    PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
    h = k32.OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | 0x0010, False, pid)
    if not h:
        return {"error": f"OpenProcess {ctypes.get_last_error()}"}

    class PROCESS_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("Reserved1", ctypes.c_void_p),
            ("PebBaseAddress", ctypes.c_void_p),
            ("Reserved2", ctypes.c_void_p * 2),
            ("UniqueProcessId", ctypes.c_void_p),
            ("Reserved3", ctypes.c_void_p),
        ]

    pbi = PROCESS_BASIC_INFORMATION()
    ret_len = ctypes.c_ulong()
    st = ntdll.NtQueryInformationProcess(h, ProcessBasicInformation, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret_len))

    debug_port = ctypes.c_ulonglong(0)
    st2 = ntdll.NtQueryInformationProcess(h, ProcessDebugPort, ctypes.byref(debug_port), ctypes.sizeof(debug_port), ctypes.byref(ret_len))

    debug_flags = ctypes.c_ulong(0)
    st3 = ntdll.NtQueryInformationProcess(h, ProcessDebugFlags, ctypes.byref(debug_flags), ctypes.sizeof(debug_flags), ctypes.byref(ret_len))

    out = {
        "NtQueryInformationProcess_PBI_status": st,
        "peb_api": hex(pbi.PebBaseAddress) if pbi.PebBaseAddress else None,
        "debug_port": int(debug_port.value),
        "debug_port_status": st2,
        "debug_flags": int(debug_flags.value),  # 0 often means debugger present when queried this way inverted — document carefully
        "debug_flags_status": st3,
        "note": "ProcessDebugFlags: 0 typically indicates debugger present (NoDebugInherit cleared)",
    }
    k32.CloseHandle(h)
    return out


def _raw_peb(pid: int, peb_addr: int | None = None) -> dict[str, Any]:
    """Raw RPM of PEB fields. If peb_addr None, obtain via NtQIP PBI then read."""
    handle, k32 = open_process(pid, access=0x0410)
    try:
        if peb_addr is None:
            ntdll = ctypes.WinDLL("ntdll")

            class PROCESS_BASIC_INFORMATION(ctypes.Structure):
                _fields_ = [
                    ("Reserved1", ctypes.c_void_p),
                    ("PebBaseAddress", ctypes.c_void_p),
                    ("Reserved2", ctypes.c_void_p * 2),
                    ("UniqueProcessId", ctypes.c_void_p),
                    ("Reserved3", ctypes.c_void_p),
                ]

            pbi = PROCESS_BASIC_INFORMATION()
            ret_len = ctypes.c_ulong()
            st = ntdll.NtQueryInformationProcess(
                handle, ProcessBasicInformation, ctypes.byref(pbi), ctypes.sizeof(pbi), ctypes.byref(ret_len)
            )
            if st != 0 or not pbi.PebBaseAddress:
                return {"error": f"PBI status={st}"}
            peb_addr = int(pbi.PebBaseAddress)

        # x64 PEB layout (stable enough for these fields):
        # +0x02 BeingDebugged (UCHAR)
        # +0xBC NtGlobalFlag (ULONG) on Win10 x64 — actually NtGlobalFlag is at 0xBC
        peb = read_process_memory(handle, k32, peb_addr, 0x400)
        being = peb[0x02]
        # NtGlobalFlag offset x64 Win10+: 0xBC
        nt_global = struct.unpack_from("<I", peb, 0xBC)[0]
        # ProcessHeap pointer at 0x30 x64
        heap = struct.unpack_from("<Q", peb, 0x30)[0]
        heap_flags = heap_force = None
        if heap:
            try:
                # HEAP.Flags at +0x70 on modern x64; ForceFlags at +0x74
                hb = read_process_memory(handle, k32, heap, 0x80)
                heap_flags = struct.unpack_from("<I", hb, 0x70)[0]
                heap_force = struct.unpack_from("<I", hb, 0x74)[0]
            except OSError:
                pass
        return {
            "peb_raw": hex(peb_addr),
            "BeingDebugged": being,
            "NtGlobalFlag": nt_global,
            "ProcessHeap": hex(heap) if heap else None,
            "HeapFlags": heap_flags,
            "HeapForceFlags": heap_force,
        }
    finally:
        k32.CloseHandle(handle)


def probe_peb(pid: int) -> dict[str, Any]:
    findings: list[Finding] = []
    api = _nt_query_debug_port(pid)
    raw = _raw_peb(pid)

    deception = False
    details = []

    # Debug port non-zero via API while BeingDebugged raw is 0 → possible hide
    if "error" not in api and "error" not in raw:
        if api.get("debug_port", 0) != 0 and raw.get("BeingDebugged", 0) == 0:
            deception = True
            details.append("DebugPort!=0 via API but BeingDebugged raw==0")
        if raw.get("BeingDebugged", 0) != 0 and api.get("debug_port", 0) == 0:
            deception = True
            details.append("BeingDebugged raw set but DebugPort API reports 0")
        # NtGlobalFlag debug heap bits: 0x70 = FLG_HEAP_ENABLE_TAIL_CHECK|FREE_CHECK|VALIDATE_PARAMETERS often set under debugger
        ng = raw.get("NtGlobalFlag") or 0
        if ng & 0x70 and api.get("debug_port", 0) == 0 and raw.get("BeingDebugged", 0) == 0:
            details.append(f"NtGlobalFlag heap-debug bits set ({hex(ng)}) while BeingDebugged clear — possible partial scrub")
            # soft signal
            findings.append(
                Finding(
                    pillar="R3",
                    flag="peb_partial_scrub_suspected",
                    score=0.35,
                    confidence=0.4,
                    detail=details[-1],
                    limits=["Heap flags also set by app verifiers / some loaders"],
                )
            )
        hf = raw.get("HeapFlags")
        if hf is not None and (hf & 0x50000062) and raw.get("BeingDebugged", 0) == 0:
            findings.append(
                Finding(
                    pillar="R3",
                    flag="heap_flags_debugish",
                    score=0.25,
                    confidence=0.35,
                    detail=f"ProcessHeap.Flags={hex(hf)} with BeingDebugged=0",
                    limits=["Not definitive anti-debug evidence"],
                )
            )

    if deception:
        findings.append(
            Finding(
                pillar="R3",
                flag="peb_api_vs_raw_mismatch",
                score=0.7,
                confidence=0.65,
                detail="; ".join(details) if details else "API/raw PEB disagreement",
                limits=[
                    "Adversary may hook RPM or rewrite PEB per-caller in kernel",
                    "HW breakpoints on PEB can hide from dual-read",
                ],
            )
        )
    elif "error" not in raw and "error" not in api:
        findings.append(
            Finding(
                pillar="R3",
                flag="peb_dual_read_consistent",
                score=0.0,
                confidence=0.5,
                detail="No clear API-vs-raw PEB deception on sampled fields",
                limits=[
                    "Clean PEB is NEVER proof of absence of anti-debug",
                    "Timing/CPUID/hypervisor checks are out of scope for R3",
                ],
            )
        )
    else:
        findings.append(
            Finding(
                pillar="R3",
                flag="peb_probe_incomplete",
                score=0.1,
                confidence=0.3,
                detail=f"api={api.get('error')} raw={raw.get('error')}",
                limits=["Insufficient rights or process exited"],
            )
        )

    return {
        "pillar": "R3",
        "ok": True,
        "pid": pid,
        "api_path": api,
        "raw_path": raw,
        "findings": [f.to_dict() for f in findings],
        "score": max((f.score for f in findings), default=0.0),
        "confidence": min((f.confidence for f in findings), default=0.5),
        "limits": [
            "Clean dual-read ≠ no anti-debug",
            "Kernel/HWBP PEB games not covered",
            "Sandbox evasion extends beyond PEB flags",
        ],
        "disclaimer": "A consistent PEB must never be interpreted as definitive proof that anti-debug is absent.",
    }
