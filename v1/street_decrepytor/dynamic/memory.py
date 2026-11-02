# language: Python 3, file: memory.py
# Live process memory scan / dump helpers — Windows
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from street_decrepytor.core.artifact import ArtifactProfile


def list_processes() -> list[dict[str, Any]]:
    if sys.platform != "win32":
        return []
    try:
        import ctypes
        from ctypes import wintypes

        TH32CS_SNAPPROCESS = 0x2

        class PROCESSENTRY32W(ctypes.Structure):
            _fields_ = [
                ("dwSize", wintypes.DWORD),
                ("cntUsage", wintypes.DWORD),
                ("th32ProcessID", wintypes.DWORD),
                ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
                ("th32ModuleID", wintypes.DWORD),
                ("cntThreads", wintypes.DWORD),
                ("th32ParentProcessID", wintypes.DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", wintypes.DWORD),
                ("szExeFile", wintypes.WCHAR * 260),
            ]

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        out = []
        if k32.Process32FirstW(snap, ctypes.byref(pe)):
            while True:
                out.append({"pid": pe.th32ProcessID, "name": pe.szExeFile})
                if not k32.Process32NextW(snap, ctypes.byref(pe)):
                    break
        k32.CloseHandle(snap)
        return out
    except Exception:
        return []


def scan_process_memory(pid: int, needles: list[bytes], max_regions: int = 400) -> dict[str, Any]:
    """Scan readable committed regions for needle bytes. Flags hits for dump."""
    if sys.platform != "win32":
        return {"ok": False, "error": "windows_only"}
    try:
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        PROCESS_VM_READ = 0x0010
        PROCESS_QUERY_INFORMATION = 0x0400
        MEM_COMMIT = 0x1000
        PAGE_NOACCESS = 0x01
        PAGE_GUARD = 0x100

        class MEMORY_BASIC_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wintypes.DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", wintypes.DWORD),
                ("Protect", wintypes.DWORD),
                ("Type", wintypes.DWORD),
            ]

        handle = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            return {"ok": False, "error": f"OpenProcess {ctypes.get_last_error()}"}

        mbi = MEMORY_BASIC_INFORMATION()
        address = 0
        hits = []
        regions = 0
        while regions < max_regions:
            got = k32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
            if not got:
                break
            base = mbi.BaseAddress or 0
            size = mbi.RegionSize or 0
            prot = mbi.Protect or 0
            if mbi.State == MEM_COMMIT and not (prot & PAGE_NOACCESS) and not (prot & PAGE_GUARD) and 0 < size <= 32 << 20:
                buf = (ctypes.c_char * size)()
                read = ctypes.c_size_t()
                if k32.ReadProcessMemory(handle, ctypes.c_void_p(base), buf, size, ctypes.byref(read)) and read.value:
                    blob = bytes(buf[: read.value])
                    for n in needles:
                        idx = blob.find(n)
                        if idx >= 0:
                            hits.append({
                                "needle": n[:40].hex(),
                                "addr": hex(base + idx),
                                "region_base": hex(base),
                                "region_size": size,
                            })
                regions += 1
            nxt = base + size
            if nxt <= address:
                break
            address = nxt

        k32.CloseHandle(handle)
        return {"ok": True, "pid": pid, "regions_scanned": regions, "hits": hits[:100]}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def dump_region(pid: int, address: int, size: int, out_path: Path) -> dict[str, Any]:
    if sys.platform != "win32":
        return {"ok": False, "error": "windows_only"}
    try:
        import ctypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        handle = k32.OpenProcess(0x0010 | 0x0400, False, pid)
        if not handle:
            return {"ok": False, "error": "OpenProcess failed"}
        buf = (ctypes.c_char * size)()
        read = ctypes.c_size_t()
        ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(address), buf, size, ctypes.byref(read))
        k32.CloseHandle(handle)
        if not ok:
            return {"ok": False, "error": f"RPM {ctypes.get_last_error()}"}
        out_path.write_bytes(bytes(buf[: read.value]))
        return {"ok": True, "path": str(out_path), "bytes": read.value}
    except Exception as e:
        return {"ok": False, "error": str(e)}


def stage_process_scan(profile: ArtifactProfile, out_dir: Path) -> dict[str, Any]:
    """
    Static stage default: does not attach unless STREET_ATTACH_PID set.
    Emits process list match by image name for operator/AI agent follow-up.
    """
    import os

    procs = list_processes()
    stem = Path(profile.path).stem.lower()
    matches = [p for p in procs if stem in p["name"].lower()]
    report: dict[str, Any] = {
        "process_matches": matches[:20],
        "total_processes": len(procs),
        "attach": None,
    }
    pid_env = os.environ.get("STREET_ATTACH_PID")
    if pid_env:
        pid = int(pid_env)
        needles = [
            b"MZ",
            b"This program",
            Path(profile.path).stem.encode("ascii", "ignore"),
        ]
        report["attach"] = scan_process_memory(pid, needles)
    (out_dir / "process_scan.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
