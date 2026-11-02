# language: Python 3, file: runtime/common.py
# Shared Windows helpers + probabilistic finding type
from __future__ import annotations

import ctypes
import hashlib
import struct
import sys
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


CRITICAL_STUBS = [
    "NtQueryInformationProcess",
    "NtSetInformationThread",
    "NtReadVirtualMemory",
    "NtWriteVirtualMemory",
    "NtClose",
    "NtOpenProcess",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "NtCreateThreadEx",
    "NtGetContextThread",
    "NtSetContextThread",
    "NtQuerySystemInformation",
]


@dataclass
class Finding:
    pillar: str
    flag: str
    score: float  # 0..1 contribution toward "suspicious"
    confidence: float  # 0..1 certainty of this observation
    detail: str
    limits: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def windows_build() -> dict[str, Any]:
    class RTL_OSVERSIONINFOW(ctypes.Structure):
        _fields_ = [
            ("dwOSVersionInfoSize", ctypes.c_ulong),
            ("dwMajorVersion", ctypes.c_ulong),
            ("dwMinorVersion", ctypes.c_ulong),
            ("dwBuildNumber", ctypes.c_ulong),
            ("dwPlatformId", ctypes.c_ulong),
            ("szCSDVersion", ctypes.c_wchar * 128),
        ]

    info = RTL_OSVERSIONINFOW()
    info.dwOSVersionInfoSize = ctypes.sizeof(info)
    status = ctypes.WinDLL("ntdll").RtlGetVersion(ctypes.byref(info))
    return {
        "status": status,
        "major": info.dwMajorVersion,
        "minor": info.dwMinorVersion,
        "build": info.dwBuildNumber,
        "key": f"{info.dwMajorVersion}.{info.dwMinorVersion}.{info.dwBuildNumber}",
    }


def ntdll_path() -> Path:
    import os

    p = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "ntdll.dll"
    if p.is_file():
        return p
    return Path(r"C:\Windows\System32\ntdll.dll")


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def open_process(pid: int, access: int = 0x0410):
    """PROCESS_QUERY_INFORMATION | PROCESS_VM_READ default."""
    if sys.platform != "win32":
        raise RuntimeError("windows_only")
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    h = k32.OpenProcess(access, False, pid)
    if not h:
        raise OSError(f"OpenProcess failed err={ctypes.get_last_error()}")
    return h, k32


def read_process_memory(handle, k32, address: int, size: int) -> bytes:
    buf = (ctypes.c_char * size)()
    read = ctypes.c_size_t()
    ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(address), buf, size, ctypes.byref(read))
    if not ok:
        raise OSError(f"ReadProcessMemory failed err={ctypes.get_last_error()} @ {hex(address)}")
    return bytes(buf[: read.value])


def module_base_in_process(pid: int, name: str) -> tuple[int, int]:
    """Return (base, size) for module name in pid."""
    from street_decrepytor.dynamic.pe_dump import list_process_modules

    mods = list_process_modules(pid)
    name_l = name.lower()
    for m in mods:
        if m["name"].lower() == name_l:
            return m["base"], m["size"]
    for m in mods:
        if name_l in m["name"].lower():
            return m["base"], m["size"]
    raise LookupError(f"module {name} not in pid {pid}")


def export_rvas_from_pe(pe_path: Path, names: list[str]) -> dict[str, int]:
    """Map export name → RVA from an on-disk PE."""
    import pefile

    pe = pefile.PE(str(pe_path), fast_load=True)
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    out: dict[str, int] = {}
    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
        return out
    want = set(names)
    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
        if not exp.name:
            continue
        n = exp.name.decode("ascii", "ignore")
        if n in want or n.replace("Zw", "Nt") in want:
            # Prefer Nt* over Zw* when both exist
            key = n if n.startswith("Nt") else n.replace("Zw", "Nt")
            if key in want and (key not in out or n.startswith("Nt")):
                out[key] = int(exp.address)
    return out


def classify_stub_patch(live: bytes, disk: bytes) -> str:
    """Heuristic class for stub mutation."""
    if live == disk:
        return "pristine"
    if len(live) < 5:
        return "unknown_short"
    # hotpatch / trampoline styles
    if live[0] in (0xE9, 0xE8):  # jmp/call rel32
        return "rel32_detour"
    if live[0] == 0xFF and live[1] in (0x25, 0x15):  # jmp/call [rip+disp]
        return "indirect_detour"
    if live[0:2] == b"\x48\xB8" or live[0:2] == b"\x48\xB9":  # movabs + later jmp
        return "abs_mov_trampoline"
    if live[0] == 0xEB:
        return "short_jmp"
    if live[0:2] == b"\x90\x90" or live[0] == 0xCC:
        return "nop_or_int3"
    # prefix diverge
    if live[:5] != disk[:5]:
        return "prologue_patch"
    return "modified_unknown"


def clamp01(x: float) -> float:
    return max(0.0, min(1.0, x))
