# language: Python 3, file: syscall_trace.py
# ntdll stub trace plan + static syscall number harvest (per Windows build)
from __future__ import annotations

import json
import re
import struct
from pathlib import Path
from typing import Any


def harvest_ntdll_syscalls(ntdll_path: str | Path | None = None) -> dict[str, Any]:
    """
    Parse ntdll exports' stubs for `mov eax, imm32; syscall` patterns.
    Numbers are **per OS build** — re-run on target machine, never hardcode forever.
    """
    path = Path(ntdll_path or r"C:\Windows\System32\ntdll.dll")
    if not path.is_file():
        return {"ok": False, "error": f"missing {path}"}
    data = path.read_bytes()
    # find export names via pefile if available
    mapping: dict[str, int] = {}
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
            return {"ok": False, "error": "no_exports"}
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if not exp.name:
                continue
            name = exp.name.decode("ascii", "ignore")
            if not (name.startswith("Nt") or name.startswith("Zw")):
                continue
            rva = exp.address
            off = pe.get_offset_from_rva(rva)
            if off is None or off + 16 > len(data):
                continue
            stub = data[off : off + 16]
            # x64: 4C 8B D1 B8 xx xx xx xx  (mov r10,rcx; mov eax,imm)
            if len(stub) >= 8 and stub[0:3] == b"\x4c\x8b\xd1" and stub[3] == 0xB8:
                ssn = struct.unpack_from("<I", stub, 4)[0]
                mapping[name] = ssn
            # alternate: B8 imm only
            elif stub[0] == 0xB8:
                ssn = struct.unpack_from("<I", stub, 1)[0]
                mapping[name] = ssn
    except ImportError:
        # fallback: scan for B8 imm near Nt strings — weaker
        for m in re.finditer(rb"Nt[A-Z][A-Za-z0-9]{3,40}\x00", data):
            name = m.group()[:-1].decode("ascii", "ignore")
            mapping.setdefault(name, -1)
        return {
            "ok": True,
            "partial": True,
            "note": "install pefile for SSN extraction",
            "names_seen": len(mapping),
            "sample": sorted(mapping)[:40],
        }
    except Exception as e:
        return {"ok": False, "error": str(e)}

    interesting = {
        k: v
        for k, v in mapping.items()
        if any(
            x in k
            for x in (
                "AllocateVirtualMemory",
                "ProtectVirtualMemory",
                "WriteVirtualMemory",
                "ReadVirtualMemory",
                "CreateThread",
                "MapViewOfSection",
                "QueryInformationProcess",
                "SetInformationThread",
                "Close",
                "OpenProcess",
            )
        )
    }
    return {
        "ok": True,
        "ntdll": str(path),
        "syscall_count": len(mapping),
        "interesting": interesting,
        "sample": dict(list(sorted(mapping.items()))[:30]),
        "trace_plan": [
            "Hook ntdll!Nt* via Frida (user-mode) — captures even if app uses direct syscall if stub still called",
            "For direct syscall (mov eax/ssn; syscall): instrument with hardware BP on syscall gadget or use Hypervisor",
            "Log args: ProcessHandle, BaseAddress, RegionSize, Protect for memory ops",
            "Re-harvest SSNs after every Windows patch Tuesday",
        ],
    }


def frida_syscall_script(ssns: dict[str, int] | None = None) -> str:
    targets = list((ssns or {}).keys()) or [
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
        "NtQueryInformationProcess",
    ]
    lines = ["// Street-decrepytor ntdll syscall stub trace", "const names = " + json.dumps(targets) + ";"]
    lines.append(
        """
for (const n of names) {
  const addr = Module.findExportByName('ntdll.dll', n);
  if (!addr) { console.log('[miss]', n); continue; }
  Interceptor.attach(addr, {
    onEnter(args) {
      console.log('[nt]', n, args[0], args[1], args[2], args[3], args[4]);
    },
    onLeave(retval) { console.log('[nt-ret]', n, retval); }
  });
  console.log('[hook-nt]', n, addr);
}
"""
    )
    return "\n".join(lines)
