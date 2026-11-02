# language: Python 3, file: runtime/syscall_observatory.py
# R1 — Syscall Observatory: live ntdll stubs vs disk, hook classification, bounded unwind
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from street_decrepytor.runtime.common import (
    CRITICAL_STUBS,
    Finding,
    classify_stub_patch,
    clamp01,
    export_rvas_from_pe,
    module_base_in_process,
    ntdll_path,
    open_process,
    read_process_memory,
)


def _resolve_rel32(stub_addr: int, live: bytes) -> int | None:
    if len(live) < 5:
        return None
    if live[0] in (0xE9, 0xE8):  # jmp/call rel32
        rel = struct.unpack_from("<i", live, 1)[0]
        return (stub_addr + 5 + rel) & 0xFFFFFFFFFFFFFFFF
    if live[0] == 0xEB:
        rel = struct.unpack_from("<b", live, 1)[0]
        return (stub_addr + 2 + rel) & 0xFFFFFFFFFFFFFFFF
    if live[0:2] == b"\xFF\x25" and len(live) >= 6:  # jmp [rip+disp]
        # can't fully resolve without reading pointer — return None marker
        return None
    return None


def observe_syscalls(
    pid: int,
    *,
    names: list[str] | None = None,
    max_unwind: int = 8,
) -> dict[str, Any]:
    names = names or CRITICAL_STUBS
    pe_path = ntdll_path()
    disk = pe_path.read_bytes()
    rvas = export_rvas_from_pe(pe_path, names)
    base, size = module_base_in_process(pid, "ntdll.dll")
    ntdll_lo, ntdll_hi = base, base + size

    import pefile

    pe = pefile.PE(data=disk, fast_load=True)

    handle, k32 = open_process(pid)
    findings: list[Finding] = []
    stubs_out: dict[str, Any] = {}
    hooked = []

    try:
        for name, rva in rvas.items():
            off = pe.get_offset_from_rva(rva)
            if off is None:
                continue
            disk_stub = disk[off : off + 16]
            addr = base + rva
            try:
                live = read_process_memory(handle, k32, addr, 16)
            except OSError as e:
                stubs_out[name] = {"error": str(e)}
                continue
            klass = classify_stub_patch(live, disk_stub)
            dest = _resolve_rel32(addr, live)
            outside = dest is not None and not (ntdll_lo <= dest < ntdll_hi)
            chain = []
            if dest is not None and outside and max_unwind > 0:
                # bounded: follow up to max_unwind jmp/call stubs
                cur = dest
                seen = set()
                for _ in range(max_unwind):
                    if cur in seen:
                        chain.append({"addr": hex(cur), "note": "cycle"})
                        break
                    seen.add(cur)
                    try:
                        b = read_process_memory(handle, k32, cur, 16)
                    except OSError:
                        chain.append({"addr": hex(cur), "note": "unreadable"})
                        break
                    chain.append({"addr": hex(cur), "bytes": b[:8].hex()})
                    nxt = _resolve_rel32(cur, b)
                    if nxt is None:
                        break
                    if ntdll_lo <= nxt < ntdll_hi:
                        chain.append({"addr": hex(nxt), "note": "back_in_ntdll"})
                        break
                    cur = nxt

            entry = {
                "addr": hex(addr),
                "class": klass,
                "live_hex": live.hex(),
                "disk_hex": disk_stub.hex(),
                "dest": hex(dest) if dest is not None else None,
                "dest_outside_ntdll": outside,
                "chain": chain,
            }
            stubs_out[name] = entry
            if klass != "pristine" or outside:
                hooked.append(name)
    finally:
        k32.CloseHandle(handle)

    if hooked:
        findings.append(
            Finding(
                pillar="R1",
                flag="ntdll_stub_hooks",
                score=clamp01(0.3 + 0.07 * len(hooked)),
                confidence=0.7,
                detail=f"hooked/modified stubs: {hooked}",
                limits=[
                    "Restore-during-scan can miss hooks",
                    "Hypervisor hooks invisible at ring-3",
                    "EDR/AV hooks are common legitimate findings",
                ],
            )
        )
    else:
        findings.append(
            Finding(
                pillar="R1",
                flag="ntdll_stubs_appear_pristine",
                score=0.0,
                confidence=0.55,
                detail="No prologue divergence vs disk ntdll for sampled Nt*",
                limits=["Does not rule out HV or ephemeral restore"],
            )
        )

    outside_count = sum(1 for s in stubs_out.values() if isinstance(s, dict) and s.get("dest_outside_ntdll"))
    if outside_count:
        findings.append(
            Finding(
                pillar="R1",
                flag="hook_destination_outside_ntdll",
                score=0.65,
                confidence=0.65,
                detail=f"{outside_count} stubs jump/call outside ntdll range",
                limits=["Unwind depth capped; intentional loops aborted"],
            )
        )

    return {
        "pillar": "R1",
        "ok": True,
        "pid": pid,
        "ntdll_base": hex(base),
        "disk_ntdll": str(pe_path),
        "stubs": stubs_out,
        "hooked": hooked,
        "findings": [f.to_dict() for f in findings],
        "score": max((f.score for f in findings), default=0.0),
        "confidence": min((f.confidence for f in findings), default=0.5),
        "limits": [
            "Ring-3 only",
            "Ephemeral stub restore between reads",
            "Chain unwind depth-limited",
        ],
    }
