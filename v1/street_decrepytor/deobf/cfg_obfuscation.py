# language: Python 3, file: cfg_obfuscation.py
# Detect / inventory CFG-style trampolines: lea rcx/rax, [rip+disp] ; jmp shared_stub
# Recovers real call targets from the lea displacement (common in protected Luau modules)
from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any


def _u32(x: int) -> int:
    return x & 0xFFFFFFFF


def find_lea_jmp_trampolines(data: bytes, image_base: int, text_va: int, text_roff: int, text_size: int) -> dict[str, Any]:
    """
    Pattern (x64):
      48 8D 0D xx xx xx xx    lea rcx, [rip+disp32]
      E9 xx xx xx xx          jmp rel32
    or lea rax (48 8D 05) then jmp.
    Target of lea = real destination when stub is a CFG/obfuscation dispatcher.
    """
    blob = data[text_roff : text_roff + text_size]
    base = image_base + text_va
    trampolines = []
    dispatchers: dict[int, int] = {}
    i = 0
    n = len(blob)
    while i + 12 <= n:
        # lea r64, [rip+disp32] = 48 8D 0D/05/15/1D ...
        if blob[i] == 0x48 and blob[i + 1] == 0x8D and blob[i + 2] in (0x0D, 0x05, 0x15, 0x1D):
            if blob[i + 7] == 0xE9:
                disp_lea = struct.unpack_from("<i", blob, i + 3)[0]
                lea_addr = base + i
                # RIP for lea is address of next insn = lea_addr+7
                lea_target = (lea_addr + 7 + disp_lea) & 0xFFFFFFFFFFFFFFFF
                disp_jmp = struct.unpack_from("<i", blob, i + 8)[0]
                jmp_addr = lea_addr + 7
                jmp_target = (jmp_addr + 5 + disp_jmp) & 0xFFFFFFFFFFFFFFFF
                trampolines.append({
                    "stub": hex(lea_addr),
                    "lea_target": hex(lea_target),
                    "dispatcher": hex(jmp_target),
                    "reg": {0x0D: "rcx", 0x05: "rax", 0x15: "rdx", 0x1D: "rbx"}[blob[i + 2]],
                })
                dispatchers[jmp_target] = dispatchers.get(jmp_target, 0) + 1
                i += 12
                continue
        i += 1

    top_dispatch = sorted(dispatchers.items(), key=lambda x: -x[1])[:10]
    n = max(1, len(trampolines))
    top_share = (top_dispatch[0][1] / n) if top_dispatch else 0.0
    likely = len(trampolines) >= 50 and (
        len(dispatchers) <= 12 or top_share >= 0.45
    )
    return {
        "trampoline_count": len(trampolines),
        "unique_dispatchers": len(dispatchers),
        "top_dispatchers": [{"addr": hex(a), "hits": c} for a, c in top_dispatch],
        "top_dispatcher_share": round(top_share, 4),
        "cfg_obfuscation_likely": likely,
        "sample": trampolines[:40],
        "recovered_targets_sample": sorted({t["lea_target"] for t in trampolines})[:40],
        "note": (
            "lea loads real callee into rcx/rax; jmp hits shared dispatcher "
            "(CFG / call-obfuscation). Deobf = follow lea_target, not dispatcher."
            if likely
            else None
        ),
    }


def pe_text_map(data: bytes) -> tuple[int, int, int, int]:
    """image_base, text_va, text_roff, text_size"""
    e = struct.unpack_from("<I", data, 0x3C)[0]
    magic = struct.unpack_from("<H", data, e + 0x18)[0]
    if magic == 0x10B:
        image_base = struct.unpack_from("<I", data, e + 0x18 + 28)[0]
        sec = e + 0x18 + 0xE0
    else:
        image_base = struct.unpack_from("<Q", data, e + 0x18 + 24)[0]
        sec = e + 0x18 + 0xF0
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    entry = struct.unpack_from("<I", data, e + 0x28)[0]
    best = None
    for i in range(nsec):
        o = sec + i * 40
        name = data[o : o + 8].split(b"\0", 1)[0]
        vsize, va, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
        if name == b".text" and rsize > 0x200:
            return image_base, va, roff, rsize
        if va <= entry < va + max(vsize, 1) and rsize > 0x200:
            best = (va, roff, rsize)
    if best:
        return image_base, best[0], best[1], best[2]
    raise ValueError("no text")


def analyze_cfg(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    data = path.read_bytes()
    try:
        ib, va, roff, sz = pe_text_map(data)
    except Exception as e:
        return {"ok": False, "error": str(e)}
    info = find_lea_jmp_trampolines(data, ib, va, roff, sz)
    info["ok"] = True
    info["path"] = str(path)
    info["text_va"] = hex(ib + va)
    return info


def stage_cfg_obfuscation(profile: Any, out_dir: Path) -> dict[str, Any]:
    path = Path(profile.path)
    if path.suffix.lower() not in (".exe", ".dll") and profile.format != "pe":
        return {"skipped": True}
    # skip obvious Themida shells (virtual .text) — CFG inventory is for mapped code
    if any("virtual_only" in s for s in (profile.signals or [])):
        return {"skipped": True, "reason": "packed_shell_no_static_text"}
    try:
        info = analyze_cfg(path)
    except Exception as e:
        return {"ok": False, "error": str(e)}
    (Path(out_dir) / "cfg_obfuscation.json").write_text(json.dumps(info, indent=2), encoding="utf-8")
    return {
        "trampoline_count": info.get("trampoline_count"),
        "cfg_obfuscation_likely": info.get("cfg_obfuscation_likely"),
        "top_dispatchers": info.get("top_dispatchers"),
        "out": str(Path(out_dir) / "cfg_obfuscation.json"),
    }
