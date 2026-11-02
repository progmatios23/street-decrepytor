# language: Python 3, file: themida_oep.py
# OEP hunt on a *dumped* Themida image — never trust disk EP.
from __future__ import annotations

import struct
from typing import Any

from street_decrepytor.dynamic.pe_dump import _pe_sections_from_bytes

# Stronger first — CRT / MSVC real starts. Bare `e8` is last and penalized.
_STRONG = (
    (b"\x48\x83\xec\x28\xe8", 0.35, "crt_sub28_call"),
    (b"\x48\x89\x5c\x24\x08", 0.25, "mov_rbx_slot"),
    (b"\x48\x8d\x6c\x24", 0.2, "lea_rbp_rsp"),
    (b"\x48\x83\xec", 0.12, "sub_rsp_ib"),
    (b"\x40\x53", 0.08, "rex_push_rbx"),
)


def entrypoint_rva(data: bytes) -> int | None:
    if data[:2] != b"MZ" or len(data) < 0x40:
        return None
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 0x2C > len(data):
        return None
    return struct.unpack_from("<I", data, e_lfanew + 0x28)[0]


def set_entrypoint_rva(data: bytes, rva: int) -> bytes:
    buf = bytearray(data)
    e_lfanew = struct.unpack_from("<I", buf, 0x3C)[0]
    struct.pack_into("<I", buf, e_lfanew + 0x28, rva & 0xFFFFFFFF)
    return bytes(buf)


def _disasm(blob: bytes, va: int):
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64

        md = Cs(CS_ARCH_X86, CS_MODE_64)
        return list(md.disasm(blob[:128], va))
    except Exception:
        return []


def _code_score(blob: bytes, va: int) -> float:
    insns = _disasm(blob, va)
    if not insns:
        nz = sum(1 for b in blob[:32] if b not in (0, 0xCC))
        return round(nz / 64.0, 3)
    bad = {"db", "int3"}
    ok = sum(1 for i in insns if i.mnemonic not in bad)
    base = ok / max(len(insns), 1)
    calls = sum(1 for i in insns if i.mnemonic == "call")
    rets = sum(1 for i in insns if i.mnemonic in ("ret", "retn"))
    # density of unique mnemonics — CRT start is varied, junk is not
    uniq = len({i.mnemonic for i in insns})
    bonus = min(0.25, 0.05 * calls) + (0.08 if rets else 0) + min(0.15, uniq / 40.0)
    return round(min(1.0, 0.45 * base + bonus), 3)


def find_oep_candidates(dump: bytes, *, max_cands: int = 8) -> list[dict[str, Any]]:
    """Rank likely OEPs. Bare `call rel32` is not enough."""
    secs = _pe_sections_from_bytes(dump)
    text = next((s for s in secs if s.get("name") == ".text"), None)
    if not text:
        return []
    roff = int(text.get("roff") or 0)
    rsize = int(text.get("rsize") or 0)
    va = int(text.get("va") or 0)
    if rsize < 0x40 or roff + 0x40 > len(dump):
        return []
    blob = dump[roff : roff + min(rsize, 0x8000)]
    cands: list[dict[str, Any]] = []

    ep = entrypoint_rva(dump)
    if ep is not None and va <= ep < va + max(int(text.get("vsize") or rsize), 1):
        off = ep - va
        if 0 <= off < len(blob):
            cands.append({
                "rva": ep,
                "score": min(1.0, _code_score(blob[off : off + 128], va + off) + 0.05),
                "why": "existing_ep_in_text",
            })

    # text start only if it looks like CRT, not a random byte
    head = blob[:16]
    start_bonus = 0.0
    start_why = "text_start"
    for pat, bonus, why in _STRONG:
        if blob.startswith(pat):
            start_bonus = bonus
            start_why = why
            break
    if blob[0] not in (0x00, 0xCC):
        sc = _code_score(blob[:128], va) + start_bonus
        if start_bonus or sc >= 0.55:
            cands.append({"rva": va, "score": min(1.0, sc), "why": start_why})

    seen = {c["rva"] for c in cands}
    limit = min(len(blob) - 8, 0x2000)
    for i in range(0, limit):
        for pat, bonus, why in _STRONG:
            if blob[i : i + len(pat)] == pat:
                rva = va + i
                if rva in seen:
                    break
                sc = min(1.0, _code_score(blob[i : i + 128], rva) + bonus)
                if sc >= 0.55:
                    seen.add(rva)
                    cands.append({"rva": rva, "score": round(sc, 3), "why": why})
                break
        if len(cands) >= max_cands * 4:
            break

    cands.sort(key=lambda c: (-c["score"], c["rva"]))
    uniq: list[dict[str, Any]] = []
    used: set[int] = set()
    for c in cands:
        r = int(c["rva"])
        if any(abs(r - u) < 16 for u in used):
            continue
        used.add(r)
        uniq.append({**c, "rva_hex": hex(r)})
        if len(uniq) >= max_cands:
            break
    return uniq
