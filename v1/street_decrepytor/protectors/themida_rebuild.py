# language: Python 3, file: themida_rebuild.py
# Build a smaller PE from a Themida *dump*: keep recovered sections, drop Oreans VM blobs.
from __future__ import annotations

import struct
from typing import Any

from street_decrepytor.dynamic.pe_dump import _pe_sections_from_bytes
from street_decrepytor.protectors.themida_oep import find_oep_candidates, set_entrypoint_rva

_KEEP = {
    ".text", ".rdata", ".data", ".pdata", ".rsrc", ".reloc",
    ".edata", ".idata", ".tls", ".gfids", ".00cfg", ".fptable", ".bss",
}


def _align(n: int, a: int) -> int:
    return (n + a - 1) & ~(a - 1)


def is_packer_section(name: str) -> bool:
    if name in _KEEP:
        return False
    if not name:
        return True
    if any(c in name for c in "!?@#$%^&*;'"):
        return True
    if name.startswith(".") and name.lower() not in _KEEP:
        # Oreans random .QR% / .mmA
        if not name[1:].isalpha():
            return True
    return name not in _KEEP


def strip_packer_sections(data: bytes) -> dict[str, Any]:
    """
    Compact PE: keep recovered payload sections, drop packer VM sections.
    Does not lift VM — removes leftover Oreans blobs from an already-dumped image.
    """
    if data[:2] != b"MZ":
        return {"ok": False, "error": "not_pe"}
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        return {"ok": False, "error": "bad_pe"}
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    magic = struct.unpack_from("<H", data, e_lfanew + 0x18)[0]
    opt_size = 0xE0 if magic == 0x10B else 0xF0
    sec_off = e_lfanew + 0x18 + opt_size
    secs = _pe_sections_from_bytes(data)
    keep, drop = [], []
    for i, s in enumerate(secs):
        o = sec_off + i * 40
        chars = struct.unpack_from("<I", data, o + 36)[0] if o + 40 <= len(data) else 0xE0000040
        rec = {**s, "chars": chars}
        (drop if is_packer_section(s["name"]) else keep).append(rec)
    if not keep:
        return {"ok": False, "error": "no_keep_sections", "dropped": [s["name"] for s in drop]}

    hdr_end = sec_off + len(keep) * 40
    file_align = 0x200
    sect_align = 0x1000
    headers = _align(hdr_end, file_align)
    buf = bytearray(headers)
    buf[: min(headers, e_lfanew + 0x18 + opt_size)] = data[: min(headers, e_lfanew + 0x18 + opt_size)]

    file_off = headers
    new_secs = []
    blobs: list[bytes] = []
    for s in keep:
        roff, rsize = int(s["roff"]), int(s["rsize"])
        raw = data[roff : roff + rsize] if rsize and roff + rsize <= len(data) else b""
        raw = raw + b"\x00" * (rsize - len(raw)) if rsize > len(raw) else raw
        new_roff = file_off
        blobs.append(raw)
        new_secs.append({**s, "roff": new_roff, "rsize": len(raw)})
        file_off = _align(file_off + len(raw), file_align)

    out = bytearray(file_off)
    out[:headers] = buf[:headers]
    cur = headers
    for raw in blobs:
        out[cur : cur + len(raw)] = raw
        cur = _align(cur + len(raw), file_align)

    # rewrite COFF + section table
    struct.pack_into("<H", out, e_lfanew + 6, len(keep))
    # SizeOfOptionalHeader already ok
    last = new_secs[-1]
    size_of_image = _align(int(last["va"]) + max(int(last["vsize"]), int(last["rsize"])), sect_align)
    # SizeOfImage at optional+56
    struct.pack_into("<I", out, e_lfanew + 0x18 + 56, size_of_image)
    struct.pack_into("<I", out, e_lfanew + 0x18 + 60, headers)  # SizeOfHeaders
    # clear leftover section slots
    old_table_bytes = nsec * 40
    new_table_bytes = len(keep) * 40
    out[sec_off : sec_off + old_table_bytes] = b"\x00" * min(old_table_bytes, len(out) - sec_off)
    for i, s in enumerate(new_secs):
        o = sec_off + i * 40
        name = s["name"].encode("latin-1", "replace")[:8].ljust(8, b"\0")
        out[o : o + 8] = name
        struct.pack_into("<IIII", out, o + 8, int(s["vsize"]), int(s["va"]), int(s["rsize"]), int(s["roff"]))
        struct.pack_into("<I", out, o + 36, int(s.get("chars") or 0xE0000040))

    oep = find_oep_candidates(bytes(out))
    applied = None
    pe_out = bytes(out)
    if oep and oep[0]["score"] >= 0.5:
        pe_out = set_entrypoint_rva(pe_out, int(oep[0]["rva"]))
        applied = oep[0]
    return {
        "ok": True,
        "kept": [s["name"] for s in keep],
        "dropped": [s["name"] for s in drop],
        "in_size": len(data),
        "out_size": len(pe_out),
        "oep": applied,
        "pe": pe_out,
    }
