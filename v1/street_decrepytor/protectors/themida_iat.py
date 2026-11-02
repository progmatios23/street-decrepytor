# language: Python 3, file: themida_iat.py
# Rebuild a PE import directory from live-resolved export pointers (x64).
from __future__ import annotations

import struct
from collections import OrderedDict
from typing import Any


def _align(n: int, a: int) -> int:
    return (n + a - 1) & ~(a - 1)


def apply_import_directory(
    dump: bytes,
    resolved: list[dict[str, Any]],
    image_base: int = 0,
) -> dict[str, Any]:
    """
    Append `.idata` with IMAGE_IMPORT_DESCRIPTORs rebuilt from `dll!name` hits.
    Only names already resolved live — does not invent APIs.
    """
    (image_base)
    if dump[:2] != b"MZ":
        return {"ok": False, "error": "not_pe", "pe": dump}
    by_dll: OrderedDict[str, list[str]] = OrderedDict()
    for r in resolved or []:
        sym = str(r.get("sym") or "")
        if "!" not in sym:
            continue
        dll, name = sym.split("!", 1)
        dll = dll.lower()
        if not dll.endswith(".dll"):
            dll += ".dll"
        if not name or name.lower().startswith("ord"):
            continue
        lst = by_dll.setdefault(dll, [])
        if name not in lst:
            lst.append(name)
    nnames = sum(len(v) for v in by_dll.values())
    if nnames < 3:
        return {"ok": False, "error": "too_few_names", "pe": dump, "dlls": list(by_dll)}

    e_lfanew = struct.unpack_from("<I", dump, 0x3C)[0]
    magic = struct.unpack_from("<H", dump, e_lfanew + 0x18)[0]
    if magic != 0x20B:
        return {"ok": False, "error": "pe32plus_only", "pe": dump}
    nsec = struct.unpack_from("<H", dump, e_lfanew + 6)[0]
    opt_size = struct.unpack_from("<H", dump, e_lfanew + 0x14)[0] or 0xF0
    sec_off = e_lfanew + 0x18 + opt_size
    size_of_image = struct.unpack_from("<I", dump, e_lfanew + 0x18 + 56)[0]
    file_align = 0x200
    sect_align = 0x1000
    new_rva = _align(size_of_image, sect_align)
    desc_size = 20 * (len(by_dll) + 1)
    desc = bytearray(desc_size)
    rest = bytearray()

    def emit(b: bytes) -> int:
        r = new_rva + desc_size + len(rest)
        rest.extend(b)
        return r

    meta_dlls = []
    for i, (dll, names) in enumerate(by_dll.items()):
        name_rva = emit(dll.encode("ascii") + b"\x00")
        hn = []
        for n in names:
            raw = struct.pack("<H", 0) + n.encode("ascii", "replace") + b"\x00"
            if len(raw) % 2:
                raw += b"\x00"
            hn.append(emit(raw))
        thunks = b"".join(struct.pack("<Q", x) for x in hn) + b"\x00" * 8
        int_rva = emit(thunks)
        iat_rva = emit(thunks)
        struct.pack_into("<IIIII", desc, i * 20, int_rva, 0, 0, name_rva, iat_rva)
        meta_dlls.append({"dll": dll, "count": len(names), "iat_rva": hex(iat_rva)})

    raw_sec = bytes(desc) + bytes(rest)
    raw_sec += b"\x00" * (_align(len(raw_sec), file_align) - len(raw_sec))
    new_rsize = len(raw_sec)
    new_vsize = _align(max(new_rsize, 1), sect_align)
    hdr_end = sec_off + (nsec + 1) * 40
    if hdr_end > struct.unpack_from("<I", dump, e_lfanew + 0x18 + 60)[0]:
        # SizeOfHeaders too small for an extra section row
        return {"ok": False, "error": "no_section_table_room", "pe": dump, "dlls": meta_dlls}

    file_off = _align(len(dump), file_align)
    out = bytearray(file_off + new_rsize)
    out[: len(dump)] = dump
    out[file_off : file_off + new_rsize] = raw_sec
    o = sec_off + nsec * 40
    out[o : o + 8] = b".idata\x00\x00"
    struct.pack_into("<IIII", out, o + 8, new_vsize, new_rva, new_rsize, file_off)
    struct.pack_into("<I", out, o + 36, 0xC0000040)
    struct.pack_into("<H", out, e_lfanew + 6, nsec + 1)
    struct.pack_into("<I", out, e_lfanew + 0x18 + 56, new_rva + new_vsize)
    dd = e_lfanew + 0x18 + 0x70
    struct.pack_into("<II", out, dd + 8, new_rva, desc_size)
    if meta_dlls:
        struct.pack_into("<II", out, dd + 12 * 8, int(meta_dlls[0]["iat_rva"], 16), 8)

    return {
        "ok": True,
        "pe": bytes(out),
        "dlls": meta_dlls,
        "import_rva": hex(new_rva),
        "section": ".idata",
        "names": nnames,
    }
