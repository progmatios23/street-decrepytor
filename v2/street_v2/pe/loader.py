# language: Python 3.11+, file: pe/loader.py
# PE image map for live IDA-like views — sections, RVA↔file, imports
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class Section:
    name: str
    va: int
    vsize: int
    raw: int
    rawsize: int
    chars: int
    data: bytes = b""

    @property
    def executable(self) -> bool:
        return bool(self.chars & 0x20000000)

    @property
    def writable(self) -> bool:
        return bool(self.chars & 0x80000000)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "va": hex(self.va),
            "vsize": self.vsize,
            "raw": hex(self.raw),
            "rawsize": self.rawsize,
            "chars": hex(self.chars),
            "executable": self.executable,
            "writable": self.writable,
        }


@dataclass
class PeImage:
    path: str
    data: bytes
    image_base: int
    entry_rva: int
    machine: int
    is_64: bool
    sections: list[Section] = field(default_factory=list)
    imports: list[dict[str, Any]] = field(default_factory=list)
    exports: list[dict[str, Any]] = field(default_factory=list)
    mtime: float = 0.0
    size: int = 0

    @property
    def arch(self) -> str:
        return "x86_64" if self.is_64 else "x86"

    def rva_to_off(self, rva: int) -> int | None:
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.rawsize):
                delta = rva - s.va
                if delta < s.rawsize:
                    return s.raw + delta
                return None
        return None

    def va_to_off(self, va: int) -> int | None:
        return self.rva_to_off(va - self.image_base)

    def read_rva(self, rva: int, n: int) -> bytes:
        off = self.rva_to_off(rva)
        if off is None:
            return b""
        return self.data[off : off + n]

    def section_at_rva(self, rva: int) -> Section | None:
        for s in self.sections:
            if s.va <= rva < s.va + max(s.vsize, s.rawsize):
                return s
        return None

    def text_blob(self) -> tuple[bytes, int]:
        for s in self.sections:
            if s.name.startswith(".text") or (s.executable and s.rawsize > 0):
                blob = s.data if s.data else self.data[s.raw : s.raw + s.rawsize]
                return blob, self.image_base + s.va
        if self.sections:
            s = self.sections[0]
            return self.data[s.raw : s.raw + s.rawsize], self.image_base + s.va
        return b"", self.image_base

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "size": self.size,
            "mtime": self.mtime,
            "image_base": hex(self.image_base),
            "entry_rva": hex(self.entry_rva),
            "entry_va": hex(self.image_base + self.entry_rva),
            "arch": self.arch,
            "machine": hex(self.machine),
            "sections": [s.to_dict() for s in self.sections],
            "imports": self.imports[:200],
            "exports": self.exports[:200],
        }


def load_pe(path: str | Path) -> PeImage:
    p = Path(path)
    data = p.read_bytes()
    if data[:2] != b"MZ":
        raise ValueError(f"not PE: {p}")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError(f"bad PE signature: {p}")
    coff = e_lfanew + 4
    machine, nsec = struct.unpack_from("<HH", data, coff)
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    is_64 = magic == 0x20B
    if is_64:
        entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    else:
        entry_rva = struct.unpack_from("<I", data, opt + 16)[0]
        image_base = struct.unpack_from("<I", data, opt + 28)[0]

    sec_off = opt + opt_size
    sections: list[Section] = []
    for i in range(nsec):
        o = sec_off + i * 40
        name = data[o : o + 8].split(b"\x00", 1)[0].decode("latin-1", "replace")
        vsize = struct.unpack_from("<I", data, o + 8)[0]
        va = struct.unpack_from("<I", data, o + 12)[0]
        rawsize = struct.unpack_from("<I", data, o + 16)[0]
        raw = struct.unpack_from("<I", data, o + 20)[0]
        chars = struct.unpack_from("<I", data, o + 36)[0]
        blob = data[raw : raw + rawsize] if raw and rawsize and raw + rawsize <= len(data) else b""
        sections.append(
            Section(name=name, va=va, vsize=vsize, raw=raw, rawsize=rawsize, chars=chars, data=blob)
        )

    imports: list[dict[str, Any]] = []
    exports: list[dict[str, Any]] = []
    try:
        import pefile

        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(
            directories=[
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
                pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"],
            ]
        )
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll = entry.dll.decode("ascii", "ignore")
                for imp in entry.imports[:80]:
                    imports.append({
                        "dll": dll,
                        "name": imp.name.decode("ascii", "ignore") if imp.name else None,
                        "ordinal": imp.ordinal,
                        "iat_rva": hex(imp.address - pe.OPTIONAL_HEADER.ImageBase) if imp.address else None,
                    })
        if hasattr(pe, "DIRECTORY_ENTRY_EXPORT") and pe.DIRECTORY_ENTRY_EXPORT:
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols[:200]:
                exports.append({
                    "name": exp.name.decode("ascii", "ignore") if exp.name else None,
                    "ordinal": exp.ordinal,
                    "rva": hex(exp.address) if exp.address else None,
                })
    except Exception:
        pass

    st = p.stat()
    return PeImage(
        path=str(p.resolve()),
        data=data,
        image_base=image_base,
        entry_rva=entry_rva,
        machine=machine,
        is_64=is_64,
        sections=sections,
        imports=imports,
        exports=exports,
        mtime=st.st_mtime,
        size=st.st_size,
    )
