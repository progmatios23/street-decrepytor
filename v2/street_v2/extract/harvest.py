# language: Python 3.11+, file: extract/harvest.py
# Dump *everything* recoverable from a file: sections, overlay, resources,
# nested PE (real SizeOfImage), archives/images, islands, strings, IAT.
from __future__ import annotations

import hashlib
import json
import re
import struct
import zlib
from pathlib import Path
from typing import Any

from street_v2.entropy.analyzer import EntropyMap, shannon
from street_v2.pe.loader import PeImage, load_pe

_ASCII = re.compile(rb"[\x20-\x7e]{8,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){8,}")

MAGIC_SIGS: list[tuple[bytes, str, int]] = [
    (b"MZ", "mz", 0x200),
    (b"PK\x03\x04", "zip", 0x40),
    (b"PK\x05\x06", "zip_eocd", 0x16),
    (b"\x7fELF", "elf", 0x40),
    (b"%PDF", "pdf", 8),
    (b"\x89PNG\r\n\x1a\n", "png", 24),
    (b"\xff\xd8\xff", "jpeg", 12),
    (b"GIF87a", "gif", 16),
    (b"GIF89a", "gif", 16),
    (b"Rar!\x1a\x07", "rar", 16),
    (b"7z\xbc\xaf'\x1c", "7z", 32),
    (b"\x1f\x8b\x08", "gzip", 10),
    (b"BZh", "bzip2", 8),
    (b"\x00asm", "wasm", 8),
    (b"\xfe\xed\xfa", "macho", 16),
    (b"\xcf\xfa\xed\xfe", "macho", 16),
    (b"wspc", "web_pe", 4),  # unlikely; keep tight
]

PYC_MAGICS = {
    0x0A0D0D0A, 0x0A0D0C0A, 0x0A0D0B0A,
    0x0D0A0D0A, 0x6F0D0D0A,  # 3.7–3.12-ish
}


def _sha16(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()[:16]


def _safe_name(s: str, n: int = 80) -> str:
    out = "".join(c if c.isalnum() or c in "._-" else "_" for c in s)
    return (out or "x")[:n]


def pe_raw_size(data: bytes, off: int) -> int | None:
    """On-disk size of an embedded PE starting at off (last section raw end)."""
    if off < 0 or off + 0x40 > len(data) or data[off : off + 2] != b"MZ":
        return None
    e_lfanew = struct.unpack_from("<I", data, off + 0x3C)[0]
    peh = off + e_lfanew
    if peh + 24 > len(data) or data[peh : peh + 4] != b"PE\x00\x00":
        return None
    nsec = struct.unpack_from("<H", data, peh + 6)[0]
    optsz = struct.unpack_from("<H", data, peh + 20)[0]
    if nsec > 96 or optsz > 0x400:
        return None
    sec = peh + 24 + optsz
    end = sec + nsec * 40 - off
    for i in range(nsec):
        o = sec + i * 40
        if o + 40 > len(data):
            break
        rawsize = struct.unpack_from("<I", data, o + 16)[0]
        rawptr = struct.unpack_from("<I", data, o + 20)[0]
        end = max(end, rawptr + rawsize)
    if end < 0x200 or end > 80 << 20:
        return None
    return min(end, len(data) - off)


def _write(path: Path, blob: bytes) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(blob)
    return {
        "path": str(path),
        "size": len(blob),
        "sha16": _sha16(blob),
        "H": round(shannon(blob[: min(len(blob), 1 << 16)]), 4),
        "magic": blob[:4].hex(),
    }


def dump_sections(pe: PeImage, out: Path) -> list[dict[str, Any]]:
    rows = []
    for s in pe.sections:
        blob = s.data if s.data else pe.data[s.raw : s.raw + s.rawsize]
        rec = _write(out / f"{_safe_name(s.name)}_{s.va:x}.bin", blob)
        rec.update({"name": s.name, "va": hex(s.va), "raw": hex(s.raw), "executable": s.executable})
        rows.append(rec)
    return rows


def dump_overlay(pe: PeImage, out: Path) -> dict[str, Any] | None:
    last = 0
    for s in pe.sections:
        last = max(last, s.raw + s.rawsize)
    if last <= 0 or last >= len(pe.data):
        return None
    blob = pe.data[last:]
    if len(blob) < 16:
        return None
    rec = _write(out / "overlay.bin", blob)
    rec["file_off"] = hex(last)
    return rec


def dump_resources(pe: PeImage, out: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    try:
        import pefile

        p = pefile.PE(data=pe.data, fast_load=False)
        p.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
        if not hasattr(p, "DIRECTORY_ENTRY_RESOURCE"):
            return rows
        n = 0
        for entry in p.DIRECTORY_ENTRY_RESOURCE.entries:
            etype = str(entry.name) if entry.name else pefile.RESOURCE_TYPE.get(entry.id, f"type_{entry.id}")
            if not getattr(entry, "directory", None):
                continue
            for e2 in entry.directory.entries:
                ename = str(e2.name) if e2.name else str(e2.id)
                if not getattr(e2, "directory", None):
                    continue
                for e3 in e2.directory.entries:
                    try:
                        rva = e3.data.struct.OffsetToData
                        size = e3.data.struct.Size
                        data = p.get_data(rva, size)
                    except Exception:
                        continue
                    n += 1
                    kind = "bin"
                    if data[:2] == b"MZ":
                        kind = "exe"
                    elif data[:2] == b"PK":
                        kind = "zip"
                    elif data[:5] in (b"<?xml", b"<Syst") or b"<Rule" in data[:400]:
                        kind = "xml"
                    elif data[:8] == b"\x89PNG\r\n\x1a\n":
                        kind = "png"
                    name = f"res_{n:03d}_{_safe_name(str(etype))}_{_safe_name(str(ename))}_{size}.{kind}"
                    rec = _write(out / name, data)
                    rec.update({"type": str(etype), "id": str(ename), "kind": kind})
                    rows.append(rec)
    except Exception as e:
        rows.append({"error": str(e)})
    return rows


def carve_embedded_pe(data: bytes, out: Path, skip_off: int = 0, limit: int = 40) -> list[dict[str, Any]]:
    rows = []
    start = 0
    seen: set[int] = set()
    while len(rows) < limit:
        idx = data.find(b"MZ", start)
        if idx < 0:
            break
        start = idx + 2
        if idx == skip_off or idx in seen:
            continue
        if idx + 0x40 >= len(data):
            continue
        e_lfanew = struct.unpack_from("<I", data, idx + 0x3C)[0]
        peh = idx + e_lfanew
        if peh + 4 > len(data) or data[peh : peh + 4] != b"PE\x00\x00":
            continue
        size = pe_raw_size(data, idx)
        if not size or size < 0x400:
            continue
        seen.add(idx)
        blob = data[idx : idx + size]
        rec = _write(out / f"pe_{idx:08x}_sz{size:x}.bin", blob)
        rec.update({"file_off": hex(idx), "pe_size": size, "kind": "copy"})
        rows.append(rec)
    return rows


def carve_magics(data: bytes, out: Path, limit: int = 30) -> list[dict[str, Any]]:
    rows = []
    for sig, name, minlen in MAGIC_SIGS:
        if name == "mz":
            continue  # handled by carve_embedded_pe
        start = 0
        hits = 0
        while hits < 8 and len(rows) < limit:
            idx = data.find(sig, start)
            if idx < 0:
                break
            start = idx + len(sig)
            if idx < 0x40 and name == "zip":
                # PE overlay zips are fine; skip PK inside DOS stub noise
                pass
            end = min(len(data), idx + (4 << 20))
            blob = data[idx:end]
            # shrink zip to EOCD if present
            if name == "zip":
                eocd = blob.rfind(b"PK\x05\x06")
                if eocd > 0:
                    blob = blob[: eocd + 22]
            rec = _write(out / f"{name}_{idx:08x}.bin", blob[: min(len(blob), 8 << 20)])
            rec.update({"file_off": hex(idx), "kind": name})
            rows.append(rec)
            hits += 1
    return rows


def dump_islands(data: bytes, ent: EntropyMap | None, out: Path) -> list[dict[str, Any]]:
    rows = []
    if not ent:
        return rows
    for i, isl in enumerate(ent.islands[:24]):
        blob = data[isl.start_off : isl.end_off]
        if len(blob) < 64:
            continue
        rec = _write(out / f"island_{i:02d}_{isl.start_off:x}_{isl.kind_hint}.bin", blob)
        rec.update({
            "start": hex(isl.start_off),
            "end": hex(isl.end_off),
            "hint": isl.kind_hint,
            "section": isl.section,
            "mean_H": round(isl.mean_H, 4),
        })
        rows.append(rec)
    return rows


def dump_strings(data: bytes, out: Path, limit: int = 80000) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    ascii_s: list[str] = []
    for m in _ASCII.finditer(data):
        ascii_s.append(m.group().decode("ascii", "ignore"))
        if len(ascii_s) >= limit:
            break
    utf: list[str] = []
    for m in _UTF16.finditer(data):
        try:
            utf.append(m.group().decode("utf-16-le", "ignore"))
        except Exception:
            continue
        if len(utf) >= limit:
            break
    (out / "strings_ascii.txt").write_text("\n".join(ascii_s), encoding="utf-8", errors="replace")
    (out / "strings_utf16.txt").write_text("\n".join(utf), encoding="utf-8", errors="replace")
    interesting = [
        s for s in ascii_s + utf
        if any(k in s.lower() for k in (
            "http", "key", "aes", "xor", "rc4", "crypt", "password", "token",
            "themida", "vmp", "pyinstaller", "mei", ".dll", "virtualprotect",
        ))
    ][:400]
    (out / "strings_interesting.txt").write_text("\n".join(interesting), encoding="utf-8", errors="replace")
    return {
        "ascii": len(ascii_s),
        "utf16": len(utf),
        "interesting": len(interesting),
        "paths": {
            "ascii": str(out / "strings_ascii.txt"),
            "utf16": str(out / "strings_utf16.txt"),
            "interesting": str(out / "strings_interesting.txt"),
        },
    }


def try_zlib_blobs(blobs: list[tuple[str, bytes]], out: Path, limit: int = 40) -> list[dict[str, Any]]:
    rows = []
    n = 0
    out.mkdir(parents=True, exist_ok=True)
    for label, blob in blobs:
        if n >= limit or not blob:
            continue
        tried = False
        # full-stream first (PyInstaller overlay is often one zlib)
        if len(blob) >= 2 and (blob[0] & 0x0F) == 8 and ((blob[0] << 8) + blob[1]) % 31 == 0:
            try:
                dec = zlib.decompress(blob)
                if len(dec) >= 32:
                    n += 1
                    rec = _write(out / f"zlib_{_safe_name(label)}_full.bin", dec[: min(len(dec), 32 << 20)])
                    rec.update({"src": label, "off": "0x0", "kind": "inflate", "in_size": len(blob), "out_size": len(dec)})
                    rows.append(rec)
                    tried = True
            except zlib.error:
                try:
                    dec = zlib.decompress(blob, wbits=-15)  # raw deflate
                    if len(dec) >= 32:
                        n += 1
                        rec = _write(out / f"zlib_{_safe_name(label)}_raw.bin", dec[: min(len(dec), 32 << 20)])
                        rec.update({"src": label, "off": "0x0", "kind": "inflate_raw", "in_size": len(blob)})
                        rows.append(rec)
                        tried = True
                except zlib.error:
                    pass
        if tried:
            continue
        step = 16
        for i in range(0, min(len(blob), 8 << 10), step):
            if i + 2 > len(blob):
                break
            cmf, flg = blob[i], blob[i + 1]
            if (cmf & 0x0F) != 8:
                continue
            if ((cmf << 8) + flg) % 31 != 0:
                continue
            try:
                dec = zlib.decompress(blob[i:])
            except zlib.error:
                continue
            if len(dec) < 32:
                continue
            n += 1
            rec = _write(out / f"zlib_{_safe_name(label)}_{i:x}.bin", dec[: min(len(dec), 32 << 20)])
            rec.update({"src": label, "off": hex(i), "kind": "inflate", "in_size": len(blob) - i, "out_size": len(dec)})
            rows.append(rec)
            break
    return rows


def harvest_file(
    path: str | Path,
    out_dir: str | Path,
    *,
    pe: PeImage | None = None,
    ent: EntropyMap | None = None,
) -> dict[str, Any]:
    path = Path(path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    data = pe.data if pe is not None else path.read_bytes()
    if pe is None:
        try:
            if data[:2] == b"MZ":
                pe = load_pe(path)
                data = pe.data
        except Exception:
            pe = None

    report: dict[str, Any] = {
        "target": str(path.resolve()),
        "size": len(data),
        "sections": [],
        "overlay": None,
        "resources": [],
        "carved_pe": [],
        "carved_magic": [],
        "islands": [],
        "strings": {},
        "zlib": [],
        "pyinstaller": None,
        "kind": "copy",
        "decrypted": False,
    }

    if pe is not None:
        report["sections"] = dump_sections(pe, out / "sections")
        report["overlay"] = dump_overlay(pe, out)
        report["resources"] = dump_resources(pe, out / "resources")
        skip = 0  # skip the host PE at 0
        report["carved_pe"] = carve_embedded_pe(data, out / "carved_pe", skip_off=skip)

    report["carved_magic"] = carve_magics(data, out / "carved_magic")
    report["islands"] = dump_islands(data, ent, out / "islands")
    report["strings"] = dump_strings(data, out / "strings")

    zlib_src: list[tuple[str, bytes]] = []
    if report.get("overlay"):
        zlib_src.append(("overlay", (out / "overlay.bin").read_bytes() if (out / "overlay.bin").is_file() else b""))
    for row in (report.get("resources") or [])[:20]:
        p = Path(row.get("path") or "")
        if p.is_file() and p.stat().st_size < 8 << 20:
            zlib_src.append((p.name, p.read_bytes()))
    for row in (report.get("islands") or [])[:12]:
        p = Path(row.get("path") or "")
        if p.is_file():
            zlib_src.append((p.name, p.read_bytes()))
    report["zlib"] = try_zlib_blobs(zlib_src, out / "zlib")

    try:
        from street_v2.compat import import_v1

        import_v1()
        from street_decrepytor.deobf.python_rt.pyinst import extract_pyinstaller

        py = extract_pyinstaller(path, out / "pyinstaller")
        report["pyinstaller"] = {
            "ok": py.get("ok"),
            "reason": py.get("reason"),
            "entry_count": py.get("entry_count"),
            "cipher_missing": py.get("cipher_missing"),
            "out": py.get("out"),
        }
    except Exception as e:
        report["pyinstaller"] = {"ok": False, "error": str(e)}

    counts = {
        "sections": len(report["sections"]),
        "resources": len([r for r in report["resources"] if "path" in r]),
        "carved_pe": len(report["carved_pe"]),
        "carved_magic": len(report["carved_magic"]),
        "islands": len(report["islands"]),
        "zlib_inflated": len(report["zlib"]),
        "strings_ascii": (report["strings"] or {}).get("ascii"),
    }
    report["counts"] = counts
    (out / "HARVEST.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return report
