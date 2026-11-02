# language: Python 3, file: pyinst.py
# PyInstaller CArchive extract — copy/inflate members. Encrypted PYZ is reported, not faked.
from __future__ import annotations

import json
import struct
import zlib
from pathlib import Path
from typing import Any

MAGIC = b"MEI\014\013\012\013\016"


def extract_pyinstaller(path: str | Path, out_dir: str | Path) -> dict[str, Any]:
    path = Path(path)
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    data = path.read_bytes()
    pos = data.rfind(MAGIC)
    if pos < 0:
        return {"ok": False, "reason": "no_mei_cookie", "entries": []}

    cookie = _parse_cookie(data, pos)
    if not cookie:
        return {"ok": False, "reason": "cookie_parse_fail", "cookie_off": hex(pos), "entries": []}

    pkg_start = pos - cookie["lengthofpackage"]
    toc_off = pkg_start + cookie["toc"]
    toc_end = toc_off + cookie["toclen"]
    if toc_off < 0 or toc_end > len(data):
        return {"ok": False, "reason": "toc_oob", "cookie": cookie, "entries": []}

    entries = _parse_toc(data, toc_off, toc_end)
    written: list[dict[str, Any]] = []
    pyz_dir = out / "pyz"
    pyz_dir.mkdir(exist_ok=True)
    cipher_missing = []

    for e in entries:
        raw = data[pkg_start + e["pos"] : pkg_start + e["pos"] + e["size"]]
        body = raw
        kind = "copy"
        if e["flag"] == 1:
            try:
                body = zlib.decompress(raw)
                kind = "inflate"
            except zlib.error:
                kind = "copy"
                cipher_missing.append({"name": e["name"], "reason": "zlib_fail"})
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in e["name"]) or "entry"
        dest = pyz_dir / safe
        dest.write_bytes(body)
        rec = {
            "name": e["name"],
            "type": e["type"],
            "flag": e["flag"],
            "kind": kind,
            "size": len(body),
            "path": str(dest),
        }
        if e["type"] in (b"z"[0], b"Z"[0], ord("z"), ord("Z")) or e["type"] in ("z", "Z"):
            inner = _try_pyz_toc(body)
            rec["pyz"] = inner
            if inner.get("encrypted"):
                cipher_missing.append({"name": e["name"], "reason": "pyz_encrypted"})
        written.append(rec)

    report = {
        "ok": True,
        "reason": None,
        "cookie": cookie,
        "cookie_off": hex(pos),
        "entry_count": len(written),
        "entries": written[:80],
        "cipher_missing": cipher_missing,
        "out": str(pyz_dir),
        "decrypted": False,
        "note": "members copied or zlib-inflated; encrypted PYZ is not decrypted",
    }
    (out / "pyinst_extract.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return report


def _parse_cookie(data: bytes, pos: int) -> dict[str, Any] | None:
    # 2.1+: magic(8) + 4*uint32 + pylibname(64) = 88
    # 2.0: 24
    for size, has_lib in ((88, True), (24, False)):
        if pos + 24 > len(data):
            continue
        if pos + (88 if has_lib else 24) > len(data) and has_lib:
            continue
        try:
            pkg, toc, toclen, pyver = struct.unpack_from("<IIII", data, pos + 8)
        except struct.error:
            continue
        if pkg <= 0 or toclen <= 0 or toc >= pkg:
            continue
        pylib = ""
        if has_lib and pos + 88 <= len(data):
            pylib = data[pos + 24 : pos + 88].split(b"\0", 1)[0].decode("latin-1", "replace")
        return {
            "lengthofpackage": pkg,
            "toc": toc,
            "toclen": toclen,
            "pyver": pyver,
            "pylib": pylib,
            "cookie_size": 88 if has_lib else 24,
        }
    return None


def _parse_toc(data: bytes, toc_off: int, toc_end: int) -> list[dict[str, Any]]:
    entries = []
    p = toc_off
    while p + 4 < toc_end:
        (elen,) = struct.unpack_from("!i", data, p)
        if elen < 18 or p + elen > len(data):
            break
        blob = data[p + 4 : p + elen]
        if len(blob) < 14:
            break
        epos, sz, ucsz = struct.unpack_from("!iii", blob, 0)
        flag = blob[12]
        typ = blob[13]
        name = blob[14:].split(b"\0", 1)[0].decode("utf-8", "replace").strip()
        entries.append({
            "pos": epos,
            "size": sz,
            "ucsize": ucsz,
            "flag": flag,
            "type": chr(typ) if 32 <= typ < 127 else typ,
            "name": name,
        })
        p += elen
        if len(entries) >= 400:
            break
    return entries


def _try_pyz_toc(body: bytes) -> dict[str, Any]:
    if len(body) < 8 or not body.startswith(b"PYZ"):
        return {"ok": False, "reason": "not_pyz"}
    try:
        import marshal
        toc_off = struct.unpack_from("!i", body, 8)[0] if len(body) > 12 else 0
        # common layout: PYZ\0 + magic + toc at end via marshal
        obj = None
        for off in (toc_off, 16, 12, 8):
            if off <= 0 or off >= len(body):
                continue
            try:
                obj = marshal.loads(body[off:])
                break
            except Exception:
                continue
        if obj is None:
            return {"ok": False, "encrypted": True, "reason": "marshal_fail"}
        names = []
        if isinstance(obj, dict):
            names = [str(k) for k in list(obj.keys())[:80]]
        elif isinstance(obj, (list, tuple)):
            names = [str(x[0] if isinstance(x, (list, tuple)) else x) for x in obj[:80]]
        return {"ok": True, "encrypted": False, "name_count": len(names), "names_sample": names}
    except Exception as e:
        return {"ok": False, "encrypted": True, "reason": str(e)}
