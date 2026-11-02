# language: Python 3, file: python_rt/engine.py
from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

from street_decrepytor.core.artifact import ArtifactProfile

PYC_MAGICS = {
    3394: "3.12",
    3495: "3.13",
    3310: "3.11",
    3439: "3.12b",
}


def deobf_python(profile: ArtifactProfile, out_dir: Path) -> dict[str, Any]:
    path = Path(profile.path)
    blob = path.read_bytes()
    head = blob[: min(len(blob), 4 << 20)]
    report: dict[str, Any] = {"format": profile.format, "decrypted": False}

    if head[:2] == b"PK" or b"PyInstaller" in head or b"MEI" in head or blob[-256:].find(b"MEI") >= 0:
        from street_decrepytor.deobf.python_rt.pyinst import extract_pyinstaller

        ext = extract_pyinstaller(path, out_dir / "pyinst")
        report["freezer"] = "pyinstaller_or_zip"
        report["extract"] = {
            "ok": ext.get("ok"),
            "reason": ext.get("reason"),
            "entry_count": ext.get("entry_count"),
            "cipher_missing": ext.get("cipher_missing"),
            "out": ext.get("out"),
        }
        report["plan"] = [
            "CArchive members copied/zlib-inflated under pyinst/pyz/",
            "encrypted PYZ listed in cipher_missing — not decrypted",
            "decompile extracted .pyc with pycdc / decompyle3 (external)",
        ]
    elif path.suffix.lower() == ".pyc" or profile.format == "pyc":
        magic = struct.unpack_from("<H", head, 0)[0] if len(head) >= 2 else 0
        report["pyc_magic"] = magic
        report["cpython_guess"] = PYC_MAGICS.get(magic, "unknown_rederive")
        report["plan"] = ["marshal load → dis → decompile; watch for custom opcodes"]
    else:
        report["plan"] = ["identify freezer (py2exe/cx_Freeze/Nuitka) via strings + overlay"]

    (out_dir / "deobf_python.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return report
