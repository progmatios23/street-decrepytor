# language: Python 3, file: analyzer.py
from __future__ import annotations

import json
import struct
from pathlib import Path
from typing import Any

from street_decrepytor.core.artifact import ArtifactProfile


def _pe_imports_exports(data: bytes) -> dict[str, Any]:
    """Lightweight PE import name harvest without full pefile dependency path."""
    out: dict[str, Any] = {"imports_sample": [], "export_names": [], "entry_rva": None}
    if data[:2] != b"MZ" or len(data) < 0x200:
        return out
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 0x50 > len(data):
        return out
    opt = e_lfanew + 0x18
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x10B:
        entry = struct.unpack_from("<I", data, opt + 0x10)[0]
        dd = opt + 0x60
    elif magic == 0x20B:
        entry = struct.unpack_from("<I", data, opt + 0x10)[0]
        dd = opt + 0x70
    else:
        return out
    out["entry_rva"] = entry
    # Prefer real PE import table via pefile; fallback to constrained IAT-area scrape
    import re
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        dlls = []
        apis = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dlls.append(entry.dll.decode("ascii", "ignore"))
                for imp in entry.imports[:40]:
                    if imp.name:
                        apis.append(imp.name.decode("ascii", "ignore"))
        out["imports_sample"] = sorted(set(dlls))[:80]
        out["api_like"] = sorted(set(apis))[:120]
        out["import_source"] = "pefile_iat"
        return out
    except Exception:
        out["import_source"] = "heuristic_fallback"
    # constrained: only names that look like real modules (no random embedded noise)
    dlls = set()
    for m in re.finditer(rb"(?:[A-Za-z]:\\|[A-Za-z0-9_\-]{3,30}\\)?([A-Za-z][A-Za-z0-9_\-]{2,40}\.dll)\x00", data, flags=re.I):
        dlls.add(m.group(1))
    if not dlls:
        dlls = set(re.findall(rb"\x00([A-Za-z][A-Za-z0-9_\-]{2,30}\.dll)\x00", data, flags=re.I))
    apis = set(
        re.findall(
            rb"(?:Nt|Zw|Rtl|Ldr|Virtual|WriteProcess|ReadProcess|CreateRemote|IsDebugger|CheckRemote|OutputDebug|QueryPerformance|GetTickCount|LoadLibrary|GetProcAddress)[A-Za-z0-9_]{0,40}",
            data,
        )
    )
    out["imports_sample"] = sorted(x.decode("ascii", "ignore") if isinstance(x, (bytes, bytearray)) else x for x in dlls)[:80]
    out["api_like"] = sorted(x.decode("ascii", "ignore") for x in apis)[:120]
    return out


def stage_static_analyze(profile: ArtifactProfile, out_dir: Path) -> dict[str, Any]:
    path = Path(profile.path)
    # map full file for mid-size; stream for huge
    if profile.size > 80 << 20:
        with path.open("rb") as f:
            data = f.read(16 << 20)
        partial = True
    else:
        data = path.read_bytes()
        partial = False

    pe = _pe_imports_exports(data) if profile.format in ("pe",) or data[:2] == b"MZ" else {}
    report = {
        "partial_read": partial,
        "bytes_read": len(data),
        "pe": pe,
        "family": profile.family.value,
        "signals": profile.signals,
    }

    # entropy per 64KB block — packing / encryption localization without signatures
    block = 64 << 10
    entropies = []
    for i in range(0, min(len(data), 8 << 20), block):
        chunk = data[i : i + block]
        if not chunk:
            break
        # Shannon-ish: byte histogram
        freq = [0] * 256
        for b in chunk:
            freq[b] += 1
        import math
        n = len(chunk)
        h = 0.0
        for c in freq:
            if c:
                p = c / n
                h -= p * math.log2(p)
        entropies.append({"off": i, "H": round(h, 3)})
    high = [e for e in entropies if e["H"] >= 7.2]
    report["entropy_blocks"] = entropies[:32]
    report["high_entropy_blocks"] = high[:16]
    report["high_entropy_ratio"] = round(len(high) / max(1, len(entropies)), 3)

    (out_dir / "static_analyze.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
