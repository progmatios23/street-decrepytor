# language: Python 3, file: multibuild/scan.py
from __future__ import annotations

import json
import re
import struct
from pathlib import Path
from typing import Any

from street_decrepytor.core.artifact import ArtifactProfile


def find_embedded_pes(data: bytes, limit: int = 20) -> list[dict[str, Any]]:
    hits = []
    start = 0
    while len(hits) < limit:
        idx = data.find(b"MZ", start)
        if idx < 0:
            break
        if idx + 0x40 < len(data):
            e_lfanew = struct.unpack_from("<I", data, idx + 0x3C)[0]
            pe_off = idx + e_lfanew
            if pe_off + 4 < len(data) and data[pe_off : pe_off + 4] == b"PE\0\0":
                hits.append({"file_off": idx, "e_lfanew": e_lfanew})
        start = idx + 2
    return hits


def stage_multibuild(profile: ArtifactProfile, out_dir: Path) -> dict[str, Any]:
    path = Path(profile.path)
    data = path.read_bytes() if profile.size < 60 << 20 else path.open("rb").read(24 << 20)

    embedded = find_embedded_pes(data)
    containers = []
    if data[:2] == b"PK":
        containers.append("zip")
    if b"ustar" in data[:512]:
        containers.append("tar")
    if b"dockerfile" in data.lower()[:2000] or b"oci-layout" in data:
        containers.append("oci_hint")

    arches = set()
    for off in [h["file_off"] for h in embedded[:10]]:
        try:
            e = struct.unpack_from("<I", data, off + 0x3C)[0]
            machine = struct.unpack_from("<H", data, off + e + 4)[0]
            arches.add(hex(machine))
        except Exception:
            pass

    report = {
        "embedded_pe_count": len(embedded),
        "embedded_pe_sample": embedded[:10],
        "machines_seen": sorted(arches),
        "container_hints": containers,
        "profile_multi_hints": profile.multi_build_hints,
        "plan": [
            "carve each embedded PE to out_dir/carved/",
            "classify each carve independently through StreetEngine",
            "for fat binaries / multi-arch: split slices before deobf",
        ],
    }

    carved_dir = out_dir / "carved"
    if embedded and len(embedded) > 1:
        carved_dir.mkdir(exist_ok=True)
        # carve second+ only if size guess available (until next MZ or +2MB)
        for i, h in enumerate(embedded[1:6], start=1):
            off = h["file_off"]
            end = embedded[i + 1]["file_off"] if i + 1 < len(embedded) else min(len(data), off + (2 << 20))
            if end <= off:
                end = min(len(data), off + 0x10000)
            blob = data[off:end]
            if len(blob) > 0x200:
                (carved_dir / f"embed_{i}_{off:x}.bin").write_bytes(blob)

    (out_dir / "multibuild.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
