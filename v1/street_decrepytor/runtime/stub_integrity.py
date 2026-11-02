# language: Python 3, file: runtime/stub_integrity.py
# R2 — Stub Integrity Validator (32-byte hashes, multi-shot, build-keyed DB)
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from street_decrepytor.runtime.common import (
    CRITICAL_STUBS,
    Finding,
    classify_stub_patch,
    clamp01,
    export_rvas_from_pe,
    module_base_in_process,
    ntdll_path,
    open_process,
    read_process_memory,
    sha256_bytes,
    windows_build,
)

STUB_LEN = 32
DEFAULT_DB = Path(__file__).resolve().parents[2] / "data" / "stub_db"


def build_stub_db(out_dir: str | Path | None = None) -> dict[str, Any]:
    """R2.1 — generate pristine stub hashes from System32 ntdll for this OS build."""
    out = Path(out_dir or DEFAULT_DB)
    out.mkdir(parents=True, exist_ok=True)
    build = windows_build()
    pe_path = ntdll_path()
    data = pe_path.read_bytes()
    rvas = export_rvas_from_pe(pe_path, CRITICAL_STUBS)

    import pefile

    pe = pefile.PE(data=data, fast_load=True)
    stubs: dict[str, Any] = {}
    for name, rva in rvas.items():
        off = pe.get_offset_from_rva(rva)
        if off is None or off < 0:
            continue
        blob = data[off : off + STUB_LEN]
        if len(blob) < STUB_LEN:
            continue
        stubs[name] = {
            "rva": hex(rva),
            "sha256_32": sha256_bytes(blob),
            "bytes_hex": blob.hex(),
        }

    payload = {
        "build": build,
        "ntdll_path": str(pe_path),
        "ntdll_sha256": sha256_bytes(data),
        "stub_len": STUB_LEN,
        "stubs": stubs,
        "limits": [
            "Valid only for this Windows build key — rebuild after cumulative updates",
            "Legitimate hotpatches / AV may diverge without malice",
        ],
    }
    key = build["key"]
    path = out / f"stubs_{key}.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    latest = out / "stubs_latest.json"
    latest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return {"ok": True, "path": str(path), "latest": str(latest), "build": key, "stub_count": len(stubs)}


def load_stub_db(db_path: str | Path | None = None) -> dict[str, Any]:
    if db_path:
        p = Path(db_path)
    else:
        build = windows_build()
        p = DEFAULT_DB / f"stubs_{build['key']}.json"
        if not p.is_file():
            p = DEFAULT_DB / "stubs_latest.json"
    if not p.is_file():
        # auto-build
        build_stub_db()
        p = DEFAULT_DB / "stubs_latest.json"
    return json.loads(p.read_text(encoding="utf-8"))


def validate_stubs_live(
    pid: int,
    *,
    shots: int = 3,
    shot_delay_ms: int = 40,
    db_path: str | Path | None = None,
) -> dict[str, Any]:
    """
    R2.2–R2.4 — multi-shot compare of live ntdll stubs vs pristine DB.
    """
    findings: list[Finding] = []
    db = load_stub_db(db_path)
    build = windows_build()
    build_mismatch = db.get("build", {}).get("key") != build["key"]
    if build_mismatch:
        findings.append(
            Finding(
                pillar="R2",
                flag="stub_db_build_mismatch",
                score=0.15,
                confidence=0.9,
                detail=f"DB build {db.get('build',{}).get('key')} vs live {build['key']}",
                limits=["Rebuild stub DB after CU — mismatch raises false-positive risk"],
            )
        )

    pe_path = ntdll_path()
    rvas = export_rvas_from_pe(pe_path, list(db.get("stubs", {}).keys()) or CRITICAL_STUBS)
    base, _size = module_base_in_process(pid, "ntdll.dll")
    handle, k32 = open_process(pid)

    shot_results: list[dict[str, Any]] = []
    try:
        for shot in range(max(1, shots)):
            if shot:
                time.sleep(shot_delay_ms / 1000.0)
            per: dict[str, Any] = {}
            for name, rva in rvas.items():
                addr = base + rva
                try:
                    live = read_process_memory(handle, k32, addr, STUB_LEN)
                except OSError as e:
                    per[name] = {"error": str(e)}
                    continue
                expected = (db.get("stubs") or {}).get(name, {})
                disk_hex = expected.get("bytes_hex")
                disk = bytes.fromhex(disk_hex) if disk_hex else b""
                live_hash = sha256_bytes(live)
                match = live_hash == expected.get("sha256_32")
                klass = classify_stub_patch(live, disk) if disk else ("pristine" if match else "modified_unknown")
                per[name] = {
                    "addr": hex(addr),
                    "match": match,
                    "class": klass,
                    "live_sha256_32": live_hash,
                    "live_hex": live.hex(),
                }
            shot_results.append({"shot": shot, "stubs": per})
    finally:
        k32.CloseHandle(handle)

    # aggregate across shots
    names = set()
    for sh in shot_results:
        names.update(sh["stubs"].keys())

    modified = []
    flapping = []
    for name in sorted(names):
        classes = []
        matches = []
        for sh in shot_results:
            st = sh["stubs"].get(name) or {}
            if "error" in st:
                continue
            matches.append(bool(st.get("match")))
            classes.append(st.get("class"))
        if not matches:
            continue
        if not all(matches):
            modified.append(name)
        if len(set(matches)) > 1 or (len(set(classes)) > 1 and not all(matches)):
            flapping.append(name)

    # scores
    if modified:
        findings.append(
            Finding(
                pillar="R2",
                flag="stub_hash_mismatch",
                score=clamp01(0.35 + 0.08 * len(modified)),
                confidence=0.75 if not build_mismatch else 0.45,
                detail=f"mismatched stubs: {modified}",
                limits=[
                    "CU-altered stubs can FP without rebuild",
                    "AV / EDR legitimately hook Nt*",
                ],
            )
        )
    if flapping:
        findings.append(
            Finding(
                pillar="R2",
                flag="stub_restore_after_check_suspected",
                score=0.55,
                confidence=0.55,
                detail=f"hash/class changed across shots: {flapping}",
                limits=["VMProtect-style restore window — timing-sensitive, not definitive"],
            )
        )
    if not modified and not flapping:
        findings.append(
            Finding(
                pillar="R2",
                flag="stubs_match_db",
                score=0.0,
                confidence=0.7 if not build_mismatch else 0.4,
                detail="All sampled critical stubs matched DB across shots",
                limits=["Does not prove absence of hypervisor or restore-between-shots"],
            )
        )

    score = max((f.score for f in findings), default=0.0)
    conf = min((f.confidence for f in findings), default=0.5)
    return {
        "pillar": "R2",
        "ok": True,
        "pid": pid,
        "build": build,
        "db_build": db.get("build"),
        "shots": shot_results,
        "modified": modified,
        "flapping": flapping,
        "findings": [f.to_dict() for f in findings],
        "score": score,
        "confidence": conf,
        "limits": [
            "Build-keyed DB required after Windows CU",
            "Multi-shot still misses sub-shot_delay restores",
            "Heap handlers after trampoline need R1 chain unwind",
        ],
    }
