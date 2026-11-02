# language: Python 3, file: potassium/recrack.py
# Re-apply learned gate signatures on NEW Potassium.dll builds (recrack_dll port)
# *rel32/rel8 wildcards + pre/post context — offsets re-derived per build*
from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

from street_decrepytor.potassium.gates import DEFAULT_TABLES, find_gate_table


def _wildcard_pattern(orig: bytes) -> bytes:
    """Turn rel32/rel8 displacement into wildcards for cross-build match."""
    pattern = bytearray(orig)
    if len(pattern) == 6 and pattern[0] == 0x0F and pattern[1] in (0x84, 0x85):
        pattern[2:6] = b"\x00\x00\x00\x00"
    elif len(pattern) == 2 and pattern[0] in (0x74, 0x75, 0xEB):
        pattern[1] = 0x00
    return bytes(pattern)


def _find_all(data: bytes, pattern: bytes, pre: bytes, post: bytes) -> list[int]:
    rx = b""
    for b in pattern:
        if b == 0x00:
            rx += b"."
        else:
            rx += re.escape(bytes([b]))
    if pre:
        rx = re.escape(pre) + rx
    if post:
        rx += re.escape(post)
    outs = []
    for m in re.finditer(rx, data, re.DOTALL):
        off = m.start()
        if pre:
            off += len(pre)
        outs.append(off)
    return outs


def _pick_best(offs: list[int], target: int, used: set[int]) -> int | None:
    best, bestd = None, None
    for o in offs:
        if o in used:
            continue
        d = abs(o - target)
        if bestd is None or d < bestd:
            best, bestd = o, d
    return best


def recrack_dll(
    src: str | Path,
    *,
    out: str | Path | None = None,
    table_path: str | Path | None = None,
    dry: bool = False,
    backup: bool = True,
) -> dict[str, Any]:
    """
    Re-derive and apply gate patches on a new Potassium.dll build.
    Writes out path (default: <src stem>_recracked.dll) unless dry.
    """
    src = Path(src)
    data = bytearray(src.read_bytes())
    full = bytes(data)
    table_path = Path(table_path) if table_path else find_gate_table()
    if not table_path or not table_path.is_file():
        return {"ok": False, "error": "no_gate_table", "tried": [str(p) for p in DEFAULT_TABLES]}

    sigs = json.loads(table_path.read_text(encoding="utf-8"))
    if not isinstance(sigs, list):
        return {"ok": False, "error": "table_not_list"}

    ok = miss = already = 0
    used: set[int] = set()
    details = []
    for idx, sig in enumerate(sigs):
        orig = bytes.fromhex(sig["orig"])
        patch = bytes.fromhex(sig["patch"])
        pre = bytes.fromhex(sig.get("pre", ""))
        post = bytes.fromhex(sig.get("post", ""))
        pattern = _wildcard_pattern(orig)
        # try full context, then shortened pre/post (new compilers shift nearby immediates)
        learned = int(sig.get("rva", 0))
        context_tries = [
            (pre, post, "full", 0x200000),
            (pre[-8:] if len(pre) >= 8 else pre, post[:8] if len(post) >= 8 else post, "trim8", 0x80000),
            (pre[-4:] if len(pre) >= 4 else pre, post[:4] if len(post) >= 4 else post, "trim4", 0x40000),
            (pre[-6:] if len(pre) >= 6 else b"", b"", "pre6_only", 0x20000),
            (b"", post[:6] if len(post) >= 6 else b"", "post6_only", 0x20000),
            # last resort: opcode-only near learned file offset (new build layout shift)
            (b"", b"", "bare_near", 0x2000),
        ]
        off = None
        mode = None
        for pre_t, post_t, label, max_delta in context_tries:
            offs = _find_all(full, pattern, pre_t, post_t)
            cand = _pick_best(offs, learned, used)
            if cand is None:
                continue
            if label != "full" and abs(cand - learned) > max_delta:
                continue
            off = cand
            mode = label
            break
        if off is None:
            miss += 1
            details.append({"idx": idx, "op": sig.get("op"), "status": "MISS", "learned_rva": learned})
            continue
        used.add(off)
        cur = bytes(data[off : off + len(orig)])
        if cur == patch or bytes(data[off : off + len(patch)]) == patch:
            already += 1
            details.append({"idx": idx, "op": sig.get("op"), "status": "ALREADY", "off": off, "mode": mode})
            continue
        data[off : off + len(patch)] = patch
        ok += 1
        details.append({
            "idx": idx,
            "op": sig.get("op"),
            "status": "OK",
            "off": off,
            "learned_rva": sig.get("rva"),
            "delta": off - int(sig.get("rva", 0)),
            "mode": mode,
        })

    report: dict[str, Any] = {
        "ok": ok + already > 0,
        "src": str(src),
        "table": str(table_path),
        "sha16_src": hashlib.sha256(full).hexdigest()[:16].upper(),
        "applied": ok,
        "already": already,
        "miss": miss,
        "entries": len(sigs),
        "dry": dry,
        "details_sample": details[:15],
        "miss_count": miss,
    }

    if dry or ok + already == 0:
        if ok + already == 0:
            report["error"] = "zero_gates_landed"
        return report

    out_path = Path(out) if out else src.with_name(src.stem + "_recracked.dll")
    if backup and out_path.resolve() == src.resolve():
        bak = Path(str(src) + ".pre_recrack")
        if not bak.exists():
            shutil.copy2(src, bak)
            report["backup"] = str(bak)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(bytes(data))
    report["out"] = str(out_path)
    report["sha16_out"] = hashlib.sha256(out_path.read_bytes()).hexdigest()[:16].upper()
    report["written"] = True
    # persist re-derived table for this build
    new_table = []
    for d in details:
        if d["status"] not in ("OK", "ALREADY"):
            continue
        sig = sigs[d["idx"]]
        new_table.append({
            **sig,
            "rva": d.get("off", sig.get("rva")),
            "file_offset": d.get("off"),
            "rederived": True,
        })
    table_out = out_path.with_suffix(".gates.json")
    table_out.write_text(json.dumps(new_table, indent=2), encoding="utf-8")
    report["gates_json"] = str(table_out)
    return report


def stage_recrack_if_potassium(profile: Any, out_dir: Path) -> dict[str, Any]:
    """Pipeline stage: auto-recrack when path looks like Potassium DLL."""
    path = Path(profile.path)
    name = path.name.lower()
    if not (name.endswith(".dll") and ("potassium" in name or len(name) > 20)):
        # versioned opaque names are long; only if size ~10MB
        if not (path.suffix.lower() == ".dll" and 8_000_000 < path.stat().st_size < 15_000_000):
            return {"skipped": True}
    # only if we have markers of product
    head = path.read_bytes()[: min(path.stat().st_size, 2 << 20)]
    if b"Potassium" not in head and b"Roblox" not in head and "potassium" not in name:
        # still try if named Potassium
        if "potassium" not in name:
            return {"skipped": True, "reason": "no_potassium_marker"}
    out = Path(out_dir) / f"{path.stem}_recracked.dll"
    return recrack_dll(path, out=out, dry=False)
