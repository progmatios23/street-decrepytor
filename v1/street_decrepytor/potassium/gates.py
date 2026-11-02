# language: Python 3, file: potassium/gates.py
# Apply dll_gates_sigs.json patches (file-offset + pre-anchor)
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


DEFAULT_TABLES = [
    Path(r"C:\claude\cracked\bin\dll_gates_sigs.json"),
    Path(r"C:\claude\cracked\patch_table.json"),
]


def find_gate_table() -> Path | None:
    for p in DEFAULT_TABLES:
        if p.is_file():
            # prefer list-of-gates shape
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if isinstance(data, list) and data and "patch" in data[0] and "orig" in data[0]:
                    return p
            except Exception:
                continue
    return None


def apply_gate_table(
    dll_path: str | Path,
    out_path: str | Path,
    table_path: str | Path | None = None,
) -> dict[str, Any]:
    dll_path = Path(dll_path)
    out_path = Path(out_path)
    table_path = Path(table_path) if table_path else find_gate_table()
    if not table_path or not table_path.is_file():
        return {"written": False, "reason": "no_gate_table"}
    table = json.loads(table_path.read_text(encoding="utf-8"))
    if not isinstance(table, list):
        return {"written": False, "reason": "table_not_gate_list", "table": str(table_path)}

    data = bytearray(dll_path.read_bytes())
    patched = already = miss = 0
    for ent in table:
        orig = bytes.fromhex(ent["orig"])
        patch = bytes.fromhex(ent["patch"])
        off = ent.get("rva", 0)
        if "pre" in ent:
            pre = bytes.fromhex(ent["pre"])
            idx = bytes(data).find(pre)
            if idx >= 0:
                off = idx + len(pre)
        if off + max(len(orig), len(patch)) > len(data):
            miss += 1
            continue
        cur = bytes(data[off : off + len(orig)])
        if cur == patch or bytes(data[off : off + len(patch)]) == patch:
            already += 1
            continue
        if cur == orig:
            data[off : off + len(patch)] = patch
            patched += 1
        else:
            # try search orig near pre
            miss += 1

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(data)
    return {
        "written": True,
        "out": str(out_path),
        "table": str(table_path),
        "patched_now": patched,
        "already_patched": already,
        "miss": miss,
        "entries": len(table),
    }
