# language: Python 3, file: tauri_extract.py
# Extract Tauri/WebView2 embedded frontend + inventory IPC commands from PE
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def extract_tauri_assets(data: bytes, out_dir: Path) -> list[dict[str, Any]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    extracted: list[dict[str, Any]] = []
    idx = 0
    n = 0
    while n < 12:
        i = data.find(b"<!DOCTYPE html", idx)
        if i < 0:
            i = data.find(b"<html", idx)
        if i < 0:
            break
        j = data.find(b"</html>", i)
        j = (j + 7) if j > 0 else min(len(data), i + 100_000)
        blob = data[i:j]
        path = out_dir / f"page_{n}.html"
        path.write_bytes(blob)
        extracted.append({"kind": "html", "off": hex(i), "size": len(blob), "path": str(path)})
        n += 1
        idx = j

    js_n = 0
    for m in re.finditer(rb"(?s)(?:\(function|window\.|__TAURI)[\x20-\x7e\r\n\t]{800,}", data):
        s = m.group()
        if b"__TAURI" not in s and b"invoke" not in s and b"plugin:" not in s:
            continue
        path = out_dir / f"bundle_{m.start():08x}.js"
        path.write_bytes(s[:300000])
        extracted.append({
            "kind": "js",
            "off": hex(m.start()),
            "size": min(len(s), 300000),
            "path": str(path),
        })
        js_n += 1
        if js_n >= 12:
            break
    return extracted


def inventory_tauri_ipc(data: bytes) -> dict[str, Any]:
    plugins = sorted({m.decode("ascii") for m in re.findall(rb"plugin:[a-zA-Z0-9_]+(?:\|[a-zA-Z0-9_]+)?", data)})
    js_invokes = sorted({
        m.decode("ascii", "ignore")
        for m in re.findall(rb"invoke\(\s*['\"]([^'\"]{2,80})['\"]", data)
    })
    internals = sorted({
        m.decode("ascii", "ignore")
        for m in re.findall(rb"__TAURI_INTERNALS__\.invoke\(\s*['\"]([^'\"]+)['\"]", data)
    })
    custom = sorted({c for c in js_invokes + internals if not c.startswith("plugin:")})
    urls = sorted({
        u.decode("ascii", "ignore")
        for u in re.findall(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,100}", data)
        if b" " not in u and b"<" not in u and re.match(rb"https?://[a-zA-Z0-9]", u)
    })
    urls = [u for u in urls if len(u) < 90][:50]
    return {
        "is_tauri": b"__TAURI" in data or b"tauri::" in data or (b"WebView2" in data and b"wry" in data),
        "plugin_commands": plugins,
        "js_invoke_literals": js_invokes,
        "internals_invoke": internals,
        "custom_commands": custom,
        "urls": urls,
        "has_fs_plugin": any(p.startswith("plugin:fs") for p in plugins),
        "has_shell_plugin": any(p.startswith("plugin:shell") for p in plugins),
    }


def stage_tauri_extract(profile: Any, out_dir: Path) -> dict[str, Any]:
    path = Path(profile.path)
    data = path.read_bytes() if path.stat().st_size < 80 << 20 else path.read_bytes()[: 40 << 20]
    # quick gate
    if not (b"__TAURI" in data or b"WebView2" in data or "tauri" in str(profile.signals)):
        return {"skipped": True}
    assets_dir = Path(out_dir) / "tauri_assets"
    assets = extract_tauri_assets(data, assets_dir)
    ipc = inventory_tauri_ipc(data)
    report = {"assets": assets, "ipc": ipc, "asset_count": len(assets)}
    (Path(out_dir) / "tauri_inventory.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return {
        "asset_count": len(assets),
        "plugins": len(ipc["plugin_commands"]),
        "custom_commands": ipc["custom_commands"],
        "is_tauri": ipc["is_tauri"],
        "out": str(Path(out_dir) / "tauri_inventory.json"),
    }
