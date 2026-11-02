# language: Python 3, file: rust_rt/engine.py
# Rust / Tauri native — Potassium UI class
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from street_decrepytor.core.artifact import ArtifactProfile


def deobf_rust(profile: ArtifactProfile, out_dir: Path) -> dict[str, Any]:
    path = Path(profile.path)
    data = path.read_bytes() if profile.size < 50 << 20 else path.open("rb").read(20 << 20)

    panic_paths = re.findall(rb"([A-Za-z0-9_\\/\-.]+\.rs):\d+", data)
    crates = re.findall(rb"\b(tokio|hyper|tungstenite|serde|reqwest|tauri|winit|tao)\b", data)
    urls = re.findall(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,120}", data)

    # brotli / resource table hint (Tauri)
    brotli_magic = data.count(b"\xce\xb2\xcf\x81")  # not always present
    has_brotli = b"brotli" in data.lower() or b"/assets/" in data

    report = {
        "rustc_paths_sample": [p.decode("utf-8", "replace") for p in panic_paths[:40]],
        "crates_seen": sorted({c.decode() for c in crates}),
        "urls_sample": [u.decode("utf-8", "replace") for u in urls[:40]],
        "tauri_like": bool(b"WebView2" in data or b"tauri" in data.lower() or has_brotli),
        "brotli_related": has_brotli,
        "plan": [
            "map Tauri command dispatch hash table (string hashes → handlers)",
            "extract embedded frontend assets (brotli/resource table) for JS patch analysis",
            "trace attach/update as process graph — do not assume classic inject APIs",
            "for string encryption: prefer dynamic intercept over static XOR assumptions",
        ],
        "potassium_notes": [
            "UI auth crack = JS bundle + mock API — not native crypto break",
            "DLL SIMD-XOR strings ≠ packer layer",
            "child PE holds inject primitive — missing stub fails whole chain",
        ],
    }
    if report["tauri_like"]:
        from street_decrepytor.deobf.rust_rt.tauri_extract import extract_tauri_assets, inventory_tauri_ipc

        assets = extract_tauri_assets(data, out_dir / "tauri_assets")
        ipc = inventory_tauri_ipc(data)
        report["tauri_extract"] = {
            "asset_count": len(assets),
            "assets": assets[:20],
            "ipc": {k: ipc[k] for k in ("is_tauri", "custom_commands", "has_fs_plugin", "has_shell_plugin") if k in ipc},
        }
    (out_dir / "deobf_rust.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
