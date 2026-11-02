# language: Python 3 — real inventory of Program Files\umi\umi.exe
from __future__ import annotations

import hashlib
import json
import re
import struct
from pathlib import Path

TARGET = Path(r"C:\Program Files\umi\umi.exe")
OUT = Path(r"D:\Street-decrepytor\output\unpack\umi")


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    data = TARGET.read_bytes()
    report: dict = {
        "path": str(TARGET),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }

    # Tauri plugin commands
    plugins = sorted({m.decode("ascii") for m in re.findall(rb"plugin:[a-zA-Z0-9_]+(?:\|[a-zA-Z0-9_]+)?", data)})
    report["tauri_plugin_commands"] = plugins

    # JS invoke calls
    js_invokes = sorted(
        {
            m.decode("ascii", "ignore")
            for m in re.findall(rb"invoke\(\s*['\"]([^'\"]{2,80})['\"]", data)
        }
    )
    report["js_invoke_literals"] = js_invokes

    internals = sorted(
        {
            m.decode("ascii", "ignore")
            for m in re.findall(rb"__TAURI_INTERNALS__\.invoke\(\s*['\"]([^'\"]+)['\"]", data)
        }
    )
    report["tauri_internals_invoke"] = internals

    # custom commands = invokes that are not plugin:*
    custom = [c for c in js_invokes + internals if not c.startswith("plugin:")]
    report["custom_commands"] = sorted(set(custom))

    # URLs (cleaner)
    urls = sorted(
        {
            u.decode("ascii", "ignore")
            for u in re.findall(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,100}", data)
            if b" " not in u and b"<" not in u
        }
    )
    # filter garbage from concatenated dicts
    urls = [u for u in urls if re.match(r"https?://[a-zA-Z0-9]", u) and len(u) < 80]
    report["urls"] = urls[:40]

    # extract HTML/JS assets from PE image
    assets = OUT / "tauri_assets"
    assets.mkdir(exist_ok=True)
    extracted = []
    idx = 0
    n = 0
    while n < 8:
        i = data.find(b"<!DOCTYPE html", idx)
        if i < 0:
            i = data.find(b"<html", idx)
        if i < 0:
            break
        j = data.find(b"</html>", i)
        j = (j + 7) if j > 0 else min(len(data), i + 80000)
        blob = data[i:j]
        path = assets / f"page_{n}.html"
        path.write_bytes(blob)
        extracted.append({"kind": "html", "off": hex(i), "size": len(blob), "path": str(path)})
        n += 1
        idx = j

    # large scripts containing TAURI
    for m in re.finditer(rb"(?s)(?:\(function|\{\}|window\.|__TAURI)[\x20-\x7e\r\n\t]{800,}", data):
        s = m.group()
        if b"__TAURI" not in s and b"invoke" not in s:
            continue
        path = assets / f"bundle_{m.start():08x}.js"
        path.write_bytes(s[:300000])
        extracted.append({"kind": "js", "off": hex(m.start()), "size": min(len(s), 300000), "path": str(path)})
        if sum(1 for e in extracted if e["kind"] == "js") >= 10:
            break
    report["extracted_assets"] = extracted

    # read page 0 summary
    p0 = assets / "page_0.html"
    if p0.exists():
        html = p0.read_text("utf-8", "replace")
        title = re.search(r"<title>([^<]+)</title>", html, re.I)
        report["ui_title"] = title.group(1) if title else None
        report["html_preview"] = html[:1200]

    # behavior conclusion
    has_shell_open = any("shell|open" in p or p.endswith("shell|open") for p in plugins)
    has_fs = any(p.startswith("plugin:fs") for p in plugins)
    report["behavior"] = {
        "stack": "Rust + Tauri + WebView2 (wry)",
        "product": "umi 0.1.0 (CompanyName=umi)",
        "config_sidecar": str(TARGET.parent / "config.json"),
        "capabilities": {
            "filesystem_plugin": has_fs,
            "shell_open": has_shell_open,
            "dialog": any(p.startswith("plugin:dialog") for p in plugins),
            "window": any(p.startswith("plugin:window") for p in plugins),
            "custom_rust_commands": report["custom_commands"],
        },
        "notes": [
            "Not Themida-packed — normal PE sections, EP in .text",
            "Frontend embedded in PE image (HTML/JS), not classic PE resources",
            "Program Files install is thin (exe+config); ANALISTAR has separate .NET Umi.exe host",
            "First-pass unpack missed Tauri assets — fixed by tauri extractor",
        ],
    }

    (OUT / "UMI_INVENTORY.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    md = [
        "# umi.exe — inventory & behavior",
        "",
        f"**Path:** `{TARGET}`",
        f"**SHA256:** `{report['sha256']}`",
        f"**Size:** {report['size']}",
        f"**Title:** {report.get('ui_title')}",
        "",
        "## What it is",
        "- Rust/Tauri/WebView2 desktop shell (`umi` 0.1.0)",
        "- UI theme from `config.json` (graphite, 940x560)",
        "- Standard Tauri plugins dominate IPC surface",
        "",
        "## Custom commands (non-plugin)",
        *(["- (none found in invoke literals)"] if not report["custom_commands"] else [f"- `{c}`" for c in report["custom_commands"]]),
        "",
        "## Plugin surface (sample)",
    ]
    for p in plugins[:40]:
        md.append(f"- `{p}`")
    if len(plugins) > 40:
        md.append(f"- … +{len(plugins)-40} more")
    md += ["", "## Extracted assets"]
    for e in extracted:
        md.append(f"- {e['kind']} @ {e['off']} → `{e['path']}` ({e['size']} b)")
    md += ["", "## URLs"]
    for u in urls[:20]:
        md.append(f"- `{u}`")
    (OUT / "UMI_INVENTORY.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps({
        "sha16": report["sha256"][:16],
        "plugins": len(plugins),
        "custom": report["custom_commands"],
        "assets": len(extracted),
        "title": report.get("ui_title"),
        "urls": urls[:10],
        "out": str(OUT),
    }, indent=2))


if __name__ == "__main__":
    main()
