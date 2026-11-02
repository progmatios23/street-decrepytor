# language: Python 3 — deobf/inventory %AppData%\umi\bin executor stack
from __future__ import annotations

import hashlib
import json
import re
import struct
from pathlib import Path

BIN = Path.home() / "AppData/Roaming/umi/bin"
OUT = Path(r"D:\Street-decrepytor\output\unpack\umi_bin")


def pe_imports(path: Path) -> list[dict]:
    try:
        import pefile
        pe = pefile.PE(str(path), fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        out = []
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for e in pe.DIRECTORY_ENTRY_IMPORT:
                dll = e.dll.decode("ascii", "ignore")
                names = [i.name.decode("ascii", "ignore") for i in e.imports if i.name][:40]
                out.append({"dll": dll, "apis": names})
        return out
    except Exception as e:
        return [{"error": str(e)}]


def interesting_strings(data: bytes) -> dict:
    from street_decrepytor.static.strings import extract_strings, classify_interesting
    # also raw patterns for Luau/Roblox/inject
    raw = {
        "luau": sorted(set(re.findall(rb"[A-Za-z0-9_]{0,20}[Ll]uau[A-Za-z0-9_]{0,40}", data)))[:40],
        "roblox": sorted(set(re.findall(rb"[A-Za-z0-9_]{0,10}[Rr]oblox[A-Za-z0-9_]{0,40}", data)))[:40],
        "http": sorted(set(re.findall(rb"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,100}", data)))[:30],
        "pipes": sorted(set(re.findall(rb"\\\\\.\\pipe\\[A-Za-z0-9_\-]+", data)))[:20],
        "exports_hint": sorted(set(re.findall(rb"(?:run_script|execute|inject|attach|compile|bytecode)[A-Za-z0-9_]{0,30}", data, re.I)))[:40],
    }
    for k in list(raw):
        raw[k] = [x.decode("ascii", "ignore") if isinstance(x, (bytes, bytearray)) else x for x in raw[k]]
    s = extract_strings(data, 6000)
    return {"buckets": classify_interesting(s), "raw": raw, "sample": s[:30]}


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    targets = [BIN / "injector.exe", BIN / "module.dll"]
    report = {"bin_dir": str(BIN), "targets": []}

    for t in targets:
        data = t.read_bytes()
        entry = {
            "name": t.name,
            "path": str(t),
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "imports": pe_imports(t),
            "strings": interesting_strings(data),
        }
        # exports for dll
        try:
            import pefile
            pe = pefile.PE(str(t), fast_load=True)
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                entry["exports"] = [
                    exp.name.decode("ascii", "ignore")
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols
                    if exp.name
                ][:80]
        except Exception as e:
            entry["exports_error"] = str(e)

        report["targets"].append(entry)
        (OUT / f"{t.stem}_strings.json").write_text(
            json.dumps(entry["strings"], indent=2), encoding="utf-8"
        )

    (OUT / "EXECUTOR_INVENTORY.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")

    # markdown
    lines = ["# umi bin executor inventory", "", f"**Dir:** `{BIN}`", ""]
    for t in report["targets"]:
        lines += [
            f"## {t['name']}",
            f"- size: {t['size']}",
            f"- sha256: `{t['sha256']}`",
            f"- exports: {t.get('exports', [])[:20]}",
            "- imports:",
        ]
        for imp in t["imports"][:15]:
            if "dll" in imp:
                lines.append(f"  - `{imp['dll']}`: {', '.join(imp['apis'][:12])}")
        lines.append("- roblox/luau hits:")
        for x in (t["strings"]["raw"].get("roblox") or [])[:15]:
            lines.append(f"  - `{x}`")
        for x in (t["strings"]["raw"].get("luau") or [])[:15]:
            lines.append(f"  - `{x}`")
        lines.append("- export/execute hints:")
        for x in (t["strings"]["raw"].get("exports_hint") or [])[:20]:
            lines.append(f"  - `{x}`")
        lines.append("")
    (OUT / "EXECUTOR_INVENTORY.md").write_text("\n".join(lines), encoding="utf-8")
    print(json.dumps({
        "out": str(OUT),
        "summary": [
            {
                "name": t["name"],
                "sha16": t["sha256"][:16],
                "exports": t.get("exports", [])[:10],
                "import_dlls": [i.get("dll") for i in t["imports"] if "dll" in i][:10],
                "hints": (t["strings"]["raw"].get("exports_hint") or [])[:15],
            }
            for t in report["targets"]
        ],
    }, indent=2))


if __name__ == "__main__":
    main()
