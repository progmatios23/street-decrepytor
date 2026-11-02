# language: Python 3, file: java/string_emu.py
# Java string decrypt emulator v1 — clinit / static decryptor patterns in class files
from __future__ import annotations

import json
import struct
import zipfile
from pathlib import Path
from typing import Any


def parse_class_constants(data: bytes) -> dict[str, Any]:
    """Minimal class file constant-pool string harvest (no full JVM)."""
    if len(data) < 10 or data[:4] != b"\xca\xfe\xba\xbe":
        return {"ok": False, "error": "not_class"}
    major = struct.unpack_from(">H", data, 6)[0]
    cp_count = struct.unpack_from(">H", data, 8)[0]
    i = 10
    strings: list[str] = []
    utf8_slots: dict[int, str] = {}
    idx = 1
    while idx < cp_count and i < len(data):
        tag = data[i]
        i += 1
        try:
            if tag == 1:  # Utf8
                ln = struct.unpack_from(">H", data, i)[0]
                i += 2
                s = data[i : i + ln].decode("utf-8", "replace")
                i += ln
                utf8_slots[idx] = s
                if len(s) >= 3:
                    strings.append(s)
            elif tag in (7, 8, 16, 19, 20):
                i += 2
            elif tag in (3, 4, 9, 10, 11, 12, 17, 18):
                i += 4
            elif tag in (5, 6):
                i += 8
                idx += 1  # takes two slots
            elif tag == 15:
                i += 3
            else:
                break
        except Exception:
            break
        idx += 1
    decryptor_hints = [
        s for s in strings
        if any(k in s.lower() for k in ("decrypt", "decode", "cipher", "xor", "allatori", "zelix", "stringer"))
    ]
    xor_hits = []
    for s in strings:
        raw = s.encode("utf-8", "replace")
        if len(raw) < 8:
            continue
        printable = sum(1 for b in raw if 32 <= b < 127) / len(raw)
        if printable >= 0.85:
            continue
        for h in xor_bruteforce_utf8(raw):
            xor_hits.append({"src_preview": s[:40], **h})
            if len(xor_hits) >= 20:
                break
        if len(xor_hits) >= 20:
            break
    return {
        "ok": True,
        "major": major,
        "cp_count": cp_count,
        "string_count": len(strings),
        "strings_sample": strings[:40],
        "decryptor_hints": decryptor_hints[:20],
        "xor_bruteforce": xor_hits,
    }


def xor_bruteforce_utf8(blob: bytes, max_key: int = 32) -> list[dict[str, Any]]:
    """When encrypted string arrays are raw bytes in constant pool — try short keys."""
    hits = []
    for key in range(1, max_key):
        dec = bytes(b ^ key for b in blob)
        try:
            s = dec.decode("utf-8")
        except Exception:
            continue
        if sum(c.isprintable() or c.isspace() for c in s) / max(1, len(s)) > 0.85 and len(s) >= 4:
            hits.append({"key": key, "preview": s[:80]})
            if len(hits) >= 5:
                break
    return hits


def deobf_java_strings(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    classes_out = []
    if path.suffix.lower() in (".jar", ".zip", ".war", ".apk") or path.read_bytes()[:2] == b"PK":
        with zipfile.ZipFile(path, "r") as z:
            for n in z.namelist():
                if not n.endswith(".class"):
                    continue
                raw = z.read(n)
                info = parse_class_constants(raw)
                info["class"] = n
                classes_out.append(info)
                if len(classes_out) >= 60:
                    break
    elif path.suffix.lower() == ".class":
        info = parse_class_constants(path.read_bytes())
        info["class"] = path.name
        classes_out.append(info)
    else:
        return {"error": "not_java_artifact", "path": str(path)}

    hints = []
    xor_hits = []
    for c in classes_out:
        hints.extend(c.get("decryptor_hints") or [])
        xor_hits.extend(c.get("xor_bruteforce") or [])
    return {
        "path": str(path),
        "classes_scanned": len(classes_out),
        "decryptor_hints": sorted(set(hints))[:40],
        "xor_bruteforce": xor_hits[:20],
        "classes_sample": classes_out[:15],
        "plan": [
            "Identify static decrypt(String)/decrypt(byte[]) via hints",
            "Emulate method with simple stack VM or load in isolated JVM agent",
            "Replace ldc encrypted with clear strings",
            "Export cleaned JAR → CFR/Fernflower",
        ],
    }


def stage_java_string_emu(profile: Any, out_dir: Path) -> dict[str, Any]:
    from street_decrepytor.core.artifact import LangFamily

    if profile.family != LangFamily.JAVA and not str(profile.path).lower().endswith((".jar", ".class", ".war")):
        return {"skipped": True}
    report = deobf_java_strings(profile.path)
    Path(out_dir, "java_string_emu.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return {
        "classes_scanned": report.get("classes_scanned"),
        "hints": report.get("decryptor_hints", [])[:10],
        "xor_hits": len(report.get("xor_bruteforce") or []),
    }
