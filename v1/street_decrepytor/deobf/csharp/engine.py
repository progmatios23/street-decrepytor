# language: Python 3, file: csharp/engine.py
# .NET deobfuscation engine — ConfuserEx, SmartAssembly, DNGuard, Agile.NET, Obfuscar
from __future__ import annotations

import json
import re
import struct
from pathlib import Path
from typing import Any

from street_decrepytor.core.artifact import ArtifactProfile

OBFUSCATOR_MARKERS = {
    "ConfuserEx": [rb"ConfuserEx", rb"ConfusedByAttribute", rb"Confuser\.Core"],
    "SmartAssembly": [rb"SmartAssembly", rb"Powered by SmartAssembly"],
    "DNGuard": [rb"DNGuard", rb"HVMRuntm.dll", rb"HVMProtect"],
    "Agile.NET": [rb"AgileDotNet", rb"Agile\.NET", rb"CliSecure"],
    "Obfuscar": [rb"Obfuscar", rb"ObfuscatedByObfuscar"],
    "Eazfuscator": [rb"Eazfuscator"],
    ".NET Reactor": [rb".NET Reactor", rb"Unknown .NET Reactor"],
    "Babel": [rb"BabelObfuscator", rb"Babel\.Attribute"],
    "Dotfuscator": [rb"Dotfuscator", rb"DotfuscatorAttribute"],
}


def _read_clr_flags(data: bytes) -> dict[str, Any]:
    info: dict[str, Any] = {"is_clr": False}
    if data[:2] != b"MZ":
        return info
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    magic = struct.unpack_from("<H", data, e_lfanew + 0x18)[0]
    dd = e_lfanew + 0x18 + (0x60 if magic == 0x10B else 0x70)
    if dd + 15 * 8 > len(data):
        return info
    clr_rva, clr_size = struct.unpack_from("<II", data, dd + 14 * 8)
    info["clr_rva"] = clr_rva
    info["clr_size"] = clr_size
    info["is_clr"] = bool(clr_rva and clr_size)
    return info


def detect_dotnet_obfuscators(data: bytes) -> list[dict[str, Any]]:
    hits = []
    for name, pats in OBFUSCATOR_MARKERS.items():
        for p in pats:
            if re.search(p, data, re.I):
                hits.append({"name": name, "pattern": p.decode("latin-1", "replace")})
                break
    return hits


def control_flow_flatten_hints(data: bytes) -> dict[str, Any]:
    """
    ConfuserEx / SA control-flow: switch dispatchers, opaque predicates.
    Without dnlib we score IL-ish patterns in #US / method bodies via raw heuristics.
    """
    # high density of br.s / switch opcodes in method-sized islands is a smell
    # IL opcodes: switch=0x45, br=0x38, br.s=0x2B
    switch_c = data.count(b"\x45")
    brs = data.count(b"\x2b")
    return {
        "raw_switch_byte_count": switch_c,
        "raw_br_s_byte_count": brs,
        "cff_suspect": switch_c > 200 and brs > 500,
        "note": "raw byte density only — confirm with dnlib/ILSpy stage when available",
    }


def string_encryption_hints(data: bytes) -> dict[str, Any]:
    # ConfuserEx string decryptor methods often call Encoding.UTF8.GetString after crypto
    markers = []
    for s in (b"GetString", b"Decrypt", b"\x00<Module>\x00", b".cctor"):
        if s in data:
            markers.append(s.decode("latin-1", "replace"))
    return {
        "markers": markers,
        "likely_runtime_string_decrypt": b"GetString" in data and (b"Decrypt" in data or b"xor" in data.lower()),
    }


def deobf_plan(obfuscators: list[dict[str, Any]]) -> list[dict[str, Any]]:
    plans = []
    names = {o["name"] for o in obfuscators}
    if "ConfuserEx" in names or not names:
        plans.append({
            "obfuscator": "ConfuserEx*",
            "pipeline": [
                "detect anti-tamper / anti-dump (module cctor)",
                "run under debugger or dump after cctor (NoFuserEx / de4dot-cex style)",
                "resolve proxy delegates / ref proxy",
                "decrypt constants (constants resource + decryptor method)",
                "undo control-flow (switch dispatcher → original blocks)",
                "restore resource names",
            ],
            "tools_interop": ["de4dot", "NoFuserEx", "dnlib", "ILSpy", "dnSpyEx"],
        })
    if "SmartAssembly" in names:
        plans.append({
            "obfuscator": "SmartAssembly",
            "pipeline": [
                "locate {SmartAssembly}.Resource / strings encoding",
                "emulate string decryptor or hook Encoding.GetString",
                "remove control flow + delegate call proxies",
            ],
        })
    if "DNGuard" in names:
        plans.append({
            "obfuscator": "DNGuard",
            "pipeline": [
                "HVM runtime dump after methods JIT",
                "collect native VM stubs; dump IL post-restore",
                "re-derive per build — static IL often empty shells",
            ],
        })
    if "Agile.NET" in names:
        plans.append({
            "obfuscator": "Agile.NET",
            "pipeline": [
                "unpack Runtime.dll companion if present",
                "method body decryption at invoke — dump via DynamicMethod or JIT hook",
            ],
        })
    if "Obfuscar" in names:
        plans.append({
            "obfuscator": "Obfuscar",
            "pipeline": [
                "rename map if shipped; else semantic rename via usage graphs",
                "string encryption optional — run decryptor methods offline",
            ],
        })
    return plans


def deobf_dotnet(profile: ArtifactProfile, out_dir: Path) -> dict[str, Any]:
    data = Path(profile.path).read_bytes()
    clr = _read_clr_flags(data)
    obf = detect_dotnet_obfuscators(data)
    from street_decrepytor.deobf.csharp.dnfile_bridge import analyze_dotnet_assembly, cctor_dump_recipe

    bridge = analyze_dotnet_assembly(profile.path)
    report = {
        "clr": clr,
        "obfuscators": obf,
        "control_flow": control_flow_flatten_hints(data),
        "strings": string_encryption_hints(data),
        "plan": deobf_plan(obf),
        "dn_bridge": {
            "engine": (bridge.get("dnfile") or {}).get("engine") or "raw",
            "markers": (bridge.get("raw") or {}).get("markers"),
            "typedefs_sample": (bridge.get("dnfile") or {}).get("typedefs_sample", [])[:20],
        },
        "cctor_dump_recipe": cctor_dump_recipe(),
        "output_actions": [
            "Write candidate decryptor RVAs to deobf_dotnet_plan.json",
            "Prefer dynamic dump after Module.cctor over static IL guess",
            "Use sdc pe-dump <pid> --module after cctor; sdc frida-run --family dotnet",
        ],
    }
    (out_dir / "deobf_dotnet.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
