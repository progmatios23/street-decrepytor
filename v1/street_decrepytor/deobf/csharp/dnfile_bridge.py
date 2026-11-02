# language: Python 3, file: dnfile_bridge.py
# .NET metadata bridge — dnfile when installed, else raw CLR heuristics
from __future__ import annotations

import json
import re
import struct
from pathlib import Path
from typing import Any


def _try_dnfile(path: Path) -> dict[str, Any] | None:
    try:
        import dnfile  # type: ignore
    except ImportError:
        return None
    try:
        pe = dnfile.dnPE(str(path))
    except Exception as e:
        return {"error": f"dnfile_open: {e}"}
    out: dict[str, Any] = {"engine": "dnfile", "modules": [], "typedefs_sample": [], "resources": []}
    if not getattr(pe, "net", None):
        return {"engine": "dnfile", "is_clr": False}
    out["is_clr"] = True
    md = pe.net.metadata
    if md is None:
        return out
    # streams
    try:
        out["streams"] = [s.struct.Name.decode("utf-8", "replace") if hasattr(s.struct, "Name") else str(s) for s in md.streams_list]
    except Exception:
        out["streams"] = []
    # TypeDef names
    try:
        td = pe.net.mdtables.TypeDef
        if td:
            for row in list(td)[:80]:
                ns = getattr(row, "TypeNamespace", None) or ""
                name = getattr(row, "TypeName", None) or ""
                if hasattr(ns, "value"):
                    ns = ns.value
                if hasattr(name, "value"):
                    name = name.value
                out["typedefs_sample"].append(f"{ns}.{name}".strip("."))
    except Exception as e:
        out["typedef_error"] = str(e)
    # user strings stream size
    try:
        us = pe.net.user_strings
        if us is not None:
            out["user_strings_present"] = True
    except Exception:
        out["user_strings_present"] = False
    return out


def _raw_clr_scan(data: bytes) -> dict[str, Any]:
    markers = {
        "ConfusedByAttribute": b"ConfusedByAttribute" in data,
        "ConfuserEx": b"ConfuserEx" in data or b"Confuser.Core" in data,
        "SmartAssembly": b"SmartAssembly" in data,
        "DNGuard": b"DNGuard" in data or b"HVMRuntm" in data,
        "Agile": b"AgileDotNet" in data or b"Agile.NET" in data,
        "Obfuscar": b"Obfuscar" in data,
        "Module_cctor": b".cctor" in data,
        "GetString": b"GetString" in data,
    }
    # #US heap rough: count UTF-16-ish runs after BSJB
    bsjb = data.find(b"BSJB")
    return {
        "engine": "raw",
        "is_clr": bsjb >= 0 or b"mscoree.dll" in data.lower(),
        "bsjb_off": bsjb,
        "markers": markers,
        "anti_tamper_suspect": markers["Module_cctor"] and (markers["ConfuserEx"] or markers["ConfusedByAttribute"]),
    }


def confuserex_constant_plan(meta: dict[str, Any]) -> list[str]:
    return [
        "1. Locate <Module>..cctor — anti-tamper / anti-dump often here",
        "2. Dump module AFTER cctor completes (debugger or frida on compileMethod)",
        "3. Find decryptor methods: static string Xxx(int id) bodies",
        "4. Emulate decryptor offline OR hook Encoding.UTF8.GetString",
        "5. Rebuild constants table → patch #US / ldstr consumers",
        "6. Undo control-flow (switch dispatchers) with de4dot-cex / NoFuserEx",
        "7. Re-derive per build — never reuse method tokens across versions",
    ]


def analyze_dotnet_assembly(path: str | Path) -> dict[str, Any]:
    path = Path(path)
    data = path.read_bytes()
    raw = _raw_clr_scan(data)
    dn = _try_dnfile(path)
    report = {
        "path": str(path),
        "raw": raw,
        "dnfile": dn,
        "plan": confuserex_constant_plan(raw),
        "cctor_dump_recipe": cctor_dump_recipe(),
    }
    return report


def cctor_dump_recipe() -> dict[str, Any]:
    """Auto-dump recipe after Module.cctor — Frida + dnSpy-class workflow."""
    return {
        "goal": "capture decrypted IL after module initializer",
        "frida_snippet": r"""
// attach to CLR process hosting target assembly
const clrjit = Process.findModuleByName('clrjit.dll') || Process.findModuleByName('mscorjit.dll');
if (clrjit) {
  const compile = Module.findExportByName(clrjit.name, 'getJit');
  console.log('jit helper', compile);
}
// fallback: dump when VirtualProtect makes .text RX after unpack
Interceptor.attach(Module.findExportByName('kernel32.dll','VirtualProtect'), {
  onEnter(args) { this.addr = args[0]; this.size = args[1].toInt32(); this.prot = args[2].toInt32(); },
  onLeave(retval) {
    if (this.prot === 0x20 || this.prot === 0x40) // RX / RWX
      console.log('VP', this.addr, this.size, this.prot);
  }
});
""",
        "manual": [
            "x64dbg/dnSpyEx: bp on module cctor end / ret",
            "MegaDumper / ExtremeDumper: dump after first managed entry",
            "Street: sdc pe-dump <pid> --module Target.dll",
        ],
        "defeats": "static empty method bodies under anti-tamper",
        "caught_by": "runtime integrity re-encrypt, server-side license",
    }


def stage_dotnet_bridge(profile: Any, out_dir: Path) -> dict[str, Any]:
    from street_decrepytor.core.artifact import LangFamily

    if profile.family not in (LangFamily.DOTNET, LangFamily.CPP_CLI, LangFamily.MIXED):
        # still scan if CLR directory present
        if not profile.pe_info.get("clr_rva"):
            return {"skipped": True}
    report = analyze_dotnet_assembly(profile.path)
    Path(out_dir, "dotnet_bridge.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return {
        "is_clr": (report.get("dnfile") or report.get("raw") or {}).get("is_clr"),
        "engine": (report.get("dnfile") or {}).get("engine") or "raw",
        "markers": (report.get("raw") or {}).get("markers"),
    }
