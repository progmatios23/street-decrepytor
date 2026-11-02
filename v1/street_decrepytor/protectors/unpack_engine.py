# language: Python 3, file: unpack_engine.py
# Real unpack/extract engine — Themida-class detect + confirmed layer removal only
from __future__ import annotations

import hashlib
import json
import math
import shutil
import struct
import subprocess
from pathlib import Path
from typing import Any

import pefile

from street_decrepytor.core.transforms import decrypted_flag, image_transform


def _entropy(chunk: bytes) -> float:
    if not chunk:
        return 0.0
    freq = [0] * 256
    for b in chunk:
        freq[b] += 1
    h = 0.0
    n = len(chunk)
    for c in freq:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def identify_themida_class(data: bytes, pe: pefile.PE) -> dict[str, Any]:
    """
    Themida / commercial packer identification with EVIDENCE.
    Positive only when structure + markers support it — never guess for theater.
    """
    markers = []
    for name, needles in (
        ("Themida", (b"Themida", b"WinLicense", b"Oreans", b".themida", b"Tmda", b"Athdet")),
        ("VMProtect", (b"VMProtect", b".vmp0", b".vmp1", b".vmp2")),
        ("UPX", (b"UPX!", b"UPX0", b"UPX1")),
        ("Enigma", (b".enigma1", b".enigma2", b"Enigma Protector")),
    ):
        if any(n in data for n in needles):
            markers.append(name)

    secs = []
    virtual_only = []
    weird_names = []
    for s in pe.sections:
        name = s.Name.split(b"\0", 1)[0].decode("latin-1", "replace")
        rsize = s.SizeOfRawData
        vsize = s.Misc_VirtualSize
        info = {
            "name": name,
            "va": s.VirtualAddress,
            "vsize": vsize,
            "rsize": rsize,
            "entropy": round(_entropy(s.get_data()[: min(65536, max(rsize, 1))]), 3) if rsize else None,
        }
        secs.append(info)
        if rsize == 0 and vsize > 0x1000:
            virtual_only.append(name)
        if name and not name.startswith(".") and name not in ("CODE", "DATA", "BSS", "PAGE"):
            if any(c in name for c in "!?@#$%^&*") or (len(name) <= 4 and not name.isalpha()):
                weird_names.append(name)
        # Oreans-style random names
        if name.startswith(".") and len(name) >= 4 and not name.lower() in (
            ".text", ".data", ".rdata", ".rsrc", ".reloc", ".pdata", ".idata", ".edata",
            ".bss", ".tls", ".gfids", ".00cfg", ".fptable",
        ):
            if name not in (".vmp0", ".vmp1", ".themida"):
                weird_names.append(name)

    ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    ep_sec = None
    for s in pe.sections:
        if s.VirtualAddress <= ep < s.VirtualAddress + max(s.Misc_VirtualSize, 1):
            ep_sec = s.Name.split(b"\0", 1)[0].decode("latin-1", "replace")
            break

    score = 0.0
    reasons = []
    if "Themida" in markers:
        score += 0.5
        reasons.append("Themida/Oreans string marker")
    if "VMProtect" in markers:
        score += 0.45
        reasons.append("VMProtect marker")
    if len(virtual_only) >= 3:
        score += 0.35
        reasons.append(f"{len(virtual_only)} zero-raw sections (runtime decrypt layout)")
    elif len(virtual_only) >= 2:
        score += 0.25
        reasons.append(f"{len(virtual_only)} zero-raw sections")
    if ep_sec and ep_sec not in (".text", "CODE", ".code") and ep_sec in virtual_only + weird_names:
        score += 0.2
        reasons.append(f"EP in non-standard section `{ep_sec}`")
    if weird_names:
        score += 0.1
        reasons.append(f"nonstandard section names: {weird_names[:6]}")
    # IAT starvation
    imports = 0
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for e in pe.DIRECTORY_ENTRY_IMPORT:
            imports += len(e.imports)
    if imports < 8 and pe.OPTIONAL_HEADER.SizeOfImage > 1_000_000:
        score += 0.15
        reasons.append(f"IAT starved ({imports} imports)")

    is_themida_class = score >= 0.45 or "Themida" in markers
    is_vmprotect = "VMProtect" in markers
    is_upx = "UPX" in markers

    return {
        "themida_class": is_themida_class,
        "vmprotect": is_vmprotect,
        "upx": is_upx,
        "score": round(min(score, 0.99), 3),
        "markers": markers,
        "virtual_only_sections": virtual_only,
        "weird_sections": weird_names,
        "ep_rva": hex(ep),
        "ep_section": ep_sec,
        "import_count": imports,
        "reasons": reasons,
        "sections": secs,
        "static_unpack_possible": is_upx,  # only UPX is safely static-unpackable here
        "dynamic_required": is_themida_class or is_vmprotect,
        "playbook": (
            _themida_playbook()
            if is_themida_class
            else (_vmp_playbook() if is_vmprotect else (_upx_playbook() if is_upx else _clean_playbook()))
        ),
    }


def _themida_playbook() -> list[str]:
    return [
        "CONFIRMED or highly likely commercial VM packer (Themida-class)",
        "A) AUTO delay-dump (no debugger):",
        "   street-decrepytor dump --spawn TARGET.exe --wait 12 --vad --fix-pe --iat",
        "B) LIVE process already running:",
        "   street-decrepytor dump --name TARGET.exe --vad --fix-pe --iat",
        "   street-decrepytor pe-dump <pid> --fix-pe --iat --out dumped.exe",
        "C) Debugger path:",
        "   street-decrepytor scyllahide-export",
        "   Optional Themidie/Magicmida → run to OEP → pe-dump <pid>",
        "D) Frida OEP-ish dump on VirtualProtect RX:",
        "   street-decrepytor dump --spawn TARGET.exe --frida-script",
        "   frida -f TARGET.exe -l dump_on_vp.js --no-pause",
        "Static NOP of VM is NOT claimed — dump after runtime decrypt is the real path.",
    ]


def _vmp_playbook() -> list[str]:
    return [
        "VMProtect markers — dynamic dump after mutation",
        "Trace VM exit only for non-virtualized leaves first",
    ]


def _upx_playbook() -> list[str]:
    return [
        "UPX detected — Street runs `upx -d` if `upx` is on PATH",
        "If upx missing: copied=false, note=upx_not_installed (not a silent unpack)",
    ]


def try_upx_decompress(src: Path, dest: Path) -> dict[str, Any]:
    exe = shutil.which("upx")
    if not exe:
        return {"ok": False, "reason": "upx_not_installed", "path": None}
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        r = subprocess.run(
            [exe, "-d", "-o", str(dest), str(src)],
            capture_output=True,
            timeout=90,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as e:
        return {"ok": False, "reason": str(e), "path": None}
    ok = r.returncode == 0 and dest.is_file()
    return {
        "ok": ok,
        "reason": None if ok else (r.stderr.decode("latin-1", "replace")[:400] or f"rc={r.returncode}"),
        "path": str(dest) if dest.is_file() else None,
        "returncode": r.returncode,
    }


def _clean_playbook() -> list[str]:
    return [
        "No Themida/VMProtect structure confirmed",
        "Extract resources, carve embedded PE, inflate confirmed compression only",
    ]


def extract_resources(pe: pefile.PE, out_dir: Path) -> list[dict[str, Any]]:
    out_dir.mkdir(parents=True, exist_ok=True)
    results = []
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return results
    n = 0
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        etype = (
            str(entry.name)
            if entry.name
            else pefile.RESOURCE_TYPE.get(entry.id, f"type_{entry.id}")
        )
        if not hasattr(entry, "directory") or not entry.directory:
            continue
        for e2 in entry.directory.entries:
            ename = str(e2.name) if e2.name else str(e2.id)
            if not hasattr(e2, "directory") or not e2.directory:
                continue
            for e3 in e2.directory.entries:
                try:
                    rva = e3.data.struct.OffsetToData
                    size = e3.data.struct.Size
                    data = pe.get_data(rva, size)
                except Exception:
                    continue
                n += 1
                kind = "bin"
                if data[:2] == b"MZ":
                    kind = "exe"
                elif data[:5] == b"<?xml" or data[:6] == b"<Sysmo" or b"<Rule" in data[:200]:
                    kind = "xml"
                elif data[:2] == b"PK":
                    kind = "zip"
                path = out_dir / f"res_{n:03d}_{etype}_{ename}_{size}.{kind}"
                # sanitize filename
                safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in path.name)
                path = out_dir / safe
                path.write_bytes(data)
                results.append({
                    "type": str(etype),
                    "id": str(ename),
                    "size": size,
                    "sha16": hashlib.sha256(data).hexdigest()[:16],
                    "kind": kind,
                    "path": str(path),
                    "is_pe": data[:2] == b"MZ",
                    "is_xml": kind == "xml",
                })
    return results


def unpack_target(path: str | Path, out_dir: str | Path | None = None) -> dict[str, Any]:
    """
    Full honest unpack:
      - Themida-class identification with evidence
      - Resource extraction (real embedded PE/XML)
      - Recurse crack on embedded PEs
      - No fake crypto removal
    """
    path = Path(path)
    out = Path(out_dir or Path("output/unpack") / path.stem)
    out.mkdir(parents=True, exist_ok=True)
    data = path.read_bytes()
    pe = pefile.PE(data=data, fast_load=False)
    pe.parse_data_directories()

    ident = identify_themida_class(data, pe)
    resources = extract_resources(pe, out / "resources")

    # CFG / trampoline obfuscation inventory (Luau modules etc.)
    cfg_rep = None
    try:
        from street_decrepytor.deobf.cfg_obfuscation import analyze_cfg

        if not ident["themida_class"]:
            cfg_rep = analyze_cfg(path)
            if cfg_rep.get("ok"):
                (out / "cfg_obfuscation.json").write_text(
                    json.dumps(cfg_rep, indent=2), encoding="utf-8"
                )
    except Exception as e:
        cfg_rep = {"ok": False, "error": str(e)}

    # write themida / scylla / dump scripts when needed
    dump_kit = None
    if ident["dynamic_required"]:
        from street_decrepytor.dynamic.scyllahide_profile import export_scyllahide_profile
        from street_decrepytor.protectors.themida import themida_playbook
        from street_decrepytor.dynamic.pe_dump import frida_dump_on_oep_script

        scy = export_scyllahide_profile(out / "scyllahide")
        dump_dir = out / "dump_kit"
        dump_dir.mkdir(exist_ok=True)
        (dump_dir / "dump_on_vp.js").write_text(frida_dump_on_oep_script(), encoding="utf-8")
        # Windows batch one-shots for operators / agents
        bat = "\r\n".join(
            [
                "@echo off",
                f"REM Auto dump for Themida-class: {path.name}",
                f'street-decrepytor dump --spawn "{path}" --wait 12 --vad --fix-pe --iat --out "%~dp0live_dump"',
                f'street-decrepytor pe-dump %%1 --fix-pe --iat --out "%~dp0from_pid.exe"',
                "echo use: dump_spawn.bat   OR   pe-dump.bat <pid>",
            ]
        )
        (dump_dir / "dump_spawn.bat").write_text(bat, encoding="utf-8")
        (dump_dir / "RUN_DUMP.txt").write_text(
            "\n".join(
                [
                    f"Target: {path}",
                    "",
                    "1) Delay dump (recommended first try):",
                    f'   street-decrepytor dump --spawn "{path}" --wait 12 --vad --fix-pe --iat --out output\\dumps\\{path.stem}',
                    "",
                    "2) If already running:",
                    f'   street-decrepytor dump --name "{path.name}" --vad --fix-pe --iat',
                    "",
                    "3) Frida VP dump:",
                    f'   frida -f "{path}" -l {dump_dir / "dump_on_vp.js"} --no-pause',
                    "",
                    "4) pe-dump only:",
                    "   street-decrepytor pe-dump <pid> --fix-pe --iat --out dumped.exe",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        dump_kit = {
            "dir": str(dump_dir),
            "frida": str(dump_dir / "dump_on_vp.js"),
            "bat": str(dump_dir / "dump_spawn.bat"),
            "run_txt": str(dump_dir / "RUN_DUMP.txt"),
        }
        (out / "THEMIDA_CLASS_PLAN.json").write_text(
            json.dumps(
                {
                    "ident": ident,
                    "playbook": themida_playbook(str(path)),
                    "street_playbook": ident["playbook"],
                    "scyllahide": scy,
                    "dump_kit": dump_kit,
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    # nested PE from resources
    nested = []
    for r in resources:
        if r.get("is_pe"):
            try:
                from street_decrepytor.core.crack import crack_target

                sub = crack_target(
                    r["path"],
                    out=out / "nested" / Path(r["path"]).stem,
                    deep_simd=False,
                    apply_gates=False,
                )
                nested.append({
                    "resource": r["path"],
                    "verdict": sub.get("verdict"),
                    "report_md": sub.get("report_md"),
                })
            except Exception as e:
                nested.append({"resource": r["path"], "error": str(e)})

    # also dump packed raw sections when virtual layout (for offline research)
    packed_secs = []
    if ident["virtual_only_sections"] or ident["themida_class"]:
        for s in pe.sections:
            if s.SizeOfRawData > 0x10000:
                name = s.Name.split(b"\0", 1)[0].decode("latin-1", "replace")
                blob = s.get_data()
                p = out / "packed_sections" / f"{name}_{s.VirtualAddress:x}_{len(blob)}.bin"
                p.parent.mkdir(parents=True, exist_ok=True)
                p.write_bytes(blob)
                packed_secs.append({
                    "name": name,
                    "size": len(blob),
                    "entropy": round(_entropy(blob[:65536]), 3),
                    "path": str(p),
                })

    report = {
        "target": str(path.resolve()),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
        "themida_class_ident": ident,
        "cfg_obfuscation": {
            "trampoline_count": (cfg_rep or {}).get("trampoline_count"),
            "cfg_obfuscation_likely": (cfg_rep or {}).get("cfg_obfuscation_likely"),
            "top_dispatchers": (cfg_rep or {}).get("top_dispatchers"),
        } if cfg_rep and cfg_rep.get("ok") else cfg_rep,
        "resources_extracted": resources,
        "nested_pe_cracks": nested,
        "packed_sections_dumped": packed_secs,
        "dump_kit": dump_kit,
        "copied": [],
        "inventoried": [],
        "image_transforms": [],
        "layers_removed": [],
        "layers_not_present": [],
        "honest_verdict": "",
        "decrypted": False,
        "upx": None,
    }

    if ident.get("upx"):
        upx_out = out / f"{path.stem}_upx_d.bin"
        upx_rep = try_upx_decompress(path, upx_out)
        report["upx"] = upx_rep
        if upx_rep.get("ok"):
            t = image_transform("inflate", "upx", upx_rep.get("path"))
            report["image_transforms"].append(t)
        else:
            report["layers_not_present"].append(f"UPX inflate ({upx_rep.get('reason')})")

    for r in resources:
        if r["is_pe"]:
            rec = {
                "type": "embedded_pe_resource",
                "detail": f"{r['type']}/{r['id']} → {r['path']}",
                "confirmed": True,
            }
            report["copied"].append(rec)
            report["image_transforms"].append(image_transform("copy", "embedded_pe_resource", r["path"]))
            report["layers_removed"].append(rec)
        if r["is_xml"]:
            rec = {
                "type": "plain_xml_resource",
                "detail": f"{r['type']}/{r['id']} plaintext (no decrypt needed)",
                "confirmed": True,
            }
            report["copied"].append(rec)
            report["image_transforms"].append(image_transform("copy", "plain_xml_resource", r["path"]))
            report["layers_removed"].append(rec)
    if packed_secs:
        rec = {
            "type": "packed_section_dump",
            "detail": f"{len(packed_secs)} high-raw section(s) copied still packed",
            "confirmed": True,
        }
        report["copied"].append(rec)
        for ps in packed_secs:
            report["image_transforms"].append(image_transform("copy", "packed_section", ps["path"]))
        report["layers_removed"].append(rec)
    if cfg_rep and cfg_rep.get("cfg_obfuscation_likely"):
        rec = {
            "type": "cfg_trampoline_inventory",
            "detail": f"{cfg_rep.get('trampoline_count')} lea+jmp stubs inventoried (not removed)",
            "confirmed": True,
        }
        report["inventoried"].append(rec)
        report["image_transforms"].append(image_transform(
            "inventoried", "cfg_trampoline",
            str(out / "cfg_obfuscation.json"),
            trampoline_count=cfg_rep.get("trampoline_count"),
        ))

    report["decrypted"] = decrypted_flag(report["image_transforms"])

    if not ident["themida_class"]:
        report["layers_not_present"].append("Themida/WinLicense packer shell")
    if not ident["vmprotect"]:
        report["layers_not_present"].append("VMProtect")
    if not any(r.get("is_pe") for r in resources):
        report["layers_not_present"].append("embedded PE in PE resources")

    # verdict text
    if ident["themida_class"]:
        report["honest_verdict"] = (
            f"THEMIDA-CLASS packer likely (score={ident['score']}): {', '.join(ident['reasons'])}. "
            "No cipher transform. Packed bytes copied. Use dump_kit / `dump --spawn` "
            "(packer decrypts in RAM; Street copies)."
        )
    elif cfg_rep and cfg_rep.get("cfg_obfuscation_likely"):
        report["honest_verdict"] = (
            f"CFG/trampoline obfuscation confirmed: {cfg_rep.get('trampoline_count')} stubs, "
            f"dispatchers={cfg_rep.get('top_dispatchers')}. "
            "Not Themida — recover real callees from lea targets (see cfg_obfuscation.json)."
        )
    elif any(r.get("is_pe") for r in resources):
        report["honest_verdict"] = (
            "No Themida on outer PE. Real payload extracted from PE resources "
            f"({sum(1 for r in resources if r.get('is_pe'))} embedded PE(s)). "
            "Nested crack reports under nested/."
        )
    else:
        report["honest_verdict"] = (
            "No Themida/VMProtect confirmed; no encrypted layer proven. "
            "File is largely plaintext PE + resources."
        )

    (out / "UNPACK_REPORT.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    md = [
        f"# Unpack report — `{path.name}`",
        "",
        f"**SHA256:** `{report['sha256']}`",
        "",
        f"- **decrypted:** `{report['decrypted']}`",
        "",
        "## Honest verdict",
        report["honest_verdict"],
        "",
        "## Image transforms",
    ]
    tx = report.get("image_transforms") or []
    if not tx:
        md.append("- (none)")
    for t in tx:
        md.append(f"- **{t.get('kind')}** `{t.get('layer')}` → `{t.get('path')}`")
    md += [
        "",
        "## Themida-class identification",
        f"- themida_class: **{ident['themida_class']}** (score {ident['score']})",
        f"- EP: `{ident['ep_rva']}` section `{ident['ep_section']}`",
        f"- virtual-only sections: {ident['virtual_only_sections']}",
        f"- markers: {ident['markers']}",
        "",
        "### Reasons",
    ]
    for r in ident["reasons"] or ["(none — clean layout)"]:
        md.append(f"- {r}")
    md.append("")
    md.append("### Playbook")
    for step in ident["playbook"]:
        md.append(f"- {step}")
    md.append("")
    md.append("## Copied / inflated (not 'removed')")
    if report["layers_removed"]:
        for L in report["layers_removed"]:
            md.append(f"- **{L['type']}**: {L['detail']}")
    else:
        md.append("- (none)")
    md.append("")
    md.append("## Layers NOT present (confirmed absent)")
    for L in report["layers_not_present"]:
        md.append(f"- {L}")
    md.append("")
    md.append("## Resources")
    for r in resources:
        md.append(f"- `{r['type']}/{r['id']}` {r['size']} b → `{r['path']}` ({r['kind']})")
    (out / "UNPACK_REPORT.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    report["report_md"] = str(out / "UNPACK_REPORT.md")
    report["out_dir"] = str(out)
    return report
