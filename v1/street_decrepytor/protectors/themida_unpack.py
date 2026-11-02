# language: Python 3, file: themida_unpack.py
# Live Themida unpack: packer decrypts in RAM, Street captures + fixes PE + hunts OEP.
# This is NOT a VM lifter. decrypted=true only with .text raw-size delta.
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pefile

from street_decrepytor.core.transforms import decrypted_flag, image_transform
from street_decrepytor.dynamic.pe_dump import (
    _pe_sections_from_bytes,
    spawn_wait_dump,
)
from street_decrepytor.protectors.themida_oep import find_oep_candidates, set_entrypoint_rva
from street_decrepytor.protectors.unpack_engine import identify_themida_class


def section_raw_delta(disk: bytes, dump: bytes) -> dict[str, Any]:
    a = {s["name"]: int(s.get("rsize") or 0) for s in _pe_sections_from_bytes(disk)}
    b = {s["name"]: int(s.get("rsize") or 0) for s in _pe_sections_from_bytes(dump)}
    names = sorted(set(a) | set(b))
    rows = []
    text_delta = 0
    for n in names:
        d0, d1 = a.get(n, 0), b.get(n, 0)
        rows.append({"name": n, "disk_raw": d0, "dump_raw": d1, "delta": d1 - d0})
        if n == ".text":
            text_delta = d1 - d0
    return {"sections": rows, "text_delta": text_delta, "text_disk": a.get(".text", 0), "text_dump": b.get(".text", 0)}


def unpack_themida_live(
    target: str | Path,
    out_dir: str | Path | None = None,
    *,
    wait_sec: float = 12.0,
    wait_mode: str = "text",
    vad: bool = True,
    apply_oep: bool = True,
    force: bool = False,
    kill_after: bool = True,
) -> dict[str, Any]:
    """
    Spawn Themida-class target, neutralize PEB, wait for runtime decrypt,
    dump, fix PE, hunt OEP, write unpacked image.
    """
    target = Path(target)
    out = Path(out_dir or Path("output/themida") / target.stem)
    out.mkdir(parents=True, exist_ok=True)
    disk = target.read_bytes()
    pe = pefile.PE(data=disk, fast_load=False)
    pe.parse_data_directories()
    ident = identify_themida_class(disk, pe)

    report: dict[str, Any] = {
        "target": str(target.resolve()),
        "out_dir": str(out),
        "themida_class": ident.get("themida_class"),
        "ident_score": ident.get("score"),
        "ident_reasons": ident.get("reasons"),
        "image_transforms": [],
        "decrypted": False,
        "ok": False,
        "note": (
            "Themida VM is not lifted. Packer decrypts .text in its own process; "
            "Street copies RAM, fixes PE, hunts OEP."
        ),
    }

    if not ident.get("themida_class") and not force:
        report["error"] = "not_themida_class"
        report["hint"] = "use unpack for resources; pass --force to dump anyway"
        _write(report, out)
        return report

    if sys.platform != "win32":
        report["error"] = "windows_only"
        _write(report, out)
        return report

    def _on_spawn(pid: int) -> dict[str, Any]:
        from street_decrepytor.dynamic.antidebug import patch_peb_being_debugged

        return patch_peb_being_debugged(pid)

    spawn = spawn_wait_dump(
        target,
        out / "live",
        wait_sec=wait_sec,
        fix_pe=True,
        vad=vad,
        kill_after=kill_after,
        wait_mode=wait_mode,
        on_spawn=_on_spawn,
    )
    report["spawn"] = {
        "ok": spawn.get("ok"),
        "pid": spawn.get("pid"),
        "wait": spawn.get("wait"),
        "peb": spawn.get("spawn_hook"),
        "error": spawn.get("error"),
    }
    dump_meta = spawn.get("main_dump") or {}
    dump_path = dump_meta.get("path")
    if not dump_meta.get("ok") or not dump_path or not Path(dump_path).is_file():
        err = dump_meta.get("error") or spawn.get("error") or "dump_failed"
        if "740" in str(err):
            err = "CreateProcess 740 ERROR_ELEVATION_REQUIRED — target needs admin/manifest. Re-run elevated or use an already-dumped image with themida-rebuild."
        report["error"] = err
        _write(report, out)
        return report

    dumped = Path(dump_path).read_bytes()
    delta = section_raw_delta(disk, dumped)
    report["section_delta"] = delta
    recovered = delta["text_disk"] == 0 and delta["text_dump"] >= 0x1000
    recovered = recovered or delta["text_delta"] >= 0x1000

    oep = find_oep_candidates(dumped)
    report["oep_candidates"] = oep
    best = oep[0] if oep else None
    unpacked_path = out / f"{target.stem}_unpacked.exe"
    final = dumped
    oep_applied = False
    if apply_oep and best and best.get("score", 0) >= 0.5:
        final = set_entrypoint_rva(dumped, int(best["rva"]))
        oep_applied = True
        report["oep_applied"] = {"rva": best["rva_hex"], "score": best["score"], "why": best["why"]}
    else:
        report["oep_applied"] = None

    unpacked_path.write_bytes(final)
    report["unpacked_pe"] = str(unpacked_path)
    report["dump_pe"] = dump_path
    report["iat_quality"] = dump_meta.get("iat_quality")
    try:
        from street_decrepytor.protectors.themida_rebuild import strip_packer_sections

        reb = strip_packer_sections(final)
        if reb.get("ok") and reb.get("pe"):
            stripped_path = out / f"{target.stem}_stripped.exe"
            stripped_path.write_bytes(reb["pe"])
            report["stripped_pe"] = str(stripped_path)
            report["stripped"] = {k: v for k, v in reb.items() if k != "pe"}
            report["image_transforms"].append(image_transform(
                "copy", "packer_sections_dropped", str(stripped_path),
                dropped=reb.get("dropped"), kept=reb.get("kept"),
            ))
    except Exception as e:
        report["stripped_error"] = str(e)

    if recovered:
        report["image_transforms"].append(image_transform(
            "runtime_dump",
            "themida_text",
            str(unpacked_path),
            method="rpm_after_packer_decrypt",
            text_delta=delta["text_delta"],
            oep_applied=oep_applied,
        ))
        report["ok"] = True
        report["decrypted"] = decrypted_flag(report["image_transforms"])
        report["honest_verdict"] = (
            f"Themida runtime image captured: .text raw {delta['text_disk']} → {delta['text_dump']}. "
            + (f"OEP set to {best['rva_hex']}." if oep_applied else "OEP not confident — inspect oep_candidates.")
            + " VM handlers are NOT lifted."
        )
    else:
        report["ok"] = bool(dump_meta.get("ok"))
        report["decrypted"] = False
        report["honest_verdict"] = (
            "Dump written but .text raw-size delta is too small — packer may still be packed "
            "(increase --wait, or anti-debug killed unpack). Not claiming decrypt."
        )
        report["image_transforms"].append(image_transform(
            "copy", "live_dump_unproven", str(unpacked_path), text_delta=delta["text_delta"],
        ))

    _write(report, out)
    return report


def _write(report: dict[str, Any], out: Path) -> None:
    (out / "THEMIDA_UNPACK.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    lines = [
        f"# Themida live unpack — `{Path(report.get('target','')).name}`",
        "",
        f"- **decrypted:** `{report.get('decrypted')}`",
        f"- **ok:** `{report.get('ok')}`",
        f"- **themida_class:** `{report.get('themida_class')}` score `{report.get('ident_score')}`",
        "",
        "## Verdict",
        str(report.get("honest_verdict") or report.get("error") or ""),
        "",
        "## Note",
        report.get("note") or "",
        "",
        f"Unpacked PE: `{report.get('unpacked_pe')}`",
        f"Dump PE: `{report.get('dump_pe')}`",
    ]
    delta = report.get("section_delta") or {}
    if delta:
        lines += ["", "## Section raw delta"]
        for s in delta.get("sections") or []:
            lines.append(f"- `{s['name']}` disk={s['disk_raw']} dump={s['dump_raw']} Δ={s['delta']}")
    lines += ["", "## OEP candidates"]
    for c in report.get("oep_candidates") or []:
        lines.append(f"- {c.get('rva_hex')} score={c.get('score')} ({c.get('why')})")
    (out / "THEMIDA_UNPACK.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    report["report_md"] = str(out / "THEMIDA_UNPACK.md")
    report["report_json"] = str(out / "THEMIDA_UNPACK.json")
