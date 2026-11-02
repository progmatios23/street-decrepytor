# language: Python 3, file: recover.py
# Fast one-shot: FarmServices extract + UMI identify + Themida dump rebuild.
# recovered_complete = all *extractable* layers; never fakes Oreans VM lift.
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from street_decrepytor.core.artifact import classify_artifact
from street_decrepytor.core.transforms import decrypted_flag, image_transform
from street_decrepytor.protectors.unpack_engine import unpack_target


UMI_UI = Path(r"C:\Program Files\umi\umi.exe")
UMI_INJECTOR = Path(r"C:\Users\ggles\AppData\Roaming\umi\bin\injector.exe")
UMI_MODULE = Path(r"C:\Users\ggles\AppData\Roaming\umi\bin\module.dll")
INJECTOR_DUMP = Path(r"D:\Street-decrepytor\output\dumps\umi_injector\spawn\injector_dumped.exe")


def recover_target(
    target: str | Path | None = None,
    *,
    out: str | Path = "output/recover",
    live: bool = True,
    wait_sec: float = 6.0,
    umi: bool = False,
    farm: bool = False,
) -> dict[str, Any]:
    outp = Path(out)
    outp.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()
    jobs: list[dict[str, Any]] = []

    if farm or (target and "farm" in Path(target).name.lower()):
        jobs.append(_recover_farm(Path(target) if target else Path(r"C:\Users\ggles\Downloads\ANALISTAR\FarmServices.exe"), outp / "farm"))
    elif target:
        jobs.append(_recover_one(Path(target), outp / Path(target).stem, live=live, wait_sec=wait_sec))

    if umi:
        jobs.append(_recover_umi(outp / "umi", live=live, wait_sec=wait_sec))

    if not jobs and target:
        jobs.append(_recover_one(Path(target), outp / Path(target).stem, live=live, wait_sec=wait_sec))

    transforms = []
    for j in jobs:
        transforms.extend(j.get("image_transforms") or [])
    report = {
        "tool": "street-decrepytor recover",
        "elapsed_sec": round(time.perf_counter() - t0, 2),
        "jobs": [{k: v for k, v in j.items() if k != "pe_bytes"} for j in jobs],
        "image_transforms": transforms,
        "decrypted": decrypted_flag(transforms),
        "recovered_complete": all(j.get("recovered_complete") for j in jobs) if jobs else False,
        "note": (
            "recovered_complete = every extractable layer on disk is out. "
            "Oreans VM is not lifted. Themida .text only if a dump already filled it."
        ),
    }
    (outp / "RECOVER.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    _md(report, outp / "RECOVER.md")
    report["report_md"] = str(outp / "RECOVER.md")
    report["report_json"] = str(outp / "RECOVER.json")
    return report


def _recover_farm(path: Path, out: Path) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    if not path.is_file():
        return {"name": "farm", "ok": False, "error": "missing", "recovered_complete": False}
    unpack = unpack_target(path, out / "unpack")
    nested = [r for r in (unpack.get("resources_extracted") or []) if r.get("is_pe")]
    xmls = [r for r in (unpack.get("resources_extracted") or []) if r.get("is_xml")]
    tx = list(unpack.get("image_transforms") or [])
    # nested PE is the payload — classify it
    nested_info = []
    for n in nested:
        p = Path(n["path"])
        prof = classify_artifact(p)
        nested_info.append({
            "path": str(p),
            "size": p.stat().st_size,
            "family": prof.family.value,
            "sha256": prof.sha256,
        })
    complete = bool(nested) and not unpack.get("themida_class_ident", {}).get("themida_class")
    if complete:
        tx.append(image_transform("copy", "farmservices_payload_pe", nested[0]["path"]))
    return {
        "name": "farm",
        "ok": True,
        "target": str(path),
        "themida": False,
        "decrypted": False,
        "recovered_complete": complete,
        "honest": "FarmServices has no Themida. 100% of extractable layers = XML + embedded PE copied.",
        "xml_count": len(xmls),
        "nested_pe": nested_info,
        "unpack_md": unpack.get("report_md"),
        "image_transforms": tx,
    }


def _recover_umi(out: Path, *, live: bool, wait_sec: float) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    ui = UMI_UI if UMI_UI.is_file() else Path(r"C:\Program Files\UMI\umi.exe")
    job: dict[str, Any] = {"name": "umi", "ui": str(ui) if ui.is_file() else None, "image_transforms": []}
    if not ui.is_file():
        job.update({"ok": False, "error": "umi.exe missing", "recovered_complete": False})
        return job

    prof = classify_artifact(ui)
    job["ui_profile"] = {"family": prof.family.value, "size": prof.size, "signals": prof.signals[:16]}

    from street_decrepytor.deobf.rust_rt.tauri_extract import extract_tauri_assets, inventory_tauri_ipc

    data = ui.read_bytes()
    assets = extract_tauri_assets(data, out / "tauri_assets")
    ipc = inventory_tauri_ipc(data)
    (out / "tauri_inventory.json").write_text(json.dumps({"assets": assets, "ipc": ipc}, indent=2, default=str), encoding="utf-8")
    job["tauri"] = {"asset_count": len(assets), "is_tauri": ipc.get("is_tauri"), "commands": (ipc.get("custom_commands") or [])[:20]}
    if assets:
        job["image_transforms"].append(image_transform("copy", "umi_tauri_frontend", str(out / "tauri_assets")))

    inj = next(
        (
            p
            for p in (
                Path(r"C:\Users\ggles\AppData\Roaming\umi\bin\injector.exe"),
                Path(r"C:\Users\ggles\AppData\Local\umi\bin\injector.exe"),
                Path(r"C:\Program Files\umi\bin\injector.exe"),
                Path(r"C:\Program Files\UMI\bin\injector.exe"),
            )
            if p.is_file()
        ),
        Path(r"C:\Users\ggles\AppData\Roaming\umi\bin\injector.exe"),
    )
    mod = next(
        (
            p
            for p in (
                Path(r"C:\Users\ggles\AppData\Roaming\umi\bin\module.dll"),
                Path(r"C:\Users\ggles\AppData\Local\umi\bin\module.dll"),
                Path(r"C:\Program Files\umi\bin\module.dll"),
            )
            if p.is_file()
        ),
        Path(r"C:\Users\ggles\AppData\Roaming\umi\bin\module.dll"),
    )
    job["injector_on_disk"] = inj.is_file()
    job["module_on_disk"] = mod.is_file()
    job["missing"] = [n for n, p in (("injector.exe", inj), ("module.dll", mod)) if not p.is_file()]

    dump_used = None
    if inj.is_file():
        dump_used = inj
        live_rep = None
        if live:
            from street_decrepytor.protectors.themida_unpack import unpack_themida_live
            live_rep = unpack_themida_live(inj, out / "injector_live", wait_sec=wait_sec, vad=False)
            job["injector_live"] = {
                "ok": live_rep.get("ok"),
                "decrypted": live_rep.get("decrypted"),
                "error": live_rep.get("error"),
                "unpacked": live_rep.get("unpacked_pe"),
            }
            job["image_transforms"].extend(live_rep.get("image_transforms") or [])
    elif INJECTOR_DUMP.is_file():
        dump_used = INJECTOR_DUMP
        job["injector_source"] = "prior_runtime_dump"

    if dump_used and dump_used.is_file():
        from street_decrepytor.protectors.themida_rebuild import strip_packer_sections
        from street_decrepytor.dynamic.pe_dump import _pe_sections_from_bytes

        blob = dump_used.read_bytes()
        secs = _pe_sections_from_bytes(blob)
        text = next((s for s in secs if s["name"] == ".text"), None)
        filled = bool(text and int(text.get("rsize") or 0) >= 0x1000)
        reb = strip_packer_sections(blob)
        stripped = out / "injector_stripped.exe"
        if reb.get("ok") and reb.get("pe"):
            stripped.write_bytes(reb["pe"])
            job["stripped"] = {
                "path": str(stripped),
                "in_size": reb.get("in_size"),
                "out_size": reb.get("out_size"),
                "dropped": reb.get("dropped"),
                "kept": reb.get("kept"),
                "oep": reb.get("oep"),
            }
            job["image_transforms"].append(image_transform(
                "runtime_dump" if filled else "copy",
                "umi_injector_text",
                str(stripped),
                dropped=reb.get("dropped"),
            ))
        job["injector_text_filled"] = filled
        job["impossible_part"] = (
            "Themida .text was empty on disk; recovered from runtime dump + stripped Oreans .QR% / .' ?r"
            if filled else "no filled dump"
        )

    if live and ui.is_file():
        from street_decrepytor.dynamic.pe_dump import spawn_wait_dump
        sp = spawn_wait_dump(ui, out / "ui_dump", wait_sec=min(wait_sec, 4.0), vad=False, kill_after=True, wait_mode="text")
        job["ui_dump"] = {"ok": sp.get("ok"), "wait": sp.get("wait"), "path": (sp.get("main_dump") or {}).get("path")}
        # injector may materialize after UI start
        job["injector_on_disk_after_ui"] = Path(r"C:\Users\ggles\AppData\Roaming\umi\bin\injector.exe").is_file()
        job["module_on_disk_after_ui"] = Path(r"C:\Users\ggles\AppData\Roaming\umi\bin\module.dll").is_file()

    job["ok"] = True
    job["recovered_complete"] = bool(job.get("tauri", {}).get("asset_count")) and bool(job.get("stripped"))
    job["live_bins_complete"] = bool(job.get("injector_on_disk")) and bool(job.get("module_on_disk"))
    job["honest"] = (
        "UMI UI = Tauri/WebView2 (not Themida). Injector Themida .text from dump+strip if dump exists. "
        + (f"Missing live bins: {job.get('missing')}" if job.get("missing") else "live injector/module present.")
    )
    return job


def _recover_one(path: Path, out: Path, *, live: bool, wait_sec: float) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    unpack = unpack_target(path, out / "unpack")
    themida = bool((unpack.get("themida_class_ident") or {}).get("themida_class"))
    job: dict[str, Any] = {
        "name": path.name,
        "themida": themida,
        "unpack_md": unpack.get("report_md"),
        "image_transforms": list(unpack.get("image_transforms") or []),
        "recovered_complete": False,
        "ok": True,
    }
    if themida and live:
        from street_decrepytor.protectors.themida_unpack import unpack_themida_live
        live_rep = unpack_themida_live(path, out / "live", wait_sec=wait_sec, vad=False)
        job["live"] = {"ok": live_rep.get("ok"), "decrypted": live_rep.get("decrypted"), "error": live_rep.get("error")}
        job["image_transforms"].extend(live_rep.get("image_transforms") or [])
        job["recovered_complete"] = bool(live_rep.get("decrypted"))
    else:
        job["recovered_complete"] = not themida and bool(unpack.get("copied"))
    return job


def _md(report: dict[str, Any], path: Path) -> None:
    lines = [
        "# Recover report",
        "",
        f"- elapsed: {report.get('elapsed_sec')}s",
        f"- decrypted (runtime_dump/cipher): `{report.get('decrypted')}`",
        f"- recovered_complete: `{report.get('recovered_complete')}`",
        "",
        report.get("note") or "",
        "",
    ]
    for j in report.get("jobs") or []:
        lines += [f"## {j.get('name')}", f"- ok: {j.get('ok')}", f"- recovered_complete: {j.get('recovered_complete')}", f"- {j.get('honest') or j.get('error') or ''}", ""]
    path.write_text("\n".join(lines), encoding="utf-8")
