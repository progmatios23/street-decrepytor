# language: Python 3, file: crack.py
# One-shot classify + pipeline + report. Does not decrypt packers.
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from street_decrepytor.core.engine import StreetEngine
from street_decrepytor.core.artifact import classify_artifact
from street_decrepytor.core.transforms import decrypted_flag, image_transform


def crack_target(
    target: str | Path,
    *,
    out: str | Path = "output/crack",
    dynamic: bool = False,
    deep_simd: bool = True,
    apply_gates: bool = False,
    funcs_list: str | Path | None = None,
) -> dict[str, Any]:
    """
    Classify → pipeline JSON → optional SIMD strings on *on-disk* .text.
    Recrack/gates are NOT applied here — use `recrack` / `cdn-pull --crack`.
    """
    target = Path(target)
    if not target.is_file():
        raise FileNotFoundError(target)

    out_root = Path(out)
    out_root.mkdir(parents=True, exist_ok=True)
    t0 = time.perf_counter()

    profile = classify_artifact(target)
    eng = StreetEngine(out_root)
    result = eng.analyze(target, dynamic=dynamic)
    transforms: list[dict[str, Any]] = []
    report: dict[str, Any] = {
        "tool": "Street-decrepytor",
        "target": str(target.resolve()),
        "profile": profile.to_dict(),
        "pipeline_summary": result.summary,
        "pipeline_dir": result.output_dir,
        "actions": [],
        "artifacts_written": [],
        "image_transforms": transforms,
        "verdict": {},
        "errors": [],
    }

    if deep_simd and profile.format == "pe" and profile.family.value in (
        "native_pe", "rust", "go", "mixed", "cpp_cli"
    ):
        try:
            from street_decrepytor.crypto.simd_emu import run_simd_emu_on_pe

            simd = run_simd_emu_on_pe(
                target,
                max_funcs=40,
                funcs_list=funcs_list,
            )
            simd_path = Path(result.output_dir) / "crack_simd.json"
            simd_path.write_text(json.dumps(simd, indent=2), encoding="utf-8")
            report["actions"].append({
                "simd_emu": {
                    "skipped": simd.get("skipped"),
                    "reason": simd.get("reason"),
                    "unique_strings": simd.get("unique_strings"),
                    "functions_emulated": simd.get("functions_emulated"),
                    "note": "string snapshots only — PE image unchanged",
                }
            })
            report["artifacts_written"].append(str(simd_path))
            if simd.get("skipped"):
                report["actions"][-1]["simd_emu"]["skipped"] = True
        except Exception as e:
            report["errors"].append(f"simd: {e}")

    if apply_gates and target.suffix.lower() == ".dll":
        try:
            from street_decrepytor.potassium.recrack import recrack_dll

            name_l = target.name.lower()
            looks_k = "potassium" in name_l
            if looks_k:
                gate_out = Path(result.output_dir) / f"{target.stem}_recracked.dll"
                g = recrack_dll(target, out=gate_out, dry=False)
                report["actions"].append({"recrack": g})
                if g.get("written"):
                    report["artifacts_written"].append(str(gate_out))
                    transforms.append(image_transform(
                        "patch", "potassium_gates", str(gate_out),
                        applied=g.get("applied"), miss=g.get("miss"),
                    ))
                    if g.get("gates_json"):
                        report["artifacts_written"].append(g["gates_json"])
                if g.get("miss", 0) and g.get("applied", 0) == 0:
                    report["errors"].append(
                        f"recrack: 0 gates applied ({g.get('miss')} miss) — build too different or not Potassium"
                    )
        except Exception as e:
            report["errors"].append(f"recrack: {e}")

    carved = Path(result.output_dir) / "carved"
    if carved.is_dir():
        carves = sorted(carved.glob("*.bin"))[:3]
        for c in carves:
            try:
                sub = eng.analyze(c, dynamic=False)
                report["actions"].append({"carved": str(c), "family": sub.profile.family.value})
                transforms.append(image_transform("copy", "embedded_mz_carve", str(c)))
            except Exception as e:
                report["errors"].append(f"carve {c.name}: {e}")

    protectors = [p.get("name") for p in (result.profile.protector_candidates or [])]
    report["verdict"] = {
        "family": result.profile.family.value,
        "arch": result.profile.arch.value,
        "protectors": protectors,
        "stages_ok": result.summary.get("stages_ok"),
        "stages_fail": result.summary.get("stages_fail"),
        "pipeline_ok": result.summary.get("stages_fail", 1) == 0,
        "decrypted": decrypted_flag(transforms),
        "image_transforms": transforms,
        "notes": _verdict_notes(result.profile, protectors),
        "elapsed_sec": round(time.perf_counter() - t0, 2),
    }

    md = _render_md(report)
    md_path = Path(result.output_dir) / "CRACK_REPORT.md"
    md_path.write_text(md, encoding="utf-8")
    report["artifacts_written"].append(str(md_path))
    json_path = Path(result.output_dir) / "crack_report.json"
    json_path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    report["artifacts_written"].append(str(json_path))
    report["report_md"] = str(md_path)
    return report


def crack_batch(directory: str | Path, *, out: str | Path = "output/batch", glob: str = "*.exe") -> dict[str, Any]:
    directory = Path(directory)
    out = Path(out)
    results = []
    paths = sorted(directory.glob(glob)) + sorted(directory.glob(glob.replace(".exe", ".dll")))
    seen = set()
    files = []
    for p in paths:
        if p.is_file() and p.resolve() not in seen:
            seen.add(p.resolve())
            files.append(p)
    for p in files:
        if p.stat().st_size > 80 << 20:
            results.append({"target": str(p), "skipped": "too_large"})
            continue
        try:
            r = crack_target(p, out=out / p.stem, deep_simd=False, apply_gates=False)
            results.append({
                "target": str(p),
                "family": r["verdict"].get("family"),
                "protectors": r["verdict"].get("protectors"),
                "decrypted": r["verdict"].get("decrypted"),
                "report": r.get("report_md"),
                "errors": r.get("errors"),
            })
        except Exception as e:
            results.append({"target": str(p), "error": str(e)})
    summary = {"directory": str(directory), "count": len(results), "results": results}
    out.mkdir(parents=True, exist_ok=True)
    (out / "batch_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def _verdict_notes(profile: Any, protectors: list) -> list[str]:
    notes = [
        "This report is classify + extract/plan. decrypted=true only if a cipher transform is listed.",
    ]
    if profile.family.value == "rust" and any("tauri" in s for s in profile.signals):
        notes.append("Tauri/WebView2 UI — check embedded assets / JS auth, not only native crypto")
    if any("dfir" in s or "sysmon" in s for s in profile.signals):
        notes.append(
            "DFIR/MITRE rule pack embedded (not a classic packer crack) — "
            "use strings/pipeline for rule extraction; auth bypass N/A"
        )
    if "Themida" in str(protectors) or "VMProtect" in str(protectors):
        notes.append("Commercial protector — dump --spawn after runtime unpack; Street does not decrypt the VM")
    if profile.multi_build_hints:
        notes.append(f"Multi-build hints: {profile.multi_build_hints} — inspect carved/ outputs")
    if not protectors and not any("dfir" in s for s in profile.signals):
        notes.append("No strong protector hit — focus strings, crypto shapes, auth gates")
    return notes


def _render_md(report: dict[str, Any]) -> str:
    v = report.get("verdict") or {}
    p = report.get("profile") or {}
    lines = [
        f"# Crack report — `{Path(report.get('target','')).name}`",
        "",
        f"- **path:** `{report.get('target')}`",
        f"- **family:** `{v.get('family')}` · **arch:** `{v.get('arch')}`",
        f"- **sha256:** `{p.get('sha256')}`",
        f"- **protectors:** {', '.join(v.get('protectors') or []) or '(none strong)'}",
        f"- **pipeline:** {v.get('stages_ok')} ok / {v.get('stages_fail')} fail",
        f"- **decrypted:** `{v.get('decrypted')}`",
        f"- **elapsed:** {v.get('elapsed_sec')}s",
        "",
        "## Image transforms (copy/patch/inflate/cipher)",
    ]
    tx = v.get("image_transforms") or report.get("image_transforms") or []
    if not tx:
        lines.append("- (none — image not rewritten)")
    for t in tx:
        lines.append(f"- **{t.get('kind')}** `{t.get('layer')}` → `{t.get('path')}`")
    lines.append("")
    lines.append("## Notes")
    for n in v.get("notes") or []:
        lines.append(f"- {n}")
    if report.get("errors"):
        lines.append("")
        lines.append("## Errors")
        for e in report["errors"]:
            lines.append(f"- {e}")
    lines.append("")
    lines.append("## Artifacts")
    for a in report.get("artifacts_written") or []:
        lines.append(f"- `{a}`")
    lines.append("")
    lines.append(f"Pipeline dir: `{report.get('pipeline_dir')}`")
    return "\n".join(lines) + "\n"
