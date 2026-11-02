# language: Python 3.11+, file: engine.py
# StreetEngineV2 — v1 StreetEngine pipeline + better entropy / crypto reports / IDA / Unicorn
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from street_v2.compat import import_v1
from street_v2.crypto.decrypt import decrypt_harvest
from street_v2.crypto.detector import detect_crypto_system
from street_v2.crypto.report_gen import generate_crypto_report
from street_v2.entropy.analyzer import analyze_entropy
from street_v2.emu.unicorn_engine import emulate_pe_entry
from street_v2.extract.harvest import harvest_file
from street_v2.live.ida_like import build_ida_view
from street_v2.pe.loader import PeImage, load_pe
from street_v2.report.full import write_all_analysis


def _safe(fn, default: Any = None) -> Any:
    try:
        return fn()
    except Exception as e:
        if isinstance(default, dict):
            d = dict(default)
            d["error"] = f"{type(e).__name__}: {e}"
            return d
        return default


class StreetEngineV2:
    """
    Same jobs as v1 StreetEngine / crack / unpack — then extra layers:
      entropy islands, crypto-system playbook, IDA views, Unicorn trace.
    Non-PE still goes through v1 classify+pipeline (JAR/pyc/Go/…).
    """

    def __init__(self, output_root: str | Path = "output"):
        self.output_root = Path(output_root)
        self.output_root.mkdir(parents=True, exist_ok=True)
        import_v1()

    def classify(self, target: str | Path) -> dict[str, Any]:
        from street_decrepytor.core.artifact import classify_artifact

        return classify_artifact(target).to_dict()

    def analyze(
        self,
        target: str | Path,
        *,
        dynamic: bool = False,
        unpack: bool = False,
        emu: bool = True,
        disasm: bool = True,
        harvest: bool = True,
        max_insns_disasm: int = 60000,
        max_insns_emu: int = 20000,
        out: str | Path | None = None,
    ) -> dict[str, Any]:
        target = Path(target)
        t0 = time.perf_counter()
        run_dir = Path(out) if out else self.output_root / f"{target.stem}_v2"
        run_dir.mkdir(parents=True, exist_ok=True)

        from street_decrepytor.core.artifact import classify_artifact
        from street_decrepytor.core.engine import StreetEngine

        profile = classify_artifact(target)
        v1_eng = StreetEngine(run_dir / "v1_pipeline")
        v1_result = v1_eng.analyze(target, dynamic=dynamic)
        v1_summary = v1_result.summary
        v1_dict = v1_result.to_dict()

        unpack_rep = None
        if unpack:
            from street_decrepytor.protectors.unpack_engine import unpack_target

            unpack_rep = _safe(lambda: unpack_target(target, run_dir / "unpack"), {"ok": False})

        pe: PeImage | None = None
        pe_err = None
        mz = False
        try:
            with target.open("rb") as fh:
                mz = fh.read(2) == b"MZ"
        except Exception:
            mz = False
        if profile.format == "pe" or mz:
            try:
                pe = load_pe(target)
            except Exception as e:
                pe_err = f"{type(e).__name__}: {e}"

        entropy = None
        crypto = None
        crypto_report = None
        ida = None
        ida_view = None
        emu_res = None
        if pe is not None:
            entropy = analyze_entropy(pe)
            crypto = detect_crypto_system(pe, entropy)
            extra = {
                "v1_family": profile.family.value,
                "v1_arch": profile.arch.value,
                "v1_protectors": [p.get("name") for p in (profile.protector_candidates or [])],
                "v1_stages": v1_summary,
            }
            if disasm:
                ida_view = build_ida_view(pe, recursive=True, max_insns=max_insns_disasm)
                ida = ida_view.to_dict()
                extra["ida_insn_count"] = ida["insn_count"]
                extra["ida_functions"] = len(ida["functions"])
                extra["xrefs"] = (ida.get("xref_report") or {}).get("counts")
                (run_dir / "ida_view.json").write_text(json.dumps(ida, indent=2), encoding="utf-8")
                if ida_view.xref_report:
                    (run_dir / "xrefs.json").write_text(
                        json.dumps(ida_view.xref_report, indent=2), encoding="utf-8"
                    )
            if emu:
                emu_obj = emulate_pe_entry(pe, max_insns=max_insns_emu)
                emu_res = emu_obj.to_dict()
                extra["emu"] = emu_res
                (run_dir / "emu_trace.json").write_text(json.dumps(emu_res, indent=2), encoding="utf-8")
            crypto_report = generate_crypto_report(pe, crypto, entropy, run_dir, extra=extra)
            (run_dir / "entropy_map.json").write_text(
                json.dumps(entropy.to_dict(), indent=2), encoding="utf-8"
            )

        harvest_rep = None
        decrypt_rep = None
        if harvest:
            harvest_rep = harvest_file(target, run_dir / "harvest", pe=pe, ent=entropy)
            text = b""
            if pe is not None:
                text, _va = pe.text_blob()
            interesting: list[str] = []
            sp = run_dir / "harvest" / "strings" / "strings_interesting.txt"
            if sp.is_file():
                interesting = sp.read_text(encoding="utf-8", errors="replace").splitlines()[:200]
            xref_keys: list[bytes] = []
            if ida_view is not None and ida_view.xref_report:
                from street_v2.live.xrefs import xor_keys_from_report

                xref_keys = xor_keys_from_report(ida_view.xref_report)
            decrypt_rep = decrypt_harvest(
                harvest_rep,
                run_dir / "decrypt",
                pe_text=text,
                strings=interesting,
                extra_keys=xref_keys,
            )

        transforms = list((unpack_rep or {}).get("image_transforms") or [])
        if decrypt_rep:
            transforms.extend(decrypt_rep.get("image_transforms") or [])
        decrypted = bool((unpack_rep or {}).get("decrypted")) or bool((decrypt_rep or {}).get("decrypted"))

        payload: dict[str, Any] = {
            "tool": "street-decrepytor-v2",
            "version": "2.0.0",
            "target": str(target.resolve()),
            "profile": profile.to_dict(),
            "v1": {
                "summary": v1_summary,
                "output_dir": v1_result.output_dir,
                "stages": [
                    {"name": s.name, "ok": s.ok, "duration_ms": round(s.duration_ms, 2), "errors": s.errors}
                    for s in v1_result.stages
                ],
            },
            "unpack": unpack_rep,
            "pe": pe.to_dict() if pe else None,
            "pe_error": pe_err,
            "entropy": entropy.to_dict() if entropy else None,
            "crypto": crypto.to_dict() if crypto else None,
            "crypto_report": crypto_report,
            "ida": {
                "insn_count": (ida or {}).get("insn_count"),
                "functions": len((ida or {}).get("functions") or []),
                "base": (ida or {}).get("base"),
                "arch": (ida or {}).get("arch"),
                "xref_report": (ida or {}).get("xref_report"),
            } if ida else None,
            "emu": emu_res,
            "harvest": {
                "counts": (harvest_rep or {}).get("counts"),
                "overlay": bool((harvest_rep or {}).get("overlay")),
                "pyinstaller": (harvest_rep or {}).get("pyinstaller"),
                "dir": str(run_dir / "harvest") if harvest_rep else None,
            } if harvest_rep else None,
            "decrypt": {
                "hit_count": (decrypt_rep or {}).get("hit_count"),
                "hits": [
                    {k: v for k, v in h.items() if k != "plain"}
                    for h in ((decrypt_rep or {}).get("hits") or [])[:40]
                ],
                "keys_tried_imm": (decrypt_rep or {}).get("keys_tried_imm"),
                "dir": str(run_dir / "decrypt") if decrypt_rep else None,
            } if decrypt_rep else None,
            "image_transforms": transforms,
            "decrypted": decrypted,
            "elapsed_sec": round(time.perf_counter() - t0, 2),
        }
        (run_dir / "pipeline_result.json").write_text(
            json.dumps(payload, indent=2, default=str), encoding="utf-8"
        )
        # keep a slim v1 dump for agents that already parse it
        (run_dir / "v1_pipeline_result.json").write_text(
            json.dumps(v1_dict, indent=2, default=str), encoding="utf-8"
        )
        all_md = write_all_analysis(run_dir, payload)
        payload["report_md"] = all_md
        payload["out_dir"] = str(run_dir)
        return payload

    def crack(
        self,
        target: str | Path,
        *,
        out: str | Path | None = None,
        dynamic: bool = False,
        unpack: bool = True,
        emu: bool = True,
        no_simd: bool = False,
        gates: bool = False,
    ) -> dict[str, Any]:
        target = Path(target)
        run_dir = Path(out) if out else self.output_root / "crack" / target.stem
        run_dir.mkdir(parents=True, exist_ok=True)

        from street_decrepytor.core.crack import crack_target

        v1_crack = crack_target(
            target,
            out=run_dir / "v1_crack",
            dynamic=dynamic,
            deep_simd=not no_simd,
            apply_gates=gates,
        )
        analysis = self.analyze(
            target,
            dynamic=dynamic,
            unpack=unpack,
            emu=emu,
            out=run_dir / "analyze",
        )
        merged = {
            "tool": "street-decrepytor-v2",
            "version": "2.0.0",
            "target": str(target.resolve()),
            "v1_crack": {
                "verdict": v1_crack.get("verdict"),
                "report_md": v1_crack.get("report_md"),
                "pipeline_dir": v1_crack.get("pipeline_dir"),
                "errors": v1_crack.get("errors"),
                "actions": v1_crack.get("actions"),
            },
            "v2": {
                "profile": analysis.get("profile"),
                "crypto": analysis.get("crypto"),
                "entropy_high_ratio": (analysis.get("entropy") or {}).get("high_ratio"),
                "ida": analysis.get("ida"),
                "emu_ok": (analysis.get("emu") or {}).get("ok") if analysis.get("emu") else None,
                "report_md": analysis.get("report_md"),
                "crypto_report": analysis.get("crypto_report"),
            },
            "decrypted": bool(v1_crack.get("verdict", {}).get("decrypted")) or bool(analysis.get("decrypted")),
            "out_dir": str(run_dir),
        }
        (run_dir / "crack_report.json").write_text(
            json.dumps(merged, indent=2, default=str), encoding="utf-8"
        )
        merged["report_md"] = analysis.get("report_md")
        return merged
