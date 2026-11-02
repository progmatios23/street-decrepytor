# language: Python 3
# Lab run: unit tests + unpack + themida-unpack + rebuild. Writes output/all_analysis/
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
OUT = ROOT / "output" / "all_analysis"
OUT.mkdir(parents=True, exist_ok=True)

SAMPLES = {
    "dfir": Path(r"C:\Users\ggles\Downloads\ANALISTAR\DFIR (1).exe"),
    "farmservices": Path(r"C:\Users\ggles\Downloads\ANALISTAR\FarmServices.exe"),
    "anydesk": Path(r"C:\Users\ggles\Downloads\ANALISTAR\AnyDesk (2).exe"),
}
INJECTOR_DUMP = ROOT / "output" / "dumps" / "umi_injector" / "spawn" / "injector_dumped.exe"


def run(cmd: list[str], log_name: str, timeout: int = 180) -> dict:
    t0 = time.perf_counter()
    p = subprocess.run(
        cmd,
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=timeout,
        env={**__import__("os").environ, "PYTHONPATH": str(ROOT)},
    )
    (OUT / log_name).write_text((p.stdout or "") + "\n--- stderr ---\n" + (p.stderr or ""), encoding="utf-8")
    return {
        "cmd": cmd,
        "rc": p.returncode,
        "sec": round(time.perf_counter() - t0, 2),
        "log": str(OUT / log_name),
        "stdout_tail": (p.stdout or "")[-2000:],
    }


def main() -> None:
    results: dict = {"root": str(ROOT), "out": str(OUT), "steps": []}

    py = sys.executable
    results["steps"].append({
        "name": "unit_tests",
        **run([py, "-m", "unittest", "tests.test_classify", "tests.test_honesty", "tests.test_themida_oep", "-v"],
              "01_unit_tests.txt", 60),
    })

    from street_decrepytor.core.artifact import classify_artifact
    from street_decrepytor.protectors.unpack_engine import identify_themida_class, unpack_target
    import pefile

    classif = {}
    for key, path in SAMPLES.items():
        if not path.is_file():
            classif[key] = {"missing": True, "path": str(path)}
            continue
        data = path.read_bytes()
        pe = pefile.PE(data=data, fast_load=False)
        pe.parse_data_directories()
        ident = identify_themida_class(data, pe)
        prof = classify_artifact(path)
        classif[key] = {
            "path": str(path),
            "size": path.stat().st_size,
            "family": prof.family.value,
            "themida_class": ident["themida_class"],
            "score": ident["score"],
            "ep_section": ident.get("ep_section"),
            "virtual_only": ident.get("virtual_only_sections"),
            "markers": ident.get("markers"),
        }
    (OUT / "02_classify.json").write_text(json.dumps(classif, indent=2), encoding="utf-8")
    results["classify"] = classif

    for key, path in SAMPLES.items():
        if not path.is_file():
            continue
        dest = OUT / f"unpack_{key}"
        t0 = time.perf_counter()
        try:
            rep = unpack_target(path, dest)
            results["steps"].append({
                "name": f"unpack_{key}",
                "ok": True,
                "sec": round(time.perf_counter() - t0, 2),
                "decrypted": rep.get("decrypted"),
                "themida": (rep.get("themida_class_ident") or {}).get("themida_class"),
                "verdict": rep.get("honest_verdict"),
                "transforms": rep.get("image_transforms"),
                "out": str(dest),
            })
        except Exception as e:
            results["steps"].append({"name": f"unpack_{key}", "ok": False, "error": str(e)})

    # live Themida on DFIR only (real spawn)
    dfir = SAMPLES["dfir"]
    if dfir.is_file():
        results["steps"].append({
            "name": "themida_unpack_dfir_live",
            **run(
                [py, "-m", "street_decrepytor", "themida-unpack", str(dfir),
                 "--wait", "14", "--out", str(OUT / "themida_dfir")],
                "03_themida_dfir.txt",
                90,
            ),
        })

    # offline rebuild of existing UMI injector dump
    if INJECTOR_DUMP.is_file():
        from street_decrepytor.protectors.themida_rebuild import strip_packer_sections
        from street_decrepytor.protectors.themida_oep import find_oep_candidates
        from street_decrepytor.protectors.themida_unpack import section_raw_delta

        dumped = INJECTOR_DUMP.read_bytes()
        oep = find_oep_candidates(dumped)
        reb = strip_packer_sections(dumped)
        dest = OUT / "injector_stripped.exe"
        if reb.get("ok") and reb.get("pe"):
            dest.write_bytes(reb["pe"])
            reb_meta = {k: v for k, v in reb.items() if k != "pe"}
            reb_meta["written"] = str(dest)
        else:
            reb_meta = reb
        (OUT / "04_injector_rebuild.json").write_text(
            json.dumps({"oep": oep[:8], "rebuild": reb_meta}, indent=2, default=str),
            encoding="utf-8",
        )
        results["injector_offline"] = {
            "dump": str(INJECTOR_DUMP),
            "dump_size": INJECTOR_DUMP.stat().st_size,
            "stripped": str(dest) if dest.is_file() else None,
            "stripped_size": dest.stat().st_size if dest.is_file() else None,
            "kept": reb_meta.get("kept"),
            "dropped": reb_meta.get("dropped"),
            "oep_top": oep[:5] if oep else [],
        }

    (OUT / "results.json").write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
    print(json.dumps({"ok": True, "out": str(OUT)}, indent=2))


if __name__ == "__main__":
    main()
