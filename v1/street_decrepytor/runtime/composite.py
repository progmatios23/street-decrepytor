# language: Python 3, file: runtime/composite.py
# R5 — Composite flagging engine across S0/S1/S2 + pillars R1–R4
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from street_decrepytor.runtime.common import clamp01, windows_build


WEIGHTS = {
    "R1": 0.25,
    "R2": 0.25,
    "R3": 0.20,
    "R4": 0.30,
}


def validate_target(
    target: str | Path | None = None,
    *,
    pid: int | None = None,
    spawn: bool = False,
    wait_sec: float = 8.0,
    out_dir: str | Path | None = None,
    skip_hooks: bool = False,
) -> dict[str, Any]:
    """
    Run reflective validation.
    - If spawn=True and target set: dump --spawn path then analyze live PID briefly before kill... 
      Actually spawn_wait_dump kills after; so we probe during wait by using spawn_wait internals
      Simpler: if pid given, probe pid; if spawn, spawn_wait_dump then analyze dumped file for R4 + use pid before kill.

    Flow:
      S0: classify + unpack structural (no nested crack)
      S1/S2: if spawn → spawn_wait_dump; if pid → R1 R2 R3 on pid; R4 on target (+pid)
    """
    from street_decrepytor.core.artifact import classify_artifact
    from street_decrepytor.protectors.unpack_engine import identify_themida_class
    import pefile

    t0 = time.perf_counter()
    out = Path(out_dir or "output/runtime/validate")
    out.mkdir(parents=True, exist_ok=True)

    report: dict[str, Any] = {
        "build": windows_build(),
        "manual_cross_check_required": True,
        "states": {},
        "pillars": {},
        "layers": {
            "static_pack": False,
            "runtime_decrypt": False,
            "hooks": False,
            "peb_lie": False,
            "cfg_obfuscation": False,
        },
        "error_margins": [],
        "composite_score": 0.0,
        "confidence": 0.0,
    }

    path = Path(target) if target else None
    dump_info = None
    live_pid = pid

    # --- optional spawn: hold process, probe live, then dump+kill ---
    spawned_hold = False
    if spawn and path and path.is_file() and live_pid is None:
        live_pid = _spawn_keep(path, out / "probe_proc", hold_sec=max(2.0, wait_sec * 0.4))
        spawned_hold = live_pid is not None
        if live_pid:
            import time as _t

            _t.sleep(max(0.5, wait_sec * 0.6))  # allow packer unpack before probes/dump

    # --- S0 static ---
    if path and path.is_file():
        profile = classify_artifact(path)
        pe = pefile.PE(str(path), fast_load=False)
        pe.parse_data_directories()
        structural = identify_themida_class(path.read_bytes(), pe)
        report["states"]["S0_static"] = {
            "profile": profile.to_dict(),
            "themida_class": structural.get("themida_class"),
            "structural_score": structural.get("score"),
            "reasons": structural.get("reasons"),
        }
        report["layers"]["static_pack"] = bool(structural.get("themida_class"))
        # CFG
        try:
            from street_decrepytor.deobf.cfg_obfuscation import analyze_cfg

            cfg = analyze_cfg(path)
            report["states"]["S0_cfg"] = {
                "trampoline_count": cfg.get("trampoline_count"),
                "cfg_obfuscation_likely": cfg.get("cfg_obfuscation_likely"),
                "top_dispatchers": cfg.get("top_dispatchers"),
            }
            report["layers"]["cfg_obfuscation"] = bool(cfg.get("cfg_obfuscation_likely"))
        except Exception as e:
            report["states"]["S0_cfg"] = {"error": str(e)}
    else:
        structural = {}
        profile = None

    # --- R4 phylo (file + optional pid) ---
    if path and path.is_file():
        from street_decrepytor.runtime.themida_phylo import themida_phylo

        r4 = themida_phylo(path, pid=live_pid, structural=structural or None)
        report["pillars"]["R4"] = r4
    else:
        report["pillars"]["R4"] = {"ok": False, "error": "no_target", "score": 0, "confidence": 0, "findings": []}

    # --- live pillars ---
    if live_pid:
        if not skip_hooks:
            from street_decrepytor.runtime.syscall_observatory import observe_syscalls
            from street_decrepytor.runtime.stub_integrity import validate_stubs_live

            report["pillars"]["R1"] = observe_syscalls(live_pid)
            report["pillars"]["R2"] = validate_stubs_live(live_pid, shots=3, shot_delay_ms=35)
            if report["pillars"]["R1"].get("hooked"):
                report["layers"]["hooks"] = True
        else:
            report["pillars"]["R1"] = {"ok": False, "skipped": True, "score": 0, "confidence": 0, "findings": []}
            report["pillars"]["R2"] = {"ok": False, "skipped": True, "score": 0, "confidence": 0, "findings": []}

        from street_decrepytor.runtime.peb_deception import probe_peb

        report["pillars"]["R3"] = probe_peb(live_pid)
        if any(f.get("flag") == "peb_api_vs_raw_mismatch" for f in report["pillars"]["R3"].get("findings") or []):
            report["layers"]["peb_lie"] = True

        # dump while still alive, then kill if we spawned
        if spawned_hold and live_pid and path:
            from street_decrepytor.dynamic.pe_dump import dump_process_module, dump_vad_regions

            main = dump_process_module(
                live_pid, None, out / "spawn_dump" / f"{path.stem}_dumped.exe", fix_pe=True, rebuild_iat=True
            )
            vad = dump_vad_regions(live_pid, out / "spawn_dump" / "vad", max_regions=60)
            report["states"]["S1_dump"] = {
                "ok": main.get("ok"),
                "pid": live_pid,
                "main_dump": main.get("path"),
                "size_disk": path.stat().st_size,
                "size_dump": main.get("size"),
                "vad_regions": vad.get("regions"),
            }
            if main.get("ok") and (main.get("size") or 0) > path.stat().st_size * 1.05:
                report["layers"]["runtime_decrypt"] = True
            _kill(live_pid)
            live_pid = None
        elif spawned_hold and live_pid:
            _kill(live_pid)
            live_pid = None
    else:
        for k in ("R1", "R2", "R3"):
            report["pillars"][k] = {
                "ok": False,
                "skipped": True,
                "reason": "no_live_pid — pass --pid or --spawn",
                "score": 0.0,
                "confidence": 0.0,
                "findings": [],
                "limits": ["Live pillars require a running process"],
            }

    # --- composite ---
    scores = []
    confs = []
    margins = []
    for key, w in WEIGHTS.items():
        p = report["pillars"].get(key) or {}
        s = float(p.get("score") or 0.0)
        c = float(p.get("confidence") or 0.0)
        scores.append(s * w)
        if c:
            confs.append(c)
        for lim in p.get("limits") or []:
            margins.append(f"{key}: {lim}")
        for f in p.get("findings") or []:
            for lim in f.get("limits") or []:
                margins.append(f"{key}/{f.get('flag')}: {lim}")

    report["composite_score"] = round(clamp01(sum(scores)), 4)
    report["confidence"] = round(sum(confs) / len(confs), 4) if confs else 0.0
    report["error_margins"] = sorted(set(margins))[:40]
    report["weights"] = WEIGHTS
    report["elapsed_sec"] = round(time.perf_counter() - t0, 2)
    report["target"] = str(path) if path else None
    report["pid"] = live_pid
    report["disclaimer"] = (
        "All conclusions are probabilistic. Manual cross-validation is required. "
        "A low score is not proof of safety; a high score is not proof of a specific packer."
    )

    (out / "VALIDATE_REPORT.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    (out / "VALIDATE_REPORT.md").write_text(_render_md(report), encoding="utf-8")
    report["out_dir"] = str(out)
    report["report_md"] = str(out / "VALIDATE_REPORT.md")
    return report


def _spawn_keep(exe: Path, out: Path, hold_sec: float = 3.0) -> int | None:
    """Spawn process, return pid; caller must kill."""
    import ctypes
    from ctypes import wintypes

    out.mkdir(parents=True, exist_ok=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)

    class STARTUPINFOW(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

    si = STARTUPINFOW()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()
    cmd = f'"{exe}"'
    ok = k32.CreateProcessW(str(exe), cmd, None, None, False, 0x10, None, str(exe.parent), ctypes.byref(si), ctypes.byref(pi))
    if not ok:
        return None
    import time as _t

    _t.sleep(hold_sec)
    # leave running — store handles in a side file? Close thread handle, keep process
    k32.CloseHandle(pi.hThread)
    # leak hProcess until kill — store pid only
    (out / "probe_pid.txt").write_text(str(pi.dwProcessId), encoding="utf-8")
    return int(pi.dwProcessId)


def _kill(pid: int) -> None:
    import ctypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    h = k32.OpenProcess(0x0001, False, pid)  # TERMINATE
    if h:
        k32.TerminateProcess(h, 0)
        k32.CloseHandle(h)


def _render_md(report: dict[str, Any]) -> str:
    lines = [
        "# Street-decrepytor — Runtime Validate Report",
        "",
        f"**Composite score:** `{report.get('composite_score')}` (confidence `{report.get('confidence')}`)",
        f"**Target:** `{report.get('target')}`",
        "",
        f"> {report.get('disclaimer')}",
        "",
        "## Layers (boolean)",
    ]
    for k, v in (report.get("layers") or {}).items():
        lines.append(f"- `{k}`: **{v}**")
    lines += ["", "## Pillars"]
    for name, p in (report.get("pillars") or {}).items():
        lines.append(f"### {name} — score `{p.get('score')}` conf `{p.get('confidence')}`")
        if p.get("skipped"):
            lines.append(f"- skipped: {p.get('reason')}")
        for f in p.get("findings") or []:
            lines.append(f"- **{f.get('flag')}** (s={f.get('score')}, c={f.get('confidence')}): {f.get('detail')}")
        lines.append("")
    lines += ["## Error margins / limitations"]
    for m in report.get("error_margins") or []:
        lines.append(f"- {m}")
    lines += ["", f"manual_cross_check_required: **{report.get('manual_cross_check_required')}**"]
    return "\n".join(lines) + "\n"
