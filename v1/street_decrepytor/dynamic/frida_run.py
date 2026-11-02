# language: Python 3, file: frida_run.py
# Frida runner wrapper — generates + optionally attaches
from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

from street_decrepytor.dynamic.api_intercept import frida_script, intercept_plan, DEFAULT_HOOK_SET


def which_frida() -> str | None:
    return shutil.which("frida") or shutil.which("frida.exe")


def write_script(family: str, out: Path, extra_hooks: list[str] | None = None) -> Path:
    plan = intercept_plan(family)
    hooks = list(DEFAULT_HOOK_SET)
    if extra_hooks:
        hooks.extend(extra_hooks)
    if plan.get("extra_hooks"):
        hooks.extend(plan["extra_hooks"])
    js = frida_script(hooks)
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(js, encoding="utf-8")
    return out


def run_frida(
    target: str,
    script_path: Path,
    *,
    spawn: bool = False,
    output_log: Path | None = None,
    timeout_sec: int = 120,
) -> dict[str, Any]:
    """
    target: PID as digit string, or process name, or path to spawn.
    Requires frida CLI on PATH. *Does not force attach if frida missing.*
    """
    frida = which_frida()
    if not frida:
        return {
            "ok": False,
            "error": "frida_cli_not_found",
            "hint": "pip install frida-tools",
            "script": str(script_path),
        }
    cmd = [frida]
    if spawn and not target.isdigit():
        cmd += ["-f", target, "-l", str(script_path), "--no-pause"]
    elif target.isdigit():
        cmd += ["-p", target, "-l", str(script_path)]
    else:
        cmd += ["-n", target, "-l", str(script_path)]

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            encoding="utf-8",
            errors="replace",
        )
        result = {
            "ok": proc.returncode == 0,
            "cmd": cmd,
            "returncode": proc.returncode,
            "stdout_tail": (proc.stdout or "")[-4000:],
            "stderr_tail": (proc.stderr or "")[-2000:],
        }
    except subprocess.TimeoutExpired as e:
        result = {
            "ok": True,
            "timeout": True,
            "cmd": cmd,
            "stdout_tail": (e.stdout or b"")[-4000:].decode("utf-8", "replace") if isinstance(e.stdout, (bytes, bytearray)) else (e.stdout or "")[-4000:],
            "note": "timed out — hooks may still have fired; increase --timeout",
        }
    except Exception as e:
        result = {"ok": False, "error": str(e), "cmd": cmd}

    if output_log:
        Path(output_log).write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def frida_session(family: str, target: str, out_dir: str | Path, spawn: bool = False) -> dict[str, Any]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    script = write_script(family, out_dir / "hooks.js")
    run = run_frida(target, script, spawn=spawn, output_log=out_dir / "frida_run.json")
    return {"script": str(script), "run": run}
