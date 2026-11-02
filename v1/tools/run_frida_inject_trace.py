#!/usr/bin/env python3
# language: Python 3, file: run_frida_inject_trace.py
# Spawn mock Roblox (optional) + Frida-trace the real umi injector for inject APIs.
import json, os, re, sys, time, subprocess
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

import frida

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output" / "frida_inject"
OUT.mkdir(parents=True, exist_ok=True)
JS = Path(__file__).with_name("frida_inject_trace.js")
INJECTOR = Path(os.environ.get(
    "UMI_INJECTOR",
    str(Path(os.environ["APPDATA"]) / "umi" / "bin" / "injector.exe"),
))
MOCK = ROOT / "build" / "RobloxPlayerBeta.exe"
MODULE = Path(os.environ.get(
    "UMI_MODULE",
    str(Path(os.environ["APPDATA"]) / "umi" / "bin" / "module.dll"),
))


def main():
    if not INJECTOR.exists():
        print("FATAL: injector missing", INJECTOR)
        return 2
    if not JS.exists():
        print("FATAL: script missing", JS)
        return 2

    mock_proc = None
    if MOCK.exists() and os.environ.get("SKIP_MOCK", "0") != "1":
        print(f"[+] starting mock Roblox: {MOCK}")
        mock_proc = subprocess.Popen(
            [str(MOCK)],
            cwd=str(MOCK.parent),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        time.sleep(1.0)
        print(f"[+] mock pid={mock_proc.pid}")
    else:
        print("[!] no mock / SKIP_MOCK — injector may exit on 'Roblox not found'")

    script_src = JS.read_text(encoding="utf-8")
    lines = []

    def on_msg(message, data):
        if message["type"] == "send":
            payload = message.get("payload")
            if isinstance(payload, dict):
                line = f"[{payload.get('tag')}] {payload.get('detail')}"
            else:
                line = str(payload)
            lines.append(line)
            print(line)
        elif message["type"] == "error":
            lines.append("ERROR " + message.get("description", json.dumps(message)))
            print("ERROR", message.get("description", message))

    target = Path(os.environ.get("FRIDA_TARGET", str(INJECTOR)))
    print(f"[+] frida spawn {target}")
    device = frida.get_local_device()
    pid = device.spawn([str(target)])
    session = device.attach(pid)
    script = session.create_script(script_src)
    script.on("message", on_msg)
    script.load()
    # give hooks a beat before resume (Themida init)
    time.sleep(0.3)
    device.resume(pid)
    timeout = float(os.environ.get("FRIDA_TIMEOUT", "30"))
    print(f"[+] resumed pid={pid} — waiting {timeout}s for inject APIs")

    t0 = time.time()
    while time.time() - t0 < timeout:
        time.sleep(0.4)
        try:
            device.get_process_by_pid(pid)
        except Exception:
            print("[+] target exited")
            break
        # early stop if we already saw the technique
        joined = "\n".join(lines)
        if "QueueUserAPC" in joined or "NtCreateThreadEx" in joined or "CreateRemoteThread" in joined:
            print("[+] technique API observed — stopping early")
            time.sleep(1.0)
            break

    try:
        session.detach()
    except Exception:
        pass
    try:
        device.kill(pid)
    except Exception:
        pass
    if mock_proc:
        try:
            mock_proc.terminate()
        except Exception:
            pass

    report = {
        "target": str(target),
        "injector_default": str(INJECTOR),
        "module": str(MODULE),
        "mock": str(MOCK) if mock_proc else None,
        "pid": pid,
        "lines": lines,
        "technique_guess": _guess(lines),
    }
    stem = "FRIDA_" + re.sub(r"[^A-Za-z0-9]+", "_", target.stem.upper())
    (OUT / "FRIDA_INJECT_TRACE.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (OUT / f"{stem}.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    md = [
        "# Frida inject trace",
        "",
        f"- target: `{target}`",
        f"- technique: **{report['technique_guess']}**",
        "",
    ]
    md += [f"- `{l}`" for l in lines[-120:]]
    (OUT / "FRIDA_INJECT_TRACE.md").write_text("\n".join(md), encoding="utf-8")
    (OUT / f"{stem}.md").write_text("\n".join(md), encoding="utf-8")
    print(f"[+] wrote {OUT / 'FRIDA_INJECT_TRACE.md'} and {stem}.*")
    print(f"[+] technique_guess: {report['technique_guess']}")
    return 0


def _guess(lines):
    joined = "\n".join(lines)
    if "QueueUserAPC" in joined:
        return "APC (QueueUserAPC)"
    if "NtCreateThreadEx" in joined or "RtlCreateUserThread" in joined:
        return "NtCreateThreadEx"
    if "CreateRemoteThread" in joined:
        return "CreateRemoteThread"
    if "NtMapViewOfSection" in joined:
        return "section map"
    if "WriteProcessMemory" in joined or "VirtualAllocEx" in joined:
        return "classic write+alloc (thread start unresolved)"
    return "unknown — no inject-surface hit"


if __name__ == "__main__":
    raise SystemExit(main())
