#!/usr/bin/env python3
"""
Sydney auth monitor + probe.

Watches %USERPROFILE%\\.sydney\\authorization.bin, logs CreateFile/MessageBox
via Frida when DumpHost loads sydney_1_pe.dll, and probes dummy key formats.

No extra deps besides optional frida (already installed).
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(r"D:\STREET-tool")
OUT = ROOT / "out"
DECRYPTOR = Path(__file__).resolve().parent
AUTH_DIR = Path.home() / ".sydney"
AUTH_FILE = AUTH_DIR / "authorization.bin"
LOG = OUT / "auth_monitor.jsonl"
JAVA = ROOT / "tools" / "jdk" / "bin" / "java.exe"
DLL = OUT / "natives" / "sydney_1_pe.dll"
CP = str(DECRYPTOR / "jnihost") + os.pathsep + str(OUT / "target-deobf.jar")


def utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def log(event: str, **kw) -> None:
    rec = {"ts": utc(), "event": event, **kw}
    OUT.mkdir(parents=True, exist_ok=True)
    with LOG.open("a", encoding="utf-8") as f:
        f.write(json.dumps(rec, ensure_ascii=False) + "\n")
    extra = " ".join(f"{k}={v}" for k, v in kw.items() if k != "text")
    print(f"[{event}] {extra}", flush=True)


def snapshot_auth() -> dict:
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    if not AUTH_FILE.exists():
        return {"exists": False, "path": str(AUTH_FILE)}
    data = AUTH_FILE.read_bytes()
    return {
        "exists": True,
        "path": str(AUTH_FILE),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "head": data[:32].hex(),
        "ascii": "".join(chr(c) if 32 <= c < 127 else "." for c in data[:64]),
        "json_ok": _try_json(data),
    }


def _try_json(data: bytes):
    try:
        return json.loads(data.decode("utf-8"))
    except Exception:
        return None


def watch_loop(seconds: float = 60.0) -> None:
    log("watch_start", **snapshot_auth())
    last = snapshot_auth()
    t0 = time.time()
    while time.time() - t0 < seconds:
        time.sleep(0.4)
        cur = snapshot_auth()
        if cur != last:
            log("auth_changed", before=last, after=cur)
            last = cur
    log("watch_end", **snapshot_auth())


def probe_dummy(payload: bytes, label: str) -> dict:
    """Write dummy authorization.bin, launch DumpHost under Frida, capture MessageBox."""
    AUTH_DIR.mkdir(parents=True, exist_ok=True)
    if AUTH_FILE.exists():
        bak = AUTH_FILE.with_suffix(".bin.bak")
        AUTH_FILE.replace(bak)
    AUTH_FILE.write_bytes(payload)
    log("probe_write", label=label, **snapshot_auth())

    result = {"label": label, "messagebox": None, "createfile": [], "jni_leave": False, "host": None}
    try:
        import frida
    except ImportError:
        log("probe_no_frida")
        return result

    hook = (DECRYPTOR / "jnihost" / "hook_auth.js").read_text(encoding="utf-8")
    events: list[dict] = []

    def on_msg(msg, _data):
        if msg.get("type") == "send":
            events.append(msg.get("payload") or {})
        elif msg.get("type") == "error":
            events.append({"error": msg})

    java = str(JAVA)
    args = ["-cp", CP, "DumpHost", str(DLL), str(OUT / "inner")]
    pid = None
    try:
        pid = frida.spawn([java] + args, cwd=str(OUT))
        session = frida.attach(pid)
        script = session.create_script(hook)
        script.on("message", on_msg)
        script.load()
        frida.resume(pid)
        t0 = time.time()
        while time.time() - t0 < 12:
            time.sleep(0.3)
    except Exception as e:
        result["error"] = str(e)
        log("probe_error", label=label, error=str(e))
    finally:
        if pid:
            try:
                frida.kill(pid)
            except Exception:
                pass

    # parse stdout-style console from our hook via... hook uses console.log not send.
    # Fall back: read nothing; caller uses hook console. We also scan LOG later.
    result["events"] = events
    log("probe_done", label=label, **result)
    return result


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "status"
    if cmd == "status":
        s = snapshot_auth()
        print(json.dumps(s, indent=2))
        log("status", **s)
        return 0 if s.get("exists") else 2
    if cmd == "watch":
        secs = float(argv[2]) if len(argv) > 2 else 120
        watch_loop(secs)
        return 0
    if cmd == "probe":
        cases = [
            ("missing", None),
            ("empty", b""),
            ("ascii_token", b"test-token-sydney"),
            ("json", b'{"token":"x","user":"kovak"}'),
            ("rand32", os.urandom(32)),
            ("rand256", os.urandom(256)),
        ]
        print("probes write dummies then you should run frida_spawn separately if spawn fails here")
        AUTH_DIR.mkdir(parents=True, exist_ok=True)
        for label, payload in cases:
            if payload is None:
                if AUTH_FILE.exists():
                    AUTH_FILE.unlink()
                log("probe_missing", label=label)
            else:
                AUTH_FILE.write_bytes(payload)
                log("probe_write", label=label, **snapshot_auth())
            print("  ready", label, "file", AUTH_FILE.exists(), "-> run: python jnihost/frida_spawn.py")
        return 0
    print("usage: auth_monitor.py status|watch [sec]|probe")
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
