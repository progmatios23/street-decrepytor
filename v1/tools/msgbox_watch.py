#!/usr/bin/env python3
# language: Python 3 — Frida 17 MessageBox watcher + stealth-ish inject trace
# Logs ALL MessageBox* text (catches "nice try, kid" / Notice / tamper).
import json, os, re, sys, time, subprocess
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import frida

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output" / "frida_inject"
OUT.mkdir(parents=True, exist_ok=True)

JS = r"""
'use strict';

function u16(p){ try { return p ? p.readUtf16String() : null; } catch(e){ return null; } }
function u8(p){ try { return p ? p.readUtf8String() : null; } catch(e){ return null; } }

function resolve(mod, fn) {
  try {
    if (Module.getGlobalExportByName) {
      const a = Module.getGlobalExportByName(fn);
      if (a) return a;
    }
  } catch (e) {}
  try {
    const m = Process.getModuleByName(mod);
    if (m.getExportByName) return m.getExportByName(fn);
    if (m.findExportByName) return m.findExportByName(fn);
  } catch (e) {}
  return null;
}

function emit(tag, detail) {
  console.log('[' + tag + '] ' + detail);
  send({tag: tag, detail: detail});
}

// --- MessageBox family (tamper / notice) ---
const MB = [
  ['user32.dll', 'MessageBoxA'],
  ['user32.dll', 'MessageBoxW'],
  ['user32.dll', 'MessageBoxExA'],
  ['user32.dll', 'MessageBoxExW'],
  ['user32.dll', 'MessageBoxTimeoutA'],
  ['user32.dll', 'MessageBoxTimeoutW'],
];
MB.forEach(function(pair) {
  const addr = resolve(pair[0], pair[1]);
  if (!addr) { emit('miss', pair[0]+'!'+pair[1]); return; }
  Interceptor.attach(addr, {
    onEnter: function(args) {
      const wide = pair[1].indexOf('W') >= 0;
      const text = wide ? u16(args[1]) : u8(args[1]);
      const caption = wide ? u16(args[2]) : u8(args[2]);
      emit('MSGBOX', caption + ' | ' + text);
      // auto-dismiss Notice patch dialogs so flow continues
      if (text && /patch roblox|try inject|first time/i.test(text)) {
        emit('MSGBOX-AUTO', 'returning IDOK for patch notice');
        this.replace = true;
      }
      if (text && /nice try/i.test(text)) {
        emit('TAMPER', text);
      }
    },
    onLeave: function(retval) {
      if (this.replace) retval.replace(1); // IDOK
    }
  });
  emit('hook', pair[0]+'!'+pair[1]+' @ '+addr);
});

// --- inject surface ---
const WATCH = [
  ['kernel32.dll','CreateToolhelp32Snapshot'],
  ['kernel32.dll','Process32FirstW'],
  ['kernel32.dll','Process32NextW'],
  ['kernel32.dll','OpenProcess'],
  ['kernel32.dll','OpenThread'],
  ['kernel32.dll','VirtualAllocEx'],
  ['kernel32.dll','WriteProcessMemory'],
  ['kernel32.dll','CreateRemoteThread'],
  ['kernel32.dll','CreateRemoteThreadEx'],
  ['kernel32.dll','QueueUserAPC'],
  ['kernel32.dll','LoadLibraryW'],
  ['kernel32.dll','LoadLibraryExW'],
  ['ntdll.dll','NtCreateThreadEx'],
  ['ntdll.dll','NtQueueApcThread'],
  ['ntdll.dll','NtQueueApcThreadEx'],
  ['ntdll.dll','NtMapViewOfSection'],
  ['ntdll.dll','NtWriteVirtualMemory'],
];
WATCH.forEach(function(pair) {
  const addr = resolve(pair[0], pair[1]);
  if (!addr) { emit('miss', pair.join('!')); return; }
  Interceptor.attach(addr, {
    onEnter: function(args) {
      let extra = '';
      const fn = pair[1];
      if (fn === 'CreateToolhelp32Snapshot') extra = ' flags=' + args[0];
      if (fn === 'OpenProcess') extra = ' pid=' + args[2];
      if (fn === 'OpenThread') extra = ' tid=' + args[2];
      if (fn === 'QueueUserAPC') extra = ' pfn=' + args[0] + ' th=' + args[1];
      if (fn.indexOf('LoadLibrary') === 0) extra = ' path=' + (fn.indexOf('W')>=0 ? u16(args[0]) : u8(args[0]));
      if (fn === 'WriteProcessMemory') extra = ' size=' + args[3];
      if (fn === 'CreateRemoteThread' || fn === 'CreateRemoteThreadEx') extra = ' start=' + args[3];
      if (fn === 'NtCreateThreadEx') extra = ' start=' + args[4];
      emit('enter', pair[0]+'!'+fn + extra);
    },
    onLeave: function(retval) { emit('leave', pair[0]+'!'+pair[1]+' => '+retval); }
  });
  emit('hook', pair.join('!')+' @ '+addr);
});

// hide obvious frida module name from naive Module32 walks (best-effort)
try {
  const fridaMods = Process.enumerateModules().filter(m => /frida|gum-js/i.test(m.name));
  fridaMods.forEach(m => emit('frida-mod', m.name + ' base=' + m.base));
} catch (e) {}

emit('ready', 'msgbox+inject watch armed');
"""


def main():
    inj = Path(os.environ.get("UMI_INJECTOR", str(Path(os.environ["APPDATA"]) / "umi" / "bin" / "injector.exe")))
    mock = ROOT / "build" / "RobloxPlayerBeta.exe"
    lines = []
    tamper = []

    def on_msg(message, data):
        if message["type"] == "send":
            p = message.get("payload")
            if isinstance(p, dict):
                line = f"[{p.get('tag')}] {p.get('detail')}"
                if p.get("tag") == "TAMPER":
                    tamper.append(p.get("detail"))
            else:
                line = str(p)
            lines.append(line)
            print(line)
        elif message["type"] == "error":
            print("ERROR", message.get("description"))
            lines.append("ERROR " + str(message.get("description")))

    mock_proc = None
    if mock.exists():
        mock_proc = subprocess.Popen([str(mock)], cwd=str(mock.parent),
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        print(f"[+] mock pid={mock_proc.pid}")

    device = frida.get_local_device()
    print(f"[+] spawn {inj}")
    pid = device.spawn([str(inj)])
    session = device.attach(pid)
    script = session.create_script(JS)
    script.on("message", on_msg)
    script.load()
    time.sleep(0.2)
    device.resume(pid)
    timeout = float(os.environ.get("FRIDA_TIMEOUT", "35"))
    print(f"[+] resumed pid={pid} timeout={timeout}s")

    t0 = time.time()
    while time.time() - t0 < timeout:
        time.sleep(0.4)
        joined = "\n".join(lines)
        if "TAMPER" in joined and "nice try" in joined.lower():
            print("[!] tamper dialog caught")
            break
        if any(x in joined for x in ("QueueUserAPC", "NtCreateThreadEx", "CreateRemoteThread", "WriteProcessMemory")):
            # keep going a bit to collect more
            if time.time() - t0 > 8:
                pass
        try:
            device.get_process_by_pid(pid)
        except Exception:
            print("[+] process exited")
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
        "target": str(inj),
        "pid": pid,
        "tamper_messages": tamper,
        "lines": lines,
        "has_nice_try": any("nice try" in (t or "").lower() for t in tamper),
        "technique_guess": _guess(lines),
    }
    (OUT / "MSGBOX_WATCH.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    md = ["# MessageBox + inject watch", "", f"nice_try: **{report['has_nice_try']}**", f"technique: **{report['technique_guess']}**", ""]
    md += [f"- `{l}`" for l in lines]
    (OUT / "MSGBOX_WATCH.md").write_text("\n".join(md), encoding="utf-8")
    print(f"[+] wrote {OUT / 'MSGBOX_WATCH.md'}")
    print(f"[+] has_nice_try={report['has_nice_try']} technique={report['technique_guess']}")
    return 0


def _guess(lines):
    j = "\n".join(lines)
    if "QueueUserAPC" in j or "NtQueueApcThread" in j:
        return "APC"
    if "NtCreateThreadEx" in j:
        return "NtCreateThreadEx"
    if "CreateRemoteThread" in j:
        return "CreateRemoteThread"
    if "WriteProcessMemory" in j:
        return "WriteProcessMemory (+ thread prep)"
    if "OpenThread" in j and "CreateToolhelp32Snapshot" in j:
        return "SNAPTHREAD+OpenThread (APC-family prep)"
    return "unknown"


if __name__ == "__main__":
    raise SystemExit(main())
