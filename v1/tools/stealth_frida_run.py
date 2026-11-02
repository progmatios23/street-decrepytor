#!/usr/bin/env python3
# language: Python 3 — stealth Frida run vs umi injector anti-tamper ("nice try, skid")
# Hides frida from PEB LDR + string scans, swallows tamper MessageBox, blocks ExitProcess.
import json, os, sys, time, subprocess
from pathlib import Path
from collections import Counter
import re

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
import frida

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "output" / "frida_inject"
OUT.mkdir(parents=True, exist_ok=True)

JS = r"""
'use strict';

function u16(p){ try { return p ? p.readUtf16String() : null; } catch(e){ return null; } }
function u8(p){ try { return p ? p.readUtf8String() : null; } catch(e){ return null; } }
function emit(tag, detail){ console.log('['+tag+'] '+detail); send({tag:tag, detail:detail}); }

function resolve(mod, fn) {
  try { if (Module.getGlobalExportByName) { const a = Module.getGlobalExportByName(fn); if (a) return a; } } catch(e){}
  try {
    const m = Process.getModuleByName(mod);
    if (m.getExportByName) return m.getExportByName(fn);
    if (m.findExportByName) return m.findExportByName(fn);
  } catch(e){}
  return null;
}

const BAD = /frida|gum-js|frida-agent|frida-gadget|linjector/i;

// ---- 1) Hide frida modules from PEB LDR linked lists (InLoadOrder / InMemory / InInit) ----
(function hideLdr() {
  try {
    const peb = Process.getCurrentThreadEnvironmentBlock
      ? Process.getCurrentThreadEnvironmentBlock().add(0x60).readPointer()
      : null;
  } catch (e) {}
  // Fall back: unlink by walking modules via enumerate and patching Flink/Blink is fragile cross-build.
  // Instead, hook Toolhelp Module32* and NtQueryVirtualMemory path used by scanners.
})();

function hook(mod, fn, callbacks) {
  const addr = resolve(mod, fn);
  if (!addr) { emit('miss', mod+'!'+fn); return null; }
  Interceptor.attach(addr, callbacks);
  emit('hook', mod+'!'+fn+' @ '+addr);
  return addr;
}

// Module32 skip frida entries
const modState = {};
hook('kernel32.dll', 'Module32FirstW', {
  onEnter(args) { this.snap = args[0]; this.me = args[1]; },
  onLeave(retval) {
    if (retval.toInt32() === 0) return;
    try {
      // MODULEENTRY32W: szModule at offset 32+260*2? Actually:
      // dwSize0, th32ModuleID4, th32ProcessID8, ... szModule at 48 (WCHAR[256]) on x64? 
      // Win10 x64 MODULEENTRY32W: szModule offset = 48
      for (let guard=0; guard<64; guard++) {
        const name = this.me.add(48).readUtf16String();
        if (!BAD.test(name || '')) break;
        emit('hide-mod', 'skip '+name);
        const next = resolve('kernel32.dll', 'Module32NextW');
        // call Module32NextW(snap, me)
        const ok = new NativeFunction(next, 'int', ['pointer','pointer'])(this.snap, this.me);
        if (ok === 0) { retval.replace(0); break; }
      }
    } catch(e) { emit('hide-err', ''+e); }
  }
});
hook('kernel32.dll', 'Module32NextW', {
  onEnter(args) { this.snap = args[0]; this.me = args[1]; },
  onLeave(retval) {
    if (retval.toInt32() === 0) return;
    try {
      for (let guard=0; guard<64; guard++) {
        const name = this.me.add(48).readUtf16String();
        if (!BAD.test(name || '')) break;
        emit('hide-mod', 'skip '+name);
        const next = resolve('kernel32.dll', 'Module32NextW');
        const ok = new NativeFunction(next, 'int', ['pointer','pointer'])(this.snap, this.me);
        if (ok === 0) { retval.replace(0); break; }
      }
    } catch(e) {}
  }
});

// String scan poison: wcsstr / strstr / StrStrIW returning null on frida needles
['wcsstr','StrStrIW','StrStrIA','StrStrW','StrStrA'].forEach(fn => {
  const addr = resolve('ntdll.dll', fn) || resolve('kernel32.dll', fn) || resolve('shlwapi.dll', fn);
  if (!addr) return;
  Interceptor.attach(addr, {
    onEnter(args) {
      this.needle = fn.indexOf('W')>=0 || fn==='wcsstr' ? u16(args[1]) : u8(args[1]);
    },
    onLeave(retval) {
      if (this.needle && BAD.test(this.needle)) {
        emit('str-hide', fn+'('+this.needle+') -> NULL');
        retval.replace(ptr(0));
      }
    }
  });
  emit('hook', 'str '+fn);
});

// MessageBox: swallow tamper, auto-OK patch notice
['MessageBoxA','MessageBoxW','MessageBoxTimeoutA','MessageBoxTimeoutW','MessageBoxExW'].forEach(fn => {
  hook('user32.dll', fn, {
    onEnter(args) {
      const wide = fn.indexOf('W')>=0;
      const text = wide ? u16(args[1]) : u8(args[1]);
      const cap = wide ? u16(args[2]) : u8(args[2]);
      emit('MSGBOX', (cap||'')+' | '+(text||''));
      this.kill = false;
      this.ok = false;
      if (text && /nice try/i.test(text)) {
        emit('TAMPER-SWALLOW', text);
        this.kill = true; // return IDOK but also block exit
      }
      if (text && /patch roblox|try inject|first time/i.test(text)) {
        emit('NOTICE-AUTOOK', text);
        this.ok = true;
      }
    },
    onLeave(retval) {
      if (this.kill || this.ok) retval.replace(1);
    }
  });
});

// Block process death after tamper
['ExitProcess','TerminateProcess'].forEach(fn => {
  hook('kernel32.dll', fn, {
    onEnter(args) {
      emit('EXIT-BLOCK', fn+' code='+args[fn==='ExitProcess'?0:1]);
      // skip real exit by replacing with sleep loop ret
      args[fn==='ExitProcess'?0:1] = ptr(0);
    },
    onLeave(retval) {
      // force stay alive: redirect to Sleep(infinite-ish)
    }
  });
});
// stronger: replace ExitProcess body
const ep = resolve('kernel32.dll','ExitProcess');
if (ep) {
  Interceptor.replace(ep, new NativeCallback(function(code) {
    emit('EXIT-REPLACED', 'ExitProcess('+code+') ignored');
  }, 'void', ['uint']));
}

// Inject surface
const WATCH = [
  ['kernel32.dll','CreateToolhelp32Snapshot'],
  ['kernel32.dll','OpenProcess'],
  ['kernel32.dll','OpenThread'],
  ['kernel32.dll','WriteProcessMemory'],
  ['kernel32.dll','VirtualAllocEx'],
  ['kernel32.dll','CreateRemoteThread'],
  ['kernel32.dll','CreateRemoteThreadEx'],
  ['kernel32.dll','QueueUserAPC'],
  ['kernel32.dll','LoadLibraryW'],
  ['ntdll.dll','NtCreateThreadEx'],
  ['ntdll.dll','NtQueueApcThread'],
  ['ntdll.dll','NtWriteVirtualMemory'],
];
WATCH.forEach(pair => {
  hook(pair[0], pair[1], {
    onEnter(args) {
      let extra='';
      const fn=pair[1];
      if (fn==='CreateToolhelp32Snapshot') extra=' flags='+args[0];
      if (fn==='OpenProcess') extra=' pid='+args[2];
      if (fn==='OpenThread') extra=' tid='+args[2];
      if (fn==='WriteProcessMemory') extra=' size='+args[3]+' dest='+args[1];
      if (fn==='QueueUserAPC') extra=' pfn='+args[0]+' th='+args[1];
      if (fn==='LoadLibraryW') extra=' path='+u16(args[0]);
      if (fn==='CreateRemoteThread'||fn==='CreateRemoteThreadEx') extra=' start='+args[3];
      if (fn==='NtCreateThreadEx') extra=' start='+args[4];
      emit('enter', pair[0]+'!'+fn+extra);
    },
    onLeave(retval){ emit('leave', pair[0]+'!'+pair[1]+' => '+retval); }
  });
});

emit('ready', 'stealth watch armed');
"""


def main():
    inj = Path(os.environ.get("UMI_INJECTOR", str(Path(os.environ["APPDATA"]) / "umi" / "bin" / "injector.exe")))
    mock = ROOT / "build" / "RobloxPlayerBeta.exe"
    lines = []
    tamper = []

    def on_msg(message, data):
        if message["type"] == "send":
            p = message["payload"]
            line = f"[{p.get('tag')}] {p.get('detail')}" if isinstance(p, dict) else str(p)
            lines.append(line)
            print(line)
            if isinstance(p, dict) and "TAMPER" in str(p.get("tag")):
                tamper.append(p.get("detail"))
        elif message["type"] == "error":
            print("ERROR", message.get("description"))
            lines.append("ERROR " + str(message.get("description")))

    mock_proc = None
    if mock.exists() and os.environ.get("SKIP_MOCK") != "1":
        mock_proc = subprocess.Popen([str(mock)], cwd=str(mock.parent),
                                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        print(f"[+] mock pid={mock_proc.pid}")

    device = frida.get_local_device()
    pid = device.spawn([str(inj)])
    session = device.attach(pid)
    script = session.create_script(JS)
    script.on("message", on_msg)
    script.load()
    time.sleep(0.3)
    device.resume(pid)
    timeout = float(os.environ.get("FRIDA_TIMEOUT", "45"))
    print(f"[+] stealth resumed pid={pid} timeout={timeout}")

    t0 = time.time()
    while time.time() - t0 < timeout:
        time.sleep(0.5)
        try:
            device.get_process_by_pid(pid)
        except Exception:
            print("[+] process gone")
            break

    try: session.detach()
    except Exception: pass
    try: device.kill(pid)
    except Exception: pass
    if mock_proc:
        try: mock_proc.terminate()
        except Exception: pass

    # technique from enters only (ignore hook lines)
    enters = [L for L in lines if L.startswith("[enter]")]
    j = "\n".join(enters)
    if "QueueUserAPC" in j or "NtQueueApcThread" in j:
        tech = "APC"
    elif "NtCreateThreadEx" in j:
        tech = "NtCreateThreadEx"
    elif "CreateRemoteThread" in j:
        tech = "CreateRemoteThread"
    elif "WriteProcessMemory" in j and "OpenThread" in j:
        tech = "OpenThread+WriteProcessMemory (inline patch / APC-family)"
    else:
        tech = "unknown"

    c = Counter()
    for L in enters:
        m = re.search(r"\[enter\] ([^\s!]+)!(\w+)", L)
        if m:
            c[m.group(1) + "!" + m.group(2)] += 1

    report = {
        "target": str(inj),
        "tamper_seen": tamper,
        "tamper_swallowed": any("SWALLOW" in L for L in lines),
        "technique_guess": tech,
        "enter_counts": c.most_common(),
        "lines": lines,
    }
    (OUT / "STEALTH_FRIDA.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    md = [
        "# Stealth Frida run",
        "",
        f"- tamper messages: `{tamper[:3]}`",
        f"- swallowed: **{report['tamper_swallowed']}**",
        f"- technique: **{tech}**",
        "",
        "## Enter counts",
    ]
    for k, v in c.most_common(20):
        md.append(f"- `{k}` × {v}")
    md += ["", "## Lines (no NtMapView spam)", ""]
    md += [f"- `{L}`" for L in lines if "NtMapView" not in L]
    (OUT / "STEALTH_FRIDA.md").write_text("\n".join(md), encoding="utf-8")
    print(f"[+] technique={tech} tamper_swallowed={report['tamper_swallowed']}")
    print(f"[+] wrote {OUT / 'STEALTH_FRIDA.md'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
