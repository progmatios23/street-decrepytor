# language: Python 3, file: api_intercept.py
# API / syscall intercept plan + Frida script generator (no hardcoded offsets)
from __future__ import annotations

from typing import Any

# Core surfaces any language runtime eventually hits on Windows
DEFAULT_HOOK_SET = [
    # memory
    "kernel32!VirtualAlloc",
    "kernel32!VirtualAllocEx",
    "kernel32!VirtualProtect",
    "kernel32!VirtualProtectEx",
    "kernel32!WriteProcessMemory",
    "kernel32!ReadProcessMemory",
    "kernel32!CreateRemoteThread",
    "kernel32!CreateRemoteThreadEx",
    "ntdll!NtAllocateVirtualMemory",
    "ntdll!NtProtectVirtualMemory",
    "ntdll!NtWriteVirtualMemory",
    "ntdll!NtCreateThreadEx",
    "ntdll!NtMapViewOfSection",
    # modules
    "kernel32!LoadLibraryA",
    "kernel32!LoadLibraryW",
    "kernel32!LoadLibraryExW",
    "kernel32!GetProcAddress",
    "ntdll!LdrLoadDll",
    # crypto (CNG/legacy)
    "bcrypt!BCryptDecrypt",
    "bcrypt!BCryptEncrypt",
    "advapi32!CryptDecrypt",
    # anti-debug
    "kernel32!IsDebuggerPresent",
    "kernel32!CheckRemoteDebuggerPresent",
    "ntdll!NtQueryInformationProcess",
    # file / net often used by droppers
    "kernel32!CreateFileW",
    "winhttp!WinHttpSendRequest",
    "wininet!InternetReadFile",
]


def frida_script(hooks: list[str] | None = None) -> str:
    hooks = hooks or DEFAULT_HOOK_SET
    # Generate a Frida JS interceptor that logs + optionally dumps buffers
    lines = [
        "// Street-decrepytor generated Frida intercept — re-resolve exports live",
        "function safeStr(p){ try{ return p?p.readUtf8String():null;}catch(e){return null;} }",
        "const targets = " + str(hooks) + ";",
        """
for (const t of targets) {
  const [mod, fn] = t.split('!');
  const addr = Module.findExportByName(mod, fn);
  if (!addr) { console.log('[miss] '+t); continue; }
  Interceptor.attach(addr, {
    onEnter(args) {
      this.t = t;
      console.log('[enter] '+t+' '+args[0]+' '+args[1]+' '+args[2]);
    },
    onLeave(retval) {
      console.log('[leave] '+this.t+' => '+retval);
    }
  });
  console.log('[hook] '+t+' @ '+addr);
}
""",
    ]
    return "\n".join(lines)


def intercept_plan(family: str) -> dict[str, Any]:
    plan = {
        "family": family,
        "hooks": DEFAULT_HOOK_SET,
        "frida_js": frida_script(),
        "notes": [
            "Resolve exports at runtime — never pin absolute addresses",
            "For syscalls: prefer ntdll hooks or instrumentation callback over SSDT",
            "Junk/dead code flagged offline; virtualization stubs via handler-table recovery",
        ],
    }
    if family == "dotnet":
        plan["extra_hooks"] = ["clr!compileMethod", "clrjit!compileMethod"]
    if family == "python":
        plan["extra_hooks"] = ["python3*.dll!PyEval_EvalCode", "python3*.dll!PyMarshal_ReadObjectFromString"]
    return plan
