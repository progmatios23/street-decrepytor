// frida_inject_trace.js — Frida 17+ compatible inject-surface capture
//   frida -f injector.exe -l tools/frida_inject_trace.js --no-pause
'use strict';

const WATCH = [
  ['kernel32.dll', 'CreateToolhelp32Snapshot'],
  ['kernel32.dll', 'Process32FirstW'],
  ['kernel32.dll', 'Process32NextW'],
  ['kernel32.dll', 'OpenProcess'],
  ['kernel32.dll', 'OpenThread'],
  ['kernel32.dll', 'VirtualAllocEx'],
  ['kernel32.dll', 'VirtualProtectEx'],
  ['kernel32.dll', 'WriteProcessMemory'],
  ['kernel32.dll', 'ReadProcessMemory'],
  ['kernel32.dll', 'CreateRemoteThread'],
  ['kernel32.dll', 'CreateRemoteThreadEx'],
  ['kernel32.dll', 'QueueUserAPC'],
  ['kernel32.dll', 'LoadLibraryA'],
  ['kernel32.dll', 'LoadLibraryW'],
  ['kernel32.dll', 'LoadLibraryExW'],
  ['kernel32.dll', 'GetProcAddress'],
  ['ntdll.dll', 'NtCreateThreadEx'],
  ['ntdll.dll', 'NtQueueApcThread'],
  ['ntdll.dll', 'NtQueueApcThreadEx'],
  ['ntdll.dll', 'NtMapViewOfSection'],
  ['ntdll.dll', 'NtCreateSection'],
  ['ntdll.dll', 'NtWriteVirtualMemory'],
  ['ntdll.dll', 'NtAllocateVirtualMemory'],
  ['ntdll.dll', 'NtProtectVirtualMemory'],
  ['ntdll.dll', 'RtlCreateUserThread'],
];

function u16(p) { try { return p ? p.readUtf16String() : null; } catch (_) { return null; } }
function u8(p) { try { return p ? p.readUtf8String() : null; } catch (_) { return null; } }

function resolveExport(modName, fn) {
  // Frida 17+: static Module.findExportByName is gone
  try {
    if (typeof Module.getGlobalExportByName === 'function') {
      const a = Module.getGlobalExportByName(fn);
      if (a) return a;
    }
  } catch (_) {}
  try {
    const m = Process.getModuleByName(modName);
    if (m && typeof m.getExportByName === 'function')
      return m.getExportByName(fn);
    if (m && typeof m.findExportByName === 'function')
      return m.findExportByName(fn);
  } catch (_) {}
  try {
    const mods = Process.enumerateModules();
    for (let i = 0; i < mods.length; i++) {
      if (mods[i].name.toLowerCase() === modName.toLowerCase()) {
        return mods[i].getExportByName(fn);
      }
    }
  } catch (_) {}
  return null;
}

function logHit(tag, detail) {
  console.log('[' + tag + '] ' + detail);
  try { send({ tag: tag, detail: detail }); } catch (_) {}
}

WATCH.forEach(function (pair) {
  const mod = pair[0], fn = pair[1];
  let addr = null;
  try { addr = resolveExport(mod, fn); } catch (e) {
    console.log('[miss] ' + mod + '!' + fn + ' err=' + e);
    return;
  }
  if (!addr) {
    console.log('[miss] ' + mod + '!' + fn);
    return;
  }
  Interceptor.attach(addr, {
    onEnter: function (args) {
      this.fn = fn; this.mod = mod;
      let extra = '';
      if (fn === 'OpenProcess') extra = ' access=' + args[0] + ' pid=' + args[2];
      else if (fn.indexOf('LoadLibrary') === 0)
        extra = ' path=' + (fn.indexOf('W') >= 0 ? u16(args[0]) : u8(args[0]));
      else if (fn === 'QueueUserAPC')
        extra = ' pfn=' + args[0] + ' thread=' + args[1] + ' ctx=' + args[2];
      else if (fn === 'CreateRemoteThread' || fn === 'CreateRemoteThreadEx')
        extra = ' proc=' + args[0] + ' start=' + args[3] + ' arg=' + args[4];
      else if (fn === 'NtCreateThreadEx')
        extra = ' process=' + args[3] + ' start=' + args[4];
      else if (fn === 'WriteProcessMemory' || fn === 'NtWriteVirtualMemory')
        extra = ' dest=' + args[1] + ' size=' + args[3];
      else if (fn === 'VirtualAllocEx')
        extra = ' size=' + args[2] + ' prot=' + args[4];
      else if (fn === 'CreateToolhelp32Snapshot')
        extra = ' flags=' + args[0];
      logHit('enter', mod + '!' + fn + extra);
    },
    onLeave: function (retval) {
      logHit('leave', this.mod + '!' + this.fn + ' => ' + retval);
    }
  });
  console.log('[hook] ' + mod + '!' + fn + ' @ ' + addr);
});

console.log('[frida] inject-trace armed (Frida 17+)');
