# language: Python 3, file: pe_dump.py
# Full process dump suite — module dump, VAD dump, PE fix, live IAT rebuild (Windows)
# *For Themida-class: spawn/wait → dump after runtime decrypt → fix PE → IAT map*
from __future__ import annotations

import json
import struct
import sys
import time
from pathlib import Path
from typing import Any


# ---------------------------------------------------------------------------
# PE helpers
# ---------------------------------------------------------------------------

def _pe_sections_from_bytes(data: bytes) -> list[dict[str, Any]]:
    if data[:2] != b"MZ" or len(data) < 0x200:
        return []
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if e_lfanew + 0x18 >= len(data) or data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        return []
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    magic = struct.unpack_from("<H", data, e_lfanew + 0x18)[0]
    sec = e_lfanew + 0x18 + (0xE0 if magic == 0x10B else 0xF0)
    out = []
    for i in range(min(nsec, 96)):
        o = sec + i * 40
        if o + 40 > len(data):
            break
        name = data[o : o + 8].split(b"\0", 1)[0].decode("latin-1", "replace")
        vsize, va, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
        out.append({"name": name, "va": va, "vsize": vsize, "roff": roff, "rsize": rsize})
    return out


def fix_memory_pe(dump: bytes, image_base: int | None = None) -> bytes:
    """
    Convert in-memory PE image to a disk-loadable PE:
    set each section PointerToRawData = VirtualAddress, SizeOfRawData = max(vsize, raw).
    *Standard Scylla/PE-sieve post-dump fix for Themida dumps.*
    """
    if dump[:2] != b"MZ" or len(dump) < 0x200:
        return dump
    data = bytearray(dump)
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        return dump
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    magic = struct.unpack_from("<H", data, e_lfanew + 0x18)[0]
    if magic == 0x20B and image_base is not None:
        struct.pack_into("<Q", data, e_lfanew + 0x18 + 24, image_base)
    elif magic == 0x10B and image_base is not None:
        struct.pack_into("<I", data, e_lfanew + 0x18 + 28, image_base & 0xFFFFFFFF)
    # FileAlignment / SectionAlignment — keep as-is; force raw = va for memory layout
    sec = e_lfanew + 0x18 + (0xE0 if magic == 0x10B else 0xF0)
    for i in range(min(nsec, 96)):
        o = sec + i * 40
        if o + 40 > len(data):
            break
        vsize, va, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
        # In memory dump, content already sits at VA offset from image base
        new_raw = va
        new_rsize = max(vsize, rsize)
        # clamp to dump length
        if new_raw + new_rsize > len(data):
            new_rsize = max(0, len(data) - new_raw)
        struct.pack_into("<I", data, o + 16, new_rsize)  # SizeOfRawData
        struct.pack_into("<I", data, o + 20, new_raw)  # PointerToRawData
    return bytes(data)


def rebuild_iat_from_dump(
    dump: bytes,
    image_base: int,
    modules_map: dict[str, int] | None = None,
    system_root: str | None = None,
) -> dict[str, Any]:
    """
    Resolve absolute pointers in dump against live module bases + system exports.
    modules_map: { "kernel32.dll": 0x7ffe0000, ... } from EnumProcessModules.
    """
    import os

    system_root = system_root or os.environ.get("SystemRoot", r"C:\Windows")
    modules_map = modules_map or {}

    # build reverse: address → dll!export using pe exports of local DLLs at recorded bases
    resolved = []
    export_index: dict[int, str] = {}

    if modules_map:
        try:
            import pefile
        except ImportError:
            pefile = None  # type: ignore
        if pefile:
            for dll_name, base in modules_map.items():
                # locate file
                candidates = [
                    Path(system_root) / "System32" / dll_name,
                    Path(system_root) / "SysWOW64" / dll_name,
                    Path(system_root) / "System32" / dll_name.lower(),
                ]
                dll_path = next((c for c in candidates if c.is_file()), None)
                if not dll_path:
                    continue
                try:
                    pe = pefile.PE(str(dll_path), fast_load=True)
                    pe.parse_data_directories(
                        directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]]
                    )
                    if not hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                        continue
                    for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                        if exp.name is None or exp.address is None:
                            continue
                        # skip forwarders roughly
                        addr = base + exp.address
                        export_index[addr] = f"{dll_name}!{exp.name.decode('ascii', 'ignore')}"
                except Exception:
                    continue

    limit = min(len(dump), 8 << 20)
    hits = 0
    for off in range(0, limit - 8, 8):
        val = struct.unpack_from("<Q", dump, off)[0]
        if val in export_index:
            resolved.append({"off": hex(off), "val": hex(val), "sym": export_index[val]})
            hits += 1
            if hits >= 500:
                break

    # also sample unresolved high pointers
    sample_unres = []
    if not resolved:
        for off in range(0, min(limit, 1 << 20) - 8, 8):
            val = struct.unpack_from("<Q", dump, off)[0]
            if 0x7FF000000000 <= val <= 0x7FFFFFFFFFFF:
                sample_unres.append({"off": hex(off), "val": hex(val)})
                if len(sample_unres) >= 30:
                    break

    resolved_count = len(resolved)
    unres_n = len(sample_unres)
    slots = max(resolved_count + unres_n, 1)
    ratio = round(resolved_count / slots, 4)
    sparse = len(dump) > 5_000_000 and resolved_count < 8
    return {
        "resolved_count": resolved_count,
        "resolved": resolved[:200],
        "iat_resolved": resolved_count,
        "iat_slots": slots,
        "iat_ratio": ratio,
        "iat_sparse": sparse,
        "resolved_sample": resolved[:40],
        "unresolved_pointer_sample": sample_unres,
        "modules_in_map": list(modules_map.keys())[:40],
        "image_base": hex(image_base),
        "system_root": system_root,
        "note": (
            "heuristic pointer resolve vs live exports — not PE IAT directory slot count. "
            + ("IAT sparse: dump likely still packed or IAT not rebuilt." if sparse else "")
        ),
    }


# ---------------------------------------------------------------------------
# WinAPI process helpers
# ---------------------------------------------------------------------------

def _win_apis():
    import ctypes
    from ctypes import wintypes

    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    psapi = ctypes.WinDLL("psapi", use_last_error=True)
    return ctypes, wintypes, k32, psapi


def list_process_modules(pid: int) -> list[dict[str, Any]]:
    if sys.platform != "win32":
        return []
    ctypes, wintypes, k32, psapi = _win_apis()
    handle = k32.OpenProcess(0x0410, False, pid)  # QUERY | VM_READ
    if not handle:
        return []
    hMods = (ctypes.c_void_p * 1024)()
    cb = wintypes.DWORD()
    mods = []
    if psapi.EnumProcessModules(handle, ctypes.byref(hMods), ctypes.sizeof(hMods), ctypes.byref(cb)):
        count = cb.value // ctypes.sizeof(ctypes.c_void_p)
        for i in range(count):
            base = hMods[i]
            if not base:
                continue
            name_buf = ctypes.create_unicode_buffer(260)
            path_buf = ctypes.create_unicode_buffer(520)
            psapi.GetModuleBaseNameW(handle, ctypes.c_void_p(base), name_buf, 260)
            psapi.GetModuleFileNameExW(handle, ctypes.c_void_p(base), path_buf, 520)

            class MODULEINFO(ctypes.Structure):
                _fields_ = [
                    ("lpBaseOfDll", ctypes.c_void_p),
                    ("SizeOfImage", wintypes.DWORD),
                    ("EntryPoint", ctypes.c_void_p),
                ]

            mi = MODULEINFO()
            size = 0
            if psapi.GetModuleInformation(handle, ctypes.c_void_p(base), ctypes.byref(mi), ctypes.sizeof(mi)):
                size = mi.SizeOfImage
            mods.append({
                "name": name_buf.value,
                "path": path_buf.value,
                "base": int(base) if base else 0,
                "base_hex": hex(base) if base else "0",
                "size": size,
            })
    k32.CloseHandle(handle)
    return mods


def find_pids_by_name(name: str) -> list[int]:
    if sys.platform != "win32":
        return []
    from street_decrepytor.dynamic.memory import list_processes

    name_l = name.lower()
    if name_l.endswith(".exe"):
        pass
    return [p["pid"] for p in list_processes() if p["name"].lower() == name_l or name_l in p["name"].lower()]


def dump_process_module(
    pid: int,
    module_name: str | None,
    out_path: Path,
    *,
    fix_pe: bool = True,
    rebuild_iat: bool = True,
) -> dict[str, Any]:
    """Dump main module or named module from live process (Windows)."""
    if sys.platform != "win32":
        return {"ok": False, "error": "windows_only"}
    try:
        ctypes, wintypes, k32, psapi = _win_apis()
        PROCESS_VM_READ = 0x0010
        PROCESS_QUERY_INFORMATION = 0x0400
        handle = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        if not handle:
            return {"ok": False, "error": f"OpenProcess {ctypes.get_last_error()}"}

        mods = list_process_modules(pid)
        if not mods:
            k32.CloseHandle(handle)
            waited = wait_for_modules(pid, timeout=6.0)
            mods = list_process_modules(pid)
            if not mods:
                return {"ok": False, "error": "no_modules", "wait_modules": waited}

        target = None
        if module_name is None:
            target = mods[0]
        else:
            for m in mods:
                if m["name"].lower() == module_name.lower():
                    target = m
                    break
            if target is None:
                for m in mods:
                    if module_name.lower() in m["name"].lower():
                        target = m
                        break
        if target is None:
            k32.CloseHandle(handle)
            return {"ok": False, "error": "module_not_found", "modules": mods[:40]}

        base = target["base"]
        size = target["size"]
        if size <= 0 or size > 400 << 20:
            k32.CloseHandle(handle)
            return {"ok": False, "error": f"bad size {size}"}

        # re-open for read
        handle = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, False, pid)
        buf = (ctypes.c_char * size)()
        read = ctypes.c_size_t()
        ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(base), buf, size, ctypes.byref(read))
        k32.CloseHandle(handle)
        if not ok:
            return {"ok": False, "error": f"RPM {ctypes.get_last_error()}"}

        raw = bytes(buf[: read.value])
        out_path = Path(out_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        raw_path = out_path.with_suffix(out_path.suffix + ".rawmem") if fix_pe else out_path
        if fix_pe:
            raw_path = out_path.parent / (out_path.stem + ".rawmem" + out_path.suffix)
            raw_path.write_bytes(raw)
            fixed = fix_memory_pe(raw, image_base=base)
            out_path.write_bytes(fixed)
            pe_bytes = fixed
        else:
            out_path.write_bytes(raw)
            pe_bytes = raw

        modules_map = {m["name"]: m["base"] for m in mods if m.get("base")}
        iat = (
            rebuild_iat_from_dump(pe_bytes, base, modules_map=modules_map)
            if rebuild_iat
            else {}
        )
        if rebuild_iat and (iat.get("resolved") or []) and len(iat.get("resolved") or []) >= 3:
            try:
                from street_decrepytor.protectors.themida_iat import apply_import_directory

                wr = apply_import_directory(pe_bytes, iat["resolved"], image_base=base)
                iat["writeback"] = {k: wr.get(k) for k in ("ok", "error", "names", "import_rva", "dlls", "section")}
                if wr.get("ok") and wr.get("pe"):
                    pe_bytes = wr["pe"]
                    out_path.write_bytes(pe_bytes)
            except Exception as e:
                iat["writeback"] = {"ok": False, "error": str(e)}
        disk_text = 0
        live_text = 0
        for s in _pe_sections_from_bytes(pe_bytes)[:24]:
            if s.get("name") == ".text":
                live_text = s.get("rsize") or 0
                break
        meta = {
            "ok": True,
            "pid": pid,
            "module": target["name"],
            "base": hex(base),
            "size": read.value,
            "path": str(out_path),
            "rawmem_path": str(raw_path) if fix_pe else None,
            "fix_pe": fix_pe,
            "sections": _pe_sections_from_bytes(pe_bytes)[:24],
            "iat": iat,
            "iat_quality": {
                "iat_resolved": (iat or {}).get("iat_resolved"),
                "iat_slots": (iat or {}).get("iat_slots"),
                "iat_ratio": (iat or {}).get("iat_ratio"),
                "iat_sparse": (iat or {}).get("iat_sparse"),
            },
            "text_raw_live": live_text,
            "modules_seen": [{"name": m["name"], "base": m["base_hex"], "size": m["size"]} for m in mods[:50]],
        }
        meta_path = Path(str(out_path) + ".meta.json")
        meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
        meta["meta_path"] = str(meta_path)
        return meta
    except Exception as e:
        return {"ok": False, "error": str(e)}


def dump_all_modules(pid: int, out_dir: Path, *, fix_pe: bool = True) -> dict[str, Any]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    mods = list_process_modules(pid)
    results = []
    for m in mods:
        safe = "".join(c if c.isalnum() or c in "._-" else "_" for c in m["name"])
        path = out_dir / f"{safe}_{m['base_hex']}.bin"
        r = dump_process_module(pid, m["name"], path, fix_pe=fix_pe, rebuild_iat=(m == mods[0]))
        results.append(r)
    return {"ok": True, "pid": pid, "count": len(results), "dumps": results}


def dump_vad_regions(pid: int, out_dir: Path, *, min_size: int = 0x1000, max_regions: int = 500) -> dict[str, Any]:
    """Dump committed private/executable regions (full memory map)."""
    if sys.platform != "win32":
        return {"ok": False, "error": "windows_only"}
    ctypes, wintypes, k32, _psapi = _win_apis()
    MEM_COMMIT = 0x1000
    PAGE_NOACCESS = 0x01
    PAGE_GUARD = 0x100
    PAGE_EXECUTE_ANY = 0x10 | 0x20 | 0x40 | 0x80

    class MEMORY_BASIC_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BaseAddress", ctypes.c_void_p),
            ("AllocationBase", ctypes.c_void_p),
            ("AllocationProtect", wintypes.DWORD),
            ("RegionSize", ctypes.c_size_t),
            ("State", wintypes.DWORD),
            ("Protect", wintypes.DWORD),
            ("Type", wintypes.DWORD),
        ]

    handle = k32.OpenProcess(0x0410, False, pid)
    if not handle:
        return {"ok": False, "error": f"OpenProcess {ctypes.get_last_error()}"}

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    mbi = MEMORY_BASIC_INFORMATION()
    address = 0
    regions = []
    dumped = 0
    while dumped < max_regions:
        got = k32.VirtualQueryEx(handle, ctypes.c_void_p(address), ctypes.byref(mbi), ctypes.sizeof(mbi))
        if not got:
            break
        base = mbi.BaseAddress or 0
        size = int(mbi.RegionSize or 0)
        prot = mbi.Protect or 0
        state = mbi.State or 0
        if (
            state == MEM_COMMIT
            and size >= min_size
            and size <= 64 << 20
            and not (prot & PAGE_NOACCESS)
            and not (prot & PAGE_GUARD)
        ):
            buf = (ctypes.c_char * size)()
            read = ctypes.c_size_t()
            if k32.ReadProcessMemory(handle, ctypes.c_void_p(base), buf, size, ctypes.byref(read)) and read.value:
                blob = bytes(buf[: read.value])
                is_exec = bool(prot & PAGE_EXECUTE_ANY)
                is_pe = blob[:2] == b"MZ"
                name = f"vad_{base:016x}_sz{size:x}"
                if is_pe:
                    name += "_PE"
                if is_exec:
                    name += "_X"
                path = out_dir / f"{name}.bin"
                path.write_bytes(blob)
                regions.append({
                    "base": hex(base),
                    "size": size,
                    "protect": hex(prot),
                    "exec": is_exec,
                    "pe": is_pe,
                    "path": str(path),
                })
                dumped += 1
        nxt = base + size
        if nxt <= address:
            break
        address = nxt
    k32.CloseHandle(handle)
    summary = {"ok": True, "pid": pid, "regions": len(regions), "list": regions[:100]}
    (out_dir / "vad_index.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    return summary


def _rpm_bytes(pid: int, addr: int, size: int) -> bytes:
    if sys.platform != "win32":
        return b""
    ctypes, wintypes, k32, _ = _win_apis()
    handle = k32.OpenProcess(0x0410, False, pid)
    if not handle:
        return b""
    buf = (ctypes.c_char * size)()
    n = ctypes.c_size_t()
    ok = k32.ReadProcessMemory(handle, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
    k32.CloseHandle(handle)
    if not ok:
        return b""
    return bytes(buf[: n.value])


def wait_for_modules(pid: int, timeout: float = 6.0, poll: float = 0.12) -> dict[str, Any]:
    """Wait until EnumProcessModules returns at least one module."""
    t0 = time.time()
    n = 0
    while time.time() - t0 < max(0.2, timeout):
        mods = list_process_modules(pid)
        n = len(mods)
        if n:
            return {"ok": True, "count": n, "waited": round(time.time() - t0, 3)}
        time.sleep(poll)
    return {"ok": False, "count": 0, "waited": round(time.time() - t0, 3)}


def spawn_elevated(exe_path: str | Path, args: str = "") -> dict[str, Any]:
    """ShellExecuteEx runas — UAC. Used when CreateProcess returns 740."""
    if sys.platform != "win32":
        return {"ok": False, "error": "windows_only"}
    import ctypes
    from ctypes import wintypes

    class SHELLEXECUTEINFOW(ctypes.Structure):
        _fields_ = [
            ("cbSize", wintypes.DWORD),
            ("fMask", ctypes.c_ulong),
            ("hwnd", wintypes.HWND),
            ("lpVerb", wintypes.LPCWSTR),
            ("lpFile", wintypes.LPCWSTR),
            ("lpParameters", wintypes.LPCWSTR),
            ("lpDirectory", wintypes.LPCWSTR),
            ("nShow", ctypes.c_int),
            ("hInstApp", wintypes.HINSTANCE),
            ("lpIDList", ctypes.c_void_p),
            ("lpClass", wintypes.LPCWSTR),
            ("hkeyClass", ctypes.c_void_p),
            ("dwHotKey", wintypes.DWORD),
            ("hIcon", wintypes.HANDLE),
            ("hProcess", wintypes.HANDLE),
        ]

    SEE_MASK_NOCLOSEPROCESS = 0x00000040
    sei = SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS
    sei.lpVerb = "runas"
    sei.lpFile = str(exe_path)
    sei.lpParameters = args or None
    sei.lpDirectory = str(Path(exe_path).parent)
    sei.nShow = 1
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    if not shell.ShellExecuteExW(ctypes.byref(sei)):
        return {"ok": False, "error": f"ShellExecuteEx {ctypes.get_last_error()}", "elevated": True}
    pid = int(k32.GetProcessId(sei.hProcess)) if sei.hProcess else 0
    return {"ok": pid > 0, "pid": pid, "elevated": True, "hProcess": int(sei.hProcess) if sei.hProcess else 0}


def wait_text_populated(pid: int, exe_path: str | Path, timeout: float, poll: float = 0.12) -> dict[str, Any]:
    """Poll RPM of disk .text RVA until non-zero bytes (packer filled virtual .text)."""
    secs = _pe_sections_from_bytes(Path(exe_path).read_bytes())
    text = next((s for s in secs if s.get("name") == ".text"), secs[0] if secs else None)
    if not text:
        return {"mode": "text", "ready": False, "reason": "no_section"}
    disk_raw = int(text.get("rsize") or 0)
    rva = int(text.get("va") or 0)
    if disk_raw >= 0x1000:
        return {"mode": "text", "ready": True, "note": "disk_text_present", "disk_raw": disk_raw, "waited": 0}
    deadline = time.time() + max(0.5, timeout)
    polls = 0
    last_nz = 0
    while time.time() < deadline:
        polls += 1
        mods = list_process_modules(pid)
        if mods:
            base = int(mods[0].get("base") or 0)
            chunk = _rpm_bytes(pid, base + rva, 256) if base else b""
            last_nz = sum(1 for b in chunk if b)
            if last_nz > 16:
                return {
                    "mode": "text",
                    "ready": True,
                    "polls": polls,
                    "nonzero": last_nz,
                    "waited": round(timeout - (deadline - time.time()), 2),
                    "disk_raw": disk_raw,
                }
        time.sleep(poll)
    return {
        "mode": "text",
        "ready": last_nz > 16,
        "polls": polls,
        "nonzero": last_nz,
        "timed_out": last_nz <= 16,
        "disk_raw": disk_raw,
    }


def spawn_wait_dump(
    exe_path: str | Path,
    out_dir: str | Path,
    *,
    wait_sec: float = 8.0,
    args: str = "",
    fix_pe: bool = True,
    vad: bool = True,
    kill_after: bool = True,
    wait_mode: str = "text",
    on_spawn: Any = None,
) -> dict[str, Any]:
    """
    Spawn target, wait, dump main module + optional VAD.
    wait_mode=text: poll .text RPM until populated (fallback timeout).
    wait_mode=sleep: time.sleep(wait_sec) only.
    Packer decrypts in its own process; this copies RAM.
    """
    if sys.platform != "win32":
        return {"ok": False, "error": "windows_only"}
    exe_path = Path(exe_path)
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    ctypes, wintypes, k32, _ = _win_apis()

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
    cmdline = f'"{exe_path}" {args}'.strip()
    # CREATE_NEW_CONSOLE
    ok = k32.CreateProcessW(
        str(exe_path),
        cmdline,
        None,
        None,
        False,
        0x00000010,  # CREATE_NEW_CONSOLE
        None,
        str(exe_path.parent),
        ctypes.byref(si),
        ctypes.byref(pi),
    )
    elevated = None
    if not ok:
        err = ctypes.get_last_error()
        if err == 740:
            elevated = spawn_elevated(exe_path, args)
            if not elevated.get("ok"):
                return {
                    "ok": False,
                    "error": (
                        "CreateProcess 740 ERROR_ELEVATION_REQUIRED — "
                        + str(elevated.get("error") or "UAC/runas failed")
                    ),
                    "elevated": elevated,
                }
            pid = int(elevated["pid"])
        else:
            return {"ok": False, "error": f"CreateProcess {err}"}
    else:
        pid = int(pi.dwProcessId)
    time.sleep(0.25)
    mods_wait = wait_for_modules(pid, timeout=min(8.0, max(1.5, wait_sec)))
    spawn_hook: dict[str, Any] | None = None
    if on_spawn is not None:
        try:
            spawn_hook = on_spawn(pid)
        except Exception as e:
            spawn_hook = {"ok": False, "error": str(e)}
    wait_rep: dict[str, Any]
    if wait_mode == "sleep":
        time.sleep(max(0.5, wait_sec))
        wait_rep = {"mode": "sleep", "wait_sec": wait_sec}
    else:
        wait_rep = wait_text_populated(pid, exe_path, wait_sec)

    main_dump = dump_process_module(
        pid,
        None,
        out_dir / f"{exe_path.stem}_dumped.exe",
        fix_pe=fix_pe,
        rebuild_iat=True,
    )
    vad_rep = dump_vad_regions(pid, out_dir / "vad") if vad else None
    all_mods = dump_all_modules(pid, out_dir / "modules", fix_pe=False) if vad else None

    h_proc = (elevated or {}).get("hProcess") if elevated else int(pi.hProcess or 0)
    h_thr = 0 if elevated else int(pi.hThread or 0)
    if kill_after and h_proc:
        k32.TerminateProcess(h_proc, 0)
    if h_thr:
        k32.CloseHandle(h_thr)
    if h_proc:
        k32.CloseHandle(h_proc)

    report = {
        "ok": bool(main_dump.get("ok")),
        "pid": pid,
        "elevated": elevated,
        "wait_sec": wait_sec,
        "wait": wait_rep,
        "wait_modules": mods_wait,
        "spawn_hook": spawn_hook,
        "exe": str(exe_path),
        "main_dump": main_dump,
        "vad": {"regions": (vad_rep or {}).get("regions")} if vad_rep else None,
        "modules_dumped": (all_mods or {}).get("count") if all_mods else None,
        "out_dir": str(out_dir),
    }
    (out_dir / "spawn_dump_report.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return report


def dump_file_as_unpacked_template(pe_path: Path, out_path: Path) -> dict[str, Any]:
    """Static: copy PE and mark high-entropy sections for dynamic fill-in."""
    data = pe_path.read_bytes()
    secs = _pe_sections_from_bytes(data)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(data)
    return {"ok": True, "path": str(out_path), "sections": secs, "mode": "static_copy"}


def frida_dump_on_oep_script() -> str:
    """Frida script: dump main module when VirtualProtect makes region RX/RWX after unpack."""
    return r"""
// Street-decrepytor — dump main module after VirtualProtect RX/RWX (Themida-class)
'use strict';
const main = Process.enumerateModules()[0];
console.log('[street] main', main.name, main.base, main.size);

function dumpMain(tag) {
  const buf = main.base.readByteArray(main.size);
  const path = 'street_dump_' + tag + '_' + main.name + '.bin';
  const f = new File(path, 'wb');
  f.write(buf);
  f.close();
  console.log('[street] dumped', path, main.size);
}

let dumps = 0;
const vp = Module.findExportByName('kernel32.dll', 'VirtualProtect');
if (vp) {
  Interceptor.attach(vp, {
    onEnter(args) {
      this.addr = args[0];
      this.size = args[1].toInt32();
      this.newProt = args[2].toInt32();
    },
    onLeave(retval) {
      // PAGE_EXECUTE_READ=0x20, EXECUTE_READWRITE=0x40
      if ((this.newProt === 0x20 || this.newProt === 0x40) && this.size > 0x10000) {
        console.log('[street] VirtualProtect RX/RWX', this.addr, this.size, this.newProt);
        if (dumps < 3) {
          dumps++;
          try { dumpMain('vp' + dumps); } catch (e) { console.log('[street] dump err', e); }
        }
      }
    }
  });
}
console.log('[street] hooks ready — run until unpack completes');
"""
