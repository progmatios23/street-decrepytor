# language: Python 3, file: api_hash.py
# ROL-19 additive hash resolver (Cs2-External class, target-v2, 2026-09-05)
#
# Discovered in the .rsrc stub of Cs2-External (1).exe (sha256 a94f6513...):
# a PEB->Ldr->InMemoryOrderModuleList walker that
#   * normalizes DLL base names to UPPERCASE (a-z -> A-Z via -0x61 bounds)
#   * hashes UTF-16 names with  h = rol(h,19) + wchar   (32-bit)
#   * hashes API names the same way (wchar-form constant seen: 0x8A8B4676)
#   * resolves exports via e_lfanew -> ExportDirectory -> NumberOfNames walk
#
# Verified constants from that binary:
#   0x6E2BCA17 = KERNEL32.DLL   (utf16, uppercase)
#   0x8A8B4676 = LoadLibraryA   (utf16 form)
#
# This module cracks such hashes against common DLL/API names.
from __future__ import annotations


def _rol32(x: int, n: int) -> int:
    x &= 0xFFFFFFFF
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def hash_utf16(name: str) -> int:
    h = 0
    for ch in name.upper():
        h = (_rol32(h, 0x13) + ord(ch)) & 0xFFFFFFFF
    return h


def hash_ascii(name: str) -> int:
    h = 0
    for ch in name:
        h = (_rol32(h, 0x13) + ord(ch)) & 0xFFFFFFFF
    return h


# common names worth testing (extend per target)
DLL_NAMES = [
    "kernel32.dll", "ntdll.dll", "user32.dll", "kernelbase.dll",
    "advapi32.dll", "winhttp.dll", "bcrypt.dll", "crypt32.dll",
    "shell32.dll", "gdi32.dll", "d3d11.dll", "dxgi.dll", "dwmapi.dll",
    "msvcrt.dll", "ucrtbase.dll", "ole32.dll", "oleaut32.dll",
    "ws2_32.dll", "winmm.dll", "imm32.dll", "shlwapi.dll",
    "sechost.dll", "rpcrt4.dll", "combase.dll", "psapi.dll",
    "dbghelp.dll", "version.dll", "wintrust.dll", "iphlpapi.dll",
    "d3dcompiler_47.dll", "wininet.dll", "urlmon.dll", "mpr.dll",
]

API_NAMES = [
    "VirtualAlloc", "VirtualAllocEx", "VirtualProtect", "VirtualProtectEx",
    "VirtualFree", "VirtualFreeEx", "LoadLibraryA", "LoadLibraryW",
    "LoadLibraryExA", "LoadLibraryExW", "GetProcAddress",
    "GetModuleHandleA", "GetModuleHandleW", "GetModuleHandleExA",
    "CreateThread", "CreateRemoteThread", "CreateRemoteThreadEx",
    "ExitThread", "ExitProcess", "TerminateProcess", "TerminateThread",
    "OpenProcess", "ReadProcessMemory", "WriteProcessMemory",
    "CloseHandle", "WaitForSingleObject", "WaitForMultipleObjects",
    "GetLastError", "SetLastError", "Sleep", "SleepEx",
    "IsDebuggerPresent", "CheckRemoteDebuggerPresent",
    "GetCurrentProcess", "GetCurrentProcessId", "GetCurrentThreadId",
    "HeapAlloc", "HeapFree", "HeapCreate", "HeapDestroy",
    "CreateFileA", "CreateFileW", "ReadFile", "WriteFile",
    "FlushInstructionCache", "GetSystemTimeAsFileTime",
    "QueryPerformanceCounter", "GetTickCount", "GetTickCount64",
    "CreateProcessA", "CreateProcessW", "WinExec", "ShellExecuteA",
    "WinHttpOpen", "WinHttpConnect", "WinHttpOpenRequest",
    "WinHttpSendRequest", "WinHttpReadData", "WinHttpCloseHandle",
    "CryptStringToBinaryA", "CryptStringToBinaryW",
    "BCryptVerifySignature", "BCryptOpenAlgorithmProvider",
    "ConvertSidToStringSidA", "ConvertSidToStringSidW",
    "VirtualQuery", "VirtualQueryEx", "IsBadReadPtr", "IsBadWritePtr",
    "IsBadCodePtr", "IsBadStringPtrA",
    "RtlDecompressBuffer", "RtlCompressBuffer", "RtlGetCompressionWorkSpaceSize",
    "lstrcmpiA", "lstrcmpiW", "lstrcmpA", "lstrcmpW",
    "lstrlenA", "lstrlenW", "lstrcpyA", "lstrcpyW",
    "FreeLibrary", "FreeLibraryAndExitThread", "GetModuleFileNameA",
    "GetModuleFileNameW", "DisableThreadLibraryCalls",
    "NtAllocateVirtualMemory", "NtProtectVirtualMemory",
    "NtCreateSection", "NtMapViewOfSection", "NtUnmapViewOfSection",
    "NtQueryInformationProcess", "NtClose", "RtlInitUnicodeString",
    "LdrLoadDll", "LdrGetProcedureAddress",
    "MessageBoxA", "MessageBoxW", "SetWindowsHookExA",
    "GetAsyncKeyState", "GetKeyState", "GetKeyboardState",
    "FindWindowA", "FindWindowW", "FindWindowExA",
    "SetWindowLongA", "SetWindowLongW", "GetWindowLongA",
    "D3D11CreateDeviceAndSwapChain", "DwmExtendFrameIntoClientArea",
    "PostMessageA", "SendMessageA", "RegisterClassA", "RegisterClassW",
    "CreateWindowExA", "CreateWindowExW", "DefWindowProcA",
    "PeekMessageA", "GetMessageA", "TranslateMessage", "DispatchMessageA",
]


def crack(target: int, extra_names: list[str] | None = None) -> list[tuple[str, str]]:
    """Try to match `target` against known names in all accepted forms.

    Returns [(form, name), ...] — form is one of:
      utf16 / ascii / ascii-lower
    """
    names = list(DLL_NAMES) + list(API_NAMES) + (extra_names or [])
    out = []
    for n in names:
        if hash_utf16(n) == target:
            out.append(("utf16", n))
        if hash_ascii(n) == target:
            out.append(("ascii", n))
        if hash_ascii(n.lower()) == target:
            out.append(("ascii-lower", n))
    return out


def crack_many(targets: list[int], extra_names: list[str] | None = None) -> dict[int, list[tuple[str, str]]]:
    return {t: crack(t, extra_names) for t in targets}
