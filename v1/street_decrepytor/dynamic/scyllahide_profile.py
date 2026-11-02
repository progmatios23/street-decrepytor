# language: Python 3, file: scyllahide_profile.py
# Export ScyllaHide-compatible INI + Street neutralizations
from __future__ import annotations

from pathlib import Path
from typing import Any

# Based on common ScyllaHide options used against Themida/VMProtect shells
DEFAULT_PROFILE = {
    "PEBBeingDebugged": 1,
    "PEBHeapFlags": 1,
    "PEBNtGlobalFlag": 1,
    "PEBStartupInfo": 1,
    "NtSetInformationThread": 1,
    "NtQuerySystemInformation": 1,
    "NtQueryInformationProcess": 1,
    "NtQueryObject": 1,
    "NtYieldExecution": 0,
    "GetTickCount": 1,
    "GetTickCount64": 1,
    "GetLocalTime": 0,
    "GetSystemTime": 0,
    "NtGetContextThread": 1,
    "NtSetContextThread": 1,
    "NtContinue": 0,
    "KiUserExceptionDispatcher": 0,
    "NtUserBlockInput": 0,
    "NtUserFindWindowEx": 1,
    "NtUserBuildHwndList": 1,
    "NtUserQueryWindow": 1,
    "NtSetDebugFilterState": 1,
    "NtClose": 1,
    "NtCreateThreadEx": 0,
    "RemoveDebugPrivileges": 0,
    "PreventThreadCreation": 0,
    "DLLStealth": 1,
    "DLLNormal": 0,
    "DLLUnload": 0,
    "GetVersionExA": 0,
    "GetVersionExW": 0,
    "OutputDebugStringA": 1,
}


def render_ini(profile: dict[str, int], section: str = "SETTINGS") -> str:
    lines = [f"[{section}]"]
    for k, v in profile.items():
        lines.append(f"{k}={int(v)}")
    return "\n".join(lines) + "\n"


def export_scyllahide_profile(out_dir: str | Path, extra: dict[str, int] | None = None) -> dict[str, Any]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    prof = dict(DEFAULT_PROFILE)
    if extra:
        prof.update(extra)
    ini_path = out_dir / "street_scyllahide.ini"
    ini_path.write_text(render_ini(prof), encoding="utf-8")
    # also x64dbg-friendly notes
    readme = out_dir / "SCYLLAHIDE_README.txt"
    readme.write_text(
        "\n".join(
            [
                "Street-decrepytor ScyllaHide profile",
                "1. Copy street_scyllahide.ini into ScyllaHide plugin folder or import options",
                "2. Attach x64dbg → Plugins → ScyllaHide → load profile",
                "3. For Themida: enable PEB* + NtQueryInformationProcess + NtSetInformationThread",
                "4. Pair with Themidie DLL inject when Oreans checks survive user-mode hooks",
                "5. Re-test after every OS update — hook surfaces shift",
                "",
                "Street CLI PEB patch (minimal): python -m street_decrepytor peb-patch <pid>",
            ]
        ),
        encoding="utf-8",
    )
    return {"ini": str(ini_path), "readme": str(readme), "options": prof}
