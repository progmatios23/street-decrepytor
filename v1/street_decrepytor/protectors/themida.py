# language: Python 3, file: themida.py
# Themida/WinLicense unpack *strategy* — dynamic dump first, static OEP hunt second
from __future__ import annotations

from typing import Any


def themida_playbook(sample_path: str) -> dict[str, Any]:
    """
    Per-build derivation — offsets rot every Oreans build.
    Strategy (not a single static unpacker):
      1. ScyllaHide / Themidie-style anti-anti-debug (PEB, NtQueryInformationProcess, heap flags)
      2. Run to VirtualProtect / VirtualAlloc of RWX region post-unpack
      3. Dump image when IAT writes stabilize
      4. Rebuild IAT from resolved pointers (see dynamic.memory + static IAT rebuild)
      5. Find OEP via pushad/popad transition or stolen-bytes restore patterns *derived live*
    """
    return {
        "target": sample_path,
        "approach": "dynamic_dump_first",
        "cli": "street-decrepytor themida-unpack TARGET --wait 12",
        "steps": [
            "street-decrepytor themida-unpack TARGET (PEB patch + wait .text + dump + OEP)",
            "or unpack TARGET --live",
            "attach with PEB.BeingDebugged=0, NtGlobalFlag clear, heap flags clean",
            "hook VirtualAlloc/VirtualProtect; log RWX transitions",
            "break on first transfer into newly decrypted .text",
            "full process dump + Scylla-style IAT rebuild",
            "re-derive OEP from dump (never trust last-build RVA)",
        ],
        "defeats": "user-mode debugger checks, import encryption shell",
        "caught_by": "kernel callbacks, hypervisor integrity, server-side license if present",
        "note": "Magicmida/Themidie in ANALISTAR/opencode are complementary injectors, not replacements for dump logic",
    }
