# language: Python 3, file: vmprotect.py
from __future__ import annotations

from typing import Any


def vmprotect_playbook(sample_path: str) -> dict[str, Any]:
    return {
        "target": sample_path,
        "approach": "trace_vm_exit_handlers",
        "steps": [
            "identify VM enter (pushf/pusha-like + jmp into bytecode stream) via dynamic trace",
            "locate handler table by correlating bytecode fetches with dispatch indirect jmps",
            "lift only *non-virtualized* leaves first (API calls, crypto)",
            "dump after mutation completes if mutation packer mode",
            "never rely on fixed handler count — re-derive per build",
        ],
        "defeats": "static CFG flatten across protected functions",
        "caught_by": "integrity checks on VM bytecode, anti-dump checksums",
    }
