# language: Python 3, file: cli/cmd_groups.py
# Click groups wrapping the same flat commands (aliases, not duplicates).
from __future__ import annotations

import click


def register_groups(main: click.Group) -> None:
    def _grp(name: str, help_text: str, names: tuple[str, ...]) -> None:
        @main.group(name, help=help_text)
        def _g() -> None:
            pass

        for n in names:
            cmd = main.commands.get(n)
            if cmd is not None:
                _g.add_command(cmd)

    _grp("static", "Classify / strings / junk / protectors / deobf / cfg / disasm", (
        "classify", "analyze", "pipeline", "protectors", "junk", "strings",
        "deobf", "cfg", "disasm", "dotnet-analyze",
    ))
    _grp("extract", "Honest extract + Themida live unpack", ("unpack", "themida-unpack", "themida-rebuild", "recover"))
    _grp("live", "Dump / validate / hooks (Windows)", (
        "dump", "pe-dump", "themida-unpack", "memscan", "validate", "observe-syscalls",
        "stub-db", "stub-integrity", "peb-probe", "peb-patch", "themida-phylo",
        "frida-script", "frida-run", "syscall-map", "scyllahide-export",
    ))
    _grp("k", "Potassium-only (not universal)", (
        "cdn-pull", "recrack", "gates-apply", "potassium", "capture-child", "simd-emu",
    ))
    _grp("report", "One-shot JSON/MD reports", ("crack", "batch", "agent"))
