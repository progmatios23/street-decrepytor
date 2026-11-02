# language: Python 3, file: cpp_native/engine.py
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from street_decrepytor.core.artifact import ArtifactProfile
from street_decrepytor.static.junk import _disasm_region, score_junk


def deobf_native(profile: ArtifactProfile, out_dir: Path) -> dict[str, Any]:
    data = Path(profile.path).read_bytes()
    if profile.size > 30 << 20:
        data = data[:20 << 20]
    code = data[0x1000:0x1000 + 0x4000] if len(data) > 0x5000 else data[:0x2000]
    insns = _disasm_region(code, 0x1000, profile.arch)
    junk = score_junk(insns)
    report = {
        "entry_region_junk": junk,
        "plan": [
            "build CFG; drop unreachable blocks after constant folding",
            "pattern-agnostic opaque predicate kill (symbolic or trace-derived)",
            "if virtualized: handler lift (see protectors.vmprotect)",
            "IAT rebuild from dump when imports encrypted",
        ],
    }
    (out_dir / "deobf_native.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
