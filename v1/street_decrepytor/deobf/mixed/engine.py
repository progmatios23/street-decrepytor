# language: Python 3, file: mixed/engine.py
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from street_decrepytor.core.artifact import ArtifactProfile


def deobf_mixed(profile: ArtifactProfile, out_dir: Path) -> dict[str, Any]:
    from street_decrepytor.deobf.csharp.engine import deobf_dotnet
    from street_decrepytor.deobf.cpp_native.engine import deobf_native

    report = {
        "strategy": "split_clr_and_native",
        "dotnet": deobf_dotnet(profile, out_dir),
        "native": deobf_native(profile, out_dir),
        "note": "C++/CLI and mixed assemblies need both IL and native passes",
    }
    (out_dir / "deobf_mixed.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
