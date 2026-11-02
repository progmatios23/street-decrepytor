# language: Python 3, file: router.py
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from street_decrepytor.core.artifact import ArtifactProfile, LangFamily


def stage_deobf_route(profile: ArtifactProfile, out_dir: Path) -> dict[str, Any]:
    family = profile.family
    result: dict[str, Any] = {"routed_to": family.value}

    if family == LangFamily.DOTNET or family == LangFamily.CPP_CLI:
        from street_decrepytor.deobf.csharp.engine import deobf_dotnet
        result["dotnet"] = deobf_dotnet(profile, out_dir)
    elif family == LangFamily.JAVA:
        from street_decrepytor.deobf.java.engine import deobf_java
        result["java"] = deobf_java(profile, out_dir)
    elif family == LangFamily.PYTHON:
        from street_decrepytor.deobf.python_rt.engine import deobf_python
        result["python"] = deobf_python(profile, out_dir)
    elif family == LangFamily.GO:
        from street_decrepytor.deobf.go_rt.engine import deobf_go
        result["go"] = deobf_go(profile, out_dir)
    elif family == LangFamily.RUST:
        from street_decrepytor.deobf.rust_rt.engine import deobf_rust
        result["rust"] = deobf_rust(profile, out_dir)
    elif family in (LangFamily.NATIVE_PE, LangFamily.NATIVE_ELF):
        from street_decrepytor.deobf.cpp_native.engine import deobf_native
        result["native"] = deobf_native(profile, out_dir)
    elif family == LangFamily.MIXED:
        from street_decrepytor.deobf.mixed.engine import deobf_mixed
        result["mixed"] = deobf_mixed(profile, out_dir)
    else:
        # still run native heuristics on PE-like
        if Path(profile.path).read_bytes()[:2] == b"MZ":
            from street_decrepytor.deobf.cpp_native.engine import deobf_native
            result["native_fallback"] = deobf_native(profile, out_dir)
        else:
            result["note"] = "no specialized deobf for family; classification only"

    (out_dir / "deobf_route.json").write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result
