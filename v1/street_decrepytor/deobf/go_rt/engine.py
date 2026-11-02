# language: Python 3, file: go_rt/engine.py
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from street_decrepytor.core.artifact import ArtifactProfile


def deobf_go(profile: ArtifactProfile, out_dir: Path) -> dict[str, Any]:
    data = Path(profile.path).read_bytes()[: 8 << 20]
    build_ids = re.findall(rb"Go build ID: ([^\x00]{8,80})", data)
    paths = re.findall(rb"([a-zA-Z0-9_\-./]+/vendor/[a-zA-Z0-9_\-./]+)", data[: 2 << 20])
    report = {
        "build_ids": [b.decode("utf-8", "replace") for b in build_ids[:5]],
        "vendor_paths_sample": [p.decode("utf-8", "replace") for p in paths[:30]],
        "plan": [
            "recover pclntab / moduledata (version-specific; re-derive offsets)",
            "symbolize functions via pclntab even when stripped",
            "string decrypt only if garble/obfuscator present — hook runtime or emulate",
        ],
    }
    (out_dir / "deobf_go.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
