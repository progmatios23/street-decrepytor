# language: Python 3, file: java/engine.py
from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

from street_decrepytor.core.artifact import ArtifactProfile


def deobf_java(profile: ArtifactProfile, out_dir: Path) -> dict[str, Any]:
    path = Path(profile.path)
    classes = []
    manifests = []
    try:
        with zipfile.ZipFile(path, "r") as z:
            for n in z.namelist():
                if n.endswith(".class"):
                    classes.append(n)
                if n.endswith("MANIFEST.MF"):
                    manifests.append(z.read(n).decode("utf-8", "replace")[:2000])
    except zipfile.BadZipFile:
        # single .class or fall through to string emu
        from street_decrepytor.deobf.java.string_emu import deobf_java_strings

        report = deobf_java_strings(path)
        (out_dir / "deobf_java.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        return report

    from street_decrepytor.deobf.java.string_emu import deobf_java_strings

    string_pass = deobf_java_strings(path)
    report = {
        "class_count": len(classes),
        "sample_classes": classes[:40],
        "manifest_sample": manifests[:1],
        "string_emu": {
            "classes_scanned": string_pass.get("classes_scanned"),
            "decryptor_hints": string_pass.get("decryptor_hints"),
        },
        "plan": string_pass.get("plan")
        or [
            "detect Allatori/Zelix/Stringer via class name entropy + bootstrap decryptors",
            "run string decrypt pass (emulate static methods returning String)",
            "rebuild CFG from flattened switches",
            "export decompiled sources via CFR/Fernflower after cleanup",
        ],
    }
    (out_dir / "deobf_java.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
