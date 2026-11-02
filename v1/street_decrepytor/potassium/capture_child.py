# language: Python 3, file: capture_child.py
# Official child PE capture path — lab procedure when CDN/auth available
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

# From AUDIT_FULL / TASK_POTASSIUM_HYPERION
EXPECTED_CHILD_SHA_PREFIX = "eb49692a"  # CDN v2.4.2 child — update per version
EXPECTED_DLL_SHA_PREFIX = "9ea56355"
STUB_SIZE = 138752
STUB_SHA_PREFIX = "419148FF"

WATCH_DIRS = [
    Path(r"%LOCALAPPDATA%\Potassium\bin").expanduser() if False else Path.home() / "AppData/Local/Potassium/bin",
    Path(r"C:\claude\cracked\bin"),
    Path(r"C:\claude\cracked-new\bin") if Path(r"C:\claude\cracked-new\bin").exists() else None,
    Path(r"C:\Users\ggles\Downloads\ANALISTAR\OpXOyuApWKTlFzrV\bin"),
]


def _sha16(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()[:16].upper()


def classify_child_candidate(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"path": str(path), "status": "missing"}
    size = path.stat().st_size
    sha = _sha16(path)
    if size == STUB_SIZE or sha.startswith(STUB_SHA_PREFIX[:8]):
        status = "STUB_NOOP"
    elif sha.lower().startswith(EXPECTED_CHILD_SHA_PREFIX[:8].lower()):
        status = "OFFICIAL_MATCH_PREFIX"
    elif size > 500_000:
        status = "CANDIDATE_LARGE"
    else:
        status = "UNKNOWN_SMALL"
    return {"path": str(path), "size": size, "sha16": sha, "status": status}


def scan_for_child(extra_roots: list[str | Path] | None = None) -> dict[str, Any]:
    roots = [p for p in WATCH_DIRS if p]
    if extra_roots:
        roots.extend(Path(p) for p in extra_roots)
    found = []
    for root in roots:
        if not root or not Path(root).exists():
            continue
        for p in Path(root).rglob("Potassium.exe"):
            # skip UI-sized ~25MB as primary UI; child historically ~hundreds KB to few MB
            # still classify all
            found.append(classify_child_candidate(p))
    # also bin\ named injector patterns
    for root in roots:
        if not root or not Path(root).exists():
            continue
        for name in ("injector.exe", "PotassiumChild.exe", "child.exe"):
            p = Path(root) / name
            if p.is_file():
                found.append(classify_child_candidate(p))
    official = [f for f in found if f.get("status") == "OFFICIAL_MATCH_PREFIX"]
    stubs = [f for f in found if f.get("status") == "STUB_NOOP"]
    return {
        "expected_child_sha_prefix": EXPECTED_CHILD_SHA_PREFIX,
        "expected_dll_sha_prefix": EXPECTED_DLL_SHA_PREFIX,
        "candidates": found,
        "official_hits": official,
        "stubs": stubs,
        "inject_complete": bool(official),
        "capture_procedure": capture_procedure(),
    }


def capture_procedure() -> list[str]:
    return [
        "1. Lab VM only; snapshot before hosts changes",
        "2. Remove hosts pins for api.potassium.pro / files.potassium.pro OR elevate capture_real/sni_proxy.py",
        "3. Valid subscriber login token required for binary body (public /hashes lists hashes only)",
        "4. Boot legitimate UI → download → watch %LOCALAPPDATA%\\Potassium\\bin\\Potassium.exe",
        "5. Hash child: expect prefix eb49692a… for v2.4.2 (re-derive from /hashes when version moves)",
        "6. Copy child into cracked-new/bin + Street fixtures; run: sdc analyze <child> && sdc potassium",
        "7. Match DLL to same CDN version → recrack gates via recrack_dll / gate table regen",
        "8. Live: attach → netstat :8225 → run_script print from game",
        "BLOCKED without step 3 token — Street will not fake inject-complete",
    ]


def write_capture_status(out_dir: str | Path) -> dict[str, Any]:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    report = scan_for_child()
    (out / "child_capture_status.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (out / "CAPTURE_CHILD.md").write_text(
        "# Capture official Potassium child\n\n"
        + "\n".join(f"- {s}" for s in report["capture_procedure"])
        + "\n\n## Last scan\n\n```json\n"
        + json.dumps({k: report[k] for k in ("official_hits", "stubs", "inject_complete")}, indent=2)
        + "\n```\n",
        encoding="utf-8",
    )
    return report
