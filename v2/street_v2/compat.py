# language: Python 3.11+, file: compat.py
# Import v1 street_decrepytor from the parent home tree (D:\Street-decrepytor)
from __future__ import annotations

import sys
from pathlib import Path

_V1: object | None = None


def v1_root() -> Path:
    # street_v2/compat.py → v2/ → Street-decrepytor/
    return Path(__file__).resolve().parents[2]


def ensure_v1_path() -> Path:
    root = v1_root()
    s = str(root)
    if s not in sys.path:
        sys.path.insert(0, s)
    return root


def import_v1():
    global _V1
    if _V1 is not None:
        return _V1
    ensure_v1_path()
    import street_decrepytor as pkg  # noqa: WPS433

    _V1 = pkg
    return pkg
