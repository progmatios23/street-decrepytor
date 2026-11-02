# language: Python 3, file: transforms.py
# Shared report contract: copy | patch | inflate | cipher | inventoried
from __future__ import annotations

from typing import Any


def image_transform(
    kind: str,
    layer: str,
    path: str | None = None,
    **extra: Any,
) -> dict[str, Any]:
    if kind not in ("copy", "patch", "inflate", "cipher", "inventoried", "runtime_dump"):
        raise ValueError(f"bad transform kind {kind}")
    rec: dict[str, Any] = {"kind": kind, "layer": layer, "path": path}
    rec.update(extra)
    return rec


def decrypted_flag(transforms: list[dict[str, Any]]) -> bool:
    return any(t.get("kind") in ("cipher", "runtime_dump") for t in transforms)
