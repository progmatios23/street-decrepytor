# language: Python 3, file: strings.py
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from street_decrepytor.core.artifact import ArtifactProfile

_ASCII = re.compile(rb"[\x20-\x7e]{6,}")
_UTF16 = re.compile(rb"(?:[\x20-\x7e]\x00){6,}")


def _is_noise(s: str) -> bool:
    """Drop disassembly / epilogue garbage that flooded FarmServices path buckets."""
    if len(s) < 4:
        return True
    # register pop epilogues: A_A^A]_^[]
    if s.count("A_") >= 1 and s.count("A^") + s.count("A]") + s.count("A\\") >= 2:
        return True
    if re.fullmatch(r"[A-Z$\\^_\[\]0-9<> ]{6,}", s) and "A_" in s:
        return True
    # mostly non-alnum
    alnum = sum(c.isalnum() for c in s)
    if alnum / max(1, len(s)) < 0.35 and not s.startswith("http"):
        return True
    return False


def extract_strings(data: bytes, limit: int = 5000) -> list[str]:
    found: list[str] = []
    for m in _ASCII.finditer(data):
        s = m.group().decode("ascii", "ignore")
        if _is_noise(s):
            continue
        found.append(s)
        if len(found) >= limit:
            break
    if len(found) < limit:
        for m in _UTF16.finditer(data):
            try:
                s = m.group().decode("utf-16-le", "ignore")
            except Exception:
                continue
            if _is_noise(s):
                continue
            found.append(s)
            if len(found) >= limit:
                break
    return found


def _looks_like_path(s: str) -> bool:
    if len(s) < 6 or _is_noise(s):
        return False
    if re.match(r"^[A-Za-z]:\\", s):
        return True
    if s.startswith("\\\\") or s.startswith("/usr/") or s.startswith("/home/"):
        return True
    if s.count("\\") >= 2 and any(c.isalpha() for c in s):
        # require at least one alnum segment longer than 2
        parts = [p for p in re.split(r"[\\/]", s) if len(p) > 2]
        return len(parts) >= 2 and not all(_is_noise(p) for p in parts)
    return False


_URL_RE = re.compile(
    r"https?://(?:localhost|127\.0\.0\.1|[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::\d{1,5})?(?:/[A-Za-z0-9._~/=?&%#-]*)?"
)
_RAW_URL = re.compile(
    rb"https?://(?:localhost|127\.0\.0\.1|[A-Za-z0-9.-]+\.[A-Za-z]{2,})(?::\d{1,5})?(?:/[A-Za-z0-9._~/=?&%#-]*)?"
)


def is_plausible_url(u: str) -> bool:
    u = u.strip().rstrip(").,;'\"")
    if "://" not in u or " " in u:
        return False
    host = u.split("://", 1)[1].split("/")[0].split(":")[0]
    if host in ("127.0.0.1", "localhost"):
        return True
    if "." not in host:
        return False
    junk = ("according", "description", "text-align", "dummy.test", "www.world", "www.recent", "html4/loose")
    low = u.lower()
    if any(j in low for j in junk):
        return False
    if len(host) < 4:
        return False
    return True


def extract_urls(data: bytes, strings: list[str] | None = None) -> list[str]:
    found: set[str] = set()
    cap = data[: 20 << 20]
    for m in _RAW_URL.finditer(cap):
        s = m.group().decode("ascii", "ignore")
        if is_plausible_url(s):
            found.add(s.rstrip(").,;'"))
    for s in strings or []:
        for m in _URL_RE.finditer(s):
            u = m.group(0)
            if is_plausible_url(u):
                found.add(u.rstrip(").,;'"))
    return sorted(found)


def classify_interesting(strings: list[str]) -> dict[str, list[str]]:
    buckets: dict[str, list[str]] = {
        "urls": [],
        "paths": [],
        "crypto_words": [],
        "antidebug": [],
        "dotnet_obf": [],
        "python_freeze": [],
        "java": [],
        "error_messages": [],
        "auth_license": [],
    }
    for s in strings:
        if _is_noise(s):
            continue
        sl = s.lower()
        for m in _URL_RE.finditer(s):
            u = m.group(0)
            if is_plausible_url(u):
                buckets["urls"].append(u.rstrip(").,;'"))
        if _looks_like_path(s):
            buckets["paths"].append(s)
        if any(k in sl for k in ("aes", "rsa", "xor", "chacha", "salsa", "rc4", "sha256", "encrypt", "decrypt", "cipher")):
            buckets["crypto_words"].append(s)
        if any(k in sl for k in ("debugger", "isdebuggerpresent", "ntqueryinformation", "outputdebug", "rdtsc", "vmware", "virtualbox", "sandbox")):
            buckets["antidebug"].append(s)
        if any(k in sl for k in ("confuser", "smartassembly", "dnguard", "agiledotnet", "obfuscar", "dotfuscator", "babel", ".cctor")):
            buckets["dotnet_obf"].append(s)
        if any(k in sl for k in ("pyinstaller", "py2exe", "pyi-", "mei\x0c", "_pytransform")):
            buckets["python_freeze"].append(s)
        if any(k in sl for k in ("java/", "kotlin", "allatori", "zelix", "stringer", "dasho")):
            buckets["java"].append(s)
        if any(k in sl for k in ("license", "serial", "activation", "hwid", "auth", "subscription", "trial expired")):
            buckets["auth_license"].append(s)
        if ("error" in sl or "failed" in sl or "exception" in sl) and alnum_ratio(s) > 0.5:
            buckets["error_messages"].append(s)
    return {k: v[:80] for k, v in buckets.items()}


def alnum_ratio(s: str) -> float:
    return sum(c.isalnum() or c.isspace() for c in s) / max(1, len(s))


def stage_string_scan(profile: ArtifactProfile, out_dir: Path) -> dict[str, Any]:
    path = Path(profile.path)
    max_bytes = 24 << 20
    with path.open("rb") as f:
        data = f.read(max_bytes)
    strings = extract_strings(data)
    interesting = classify_interesting(strings)
    urls = extract_urls(data, strings)
    if urls:
        merged = list(dict.fromkeys(list(interesting.get("urls") or []) + urls))
        interesting["urls"] = merged[:120]
    report = {
        "string_count": len(strings),
        "sample": strings[:40],
        "interesting": interesting,
        "urls": interesting.get("urls") or [],
        "truncated_read": profile.size > max_bytes,
    }
    (out_dir / "strings.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (out_dir / "strings_all.txt").write_text("\n".join(strings[:8000]), encoding="utf-8", errors="replace")
    return report
