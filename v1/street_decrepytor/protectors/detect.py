# language: Python 3, file: detect.py
# Behavioral protector detection — Themida, VMProtect, .NET, UPX-class, custom
# *Not a static signature DB as sole authority: combines entropy, sections, IAT shape, strings*
from __future__ import annotations

import json
import re
import struct
from pathlib import Path
from typing import Any

from street_decrepytor.core.artifact import ArtifactProfile


def _section_table(data: bytes) -> list[dict[str, Any]]:
    if data[:2] != b"MZ" or len(data) < 0x200:
        return []
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        return []
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    magic = struct.unpack_from("<H", data, e_lfanew + 0x18)[0]
    sec_off = e_lfanew + 0x18 + (0xE0 if magic == 0x10B else 0xF0)
    secs = []
    for i in range(min(nsec, 40)):
        o = sec_off + i * 40
        if o + 40 > len(data):
            break
        name = data[o : o + 8].split(b"\0", 1)[0].decode("latin-1", "replace")
        vsize, va, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
        chars = struct.unpack_from("<I", data, o + 36)[0]
        secs.append({
            "name": name, "vsize": vsize, "va": va, "rsize": rsize, "roff": roff, "chars": chars,
        })
    return secs


def _entry_rva(data: bytes) -> int:
    """AddressOfEntryPoint from the optional header (0 when absent)."""
    if data[:2] != b"MZ" or len(data) < 0x200:
        return 0
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew : e_lfanew + 4] != b"PE\0\0":
        return 0
    magic = struct.unpack_from("<H", data, e_lfanew + 0x18)[0]
    if magic not in (0x10B, 0x20B):
        return 0
    off = e_lfanew + 0x18 + (0x10 if magic == 0x20B else 0x14)
    return struct.unpack_from("<I", data, off)[0]


def _section_of(secs: list[dict[str, Any]], rva: int) -> dict[str, Any] | None:
    for s in secs:
        if s["va"] <= rva < s["va"] + max(s["vsize"], s["rsize"]):
            return s
    return None


def _first_call_target(data: bytes, secs: list[dict[str, Any]], ep_rva: int) -> int | None:
    """Follow the first E8 rel32 at the EP (rva space) — returns the target RVA."""
    if not ep_rva:
        return None
    sec = _section_of(secs, ep_rva)
    if not sec or not sec["rsize"]:
        return None
    off = sec["roff"] + (ep_rva - sec["va"])
    if off + 5 > len(data) or data[off] != 0xE8:
        return None
    rel = struct.unpack_from("<i", data, off + 1)[0]
    return ep_rva + 5 + rel


# dword-transform shapes are decoded inline by _dw_decryptor_density
# (opcode 0x81 /0 add, /5 sub, /6 xor + 0xF7 /2 not with mod=10 disp32)


def _dw_decryptor_density(blob: bytes) -> int:
    """Dense-run score: dword-transform ops per 4 KB inside the .rsrc raw.

    A polymorphic key-block decryptor packs hundreds of
    add/sub/xor/not dword [reg+disp32], imm32 instructions into a few KB.
    Normal resources (icons, manifests, dialogs) sit near zero; we take the
    densest 4 KB window and return its op count.
    """
    if len(blob) < 0x400:
        return 0
    n = len(blob)
    best = 0
    step = 0x400
    limit = min(n, 1 << 20)
    for off in range(0, limit, step):
        end = min(off + step + 10, n)  # +10: ops straddling the window edge
        cnt = 0
        i = off
        while i < end - 9:
            op = blob[i]
            modrm = blob[i + 1]
            if op == 0x81 and (modrm & 0xC0) == 0x80 and (modrm & 0x07) != 0x04:
                # add/sub/xor/or/adc/... dword [reg+disp32], imm32 (10 bytes)
                cnt += 1
                i += 10
                continue
            if op == 0xF7 and (modrm & 0xF8) == 0x10 and (modrm & 0x07) != 0x04:
                # not dword [reg+disp32] (6 bytes)
                cnt += 1
                i += 6
                continue
            i += 1
        if cnt > best:
            best = cnt
    return best


def detect_protectors(data: bytes, profile: ArtifactProfile) -> list[dict[str, Any]]:
    hits: list[dict[str, Any]] = []
    secs = _section_table(data)
    names = [s["name"].lower() for s in secs]
    window = data[: min(len(data), 6 << 20)]

    def add(name: str, conf: float, why: str, **extra: Any) -> None:
        hits.append({"name": name, "confidence": conf, "reason": why, **extra})

    # Named sections (weak alone, strong with more)
    for n in names:
        if "themida" in n or "winlice" in n:
            add("Themida/WinLicense", 0.85, f"section {n}")
        if n.startswith(".vmp") or n == "vmp0":
            add("VMProtect", 0.85, f"section {n}")
        if n in (".upx0", ".upx1", "upx0", "upx1"):
            add("UPX", 0.9, f"section {n}")
        if n in (".enigma1", ".enigma2"):
            add("Enigma", 0.8, f"section {n}")

    # String / blob behavioral
    patterns = [
        (rb"Themida", "Themida/WinLicense", 0.7),
        (rb"Oreans", "Themida/Oreans", 0.75),
        (rb"VMProtect", "VMProtect", 0.7),
        (rb"VirtualProtect", "generic_runtime_unpack", 0.25),
        (rb"UPX!", "UPX", 0.9),
        (rb"ConfuserEx", "ConfuserEx", 0.9),
        (rb"ConfusedByAttribute", "ConfuserEx", 0.85),
        (rb"SmartAssembly", "SmartAssembly", 0.85),
        (rb"\x00Agile\.NET|\x00AgileDotNet", "Agile.NET", 0.7),
        (rb"DNGuard", "DNGuard", 0.85),
        (rb"Obfuscar", "Obfuscar", 0.85),
        (rb"BabelObfuscator|\x00Babel\.", "Babel", 0.7),
        (rb"Eazfuscator", "Eazfuscator", 0.8),
        (rb".NET Reactor|Unknown .NET Reactor", ".NET Reactor", 0.75),
        (rb"Allatori", "Allatori(Java)", 0.8),
        (rb"Zelix KlassMaster", "Zelix(Java)", 0.8),
        (rb"PyInstaller", "PyInstaller", 0.85),
        (rb"py2exe", "py2exe", 0.8),
    ]
    for pat, name, conf in patterns:
        if re.search(pat, window, re.I):
            add(name, conf, "content_pattern")

    # Behavioral PE shape
    virtual_only = [s for s in secs if s["rsize"] == 0 and s["vsize"] > 0x1000]
    if len(virtual_only) >= 2:
        add(
            "custom_or_commercial_packer",
            0.55,
            f"{len(virtual_only)} virtual-only sections (runtime decrypt layout)",
            sections=[s["name"] for s in virtual_only],
        )

    # rsrc-stub decryptor (Cs2-External class, 2026-09-05):
    # EP lives in a raw-backed section but its first CALL target resolves into
    # .rsrc while >= 4 virtual-only sections exist → decryptor stub hidden in
    # resources. Discovered on target-v2 (a94f6513...): EP in .Z@q → call .rsrc.
    if len(virtual_only) >= 4 and profile.format == "pe":
        ep_rva = _entry_rva(data)
        ep_sec = _section_of(secs, ep_rva)
        if ep_sec and ep_sec["rsize"] > 0:
            tgt = _first_call_target(data, secs, ep_rva)
            if tgt is not None:
                tgt_sec = _section_of(secs, tgt)
                if tgt_sec and tgt_sec["name"].lower().startswith(".rsrc"):
                    add(
                        "rsrc_stub_decryptor",
                        0.8,
                        f"EP call target {tgt:#x} resolves into .rsrc "
                        f"(decryptor hidden in resources, {len(virtual_only)} virtual-only sections)",
                        ep_rva=ep_rva,
                        stub_rva=tgt,
                    )

    # dw-arithmetric decryptor body (Cs2-External class):
    # a dense linear run of add/sub/xor/not dword [reg+disp], imm ops inside
    # the .rsrc raw area marks the polymorphic key-block transformer.
    rsrc_raw = b""
    for s in secs:
        if s["name"].lower().startswith(".rsrc") and s["rsize"]:
            rsrc_raw = data[s["roff"] : s["roff"] + s["rsize"]]
            break
    if rsrc_raw:
        dw = _dw_decryptor_density(rsrc_raw)
        if dw >= 40:  # ops per 4 KB — stub density, normal resources ~0
            add(
                "dw_arithmetric_decryptor",
                0.75,
                f"{dw} dword-transform ops per 4 KB in .rsrc raw — "
                "polymorphic key-block decryptor (add/sub/xor/not [reg+disp], imm)",
            )

    # Tiny IAT / few imports → packer shell
    dll_hits = len(re.findall(rb"[A-Za-z0-9_\-.]{3,40}\.dll", window[: 2 << 20], flags=re.I))
    if dll_hits <= 4 and profile.format == "pe" and profile.size > 200_000:
        add("iat_starved_packer_shell", 0.5, f"very few dll name hits ({dll_hits}) in head")

    # .NET protector stack when CLR present
    if profile.family.value in ("dotnet", "cpp_cli", "mixed"):
        if not any(h["name"] in ("ConfuserEx", "SmartAssembly", "DNGuard", "Agile.NET", "Obfuscar") for h in hits):
            # method rename / no useful strings often → generic
            printable = sum(1 for b in window[0x2000:0xA000] if 32 <= b < 127) if len(window) > 0xA000 else 0
            if printable and printable / 0x8000 < 0.1:
                add("dotnet_obfuscated_generic", 0.45, "CLR image with sparse printable mid-file")

    # Dedup by name keeping max confidence
    best: dict[str, dict[str, Any]] = {}
    for h in hits:
        cur = best.get(h["name"])
        if not cur or h["confidence"] > cur["confidence"]:
            best[h["name"]] = h
    return sorted(best.values(), key=lambda x: -x["confidence"])


def stage_protector_detect(profile: ArtifactProfile, out_dir: Path) -> dict[str, Any]:
    path = Path(profile.path)
    data = path.read_bytes() if profile.size < 60 << 20 else path.open("rb").read(20 << 20)
    hits = detect_protectors(data, profile)
    # merge classify-time candidates
    for c in profile.protector_candidates:
        if not any(h["name"] == c.get("name") for h in hits):
            hits.append(c)
    report = {"hits": hits, "sections": _section_table(data)[:20]}
    (out_dir / "protectors.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    profile.protector_candidates = hits
    return report
