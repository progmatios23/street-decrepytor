# language: Python 3, file: runtime/themida_phylo.py
# R4 — Phylogenetic Themida detector (structural + EP heuristic + optional live RWX)
from __future__ import annotations

import struct
from pathlib import Path
from typing import Any

from street_decrepytor.runtime.common import Finding, clamp01


def _ep_window(data: bytes, max_bytes: int = 0x800) -> tuple[int, bytes, str]:
    """Return (va_base_with_image, window, section_name)."""
    e = struct.unpack_from("<I", data, 0x3C)[0]
    magic = struct.unpack_from("<H", data, e + 0x18)[0]
    entry = struct.unpack_from("<I", data, e + 0x28)[0]
    if magic == 0x10B:
        image_base = struct.unpack_from("<I", data, e + 0x18 + 28)[0]
        sec = e + 0x18 + 0xE0
    else:
        image_base = struct.unpack_from("<Q", data, e + 0x18 + 24)[0]
        sec = e + 0x18 + 0xF0
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    for i in range(nsec):
        o = sec + i * 40
        name = data[o : o + 8].split(b"\0", 1)[0].decode("latin-1", "replace")
        vsize, va, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
        if va <= entry < va + max(vsize, 1):
            if rsize > 0:
                off = roff + (entry - va)
                blob = data[off : off + min(max_bytes, rsize - (entry - va))]
            else:
                # virtual-only — return empty; live dump required
                blob = b""
            return image_base + entry, blob, name
    return image_base + entry, b"", "?"


def _scan_integrity_loop(code: bytes) -> dict[str, Any]:
    """Heuristic: look for XOR/ROR loops near cmp/jcc in first ~500 insns."""
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64
    except ImportError:
        return {"available": False}
    if not code:
        return {"available": True, "insns": 0, "signals": [], "note": "empty EP window (packed virtual section)"}
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    xor_like = 0
    ror_like = 0
    cmp_jcc = 0
    signals = []
    count = 0
    for insn in md.disasm(code, 0):
        count += 1
        if count > 500:
            break
        m = insn.mnemonic
        if m in ("xor", "xorps", "pxor", "xorpd"):
            xor_like += 1
        if m in ("ror", "rol", "rcr", "rcl"):
            ror_like += 1
        if m == "cmp":
            # peek — Capstone linear; count cmp density
            cmp_jcc += 1
        if m.startswith("j") and m != "jmp" and xor_like + ror_like >= 2:
            cmp_jcc += 1
    if xor_like >= 4 and ror_like >= 1:
        signals.append("xor_ror_dense")
    if xor_like >= 6 and cmp_jcc >= 3:
        signals.append("possible_integrity_loop_shape")
    if count < 20 and len(code) > 0x100:
        signals.append("sparse_decode_or_ciphertext")
    return {
        "available": True,
        "insns": count,
        "xor_like": xor_like,
        "ror_like": ror_like,
        "cmp_jcc_ish": cmp_jcc,
        "signals": signals,
    }


def themida_phylo(
    target: str | Path,
    *,
    pid: int | None = None,
    structural: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Combine S0 structural Themida-class with EP integrity-loop heuristic.
    Optional pid: fingerprint RWX regions (S1/S2 light).
    """
    from street_decrepytor.protectors.unpack_engine import identify_themida_class
    import pefile

    path = Path(target)
    data = path.read_bytes()
    pe = pefile.PE(data=data, fast_load=False)
    pe.parse_data_directories()
    structural = structural or identify_themida_class(data, pe)

    ep_va, window, sec = _ep_window(data)
    loop = _scan_integrity_loop(window)

    findings: list[Finding] = []
    score = float(structural.get("score") or 0.0)

    if structural.get("themida_class"):
        findings.append(
            Finding(
                pillar="R4",
                flag="structural_themida_class",
                score=clamp01(score),
                confidence=0.75,
                detail="; ".join(structural.get("reasons") or []),
                limits=["Structural only — confirm with dump --spawn"],
            )
        )

    # CFG-heavy modules (umi module.dll) often show xor/cmp density without Themida
    cfg_heavy = False
    try:
        from street_decrepytor.deobf.cfg_obfuscation import analyze_cfg

        cfg = analyze_cfg(path)
        cfg_heavy = bool(cfg.get("cfg_obfuscation_likely"))
    except Exception:
        cfg = None

    sigs = loop.get("signals") or []
    if "possible_integrity_loop_shape" in sigs and not cfg_heavy and not structural.get("themida_class"):
        findings.append(
            Finding(
                pillar="R4",
                flag="ep_integrity_loop_heuristic",
                score=0.35,
                confidence=0.35,
                detail=f"EP section `{sec}` shows xor/ror+cmp/jcc density (no Themida structure)",
                limits=[
                    "Themida obfuscates these loops (opaque predicates / CFF)",
                    "Go/Rust init can resemble — cross-check languages",
                ],
            )
        )
        score = max(score, 0.35)
    elif "possible_integrity_loop_shape" in sigs and structural.get("themida_class"):
        findings.append(
            Finding(
                pillar="R4",
                flag="ep_integrity_loop_heuristic",
                score=0.45,
                confidence=0.45,
                detail=f"EP section `{sec}` integrity-loop shape + Themida structure",
                limits=["Still prefer dump --spawn for confirmation"],
            )
        )
        score = max(score, 0.45)
    elif cfg_heavy and not structural.get("themida_class"):
        findings.append(
            Finding(
                pillar="R4",
                flag="cfg_not_themida",
                score=0.0,
                confidence=0.7,
                detail=f"CFG trampolines present ({(cfg or {}).get('trampoline_count')}) — not classified as Themida",
                limits=["Use `cfg` command for trampoline deobf inventory"],
            )
        )
    if "sparse_decode_or_ciphertext" in sigs or (structural.get("themida_class") and not window):
        findings.append(
            Finding(
                pillar="R4",
                flag="ep_in_packed_or_empty_raw",
                score=0.55,
                confidence=0.7,
                detail=f"EP `{hex(ep_va)}` in `{sec}` with empty/cipher EP window — runtime decrypt expected",
                limits=["Fingerprint DB of handlers needs live RWX capture"],
            )
        )
        score = max(score, 0.55)

    # Go/Rust FP guard: if rust/go markers and NOT virtual sections, downweight loop signal
    rust = b"rustc" in data or b"Runtime.main" in data or b".rdata" in data[:0x400] and b"tokio" in data
    go = b"Go build ID:" in data or b"runtime.main" in data
    if (rust or go) and not structural.get("themida_class") and "possible_integrity_loop_shape" in sigs:
        findings.append(
            Finding(
                pillar="R4",
                flag="golang_rust_init_fp_guard",
                score=0.0,
                confidence=0.6,
                detail="Language markers present without Themida structure — downweight integrity-loop",
                limits=["Heuristic language detect"],
            )
        )
        score = min(score, 0.2)

    rwx = None
    if pid is not None:
        try:
            from street_decrepytor.dynamic.pe_dump import dump_vad_regions
            import tempfile
            from pathlib import Path as P

            tmp = P("output/runtime/rwx_scan")
            vad = dump_vad_regions(pid, tmp / f"pid_{pid}", max_regions=80)
            exec_pe = [r for r in (vad.get("list") or []) if r.get("exec")]
            rwx = {"exec_regions": len(exec_pe), "sample": exec_pe[:10]}
            if structural.get("themida_class") and len(exec_pe) >= 2:
                findings.append(
                    Finding(
                        pillar="R4",
                        flag="rwx_regions_post_load",
                        score=0.35,
                        confidence=0.5,
                        detail=f"{len(exec_pe)} executable VAD regions during live probe",
                        limits=["Many legit JIT/loaders allocate RX"],
                    )
                )
                score = max(score, min(0.85, score + 0.1))
        except Exception as e:
            rwx = {"error": str(e)}

    if not findings:
        findings.append(
            Finding(
                pillar="R4",
                flag="no_themida_phylo_signal",
                score=0.0,
                confidence=0.55,
                detail="No structural Themida-class and weak EP integrity-loop signals",
                limits=["Obfuscated Themida loops may evade this heuristic"],
            )
        )

    return {
        "pillar": "R4",
        "ok": True,
        "target": str(path),
        "ep": hex(ep_va),
        "ep_section": sec,
        "structural": {
            "themida_class": structural.get("themida_class"),
            "score": structural.get("score"),
            "reasons": structural.get("reasons"),
        },
        "ep_scan": loop,
        "rwx": rwx,
        "findings": [f.to_dict() for f in findings],
        "score": clamp01(score),
        "confidence": min((f.confidence for f in findings), default=0.5),
        "limits": [
            "Primary Themida confirmation remains dump --spawn + restored .text",
            "Handler fingerprint DB not yet trained — structural+EP heuristic only",
            "False positives possible on exotic compiler startups",
        ],
    }
