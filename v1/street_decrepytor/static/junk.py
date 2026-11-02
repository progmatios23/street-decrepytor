# language: Python 3, file: junk.py
# Adaptive junk / dead-code / opaque-predicate heuristics via Capstone when available
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from street_decrepytor.core.artifact import ArtifactProfile, Arch


def _disasm_region(code: bytes, base: int, arch: Arch) -> list[dict[str, Any]]:
    try:
        from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32
    except ImportError:
        return []
    mode = CS_MODE_64 if arch in (Arch.X64, Arch.UNKNOWN) else CS_MODE_32
    md = Cs(CS_ARCH_X86, mode)
    md.detail = False
    out = []
    for insn in md.disasm(code, base):
        out.append({"addr": insn.address, "mnem": insn.mnemonic, "op": insn.op_str, "size": insn.size})
        if len(out) >= 4000:
            break
    return out


def score_junk(insns: list[dict[str, Any]]) -> dict[str, Any]:
    """Behavioral junk scoring — no fixed AOB bank required."""
    if not insns:
        return {"available": False, "reason": "no_disasm"}

    junk_hits = 0
    dead_candidates = 0
    opaque = 0
    virt_stub = 0
    reasons: list[str] = []

    mnems = [i["mnem"] for i in insns]
    # opaque: jcc to next + nop sled / xor reg,reg; jz
    for i, ins in enumerate(insns):
        m = ins["mnem"]
        op = ins["op"]
        if m in ("pushfq", "popfq", "pushf", "popf"):
            junk_hits += 1
        if m in ("rdtsc", "rdtscp", "cpuid"):
            virt_stub += 1
        if m in ("in", "out"):
            junk_hits += 2
        if m == "xor" and op.split(",")[0].strip() == op.split(",")[-1].strip():
            # xor reg,reg often legit — only count clusters
            if i + 1 < len(insns) and insns[i + 1]["mnem"] in ("jz", "je", "jnz", "jne"):
                opaque += 1
        if m == "jmp" and op.startswith("0x"):
            # possible dead after unconditional
            dead_candidates += 1
        if m in ("nop", "int3") or m.startswith("nop"):
            junk_hits += 1

    # call $+5 pattern density
    for i, ins in enumerate(insns[:-1]):
        if ins["mnem"] == "call" and insns[i + 1]["addr"] == ins["addr"] + ins["size"]:
            junk_hits += 2
            reasons.append(f"call_next@{hex(ins['addr'])}")

    density = junk_hits / max(1, len(insns))
    return {
        "available": True,
        "insn_count": len(insns),
        "junk_score": junk_hits,
        "junk_density": round(density, 4),
        "opaque_predicate_hits": opaque,
        "timing_cpuid_rdtsc": virt_stub,
        "uncond_jmps": dead_candidates,
        "sample_reasons": reasons[:20],
        "likely_junk_heavy": density > 0.08 or opaque > 15,
        "likely_vm_or_timing": virt_stub > 5,
    }


def stage_junk_scan(profile: ArtifactProfile, out_dir: Path) -> dict[str, Any]:
    path = Path(profile.path)
    data = path.read_bytes() if profile.size < 40 << 20 else path.read_bytes()[:16 << 20]

    # pick entry region when PE
    base = 0
    code = data[:0x2000]
    if data[:2] == b"MZ" and profile.pe_info.get("entry_rva") is None:
        # use static analyzer's entry if present in pe_info — else first 8k after header
        import struct
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        opt = e_lfanew + 0x18
        if e_lfanew + 0x30 < len(data):
            entry = struct.unpack_from("<I", data, opt + 0x10)[0]
            # crude: treat file offset ≈ entry for non-packed; else scan .text-ish mid file
            off = entry if entry < len(data) else 0x1000
            code = data[off : off + 0x3000]
            base = entry
    elif profile.pe_info.get("entry_rva"):
        # cannot map RVA without section table fully — fall back mid-file probe + entry file guess
        code = data[0x1000 : 0x1000 + 0x3000]
        base = 0x1000

    insns = _disasm_region(code, base, profile.arch)
    scored = score_junk(insns)
    report = {"region_base": hex(base), "region_len": len(code), **scored}
    if insns:
        report["disasm_head"] = insns[:30]
    (out_dir / "junk_scan.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
