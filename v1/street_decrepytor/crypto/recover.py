# language: Python 3, file: recover.py
# Crypto / string-encryption recovery heuristics — algorithm discovery, not fixed keys
from __future__ import annotations

import json
import re
import struct
from pathlib import Path
from typing import Any

from street_decrepytor.core.artifact import ArtifactProfile


def find_xor_imm_loops(data: bytes) -> list[dict[str, Any]]:
    """Scan for short XOR key immediates near rep-like patterns (x64)."""
    hits = []
    # mov reg, imm32/imm64 followed closely by xor [mem], reg — heuristic windows
    for m in re.finditer(rb"\x48\xb8(.{8})", data):  # mov rax, imm64
        imm = m.group(1)
        if imm == b"\x00" * 8:
            continue
        window = data[m.start() : m.start() + 64]
        if b"\x30" in window or b"\x31" in window or b"\x80" in window:  # xor variants present
            hits.append({
                "off": m.start(),
                "imm64_hex": imm.hex(),
                "kind": "mov_rax_imm64_xor_window",
            })
        if len(hits) >= 40:
            break
    return hits


def find_simd_xor_shapes(data: bytes) -> list[dict[str, Any]]:
    """
    Potassium-class SIMD string decrypt: pxor xmm, xmm / movdqu loads.
    We flag *shapes*, keys are recovered by emulator stage (see simd_xor).
    """
    hits = []
    # 66 0F EF = pxor xmm,xmm form prefix family
    for m in re.finditer(rb"\x66\x0f\xef", data):
        hits.append({"off": m.start(), "op": "pxor_prefix"})
        if len(hits) >= 60:
            break
    # AES-NI
    for m in re.finditer(rb"\x66\x0f\x38\xdc|\x66\x0f\x38\xdd|\x66\x0f\x3a\xdf", data):
        hits.append({"off": m.start(), "op": "aes_ni"})
        if len(hits) >= 80:
            break
    return hits


def rolling_xor_bruteforce_ascii(blob: bytes, max_key_len: int = 4, sample: int = 0x4000) -> list[dict[str, Any]]:
    """
    Only for *small* high-entropy islands that decode to ASCII — not a substitute for real crypto.
    Prior RE failures often stopped at single-byte XOR; we still try 1..N as a prefilter.
    """
    region = blob[:sample]
    results = []
    for key_len in range(1, max_key_len + 1):
        # try keys from repeating first non-zero density — limited search
        # sample candidate keys: 0x00..0xFF for len1; for longer only common English
        if key_len == 1:
            candidates = [bytes([k]) for k in range(256)]
        else:
            candidates = []
            # derive candidate bytes from histogram peaks XOR 'e'/'a'/' '
            hist = [0] * 256
            for b in region:
                hist[b] += 1
            peaks = sorted(range(256), key=lambda i: -hist[i])[:6]
            for p in peaks:
                for plain in (0x20, 0x41, 0x65, 0x00):
                    candidates.append(bytes([p ^ plain]) * key_len)
            candidates = candidates[:40]

        best = None
        for key in candidates:
            dec = bytes(region[i] ^ key[i % key_len] for i in range(len(region)))
            printable = sum(1 for b in dec if 32 <= b < 127 or b in (9, 10, 13))
            score = printable / max(1, len(dec))
            if best is None or score > best["score"]:
                best = {"key_len": key_len, "key_hex": key.hex(), "score": round(score, 4),
                        "preview": dec[:60].decode("latin-1", "replace")}
        if best and best["score"] >= 0.75:
            results.append(best)
    return results


def stage_crypto_heuristics(profile: ArtifactProfile, out_dir: Path) -> dict[str, Any]:
    path = Path(profile.path)
    data = path.read_bytes() if profile.size < 40 << 20 else path.open("rb").read(16 << 20)
    report = {
        "xor_imm_loops": find_xor_imm_loops(data),
        "simd_xor_shapes": find_simd_xor_shapes(data),
        "rolling_xor_prefilter": rolling_xor_bruteforce_ascii(data[-min(len(data), 0x8000):]),
        "notes": [
            "Keys are not assumed; shapes feed emulator / dynamic intercept stages",
            "Potassium.dll uses per-slot SIMD-XOR — see street_decrepytor.crypto.simd_xor",
        ],
    }
    (out_dir / "crypto_heuristics.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    return report
