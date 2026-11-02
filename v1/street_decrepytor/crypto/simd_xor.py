# language: Python 3, file: simd_xor.py
# Portable SIMD-XOR string decrypt helpers (Potassium-class, re-derive keys per function)
from __future__ import annotations

import struct
from typing import Iterable


def xor_bytes(data: bytes, key: bytes) -> bytes:
    if not key:
        return data
    kl = len(key)
    return bytes(data[i] ^ key[i % kl] for i in range(len(data)))


def simd_lane_xor(block: bytes, key16: bytes) -> bytes:
    """16-byte lane XOR — mirrors SSE pxor lane decrypt used in Potassium.dll."""
    if len(key16) < 16:
        key16 = (key16 * 16)[:16]
    out = bytearray()
    for i in range(0, len(block), 16):
        chunk = block[i : i + 16]
        k = key16[: len(chunk)]
        out.extend(c ^ k[j] for j, c in enumerate(chunk))
    return bytes(out)


def try_keys_on_blob(blob: bytes, keys: Iterable[bytes]) -> list[dict]:
    results = []
    for key in keys:
        dec = simd_lane_xor(blob, key) if len(key) == 16 else xor_bytes(blob, key)
        printable = sum(1 for b in dec if 32 <= b < 127)
        ratio = printable / max(1, len(dec))
        if ratio >= 0.7:
            results.append({
                "key_hex": key.hex(),
                "score": round(ratio, 4),
                "preview": dec[:80].decode("latin-1", "replace"),
            })
    return results


def extract_imm64_keys_from_text(text: bytes, limit: int = 200) -> list[bytes]:
    """Pull mov-imm64 immediates as candidate key material (re-derived each sample)."""
    keys = []
    i = 0
    while i < len(text) - 10 and len(keys) < limit:
        # REX.W mov r64, imm64 = 48 B8+r
        if text[i] == 0x48 and 0xB8 <= text[i + 1] <= 0xBF:
            imm = text[i + 2 : i + 10]
            if imm != b"\x00" * 8 and imm not in keys:
                keys.append(imm)
            i += 10
            continue
        i += 1
    return keys
