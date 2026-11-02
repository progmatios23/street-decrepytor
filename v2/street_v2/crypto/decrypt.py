# language: Python 3.11+, file: crypto/decrypt.py
# Honest decrypt attempts on harvested blobs: magic-anchored XOR, repeating XOR,
# ADD/SUB rolling, RC4 (keys from the file), zlib. Writes only on real transform.
from __future__ import annotations

import json
import struct
import zlib
from pathlib import Path
from typing import Any, Iterable

from street_v2.crypto.ciphers import (
    aes128_ecb_decrypt_key,
    chacha20_xor_key,
    tea_decrypt_key,
    xtea_decrypt_key,
    xor_add_index,
    xor_feed,
    xor_repeat,
    xor_rol1,
)
from street_v2.entropy.analyzer import shannon

PROBE = 4096
MAX_BLOB = 12 << 20

PLAIN_MAGICS: list[tuple[bytes, str]] = [
    (b"MZ", "pe"),
    (b"PK\x03\x04", "zip"),
    (b"\x7fELF", "elf"),
    (b"%PDF", "pdf"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"\x1f\x8b\x08", "gzip"),
    (b"7z\xbc\xaf'\x1c", "7z"),
    (b"Rar!\x1a\x07", "rar"),
    (b"\x00asm\x01\x00\x00\x00", "wasm"),
    (b"BZh", "bzip2"),
    (b"<?xml", "xml"),
]

# only these are used to *derive* keys — short/weak headers cause XOR false positives
KEY_MAGICS: list[tuple[bytes, str]] = [
    (b"MZ", "pe"),
    (b"PK\x03\x04", "zip"),
    (b"\x7fELF", "elf"),
    (b"%PDF-", "pdf"),
    (b"\x89PNG\r\n\x1a\n", "png"),
]


# xor_repeat imported from ciphers


def add_repeat(data: bytes, key: bytes, rolling: bool = False) -> bytes:
    kl = max(1, len(key))
    out = bytearray(len(data))
    for i, b in enumerate(data):
        k = key[i % kl]
        if rolling:
            k = (k + i) & 0xFF
        out[i] = (b - k) & 0xFF
    return bytes(out)


def rc4(key: bytes, data: bytes) -> bytes:
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) % 256
        s[i], s[j] = s[j], s[i]
    i = j = 0
    out = bytearray(len(data))
    for n, b in enumerate(data):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        out[n] = b ^ s[(s[i] + s[j]) % 256]
    return bytes(out)


def _pe_ok(blob: bytes) -> bool:
    if blob[:2] != b"MZ" or len(blob) < 0x40:
        return False
    e = struct.unpack_from("<I", blob, 0x3C)[0]
    return 0x40 <= e < min(len(blob) - 4, 0x1000) and blob[e : e + 4] == b"PE\x00\x00"


def _magic_struct_ok(dec: bytes, name: str) -> bool:
    """Header bytes alone are not enough — key-anchored XOR always forges them."""
    if name == "pe":
        return _pe_ok(dec)
    if name == "png":
        return len(dec) >= 16 and dec[12:16] == b"IHDR"
    if name == "zip":
        if len(dec) < 30:
            return False
        ver = struct.unpack_from("<H", dec, 4)[0]
        method = struct.unpack_from("<H", dec, 8)[0]
        return ver <= 90 and method in (0, 8, 9, 12, 14, 98)
    if name == "gzip":
        return False  # too easy to forge via short-key XOR; inflate path handles real gzip
    if name == "pdf":
        # %PDF-1.N is 8 bytes — extra bytes sit outside 4-byte keys
        return (
            len(dec) >= 8
            and dec[4:5] == b"-"
            and dec[5] in b"123"
            and dec[6:7] == b"."
            and dec[7] in b"01234567"
        )
    if name == "elf":
        return len(dec) >= 6 and dec[4] in (1, 2) and dec[5] in (1, 2)
    if name == "jpeg":
        return len(dec) >= 4 and dec[3] in (0xE0, 0xE1, 0xDB, 0xC0)
    if name == "7z":
        return len(dec) >= 32 and dec[6] == 0 and dec[7] <= 4
    if name == "rar":
        return len(dec) >= 12 and dec[6] in (0, 1)
    if name == "xml":
        return b"<?xml" in dec[:40] and b">" in dec[:200]
    if name == "wasm":
        return len(dec) >= 8 and dec[4:8] == b"\x01\x00\x00\x00"
    if name == "bzip2":
        return len(dec) >= 4 and dec[3] in (b"1"[0], b"9"[0])
    return False


def score_plain(orig_h: float, dec: bytes) -> tuple[float, list[str]]:
    why: list[str] = []
    s = 0.0
    if not dec:
        return 0.0, why
    for mag, name in PLAIN_MAGICS:
        if dec.startswith(mag):
            if not _magic_struct_ok(dec, name):
                break
            s += 80.0 + len(mag) + (40.0 if name == "pe" else 0.0)
            why.append(f"magic:{name}")
            break
    h = shannon(dec[: min(len(dec), 1 << 16)])
    drop = orig_h - h
    if drop > 0.4:
        s += min(25.0, drop * 8)
        why.append(f"H_drop:{drop:.2f}")
    printable = sum(1 for b in dec[:PROBE] if 32 <= b < 127 or b in (9, 10, 13))
    ratio = printable / max(1, min(len(dec), PROBE))
    if ratio >= 0.85:
        s += 18.0
        why.append(f"print:{ratio:.2f}")
    elif ratio >= 0.70:
        s += 8.0
    # zlib
    if len(dec) >= 2 and (dec[0] & 0x0F) == 8 and ((dec[0] << 8) + dec[1]) % 31 == 0:
        try:
            z = zlib.decompress(dec[: min(len(dec), 2 << 20)])
            if len(z) >= 32:
                s += 35.0
                why.append(f"zlib:{len(z)}")
        except zlib.error:
            pass
    return s, why


def keys_from_magic(blob: bytes) -> list[tuple[bytes, str]]:
    """If ciphertext starts as XOR of a known header, recover the repeating key."""
    out: list[tuple[bytes, str]] = []
    if len(blob) < 4:
        return out
    for mag, name in KEY_MAGICS:
        if len(blob) < len(mag):
            continue
        raw = bytes(blob[i] ^ mag[i] for i in range(len(mag)))
        # key lengths that divide / fit the recovered prefix
        seen: set[bytes] = set()
        for klen in (1, 2, 4, 8, 16):
            if klen > len(raw):
                key = (raw * ((klen // len(raw)) + 1))[:klen]
            else:
                key = raw[:klen]
            if key == b"\x00" * klen or key in seen:
                continue
            seen.add(key)
            out.append((key, f"magic_{name}_k{klen}"))
        # single-byte consistency: blob[0]^mag[0] should equal blob[1]^mag[1] for k=1
        if len(mag) >= 2:
            k0 = blob[0] ^ mag[0]
            if (blob[1] ^ mag[1]) == k0 and k0 != 0:
                kb = bytes([k0])
                if kb not in seen:
                    out.append((kb, f"magic_{name}_byte"))
    return out


def keys_from_xor_opcodes(text: bytes, limit: int = 60) -> list[bytes]:
    """Harvest xor imm8/imm32 from x86 encoding (feeds extra_keys)."""
    keys: list[bytes] = []
    i = 0
    n = len(text)
    while i < n - 1 and len(keys) < limit:
        b = text[i]
        if b == 0x34:  # xor al, imm8
            keys.append(bytes([text[i + 1]]))
            i += 2
            continue
        if b == 0x35 and i + 5 <= n:  # xor eax, imm32
            imm = text[i + 1 : i + 5]
            if imm != b"\x00" * 4:
                keys.append(imm)
                keys.append(bytes([imm[0]]))
            i += 5
            continue
        if b == 0x80 and i + 2 < n and (text[i + 1] & 0x38) == 0x30:
            keys.append(bytes([text[i + 2]]))
            i += 3
            continue
        i += 1
    return keys


def keys_from_imm(text: bytes, limit: int = 80) -> list[bytes]:
    keys: list[bytes] = []
    i = 0
    n = len(text)
    while i < n - 10 and len(keys) < limit:
        if text[i] == 0x48 and 0xB8 <= text[i + 1] <= 0xBF:
            imm = text[i + 2 : i + 10]
            if imm != b"\x00" * 8 and imm not in keys:
                keys.append(imm)
                keys.append(imm[:4])
                keys.append(imm[:1])
            i += 10
            continue
        i += 1
    return keys


def keys_from_strings(strings: Iterable[str], limit: int = 40) -> list[bytes]:
    keys: list[bytes] = []
    for s in strings:
        if 4 <= len(s) <= 32 and s.isascii() and s.isprintable():
            b = s.encode("ascii", "ignore")
            if b and b not in keys:
                keys.append(b)
        if len(s) in (32, 64) and all(c in "0123456789abcdefABCDEF" for c in s):
            try:
                raw = bytes.fromhex(s)
                if raw not in keys:
                    keys.append(raw)
            except ValueError:
                pass
        if len(keys) >= limit:
            break
    return keys


def _try_one(
    blob: bytes,
    orig_h: float,
    kind: str,
    key: bytes,
    transform,
    threshold: float = 48.0,
) -> dict[str, Any] | None:
    probe = blob[: min(len(blob), PROBE)]
    try:
        dec_p = transform(probe, key)
    except Exception:
        return None
    sc, why = score_plain(orig_h, dec_p)
    if sc < threshold:
        return None
    full = blob if len(blob) <= MAX_BLOB else blob[:MAX_BLOB]
    try:
        dec = dec_p if len(full) == len(probe) else transform(full, key)
    except Exception:
        dec = dec_p
    sc2, why2 = score_plain(orig_h, dec[:PROBE])
    return {
        "kind": "cipher",
        "algo": kind,
        "key_hex": key.hex() if key else "",
        "score": round(max(sc, sc2), 2),
        "why": why2 or why,
        "plain": dec,
        "H_in": round(orig_h, 4),
        "H_out": round(shannon(dec[: min(len(dec), 1 << 16)]), 4),
    }


def decrypt_blob(
    blob: bytes,
    *,
    extra_keys: list[bytes] | None = None,
    label: str = "blob",
) -> dict[str, Any] | None:
    if len(blob) < 32:
        return None
    orig_h = shannon(blob[: min(len(blob), 1 << 16)])
    already, _ = score_plain(orig_h, blob[:PROBE])
    if already >= 50:
        return None  # already plaintext — not a cipher transform
    candidates: list[dict[str, Any]] = []

    def consider(hit: dict[str, Any] | None) -> None:
        if hit is None:
            return
        candidates.append(hit)

    # 1) magic-anchored repeating XOR (finds XOR-hidden PE/ZIP fast)
    for key, tag in keys_from_magic(blob):
        consider(_try_one(blob, orig_h, f"xor/{tag}", key, lambda d, k: xor_repeat(d, k), threshold=50))

    # 2) single-byte XOR brute on probe (only if still high entropy)
    if orig_h >= 6.5:
        best_k = None
        best_sc = 0.0
        probe = blob[:PROBE]
        for k in range(1, 256):
            dec = bytes(b ^ k for b in probe)
            sc, _ = score_plain(orig_h, dec)
            if sc > best_sc:
                best_sc = sc
                best_k = k
        if best_k is not None and best_sc >= 48:
            consider(_try_one(
                blob, orig_h, "xor/byte", bytes([best_k]),
                lambda d, k: xor_repeat(d, k), threshold=48,
            ))

    # 3) extra keys from .text immediates / xor-insns / strings / xrefs
    for i, key in enumerate(extra_keys or []):
        if not key or set(key) == {0}:
            continue
        consider(_try_one(blob, orig_h, "xor/imm", key, lambda d, k: xor_repeat(d, k), threshold=50))
        if i < 16:
            consider(_try_one(blob, orig_h, "xor/add_i", key, lambda d, k: xor_add_index(d, k), threshold=55))
            consider(_try_one(blob, orig_h, "xor/feed", key, lambda d, k: xor_feed(d, k), threshold=55))
            consider(_try_one(blob, orig_h, "xor/rol1", key, lambda d, k: xor_rol1(d, k), threshold=55))
        if i < 16 and 4 <= len(key) <= 32:
            consider(_try_one(blob, orig_h, "rc4/imm", key, lambda d, k: rc4(k, d), threshold=55))
        if i < 6 and orig_h >= 7.0 and len(key) >= 16:
            k16 = key[:16]
            consider(_try_one(blob, orig_h, "aes128/ecb", k16, lambda d, k: aes128_ecb_decrypt_key(d, k), threshold=70))
            consider(_try_one(blob, orig_h, "chacha20", key, lambda d, k: chacha20_xor_key(d, k), threshold=70))
            consider(_try_one(blob, orig_h, "tea", k16, lambda d, k: tea_decrypt_key(d, k), threshold=70))
            consider(_try_one(blob, orig_h, "xtea", k16, lambda d, k: xtea_decrypt_key(d, k), threshold=70))

    # 4) ADD/SUB rolling 1-byte if magic-anchored
    if blob[:2] != b"MZ":
        for k in range(1, 256, 1):
            # only test keys that would produce 'M'
            if ((blob[0] - k) & 0xFF) != 0x4D:
                continue
            consider(_try_one(
                blob, orig_h, "sub/byte", bytes([k]),
                lambda d, key: add_repeat(d, key, rolling=False), threshold=55,
            ))
            consider(_try_one(
                blob, orig_h, "sub/roll", bytes([k]),
                lambda d, key: add_repeat(d, key, rolling=True), threshold=55,
            ))
            break

    # 5) zlib of the blob itself
    if len(blob) >= 2 and (blob[0] & 0x0F) == 8:
        try:
            z = zlib.decompress(blob[: min(len(blob), 8 << 20)])
            if len(z) >= 32:
                sc, why = score_plain(orig_h, z[:PROBE])
                candidates.append({
                    "kind": "cipher",
                    "algo": "zlib",
                    "key_hex": "",
                    "score": round(sc + 20, 2),
                    "why": why + ["zlib_full"],
                    "plain": z,
                    "H_in": round(orig_h, 4),
                    "H_out": round(shannon(z[: min(len(z), 1 << 16)]), 4),
                })
        except zlib.error:
            pass

    if not candidates:
        return None
    candidates.sort(key=lambda h: -h["score"])
    best = candidates[0]
    best["src"] = label
    return best


def decrypt_harvest(
    harvest: dict[str, Any],
    out_dir: str | Path,
    *,
    pe_text: bytes = b"",
    strings: list[str] | None = None,
    extra_keys: list[bytes] | None = None,
) -> dict[str, Any]:
    out = Path(out_dir)
    hits_dir = out / "hits"
    hits_dir.mkdir(parents=True, exist_ok=True)

    extra = keys_from_imm(pe_text) if pe_text else []
    if pe_text:
        extra.extend(keys_from_xor_opcodes(pe_text))
    if strings:
        extra.extend(keys_from_strings(strings))
    if extra_keys:
        extra.extend(extra_keys)
    # unique
    uniq: list[bytes] = []
    for k in extra:
        if k not in uniq:
            uniq.append(k)
    extra = uniq[:120]

    jobs: list[tuple[str, Path]] = []
    for group in ("islands", "carved_pe", "carved_magic", "resources", "zlib"):
        for row in harvest.get(group) or []:
            p = Path(row.get("path") or "")
            if p.is_file() and 32 <= p.stat().st_size <= MAX_BLOB:
                jobs.append((f"{group}:{p.name}", p))
    ov = harvest.get("overlay") or {}
    if ov.get("path"):
        p = Path(ov["path"])
        if p.is_file() and p.stat().st_size >= 32:
            jobs.append(("overlay", p))
    for row in harvest.get("sections") or []:
        # skip low-entropy already-plain .text unless tiny
        if (row.get("H") or 0) < 6.8:
            continue
        p = Path(row.get("path") or "")
        if p.is_file() and 64 <= p.stat().st_size <= MAX_BLOB:
            jobs.append((f"section:{row.get('name')}", p))

    hits: list[dict[str, Any]] = []
    transforms: list[dict[str, Any]] = []
    seen_sha: set[str] = set()
    for label, p in jobs[:80]:
        blob = p.read_bytes()
        hit = decrypt_blob(blob, extra_keys=extra, label=label)
        if not hit:
            continue
        plain: bytes = hit.pop("plain")
        sha = __import__("hashlib").sha256(plain).hexdigest()[:16]
        if sha in seen_sha:
            continue
        seen_sha.add(sha)
        ext = "bin"
        if plain[:2] == b"MZ":
            ext = "exe"
        elif plain[:2] == b"PK":
            ext = "zip"
        elif plain[:4] == b"%PDF":
            ext = "pdf"
        dest = hits_dir / f"{len(hits):03d}_{hit['algo'].replace('/', '_')}_{sha}.{ext}"
        dest.write_bytes(plain)
        rec = {
            **{k: v for k, v in hit.items() if k != "plain"},
            "out": str(dest),
            "out_size": len(plain),
            "src_path": str(p),
        }
        hits.append(rec)
        transforms.append({
            "kind": "cipher",
            "layer": rec["algo"],
            "path": str(dest),
            "key_hex": rec.get("key_hex"),
            "score": rec.get("score"),
            "src": label,
        })

    report = {
        "hit_count": len(hits),
        "hits": hits,
        "image_transforms": transforms,
        "decrypted": any(t["kind"] == "cipher" for t in transforms),
        "keys_tried_imm": len(extra),
        "jobs": len(jobs),
        "note": "cipher only if magic/H-drop/zlib score cleared threshold; Themida VM not inverted",
    }
    (out / "DECRYPT.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    return report
