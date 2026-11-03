"""Port of Diobf ZKMCipher.StaticInit + Sydney 7-xor clinit recovery."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from sfsociety import (
    class_methods,
    extract_7xor_keys,
    mutf8_to_chars,
    utf,
    parse_cp,
    u2,
    u4,
)

UNPACKED = Path(r"D:\STREET-tool\out\unpacked")


def zkm_7xor_chars(s: str, keys: list[int]) -> str:
    chars = [ord(c) for c in s]
    out = [c ^ keys[i % len(keys)] for i, c in enumerate(chars)]
    return "".join(chr(c) for c in out)


def static_init(enc1: str, enc2: str, keys: list[int], offset: int, offset2: int, arraysize: int) -> list[str]:
    """Diobf ZKMCipher.StaticInit with 7-xor instead of cipher1+cipher2."""
    h2 = [""] * arraysize
    n = 0
    s = enc1
    n2 = len(s)
    n3 = offset
    n4 = -1
    phase = 0
    while True:
        n4 += 1
        s3 = s[n4 : n4 + n3]
        a = zkm_7xor_chars(s3, keys)
        h2[n] = a
        n += 1
        n4 += n3
        if n4 < n2:
            n3 = ord(s[n4])
            continue
        if phase == 0:
            s = enc2
            n2 = len(s)
            n3 = offset2
            n4 = -1
            phase = 1
            continue
        break
    return h2[:n]


def ldc_strings_and_offsets(code: bytes, cp) -> tuple[list[str], list[int]]:
    """Walk clinit for LDC string + bipush/sipush after String.length()."""
    strings: list[str] = []
    offsets: list[int] = []
    pc = 0
    last_was_length = False
    from sfsociety import skip_insn

    while pc < len(code):
        op = code[pc]
        if op == 0x12:  # ldc
            idx = code[pc + 1]
            e = cp[idx]
            if e and e[0] == 8:
                raw = cp[e[1]][1] if cp[e[1]] and cp[e[1]][0] == "Utf8" else None
                if raw is not None:
                    strings.append("".join(chr(c) for c in mutf8_to_chars(raw)))
        elif op == 0x13:
            idx = struct.unpack_from(">H", code, pc + 1)[0]
            e = cp[idx]
            if e and e[0] == 8:
                raw = cp[e[1]][1] if cp[e[1]] and cp[e[1]][0] == "Utf8" else None
                if raw is not None:
                    strings.append("".join(chr(c) for c in mutf8_to_chars(raw)))
        if op == 0xB6:  # invokevirtual
            idx = struct.unpack_from(">H", code, pc + 1)[0]
            name = utf(cp, idx)
            if "length" in name:
                last_was_length = True
            else:
                last_was_length = False
        elif last_was_length and op in (0x10, 0x11):
            if op == 0x10:
                offsets.append(struct.unpack("b", bytes([code[pc + 1]]))[0])
            else:
                offsets.append(struct.unpack_from(">h", code, pc + 1)[0])
            last_was_length = False
        pc += skip_insn(code, pc)
    return strings, offsets


def main():
    for p in UNPACKED.rglob("*.class"):
        data = p.read_bytes()
        this, cp, methods = class_methods(data)
        clinit = next((m for m in methods if m[0] == "<clinit>" and m[3]), None)
        if not clinit:
            continue
        keys = extract_7xor_keys(clinit[3])
        if not keys:
            continue
        strings, offsets = ldc_strings_and_offsets(clinit[3], cp)
        print("=" * 60)
        print(this)
        print("keys", keys)
        print("ldc count", len(strings), "lens", [len(s) for s in strings])
        print("offsets", offsets)
        if len(strings) >= 2 and len(offsets) >= 2:
            try:
                arr = static_init(strings[0], strings[1], keys, offsets[0], offsets[1], 64)
                print("decrypted", len(arr), "chunks:")
                for i, s in enumerate(arr):
                    vis = "".join(ch if 32 <= ord(ch) < 127 else "." for ch in s)
                    print(f"  [{i}] {vis!r}")
            except Exception as e:
                print("static_init fail", e)
        elif strings:
            for i, s in enumerate(strings[:4]):
                vis = zkm_7xor_chars(s, keys)
                print(f"  xor ldc[{i}] {vis[:80]!r}")


if __name__ == "__main__":
    main()
