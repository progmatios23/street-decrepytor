"""Try AES modes on leftover blob with candidate keys from XOR key / .so."""
from __future__ import annotations

import hashlib
import struct
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util import Counter

LEFTOVER = Path(r"D:\STREET-tool\out\natives\blob_leftover_xor.bin").read_bytes()
RAW = Path(r"D:\STREET-tool\out\natives\blob_raw.bin").read_bytes()
SO = Path(r"D:\STREET-tool\out\natives\libsydney_0_linux_x86_64.so").read_bytes()
KEY32 = b"CqbHnBrA4QMB3AsnEmfbPG42XDMXD0QO"
HDR = Path(r"D:\STREET-tool\out\natives\blob_header.bin").read_bytes()


def mag(d: bytes) -> str | None:
    if d[:4] == b"\x7fELF":
        return "ELF"
    if d[:2] == b"MZ" and len(d) > 0x40:
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        if 0x40 < pe < 0x400 and d[pe : pe + 4] == b"PE\x00\x00":
            return "PE"
    if d[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return "MACHO"
    if d[:4] == b"PK\x03\x04":
        return "ZIP"
    if d[:4] == b"\xca\xfe\xba\xbe":
        return "CLASS"
    if d[:2] == b"\x1f\x8b":
        return "GZIP"
    if d[:8] == b"!<arch>\n":
        return "AR"
    return None


def show(tag: str, pt: bytes):
    m = mag(pt)
    head = "".join(chr(c) if 32 <= c < 127 else "." for c in pt[:32])
    print(f"  {tag:40} mag={m!s:6} {pt[:16].hex()} {head}")


keys = {
    "xor32": KEY32,
    "xor16": KEY32[:16],
    "sha256": hashlib.sha256(KEY32).digest(),
    "md5+md5": hashlib.md5(KEY32).digest() + hashlib.md5(KEY32[::-1]).digest(),
    "hdr+xor": (HDR + KEY32)[:32],
    "so[:32]": SO[:32],
    "so_rodata": SO[0x23000 : 0x23000 + 32],
}

# leftover as-is, and leftover from raw[19+elfsize:] without prior xor
elf_size = 5382488
raw_rest = RAW[19 + elf_size :]

blobs = {"leftover_xor": LEFTOVER, "raw_rest": raw_rest}

print("leftover", len(LEFTOVER), "raw_rest", len(raw_rest))

for bname, blob in blobs.items():
    print("=" * 70, bname)
    for kname, key in keys.items():
        k16, k24, k32 = key[:16], key[:24] if len(key) >= 24 else key, key[:32] if len(key) >= 32 else key
        # AES-GCM nonce 12 + ct + tag 16
        if len(blob) > 28:
            nonce, ct, tag = blob[:12], blob[12:-16], blob[-16:]
            for kn, k in (("k16", k16), ("k32", k32 if len(k32) in (16, 24, 32) else k16)):
                if len(k) not in (16, 24, 32):
                    continue
                try:
                    pt = AES.new(k, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct[:65536], tag)
                    show(f"{kname}/{kn} GCM-head12", pt)
                except Exception:
                    pass
                # nonce at 0, tag after first 64k
            # CTR iv 16
            try:
                ctr = Counter.new(128, initial_value=int.from_bytes(blob[:16], "big"))
                pt = AES.new(k32 if len(k32) == 32 else k16, AES.MODE_CTR, counter=ctr).decrypt(blob[16:16 + 64])
                show(f"{kname} CTR-iv16", pt)
            except Exception as e:
                print(" ctr", kname, e)
            try:
                pt = AES.new(k16, AES.MODE_CBC, iv=blob[:16]).decrypt(blob[16:80])
                show(f"{kname} CBC-iv16", pt)
            except Exception:
                pass
            try:
                pt = AES.new(k16, AES.MODE_ECB).decrypt(blob[:64])
                show(f"{kname} ECB", pt)
            except Exception:
                pass

# also try GCM with nonce=zeros
print("=" * 70, "GCM nonce0 / nonce from header")
for kname, key in keys.items():
    if len(key) not in (16, 24, 32):
        key = key[:16]
    if len(key) not in (16, 24, 32):
        continue
    for nonce in (b"\x00" * 12, HDR[:12], KEY32[:12], RAW[:12], RAW[7:19]):
        if len(nonce) != 12:
            continue
        ct, tag = LEFTOVER[:-16], LEFTOVER[-16:]
        try:
            pt = AES.new(key, AES.MODE_GCM, nonce=nonce).decrypt_and_verify(ct[:4096], tag)
            show(f"{kname} nonce={nonce[:4].hex()}", pt)
        except Exception:
            pass
print("done")
