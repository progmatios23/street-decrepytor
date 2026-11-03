"""Scan leftover for magics at every key alignment / header skip."""
from pathlib import Path
import struct

KEY = b"CqbHnBrA4QMB3AsnEmfbPG42XDMXD0QO"
raw = Path(r"D:\STREET-tool\out\natives\blob_raw.bin").read_bytes()
left = Path(r"D:\STREET-tool\out\natives\blob_leftover_xor.bin").read_bytes()
elf_off, elf_size = 19, 5382488


def xor(data, key, koff=0):
    klen = len(key)
    rot = key[koff % klen :] + key[: koff % klen]
    rep = (rot * (len(data) // klen + 1))[: len(data)]
    return bytes(a ^ b for a, b in zip(data, rep))


def mag(d):
    if d[:4] == b"\x7fELF":
        return "ELF"
    if d[:4] == b"PK\x03\x04":
        return "ZIP"
    if d[:4] == b"\xca\xfe\xba\xbe":
        return "CLASS"
    if d[:2] == b"MZ" and len(d) > 0x40:
        pe = struct.unpack_from("<I", d, 0x3C)[0]
        if 0x40 < pe < 0x800 and pe + 4 <= len(d) and d[pe : pe + 4] == b"PE\x00\x00":
            return "PE"
    if d[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return "MACHO"
    return None


rest = raw[elf_off + elf_size :]
print("rest", len(rest), "left", len(left))
print("scan skip 0..128, key_off 0..31 on raw rest")
hits = []
for skip in range(0, 129):
    for koff in range(32):
        chunk = xor(rest[skip : skip + 64], KEY, koff)
        m = mag(chunk)
        if m:
            hits.append((skip, koff, m, chunk[:8].hex()))
print("hits", hits[:40], "count", len(hits))

print("scan leftover skip 0..256 magics (already xor idx0)")
hits2 = []
for skip in range(0, 257):
    m = mag(left[skip : skip + 64])
    if m:
        hits2.append((skip, m, left[skip : skip + 8].hex()))
print("left hits", hits2[:20], "count", len(hits2))

# zlib
import zlib
for skip in range(0, 32):
    for wbits in (15, -15, 31, 47):
        try:
            pt = zlib.decompress(left[skip : skip + 256], wbits)
            print("zlib", skip, wbits, pt[:20])
        except Exception:
            pass
print("done")
