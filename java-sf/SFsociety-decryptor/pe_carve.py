"""Carve embedded archives / class files from sydney_1_pe.dll."""
from __future__ import annotations

import struct
from collections import Counter
from pathlib import Path

from sfsociety import SYDNEY_XOR_KEY, xor_bytes, detect_magic, entropy as _ent

PE = Path(r"D:\STREET-tool\out\natives\sydney_1_pe.dll")
data = PE.read_bytes()
out = Path(r"D:\STREET-tool\out\pe_carve")
out.mkdir(parents=True, exist_ok=True)

pe = struct.unpack_from("<I", data, 0x3C)[0]
nsec = struct.unpack_from("<H", data, pe + 6)[0]
opt_size = struct.unpack_from("<H", data, pe + 20)[0]
sec0 = pe + 24 + opt_size
last_end = 0
print("sections")
for i in range(nsec):
    o = sec0 + i * 40
    name = data[o : o + 8].split(b"\x00", 1)[0].decode("ascii", "replace")
    vsz, va, rsz, raw = struct.unpack_from("<IIII", data, o + 8)
    end = raw + rsz
    last_end = max(last_end, end)
    chunk = data[raw : raw + rsz]
    print(f"  {name:8} raw={raw:#x} rsz={rsz} ent={_ent(chunk[:65536]) if chunk else 0:.2f} mag={detect_magic(chunk)}")

print("file size", len(data), "last section end", last_end, "overlay", len(data) - last_end)
if last_end < len(data):
    ov = data[last_end:]
    print("overlay mag", detect_magic(ov), "ent", _ent(ov[:65536]))


def scan(buf: bytes, label: str):
    magics = {
        "PK": b"PK\x03\x04",
        "CAFE": b"\xca\xfe\xba\xbe",
        "ELF": b"\x7fELF",
        "MZ": b"MZ",
        "7z": b"7z\xbc\xaf'\x1c",
        "gzip": b"\x1f\x8b",
    }
    for n, m in magics.items():
        hits = []
        start = 0
        while len(hits) < 5:
            i = buf.find(m, start)
            if i < 0:
                break
            hits.append(i)
            start = i + 1
        if hits:
            print(f"  {label} {n} @{hits}")


print("raw scan")
scan(data, "raw")
x = xor_bytes(data, SYDNEY_XOR_KEY, 0)
print("xor-key scan")
scan(x, "xor")

# sliding 16-byte aligned XOR of .rdata only
rdata_off = 0x37E400
rdata = data[rdata_off : rdata_off + 0xCF800]
print("rdata ent", _ent(rdata[:65536]), "xor rdata cafe", xor_bytes(rdata, SYDNEY_XOR_KEY, 0).find(b"\xca\xfe\xba\xbe"))
print("rdata PK", rdata.find(b"PK\x03\x04"), "cafe", rdata.find(b"\xca\xfe\xba\xbe"))

# look for rust panic strings about decrypt
for s in (b"encrypted", b"payload", b"classes", b".jar", b"assets/", b"BOOT-INF"):
    print("find", s, data.find(s))
print("done")
