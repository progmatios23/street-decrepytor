"""PE exports + JNI/class-name strings from sydney_1_pe.dll."""
from __future__ import annotations

import struct
from pathlib import Path

PE = Path(r"D:\STREET-tool\out\natives\sydney_1_pe.dll")
data = PE.read_bytes()


def u16(o):
    return struct.unpack_from("<H", data, o)[0]


def u32(o):
    return struct.unpack_from("<I", data, o)[0]


def u64(o):
    return struct.unpack_from("<Q", data, o)[0]


assert data[:2] == b"MZ"
pe = u32(0x3C)
assert data[pe : pe + 4] == b"PE\x00\x00"
coff = pe + 4
nsec = u16(coff + 2)
opt = u16(coff + 16)
magic = u16(coff + 16)  # wait opt header magic at pe+24
opt_off = pe + 24
opt_magic = u16(opt_off)
print("PE", "PE32+" if opt_magic == 0x20B else hex(opt_magic), "sections", nsec)
if opt_magic == 0x20B:
    dd = opt_off + 112
else:
    dd = opt_off + 96
export_rva, export_sz = u32(dd), u32(dd + 4)
print("export dir rva", hex(export_rva), "size", export_sz)

# sections
sec_off = opt_off + u16(pe + 20)
sects = []
for i in range(nsec):
    o = sec_off + i * 40
    name = data[o : o + 8].split(b"\x00", 1)[0].decode("ascii", "replace")
    vsz, va, rsz, raw = struct.unpack_from("<IIII", data, o + 8)
    sects.append((name, va, vsz, raw, rsz))
    print(f"  {name:8} va={va:#x} vsz={vsz:#x} raw={raw:#x} rsz={rsz:#x}")


def rva_to_off(rva):
    for name, va, vsz, raw, rsz in sects:
        if va <= rva < va + max(vsz, rsz):
            return raw + (rva - va)
    return None


if export_rva:
    eo = rva_to_off(export_rva)
    print("export off", eo)
    if eo:
        nnames = u32(eo + 24)
        names_rva = u32(eo + 32)
        ords_rva = u32(eo + 36)
        funcs_rva = u32(eo + 28)
        print("nnames", nnames)
        no = rva_to_off(names_rva)
        for i in range(min(nnames, 40)):
            nr = u32(no + i * 4)
            ns = rva_to_off(nr)
            name = data[ns : data.find(b"\x00", ns)].decode("ascii", "replace")
            print("  exp", name)

print("\nclass-like / jni strings:")
cur = []
seen = []
for b in data:
    if 32 <= b < 127:
        cur.append(chr(b))
    else:
        if len(cur) >= 6:
            s = "".join(cur)
            if (
                "sydney" in s.lower()
                or s.startswith("net/")
                or s.startswith("Java_")
                or "JNI" in s
                or "RegisterNatives" in s
                or "FindClass" in s
                or "getResource" in s
                or "Mixin" in s
                or s.endswith(".class")
            ):
                if s not in seen:
                    seen.append(s)
        cur = []
for s in seen[:80]:
    print(" ", s[:160])
print("count", len(seen))
