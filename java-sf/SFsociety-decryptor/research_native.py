"""Dump ELF dynsym + interesting strings from the recovered linux .so."""
from __future__ import annotations

import struct
from pathlib import Path

SO = Path(r"D:\STREET-tool\out\natives\libsydney_0_linux_x86_64.so")
data = SO.read_bytes()


def parse_elf(d: bytes):
    assert d[:4] == b"\x7fELF"
    e_shoff = struct.unpack_from("<Q", d, 40)[0]
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", d, 58)
    sh = []
    for i in range(e_shnum):
        off = e_shoff + i * e_shentsize
        name, typ, flags, addr, soff, size, link, info, addralign, entsize = struct.unpack_from(
            "<IIQQQQIIQQ", d, off
        )
        sh.append(
            dict(
                i=i,
                name=name,
                typ=typ,
                flags=flags,
                addr=addr,
                off=soff,
                size=size,
                link=link,
                info=info,
                entsize=entsize,
            )
        )
    strtab = sh[e_shstrndx]
    names = d[strtab["off"] : strtab["off"] + strtab["size"]]

    def shname(n):
        return names[n : names.find(b"\x00", n)].decode("ascii", "replace")

    for s in sh:
        s["nm"] = shname(s["name"])
    return sh


sh = parse_elf(data)
print("sections:")
for s in sh:
    print(f"  {s['nm']:20} type={s['typ']} off={s['off']:#x} size={s['size']} addr={s['addr']:#x}")

dynsym = next((s for s in sh if s["nm"] == ".dynsym"), None)
dynstr = next((s for s in sh if s["nm"] == ".dynstr"), None)
if dynsym and dynstr:
    strs = data[dynstr["off"] : dynstr["off"] + dynstr["size"]]
    entsize = dynsym["entsize"] or 24
    print("\nDYNSYM exports / jni:")
    for i in range(dynsym["size"] // entsize):
        off = dynsym["off"] + i * entsize
        st_name, st_info, st_other, st_shndx, st_value, st_size = struct.unpack_from(
            "<IBBHQQ", data, off
        )
        nm = strs[st_name : strs.find(b"\x00", st_name)].decode("ascii", "replace")
        bind = st_info >> 4
        if not nm:
            continue
        if bind == 1 or "JNI" in nm or "Java" in nm or "sydney" in nm.lower() or "load" in nm.lower():
            print(f"  {nm:60} val={st_value:#x} size={st_size} bind={bind}")

print("\ninteresting strings:")
keys = (
    "JNI",
    "Java_",
    "sydney",
    "decrypt",
    "encrypt",
    "AES",
    "GCM",
    "resource",
    "class",
    "jar",
    "loadLibrary",
    "username",
    "userid",
    "hwid",
    "license",
    "key",
    "blob",
    "native",
    "windows",
    "macos",
    ".dll",
    ".dylib",
    ".so",
    "getResource",
    "defineClass",
)
seen = set()
cur = []
for b in data:
    if 32 <= b < 127:
        cur.append(chr(b))
    else:
        if len(cur) >= 6:
            s = "".join(cur)
            low = s.lower()
            if any(k.lower() in low for k in keys) and s not in seen:
                if not s.startswith(("aes-", "AES-", "id-aes", "/aws-lc")):
                    seen.add(s)
                    print(" ", s[:160])
        cur = []
