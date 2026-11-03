from pathlib import Path
import struct

d = Path(r"D:\STREET-tool\out\natives\sydney_1_pe.dll").read_bytes()
pe = struct.unpack_from("<I", d, 0x3C)[0]
opt = pe + 24
nsec = struct.unpack_from("<H", d, pe + 6)[0]
opt_size = struct.unpack_from("<H", d, pe + 20)[0]
sec0 = pe + 24 + opt_size
sects = []
for i in range(nsec):
    o = sec0 + i * 40
    vsz, va, rsz, raw = struct.unpack_from("<IIII", d, o + 8)
    sects.append((va, raw, rsz, vsz))


def rva2(rva):
    for va, raw, rsz, vsz in sects:
        if va <= rva < va + max(vsz, rsz):
            return raw + (rva - va)
    return None


imp_rva = struct.unpack_from("<I", d, opt + 112 + 8)[0]
off = rva2(imp_rva)
want = {
    b"connect",
    b"WSAConnect",
    b"getaddrinfo",
    b"GetAddrInfoW",
    b"WSAStartup",
    b"send",
    b"recv",
    b"socket",
}
while off:
    orig, tim, fwd, name_rva, ft = struct.unpack_from("<IIIII", d, off)
    if orig == 0 and name_rva == 0:
        break
    no = rva2(name_rva)
    dll = d[no : d.find(b"\x00", no)].decode("ascii", "replace") if no else "?"
    thunk = rva2(orig if orig else ft)
    names = []
    t = thunk
    while t:
        hint_rva = struct.unpack_from("<Q", d, t)[0]
        if hint_rva == 0:
            break
        if hint_rva & 0x8000000000000000:
            names.append(f"ord_{hint_rva & 0xffff}")
        else:
            ho = rva2(hint_rva & 0x7FFFFFFF)
            if ho:
                nm = d[ho + 2 : d.find(b"\x00", ho + 2)]
                names.append(nm.decode("ascii", "replace"))
        t += 8
    interesting = [n for n in names if any(w.decode() in n or n.encode() == w for w in want) or "addr" in n.lower() or "connect" in n.lower() or n.startswith("WSA") or n in ("send", "recv", "socket")]
    if interesting or dll.lower().startswith("ws2"):
        print("==", dll)
        for n in names:
            mark = " *" if any(w.decode() in n for w in want) or "connect" in n.lower() or "addr" in n.lower() else ""
            print("  ", n + mark)
    off += 20
