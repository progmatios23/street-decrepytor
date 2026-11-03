"""Walk the native blob as Natives.load() does after CFR deobf:

  int count
  for i in count:
      int extLen;  bytes ext
      int archLen; bytes arch
      int dataLen; bytes encrypted
      data = xor(encrypted, KEY)
"""
from pathlib import Path
import struct

KEY = b"CqbHnBrA4QMB3AsnEmfbPG42XDMXD0QO"
blob = Path(r"D:\STREET-tool\out\natives\blob_raw.bin").read_bytes()
out = Path(r"D:\STREET-tool\out\natives")


def xor(data):
    k = KEY * (len(data) // len(KEY) + 1)
    return bytes(a ^ b for a, b in zip(data, k[: len(data)]))


def try_walk(u32=">I", u16=None):
    print("====", u32, u16)
    off = 0

    def gi():
        nonlocal off
        v = struct.unpack_from(u32, blob, off)[0]
        off += 4
        return v

    def gs(n):
        nonlocal off
        s = blob[off : off + n]
        off += n
        return s

    try:
        count = gi()
    except Exception as e:
        print("fail", e)
        return
    print("count", count, "off", off)
    if not (1 <= count <= 16):
        print("bad count")
        return
    for i in range(count):
        if off + 12 > len(blob):
            print("eof at rec", i, "off", off)
            return
        ext_len = gi()
        print(f"  [{i}] ext_len={ext_len} off={off}")
        if ext_len < 0 or ext_len > 1024:
            print("  abort ext")
            return
        ext = gs(ext_len)
        arch_len = gi()
        print(f"      arch_len={arch_len}")
        if arch_len < 0 or arch_len > 1024:
            print("  abort arch")
            return
        arch = gs(arch_len)
        data_len = gi()
        print(f"      data_len={data_len} ext={ext!r} arch={arch!r}")
        if data_len < 0 or off + data_len > len(blob):
            print("  abort data", off, data_len, len(blob))
            return
        enc = gs(data_len)
        plain = xor(enc)
        mag = plain[:4]
        print(f"      mag={mag!r} {plain[:8].hex()}")
        name = f"lib_{i}_{arch.decode('ascii','replace')}.{ext.decode('ascii','replace')}"
        name = "".join(c if c.isalnum() or c in "._-" else "_" for c in name)
        (out / name).write_bytes(plain)
        print("      wrote", name, len(plain))
    print("leftover", len(blob) - off)


try_walk(">I")
# maybe u16 lengths
print("---- u16 names + u32 data ----")
off = 4
count = struct.unpack_from(">I", blob, 0)[0]
print("count", count)
names = {0: "linux_x86_64.so", 1: "windows_x86_64.dll", 2: "macos_arm64.dylib"}
for i in range(count):
    el = struct.unpack_from(">H", blob, off)[0]
    off += 2
    ext = blob[off : off + el]
    off += el
    al = struct.unpack_from(">H", blob, off)[0]
    off += 2
    arch = blob[off : off + al]
    off += al
    dl = struct.unpack_from(">I", blob, off)[0]
    off += 4
    enc = blob[off : off + dl]
    off += dl
    plain = xor(enc)
    mag = plain[:8]
    fn = names.get(i, f"lib_{i}.bin")
    path = out / f"sydney_{fn}"
    path.write_bytes(plain)
    print(i, "ext", ext, "arch", arch, "dl", dl, "mag", mag, "->", path.name, "sha", __import__("hashlib").sha256(plain).hexdigest()[:16])
print("leftover", len(blob) - off)
print("done")
