"""Disassemble JNI_OnLoad and find MessageBoxW call sites."""
from __future__ import annotations

import struct
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_OP_IMM, CS_OP_MEM

PE = Path(r"D:\STREET-tool\out\natives\sydney_1_pe.dll")
data = PE.read_bytes()

pe = struct.unpack_from("<I", data, 0x3C)[0]
nsec = struct.unpack_from("<H", data, pe + 6)[0]
opt_size = struct.unpack_from("<H", data, pe + 20)[0]
opt = pe + 24
image_base = struct.unpack_from("<Q", data, opt + 24)[0]
sec0 = pe + 24 + opt_size
sects = []
for i in range(nsec):
    o = sec0 + i * 40
    name = data[o : o + 8].split(b"\x00", 1)[0].decode("ascii", "replace")
    vsz, va, rsz, raw = struct.unpack_from("<IIII", data, o + 8)
    sects.append((name, va, vsz, raw, rsz))


def rva2(rva):
    for name, va, vsz, raw, rsz in sects:
        if va <= rva < va + max(vsz, rsz):
            return raw + (rva - va)
    return None


def off2rva(off):
    for name, va, vsz, raw, rsz in sects:
        if raw <= off < raw + rsz:
            return va + (off - raw)
    return None


# exports
dd = opt + 112
exp_rva = struct.unpack_from("<I", data, dd)[0]
eo = rva2(exp_rva)
nfunc = struct.unpack_from("<I", data, eo + 20)[0]
nnames = struct.unpack_from("<I", data, eo + 24)[0]
funcs = rva2(struct.unpack_from("<I", data, eo + 28)[0])
names = rva2(struct.unpack_from("<I", data, eo + 32)[0])
ords = rva2(struct.unpack_from("<I", data, eo + 36)[0])
jni_rva = None
for i in range(nnames):
    nr = struct.unpack_from("<I", data, names + i * 4)[0]
    ns = rva2(nr)
    nm = data[ns : data.find(b"\x00", ns)].decode()
    ord_i = struct.unpack_from("<H", data, ords + i * 2)[0]
    fr = struct.unpack_from("<I", data, funcs + ord_i * 4)[0]
    print("export", nm, hex(fr))
    if nm == "JNI_OnLoad":
        jni_rva = fr

print("image_base", hex(image_base), "JNI_OnLoad rva", hex(jni_rva or 0))

# IAT MessageBoxW
imp_rva = struct.unpack_from("<I", data, dd + 8)[0]
mbox_iat_rva = None
off = rva2(imp_rva)
while off:
    orig, tim, fwd, name_rva, ft = struct.unpack_from("<IIIII", data, off)
    if orig == 0 and name_rva == 0:
        break
    no = rva2(name_rva)
    dll = data[no : data.find(b"\x00", no)].decode("ascii", "replace")
    thunk = rva2(orig if orig else ft)
    iat = rva2(ft)
    t = thunk
    idx = 0
    while t:
        hint_rva = struct.unpack_from("<Q", data, t)[0]
        if hint_rva == 0:
            break
        if not (hint_rva & 0x8000000000000000):
            ho = rva2(hint_rva & 0x7FFFFFFF)
            if ho:
                nm = data[ho + 2 : data.find(b"\x00", ho + 2)].decode("ascii", "replace")
                if nm == "MessageBoxW":
                    mbox_iat_rva = ft + idx * 8
                    print("MessageBoxW IAT rva", hex(mbox_iat_rva), "ft", hex(ft), "idx", idx)
        t += 8
        idx += 1
    off += 20

cs = Cs(CS_ARCH_X86, CS_MODE_64)
cs.detail = True

# disasm JNI_OnLoad ~400 insns
jo = rva2(jni_rva)
print("\n==== JNI_OnLoad ====")
code = data[jo : jo + 800]
for insn in cs.disasm(code, jni_rva):
    print(f"  {insn.address:08x}  {insn.mnemonic:8} {insn.op_str}")
    if insn.address - jni_rva > 500:
        break

# scan .text for calls that load IAT MessageBoxW: ff 15 rel32
print("\n==== MessageBoxW call sites (ff 15) ====")
text = next(s for s in sects if s[0] == ".text")
_, tva, tvsz, traw, trsz = text
blob = data[traw : traw + trsz]
if mbox_iat_rva:
    i = 0
    hits = 0
    while i < len(blob) - 6:
        if blob[i] == 0xFF and blob[i + 1] == 0x15:
            rel = struct.unpack_from("<i", blob, i + 2)[0]
            rip = tva + i + 6
            target = (rip + rel) & 0xFFFFFFFF
            if target == mbox_iat_rva:
                print(f"  call MessageBoxW at rva {tva+i:#x}")
                # print nearby
                start = max(0, i - 80)
                for insn in cs.disasm(blob[start : i + 16], tva + start):
                    mark = " <<<" if insn.address == tva + i else ""
                    print(f"    {insn.address:08x}  {insn.mnemonic:8} {insn.op_str}{mark}")
                    if insn.address > tva + i:
                        break
                hits += 1
        i += 1
    print("hits", hits)
