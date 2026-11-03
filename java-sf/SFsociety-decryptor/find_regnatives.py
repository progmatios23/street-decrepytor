from pathlib import Path

d = Path(r"D:\STREET-tool\out\natives\sydney_1_pe.dll").read_bytes()
va, raw = 0x1000, 0x400
blob = d[raw : raw + 0x379600]
needles = [
    b"\xff\x90\xb8\x06\x00\x00",
    b"\xff\x91\xb8\x06\x00\x00",
    b"\xff\x92\xb8\x06\x00\x00",
    b"\xff\x50\x6b",
    b"\xb8\x06\x00\x00",
]
for nd in needles:
    print("needle", nd.hex())
    off = 0
    c = 0
    while c < 12:
        j = blob.find(nd, off)
        if j < 0:
            break
        print(" ", hex(va + j), blob[max(0, j - 8) : j + 10].hex())
        off = j + 1
        c += 1
