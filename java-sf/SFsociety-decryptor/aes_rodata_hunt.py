"""Hunt AES keys in .so .rodata against leftover first block."""
from pathlib import Path
import struct
from Crypto.Cipher import AES

SO = Path(r"D:\STREET-tool\out\natives\libsydney_0_linux_x86_64.so").read_bytes()
LEFT = Path(r"D:\STREET-tool\out\natives\blob_leftover_xor.bin").read_bytes()
RAWREST = Path(r"D:\STREET-tool\out\natives\blob_raw.bin").read_bytes()[19 + 5382488 :]

# .rodata off=0x23000 size=671040
ro = SO[0x23000 : 0x23000 + 671040]
text = SO[0x10BB80 : 0x10BB80 + 4208054]


def mag(d: bytes):
    if d[:4] == b"\x7fELF":
        return "ELF"
    if d[:4] == b"PK\x03\x04":
        return "ZIP"
    if d[:4] == b"\xca\xfe\xba\xbe":
        return "CLASS"
    if d[:2] == b"MZ" and len(d) > 64:
        pe = struct.unpack_from("<I", d, 0x3C)[0] if len(d) >= 64 else 0
        if 0x40 < pe < 0x800:
            return "MZ?"
    if d[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return "MACHO"
    if d[:2] == b"\x1f\x8b":
        return "GZIP"
    return None


def hunt(blob: bytes, region: bytes, tag: str):
    hits = 0
    first16 = blob[:16]
    iv = blob[:16]
    body = blob[16:48]
    for i in range(0, len(region) - 32, 8):
        k16 = region[i : i + 16]
        k32 = region[i : i + 32]
        try:
            pt = AES.new(k16, AES.MODE_ECB).decrypt(first16)
            m = mag(pt)
            if m:
                print(f"HIT {tag} ECB16 off={i:#x} {m} {pt.hex()}")
                hits += 1
        except Exception:
            pass
        try:
            pt = AES.new(k16, AES.MODE_CBC, iv=iv).decrypt(body)
            m = mag(pt)
            if m:
                print(f"HIT {tag} CBC16 off={i:#x} {m} {pt[:16].hex()}")
                hits += 1
        except Exception:
            pass
        if i % 16 == 0:
            try:
                pt = AES.new(k32, AES.MODE_ECB).decrypt(first16)
                m = mag(pt)
                if m:
                    print(f"HIT {tag} ECB32 off={i:#x} {m} {pt.hex()}")
                    hits += 1
            except Exception:
                pass
        if hits > 15:
            print("too many, stop")
            return hits
    print(f"{tag} hits={hits}")
    return hits


print("leftover vs rodata")
hunt(LEFT, ro, "left/ro")
print("leftover vs first 256k text")
hunt(LEFT, text[: 256 * 1024], "left/text")
print("rawrest vs rodata")
hunt(RAWREST, ro, "raw/ro")
print("done")
