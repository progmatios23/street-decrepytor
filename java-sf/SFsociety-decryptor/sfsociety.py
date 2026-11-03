#!/usr/bin/env python3
"""
SFsociety-decryptor
Universal JAR unpack/dump + Sydney/ZKM loader decrypt.

Python 3.10+  —  no extra deps
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import zipfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

VERSION = "1.1.0"
TOOL_DIR = Path(__file__).resolve().parent
DEFAULT_ROOT = Path(r"D:\STREET-tool")
DEFAULT_JAR = DEFAULT_ROOT / "target.jar"
DEFAULT_OUT = DEFAULT_ROOT / "out"

# ZKM 21 marker left in the constant pool of every protected class.
ZKM_MARKER = b"ZKM21.0.0"

# Recovered from sydney$d80eeccfcac2600d61a77f3e <clinit> 7-xor
# (tableswitch 0..5 + default) applied to CP #5, then String.getBytes(UTF_8).
SYDNEY_XOR_KEY = b"CqbHnBrA4QMB3AsnEmfbPG42XDMXD0QO"
SYDNEY_BLOB_ELF_OFF = 19


# ---------------------------------------------------------------------------
# class-file crumbs
# ---------------------------------------------------------------------------

def u2(d: bytes, i: int) -> tuple[int, int]:
    return struct.unpack_from(">H", d, i)[0], i + 2


def u4(d: bytes, i: int) -> tuple[int, int]:
    return struct.unpack_from(">I", d, i)[0], i + 4


def parse_cp(data: bytes):
    i = 8
    cp_count, i = u2(data, i)
    cp: list = [None] * cp_count
    j = 1
    while j < cp_count:
        tag = data[i]
        i += 1
        if tag == 1:
            ln, i = u2(data, i)
            cp[j] = ("Utf8", data[i : i + ln])
            i += ln
        elif tag in (7, 8, 16, 19, 20):
            a, i = u2(data, i)
            cp[j] = (tag, a)
        elif tag == 3:
            v, i = u4(data, i)
            cp[j] = ("Int", v)
        elif tag == 4:
            v, i = u4(data, i)
            cp[j] = ("Float", v)
        elif tag in (9, 10, 11, 12, 17, 18):
            a, i = u2(data, i)
            b, i = u2(data, i)
            cp[j] = (tag, a, b)
        elif tag == 5:
            a, i = u4(data, i)
            b, i = u4(data, i)
            cp[j] = ("Long", (a << 32) | b)
            j += 1
        elif tag == 6:
            a, i = u4(data, i)
            b, i = u4(data, i)
            cp[j] = ("Double", a, b)
            j += 1
        elif tag == 15:
            i += 3
            cp[j] = ("MH",)
        else:
            raise ValueError(f"unknown CP tag {tag} at {i}")
        j += 1
    return cp, i


def utf(cp, idx: int) -> str:
    if idx == 0 or cp[idx] is None:
        return ""
    e = cp[idx]
    if e[0] == "Utf8":
        return e[1].decode("utf-8", "replace")
    if e[0] == 7:
        return utf(cp, e[1])
    if e[0] == 8:
        return utf(cp, e[1])
    if e[0] == 12:
        return utf(cp, e[1]) + utf(cp, e[2])
    if e[0] in (9, 10, 11):
        return utf(cp, e[1]) + "." + utf(cp, e[2])
    return str(e)


def skip_insn(code: bytes, pc: int) -> int:
    op = code[pc]
    if op == 0xC4:
        return 6 if code[pc + 1] == 0x84 else 4
    if op == 0xAA:
        p = (pc + 4) & ~3
        _default, low, high = struct.unpack_from(">iii", code, p)
        n = high - low + 1
        return (p + 12 + 4 * n) - pc
    if op == 0xAB:
        p = (pc + 4) & ~3
        _default, npairs = struct.unpack_from(">ii", code, p)
        return (p + 8 + 8 * npairs) - pc
    sizes = {
        0x10: 2, 0x11: 3, 0x12: 2, 0x13: 3, 0x14: 3,
        0x15: 2, 0x16: 2, 0x17: 2, 0x18: 2, 0x19: 2,
        0x36: 2, 0x37: 2, 0x38: 2, 0x39: 2, 0x3A: 2,
        0x84: 3,
        0x99: 3, 0x9A: 3, 0x9B: 3, 0x9C: 3, 0x9D: 3, 0x9E: 3,
        0x9F: 3, 0xA0: 3, 0xA1: 3, 0xA2: 3, 0xA3: 3, 0xA4: 3, 0xA5: 3, 0xA6: 3,
        0xA7: 3, 0xA8: 3, 0xA9: 2,
        0xB2: 3, 0xB3: 3, 0xB4: 3, 0xB5: 3,
        0xB6: 3, 0xB7: 3, 0xB8: 3, 0xB9: 5, 0xBA: 5,
        0xBB: 3, 0xBC: 2, 0xBD: 3, 0xC0: 3, 0xC1: 3,
        0xC5: 4, 0xC6: 3, 0xC7: 3, 0xC8: 5, 0xC9: 5,
    }
    return sizes.get(op, 1)


def extract_7xor_keys(code: bytes) -> list[int] | None:
    """tableswitch 0..5 whose cases are bipush + default bipush -> 7-byte ZKM key."""
    pc = 0
    while pc < len(code):
        if code[pc] == 0xAA:
            p = (pc + 4) & ~3
            default, low, high = struct.unpack_from(">iii", code, p)
            n = high - low + 1
            offs = struct.unpack_from(">" + "i" * n, code, p + 12)
            if low == 0 and high == 5 and n == 6:
                keys: list[int] = []
                ok = True
                for off in list(offs) + [default]:
                    tpc = pc + off
                    if tpc < 0 or tpc >= len(code) or code[tpc] != 0x10:
                        ok = False
                        break
                    keys.append(code[tpc + 1])
                if ok:
                    return keys
            pc = p + 12 + 4 * n
            continue
        pc += skip_insn(code, pc)
    return None


def class_methods(data: bytes):
    cp, i = parse_cp(data)
    _acc, i = u2(data, i)
    this, i = u2(data, i)
    _sup, i = u2(data, i)
    ifc, i = u2(data, i)
    for _ in range(ifc):
        _, i = u2(data, i)
    nf, i = u2(data, i)
    for _ in range(nf):
        _, i = u2(data, i)
        _, i = u2(data, i)
        _, i = u2(data, i)
        na, i = u2(data, i)
        for __ in range(na):
            _, i = u2(data, i)
            al, i = u4(data, i)
            i += al
    nm, i = u2(data, i)
    methods = []
    for _ in range(nm):
        ma, i = u2(data, i)
        mn, i = u2(data, i)
        md, i = u2(data, i)
        na, i = u2(data, i)
        code = None
        for __ in range(na):
            an, i = u2(data, i)
            al, i = u4(data, i)
            av = data[i : i + al]
            i += al
            if utf(cp, an) == "Code":
                clen = struct.unpack_from(">I", av, 4)[0]
                code = av[8 : 8 + clen]
        methods.append((utf(cp, mn), utf(cp, md), ma, code))
    return utf(cp, this), cp, methods


def mutf8_to_chars(data: bytes) -> list[int]:
    chars: list[int] = []
    i = 0
    n = len(data)
    while i < n:
        b = data[i]
        if b < 0x80:
            chars.append(b)
            i += 1
        elif (b & 0xE0) == 0xC0 and i + 1 < n:
            chars.append(((b & 0x1F) << 6) | (data[i + 1] & 0x3F))
            i += 2
        elif (b & 0xF0) == 0xE0 and i + 2 < n:
            chars.append(
                ((b & 0x0F) << 12)
                | ((data[i + 1] & 0x3F) << 6)
                | (data[i + 2] & 0x3F)
            )
            i += 3
        else:
            chars.append(b)
            i += 1
    return chars


def zkm_7xor_string(raw: bytes, keys: list[int]) -> str:
    chars = mutf8_to_chars(raw)
    out = [c ^ keys[i % len(keys)] for i, c in enumerate(chars)]
    return "".join(chr(c) if 0 <= c < 0x110000 else "?" for c in out)


# ---------------------------------------------------------------------------
# unpack
# ---------------------------------------------------------------------------

def unpack_jar(jar: Path, dest: Path) -> list[dict]:
    dest.mkdir(parents=True, exist_ok=True)
    entries = []
    with zipfile.ZipFile(jar, "r") as zf:
        for info in zf.infolist():
            target = dest / info.filename
            if info.is_dir() or info.filename.endswith("/"):
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            data = zf.read(info)
            target.write_bytes(data)
            entries.append(
                {
                    "name": info.filename,
                    "size": info.file_size,
                    "compress": info.compress_size,
                    "sha256": hashlib.sha256(data).hexdigest(),
                }
            )
    return entries


# ---------------------------------------------------------------------------
# native blob decrypt (Sydney loader)
# ---------------------------------------------------------------------------

def xor_bytes(data: bytes, key: bytes, key_off: int = 0) -> bytes:
    if not data:
        return b""
    klen = len(key)
    off = key_off % klen
    rotated = key[off:] + key[:off]
    repeated = rotated * (len(data) // klen + 1)
    repeated = repeated[: len(data)]
    return bytes(a ^ b for a, b in zip(data, repeated))


def elf_file_size(plain: bytes) -> int:
    """Estimate ELF size from section headers, else program headers. `plain` is already decrypted."""
    if len(plain) < 64 or plain[:4] != b"\x7fELF":
        return 0
    cls, endian = plain[4], plain[5]
    if cls != 2:
        return 0
    fmt = "<" if endian == 1 else ">"
    e_phoff, e_shoff = struct.unpack_from(fmt + "QQ", plain, 32)
    _flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum, _ = struct.unpack_from(
        fmt + "IHHHHHH", plain, 48
    )
    if e_shoff and e_shnum and e_shentsize:
        end = int(e_shoff + e_shnum * e_shentsize)
        if end <= len(plain):
            return end
    if e_phoff and e_phnum and e_phentsize:
        ph_off = int(e_phoff)
        end = 64
        for i in range(e_phnum):
            p = plain[ph_off + i * e_phentsize : ph_off + (i + 1) * e_phentsize]
            if len(p) < 56:
                break
            p_offset, _v, _p, p_filesz = struct.unpack_from(fmt + "QQQQ", p, 8)
            end = max(end, p_offset + p_filesz)
        return int(end)
    return 0


def pe_file_size(mz: bytes) -> int:
    if mz[:2] != b"MZ" or len(mz) < 0x40:
        return 0
    pe_off = struct.unpack_from("<I", mz, 0x3C)[0]
    if pe_off + 24 >= len(mz) or mz[pe_off : pe_off + 4] != b"PE\x00\x00":
        return 0
    nsec = struct.unpack_from("<H", mz, pe_off + 6)[0]
    opt = struct.unpack_from("<H", mz, pe_off + 20)[0]
    sec_off = pe_off + 24 + opt
    end = sec_off + nsec * 40
    for i in range(nsec):
        s = sec_off + i * 40
        if s + 40 > len(mz):
            break
        raw_size = struct.unpack_from("<I", mz, s + 16)[0]
        raw_ptr = struct.unpack_from("<I", mz, s + 20)[0]
        end = max(end, raw_ptr + raw_size)
    return end


def detect_magic(b: bytes) -> str | None:
    if b[:4] == b"\x7fELF":
        return "elf"
    if b[:2] == b"MZ":
        return "pe"
    if b[:4] in (b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        return "macho"
    if b[:4] == b"PK\x03\x04":
        return "zip"
    if b[:4] == b"\xca\xfe\xba\xbe":
        return "class"
    if b[:2] == b"\x1f\x8b":
        return "gzip"
    return None


def _valid_pe(hdr: bytes) -> bool:
    if len(hdr) < 0x40 or hdr[:2] != b"MZ":
        return False
    pe_off = struct.unpack_from("<I", hdr, 0x3C)[0]
    if pe_off < 0x40 or pe_off + 4 > len(hdr):
        return False
    return hdr[pe_off : pe_off + 4] == b"PE\x00\x00"


def decrypt_sydney_blob(blob: bytes, key: bytes, out_dir: Path) -> list[dict]:
    """Native table from decompiled Natives.load() (CFR after Zelix string decrypt):

      u32be count
      for each:
          u16be extLen;  bytes ext
          u16be archLen; bytes arch
          u32be dataLen; bytes encrypted
          payload = XOR(encrypted, key, idx=0)
    """
    if out_dir.exists():
        for old in out_dir.iterdir():
            if old.is_file():
                old.unlink()
    out_dir.mkdir(parents=True, exist_ok=True)
    results: list[dict] = []
    (out_dir / "blob_raw.bin").write_bytes(blob)

    count = struct.unpack_from(">I", blob, 0)[0]
    off = 4
    print(f"  native table count={count} xor={key!r}", flush=True)
    for i in range(count):
        ext_len = struct.unpack_from(">H", blob, off)[0]
        off += 2
        ext = blob[off : off + ext_len]
        off += ext_len
        arch_len = struct.unpack_from(">H", blob, off)[0]
        off += 2
        arch = blob[off : off + arch_len]
        off += arch_len
        data_len = struct.unpack_from(">I", blob, off)[0]
        off += 4
        enc = blob[off : off + data_len]
        rec_off = off
        off += data_len
        plain = xor_bytes(enc, key, 0)
        mag = detect_magic(plain) or "bin"
        extn = { "elf": ".so", "pe": ".dll", "macho": ".dylib" }.get(mag, ".bin")
        path = out_dir / f"sydney_{i}_{mag}{extn}"
        path.write_bytes(plain)
        rec = {
            "index": i,
            "offset": rec_off,
            "size": data_len,
            "magic": mag,
            "ext_raw": ext.hex(),
            "arch_raw": arch.hex(),
            "path": str(path),
            "sha256": hashlib.sha256(plain).hexdigest(),
        }
        results.append(rec)
        print(f"  [{i}] {mag:5} size={data_len} -> {path.name}", flush=True)
    if off < len(blob):
        (out_dir / "blob_tail.bin").write_bytes(blob[off:])
        print(f"  tail {len(blob) - off} bytes", flush=True)
    return results


# ---------------------------------------------------------------------------
# analysis
# ---------------------------------------------------------------------------

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    import math

    c = Counter(data)
    n = len(data)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def analyze_unpacked(unpacked: Path, out: Path) -> dict:
    classes = list(unpacked.rglob("*.class"))
    blobs = [
        p
        for p in unpacked.rglob("*")
        if p.is_file()
        and p.suffix not in {".class", ".json", ".MF", ".png"}
        and not p.name.endswith(".MF")
    ]
    report: dict = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "unpacked": str(unpacked),
        "class_count": len(classes),
        "zkm": False,
        "loader": None,
        "classes": [],
        "zkm_strings": [],
        "natives": [],
        "blobs": [],
    }

    for p in classes:
        data = p.read_bytes()
        rec = {
            "path": str(p.relative_to(unpacked)).replace("\\", "/"),
            "size": len(data),
            "major": struct.unpack_from(">H", data, 6)[0] if len(data) >= 8 else 0,
        }
        zkm = ZKM_MARKER in data
        rec["zkm"] = zkm
        report["zkm"] = report["zkm"] or zkm
        try:
            this, cp, methods = class_methods(data)
        except Exception as e:
            rec["error"] = str(e)
            report["classes"].append(rec)
            continue
        rec["this"] = this
        rec["methods"] = [
            {
                "name": n,
                "desc": d,
                "acc": hex(a),
                "native": bool(a & 0x100),
                "code": 0 if c is None else len(c),
            }
            for n, d, a, c in methods
        ]
        rec["native_methods"] = [m["name"] for m in rec["methods"] if m["native"]]
        utf8s = [e[1] for e in cp if e and e[0] == "Utf8"]
        rec["strings"] = [
            s.decode("utf-8", "replace")[:120]
            for s in utf8s
            if 3 < len(s) < 80
        ]
        for n, d, a, c in methods:
            if not c:
                continue
            keys = extract_7xor_keys(c)
            if not keys:
                continue
            rec["zkm7_keys"] = keys
            for raw in utf8s:
                if len(raw) < 4 or raw.startswith(
                    (b"java", b"net/", b"Code", b"Loc", b"Sta", b"Sig", b"Boo", b"Sou", b"Lnet", b"Ljav")
                ):
                    continue
                dec = zkm_7xor_string(raw, keys)
                printable = sum(32 <= ord(ch) < 127 for ch in dec) / max(len(dec), 1)
                alnum = sum(ch.isalnum() for ch in dec) / max(len(dec), 1)
                if printable > 0.9 and alnum > 0.55 and " " not in dec[:2]:
                    report["zkm_strings"].append(
                        {"class": this, "keys": keys, "plain": dec[:200]}
                    )
        report["classes"].append(rec)

    # loader fingerprint
    fabric = unpacked / "fabric.mod.json"
    if fabric.exists():
        try:
            report["loader"] = json.loads(fabric.read_text(encoding="utf-8"))
        except Exception:
            report["loader"] = {"raw": fabric.read_text(encoding="utf-8", errors="replace")}

    for p in unpacked.rglob("*"):
        if not p.is_file():
            continue
        if p.suffix == ".class":
            continue
        rel = str(p.relative_to(unpacked)).replace("\\", "/")
        data = p.read_bytes() if p.stat().st_size <= 64 * 1024 * 1024 else b""
        rec = {
            "path": rel,
            "size": p.stat().st_size,
            "sha256": hashlib.sha256(p.read_bytes()).hexdigest() if p.stat().st_size <= 64 * 1024 * 1024 else None,
            "head": p.read_bytes()[:16].hex() if p.stat().st_size else "",
            "entropy64k": round(entropy(p.read_bytes()[:65536]), 3),
        }
        report["blobs"].append(rec)

        if p.name.startswith("sydney$") and p.stat().st_size > 100_000:
            print(f"[*] sydney encrypted blob {rel} ({p.stat().st_size} bytes)")
            native_dir = out / "natives"
            report["natives"] = decrypt_sydney_blob(p.read_bytes(), SYDNEY_XOR_KEY, native_dir)

    (out / "analysis.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    write_markdown_report(report, out / "LOADER_REPORT.md")
    return report


def write_markdown_report(report: dict, path: Path) -> None:
    lines = [
        "# SFsociety-decryptor — loader report",
        "",
        f"generated: {report['generated']}",
        f"classes: {report['class_count']}",
        f"ZKM21 marker: {report['zkm']}",
        "",
        "## What this JAR is",
        "",
        "Fabric 1.21+ client loader for **Sydney** (`sydneyclient.net`).",
        "Outer JAR is a stub: ZKM 21 string encryption + JNI natives + one 13 MB encrypted resource.",
        "Real client classes live behind `Natives.getResource` / `getClassBytes` after `Natives.load()`.",
        "",
        "## Protection stack",
        "",
        "- Zelix Klassmaster 21.0.0 (`ZKM21.0.0` in every class CP)",
        "- invokedynamic string / member hiding via `net.sydneyclient.loader.h`",
        "- 7-xor char tableswitch in `<clinit>` (recovered)",
        "- repeating-XOR native blob key `CqbHnBrA4QMB3AsnEmfbPG42XDMXD0QO`",
        "- native methods: `Natives.getResource`, `getResources`, `getUserId`, `getUsername`",
        "- mixin plugin + Knot classloader override (`MixinServiceKnot` subclass)",
        "",
        "## Recovered ZKM 7-xor strings",
        "",
    ]
    if report["zkm_strings"]:
        for s in report["zkm_strings"][:80]:
            lines.append(f"- `{s['class']}` keys={s['keys']} → `{s['plain']}`")
    else:
        lines.append("_none that passed the printable filter (indy strings still encrypted)_")
    lines += [
        "",
        "## Native payload",
        "",
    ]
    if report["natives"]:
        for n in report["natives"]:
            lines.append(
                f"- {n['magic']} off={n['offset']} size={n['size']} `{n['path']}` sha256={n['sha256'][:16]}…"
            )
    else:
        lines.append("_no native extracted_")
    lines += [
        "",
        "## Classes",
        "",
        "| class | natives | zkm |",
        "|---|---|---|",
    ]
    for c in report["classes"]:
        lines.append(
            f"| `{c.get('this', c['path'])}` | {', '.join(c.get('native_methods') or ['-'])} | {c.get('zkm')} |"
        )
    lines += [
        "",
        "## Next layer (needs JVM 21 or java-deobfuscator)",
        "",
        "ZKM `a(II)` / `a(III)` + invokedynamic bootstrap in `h` still hide names.",
        "Run `github/deobfuscator` with `deobfuscator-config.yml` on a JDK 17+ box.",
        "After ZKM strings drop, `Natives.load` shows the temp-file + `System.load` path;",
        "`getResource` then yields inner class bytes which go through",
        "`sydney$d80eeccfcac2600d61a77f3e.sydney$3aa681e4573fa8bf086d08d1([B)[B` (same XOR).",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def dump_inventory(unpacked: Path, out: Path) -> None:
    rows = ["path,size,sha256"]
    for p in sorted(unpacked.rglob("*")):
        if not p.is_file():
            continue
        data = p.read_bytes()
        rel = str(p.relative_to(unpacked)).replace("\\", "/")
        rows.append(f"{rel},{len(data)},{hashlib.sha256(data).hexdigest()}")
    (out / "inventory.csv").write_text("\n".join(rows), encoding="utf-8")


# ---------------------------------------------------------------------------
# cli
# ---------------------------------------------------------------------------

def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="sfsociety", description="SFsociety-decryptor — universal JAR unpack + Sydney/ZKM decrypt")
    p.add_argument("jar", nargs="?", default=str(DEFAULT_JAR), help="input JAR")
    p.add_argument("-o", "--out", default=str(DEFAULT_OUT), help="output directory")
    p.add_argument("--unpack-only", action="store_true")
    p.add_argument("--analyze-only", action="store_true", help="skip unpack, analyze existing unpacked/")
    p.add_argument("--crack", action="store_true", help="full pipeline: unpack + zkm emu + source compare")
    p.add_argument("--unpacked", default=None, help="existing unpacked dir")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    jar = Path(args.jar)
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    unpacked = Path(args.unpacked) if args.unpacked else out / "unpacked"

    if args.crack:
        from crack import main as crack_main

        return crack_main()

    print(f"SFsociety-decryptor {VERSION}", flush=True)
    print(f"  jar  {jar}", flush=True)
    print(f"  out  {out}", flush=True)

    if not args.analyze_only:
        if not jar.is_file():
            print(f"jar not found: {jar}", file=sys.stderr)
            return 2
        print("[*] unpacking")
        entries = unpack_jar(jar, unpacked)
        print(f"    {len(entries)} files")
        dump_inventory(unpacked, out)

    if args.unpack_only:
        return 0

    print("[*] analyze + decrypt")
    analyze_unpacked(unpacked, out)
    print(f"[*] report -> {out / 'LOADER_REPORT.md'}")
    print(f"[*] json   -> {out / 'analysis.json'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
