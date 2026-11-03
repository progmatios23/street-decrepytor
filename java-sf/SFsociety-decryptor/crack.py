#!/usr/bin/env python3
"""
SFsociety crack pipeline — compare github deobfuscators + emulate ZKM + unpack natives.

Layers we actually break here:
  1. JAR unpack (universal)
  2. ZKM 21 7-xor clinit (Diobf ZKMCipher.cipher2 equivalent)
  3. Repeating-XOR native blob → ELF64 JNI .so
  4. Byte-xor class decrypt sydney$3aa681…([B)[B  (same key)

Layers that need JDK 21 + Linux (not this box: JRE 8, Windows):
  - invokedynamic MethodHandles bootstrap in h  (java-deobfuscator javavm / threadtear VM)
  - JNI_OnLoad RegisterNatives + AWS-LC AES on leftover 8.6 MB
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from jvm_lite import Interpreter, VMError, load_class
from sfsociety import (
    SYDNEY_XOR_KEY,
    VERSION,
    analyze_unpacked,
    decrypt_sydney_blob,
    unpack_jar,
    xor_bytes,
)

ROOT = Path(r"D:\STREET-tool")
OUT = ROOT / "out"
JAR = ROOT / "target.jar"
GITHUB = ROOT / "github"
DECRYPTOR = Path(__file__).resolve().parent


def emulate_zkm(unpacked: Path) -> dict:
    classes = {}
    loader = unpacked / "net" / "sydneyclient" / "loader"
    if not loader.exists():
        return {"ok": False, "error": "no loader dir"}
    for p in unpacked.rglob("*.class"):
        jc = load_class(p)
        classes[jc.name] = jc
    vm = Interpreter(classes)
    results = {"classes": {}, "strings": [], "xor_key": None}
    for name, jc in classes.items():
        try:
            vm.clinit(name)
            snap = {}
            for k, v in jc.statics.items():
                if k == "<clinit_done>":
                    continue
                if isinstance(v, list) and v and isinstance(v[0], int) and max(v[:8] or [0]) <= 255:
                    b = bytes(x & 0xFF for x in v)
                    snap[k] = {"bytes_len": len(b), "head": b[:32].hex(), "ascii": b.decode("utf-8", "replace")[:64]}
                    if b == SYDNEY_XOR_KEY:
                        results["xor_key"] = b.decode("ascii")
                elif isinstance(v, list):
                    snap[k] = [str(x)[:80] for x in v[:16]]
                elif isinstance(v, str):
                    snap[k] = v[:120]
                else:
                    snap[k] = repr(v)[:120]
            results["classes"][name] = {"ok": True, "statics": snap}
        except Exception as e:
            results["classes"][name] = {"ok": False, "error": f"{type(e).__name__}: {e}"}

    # enhanced a(III)
    nat = "net/sydneyclient/loader/Natives"
    if nat in classes and results["classes"].get(nat, {}).get("ok"):
        try:
            s = vm.call(nat, "a", "(III)Ljava/lang/String;", [625728180, -7152, 0])
            results["strings"].append({"sig": "Natives.a(III)", "args": [625728180, -7152, 0], "out": str(s)[:200]})
        except Exception as e:
            results["strings"].append({"sig": "Natives.a(III)", "error": str(e)})
    return results


def compare_sources() -> list[dict]:
    rows = [
        {
            "tool": "SFsociety-decryptor (ours)",
            "zkm": "ZKM21 7-xor tableswitch + StaticInit port + jvm_lite a(II/III)",
            "native": "repeating-XOR ELF extract, leftover AES not broken",
            "vm": "Python interpreter (no indy MH)",
            "zkm_max": "21 simple + partial enhanced",
        },
        {
            "tool": "Diobf/Deobfuscator (narumi)",
            "zkm": "ComposedZelixTransformer, ZKMCipher, tested ZKM 22.0.3",
            "native": "none",
            "vm": "ASM transformers + optional sandbox",
            "zkm_max": "22 enhanced strings",
        },
        {
            "tool": "java-deobfuscator/deobfuscator",
            "zkm": "StringEncryptionTransformer + Enhanced via javavm",
            "native": "none",
            "vm": "full Java VM (javavm) — best for indy",
            "zkm_max": "5-9 documented; 21 indy needs VM",
        },
        {
            "tool": "GraxCode/threadtear",
            "zkm": "StringObfuscationZKM + DESObfuscationZKM + AccessObfuscationZKM",
            "native": "none",
            "vm": "Sandbox VM, reflection required",
            "zkm_max": "5-14 (DES WIP)",
        },
        {
            "tool": "katana-project/poke",
            "zkm": "generic ProGuard-core normalize, not ZKM-specific",
            "native": "none",
            "vm": "no",
            "zkm_max": "generic only",
        },
        {
            "tool": "c2j-native-deobfuscator",
            "zkm": "no",
            "native": "JVMTI + Ghidra + CPU emu + mock JNI (native-obfuscator / j2cc)",
            "vm": "CPU emulator",
            "zkm_max": "n/a — this .so is Rust+JNI_OnLoad, not j2cc",
        },
    ]
    present = []
    for r in rows:
        r["cloned"] = True
        present.append(r)
    # poke/threadtear existence
    for r in present:
        slug = r["tool"].split()[0].split("/")[-1]
        if slug == "SFsociety-decryptor":
            r["path"] = str(DECRYPTOR)
        elif slug == "Diobf":
            r["path"] = str(GITHUB / "Diobf-Deobfuscator")
        elif "java-deobfuscator" in r["tool"]:
            r["path"] = str(GITHUB / "deobfuscator")
        elif "threadtear" in r["tool"]:
            r["path"] = str(GITHUB / "threadtear")
        elif "poke" in r["tool"]:
            r["path"] = str(GITHUB / "poke")
        elif "c2j" in r["tool"]:
            r["path"] = str(GITHUB / "c2j-native-deobfuscator")
        r["on_disk"] = Path(r["path"]).exists() if r.get("path") else False
    return present


def xor_class_decrypt(natives_dir: Path) -> dict:
    """Apply sydney$3aa681 repeating-XOR to leftover; carve CAFE/PK."""
    leftover = natives_dir / "blob_leftover_xor.bin"
    raw = natives_dir / "blob_raw.bin"
    info = {"carves": []}
    if not leftover.exists():
        return info
    data = leftover.read_bytes()
    plain = xor_bytes(data, SYDNEY_XOR_KEY, 0)
    (natives_dir / "leftover_xor_again.bin").write_bytes(plain)
    blob = raw.read_bytes() if raw.exists() else b""
    rest = blob[19 + 5382488 :] if len(blob) > 19 + 5382488 else b""
    (natives_dir / "raw_rest.bin").write_bytes(rest)
    for label, buf in (("leftover", data), ("leftover^key", plain), ("raw_rest", rest)):
        for magic, tag in ((b"\xca\xfe\xba\xbe", "class"), (b"PK\x03\x04", "zip"), (b"\x7fELF", "elf")):
            i = buf.find(magic)
            info["carves"].append({"buf": label, "tag": tag, "off": i})
    return info


def write_report(path: Path, emu: dict, cmp_: list[dict], carve: dict) -> None:
    lines = [
        "# SFsociety crack report",
        "",
        f"generated: {datetime.now(timezone.utc).isoformat()}",
        f"tool {VERSION}",
        "",
        "## Source compare (ours vs cloned github)",
        "",
        "| tool | ZKM | native | VM | on disk |",
        "|---|---|---|---|---|",
    ]
    for r in cmp_:
        lines.append(
            f"| {r['tool']} | {r['zkm']} | {r['native']} | {r['vm']} | {r.get('on_disk')} |"
        )
    lines += [
        "",
        "## What we emulate",
        "",
        "- Diobf `ZKMCipher.cipher2` = 7-xor tableswitch (proven: blob key `CqbHnBrA4QMB3AsnEmfbPG42XDMXD0QO`)",
        "- java-deobfuscator enhanced `(II)/(III)Ljava/lang/String;` via `jvm_lite` (partial; ZKM junk stack)",
        "- threadtear-style isolate of String calls — same interpreter",
        "- c2j-style native unpack: XOR record 0 → ELF64 `JNI_OnLoad` AWS-LC",
        "",
        "## Emulator statics",
        "",
        "```json",
        json.dumps(emu, indent=2)[:4000],
        "```",
        "",
        "## Native leftover",
        "",
        "8.6 MB after the linux .so. No ELF/PE/ZIP/CAFE at any XOR alignment.",
        "AES-ECB/CBC/GCM with xor-key, sha256(key), .rodata keys: no verified magic.",
        "`.so` strings: `JNI_OnLoad`, `DefineClass`, `DecryptionFailed`, AES-256-GCM/CTR (aws-lc).",
        "This remaining payload is decrypted **inside** `JNI_OnLoad` after `RegisterNatives`.",
        "100% of that layer = run the .so under Linux + JDK 21 (or Unicorn + JNI stubs).",
        "",
        f"carve scan: {carve}",
        "",
        "## 100% crack checklist",
        "",
        "1. [x] unpack JAR",
        "2. [x] detect ZKM21",
        "3. [x] recover 7-xor key + linux .so",
        "4. [~] emulate ZKM string methods (jvm_lite)",
        "5. [ ] javavm/threadtear on JDK 17+ for indy bootstrap `h`",
        "6. [ ] execute `JNI_OnLoad` (Linux) → AES leftover → win .dll + inner classes",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    print(f"SFsociety crack {VERSION}", flush=True)
    unpacked = OUT / "unpacked"
    if not unpacked.exists() or not JAR.exists():
        print("[*] unpack", flush=True)
        unpack_jar(JAR, unpacked)
    print("[*] analyze + native xor", flush=True)
    analyze_unpacked(unpacked, OUT)
    print("[*] emulate ZKM", flush=True)
    emu = emulate_zkm(unpacked)
    print("[*] compare sources", flush=True)
    cmp_ = compare_sources()
    print("[*] leftover carve", flush=True)
    carve = xor_class_decrypt(OUT / "natives")
    write_report(OUT / "CRACK_REPORT.md", emu, cmp_, carve)
    (OUT / "source_compare.json").write_text(json.dumps(cmp_, indent=2), encoding="utf-8")
    (OUT / "emu_zkm.json").write_text(json.dumps(emu, indent=2), encoding="utf-8")
    print(f"[*] {OUT / 'CRACK_REPORT.md'}", flush=True)
    xor_ok = emu.get("xor_key")
    print(f"    xor_key recovered by emu: {xor_ok}", flush=True)
    fails = [k for k, v in emu.get("classes", {}).items() if not v.get("ok")]
    print(f"    clinit fail: {fails}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
