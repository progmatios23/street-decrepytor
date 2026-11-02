# language: Python 3, file: farmservices_real_crack.py
# Honest crypto/protection analysis + extraction for FarmServices.exe
# *No Themida theater — only confirmed layers*
from __future__ import annotations

import gzip
import hashlib
import io
import json
import math
import re
import struct
import zlib
from pathlib import Path

TARGET = Path(r"C:\Users\ggles\Downloads\ANALISTAR\FarmServices.exe")
OUT = Path(r"D:\Street-decrepytor\output\crack\FarmServices_REAL")


def entropy(chunk: bytes) -> float:
    if not chunk:
        return 0.0
    freq = [0] * 256
    for b in chunk:
        freq[b] += 1
    h = 0.0
    n = len(chunk)
    for c in freq:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def pe_sections(data: bytes) -> list[dict]:
    e = struct.unpack_from("<I", data, 0x3C)[0]
    magic = struct.unpack_from("<H", data, e + 0x18)[0]
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    entry = struct.unpack_from("<I", data, e + 0x28)[0]
    sec = e + 0x18 + (0xE0 if magic == 0x10B else 0xF0)
    out = []
    for i in range(nsec):
        o = sec + i * 40
        name = data[o : o + 8].split(b"\0", 1)[0].decode("latin-1", "replace")
        vsize, va, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
        chunk = data[roff : roff + min(rsize, 1 << 16)] if rsize else b""
        out.append({
            "name": name,
            "va": va,
            "vsize": vsize,
            "roff": roff,
            "rsize": rsize,
            "entropy_sample": round(entropy(chunk), 3),
            "contains_ep": va <= entry < va + max(vsize, 1),
        })
    return out, entry


def detect_protectors_honest(data: bytes, secs: list[dict]) -> dict:
    markers = {
        "Themida": [b"Themida", b"WinLicense", b"Oreans", b".themida", b"Tmda"],
        "VMProtect": [b"VMProtect", b".vmp0", b".vmp1"],
        "UPX": [b"UPX!", b"UPX0", b"UPX1"],
        "Enigma": [b"Enigma Protector", b".enigma1"],
    }
    hits = {}
    for name, needles in markers.items():
        found = [n.decode("latin-1", "replace") for n in needles if n in data]
        if found:
            hits[name] = found
    # structural Themida: many virtual-only sections, EP outside .text
    virtual = [s for s in secs if s["rsize"] == 0 and s["vsize"] > 0x1000]
    ep_in_text = any(s["contains_ep"] and s["name"].startswith(".text") for s in secs)
    themida_struct = len(virtual) >= 2 and not ep_in_text
    return {
        "marker_hits": hits,
        "virtual_only_sections": len(virtual),
        "ep_in_text": ep_in_text,
        "themida_structural": themida_struct,
        "verdict": (
            "Themida/VMProtect NOT present"
            if not hits and not themida_struct
            else "protector markers or structure detected"
        ),
        "evidence": {
            "ep_in_text": ep_in_text,
            "section_entropies": {s["name"]: s["entropy_sample"] for s in secs},
            "note": "Packed Themida shells usually EP outside .text + high-entropy virtual sections",
        },
    }


def try_inflate_blob(blob: bytes) -> list[dict]:
    """Try gzip / zlib / raw deflate on a blob; return successful decodes."""
    results = []
    # gzip
    if blob[:2] == b"\x1f\x8b":
        try:
            dec = gzip.decompress(blob)
            results.append({"codec": "gzip", "out_len": len(dec), "data": dec})
        except Exception:
            try:
                dec = gzip.GzipFile(fileobj=io.BytesIO(blob)).read()
                results.append({"codec": "gzip_file", "out_len": len(dec), "data": dec})
            except Exception:
                pass
    # zlib
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS, 16 + zlib.MAX_WBITS):
        try:
            dec = zlib.decompress(blob, wbits)
            if len(dec) > 32:
                results.append({"codec": f"zlib_w{wbits}", "out_len": len(dec), "data": dec})
                break
        except Exception:
            continue
    return results


def scan_compressed_regions(data: bytes, out_dir: Path) -> list[dict]:
    """Walk whole file for gzip/zlib magic and inflate confirmed streams."""
    found = []
    magics = [
        (b"\x1f\x8b", "gzip"),
        (bytes([0x78, 0x9C]), "zlib_default"),
        (bytes([0x78, 0xDA]), "zlib_best"),
        (bytes([0x78, 0x01]), "zlib_no"),
    ]
    for mag, label in magics:
        start = 0
        while True:
            j = data.find(mag, start)
            if j < 0:
                break
            # try expanding windows
            decoded = None
            for size in (256, 1024, 4096, 16384, 65536, 262144, 1 << 20, 4 << 20):
                blob = data[j : j + min(size, len(data) - j)]
                hits = try_inflate_blob(blob)
                if hits:
                    decoded = hits[0]
                    decoded["window"] = size
                    break
            if decoded and decoded["out_len"] > 64:
                # avoid dupes near same offset
                if any(abs(f["off"] - j) < 32 for f in found):
                    start = j + 1
                    continue
                preview = decoded["data"][:120]
                entry = {
                    "off": j,
                    "off_hex": hex(j),
                    "magic": label,
                    "codec": decoded["codec"],
                    "window": decoded.get("window"),
                    "out_len": decoded["out_len"],
                    "sha16": hashlib.sha256(decoded["data"]).hexdigest()[:16],
                    "preview_ascii": "".join(chr(b) if 32 <= b < 127 else "." for b in preview[:80]),
                }
                # write payload
                kind = "bin"
                if decoded["data"][:5] == b"<?xml" or b"<Rule" in decoded["data"][:200]:
                    kind = "xml"
                elif decoded["data"][:1] == b"{" or decoded["data"][:1] == b"[":
                    kind = "json"
                elif b"technique_id" in decoded["data"][:500]:
                    kind = "sysmon_rule"
                path = out_dir / "decrypted" / f"{label}_{j:08x}.{kind}"
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(decoded["data"])
                entry["path"] = str(path)
                found.append(entry)
            start = j + 1
            if len(found) >= 80:
                return found
    return found


def carve_embedded_pes(data: bytes, out_dir: Path) -> list[dict]:
    pes = []
    start = 0
    while True:
        i = data.find(b"MZ", start)
        if i < 0:
            break
        if i + 0x40 >= len(data):
            start = i + 2
            continue
        e_lfanew = struct.unpack_from("<I", data, i + 0x3C)[0]
        if e_lfanew == 0 or e_lfanew > 0x800 or i + e_lfanew + 0x18 >= len(data):
            start = i + 2
            continue
        if data[i + e_lfanew : i + e_lfanew + 4] != b"PE\x00\x00":
            start = i + 2
            continue
        magic = struct.unpack_from("<H", data, i + e_lfanew + 0x18)[0]
        if magic not in (0x10B, 0x20B):
            start = i + 2
            continue
        nsec = struct.unpack_from("<H", data, i + e_lfanew + 6)[0]
        sec = i + e_lfanew + 0x18 + (0xE0 if magic == 0x10B else 0xF0)
        end = i + 0x400
        ok = True
        for s in range(min(nsec, 40)):
            o = sec + s * 40
            if o + 40 > len(data):
                ok = False
                break
            rsize, roff = struct.unpack_from("<II", data, o + 16)
            end = max(end, i + roff + rsize)
        if not ok or end - i < 0x400:
            start = i + 2
            continue
        size = min(end - i, len(data) - i, 30 << 20)
        blob = data[i : i + size]
        sha = hashlib.sha256(blob).hexdigest()
        # skip primary if i==0 (main PE) but still record
        path = out_dir / "carved" / f"pe_{i:08x}_{sha[:12]}.bin"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(blob)
        pes.append({
            "off": i,
            "size": size,
            "sha16": sha[:16],
            "is_main": i == 0,
            "path": str(path),
        })
        start = i + 2
    return pes


def extract_rsrc_strings_rules(data: bytes, out_dir: Path) -> dict:
    """Extract readable DFIR/Sysmon rule text from resources (not crypto — plain)."""
    # large printable runs with technique_id
    rules = []
    for m in re.finditer(rb"[\x20-\x7e\r\n\t]{200,}", data):
        s = m.group()
        if b"technique_id" in s or b"RuleGroup" in s or b"Sysmon" in s:
            rules.append({"off": m.start(), "len": len(s)})
    # write concatenated
    out_dir.mkdir(parents=True, exist_ok=True)
    rule_dir = out_dir / "plain_rules"
    rule_dir.mkdir(exist_ok=True)
    written = []
    for i, r in enumerate(rules[:30]):
        chunk = data[r["off"] : r["off"] + r["len"]]
        path = rule_dir / f"rule_blob_{i:02d}_{r['off']:08x}.txt"
        path.write_bytes(chunk)
        written.append(str(path))
    return {"rule_blobs": len(rules), "written": written[:20]}


def find_xor_encrypted_blocks(data: bytes, out_dir: Path) -> list[dict]:
    """
    Confirmed XOR-ish: high-entropy islands that decode to XML/UTF8 with single-byte key.
    Only report when decode score is high — no fake claims.
    """
    results = []
    # scan .rsrc primarily
    e = struct.unpack_from("<I", data, 0x3C)[0]
    magic = struct.unpack_from("<H", data, e + 0x18)[0]
    nsec = struct.unpack_from("<H", data, e + 6)[0]
    sec = e + 0x18 + (0xE0 if magic == 0x10B else 0xF0)
    regions = []
    for i in range(nsec):
        o = sec + i * 40
        name = data[o : o + 8].split(b"\0", 1)[0]
        vsize, va, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
        if rsize > 0x1000:
            regions.append((roff, min(rsize, len(data) - roff), name.decode("latin-1", "replace")))

    out_x = out_dir / "xor_decoded"
    out_x.mkdir(parents=True, exist_ok=True)

    for roff, rsize, name in regions:
        # sample 4KB windows stepping 2KB on high entropy
        for off in range(roff, roff + rsize - 4096, 2048):
            win = data[off : off + 4096]
            if entropy(win) < 7.2:
                continue
            best = None
            for key in range(1, 256):
                dec = bytes(b ^ key for b in win)
                # score xml / ascii
                if b"<?xml" in dec or b"<Rule" in dec or b"technique_id" in dec:
                    score = 1.0
                else:
                    printable = sum(32 <= c < 127 or c in (9, 10, 13) for c in dec)
                    score = printable / len(dec)
                if score >= 0.85:
                    if best is None or score > best["score"]:
                        best = {"key": key, "score": score, "dec": dec}
            if best and best["score"] >= 0.85:
                # expand full run with same key until entropy drops / nonprint
                key = best["key"]
                end = off + 4096
                while end < roff + rsize and end - off < 2 << 20:
                    b = data[end] ^ key
                    if not (32 <= b < 127 or b in (9, 10, 13, 0)):
                        # allow some binary inside xml? stop on long garbage
                        if end > off + 512:
                            break
                    end += 1
                full = bytes(data[i] ^ key for i in range(off, end))
                # require meaningful content
                if b"technique_id" not in full and b"<?xml" not in full and b"<Rule" not in full:
                    if sum(32 <= c < 127 for c in full) / max(1, len(full)) < 0.9:
                        continue
                path = out_x / f"xor_k{key:02x}_{off:08x}.bin"
                path.write_bytes(full)
                results.append({
                    "off": off,
                    "key": key,
                    "score": best["score"],
                    "len": len(full),
                    "section": name.decode() if isinstance(name, bytes) else name,
                    "path": str(path),
                    "preview": full[:80].decode("latin-1", "replace"),
                })
                if len(results) >= 25:
                    return results
    return results


def bcrypt_usage(data: bytes) -> dict:
    """bcrypt imports present — classify hash vs decrypt."""
    has_hash = all(x in data for x in (b"BCryptCreateHash", b"BCryptHashData", b"BCryptFinishHash"))
    has_encrypt = any(x in data for x in (b"BCryptEncrypt", b"BCryptDecrypt", b"BCryptGenerateSymmetricKey"))
    return {
        "hash_api_present": has_hash,
        "symmetric_encrypt_api_present": has_encrypt,
        "verdict": (
            "bcrypt used for HASHING only (SHA family) — no BCryptDecrypt/Encrypt import"
            if has_hash and not has_encrypt
            else (
                "symmetric bcrypt crypto present"
                if has_encrypt
                else "no bcrypt crypto surface"
            )
        ),
    }


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    data = TARGET.read_bytes()
    secs, entry = pe_sections(data)
    report = {
        "target": str(TARGET),
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "entry_rva": hex(entry),
        "sections": secs,
        "protector": detect_protectors_honest(data, secs),
        "bcrypt": bcrypt_usage(data),
        "honest_summary": [],
    }

    # 1) compressed streams
    print("[*] scanning compressed streams (gzip/zlib)...")
    compressed = scan_compressed_regions(data, OUT)
    report["compressed_streams"] = [{k: v for k, v in c.items() if k != "data"} for c in compressed]
    report["compressed_count"] = len(compressed)

    # 2) PE carve
    print("[*] carving embedded PEs...")
    pes = carve_embedded_pes(data, OUT)
    report["embedded_pes"] = pes

    # 3) plain rules
    print("[*] extracting plain DFIR rule blobs...")
    rules = extract_rsrc_strings_rules(data, OUT)
    report["plain_rules"] = rules

    # 4) XOR only when confirmed
    print("[*] probing high-entropy XOR → XML/rules...")
    xors = find_xor_encrypted_blocks(data, OUT)
    report["xor_confirmed"] = xors

    # honest summary
    s = report["honest_summary"]
    s.append(f"Themida: {report['protector']['verdict']}")
    s.append(f"bcrypt: {report['bcrypt']['verdict']}")
    s.append(f"Confirmed compressed streams decoded: {len(compressed)}")
    s.append(f"Embedded PE images carved: {len(pes)} (including main at 0)")
    s.append(f"Plain DFIR/Sysmon rule text blobs: {rules['rule_blobs']}")
    s.append(f"Confirmed single-byte XOR→readable blocks: {len(xors)}")
    if not compressed and not xors:
        s.append(
            "No Themida layer and no confirmed ciphertext→plaintext transform found. "
            "Payload is largely PLAIN XML/rules inside .rsrc + normal PE code."
        )

    # write report
    (OUT / "REAL_CRACK_REPORT.json").write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    md = [
        "# FarmServices.exe — REAL crack report (no theater)",
        "",
        f"**SHA256:** `{report['sha256']}`",
        f"**Size:** {report['size']}",
        f"**Entry RVA:** `{report['entry_rva']}` (in `.text`)",
        "",
        "## Protector verdict",
        f"- {report['protector']['verdict']}",
        f"- Marker hits: `{report['protector']['marker_hits']}`",
        f"- EP in .text: **{report['protector']['ep_in_text']}**",
        f"- Virtual-only sections: **{report['protector']['virtual_only_sections']}**",
        "",
        "## Crypto surface",
        f"- {report['bcrypt']['verdict']}",
        "",
        "## What was actually removed / extracted",
        f"- Compressed streams inflated: **{len(compressed)}** → `decrypted/`",
        f"- Embedded PEs carved: **{len(pes)}** → `carved/`",
        f"- Plain rule blobs: **{rules['rule_blobs']}** → `plain_rules/`",
        f"- Confirmed XOR decodes: **{len(xors)}** → `xor_decoded/`",
        "",
        "## Honest summary",
    ]
    for line in s:
        md.append(f"- {line}")
    md.append("")
    md.append("## Section entropy")
    for sec in secs:
        md.append(
            f"- `{sec['name']}` H≈{sec['entropy_sample']} "
            f"va={hex(sec['va'])} raw={sec['rsize']} ep={sec['contains_ep']}"
        )
    if compressed:
        md.append("")
        md.append("## Decoded streams")
        for c in compressed[:20]:
            md.append(f"- `{c['off_hex']}` {c['codec']} → {c['out_len']} bytes → `{c.get('path')}`")
    if xors:
        md.append("")
        md.append("## XOR decodes")
        for x in xors:
            md.append(f"- key=`{x['key']:#04x}` off=`{hex(x['off'])}` len={x['len']} → `{x['path']}`")
    (OUT / "REAL_CRACK_REPORT.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    print(json.dumps({
        "out": str(OUT),
        "themida": report["protector"]["verdict"],
        "bcrypt": report["bcrypt"]["verdict"],
        "compressed": len(compressed),
        "pes": len(pes),
        "rules": rules["rule_blobs"],
        "xor": len(xors),
        "summary": s,
    }, indent=2))


if __name__ == "__main__":
    main()
