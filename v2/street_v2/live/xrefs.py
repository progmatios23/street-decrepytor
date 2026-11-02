# language: Python 3.11+, file: live/xrefs.py
# IDA-style xrefs: code / data / string / xor / crypto  + key harvest from xor imm
from __future__ import annotations

import re
from typing import Any

from street_v2.live.ida_like import IdaView, Insn
from street_v2.pe.loader import PeImage

_CRYPTO_MNEM = {
    "aesenc", "aesenclast", "aesdec", "aesdeclast", "aeskeygenassist", "aesimc",
    "pxor", "xorps", "xorpd", "pclmulqdq", "crc32", "sha256rnds2", "sha1rnds4",
}
_ASCII = re.compile(rb"[\x20-\x7e]{6,}")


def _in_image(pe: PeImage, va: int) -> bool:
    rva = va - pe.image_base
    return pe.section_at_rva(rva) is not None if rva >= 0 else False


def _va_to_off(pe: PeImage, va: int) -> int | None:
    return pe.va_to_off(va)


def _string_at(pe: PeImage, va: int) -> str | None:
    off = _va_to_off(pe, va)
    if off is None:
        return None
    chunk = pe.data[off : off + 96]
    if not chunk:
        return None
    # utf16
    if len(chunk) >= 8 and chunk[1] == 0 and 32 <= chunk[0] < 127:
        try:
            s = chunk.split(b"\x00\x00", 1)[0].decode("utf-16-le", "ignore")
            if len(s) >= 4:
                return s[:80]
        except Exception:
            pass
    end = chunk.find(b"\x00")
    blob = chunk[: end if end >= 0 else 80]
    if blob and all(32 <= b < 127 for b in blob) and len(blob) >= 4:
        return blob.decode("ascii")
    return None


def enrich_xrefs(pe: PeImage, view: IdaView) -> dict[str, Any]:
    code: list[dict[str, Any]] = []
    data: list[dict[str, Any]] = []
    strings: list[dict[str, Any]] = []
    xor_x: list[dict[str, Any]] = []
    crypto: list[dict[str, Any]] = []
    xor_keys: list[bytes] = []

    for insn in view.instructions:
        if insn.is_call and insn.target is not None:
            code.append({"from": hex(insn.addr), "to": hex(insn.target), "type": "call"})
        elif insn.is_jmp and insn.target is not None:
            code.append({"from": hex(insn.addr), "to": hex(insn.target), "type": "jmp"})
        elif insn.is_jcc and insn.target is not None:
            code.append({"from": hex(insn.addr), "to": hex(insn.target), "type": "jcc"})

        if insn.data_target is not None and _in_image(pe, insn.data_target):
            rec = {
                "from": hex(insn.addr),
                "to": hex(insn.data_target),
                "type": "data",
                "mnem": insn.mnemonic,
            }
            s = _string_at(pe, insn.data_target)
            if s:
                rec["type"] = "str"
                rec["str"] = s
                strings.append(rec)
            else:
                data.append(rec)

        if insn.is_xor:
            rec = {
                "from": hex(insn.addr),
                "type": "xor",
                "mnem": insn.mnemonic,
                "op": insn.op_str,
            }
            if insn.xor_imm is not None:
                rec["imm"] = hex(insn.xor_imm)
                imm = insn.xor_imm
                if 0 < imm <= 0xFF:
                    xor_keys.append(bytes([imm]))
                elif imm <= 0xFFFFFFFF:
                    xor_keys.append(imm.to_bytes(4, "little"))
                    xor_keys.append(bytes([imm & 0xFF]))
                else:
                    xor_keys.append((imm & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little"))
            if insn.data_target is not None:
                rec["to"] = hex(insn.data_target)
            xor_x.append(rec)

        if insn.is_crypto:
            crypto.append({
                "from": hex(insn.addr),
                "type": "crypto",
                "mnem": insn.mnemonic,
                "op": insn.op_str,
            })

    # import IAT as data xrefs
    for imp in pe.imports[:200]:
        if imp.get("iat_rva"):
            try:
                va = pe.image_base + int(imp["iat_rva"], 16)
            except Exception:
                continue
            data.append({
                "from": hex(va),
                "to": hex(va),
                "type": "import",
                "name": f"{imp.get('dll')}!{imp.get('name')}",
            })

    # unique xor keys
    uniq: list[bytes] = []
    for k in xor_keys:
        if k and set(k) != {0} and k not in uniq:
            uniq.append(k)

    report = {
        "code": code[:4000],
        "data": data[:2000],
        "string": strings[:800],
        "xor": xor_x[:800],
        "crypto": crypto[:400],
        "counts": {
            "code": len(code),
            "data": len(data),
            "string": len(strings),
            "xor": len(xor_x),
            "crypto": len(crypto),
            "xor_keys": len(uniq),
        },
        "xor_keys_hex": [k.hex() for k in uniq[:80]],
    }
    # merge into view for HTTP /listing consumers
    merged = []
    merged.extend(code[:1500])
    merged.extend(data[:500])
    merged.extend(strings[:400])
    merged.extend(xor_x[:400])
    merged.extend(crypto[:200])
    view.xrefs = merged
    view.xref_report = report  # type: ignore[attr-defined]
    return report


def xor_keys_from_report(report: dict[str, Any]) -> list[bytes]:
    out: list[bytes] = []
    for hx in report.get("xor_keys_hex") or []:
        try:
            b = bytes.fromhex(hx)
        except ValueError:
            continue
        if b and b not in out:
            out.append(b)
    return out
