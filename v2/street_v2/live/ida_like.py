# language: Python 3.11+, file: live/ida_like.py
# Capstone recursive-descent: functions, xrefs, listing — IDA-shaped views
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from street_v2.pe.loader import PeImage


@dataclass
class Insn:
    addr: int
    size: int
    bytes_hex: str
    mnemonic: str
    op_str: str
    is_call: bool = False
    is_jmp: bool = False
    is_jcc: bool = False
    is_ret: bool = False
    is_xor: bool = False
    is_crypto: bool = False
    xor_imm: int | None = None
    data_target: int | None = None
    target: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d = {
            "addr": hex(self.addr),
            "size": self.size,
            "bytes": self.bytes_hex,
            "mnem": self.mnemonic,
            "op": self.op_str,
        }
        if self.target is not None:
            d["target"] = hex(self.target)
        if self.data_target is not None:
            d["data"] = hex(self.data_target)
        if self.xor_imm is not None:
            d["xor_imm"] = hex(self.xor_imm)
        flags = []
        if self.is_call:
            flags.append("call")
        if self.is_jmp:
            flags.append("jmp")
        if self.is_jcc:
            flags.append("jcc")
        if self.is_ret:
            flags.append("ret")
        if self.is_xor:
            flags.append("xor")
        if self.is_crypto:
            flags.append("crypto")
        if flags:
            d["flags"] = flags
        return d


@dataclass
class IdaView:
    arch: str
    base: int
    instructions: list[Insn] = field(default_factory=list)
    functions: list[dict[str, Any]] = field(default_factory=list)
    xrefs: list[dict[str, Any]] = field(default_factory=list)
    cfg_edges: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    xref_report: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "arch": self.arch,
            "base": hex(self.base),
            "insn_count": len(self.instructions),
            "instructions": [i.to_dict() for i in self.instructions],
            "functions": self.functions,
            "xrefs": self.xrefs[:3000],
            "xref_report": self.xref_report,
            "cfg_edges": self.cfg_edges[:4000],
            "errors": self.errors,
        }

    def listing_slice(self, start_va: int = 0, count: int = 200) -> dict[str, Any]:
        idx = 0
        if start_va:
            for i, insn in enumerate(self.instructions):
                if insn.addr >= start_va:
                    idx = i
                    break
        chunk = self.instructions[idx : idx + count]
        return {
            "index": idx,
            "total": len(self.instructions),
            "instructions": [i.to_dict() for i in chunk],
        }


def _cs(is_64: bool):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

    md = Cs(CS_ARCH_X86, CS_MODE_64 if is_64 else CS_MODE_32)
    md.detail = True
    return md


_CRYPTO = {
    "aesenc", "aesenclast", "aesdec", "aesdeclast", "aeskeygenassist", "aesimc",
    "pxor", "xorps", "xorpd", "pclmulqdq", "crc32", "sha256rnds2", "sha1rnds4",
}


def _classify(insn) -> Insn:
    from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET
    from capstone.x86 import X86_OP_IMM, X86_OP_MEM

    groups = set(insn.groups) if hasattr(insn, "groups") else set()
    is_call = CS_GRP_CALL in groups or insn.mnemonic.startswith("call")
    is_jmp = insn.mnemonic in ("jmp", "ljmp")
    is_jcc = insn.mnemonic.startswith("j") and not is_jmp and not insn.mnemonic.startswith("jmp")
    is_ret = CS_GRP_RET in groups or insn.mnemonic.startswith("ret")
    mnem = insn.mnemonic
    is_xor = mnem in ("xor", "xorps", "xorpd", "pxor")
    is_crypto = mnem in _CRYPTO
    target = None
    xor_imm = None
    data_target = None
    try:
        if hasattr(insn, "operands"):
            for op in insn.operands:
                if op.type == X86_OP_IMM:
                    if is_call or is_jmp or is_jcc:
                        target = int(op.imm)
                    elif is_xor:
                        xor_imm = int(op.imm) & 0xFFFFFFFFFFFFFFFF
                    elif mnem in ("lea", "mov", "push") and not (is_call or is_jmp):
                        # absolute imm that may be a VA
                        data_target = int(op.imm)
                elif op.type == X86_OP_MEM:
                    disp = int(op.mem.disp)
                    # RIP-relative: next insn + disp
                    if insn.reg_name(op.mem.base) in ("rip", "eip"):
                        data_target = insn.address + insn.size + disp
                    elif disp and not op.mem.base and not op.mem.index:
                        data_target = disp
    except Exception:
        import re

        m = re.search(r"0x[0-9a-fA-F]+", insn.op_str or "")
        if m and (is_call or is_jmp or is_jcc):
            target = int(m.group(0), 16)
    return Insn(
        addr=insn.address,
        size=insn.size,
        bytes_hex=insn.bytes.hex(),
        mnemonic=mnem,
        op_str=insn.op_str or "",
        is_call=is_call,
        is_jmp=is_jmp,
        is_jcc=is_jcc,
        is_ret=is_ret,
        is_xor=is_xor,
        is_crypto=is_crypto,
        xor_imm=xor_imm,
        data_target=data_target,
        target=target,
    )


def build_ida_view(
    pe: PeImage,
    recursive: bool = True,
    max_insns: int = 80000,
    seed_rva: int | None = None,
) -> IdaView:
    md = _cs(pe.is_64)
    view = IdaView(arch=pe.arch, base=pe.image_base)
    text, text_va = pe.text_blob()
    if not text:
        # fall back: map all executable sections
        chunks: list[tuple[bytes, int]] = []
        for s in pe.sections:
            if s.executable and s.rawsize:
                chunks.append((s.data or pe.data[s.raw : s.raw + s.rawsize], pe.image_base + s.va))
        if not chunks:
            view.errors.append("no_executable_bytes")
            return view
        text, text_va = chunks[0]

    text_end = text_va + len(text)
    seeds: list[int] = []
    if seed_rva is not None:
        seeds.append(pe.image_base + seed_rva)
    seeds.append(pe.image_base + pe.entry_rva)
    for exp in pe.exports[:50]:
        if exp.get("rva"):
            seeds.append(pe.image_base + int(exp["rva"], 16))

    seen_addr: set[int] = set()
    by_addr: dict[int, Insn] = {}
    queue: list[int] = []
    for s in seeds:
        if text_va <= s < text_end:
            queue.append(s)

    def enqueue(a: int) -> None:
        if text_va <= a < text_end and a not in seen_addr:
            queue.append(a)

    if not recursive:
        # linear sweep
        offset = 0
        while offset < len(text) and len(by_addr) < max_insns:
            va = text_va + offset
            for insn in md.disasm(text[offset : offset + 16], va):
                row = _classify(insn)
                by_addr[row.addr] = row
                offset += row.size
                break
            else:
                offset += 1
    else:
        while queue and len(by_addr) < max_insns:
            va = queue.pop()
            if va in seen_addr:
                continue
            seen_addr.add(va)
            off = va - text_va
            if off < 0 or off >= len(text):
                continue
            decoded = False
            for insn in md.disasm(text[off : off + 16], va):
                row = _classify(insn)
                by_addr[row.addr] = row
                decoded = True
                if row.is_ret:
                    break
                if row.is_jmp and row.target is not None:
                    enqueue(row.target)
                    break
                if row.is_jcc and row.target is not None:
                    enqueue(row.target)
                    enqueue(row.addr + row.size)
                    break
                if row.is_call and row.target is not None:
                    enqueue(row.target)
                    enqueue(row.addr + row.size)
                    break
                enqueue(row.addr + row.size)
                break
            if not decoded:
                # skip one byte on invalid
                enqueue(va + 1)

    view.instructions = [by_addr[a] for a in sorted(by_addr)]
    # functions: entry + call targets
    func_starts = {pe.image_base + pe.entry_rva}
    xrefs: list[dict[str, Any]] = []
    edges: list[dict[str, Any]] = []
    for insn in view.instructions:
        if insn.is_call and insn.target is not None:
            func_starts.add(insn.target)
            xrefs.append({"from": hex(insn.addr), "to": hex(insn.target), "type": "call"})
            edges.append({"from": hex(insn.addr), "to": hex(insn.target), "type": "call"})
        if (insn.is_jmp or insn.is_jcc) and insn.target is not None:
            xrefs.append({
                "from": hex(insn.addr),
                "to": hex(insn.target),
                "type": "jmp" if insn.is_jmp else "jcc",
            })
            edges.append({
                "from": hex(insn.addr),
                "to": hex(insn.target),
                "type": "jmp" if insn.is_jmp else "jcc",
            })
            if not insn.is_jmp:
                edges.append({"from": hex(insn.addr), "to": hex(insn.addr + insn.size), "type": "fallthrough"})

    funcs = []
    for start in sorted(func_starts):
        if start not in by_addr and not (text_va <= start < text_end):
            continue
        end = start
        for insn in view.instructions:
            if insn.addr < start:
                continue
            if insn.addr > end + 0x1000 and insn.addr != start:
                break
            end = insn.addr + insn.size
            if insn.is_ret and insn.addr >= start:
                break
        funcs.append({
            "start": hex(start),
            "end": hex(end),
            "name": f"sub_{start:X}",
            "is_entry": start == pe.image_base + pe.entry_rva,
        })
    view.functions = funcs[:2000]
    view.xrefs = xrefs
    view.cfg_edges = edges
    from street_v2.live.xrefs import enrich_xrefs

    enrich_xrefs(pe, view)
    return view
