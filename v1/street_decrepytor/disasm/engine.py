# language: Python 3, file: disasm/engine.py
# Capstone disassembler — linear + recursive descent, CFG, xrefs, function guess
from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any


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
    target: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["addr"] = hex(self.addr)
        if self.target is not None:
            d["target"] = hex(self.target)
        return d


@dataclass
class DisasmResult:
    arch: str
    mode: str
    base: int
    instructions: list[Insn] = field(default_factory=list)
    functions: list[dict[str, Any]] = field(default_factory=list)
    xrefs: list[dict[str, Any]] = field(default_factory=list)
    cfg_edges: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "arch": self.arch,
            "mode": self.mode,
            "base": hex(self.base),
            "insn_count": len(self.instructions),
            "instructions": [i.to_dict() for i in self.instructions],
            "functions": self.functions,
            "xrefs": self.xrefs[:500],
            "cfg_edges": self.cfg_edges[:2000],
            "errors": self.errors,
        }

    def to_listing(self, max_insns: int | None = None) -> str:
        lines = []
        n = 0
        for i in self.instructions:
            lines.append(f"{i.addr:016x}  {i.bytes_hex:<24}  {i.mnemonic:<8} {i.op_str}")
            n += 1
            if max_insns and n >= max_insns:
                lines.append(f"; ... truncated at {max_insns}")
                break
        return "\n".join(lines)


def _cs(arch: str = "x86", mode: str = "64"):
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32, CS_MODE_ARM, CS_ARCH_ARM64, CS_ARCH_ARM

    if arch == "x86" and mode == "64":
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    elif arch == "x86" and mode == "32":
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    elif arch == "arm64":
        md = Cs(CS_ARCH_ARM64, 0)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    return md


def _classify(md, insn) -> Insn:
    from capstone import CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET, CS_GRP_BRANCH_RELATIVE
    from capstone.x86 import X86_OP_IMM

    groups = set(insn.groups) if hasattr(insn, "groups") else set()
    is_call = CS_GRP_CALL in groups or insn.mnemonic.startswith("call")
    is_jmp = insn.mnemonic in ("jmp", "ljmp")
    is_jcc = insn.mnemonic.startswith("j") and not is_jmp and not insn.mnemonic.startswith("jmp")
    is_ret = CS_GRP_RET in groups or insn.mnemonic.startswith("ret")
    target = None
    try:
        if hasattr(insn, "operands"):
            for op in insn.operands:
                if op.type == X86_OP_IMM and (is_call or is_jmp or is_jcc):
                    target = int(op.imm)
                    break
    except Exception:
        # parse from op_str as fallback: 0x140001000
        import re

        m = re.search(r"0x[0-9a-fA-F]+", insn.op_str or "")
        if m and (is_call or is_jmp or is_jcc):
            target = int(m.group(0), 16)
    return Insn(
        addr=insn.address,
        size=insn.size,
        bytes_hex=insn.bytes.hex(),
        mnemonic=insn.mnemonic,
        op_str=insn.op_str or "",
        is_call=is_call,
        is_jmp=is_jmp,
        is_jcc=is_jcc,
        is_ret=is_ret,
        target=target,
    )


def disassemble_blob(
    code: bytes,
    base: int = 0,
    *,
    arch: str = "x86",
    mode: str = "64",
    recursive: bool = True,
    max_insns: int = 200_000,
) -> DisasmResult:
    """Disassemble a code blob. recursive=True follows call/jmp/jcc targets inside range."""
    result = DisasmResult(arch=arch, mode=mode, base=base)
    try:
        md = _cs(arch, mode)
    except Exception as e:
        result.errors.append(f"capstone: {e}")
        return result

    end = base + len(code)
    if not recursive:
        # Skip-byte linear sweep — Capstone stops on invalid; advance 1 and continue
        # (required for Themida-class ciphertext that isn't clean code yet)
        off = 0
        while off < len(code) and len(result.instructions) < max_insns:
            chunk = code[off:]
            got = False
            for insn in md.disasm(chunk, base + off, count=1):
                result.instructions.append(_classify(md, insn))
                off += insn.size
                got = True
                break
            if not got:
                # db XX placeholder
                b = code[off]
                result.instructions.append(
                    Insn(
                        addr=base + off,
                        size=1,
                        bytes_hex=f"{b:02x}",
                        mnemonic="db",
                        op_str=f"0x{b:02x}",
                    )
                )
                off += 1
    else:
        # recursive descent worklist
        visited: set[int] = set()
        queue: list[int] = [base]
        insn_map: dict[int, Insn] = {}
        while queue and len(insn_map) < max_insns:
            addr = queue.pop()
            if addr in visited or addr < base or addr >= end:
                continue
            visited.add(addr)
            off = addr - base
            # disassemble linearly until ret/jmp/undef
            for insn in md.disasm(code[off:], addr):
                if insn.address in insn_map:
                    break
                row = _classify(md, insn)
                insn_map[insn.address] = row
                # fallthrough
                fall = insn.address + insn.size
                if row.is_jmp and row.target is not None:
                    if base <= row.target < end:
                        queue.append(row.target)
                    break  # no fallthrough for uncond jmp
                if row.is_ret:
                    break
                if row.is_call and row.target is not None and base <= row.target < end:
                    queue.append(row.target)
                    # fallthrough after call
                    if fall < end:
                        queue.append(fall)
                    break
                if row.is_jcc and row.target is not None:
                    if base <= row.target < end:
                        queue.append(row.target)
                    if fall < end:
                        queue.append(fall)
                    break
                if fall >= end:
                    break
                # continue linear
                if len(insn_map) >= max_insns:
                    break
        result.instructions = [insn_map[a] for a in sorted(insn_map)]

    # CFG edges + xrefs
    for i in result.instructions:
        if i.is_call and i.target is not None:
            result.xrefs.append({"from": hex(i.addr), "to": hex(i.target), "type": "call"})
            result.cfg_edges.append({"from": hex(i.addr), "to": hex(i.target), "type": "call"})
        if (i.is_jmp or i.is_jcc) and i.target is not None:
            result.xrefs.append({
                "from": hex(i.addr),
                "to": hex(i.target),
                "type": "jmp" if i.is_jmp else "jcc",
            })
            result.cfg_edges.append({
                "from": hex(i.addr),
                "to": hex(i.target),
                "type": "jmp" if i.is_jmp else "jcc",
            })
        if not i.is_jmp and not i.is_ret:
            nxt = i.addr + i.size
            if any(x.addr == nxt for x in result.instructions[:1]) or True:
                # fallthrough edge if next insn exists
                pass

    # function starts: base + call targets + prologue heuristics
    starts = {base}
    for x in result.xrefs:
        if x["type"] == "call":
            starts.add(int(x["to"], 16))
    # prologue: 48 89 5c 24 / 40 53 / 55
    for i, insn in enumerate(result.instructions):
        off = insn.addr - base
        if 0 <= off < len(code) - 4:
            b = code[off : off + 4]
            if b[:4] == b"\x48\x89\x5c\x24" or b[:2] in (b"\x40\x53", b"\x55\x48"):
                starts.add(insn.addr)

    sorted_starts = sorted(a for a in starts if base <= a < end)
    for idx, s in enumerate(sorted_starts):
        e = sorted_starts[idx + 1] if idx + 1 < len(sorted_starts) else end
        # trim to last ret in range if any
        size = e - s
        result.functions.append({
            "start": hex(s),
            "end": hex(e),
            "size": size,
            "name": f"sub_{s:X}",
        })

    return result


def _pe_text(data: bytes) -> tuple[bytes, int, str, str]:
    """Return (.text bytes, VA base including image base, arch, mode)."""
    if data[:2] != b"MZ":
        raise ValueError("not PE")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    machine = struct.unpack_from("<H", data, e_lfanew + 4)[0]
    magic = struct.unpack_from("<H", data, e_lfanew + 0x18)[0]
    if magic == 0x10B:
        image_base = struct.unpack_from("<I", data, e_lfanew + 0x18 + 28)[0]
        sec = e_lfanew + 0x18 + 0xE0
        mode = "32"
    else:
        image_base = struct.unpack_from("<Q", data, e_lfanew + 0x18 + 24)[0]
        sec = e_lfanew + 0x18 + 0xF0
        mode = "64"
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    entry = struct.unpack_from("<I", data, e_lfanew + 0x28)[0]
    # Collect sections; for packed (Themida-class) .text often has rsize=0 —
    # prefer section that CONTAINS EP and has raw bytes on disk.
    sections = []
    for i in range(nsec):
        o = sec + i * 40
        name = data[o : o + 8].split(b"\0", 1)[0]
        vsize, va, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
        sections.append((name, va, vsize, rsize, roff))

    text_va = text_roff = text_size = None
    # 1) EP section with raw > 0x200
    for name, va, vsize, rsize, roff in sections:
        if va <= entry < va + max(vsize, 1) and rsize > 0x200:
            text_va, text_roff, text_size = va, roff, rsize
            break
    # 2) .text with raw
    if text_va is None:
        for name, va, vsize, rsize, roff in sections:
            if name == b".text" and rsize > 0x200:
                text_va, text_roff, text_size = va, roff, rsize
                break
    # 3) largest raw executable-looking section
    if text_va is None:
        best = None
        for name, va, vsize, rsize, roff in sections:
            if rsize > 0x1000 and (best is None or rsize > best[3]):
                best = (name, va, vsize, rsize, roff)
        if best:
            _, text_va, _, text_size, text_roff = best
    if text_va is None:
        raise ValueError("no disasmable section with raw data")
    # Cap huge packed sections for default pass (UI can request RVA windows)
    take = min(text_size, 4 << 20)
    blob = data[text_roff : text_roff + take]

    arch = "x86"
    if machine == 0xAA64:
        arch = "arm64"
        mode = "64"
    return blob, image_base + text_va, arch, mode


def disassemble_pe(
    path: str | Path,
    *,
    recursive: bool = True,
    max_insns: int = 100_000,
    rva: int | None = None,
    size: int | None = None,
) -> DisasmResult:
    path = Path(path)
    data = path.read_bytes()
    blob, base, arch, mode = _pe_text(data)
    if rva is not None:
        # re-map: user RVA → file
        e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        magic = struct.unpack_from("<H", data, e_lfanew + 0x18)[0]
        image_base = (
            struct.unpack_from("<I", data, e_lfanew + 0x18 + 28)[0]
            if magic == 0x10B
            else struct.unpack_from("<Q", data, e_lfanew + 0x18 + 24)[0]
        )
        # find section containing rva
        nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
        sec = e_lfanew + 0x18 + (0xE0 if magic == 0x10B else 0xF0)
        for i in range(nsec):
            o = sec + i * 40
            vsize, va, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
            if va <= rva < va + max(vsize, rsize, 1):
                off = roff + (rva - va)
                sz = size or min(0x4000, rsize - (rva - va))
                blob = data[off : off + sz]
                base = image_base + rva
                break
    result = disassemble_blob(blob, base, arch=arch, mode=mode, recursive=recursive, max_insns=max_insns)
    # Packed/encrypted entry stubs often defeat recursive descent (few real edges).
    # Fall back to linear sweep so StreetDbg still shows a full listing.
    if recursive and len(result.instructions) < 64 and len(blob) > 0x1000:
        linear = disassemble_blob(
            blob[: min(len(blob), 0x20000)],
            base,
            arch=arch,
            mode=mode,
            recursive=False,
            max_insns=max_insns,
        )
        linear.errors.append(
            "recursive yielded sparse listing — linear sweep used (typical Themida-class ciphertext)"
        )
        return linear
    return result
