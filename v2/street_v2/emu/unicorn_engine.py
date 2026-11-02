# language: Python 3.11+, file: emu/unicorn_engine.py
# Unicorn-backed x86/x64 emulator — trace crypto-ish ops, capture mem writes
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from street_v2.pe.loader import PeImage

PAGE = 0x1000
STACK_BASE = 0x00007FFF00000000
STACK_SIZE = 0x100000


def _align_down(x: int, a: int = PAGE) -> int:
    return x & ~(a - 1)


def _align_up(x: int, a: int = PAGE) -> int:
    return (x + a - 1) & ~(a - 1)


@dataclass
class EmuResult:
    ok: bool
    arch: str
    start: int
    end: int
    insn_count: int = 0
    stops_reason: str = ""
    xor_events: list[dict[str, Any]] = field(default_factory=list)
    aes_events: list[dict[str, Any]] = field(default_factory=list)
    mem_writes: list[dict[str, Any]] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)
    printable_recoveries: list[dict[str, Any]] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    regs: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "arch": self.arch,
            "start": hex(self.start),
            "end": hex(self.end),
            "insn_count": self.insn_count,
            "stops_reason": self.stops_reason,
            "xor_events": self.xor_events[:200],
            "aes_events": self.aes_events[:100],
            "mem_writes": self.mem_writes[:200],
            "calls": self.calls[:100],
            "printable_recoveries": self.printable_recoveries[:50],
            "regs": self.regs,
            "errors": self.errors,
            "image_transforms": [],
            "decrypted": False,
        }


def _map_image(uc, pe: PeImage) -> None:
    # Map each section at ImageBase+VA with RWX for analysis (lab emu, not production sandbox)
    bases: dict[int, int] = {}
    for s in pe.sections:
        if s.rawsize == 0 and s.vsize == 0:
            continue
        va = pe.image_base + s.va
        size = max(s.vsize, s.rawsize, PAGE)
        start = _align_down(va)
        end = _align_up(va + size)
        for page in range(start, end, PAGE):
            if page not in bases:
                try:
                    uc.mem_map(page, PAGE)
                    bases[page] = 1
                except Exception:
                    pass
        blob = s.data if s.data else pe.data[s.raw : s.raw + s.rawsize]
        if blob:
            try:
                uc.mem_write(va, blob)
            except Exception:
                # partial write if vsize > raw
                try:
                    uc.mem_write(va, blob[: min(len(blob), size)])
                except Exception as e:
                    raise RuntimeError(f"map section {s.name}: {e}") from e

    # stack
    for page in range(STACK_BASE, STACK_BASE + STACK_SIZE, PAGE):
        try:
            uc.mem_map(page, PAGE)
        except Exception:
            pass


def emulate_range(
    pe: PeImage,
    start_va: int,
    max_insns: int = 50000,
    stop_vas: list[int] | None = None,
) -> EmuResult:
    try:
        from unicorn import Uc, UC_ARCH_X86, UC_MODE_64, UC_MODE_32, UcError
        from unicorn import UC_HOOK_CODE, UC_HOOK_MEM_WRITE
        from unicorn.x86_const import (
            UC_X86_REG_RSP,
            UC_X86_REG_RIP,
            UC_X86_REG_EIP,
            UC_X86_REG_RAX,
            UC_X86_REG_RBX,
            UC_X86_REG_RCX,
            UC_X86_REG_RDX,
            UC_X86_REG_RSI,
            UC_X86_REG_RDI,
            UC_X86_REG_R8,
            UC_X86_REG_R9,
        )
    except ImportError as e:
        return EmuResult(
            ok=False,
            arch=pe.arch,
            start=start_va,
            end=start_va,
            stops_reason="unicorn_missing",
            errors=[str(e)],
        )

    mode = UC_MODE_64 if pe.is_64 else UC_MODE_32
    uc = Uc(UC_ARCH_X86, mode)
    result = EmuResult(ok=False, arch=pe.arch, start=start_va, end=start_va)
    stop_set = set(stop_vas or [])

    try:
        _map_image(uc, pe)
    except Exception as e:
        result.errors.append(f"map: {e}")
        return result

    sp = STACK_BASE + STACK_SIZE - 0x1000
    uc.reg_write(UC_X86_REG_RSP, sp)

    # Capstone for mnemonic classify inside hook (Unicorn gives address+size only)
    from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CS_MODE_32

    md = Cs(CS_ARCH_X86, CS_MODE_64 if pe.is_64 else CS_MODE_32)
    md.detail = True

    def on_code(mu, address, size, user_data):
        result.insn_count += 1
        if result.insn_count > max_insns:
            mu.emu_stop()
            result.stops_reason = "max_insns"
            return
        if address in stop_set:
            mu.emu_stop()
            result.stops_reason = f"stop_va:{address:#x}"
            return
        try:
            code = bytes(mu.mem_read(address, size))
        except Exception:
            return
        for insn in md.disasm(code, address):
            mnem = insn.mnemonic
            if mnem in ("xor", "pxor", "xorps", "xorpd"):
                result.xor_events.append({
                    "va": hex(address),
                    "mnem": mnem,
                    "op": insn.op_str,
                })
            if mnem.startswith("aes"):
                result.aes_events.append({
                    "va": hex(address),
                    "mnem": mnem,
                    "op": insn.op_str,
                })
            if mnem == "call":
                result.calls.append({"va": hex(address), "op": insn.op_str})
            break

    def on_write(mu, access, address, size, value, user_data):
        if size <= 8:
            result.mem_writes.append({
                "va": hex(address),
                "size": size,
                "value": hex(value & ((1 << (size * 8)) - 1)),
            })
            return
        # larger block — sample
        try:
            blob = bytes(mu.mem_read(address, min(size, 64)))
            printable = sum(1 for b in blob if 32 <= b < 127)
            if printable >= 8 and printable / max(1, len(blob)) >= 0.75:
                result.printable_recoveries.append({
                    "va": hex(address),
                    "preview": blob[:64].decode("latin-1", "replace"),
                    "kind": "mem_write_printable",
                })
        except Exception:
            pass

    uc.hook_add(UC_HOOK_CODE, on_code)
    uc.hook_add(UC_HOOK_MEM_WRITE, on_write)

    # run until ret-ish or max — use a soft end window of 4MB from start
    end_va = start_va + 0x400000
    result.end = end_va
    try:
        uc.emu_start(start_va, end_va, count=max_insns)
        if not result.stops_reason:
            result.stops_reason = "end_or_halt"
        result.ok = True
    except UcError as e:
        result.stops_reason = f"uc_error:{e}"
        result.ok = result.insn_count > 0
        result.errors.append(str(e))
        # still useful partial trace
    except Exception as e:
        result.stops_reason = "exception"
        result.errors.append(str(e))

    try:
        if pe.is_64:
            result.regs = {
                "rax": hex(uc.reg_read(UC_X86_REG_RAX)),
                "rbx": hex(uc.reg_read(UC_X86_REG_RBX)),
                "rcx": hex(uc.reg_read(UC_X86_REG_RCX)),
                "rdx": hex(uc.reg_read(UC_X86_REG_RDX)),
                "rsi": hex(uc.reg_read(UC_X86_REG_RSI)),
                "rdi": hex(uc.reg_read(UC_X86_REG_RDI)),
                "r8": hex(uc.reg_read(UC_X86_REG_R8)),
                "r9": hex(uc.reg_read(UC_X86_REG_R9)),
                "rip": hex(uc.reg_read(UC_X86_REG_RIP)),
            }
        else:
            result.regs = {"eip": hex(uc.reg_read(UC_X86_REG_EIP))}
    except Exception:
        pass

    return result


def emulate_pe_entry(pe: PeImage, max_insns: int = 50000) -> EmuResult:
    start = pe.image_base + pe.entry_rva
    # skip if .text empty on disk — emu of packer stub still possible at EP
    text = next((s for s in pe.sections if s.name.startswith(".text")), None)
    if text and text.rawsize == 0:
        # EP may still be in another section (stub)
        pass
    return emulate_range(pe, start, max_insns=max_insns)
