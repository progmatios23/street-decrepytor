# language: Python 3, file: stub_decrypt.py
# Offline-Stub-Entschluessler fuer dw-arithmetische Packer (Cs2-External-Klasse)
#
# Entdeckt am target-v2 (2026-09-06): Ein .rsrc-Stub mit ~256 individuellen
# add/sub/xor/not dword [rcx+disp32], imm32 Operationen transformiert
# Block fuer Block (0x400 B) eine Region in .rsrc (Loop bis cmp-Grenze).
# Der Stub liegt im KLARTEXT im .rsrc-Rohbereich; die Ziel-Region auf Disk
# ist verschluesselt. Dieses Model extrahiert die Ops aus dem Stub und
# wendet sie offline an — kein Prozessstart noetig.
#
# Verifiziert: target-v2 Cs2-External (a94f6513...) -> 448 KB Container,
# bestatigt durch RAM-Vergleich (Container-Header [0x0C..0x18] identisch).
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Optional

from capstone import Cs, CS_ARCH_X86, CS_MODE_64


@dataclass
class DwOp:
    """Eine dword-Transform-Operation: op [base+disp], imm"""
    op: str            # "add" | "sub" | "xor" | "not"
    disp: int          # displacement in byte (vielfaches von 4)
    imm: int           # immediate (0 fuer not)

    def apply(self, block: bytearray) -> None:
        off = self.disp
        if off < 0 or off + 4 > len(block):
            return
        v = struct.unpack_from("<I", block, off)[0]
        if self.op == "add":
            v = (v + self.imm) & 0xFFFFFFFF
        elif self.op == "sub":
            v = (v - self.imm) & 0xFFFFFFFF
        elif self.op == "xor":
            v ^= self.imm
        elif self.op == "not":
            v = (~v) & 0xFFFFFFFF
        struct.pack_into("<I", block, off, v)


@dataclass
class StubLayout:
    """Erkannte Stub-Geometrie."""
    stub_file_off: int          # file-offset des stub-anfangs
    ops: list[DwOp] = field(default_factory=list)
    key_region_file_off: int = 0   # file-offset der verschluesselten region
    block_size: int = 0x400       # blockgroesse (standard 0x400)
    total_size: int = 0           # loop-grenze (cmp-wert)
    lea_rip_displacement: int = 0 # disp32 des lea rcx,[rip+X]


def extract_dw_ops(stub_bytes: bytes, stub_rva: int) -> list[DwOp]:
    """Extrahiert die dw-Op-Sequenz aus einem Stub.

    Strategie: linearer disasm ueber den gesamten stub; jede
    add/sub/xor/not dword [rcx+disp],imm wird gesammelt. Zwischen-
    liegende instruktionen (nops, jcc-junk, alignment) werden
    uebersprungen, solange后续 weitere dw-ops kommen. Abbruch erst,
    wenn nach >= 16 gesammelten ops fuer > 64 bytes keine weitere
    dw-op mehr kommt (sequenz-ende / loop-epilog erreicht).
    """
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    ops: list[DwOp] = []
    pos = 0
    n = len(stub_bytes)
    gap = 0  # bytes seit der letzten dw-op
    while pos + 16 < n:
        code = stub_bytes[pos:pos + 16]
        ins = next(md.disasm(code, stub_rva + pos), None)
        if ins is None:
            pos += 1
            gap += 1
            continue
        parsed = _parse_dw_op(ins)
        if parsed is not None:
            ops.append(parsed)
            gap = 0
            pos += ins.size
            continue
        # non-op: tolerieren solange die sequenz noch nicht "zu ende" ist
        if ops and gap > 64:
            break  # >64 bytes ohne dw-op -> sequenz vorbei
        gap += ins.size
        pos += ins.size
    return ops


def _parse_dw_op(ins) -> Optional[DwOp]:
    """Parst add/sub/xor/not dword [rcx+disp], imm aus einer capstone-insn."""
    if ins.mnemonic in ("add", "sub", "xor") and "dword ptr [rcx" in ins.op_str:
        try:
            left, imm = ins.op_str.split(", ", 1)
            disp = _disp_from_left(left)
            return DwOp(ins.mnemonic, disp, int(imm, 0))
        except (ValueError, IndexError):
            return None
    if ins.mnemonic == "not" and "dword ptr [rcx" in ins.op_str:
        try:
            disp = _disp_from_left(ins.op_str)
            return DwOp("not", disp, 0)
        except (ValueError, IndexError):
            return None
    return None


def _disp_from_left(left: str) -> int:
    """Extrahiert den displacement aus 'dword ptr [rcx + 0xNNN]' / '[rcx + 4]' / '[rcx]'.

    Capstone gibt kleine displacements dezimal ('+ 4') und grosse
    hexadezimal ('+ 0x214') aus — int(x, 0) behandelt beides.
    """
    if left.strip().endswith("[rcx]"):
        return 0
    if "rcx + " in left:
        return int(left.split("rcx + ")[1].rstrip("]"), 0)
    if "rcx - " in left:
        return -int(left.split("rcx - ")[1].rstrip("]"), 0)
    raise ValueError("kein rcx-displacement")


def extract_stub_geometry(data: bytes, stub_file_off: int, stub_rva: int) -> StubLayout:
    """Extrahiert die komplette Stub-Geometrie (ops + loop + lea-ziel).

    Erwartete Stub-Struktur (Cs2-External-Klasse):
      push-regs prolog
      lea rcx, [rip + X]      <- ziel = verschluesselte region
      push 0 / pop rdi / push rcx
      [dw-ops sequenz]
      add rdi, 0x400 / add rcx, 0x400 / cmp rdi, LIMIT / jne loop
      ... epilog
    """
    layout = StubLayout(stub_file_off=stub_file_off)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    stub = data[stub_file_off:stub_file_off + 0x2000]

    # lea rcx,[rip+disp] finden (erste nach dem prolog)
    pos = 0
    while pos + 8 < len(stub):
        code = stub[pos:pos + 8]
        ins = next(md.disasm(code, stub_rva + pos), None)
        if ins is None:
            pos += 1
            continue
        if ins.mnemonic == "lea" and "rcx" in ins.op_str and "rip" in ins.op_str:
            # disp auslesen
            op = ins.op_str
            if "rip + 0x" in op:
                disp = int(op.split("rip + ")[1].rstrip("]"), 16)
            elif "rip - 0x" in op:
                disp = -int(op.split("rip - ")[1].rstrip("]"), 16)
            else:
                pos += ins.size
                continue
            layout.lea_rip_displacement = disp
            # ziel-rva = insn-adresse + size + disp
            target_rva = ins.address + ins.size + disp
            layout.key_region_file_off = _rva_to_file(data, target_rva)
            break
        pos += ins.size

    # block-groesse + loop-grenze aus dem epilog-ende
    pos = 0
    while pos + 16 < len(stub):
        code = stub[pos:pos + 16]
        ins = next(md.disasm(code, stub_rva + pos), None)
        if ins is None:
            pos += 1
            continue
        # add rdi, X nach der op-sequenz
        if ins.mnemonic == "add" and ins.op_str.startswith("rdi, 0x"):
            try:
                layout.block_size = int(ins.op_str.split(", ")[1], 16)
            except ValueError:
                pass
        # cmp rdi, TOTAL
        if ins.mnemonic == "cmp" and ins.op_str.startswith("rdi, 0x"):
            try:
                layout.total_size = int(ins.op_str.split(", ")[1], 16)
            except ValueError:
                pass
        if layout.block_size and layout.total_size:
            break
        pos += ins.size

    # ops extrahieren
    layout.ops = extract_dw_ops(stub, stub_rva)
    return layout


def _rva_to_file(data: bytes, rva: int) -> int:
    """RVA -> file-offset via section-table (headers pur)."""
    if data[:2] != b"MZ" or len(data) < 0x200:
        return 0
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        return 0
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    magic = struct.unpack_from("<H", data, e_lfanew + 0x18)[0]
    sec_off = e_lfanew + 0x18 + (0xE0 if magic == 0x10B else 0xF0)
    for i in range(min(nsec, 40)):
        o = sec_off + i * 40
        if o + 40 > len(data):
            break
        vsize, va, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
        if va <= rva < va + max(vsize, rsize):
            if rsize == 0:
                return 0
            return roff + (rva - va)
    return 0


def decrypt_region(data: bytes, layout: StubLayout) -> bytes:
    """Wendet die extrahierten dw-ops offline auf die region an.

    data: komplette PE-datei (nur zum lesen der region)
    layout: die erkannte stub-geometrie
    returns: entschlüsselte region (total_size bytes)
    """
    if not layout.ops or not layout.total_size:
        raise ValueError("stub-geometrie unvollstaendig")
    src = data[layout.key_region_file_off:layout.key_region_file_off + layout.total_size]
    out = bytearray()
    for blk_off in range(0, layout.total_size, layout.block_size):
        block = bytearray(src[blk_off:blk_off + layout.block_size])
        for op in layout.ops:
            op.apply(block)
        out += block
    return bytes(out)


def find_and_decrypt(data: bytes, stub_file_off: int, stub_rva: int) -> tuple[StubLayout, bytes]:
    """Kompletter flow: stub analysieren + region offline entschluesseln."""
    layout = extract_stub_geometry(data, stub_file_off, stub_rva)
    decrypted = decrypt_region(data, layout)
    return layout, decrypted
