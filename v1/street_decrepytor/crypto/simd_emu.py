# language: Python 3, file: simd_emu.py
# Port of ANALISTAR server_files/simd_decrypt_v2.py — library API + PE auto map
from __future__ import annotations
import json
import struct
from pathlib import Path
from typing import Any

REGS = [
    "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
]
STACK_BASE = 0x10000
STACK_SIZE = 0x4000
TEXT_VA = 0x180001000  # overwritten per sample by run_simd_emu_on_pe


class Emu:
    def __init__(self, blob, va_start, end):
        self.blob = blob
        self.va = va_start
        self.end = end
        self.regs = {}
        self.stack = bytearray(STACK_SIZE)
        self.frame_size = 0x1000
        self.sp = STACK_BASE + STACK_SIZE - 0x100  # rsp initial (frame top)
        self.bp = self.sp          # rbp sits at frame top; locals hang below
        self._lea_imm = 0
        self._sub_imm = 0x1000     # default span so rbp/rsp~hose down below
        self.xor_pairs = []
        self.leas = []             # (va, base_reg, disp)
        self.calls = []
        self._cur_xmm_src = None
        self._xor_src_key = None
        self._xmm_value = None
        self.insn_count = 0
        self._frame_known = False
        self.pending_targets = []   # (target, state_snapshot)
        self._seen_targets = set()
        self.known_imm = {}  # register -> imm64 seen via mov (key material reused across switch cases)

    def _snapshot_state(self):
        """capture full machine state at a jmp point so pending targets
        re-enter with the exact register/stack/frame context of the branch."""
        return (
            dict(self.regs),
            bytes(self.stack),
            self.sp,
            self.bp,
            self._lea_imm,
            self._sub_imm,
            self._xmm_value,
            self._xor_src_key,
            self._frame_known,
        )

    def _restore_state(self, snap):
        (regs, stack, sp, bp, lea_imm, sub_imm, xmm, xor_key, frame_known) = snap
        self.regs = dict(regs)
        # key material (r14/rsi/r15...) is loaded once before the switch and
        # reused by every case; if the snapshot predates that load, refill.
        for r in self.known_imm:
            if r in REGS and r in self.regs and self.regs[r] == 0 and r in ("r14", "r15", "rsi", "rbx"):
                self.regs[r] = self.known_imm[r]
        self.stack = bytearray(stack)
        self.sp = sp
        self.bp = bp
        self._lea_imm = lea_imm
        self._sub_imm = sub_imm
        self._xmm_value = xmm
        self._xor_src_key = xor_key
        self._frame_known = frame_known

    # ---------- addressing ----------
    def d8(self, x): return x - 256 if x >= 128 else x
    def d32(self, x): return x - 0x100000000 if x >= 0x80000000 else x

    def reg_addr(self, base):
        """map base register to unified stack address.
        MSVC frame: rbp = rsp_initial + lea_imm ; sub rsp,X -> rsp = rbp + lea_imm - X
        so slots referenced by [rbp+k] and [rsp+j] share backing memory."""
        if base == "rbp":
            return self.bp
        if base == "rsp":
            return self.bp + self._lea_imm - self._sub_imm
        # r12-r15 / rsi / rdi / others: per-register scratch banks (heap-ish)
        idx = REGS.index(base)
        return 0x20000 + idx * 0x200

    def mem_at(self, addr, size=16):
        off = addr - STACK_BASE
        if off < 0 or off + size > len(self.stack):
            return None
        return self.stack[off:off+size]

    def mem_write(self, addr, data):
        off = addr - STACK_BASE
        if off < 0 or off + len(data) > len(self.stack):
            return
        self.stack[off:off+len(data)] = data

    def rd64(self, base, disp):
        m = self.mem_at(self.reg_addr(base) + self.d32(disp), 8)
        return int.from_bytes(m, "little") if m else 0

    def wr64(self, base, disp, val):
        self.mem_write(self.reg_addr(base) + self.d32(disp), (val & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little"))

    # ---------- frame / prologue ----------
    def parse_prologue(self):
        """detect lea rbp,[rsp+imm32] ; sub rsp, imm32 / imm8 — MSVC frame pattern"""
        b = self.blob
        p = self.va - TEXT_VA
        n = len(b)
        # push rbp : 55 ; push rbx..r15 : 53 56 57 41 54-57
        off = p
        while off < p + 32 and off < n:
            # leave 48 8D (lea) in place for pattern match
            if b[off] == 0x48 and off + 1 < n and b[off+1] == 0x8D:
                break
            if b[off] == 0x41 and off + 1 < n and 0x54 <= b[off+1] <= 0x57:
                off += 2
                continue
            if 0x40 <= b[off] <= 0x4F:  # REX prefix
                off += 1
                continue
            if b[off] == 0x55 or b[off] in (0x53, 0x56, 0x57):
                off += 1
                continue
            break
        # lea rbp, [rsp+imm32] : 48 8D AC 24 imm32
        if off + 8 <= n and b[off] == 0x48 and b[off+1] == 0x8D and b[off+2] == 0xAC and b[off+3] == 0x24:
            imm = struct.unpack("<i", b[off+4:off+8])[0]
            self._lea_imm = imm
            self._frame_known = True
            off += 8
        # lea rbp, [rsp+disp8] : 48 8D 6C 24 d8
        elif off + 6 <= n and b[off] == 0x48 and b[off+1] == 0x8D and b[off+2] == 0x6C and b[off+3] == 0x24:
            self._lea_imm = self.d8(b[off+4])
            self._frame_known = True
            off += 5
        elif off + 3 <= n and b[off] == 0x48 and b[off+1] == 0x89 and b[off+2] == 0xE5:
            # mov rbp, rsp : rbp = rsp_initial
            self._lea_imm = 0
            self._frame_known = True
            off += 3
        else:
            self._lea_imm = 0
            self._frame_known = True
        # sub rsp, imm32 : 48 81 EC imm32 / sub rsp, imm8 : 48 83 EC ib
        # some funcs have a mov [rsp+8],rcx prologue-slot before the sub —
        # scan a short window instead of requiring it right at off.
        scan_end = min(n, off + 40)
        for j in range(off, scan_end):
            if b[j] == 0x48 and b[j+1] == 0x81 and b[j+2] == 0xEC and j + 7 <= n:
                self._sub_imm = struct.unpack("<i", b[j+3:j+7])[0]
                return
            if b[j] == 0x48 and b[j+1] == 0x83 and b[j+2] == 0xEC and j + 4 <= n:
                self._sub_imm = self.d8(b[j+3])
                return
        self._sub_imm = 0

    # ---------- xmm ops ----------
    def xmm_slice(self, base, disp):
        return self.mem_at(self.reg_addr(base) + self.d32(disp), 16)

    def xmm_read(self, base, disp):
        """read 16 bytes at slot into xmm register image"""
        s = self.xmm_slice(base, disp)
        if s is None:
            return None
        return bytes(s)

    def xmm_xor_inplace(self, base, disp):
        """xmm_value ^= mem[slot]"""
        s = self.xmm_slice(base, disp)
        if s is None or self._xmm_value is None:
            return
        v = bytearray(self._xmm_value)
        for i in range(16):
            v[i] ^= s[i]
        self._xmm_value = bytes(v)

    def xmm_store(self, base, disp):
        """mem[slot] = xmm_value"""
        s = self.xmm_slice(base, disp)
        if s is None or self._xmm_value is None:
            return
        self.mem_write(self.reg_addr(base) + self.d32(disp), self._xmm_value)

    # ---------- snapshot / reconstruction ----------
    def snapshot(self, base, disp):
        """read string from unified stack starting at slot, spanning multi-slot"""
        addr = self.reg_addr(base) + self.d32(disp)
        out = bytearray()
        for i in range(160):
            bts = self.mem_at(addr + i, 1)
            if bts is None: break
            c = bts[0]
            if c == 0: break
            # allow printable + common whitespace; newline terminates nothing
            if c == 0x09 or c == 0x0A or c == 0x0D:
                out.append(c)
                continue
            if not (0x20 <= c < 0x7F):
                return ""
            out.append(c)
        return out.decode("ascii")

    # ---------- instruction step ----------
    def step(self):
        b = self.blob
        p = self.va - TEXT_VA
        n = len(b)
        if p < 0 or p >= n: return 0
        if p + 2 > n: return 0
        self.insn_count += 1
        if self.insn_count > 200_000:
            return 0

        # mov r64, imm64 : 48/49 B8-BF imm64
        if b[p] in (0x48, 0x49) and p + 10 <= n and 0xB8 <= b[p+1] <= 0xBF:
            reg = (b[p+1] & 0x07) + (8 if b[p] == 0x49 else 0)
            val = int.from_bytes(b[p+2:p+10], "little")
            self.regs[REGS[reg]] = val
            if self.known_imm.get(REGS[reg]) is None:
                self.known_imm[REGS[reg]] = val
            return 10

        # mov r64, imm32 sign-extended : 48/49 C7 C0-C7 imm32
        if b[p] in (0x48, 0x49) and b[p+1] == 0xC7 and 0xC0 <= b[p+2] <= 0xC7 and p + 8 <= n:
            reg = (b[p+2] & 0x07) + (8 if b[p] == 0x49 else 0)
            self.regs[REGS[reg]] = struct.unpack("<i", b[p+3:p+7])[0]
            return 7

        # mov r64, [base+disp8/disp32] : 48/4C/49 8B modrm [sib] disp
        if b[p] in (0x48, 0x4C, 0x49) and b[p+1] == 0x8B:
            base_hi = 8 if b[p] in (0x4C, 0x49) else 0
            modrm = b[p+2]
            reg = (modrm >> 3) & 7
            mod = modrm >> 6
            rm = modrm & 7
            if mod == 1:  # [base+disp8]
                if rm == 5:
                    if b[p+3] in (0x24, 0x28, 0x2C) and p + 5 <= n:  # rsp variants
                        return 1
                    self.regs[REGS[reg + base_hi]] = self.rd64("rbp", self.d8(b[p+3]))
                    return 4
                if rm == 4:  # SIB
                    sib = b[p+3]
                    base_reg = sib & 7
                    base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][base_reg]
                    disp = self.d8(b[p+4])
                    if base_name == "rbp":
                        self.regs[REGS[reg + base_hi]] = self.rd64("rbp", disp)
                    elif base_name == "rsp":
                        self.regs[REGS[reg + base_hi]] = self.rd64("rsp", disp)
                    return 5
                if rm == 0:
                    self.regs[REGS[reg + base_hi]] = self.rd64("rax", self.d8(b[p+3]))
                    return 4
                if rm == 1:
                    self.regs[REGS[reg + base_hi]] = self.rd64("rcx", self.d8(b[p+3]))
                    return 4
                if rm == 2:
                    self.regs[REGS[reg + base_hi]] = self.rd64("rdx", self.d8(b[p+3]))
                    return 4
                if rm == 3:
                    self.regs[REGS[reg + base_hi]] = self.rd64("rbx", self.d8(b[p+3]))
                    return 4
                if rm == 6:
                    self.regs[REGS[reg + base_hi]] = self.rd64("rsi", self.d8(b[p+3]))
                    return 4
                if rm == 7:
                    self.regs[REGS[reg + base_hi]] = self.rd64("rdi", self.d8(b[p+3]))
                    return 4
            if mod == 2:  # [base+disp32]
                if rm == 4:  # SIB: modrm p+2, sib p+3, disp32 p+4..p+8
                    base_reg = b[p+3] & 7
                    base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][base_reg]
                    disp = self.d32(struct.unpack("<i", b[p+4:p+8])[0])
                    self.regs[REGS[reg + base_hi]] = self.rd64(base_name, disp)
                    return 8
                disp = self.d32(struct.unpack("<i", b[p+3:p+7])[0])
                base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][rm]
                self.regs[REGS[reg + base_hi]] = self.rd64(base_name, disp)
                return 7  # 48 8B modrm disp32 = 7 bytes, no SIB
            if mod == 0:
                if rm == 5:  # RIP-relative (data ref) — skip, not stack
                    return 7
                if rm == 4 and p + 4 <= n:
                    base_reg = b[p+3] & 7
                    base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][base_reg]
                    self.regs[REGS[reg + base_hi]] = self.rd64(base_name, 0)
                    return 4
                if rm < 4 or rm > 5:
                    base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][rm]
                    self.regs[REGS[reg + base_hi]] = self.rd64(base_name, 0)
                    return 3
            if mod == 3:  # mov r64, r64 : 48 8B /r
                src_hi = 8 if (b[p] & 1) else 0
                self.regs[REGS[reg + base_hi]] = self.regs.get(REGS[rm + src_hi], 0)
                return 3
            return 1

        # mov [base+disp], r64 : 48/4C/49 89
        if b[p] in (0x48, 0x4C, 0x49) and b[p+1] == 0x89:
            base_hi = 8 if b[p] in (0x4C, 0x49) else 0
            modrm = b[p+2]
            reg = (modrm >> 3) & 7
            mod = modrm >> 6
            rm = modrm & 7
            val = self.regs.get(REGS[reg + base_hi], 0)
            if mod == 1:
                if rm == 5:
                    if b[p+3] in (0x24, 0x28, 0x2C) and p + 5 <= n:
                        self.wr64("rsp", self.d8(b[p+4]), val)
                        return 5
                    self.wr64("rbp", self.d8(b[p+3]), val)
                    return 4
                if rm == 4 and p + 5 <= n:
                    base_reg = b[p+3] & 7
                    base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][base_reg]
                    self.wr64(base_name, self.d8(b[p+4]), val)
                    return 5
                if rm == 3:
                    self.wr64("rbx", self.d8(b[p+3]), val)
                    return 4
                if rm == 6:
                    self.wr64("rsi", self.d8(b[p+3]), val)
                    return 4
                if rm == 7:
                    self.wr64("rdi", self.d8(b[p+3]), val)
                    return 4
                if rm == 0:
                    self.wr64("rax", self.d8(b[p+3]), val)
                    return 4
                if rm == 1:
                    self.wr64("rcx", self.d8(b[p+3]), val)
                    return 4
                if rm == 2:
                    self.wr64("rdx", self.d8(b[p+3]), val)
                    return 4
                return 1
            if mod == 2:
                if rm == 4:
                    base_reg = b[p+3] & 7
                    base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][base_reg]
                    disp = self.d32(struct.unpack("<i", b[p+4:p+8])[0])
                    self.wr64(base_name, disp, val)
                    return 8
                disp = self.d32(struct.unpack("<i", b[p+3:p+7])[0])
                base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][rm]
                self.wr64(base_name, disp, val)
                return 7  # 48 89 modrm disp32 = 7 bytes, no SIB
            if mod == 0:
                if rm == 5:
                    return 7  # RIP-relative — skip
                if rm == 4 and p + 4 <= n:
                    base_reg = b[p+3] & 7
                    base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][base_reg]
                    self.wr64(base_name, 0, val)
                    return 4
                if rm < 4 or rm > 5:
                    base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][rm]
                    self.wr64(base_name, 0, val)
                    return 3
            if mod == 3:  # mov r64, r64 : 48 89 /r
                src_hi = 8 if (b[p] & 1) else 0
                self.regs[REGS[rm + src_hi]] = self.regs.get(REGS[reg + base_hi], 0)
                return 3
            return 1

        # movdqa xmm0, [base+disp] : 66 0F 6F modrm [sib] disp
        # lengths: mod=1 -> 5 bytes (66 0F 6F modrm d8), SIB+d8 -> 6, mod=2 -> 8 (SIB) / 7, mod=0 -> 4 (3 no SIB)
        if b[p] == 0x66 and b[p+1] == 0x0F and b[p+2] == 0x6F and p + 4 <= n:
            modrm = b[p+3]
            mod, rm = modrm >> 6, modrm & 7
            if mod == 1:
                if rm == 5:  # [rbp+disp8] = 5 bytes
                    self._xmm_value = self.xmm_read("rbp", self.d8(b[p+4]))
                    return 5
                if rm == 4 and p + 5 <= n:  # SIB disp8 = 6 bytes
                    base_reg = b[p+4] & 7
                    base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][base_reg]
                    self._xmm_value = self.xmm_read(base_name, self.d8(b[p+5]))
                    return 6
                base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][rm]
                self._xmm_value = self.xmm_read(base_name, self.d8(b[p+4]))
                return 5
            if mod == 2 and rm == 4 and p + 9 <= n:  # SIB disp32 : modrm p+3, sib p+4, disp p+5..p+9 = 9 bytes
                base_reg = b[p+4] & 7
                base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][base_reg]
                self._xmm_value = self.xmm_read(base_name, self.d32(struct.unpack("<i", b[p+5:p+9])[0]))
                return 9
            if mod == 2 and rm == 5 and p + 8 <= n:  # [rbp+disp32] : modrm p+3, disp p+4..p+8 = 8 bytes
                self._xmm_value = self.xmm_read("rbp", self.d32(struct.unpack("<i", b[p+4:p+8])[0]))
                return 8
            if mod == 2 and rm != 5 and p + 8 <= n:  # [base+disp32] = 8 bytes
                base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][rm]
                self._xmm_value = self.xmm_read(base_name, self.d32(struct.unpack("<i", b[p+4:p+8])[0]))
                return 8
            if mod == 0 and rm == 4 and p + 4 <= n:  # [SIB] no disp = 5 bytes (with sib byte)
                base_reg = b[p+4] & 7
                base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][base_reg]
                self._xmm_value = self.xmm_read(base_name, 0)
                return 5
            if mod == 0 and rm != 5 and p + 4 <= n:  # [base] = 4 bytes
                base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][rm]
                self._xmm_value = self.xmm_read(base_name, 0)
                return 4
            if rm == 5 and mod == 0:  # RIP-relative [rip+disp32] = 7 bytes — skip
                return 7
            return 1

        # xorps xmm0, [base+disp] : 0F 57 modrm [sib] disp
        if b[p] == 0x0F and b[p+1] == 0x57 and p + 3 <= n:
            modrm = b[p+2]
            mod, rm = modrm >> 6, modrm & 7
            if mod == 1:
                if rm == 5:  # [rbp+disp8] = 4 bytes
                    self.xmm_xor_inplace("rbp", self.d8(b[p+3]))
                    self._xor_src_key = ("rbp", self.d8(b[p+3]))
                    return 4
                if rm == 4 and p + 5 <= n:  # SIB disp8 : modrm p+2, sib p+3, disp8 p+4 = 5 bytes
                    base_reg = b[p+3] & 7
                    base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][base_reg]
                    self.xmm_xor_inplace(base_name, self.d8(b[p+4]))
                    self._xor_src_key = (base_name, self.d8(b[p+4]))
                    return 5
                base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][rm]
                self.xmm_xor_inplace(base_name, self.d8(b[p+4]))
                self._xor_src_key = (base_name, self.d8(b[p+4]))
                return 4
            if mod == 2 and rm == 5 and p + 7 <= n:  # [rbp+disp32] = 7 bytes
                self.xmm_xor_inplace("rbp", self.d32(struct.unpack("<i", b[p+3:p+7])[0]))
                self._xor_src_key = ("rbp", self.d32(struct.unpack("<i", b[p+3:p+7])[0]))
                return 7
            if mod == 2 and rm == 4 and p + 8 <= n:  # SIB disp32 : sib p+3, disp p+4..p+8 = 8 bytes
                base_reg = b[p+3] & 7
                base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][base_reg]
                disp = self.d32(struct.unpack("<i", b[p+4:p+8])[0])
                self.xmm_xor_inplace(base_name, disp)
                self._xor_src_key = (base_name, disp)
                return 8
            if mod == 0 and rm == 4 and p + 4 <= n:  # SIB no disp : modrm p+2, sib p+3 = 4 bytes
                base_reg = b[p+3] & 7
                base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][base_reg]
                self.xmm_xor_inplace(base_name, 0)
                self._xor_src_key = (base_name, 0)
                return 4
            if mod == 0 and rm != 5 and p + 3 <= n:  # [base] = 3 bytes
                base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][rm]
                self.xmm_xor_inplace(base_name, 0)
                self._xor_src_key = (base_name, 0)
                return 3
            if rm == 5 and mod == 0:  # RIP-relative = 6 bytes — skip
                return 6
            return 1

        # movdqa [base+disp], xmm0 : 66 0F 7F modrm [sib] disp
        if b[p] == 0x66 and b[p+1] == 0x0F and b[p+2] == 0x7F and p + 4 <= n:
            modrm = b[p+3]
            mod, rm = modrm >> 6, modrm & 7
            if mod == 1:
                if rm == 5:  # 5 bytes
                    self.xmm_store("rbp", self.d8(b[p+4]))
                    self.xor_pairs.append((("rbp", self.d8(b[p+4])), self._xor_src_key, self.va))
                    return 5
                if rm == 4 and p + 5 <= n:  # 6 bytes
                    base_reg = b[p+4] & 7
                    base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][base_reg]
                    self.xmm_store(base_name, self.d8(b[p+5]))
                    self.xor_pairs.append(((base_name, self.d8(b[p+5])), self._xor_src_key, self.va))
                    return 6
                base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][rm]
                self.xmm_store(base_name, self.d8(b[p+4]))
                self.xor_pairs.append(((base_name, self.d8(b[p+4])), self._xor_src_key, self.va))
                return 5
            if mod == 2 and rm == 5 and p + 8 <= n:  # [rbp+disp32] : modrm p+3, disp p+4..p+8 = 8 bytes
                disp = self.d32(struct.unpack("<i", b[p+4:p+8])[0])
                self.xmm_store("rbp", disp)
                self.xor_pairs.append((("rbp", disp), self._xor_src_key, self.va))
                return 8
            if mod == 2 and rm == 4 and p + 9 <= n:  # SIB disp32 : modrm p+3, sib p+4, disp p+5..p+9 = 9 bytes
                base_reg = b[p+4] & 7
                base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][base_reg]
                disp = self.d32(struct.unpack("<i", b[p+5:p+9])[0])
                self.xmm_store(base_name, disp)
                self.xor_pairs.append(((base_name, disp), self._xor_src_key, self.va))
                return 9
            if mod == 2 and rm != 5 and p + 8 <= n:  # [base+disp32] = 8 bytes
                base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][rm]
                disp = self.d32(struct.unpack("<i", b[p+4:p+8])[0])
                self.xmm_store(base_name, disp)
                self.xor_pairs.append(((base_name, disp), self._xor_src_key, self.va))
                return 8
            if mod == 0 and rm == 4 and p + 4 <= n:  # 5 bytes
                base_reg = b[p+4] & 7
                base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][base_reg]
                self.xmm_store(base_name, 0)
                self.xor_pairs.append(((base_name, 0), self._xor_src_key, self.va))
                return 5
            if mod == 0 and rm != 5 and p + 4 <= n:  # 4 bytes
                base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][rm]
                self.xmm_store(base_name, 0)
                self.xor_pairs.append(((base_name, 0), self._xor_src_key, self.va))
                return 4
            if rm == 5 and mod == 0:  # RIP-relative = 7 bytes — skip
                return 7
            return 1

        # lea rcx, [base+disp8] : 48 8D 4D/4C 24 ...
        if b[p] == 0x48 and b[p+1] == 0x8D and p + 4 <= n:
            modrm = b[p+2]
            reg = (modrm >> 3) & 7
            mod, rm = modrm >> 6, modrm & 7
            if mod == 1:
                base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][rm] if rm != 5 else "rbp"
                disp = self.d8(b[p+3])
                if rm == 4 and p + 5 <= n:  # SIB
                    base_reg = b[p+3] & 7
                    base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][base_reg]
                    disp = self.d8(b[p+4])
                    if reg == 1:  # rcx
                        self.leas.append((self.va, base_name, disp, self.snapshot(base_name, disp)))
                    return 5
                if reg == 1:  # rcx
                    self.leas.append((self.va, base_name, disp, self.snapshot(base_name, disp)))
                return 4
            if mod == 0:
                if rm == 5:  # RIP-rel
                    return 7
                base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][rm]
                if reg == 1:
                    self.leas.append((self.va, base_name, 0, self.snapshot(base_name, 0)))
                return 3
            if mod == 2 and p + 8 <= n:
                if rm == 4:  # SIB disp32 : modrm p+2, sib p+3, disp p+4..p+8 = 8 bytes
                    base_reg = b[p+3] & 7
                    base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][base_reg]
                    disp = self.d32(struct.unpack("<i", b[p+4:p+8])[0])
                    if reg == 1:
                        self.leas.append((self.va, base_name, disp, self.snapshot(base_name, disp)))
                    return 8
                base_name = ["rax","rcx","rdx","rbx","rsp","rbp","rsi","rdi"][rm]
                disp = self.d32(struct.unpack("<i", b[p+3:p+7])[0])
                if reg == 1:
                    self.leas.append((self.va, base_name, disp, self.snapshot(base_name, disp)))
                return 7
            return 1

# jmp rel8/rel32 : EB / E9
        if b[p] == 0xEB and p + 2 <= n:
            rel = self.d8(b[p+1])
            target = self.va + 2 + rel
            if target > self.va and target < self.end:
                self.pending_targets.append((target, self._snapshot_state()))
            return 2
        if b[p] == 0xE9 and p + 5 <= n:
            rel = struct.unpack("<i", b[p+1:p+5])[0]
            target = self.va + 5 + rel
            if target > self.va and target < self.end:
                self.pending_targets.append((target, self._snapshot_state()))
            return 5

        # call rel32 : E8
        if b[p] == 0xE8 and p + 5 <= n:
            rel = struct.unpack("<i", b[p+1:p+5])[0]
            self.calls.append(self.va + 5 + rel)
            return 5

        # jcc rel8 (fall-through + pending target) : 70-7F
        if 0x70 <= b[p] <= 0x7F and p + 2 <= n:
            rel = self.d8(b[p+1])
            target = self.va + 2 + rel
            if target > self.va and target < self.end:
                self.pending_targets.append((target, self._snapshot_state()))
            return 2
        # jcc rel32 (fall-through + pending target) : 0F 80-8F
        if b[p] == 0x0F and 0x80 <= b[p+1] <= 0x8F and p + 6 <= n:
            rel = struct.unpack("<i", b[p+2:p+6])[0]
            target = self.va + 6 + rel
            if target > self.va and target < self.end:
                self.pending_targets.append((target, self._snapshot_state()))
            return 6

        # ret : C3 / C2 imm16
        if b[p] == 0xC3: return 1
        if b[p] == 0xC2 and p + 3 <= n: return 3

        # nop / endbr64
        if b[p] == 0x90: return 1
        if b[p] == 0xF3 and b[p+1] == 0x0F and b[p+2] == 0x1E: return 4

        # lea rax, [rip+disp32] : 48 8D 05 — skip 7
        if b[p] == 0x48 and b[p+1] == 0x8D and p + 7 <= n:
            modrm = b[p+2]
            if (modrm & 0xC7) == 0x05:
                return 7

        # unknown
        return 1

    def run(self):
        if not self._frame_known:
            self.parse_prologue()
        while True:
            while self.va < self.end:
                s = self.step()
                if s == 0:
                    break
                self.va += s
            # pull next pending jmp target (explore both sides of forward jumps)
            nxt = None
            while self.pending_targets:
                t, snap = self.pending_targets.pop()
                if t < self.end and t not in self._seen_targets:
                    self._seen_targets.add(t)
                    nxt = (t, snap)
                    break
            if nxt is None:
                break
            self._restore_state(nxt[1])
            self.va = nxt[0]


def pe_text_map(data: bytes) -> dict[str, Any]:
    """Derive image base, .text VA and file offset from PE headers."""
    if data[:2] != b"MZ":
        raise ValueError("not PE")
    e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
    magic = struct.unpack_from("<H", data, e_lfanew + 0x18)[0]
    if magic == 0x10B:
        image_base = struct.unpack_from("<I", data, e_lfanew + 0x18 + 28)[0]
        sec = e_lfanew + 0x18 + 0xE0
    else:
        image_base = struct.unpack_from("<Q", data, e_lfanew + 0x18 + 24)[0]
        sec = e_lfanew + 0x18 + 0xF0
    nsec = struct.unpack_from("<H", data, e_lfanew + 6)[0]
    fallback = None
    for i in range(nsec):
        o = sec + i * 40
        name = data[o : o + 8].split(b"\x00", 1)[0]
        vsize, va, rsize, roff = struct.unpack_from("<IIII", data, o + 8)
        rec = {
            "image_base": image_base,
            "text_va": image_base + va,
            "text_rva": va,
            "text_roff": roff,
            "text_rsize": rsize,
            "text_vsize": vsize,
            "text_size": rsize if rsize else vsize,
            "name": name.decode("latin-1", "replace"),
        }
        if name == b".text":
            return rec
        if fallback is None:
            fallback = rec
    if fallback:
        return fallback
    raise ValueError("no .text section")


def find_simd_functions(text: bytes, text_va: int, window: int = 0x800) -> list[tuple[int, int]]:
    """Cluster movdqa densitites into candidate decryptor ranges."""
    sig_load = bytes((0x66, 0x0F, 0x6F))
    hits: list[int] = []
    i = 0
    while True:
        j = text.find(sig_load, i)
        if j < 0:
            break
        hits.append(j)
        i = j + 1
    if not hits:
        return []
    clusters: list[tuple[int, int]] = []
    start = prev = hits[0]
    for h in hits[1:]:
        if h - prev > window:
            clusters.append((text_va + start, text_va + prev + 0x40))
            start = h
        prev = h
    clusters.append((text_va + start, text_va + prev + 0x40))
    merged: list[tuple[int, int]] = []
    for a, b in clusters:
        if b - a > 0x4000:
            b = a + 0x2000
        if merged and a <= merged[-1][1] + 0x100:
            merged[-1] = (merged[-1][0], max(merged[-1][1], b))
        else:
            merged.append((a, b))
    return merged[:200]


def emulate_range(text: bytes, text_va: int, start_va: int, end_va: int) -> dict[str, Any]:
    global TEXT_VA
    TEXT_VA = text_va
    emu = Emu(text, start_va, end_va)
    emu.run()
    strings: list[dict[str, Any]] = []
    for item in emu.leas:
        if len(item) >= 4:
            s = item[3]
            if s and len(s) >= 3:
                strings.append({"va": hex(item[0]), "base": item[1], "disp": item[2], "str": s})
    return {
        "start": hex(start_va),
        "end": hex(end_va),
        "insn": emu.insn_count,
        "xor_pairs": len(emu.xor_pairs),
        "strings": strings,
        "calls": [hex(c) for c in emu.calls[:20]],
    }


def run_simd_emu_on_pe(
    path: str | Path,
    max_funcs: int = 80,
    funcs_list: str | Path | None = None,
) -> dict[str, Any]:
    path = Path(path)
    data = path.read_bytes()
    meta = pe_text_map(data)
    if int(meta.get("text_rsize") or 0) < 0x1000:
        return {
            "path": str(path),
            "skipped": True,
            "reason": "empty_or_tiny_text_raw",
            "text_rsize": meta.get("text_rsize"),
            "unique_strings": 0,
            "functions_emulated": 0,
            "strings_sample": [],
            "pe_text": {k: (hex(v) if isinstance(v, int) else v) for k, v in meta.items()},
        }
    global TEXT_VA
    TEXT_VA = meta["text_va"]
    text = data[meta["text_roff"] : meta["text_roff"] + meta["text_rsize"]]
    ranges: list[tuple[int, int]] = []
    if funcs_list and Path(funcs_list).is_file():
        for line in Path(funcs_list).read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            try:
                # formats: "0xVA name size" | "name 0xVA size" | "0xVA 0xSIZE"
                if parts[0].startswith("sub_") or (parts[0][0].isalpha() and not parts[0].startswith("0x")):
                    va = int(parts[1], 16)
                    size = int(parts[2], 0) if len(parts) > 2 else 0x400
                else:
                    va = int(parts[0], 16)
                    size = int(parts[2] if len(parts) > 2 else parts[1], 0)
                if size < 0x80:
                    continue  # skip tiny stubs
                ranges.append((va, va + size))
            except Exception:
                continue
    # Prefer bodies that actually contain SIMD xor/load shapes
    def _simd_score(start: int, end: int) -> int:
        off0 = start - meta["text_va"]
        off1 = end - meta["text_va"]
        if off0 < 0 or off0 >= len(text):
            return 0
        blob = text[off0 : min(off1, len(text))]
        return blob.count(b"\x0f\x57") + blob.count(b"\x66\x0f\x6f") + blob.count(b"\x66\x0f\xef")

    if ranges:
        scored = sorted(ranges, key=lambda ab: -_simd_score(ab[0], ab[1]))
        ranges = [ab for ab in scored if _simd_score(ab[0], ab[1]) > 0] or scored[:max_funcs]
    if not ranges:
        ranges = find_simd_functions(text, meta["text_va"])
    results: list[dict[str, Any]] = []
    all_strings: list[dict[str, Any]] = []
    for start, end in ranges[:max_funcs]:
        if start < meta["text_va"] or start >= meta["text_va"] + len(text):
            continue
        end = min(end, meta["text_va"] + len(text))
        try:
            r = emulate_range(text, meta["text_va"], start, end)
            results.append(r)
            all_strings.extend(r["strings"])
        except Exception as e:
            results.append({"start": hex(start), "error": str(e)})
    seen: set[str] = set()
    uniq: list[dict[str, Any]] = []
    for s in all_strings:
        if s["str"] not in seen:
            seen.add(s["str"])
            uniq.append(s)
    return {
        "path": str(path),
        "pe_text": {k: (hex(v) if isinstance(v, int) else v) for k, v in meta.items()},
        "functions_emulated": len(results),
        "unique_strings": len(uniq),
        "strings_sample": uniq[:200],
        "functions": results[:40],
    }


def stage_simd_emu(profile: Any, out_dir: Path) -> dict[str, Any]:
    path = Path(profile.path)
    if getattr(profile, "format", "") not in ("pe",) and path.suffix.lower() not in (".dll", ".exe"):
        return {"skipped": True}
    size = path.stat().st_size
    head = path.read_bytes()[: min(size, 2 << 20)]
    dense = head.count(b"\x0f\x57") >= 5 or head.count(b"\x66\x0f\xef") >= 3 or size > 2_000_000
    if not dense:
        return {"skipped": True, "reason": "low_simd_density"}
    report = run_simd_emu_on_pe(path, max_funcs=40)
    if report.get("skipped"):
        return report
    out_dir = Path(out_dir)
    (out_dir / "simd_emu.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
    (out_dir / "simd_strings.txt").write_text(
        "\n".join(s["str"] for s in report.get("strings_sample", [])),
        encoding="utf-8",
        errors="replace",
    )
    return {
        "unique_strings": report.get("unique_strings"),
        "functions_emulated": report.get("functions_emulated"),
        "out": str(out_dir / "simd_emu.json"),
    }

