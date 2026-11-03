"""Minimal JVM interpreter for ZKM 21 string decrypt methods (clinit / a(II) / a(III)).

Ported patterns:
  - Diobf ZKMCipher 7-xor tableswitch (ZelixStringTransformer)
  - threadtear / java-deobfuscator enhanced (II)/(III) String decrypt
Does not implement invokedynamic / MethodHandles (that's h's bootstrap — needs JDK 21 VM).
"""
from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from sfsociety import class_methods, parse_cp, skip_insn, u2, u4, utf


def _i32(x: int) -> int:
    x &= 0xFFFFFFFF
    return x - 0x100000000 if x >= 0x80000000 else x


def _i64(x: int) -> int:
    x &= 0xFFFFFFFFFFFFFFFF
    return x - 0x10000000000000000 if x >= 0x8000000000000000 else x


@dataclass
class JavaClass:
    name: str
    cp: list
    methods: dict  # (name, desc) -> (acc, code)
    statics: dict = field(default_factory=dict)
    data: bytes = b""


def load_class(path) -> JavaClass:
    data = open(path, "rb").read()
    this, cp, methods = class_methods(data)
    md = {(n, d): (a, c) for n, d, a, c in methods}
    return JavaClass(name=this, cp=cp, methods=md, data=data)


def _cp_const(cp, idx):
    e = cp[idx]
    if e is None:
        return None
    if e[0] == "Int":
        return _i32(e[1])
    if e[0] == "Long":
        return _i64(e[1])
    if e[0] == "Utf8":
        return e[1].decode("utf-8", "replace")
    if e[0] == 8:
        return utf(cp, e[1])
    if e[0] == 7:
        return utf(cp, e[1])
    if e[0] == "Float":
        return struct.unpack(">f", struct.pack(">I", e[1]))[0]
    return e


class VMError(RuntimeError):
    pass


class Interpreter:
    def __init__(self, classes: dict[str, JavaClass]):
        self.classes = classes

    def call(self, cname: str, name: str, desc: str, args: list[Any]) -> Any:
        jc = self.classes[cname]
        if (name, desc) not in jc.methods:
            raise VMError(f"no method {cname}.{name}{desc}")
        acc, code = jc.methods[(name, desc)]
        if code is None:
            raise VMError(f"native/abstract {cname}.{name}{desc}")
        return self._exec(jc, code, list(args))

    def clinit(self, cname: str) -> None:
        jc = self.classes[cname]
        if jc.statics.get("<clinit_done>"):
            return
        jc.statics["<clinit_done>"] = True
        if ("<clinit>", "()V") in jc.methods:
            self.call(cname, "<clinit>", "()V", [])

    def _exec(self, jc: JavaClass, code: bytes, locals_: list[Any]) -> Any:
        # pad locals
        while len(locals_) < 256:
            locals_.append(None)
        stack: list[Any] = []
        pc = 0
        steps = 0
        cp = jc.cp

        def push(x):
            stack.append(x)

        def pop():
            return stack.pop()

        while pc < len(code):
            steps += 1
            if steps > 2_000_000:
                raise VMError("step limit")
            op = code[pc]
            nxt = skip_insn(code, pc)

            if op == 0x00:  # nop
                pass
            elif op == 0x01:
                push(None)
            elif 0x02 <= op <= 0x08:
                push(op - 0x03)
            elif op in (0x09, 0x0A):
                push(0 if op == 0x09 else 1)
            elif op == 0x10:
                push(struct.unpack("b", bytes([code[pc + 1]]))[0])
            elif op == 0x11:
                push(struct.unpack_from(">h", code, pc + 1)[0])
            elif op == 0x12:
                push(_cp_const(cp, code[pc + 1]))
            elif op in (0x13, 0x14):
                push(_cp_const(cp, struct.unpack_from(">H", code, pc + 1)[0]))
            elif op in (0x15, 0x16, 0x17, 0x18, 0x19):
                push(locals_[code[pc + 1]])
            elif 0x1A <= op <= 0x1D:
                push(locals_[op - 0x1A])
            elif 0x1E <= op <= 0x21:
                push(locals_[op - 0x1E])
            elif 0x2A <= op <= 0x2D:
                push(locals_[op - 0x2A])
            elif op == 0x2E:  # iaload
                i = pop(); a = pop(); push(_i32(a[i]))
            elif op == 0x32:  # aaload
                i = pop(); a = pop(); push(a[i])
            elif op == 0x33:  # baload
                i = pop(); a = pop(); push(_i32(a[i]))
            elif op == 0x34:  # caload
                i = pop(); a = pop(); push(ord(a[i]) if isinstance(a, str) else a[i] & 0xFFFF)
            elif op in (0x36, 0x37, 0x38, 0x39, 0x3A):
                locals_[code[pc + 1]] = pop()
            elif 0x3B <= op <= 0x3E:
                locals_[op - 0x3B] = pop()
            elif 0x3F <= op <= 0x42:
                locals_[op - 0x3F] = pop()
            elif 0x4B <= op <= 0x4E:
                locals_[op - 0x4B] = pop()
            elif op == 0x4F:  # iastore
                v = pop(); i = pop(); a = pop(); a[i] = _i32(v)
            elif op == 0x53:  # aastore
                v = pop(); i = pop(); a = pop(); a[i] = v
            elif op == 0x54:  # bastore
                v = pop(); i = pop(); a = pop(); a[i] = _i32(v) & 0xFF
            elif op == 0x55:  # castore
                v = pop(); i = pop(); a = pop()
                if isinstance(a, list):
                    a[i] = _i32(v) & 0xFFFF
            elif op == 0x57:
                pop()
            elif op == 0x58:  # pop2
                pop()
                if stack:
                    pop()
            elif op == 0x59:
                push(stack[-1])
            elif op == 0x5A:  # dup_x1
                a = pop(); b = pop(); push(a); push(b); push(a)
            elif op == 0x5B:  # dup_x2  (cat1,cat1,cat1)
                a = pop(); b = pop(); c = pop(); push(a); push(c); push(b); push(a)
            elif op == 0x5C:  # dup2
                if len(stack) >= 2:
                    x, y = stack[-2], stack[-1]
                    push(x); push(y)
                else:
                    push(stack[-1]); push(stack[-1])
            elif op == 0x5D:  # dup2_x1
                a = pop(); b = pop(); c = pop(); push(b); push(a); push(c); push(b); push(a)
            elif op == 0x5E:  # dup2_x2
                a = pop(); b = pop(); c = pop(); d = pop(); push(b); push(a); push(d); push(c); push(b); push(a)
            elif op == 0x5F:
                stack[-1], stack[-2] = stack[-2], stack[-1]
            elif op == 0x60:
                b = pop(); a = pop(); push(_i32(a + b))
            elif op == 0x61:
                b = pop(); a = pop(); push(_i64(a + b))
            elif op == 0x64:
                b = pop(); a = pop(); push(_i32(a - b))
            elif op == 0x68:
                b = pop(); a = pop(); push(_i32(a * b))
            elif op == 0x6C:
                b = pop(); a = pop(); push(_i32(int(a / b)) if b else 0)
            elif op == 0x70:
                b = pop(); a = pop(); push(_i32(a % b) if b else 0)
            elif op == 0x74:
                push(_i32(-pop()))
            elif op == 0x78:
                b = pop(); a = pop(); push(_i32(a << (b & 31)))
            elif op == 0x79:  # lshl
                b = pop(); a = pop(); push(_i64(a << (int(b) & 63)))
            elif op == 0x7A:
                b = pop(); a = pop(); push(_i32(a >> (b & 31)))
            elif op == 0x7B:  # lshr
                b = pop(); a = pop(); push(_i64(a >> (int(b) & 63)))
            elif op == 0x7C:
                b = pop(); a = pop(); push(_i32((a & 0xFFFFFFFF) >> (b & 31)))
            elif op == 0x7D:  # lushr
                b = pop(); a = pop(); push(_i64((a & 0xFFFFFFFFFFFFFFFF) >> (int(b) & 63)))
            elif op == 0x7E:
                b = pop(); a = pop(); push(_i32(a & b))
            elif op == 0x80:
                b = pop(); a = pop(); push(_i32(a | b))
            elif op == 0x82:
                b = pop(); a = pop(); push(_i32(a ^ b))
            elif op == 0x83:  # lxor
                b = pop(); a = pop(); push(_i64(a ^ b))
            elif op == 0x84:
                idx, inc = code[pc + 1], struct.unpack("b", bytes([code[pc + 2]]))[0]
                locals_[idx] = _i32((locals_[idx] or 0) + inc)
            elif op == 0x85:  # i2l
                push(_i64(pop()))
            elif op == 0x88:  # l2i
                push(_i32(pop()))
            elif op == 0x91:  # i2b
                v = _i32(pop()) & 0xFF
                push(v - 256 if v >= 128 else v)
            elif op == 0x92:  # i2c
                push(_i32(pop()) & 0xFFFF)
            elif op == 0x93:  # i2s
                v = _i32(pop()) & 0xFFFF
                push(v - 0x10000 if v >= 0x8000 else v)
            elif op in (0x94,):  # lcmp
                b = pop(); a = pop()
                push(0 if a == b else (1 if a > b else -1))
            elif 0x99 <= op <= 0x9E:
                off = struct.unpack_from(">h", code, pc + 1)[0]
                v = _i32(pop())
                take = (
                    (op == 0x99 and v == 0)
                    or (op == 0x9A and v != 0)
                    or (op == 0x9B and v < 0)
                    or (op == 0x9C and v >= 0)
                    or (op == 0x9D and v > 0)
                    or (op == 0x9E and v <= 0)
                )
                if take:
                    pc = pc + off
                    continue
            elif 0x9F <= op <= 0xA4:
                off = struct.unpack_from(">h", code, pc + 1)[0]
                b = _i32(pop()); a = _i32(pop())
                take = (
                    (op == 0x9F and a == b)
                    or (op == 0xA0 and a != b)
                    or (op == 0xA1 and a < b)
                    or (op == 0xA2 and a >= b)
                    or (op == 0xA3 and a > b)
                    or (op == 0xA4 and a <= b)
                )
                if take:
                    pc = pc + off
                    continue
            elif op == 0xA7:
                pc = pc + struct.unpack_from(">h", code, pc + 1)[0]
                continue
            elif op == 0xAA:
                p = (pc + 4) & ~3
                default, low, high = struct.unpack_from(">iii", code, p)
                n = high - low + 1
                offs = struct.unpack_from(">" + "i" * n, code, p + 12)
                idx = _i32(pop())
                if low <= idx <= high:
                    pc = pc + offs[idx - low]
                else:
                    pc = pc + default
                continue
            elif op == 0xAC:
                return _i32(pop())
            elif op == 0xAD:
                return _i64(pop())
            elif op == 0xB0:
                return pop()
            elif op == 0xB1:
                return None
            elif op == 0xB2:  # getstatic
                idx = struct.unpack_from(">H", code, pc + 1)[0]
                field = utf(cp, idx)
                # Fieldref -> name
                e = cp[idx]
                fname = field
                if e and e[0] in (9,):
                    nt = cp[e[2]]
                    fname = utf(cp, nt[1]) if nt else field
                owner = jc.name
                if e and e[0] == 9:
                    owner = utf(cp, e[1])
                if owner in self.classes:
                    self.clinit(owner)
                    push(self.classes[owner].statics.get(fname))
                else:
                    # TYPE fields etc
                    if fname == "TYPE":
                        push("TYPE")
                    else:
                        push(None)
            elif op == 0xB3:  # putstatic
                idx = struct.unpack_from(">H", code, pc + 1)[0]
                e = cp[idx]
                fname = utf(cp, idx)
                owner = jc.name
                if e and e[0] == 9:
                    nt = cp[e[2]]
                    fname = utf(cp, nt[1]) if nt else fname
                    owner = utf(cp, e[1])
                val = pop()
                if owner in self.classes:
                    self.classes[owner].statics[fname] = val
            elif op in (0xB6, 0xB7, 0xB8):  # invokevirtual/special/static
                idx = struct.unpack_from(">H", code, pc + 1)[0]
                e = cp[idx]
                owner = utf(cp, e[1]) if e else ""
                nt = cp[e[2]] if e else None
                mname = utf(cp, nt[1]) if nt else ""
                mdesc = utf(cp, nt[2]) if nt else ""
                nargs = _nargs(mdesc)
                args = [pop() for _ in range(nargs)][::-1]
                if op != 0xB8:
                    recv = pop()
                else:
                    recv = None
                r = self._invoke(owner, mname, mdesc, recv, args)
                if not mdesc.endswith("V"):
                    push(r)
            elif op == 0xBA:
                # ZKM 21 indy: dummy long(s) + String.getBytes(Charset) or ByteBuffer ops.
                grabbed = []
                while stack and len(grabbed) < 8:
                    grabbed.append(pop())
                src = None
                for v in grabbed:
                    if isinstance(v, str) or (isinstance(v, dict) and "str" in v):
                        src = v if isinstance(v, str) else v["str"]
                        break
                    if isinstance(v, list) and v and isinstance(v[0], int):
                        src = bytes(x & 0xFF for x in v)
                        break
                if isinstance(src, str):
                    push(list(src.encode("utf-8")))
                elif isinstance(src, (bytes, bytearray)):
                    push(list(src))
                else:
                    raise VMError(f"invokedynamic at {pc:#x} stack={ [type(x) for x in grabbed] }")
            elif op == 0xBB:
                push({"new": utf(cp, struct.unpack_from(">H", code, pc + 1)[0])})
            elif op == 0xBC:
                n = pop()
                atype = code[pc + 1]
                push([0] * max(int(n), 0))
            elif op == 0xBD:
                n = pop()
                push([None] * max(int(n), 0))
            elif op == 0xBE:
                a = pop()
                push(len(a) if a is not None else 0)
            elif op == 0xBF:
                raise VMError(f"athrow {pop()!r}")
            elif op == 0xC0:
                pass  # checkcast
            elif op == 0xC6:
                off = struct.unpack_from(">h", code, pc + 1)[0]
                if pop() is None:
                    pc = pc + off
                    continue
            elif op == 0xC7:
                off = struct.unpack_from(">h", code, pc + 1)[0]
                if pop() is not None:
                    pc = pc + off
                    continue
            else:
                # skip unknown (ZKM junk) rather than die — but stack may desync
                pass
            pc += nxt
        return None

    def _invoke(self, owner, name, desc, recv, args):
        if owner in self.classes and (name, desc) in self.classes[owner].methods:
            acc, code = self.classes[owner].methods[(name, desc)]
            if code is not None:
                locals_ = ([] if recv is None else [recv]) + list(args)
                return self._exec(self.classes[owner], code, locals_)
        # java/lang/String
        if name == "length":
            return len(recv) if recv is not None else 0
        if name == "charAt":
            return ord(recv[args[0]])
        if name == "substring":
            if len(args) == 2:
                return recv[args[0] : args[1]]
            return recv[args[0] :]
        if name == "toCharArray":
            s = recv["str"] if isinstance(recv, dict) else recv
            return [ord(c) for c in s]
        if name == "intern":
            if isinstance(recv, dict) and "str" in recv:
                return recv["str"]
            return recv
        if name == "<init>":
            if desc == "([C)V":
                recv["str"] = "".join(chr(c & 0xFFFF) for c in args[0])
                return None
            if desc == "([BLjava/nio/charset/Charset;)V":
                raw = bytes(args[0]) if not isinstance(args[0], bytes) else args[0]
                recv["str"] = raw.decode("utf-8", "replace")
                return None
            if desc == "(Ljava/lang/String;)V":
                return None
            if desc == "(Ljava/lang/String;Ljava/lang/Throwable;)V":
                return None
            return None
        if name == "getBytes":
            s = recv if isinstance(recv, str) else recv.get("str", "")
            return list(s.encode("utf-8"))
        # String.<init> result used as object; coerce
        if isinstance(recv, dict) and "str" in recv:
            return recv["str"]
        return None


def _nargs(desc: str) -> int:
    n = 0
    i = 1
    while i < len(desc) and desc[i] != ")":
        c = desc[i]
        if c in "BCDFIJSZ":
            n += 1
            i += 1
        elif c == "L":
            n += 1
            i = desc.index(";", i) + 1
        elif c == "[":
            while desc[i] == "[":
                i += 1
            if desc[i] == "L":
                i = desc.index(";", i) + 1
            else:
                i += 1
            n += 1
        else:
            i += 1
    return n
