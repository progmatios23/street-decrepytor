# language: Python 3.11+, unittest for v2 entropy + detector smoke
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path

from street_v2.crypto.detector import detect_crypto_system
from street_v2.entropy.analyzer import analyze_entropy, shannon
from street_v2.pe.loader import load_pe


def _minimal_pe(text: bytes = b"\x90" * 64) -> bytes:
    """Tiny PE32+ with one .text section — enough for loader + entropy."""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)

    pe = bytearray()
    pe += b"PE\x00\x00"
    # COFF: Machine AMD64, 1 section, TimeDateStamp, PointerToSymbolTable, NumberOfSymbols,
    # SizeOfOptionalHeader, Characteristics
    pe += struct.pack("<HHIIIHH", 0x8664, 1, 0, 0, 0, 0xF0, 0x22)
    opt = bytearray(0xF0)
    struct.pack_into("<H", opt, 0, 0x20B)  # PE32+
    struct.pack_into("<I", opt, 16, 0x1000)  # AddressOfEntryPoint
    struct.pack_into("<Q", opt, 24, 0x140000000)  # ImageBase
    struct.pack_into("<I", opt, 32, 0x1000)  # SectionAlignment
    struct.pack_into("<I", opt, 36, 0x200)  # FileAlignment
    struct.pack_into("<H", opt, 56, 6)  # MajorSubsystemVersion-ish area skip
    struct.pack_into("<I", opt, 56, 0x2000)  # SizeOfImage (offset in PE32+ opt)
    # PE32+ SizeOfImage is at +56
    struct.pack_into("<I", opt, 60, 0x200)  # SizeOfHeaders
    struct.pack_into("<H", opt, 68, 3)  # Subsystem IMAGE_SUBSYSTEM_WINDOWS_CUI
    pe += opt

    # section header 40 bytes
    name = b".text\x00\x00\x00"
    vsize = len(text)
    va = 0x1000
    rawsize = (len(text) + 0x1FF) & ~0x1FF
    raw = 0x200
    chars = 0x60000020
    sec = name + struct.pack("<IIIIIIHHI", vsize, va, rawsize, raw, 0, 0, 0, 0, chars)
    # NumberOfRelocations/NumberOfLinenumbers are H H then Characteristics I —
    # pack manually to match loader
    sec = name + struct.pack("<IIII", vsize, va, rawsize, raw)
    sec += struct.pack("<II", 0, 0)  # PointerToRelocations, PointerToLinenumbers
    sec += struct.pack("<HH", 0, 0)
    sec += struct.pack("<I", chars)
    pe += sec

    file_data = bytes(dos) + bytes(pe)
    if len(file_data) > raw:
        raise AssertionError("headers too big")
    file_data = file_data.ljust(raw, b"\x00")
    file_data += text.ljust(rawsize, b"\x00")
    return file_data


class TestV2(unittest.TestCase):
    def test_shannon_zero(self):
        self.assertEqual(shannon(b"\x00" * 100), 0.0)

    def test_shannon_high(self):
        import os

        h = shannon(os.urandom(4096))
        self.assertGreater(h, 7.0)

    def test_pe_entropy_and_crypto(self):
        blob = _minimal_pe(b"\x90\x90\xc3" + b"UPX0" + b"\x00" * 50)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "t.exe"
            p.write_bytes(blob)
            pe = load_pe(p)
            self.assertTrue(pe.is_64)
            self.assertEqual(pe.entry_rva, 0x1000)
            ent = analyze_entropy(pe, window=64, step=64)
            self.assertGreater(ent.global_H, 0.0)
            crypto = detect_crypto_system(pe, ent)
            self.assertEqual(crypto.primary, "upx")
            self.assertEqual(crypto.playbook, "upx_d")


if __name__ == "__main__":
    unittest.main()
