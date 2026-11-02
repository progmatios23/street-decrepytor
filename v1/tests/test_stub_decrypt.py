# language: Python 3, file: tests/test_stub_decrypt.py
#
# Regression-Guard fuer den dw-Stub-Entschluessler (Cs2-External-Klasse).
#
# HISTORIE (2026-09-07): Der erste Parser las Capstone-Displacements nur in
# der Hex-Form "rcx + 0x4". Capstone gibt KLEINE Displacements aber DEZIMAL
# aus ("rcx + 4") — zwei Ops ([rcx+4], [rcx+8]) wurden dadurch als [rcx+0]
# gelesen und an falscher Stelle angewendet. Der Container-Header war
# 3/7 Dwords falsch. Fix: int(disp, 0) parst beide Formen.
#
# Dieser Test baut einen kuenstlichen Stub mit BEIDEN Displacement-Formen
# und prueft, dass der Extraktor + Transform bit-genau arbeiten.
from __future__ import annotations

import struct
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from street_decrepytor.crypto.stub_decrypt import (
    DwOp,
    _disp_from_left,
    _parse_dw_op,
    decrypt_region,
    extract_dw_ops,
    StubLayout,
)


class DispParserTests(unittest.TestCase):
    """Der disp-Parser muss dezimale UND hexadezimale Displacements lesen."""

    def test_small_disp_decimal(self):
        # Capstone-Form fuer kleine Werte
        self.assertEqual(_disp_from_left("dword ptr [rcx + 4]"), 4)
        self.assertEqual(_disp_from_left("dword ptr [rcx + 8]"), 8)

    def test_large_disp_hex(self):
        # Capstone-Form fuer groessere Werte
        self.assertEqual(_disp_from_left("dword ptr [rcx + 0x214]"), 0x214)
        self.assertEqual(_disp_from_left("dword ptr [rcx + 0x3fc]"), 0x3FC)

    def test_zero_disp(self):
        self.assertEqual(_disp_from_left("dword ptr [rcx]"), 0)

    def test_negative_disp(self):
        self.assertEqual(_disp_from_left("dword ptr [rcx - 4]"), -4)


class DwOpApplyTests(unittest.TestCase):
    """Jede Op muss exakt invertierbar sein (L2: Transform, kein Cipher)."""

    def test_add_sub_inverse(self):
        block = bytearray(struct.pack("<I", 0x12345678))
        DwOp("add", 0, 0xDEADBEEF).apply(block)
        DwOp("sub", 0, 0xDEADBEEF).apply(block)
        self.assertEqual(struct.unpack_from("<I", block, 0)[0], 0x12345678)

    def test_xor_inverse(self):
        block = bytearray(struct.pack("<I", 0xCAFEBABE))
        DwOp("xor", 0, 0x0F0F0F0F).apply(block)
        DwOp("xor", 0, 0x0F0F0F0F).apply(block)
        self.assertEqual(struct.unpack_from("<I", block, 0)[0], 0xCAFEBABE)

    def test_not_inverse(self):
        block = bytearray(struct.pack("<I", 0xAAAAAAAA))
        DwOp("not", 0, 0).apply(block)
        self.assertEqual(struct.unpack_from("<I", block, 0)[0], 0x55555555)
        DwOp("not", 0, 0).apply(block)
        self.assertEqual(struct.unpack_from("<I", block, 0)[0], 0xAAAAAAAA)


class StubRoundtripTests(unittest.TestCase):
    """Baut einen Mini-Stub mit gemischten disp-Formen und verifiziert
    Extraktion + Rueck-Transformation bit-genau."""

    def _build_stub(self) -> bytes:
        """Stub: prolog-art, lea (wird ignoriert), 6 dw-ops mit dezimalen
        UND hex-disps, loop-epilog. Die ops wirken auf [rcx+0..0x14]."""
        code = bytearray()
        # prolog: push rax (harmlos)
        code += b"\x50"
        # --- dw-ops (gemischt dezimal/hex-disps) ---
        # add dword [rcx+4], 0x11111111      (disp dezimal)
        code += b"\x81\x41\x04" + struct.pack("<I", 0x11111111)
        # xor dword [rcx+0x0c], 0x22222222   (disp hex)
        code += b"\x81\x71\x0c" + struct.pack("<I", 0x22222222)
        # sub dword [rcx+8], 0x33333333      (disp dezimal)
        code += b"\x81\x69\x08" + struct.pack("<I", 0x33333333)
        # not dword [rcx+0x10]               (disp hex)
        code += b"\xf7\x91\x10\x00\x00\x00"
        # add dword [rcx+0x14], 0x55555555   (disp hex, gross)
        code += b"\x81\x81\x14\x00\x00\x00" + struct.pack("<I", 0x55555555)
        # xor dword [rcx], 0x66666666        (disp null)
        code += b"\x81\x31" + struct.pack("<I", 0x66666666)
        # --- loop-epilog + gap ---
        code += b"\x48\x81\xc7\x00\x04\x00\x00"   # add rdi, 0x400
        code += b"\x48\x81\xc1\x00\x04\x00\x00"   # add rcx, 0x400
        code += b"\x48\x81\xff\x00\x00\x08\x00"   # cmp rdi, 0x80000
        code += b"\x75\xca"                        # jne loop
        code += b"\x90" * 0x40                     # padding
        return bytes(code)

    def test_extract_all_six_ops(self):
        stub = self._build_stub()
        ops = extract_dw_ops(stub, 0x1000)
        self.assertEqual(len(ops), 6, f"erwartet 6 ops, bekam {len(ops)}: {ops}")
        # disp-verteilung pruefen (dezimal + hex gemixt)
        disps = sorted(op.disp for op in ops)
        self.assertEqual(disps, [0, 4, 8, 0x0C, 0x10, 0x14])

    def test_transform_matches_manual(self):
        """Manuell angewendete ops == Tool-transform."""
        ops = [
            DwOp("add", 4, 0x11111111),
            DwOp("xor", 0x0C, 0x22222222),
            DwOp("sub", 8, 0x33333333),
            DwOp("not", 0x10, 0),
            DwOp("add", 0x14, 0x55555555),
            DwOp("xor", 0, 0x66666666),
        ]
        original = bytes(range(32))
        # manuell
        manual = bytearray(original)
        for op in ops:
            op.apply(manual)
        # via decrypt_region (layout zusammengebaut)
        layout = StubLayout(
            stub_file_off=0, ops=ops, key_region_file_off=0,
            block_size=0x20, total_size=0x20)
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as tf:
            tf.write(original)
            p = tf.name
        try:
            dec = decrypt_region(Path(p).read_bytes(), layout)
            self.assertEqual(dec, bytes(manual))
        finally:
            Path(p).unlink()


class RealTargetRegression(unittest.TestCase):
    """Wenn das echte Target vorhanden ist: 7/7 Header-Dwords muessen stimmen.

    Das ist der Test, der den Produktions-Bug 2026-09-07 gefangen haette.
    """

    TARGET = Path(r"D:\Street-decrepytor\target-v2\Cs2-External (1).exe")
    EXPECTED_HEADER = [0x46110, 0x3D362, 0x284, 0x49F54, 0x4A1A4, 0x8B906, 0x8C000]

    @unittest.skipUnless(TARGET.exists(), "target-v2 nicht vorhanden")
    def test_seven_header_dwords(self):
        from street_decrepytor.crypto.stub_decrypt import find_and_decrypt
        data = self.TARGET.read_bytes()
        layout, dec = find_and_decrypt(data, 0x1AAA800, 0x2C68000)
        self.assertEqual(len(layout.ops), 256)
        got = [struct.unpack_from("<I", dec, i * 4)[0] for i in range(7)]
        self.assertEqual(got, self.EXPECTED_HEADER,
                         f"container-header falsch: {[hex(x) for x in got]}")


if __name__ == "__main__":
    unittest.main()
