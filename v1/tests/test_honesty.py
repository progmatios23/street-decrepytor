# language: Python 3, file: tests/test_honesty.py
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from street_decrepytor.core.artifact import classify_artifact
from street_decrepytor.core.transforms import decrypted_flag, image_transform
from street_decrepytor.deobf.python_rt.pyinst import extract_pyinstaller
from street_decrepytor.crypto.simd_emu import pe_text_map, run_simd_emu_on_pe
from street_decrepytor.protectors.unpack_engine import identify_themida_class, unpack_target
from street_decrepytor.core.crack import crack_target


def _pe64(sections: list[tuple[bytes, int, int, bytes]]) -> bytes:
    """Minimal PE32+ with named sections (not runnable)."""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    nsec = len(sections)
    opt_size = 0xF0
    peh = bytearray(4 + 20 + opt_size + nsec * 40)
    peh[0:4] = b"PE\0\0"
    struct.pack_into("<H", peh, 4, 0x8664)
    struct.pack_into("<H", peh, 6, nsec)
    struct.pack_into("<H", peh, 0x10, opt_size)
    struct.pack_into("<H", peh, 0x14, 0x20B)  # magic at optional start = e_lfanew+0x18 relative to peh...
    # File layout: dos(0x80) + PE header. Optional magic is at peh+0x18
    struct.pack_into("<H", peh, 0x18, 0x20B)
    struct.pack_into("<Q", peh, 0x18 + 24, 0x140000000)
    struct.pack_into("<I", peh, 0x18 + 56, 0x1000)  # section alignment-ish SizeOfImage later
    sec_off = 4 + 20 + opt_size  # 0x108
    file_off = 0x80 + len(peh)
    file_off = (file_off + 0x1FF) & ~0x1FF
    blob = bytearray(file_off)
    blob[0:0x80] = dos
    raw_parts = []
    va = 0x1000
    for i, (name, vsize, rsize, data) in enumerate(sections):
        o = sec_off + i * 40
        peh[o : o + 8] = name.ljust(8, b"\0")[:8]
        struct.pack_into("<IIII", peh, o + 8, vsize, va, rsize, file_off if rsize else 0)
        if rsize:
            pad = data[:rsize] + b"\x00" * max(0, rsize - len(data))
            raw_parts.append((file_off, pad))
            file_off += rsize
        va += max(vsize, 0x1000)
    blob[0x80 : 0x80 + len(peh)] = peh
    total = file_off
    out = bytearray(total)
    out[: len(blob)] = blob
    for off, pad in raw_parts:
        out[off : off + len(pad)] = pad
    return bytes(out)


class TransformContractTests(unittest.TestCase):
    def test_decrypted_only_cipher(self):
        self.assertFalse(decrypted_flag([image_transform("copy", "res", "a")]))
        self.assertFalse(decrypted_flag([image_transform("patch", "gates", "a")]))
        self.assertTrue(decrypted_flag([image_transform("cipher", "xor", "a")]))


class UnpackHonestyTests(unittest.TestCase):
    def test_plain_pe_not_themida_not_decrypted(self):
        pe = _pe64([(b".text", 0x1000, 0x200, b"\x90" * 0x200), (b".rdata", 0x1000, 0x200, b"A" * 0x200)])
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "plain.exe"
            p.write_bytes(pe)
            import pefile
            peo = pefile.PE(data=pe, fast_load=False)
            ident = identify_themida_class(pe, peo)
            self.assertFalse(ident["themida_class"])
            rep = unpack_target(p, Path(td) / "out")
            self.assertFalse(rep["decrypted"])
            self.assertFalse(any(t["kind"] == "cipher" for t in rep["image_transforms"]))


class SimdSkipTests(unittest.TestCase):
    def test_empty_text_skipped(self):
        pe = _pe64([(b".text", 0x2000, 0, b""), (b".data", 0x1000, 0x200, b"\x00" * 0x200)])
        meta = pe_text_map(pe)
        self.assertEqual(meta["name"], ".text")
        self.assertEqual(meta["text_rsize"], 0)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "packed.exe"
            p.write_bytes(pe)
            r = run_simd_emu_on_pe(p)
            self.assertTrue(r.get("skipped"))
            self.assertEqual(r.get("reason"), "empty_or_tiny_text_raw")
            self.assertEqual(r.get("unique_strings"), 0)


class PyinstTests(unittest.TestCase):
    def test_no_cookie(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "x.bin"
            p.write_bytes(b"MZ" + b"\x00" * 64)
            r = extract_pyinstaller(p, Path(td) / "out")
            self.assertFalse(r["ok"])
            self.assertEqual(r["reason"], "no_mei_cookie")


class CrackNoGatesTests(unittest.TestCase):
    def test_crack_does_not_patch_random_dll(self):
        pe = _pe64([(b".text", 0x1000, 0x400, b"\x90" * 0x400)])
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "other.dll"
            p.write_bytes(pe)
            r = crack_target(p, out=Path(td) / "c", deep_simd=False, apply_gates=False)
            self.assertFalse(r["verdict"]["decrypted"])
            kinds = {t["kind"] for t in r["verdict"]["image_transforms"]}
            self.assertNotIn("patch", kinds)


class ClassifyStillWorks(unittest.TestCase):
    def test_pe(self):
        pe = _pe64([(b".text", 0x1000, 0x200, b"\x90" * 0x200)])
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "t.exe"
            p.write_bytes(pe)
            prof = classify_artifact(p)
            self.assertEqual(prof.format, "pe")


if __name__ == "__main__":
    unittest.main()
