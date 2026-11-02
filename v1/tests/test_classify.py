# language: Python 3, file: tests/test_classify.py
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from street_decrepytor.core.artifact import classify_artifact, LangFamily


def _minimal_pe64() -> bytes:
    """Tiny MZ/PE64 header stub for classification smoke (not a runnable image)."""
    dos = bytearray(0x80)
    dos[0:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x80)
    pe = bytearray(0x200)
    pe[0:4] = b"PE\0\0"
    struct.pack_into("<H", pe, 4, 0x8664)  # machine
    struct.pack_into("<H", pe, 6, 1)  # sections
    struct.pack_into("<H", pe, 0x18, 0x20B)  # PE32+
    # optional header size-ish
    return bytes(dos + pe)


class ClassifyTests(unittest.TestCase):
    def test_pe_classifies(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "t.exe"
            p.write_bytes(_minimal_pe64() + b"\x00" * 0x400)
            prof = classify_artifact(p)
            self.assertEqual(prof.format, "pe")
            self.assertIn(prof.family, (LangFamily.NATIVE_PE, LangFamily.UNKNOWN, LangFamily.RUST, LangFamily.GO))

    def test_zip_jar_hint(self):
        import zipfile
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "a.jar"
            with zipfile.ZipFile(p, "w") as z:
                z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
                z.writestr("com/x/A.class", b"\xca\xfe\xba\xbe" + b"\x00" * 20)
            prof = classify_artifact(p)
            self.assertEqual(prof.family, LangFamily.JAVA)


if __name__ == "__main__":
    unittest.main()
