# language: Python 3.11+
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from street_v2.crypto.decrypt import decrypt_blob, xor_repeat
from street_v2.extract.harvest import harvest_file
from tests.test_entropy_crypto import _minimal_pe


class TestDecrypt(unittest.TestCase):
    def test_xor_byte_recovers_pe(self):
        pe = _minimal_pe(b"\x90\x90\xc3" + b"HelloWorld" + b"\x00" * 40)
        enc = xor_repeat(pe, bytes([0x5A]))
        self.assertNotEqual(enc[:2], b"MZ")
        hit = decrypt_blob(enc, label="t")
        self.assertIsNotNone(hit)
        assert hit is not None
        self.assertEqual(hit["plain"][:2], b"MZ")
        self.assertEqual(hit["kind"], "cipher")
        self.assertGreaterEqual(hit["score"], 50)

    def test_xor_4byte_zip_magic_anchor(self):
        z = b"PK\x03\x04" + b"\x00" * 80 + b"hello.txt"
        key = b"\x11\x22\x33\x44"
        enc = xor_repeat(z, key)
        hit = decrypt_blob(enc, label="t")
        self.assertIsNotNone(hit)
        assert hit is not None
        self.assertEqual(hit["plain"][:4], b"PK\x03\x04")
        self.assertTrue(hit.get("key_hex"))

    def test_harvest_writes_section(self):
        pe = _minimal_pe()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "t.exe"
            p.write_bytes(pe)
            out = Path(td) / "h"
            rep = harvest_file(p, out)
            self.assertGreaterEqual((rep.get("counts") or {}).get("sections", 0), 1)
            self.assertTrue((out / "HARVEST.json").is_file())
            self.assertTrue((out / "strings" / "strings_ascii.txt").is_file())


if __name__ == "__main__":
    unittest.main()
