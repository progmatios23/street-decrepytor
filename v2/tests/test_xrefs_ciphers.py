# language: Python 3.11+
from __future__ import annotations

import unittest

from street_v2.crypto.ciphers import chacha20_xor, xor_repeat, xor_add_index
from street_v2.crypto.decrypt import decrypt_blob, keys_from_xor_opcodes
from tests.test_entropy_crypto import _minimal_pe


class TestCiphers(unittest.TestCase):
    def test_chacha_roundtrip(self):
        key = b"A" * 32
        pt = b"PK\x03\x04" + b"\x00" * 60 + b"hello.zip-payload"
        ct = chacha20_xor(key, pt)
        self.assertNotEqual(ct[:4], b"PK\x03\x04")
        back = chacha20_xor(key, ct)
        self.assertEqual(back[:4], b"PK\x03\x04")

    def test_xor_add_index_roundtrip_not_plain_xor(self):
        key = b"\x11"
        pt = b"PK\x03\x04" + b"\x00" * 40
        ct = xor_add_index(pt, key)
        self.assertNotEqual(xor_repeat(ct, key)[:4], b"PK\x03\x04")
        rec = decrypt_blob(ct, extra_keys=[key], label="t")
        self.assertIsNotNone(rec)
        assert rec is not None
        self.assertEqual(rec["plain"][:4], b"PK\x03\x04")

    def test_xor_opcode_keys(self):
        # xor al, 0x5A  = 34 5A
        text = b"\x90\x34\x5A\xC3"
        keys = keys_from_xor_opcodes(text)
        self.assertIn(b"\x5a", keys)


class TestXrefs(unittest.TestCase):
    def test_xor_flag_in_disasm(self):
        from street_v2.live.ida_like import build_ida_view
        from street_v2.pe.loader import load_pe
        import tempfile
        from pathlib import Path

        # xor eax, 0x11223344 ; ret
        code = b"\x35\x44\x33\x22\x11\xC3" + b"\x90" * 50
        pe = _minimal_pe(code)
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "t.exe"
            p.write_bytes(pe)
            view = build_ida_view(load_pe(p), recursive=False, max_insns=200)
        xors = [i for i in view.instructions if i.is_xor]
        self.assertTrue(xors)
        self.assertTrue(view.xref_report)
        self.assertGreaterEqual((view.xref_report or {}).get("counts", {}).get("xor", 0), 1)


if __name__ == "__main__":
    unittest.main()
