# language: Python 3, file: tests/test_themida_oep.py
from __future__ import annotations

import struct
import tempfile
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from street_decrepytor.core.transforms import decrypted_flag, image_transform
from street_decrepytor.protectors.themida_oep import (
    entrypoint_rva,
    find_oep_candidates,
    set_entrypoint_rva,
)
from street_decrepytor.protectors.themida_unpack import section_raw_delta, unpack_themida_live
from tests.test_honesty import _pe64


class OepTests(unittest.TestCase):
    def test_set_and_read_ep(self):
        pe = _pe64([(b".text", 0x1000, 0x200, b"\x48\x83\xec\x28" + b"\x90" * 0x1FC)])
        pe2 = set_entrypoint_rva(pe, 0x1000)
        self.assertEqual(entrypoint_rva(pe2), 0x1000)

    def test_find_prologue_in_text(self):
        body = b"\x00" * 16 + b"\x48\x89\x5c\x24\x08" + b"\x48\x83\xec\x20" + b"\x90" * 0x100
        pe = _pe64([(b".text", 0x1000, len(body), body)])
        cands = find_oep_candidates(pe)
        self.assertTrue(cands)
        rvas = {c["rva"] for c in cands}
        self.assertTrue(any(r >= 0x1000 for r in rvas))

    def test_runtime_dump_counts_as_decrypted(self):
        self.assertTrue(decrypted_flag([image_transform("runtime_dump", "themida_text", "x")]))
        self.assertFalse(decrypted_flag([image_transform("copy", "live_dump_unproven", "x")]))


class DeltaTests(unittest.TestCase):
    def test_text_delta(self):
        disk = _pe64([(b".text", 0x2000, 0, b""), (b".data", 0x1000, 0x200, b"\x00" * 0x200)])
        live = _pe64([(b".text", 0x2000, 0x1000, b"\x90" * 0x1000), (b".data", 0x1000, 0x200, b"\x00" * 0x200)])
        d = section_raw_delta(disk, live)
        self.assertEqual(d["text_disk"], 0)
        self.assertGreaterEqual(d["text_dump"], 0x1000)
        self.assertGreaterEqual(d["text_delta"], 0x1000)


class UrlExtractTests(unittest.TestCase):
    def test_finds_https_inside_junk_string(self):
        from street_decrepytor.static.strings import extract_urls, is_plausible_url

        blob = b"xxxxhttps://api.potassium.pro/versionyyyy" + b"http://accordingNO"
        urls = extract_urls(blob)
        self.assertTrue(any("api.potassium.pro" in u for u in urls), urls)
        self.assertFalse(is_plausible_url("http://according"))
        self.assertTrue(is_plausible_url("https://files.potassium.pro"))


class IatWriteTests(unittest.TestCase):
    def test_too_few_names(self):
        from street_decrepytor.protectors.themida_iat import apply_import_directory

        r = apply_import_directory(b"MZ" + b"\x00" * 64, [])
        self.assertFalse(r["ok"])


class StripTests(unittest.TestCase):
    def test_drops_weird_section(self):
        from street_decrepytor.protectors.themida_rebuild import strip_packer_sections

        pe = _pe64([
            (b".text", 0x1000, 0x200, b"\x48\x83\xec\x28" + b"\x90" * 0x1FC),
            (b".QR%", 0x2000, 0x400, b"\xCC" * 0x400),
        ])
        r = strip_packer_sections(pe)
        self.assertTrue(r.get("ok"), r)
        self.assertIn(".text", r.get("kept") or [])
        self.assertTrue(any("QR" in n or "?" in n or n.startswith(".") and n not in (".text",) for n in (r.get("dropped") or []) ) or ".QR%" in (r.get("dropped") or []))
        self.assertLess(r["out_size"], r["in_size"])


class LiveRefuseTests(unittest.TestCase):
    def test_plain_pe_refused(self):
        pe = _pe64([(b".text", 0x1000, 0x200, b"\x90" * 0x200)])
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "plain.exe"
            p.write_bytes(pe)
            r = unpack_themida_live(p, Path(td) / "out")
            self.assertEqual(r.get("error"), "not_themida_class")
            self.assertFalse(r.get("decrypted"))


if __name__ == "__main__":
    unittest.main()
