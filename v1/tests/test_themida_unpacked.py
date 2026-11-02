# language: Python 3
# Assert unpacked Themida artifacts exist and .text is filled.
from __future__ import annotations

import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from street_decrepytor.dynamic.pe_dump import _pe_sections_from_bytes
from street_decrepytor.protectors.themida_oep import entrypoint_rva

UNPACKED = ROOT / "tests" / "output" / "themidas" / "umi_injector"


class UnpackedThemidaArtifacts(unittest.TestCase):
    def test_files_exist(self):
        for name in ("injector_dumped.exe", "injector_unpacked.exe", "injector_stripped.exe", "UNPACKED.json"):
            p = UNPACKED / name
            self.assertTrue(p.is_file(), f"missing {p}")

    def test_unpacked_text_filled(self):
        data = (UNPACKED / "injector_unpacked.exe").read_bytes()
        self.assertEqual(data[:2], b"MZ")
        secs = _pe_sections_from_bytes(data)
        text = next((s for s in secs if s["name"] == ".text"), None)
        self.assertIsNotNone(text)
        self.assertGreaterEqual(int(text["rsize"]), 0x1000)
        ep = entrypoint_rva(data)
        self.assertIsNotNone(ep)
        self.assertGreaterEqual(ep, int(text["va"]))
        self.assertLess(ep, int(text["va"]) + int(text["vsize"] or text["rsize"]))

    def test_stripped_smaller_without_oreans(self):
        dumped = (UNPACKED / "injector_dumped.exe").stat().st_size
        stripped = (UNPACKED / "injector_stripped.exe").stat().st_size
        self.assertLess(stripped, dumped)
        data = (UNPACKED / "injector_stripped.exe").read_bytes()
        names = [s["name"] for s in _pe_sections_from_bytes(data)]
        self.assertIn(".text", names)
        self.assertFalse(any("QR" in n or "?" in n for n in names))


if __name__ == "__main__":
    unittest.main()
