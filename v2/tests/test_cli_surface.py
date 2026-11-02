# language: Python 3.11+, v2 must expose v1 verbs + own engine
from __future__ import annotations

import unittest

import click

from street_v2.cli import main
from street_v2.compat import import_v1, v1_root


class TestCliSurface(unittest.TestCase):
    def test_v1_root_exists(self):
        root = v1_root()
        self.assertTrue((root / "street_decrepytor").is_dir(), root)

    def test_import_v1(self):
        pkg = import_v1()
        self.assertTrue(hasattr(pkg, "__version__"))

    def test_v1_verbs_attached(self):
        need = {
            "classify", "analyze", "crack", "unpack", "dump", "protectors",
            "strings", "junk", "deobf", "cfg", "themida-unpack", "live",
            "serve", "entropy", "crypto", "emu", "disasm", "harvest", "decrypt", "xref",
        }
        have = set(main.commands)
        missing = need - have
        self.assertFalse(missing, f"missing commands: {missing}")
        live = main.commands["live"]
        self.assertFalse(isinstance(live, click.Group), "live must stay the v2 watch command")
        self.assertIn("dyn", main.commands)


if __name__ == "__main__":
    unittest.main()
