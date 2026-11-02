# language: Python 3
# Potassium files: classify, URLs/links, recrack dry, tauri. Writes tests/output/potassium/
from __future__ import annotations

import hashlib
import json
import re
import unittest
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from street_decrepytor.core.artifact import classify_artifact
from street_decrepytor.static.strings import extract_strings, classify_interesting
from street_decrepytor.protectors.unpack_engine import identify_themida_class
from street_decrepytor.potassium.recrack import recrack_dll
from street_decrepytor.potassium.gates import find_gate_table
from street_decrepytor.deobf.rust_rt.tauri_extract import extract_tauri_assets, inventory_tauri_ipc
import pefile

CDN = ROOT / "output" / "cdn" / "potassium"
OUT = ROOT / "tests" / "output" / "potassium"
CRACKED_DLL = Path(r"C:\claude\cracked\bin\Potassium.dll")
CRACKED_EXE = Path(r"C:\claude\cracked\bin\Potassium.exe")
CDN_DLL = CDN / "bin" / "Potassium.dll"
CDN_EXE = CDN / "bin" / "Potassium.exe"
CDN_DLL_OPAQUE = CDN / "bin" / "UJHTsWfaQaTkMszMqHbjxeufjJRbDyJL.dll"
CDN_EXE_OPAQUE = CDN / "bin" / "UJHTsWfaQaTkMszMqHbjxeufjJRbDyJL.exe"

_URL = re.compile(r"https?://[A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{6,160}")
_HOST = re.compile(r"(?:[a-zA-Z0-9-]+\.)+(?:pro|com|net|io|dev|gg|org)(?:/[^\s\"']*)?")


def _sha256(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _links_from(data: bytes) -> dict:
    strings = extract_strings(data, limit=8000)
    interesting = classify_interesting(strings)
    blob = "\n".join(strings)
    urls = sorted(set(interesting.get("urls") or []) | set(_URL.findall(blob)))
    hosts = sorted({m.group(0).rstrip(").,") for m in _HOST.finditer(blob) if "potassium" in m.group(0).lower() or m.group(0).count(".") >= 1})
    hosts = [h for h in hosts if not h.startswith("http") and len(h) < 80][:80]
    return {
        "string_count": len(strings),
        "urls": urls[:120],
        "url_count": len(urls),
        "hosts_sample": hosts[:60],
        "auth_license": (interesting.get("auth_license") or [])[:40],
        "crypto_words": (interesting.get("crypto_words") or [])[:40],
        "antidebug": (interesting.get("antidebug") or [])[:20],
        "paths": (interesting.get("paths") or [])[:20],
    }


@unittest.skipUnless(CDN_DLL.is_file() or CRACKED_DLL.is_file(), "no Potassium.dll on disk")
class PotassiumLab(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        OUT.mkdir(parents=True, exist_ok=True)
        cls.dll = CDN_DLL if CDN_DLL.is_file() else CRACKED_DLL
        cls.exe = CDN_EXE if CDN_EXE.is_file() else CRACKED_EXE
        cls.report: dict = {"dll": str(cls.dll), "exe": str(cls.exe) if cls.exe.is_file() else None}

        dll_data = cls.dll.read_bytes()
        cls.report["dll_sha256"] = hashlib.sha256(dll_data).hexdigest()
        cls.report["dll_size"] = len(dll_data)
        prof = classify_artifact(cls.dll)
        pe = pefile.PE(data=dll_data, fast_load=False)
        pe.parse_data_directories()
        ident = identify_themida_class(dll_data, pe)
        cls.report["dll_classify"] = {
            "family": prof.family.value,
            "format": prof.format,
            "signals": prof.signals[:20],
            "themida_class": ident["themida_class"],
            "score": ident["score"],
        }
        cls.report["dll_links"] = _links_from(dll_data[: min(len(dll_data), 16 << 20)])

        if cls.exe.is_file():
            exe_data = cls.exe.read_bytes()
            cls.report["exe_sha256"] = hashlib.sha256(exe_data).hexdigest()
            cls.report["exe_size"] = len(exe_data)
            ep = classify_artifact(cls.exe)
            pe2 = pefile.PE(data=exe_data, fast_load=False)
            pe2.parse_data_directories()
            ident2 = identify_themida_class(exe_data, pe2)
            cls.report["exe_classify"] = {
                "family": ep.family.value,
                "signals": ep.signals[:20],
                "themida_class": ident2["themida_class"],
                "score": ident2["score"],
            }
            cls.report["exe_links"] = _links_from(exe_data[: min(len(exe_data), 16 << 20)])
            assets = extract_tauri_assets(exe_data, OUT / "tauri_assets")
            ipc = inventory_tauri_ipc(exe_data)
            cls.report["exe_tauri"] = {
                "asset_count": len(assets),
                "is_tauri": ipc.get("is_tauri"),
                "custom_commands": (ipc.get("custom_commands") or [])[:30],
                "urls": (ipc.get("urls") or [])[:40],
            }

        table = find_gate_table()
        cls.report["gate_table"] = str(table) if table else None
        if table:
            g = recrack_dll(cls.dll, dry=True, table_path=table)
            cls.report["recrack_dry"] = {k: g.get(k) for k in ("ok", "applied", "miss", "already", "error", "written")}

        hashes_p = CDN / "hashes.json"
        if hashes_p.is_file():
            want = json.loads(hashes_p.read_text(encoding="utf-8"))
            cls.report["cdn_hashes"] = want
            cls.report["hash_check"] = {}
            for name, digest in want.items():
                p = CDN / "bin" / name
                if p.is_file():
                    got = _sha256(p)
                    cls.report["hash_check"][name] = {"match": got == digest, "got": got, "want": digest}

        (OUT / "REPORT.json").write_text(json.dumps(cls.report, indent=2, default=str), encoding="utf-8")
        urls = []
        for key in ("dll_links", "exe_links"):
            urls.extend((cls.report.get(key) or {}).get("urls") or [])
        urls.extend((cls.report.get("exe_tauri") or {}).get("urls") or [])
        uniq = sorted(set(urls))
        (OUT / "LINKS.txt").write_text("\n".join(uniq) + "\n", encoding="utf-8")
        cls.report["all_urls"] = uniq

    def test_dll_not_themida(self):
        self.assertFalse(self.report["dll_classify"]["themida_class"])

    def test_dll_has_potassium_or_urls(self):
        links = self.report["dll_links"]
        blob = " ".join(links.get("urls") or []) + " " + " ".join(links.get("auth_license") or [])
        self.assertTrue(
            links["url_count"] > 0 or "potassium" in blob.lower() or links.get("auth_license"),
            msg=f"no urls/auth on dll: {links}",
        )

    def test_exe_tauri_or_rust(self):
        if not self.exe.is_file():
            self.skipTest("no exe")
        fam = self.report["exe_classify"]["family"]
        sigs = " ".join(self.report["exe_classify"]["signals"])
        self.assertTrue(fam in ("rust", "native_pe") or "tauri" in sigs.lower())

    def test_links_file_written(self):
        self.assertTrue((OUT / "LINKS.txt").is_file())
        self.assertTrue((OUT / "REPORT.json").is_file())

    def test_recrack_dry_runs(self):
        if not self.report.get("gate_table"):
            self.skipTest("no gate table")
        r = self.report.get("recrack_dry") or {}
        self.assertNotEqual(r.get("error"), "no_gate_table")

    def test_cdn_hash_potassium_exe_listed(self):
        h = self.report.get("cdn_hashes") or {}
        self.assertIn("Potassium.exe", h)


if __name__ == "__main__":
    unittest.main()
