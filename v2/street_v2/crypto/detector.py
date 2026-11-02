# language: Python 3.11+, file: crypto/detector.py
# Detect crypto / protector *system* from PE shapes — feeds automated report templates
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from street_v2.entropy.analyzer import EntropyMap
from street_v2.pe.loader import PeImage


@dataclass
class CryptoHit:
    system: str
    confidence: float
    evidence: list[str] = field(default_factory=list)
    offsets: list[int] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "system": self.system,
            "confidence": round(self.confidence, 3),
            "evidence": self.evidence,
            "offsets": [hex(o) for o in self.offsets[:40]],
        }


@dataclass
class CryptoSystem:
    primary: str
    hits: list[CryptoHit] = field(default_factory=list)
    playbook: str = "generic"
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "primary": self.primary,
            "playbook": self.playbook,
            "hits": [h.to_dict() for h in self.hits],
            "notes": self.notes,
        }


# opcode / string fingerprints (behavioral, not eternal AOB banks as sole truth)
_AES_NI = re.compile(rb"\x66\x0f\x38(?:\xdc|\xdd|\xde|\xdf)|\x66\x0f\x3a\xdf")
_PXOR = re.compile(rb"\x66\x0f\xef")
_RC4_KSA_HINT = re.compile(
    rb"(?:S[\x00-\xff]{0,8}box|RC4|arc4)", re.I
)
# Strong ASCII markers only — bare ".themida"/".vmp0" inside entropy blobs are FPs (PyInstaller etc.)
_THEMIDA_STRONG = (b"Themida", b"WinLicense", b"Oreans Technologies", b"SecureEngine")
_THEMIDA_WEAK = (b"Oreans", b".themida")
_VMP_STRONG = (b"VMProtect", b"VMProtect begin", b"VMProtect end")
_VMP_WEAK = (b".vmp0", b".vmp1")
_UPX_MARKERS = (b"UPX0", b"UPX1", b"UPX!")
_DOTNET_CRYPTO = (
    b"System.Security.Cryptography",
    b"AesCryptoServiceProvider",
    b"Rijndael",
    b"ProtectedData",
)
_CHACHA_CONST = (b"expand 32-byte k", b"expand 16-byte k")
_TEA_DELTA = re.compile(rb"\xb9\x79\x37\x9e")  # 0x9E3779B9 LE


def _score_aes_ni(data: bytes) -> CryptoHit | None:
    offs = [m.start() for m in _AES_NI.finditer(data)]
    if not offs:
        return None
    conf = min(0.95, 0.35 + 0.02 * len(offs))
    return CryptoHit("aes_ni", conf, [f"AES-NI insn count={len(offs)}"], offs[:40])


def _score_simd_xor(data: bytes) -> CryptoHit | None:
    offs = [m.start() for m in _PXOR.finditer(data)]
    if len(offs) < 3:
        return None
    conf = min(0.9, 0.25 + 0.01 * len(offs))
    return CryptoHit("simd_xor_string", conf, [f"pxor density={len(offs)}"], offs[:40])


def _score_xor_imm(data: bytes) -> CryptoHit | None:
    # mov rax, imm64 near xor
    offs = []
    for m in re.finditer(rb"\x48\xb8.{8}", data):
        window = data[m.start() : m.start() + 48]
        if b"\x30" in window or b"\x31" in window or b"\x80\x30" in window:
            offs.append(m.start())
        if len(offs) >= 40:
            break
    if len(offs) < 2:
        return None
    return CryptoHit("xor_imm_loop", min(0.75, 0.2 + 0.03 * len(offs)),
                     [f"mov rax,imm64 + xor window hits={len(offs)}"], offs)


def _find_ascii_marker(data: bytes, mk: bytes) -> int:
    """Require marker bounded by non-letter bytes so random entropy rarely matches."""
    start = 0
    while True:
        i = data.find(mk, start)
        if i < 0:
            return -1
        before = data[i - 1] if i > 0 else 0
        after_i = i + len(mk)
        after = data[after_i] if after_i < len(data) else 0
        # accept C-string / section-name style: null or punctuation around
        def _ok(b: int) -> bool:
            return not (0x41 <= b <= 0x5A or 0x61 <= b <= 0x7A or 0x30 <= b <= 0x39)

        if _ok(before) and _ok(after):
            return i
        start = i + 1


def _score_named(
    data: bytes,
    strong: tuple[bytes, ...],
    weak: tuple[bytes, ...],
    name: str,
    base: float,
) -> CryptoHit | None:
    found: list[int] = []
    evid: list[str] = []
    strong_hits = 0
    for mk in strong:
        i = _find_ascii_marker(data, mk)
        if i >= 0:
            found.append(i)
            evid.append(f"strong {mk!r} @ {i:#x}")
            strong_hits += 1
    weak_hits = 0
    for mk in weak:
        i = _find_ascii_marker(data, mk)
        if i >= 0:
            found.append(i)
            evid.append(f"weak {mk!r} @ {i:#x}")
            weak_hits += 1
    if strong_hits == 0 and weak_hits < 2:
        return None
    conf = base + 0.12 * strong_hits + 0.04 * weak_hits
    if strong_hits == 0:
        conf = min(conf, 0.55)  # weak-only never primary-grade
    return CryptoHit(name, min(0.98, conf), evid, found)


def _score_empty_text(pe: PeImage, ent: EntropyMap | None) -> CryptoHit | None:
    text = next((s for s in pe.sections if s.name.startswith(".text")), None)
    if text is None:
        return None
    if text.rawsize == 0 and text.vsize > 0x1000:
        evid = [f".text raw=0 vsize={text.vsize:#x} — runtime decrypt shell"]
        high = 0.0
        if ent:
            high = ent.high_ratio
            evid.append(f"high_entropy_ratio={high}")
        return CryptoHit("runtime_encrypted_text", 0.85 + min(0.1, high * 0.1), evid, [text.va])
    return None


def _score_chacha(data: bytes) -> CryptoHit | None:
    for mk in _CHACHA_CONST:
        i = data.find(mk)
        if i >= 0:
            return CryptoHit("chacha20", 0.88, [f"{mk!r} @ {i:#x}"], [i])
    return None


def _score_tea(data: bytes) -> CryptoHit | None:
    offs = [m.start() for m in _TEA_DELTA.finditer(data)]
    if not offs:
        return None
    return CryptoHit("tea_xtea", min(0.8, 0.4 + 0.05 * len(offs)), [f"delta 0x9E3779B9 x{len(offs)}"], offs[:20])


def _score_dotnet_crypto(data: bytes) -> CryptoHit | None:
    evid = []
    offs = []
    for mk in _DOTNET_CRYPTO:
        i = data.find(mk)
        if i >= 0:
            evid.append(mk.decode("ascii", "ignore"))
            offs.append(i)
    if not evid:
        return None
    return CryptoHit("dotnet_bcl_crypto", min(0.9, 0.4 + 0.1 * len(evid)), evid, offs)


def detect_crypto_system(pe: PeImage, ent: EntropyMap | None = None) -> CryptoSystem:
    data = pe.data if pe.size < 40 << 20 else pe.data[: 16 << 20]
    hits: list[CryptoHit] = []

    for fn in (
        lambda: _score_named(data, _THEMIDA_STRONG, _THEMIDA_WEAK, "themida_winlicense", 0.7),
        lambda: _score_named(data, _VMP_STRONG, _VMP_WEAK, "vmprotect", 0.7),
        lambda: _score_named(data, _UPX_MARKERS, (), "upx", 0.8),
        lambda: _score_empty_text(pe, ent),
        lambda: _score_aes_ni(data),
        lambda: _score_chacha(data),
        lambda: _score_tea(data),
        lambda: _score_simd_xor(data),
        lambda: _score_xor_imm(data),
        lambda: _score_dotnet_crypto(data),
    ):
        h = fn()
        if h:
            hits.append(h)

    # RC4 string hint only if also high-entropy island
    if ent and ent.islands:
        m = _RC4_KSA_HINT.search(data)
        if m:
            hits.append(CryptoHit("rc4_hint", 0.45, ["RC4/Sbox string near high-entropy island"], [m.start()]))

    hits.sort(key=lambda h: -h.confidence)
    if not hits:
        primary = "unknown"
        playbook = "generic"
        notes = ["no strong crypto/protector fingerprint — entropy islands still reported"]
    else:
        primary = hits[0].system
        playbook = {
            "themida_winlicense": "themida_live_dump",
            "vmprotect": "vmp_live_dump",
            "upx": "upx_d",
            "runtime_encrypted_text": "live_dump_wait_text",
            "aes_ni": "aes_ni_trace",
            "chacha20": "chacha_recover",
            "tea_xtea": "tea_recover",
            "simd_xor_string": "simd_emu",
            "xor_imm_loop": "xor_recover",
            "dotnet_bcl_crypto": "dotnet_crypto_trace",
            "rc4_hint": "rc4_recover",
        }.get(primary, "generic")
        notes = [
            "primary = highest-confidence hit; secondary hits remain in report",
            "commercial VM is NOT lifted — playbook is dump/trace, not cipher invert",
        ]

    if ent and ent.high_ratio >= 0.4 and primary in ("unknown", "xor_imm_loop"):
        notes.append(f"elevated packing signal high_ratio={ent.high_ratio:.3f}")

    return CryptoSystem(primary=primary, hits=hits, playbook=playbook, notes=notes)
