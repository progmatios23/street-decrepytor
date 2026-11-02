# language: Python 3.11+, file: entropy/analyzer.py
# Sliding-window Shannon entropy + crypto-island clustering (IDA-style heatmap)
from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any

from street_v2.pe.loader import PeImage


def shannon(blob: bytes) -> float:
    if not blob:
        return 0.0
    freq = [0] * 256
    for b in blob:
        freq[b] += 1
    n = len(blob)
    h = 0.0
    for c in freq:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def chi_square_uniform(blob: bytes) -> float:
    """χ² against uniform byte distribution — low ≈ packed/encrypted."""
    if len(blob) < 256:
        return 0.0
    freq = [0] * 256
    for b in blob:
        freq[b] += 1
    expected = len(blob) / 256.0
    return sum((c - expected) ** 2 / expected for c in freq)


@dataclass
class EntropyBlock:
    off: int
    size: int
    H: float
    chi2: float
    section: str | None = None
    rva: int | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "off": hex(self.off),
            "size": self.size,
            "H": round(self.H, 4),
            "chi2": round(self.chi2, 2),
        }
        if self.section is not None:
            d["section"] = self.section
        if self.rva is not None:
            d["rva"] = hex(self.rva)
        return d


@dataclass
class CryptoIsland:
    start_off: int
    end_off: int
    mean_H: float
    blocks: int
    section: str | None
    kind_hint: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "start_off": hex(self.start_off),
            "end_off": hex(self.end_off),
            "span": self.end_off - self.start_off,
            "mean_H": round(self.mean_H, 4),
            "blocks": self.blocks,
            "section": self.section,
            "kind_hint": self.kind_hint,
        }


@dataclass
class EntropyMap:
    window: int
    step: int
    blocks: list[EntropyBlock] = field(default_factory=list)
    islands: list[CryptoIsland] = field(default_factory=list)
    section_summary: list[dict[str, Any]] = field(default_factory=list)
    global_H: float = 0.0
    high_ratio: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "window": self.window,
            "step": self.step,
            "global_H": round(self.global_H, 4),
            "high_ratio": round(self.high_ratio, 4),
            "block_count": len(self.blocks),
            "blocks": [b.to_dict() for b in self.blocks],
            "islands": [i.to_dict() for i in self.islands],
            "sections": self.section_summary,
        }


def _section_for_off(pe: PeImage, off: int) -> tuple[str | None, int | None]:
    for s in pe.sections:
        if s.raw <= off < s.raw + max(s.rawsize, 1):
            return s.name, s.va + (off - s.raw)
    return None, None


def _cluster_islands(
    blocks: list[EntropyBlock],
    high_thresh: float = 7.2,
    merge_gap: int = 2,
) -> list[CryptoIsland]:
    high = [b for b in blocks if b.H >= high_thresh]
    if not high:
        return []
    islands: list[CryptoIsland] = []
    run = [high[0]]
    for b in high[1:]:
        prev = run[-1]
        gap_blocks = (b.off - (prev.off + prev.size)) // max(1, prev.size)
        same_sec = b.section == prev.section
        if same_sec and gap_blocks <= merge_gap:
            run.append(b)
        else:
            islands.append(_finalize_island(run))
            run = [b]
    islands.append(_finalize_island(run))
    return islands


def _finalize_island(run: list[EntropyBlock]) -> CryptoIsland:
    mean_h = sum(b.H for b in run) / len(run)
    mean_chi = sum(b.chi2 for b in run) / len(run)
    # χ² low + H high → crypto/packed; H high + χ² high → compressed with structure
    if mean_h >= 7.5 and mean_chi < 400:
        hint = "encrypted_or_cspng"
    elif mean_h >= 7.2:
        hint = "packed_or_compressed"
    else:
        hint = "elevated"
    return CryptoIsland(
        start_off=run[0].off,
        end_off=run[-1].off + run[-1].size,
        mean_H=mean_h,
        blocks=len(run),
        section=run[0].section,
        kind_hint=hint,
    )


def analyze_entropy(
    pe: PeImage,
    window: int = 4096,
    step: int | None = None,
    max_bytes: int = 32 << 20,
) -> EntropyMap:
    step = step or window
    data = pe.data[:max_bytes]
    blocks: list[EntropyBlock] = []
    for off in range(0, len(data), step):
        chunk = data[off : off + window]
        if len(chunk) < 64:
            break
        sec, rva = _section_for_off(pe, off)
        blocks.append(
            EntropyBlock(
                off=off,
                size=len(chunk),
                H=shannon(chunk),
                chi2=chi_square_uniform(chunk),
                section=sec,
                rva=rva,
            )
        )

    high = [b for b in blocks if b.H >= 7.2]
    section_summary: list[dict[str, Any]] = []
    for s in pe.sections:
        blob = s.data if s.data else pe.data[s.raw : s.raw + s.rawsize]
        if not blob:
            section_summary.append({"name": s.name, "H": 0.0, "rawsize": 0, "empty_raw": True})
            continue
        sample = blob if len(blob) <= (1 << 20) else blob[: 1 << 20]
        section_summary.append({
            "name": s.name,
            "H": round(shannon(sample), 4),
            "chi2": round(chi_square_uniform(sample), 2),
            "rawsize": s.rawsize,
            "vsize": s.vsize,
            "empty_raw": s.rawsize == 0,
            "executable": s.executable,
            "writable": s.writable,
        })

    return EntropyMap(
        window=window,
        step=step,
        blocks=blocks,
        islands=_cluster_islands(blocks),
        section_summary=section_summary,
        global_H=shannon(data[: min(len(data), 1 << 20)]),
        high_ratio=len(high) / max(1, len(blocks)),
    )
