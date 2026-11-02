# language: Python 3.11+, file: live/session.py
# Live analysis session — file watch + periodic re-analysis (IDA-like refresh)
from __future__ import annotations

import json
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from street_v2.crypto.detector import CryptoSystem, detect_crypto_system
from street_v2.crypto.report_gen import generate_crypto_report
from street_v2.entropy.analyzer import EntropyMap, analyze_entropy
from street_v2.emu.unicorn_engine import EmuResult, emulate_pe_entry
from street_v2.live.ida_like import IdaView, build_ida_view
from street_v2.pe.loader import PeImage, load_pe


@dataclass
class AnalysisSnapshot:
    generation: int
    ts: float
    pe: dict[str, Any] | None
    entropy: dict[str, Any] | None
    crypto: dict[str, Any] | None
    ida: dict[str, Any] | None
    emu: dict[str, Any] | None
    report_paths: dict[str, Any] | None = None
    v1_profile: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        ida = self.ida or {}
        return {
            "generation": self.generation,
            "ts": self.ts,
            "v1_profile": self.v1_profile,
            "pe": self.pe,
            "entropy": self.entropy,
            "crypto": self.crypto,
            "ida": {
                "insn_count": ida.get("insn_count"),
                "functions": len(ida.get("functions") or []),
                "base": ida.get("base"),
                "arch": ida.get("arch"),
            },
            "emu": self.emu,
            "report_paths": self.report_paths,
        }


class LiveSession:
    """
    Holds one PE under continuous analysis.
    refresh() rebuilds entropy + crypto + IDA views.
    watch_loop() polls mtime and refreshes on change + interval (frequent updates).
    """

    def __init__(
        self,
        path: str | Path,
        out_dir: str | Path | None = None,
        interval_sec: float = 2.0,
        run_emu: bool = True,
        run_v1: bool = False,
        max_insns_disasm: int = 60000,
        max_insns_emu: int = 20000,
    ):
        self.path = Path(path)
        self.out_dir = Path(out_dir) if out_dir else Path("output") / (self.path.stem + "_v2")
        self.interval_sec = interval_sec
        self.run_emu = run_emu
        self.run_v1 = run_v1
        self.max_insns_disasm = max_insns_disasm
        self.max_insns_emu = max_insns_emu

        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._mtime: float = 0.0
        self.generation = 0
        self.pe: PeImage | None = None
        self.entropy: EntropyMap | None = None
        self.crypto: CryptoSystem | None = None
        self.ida: IdaView | None = None
        self.emu: EmuResult | None = None
        self.snapshot: AnalysisSnapshot | None = None
        self.listeners: list[Callable[[AnalysisSnapshot], None]] = []
        self.last_error: str | None = None

    def add_listener(self, fn: Callable[[AnalysisSnapshot], None]) -> None:
        self.listeners.append(fn)

    def refresh(self, force: bool = False) -> AnalysisSnapshot:
        with self._lock:
            if not self.path.is_file():
                raise FileNotFoundError(self.path)
            st = self.path.stat()
            if not force and self.pe and st.st_mtime == self._mtime and self.snapshot:
                return self.snapshot

            v1_profile = None
            try:
                from street_v2.compat import import_v1

                import_v1()
                from street_decrepytor.core.artifact import classify_artifact

                v1_profile = classify_artifact(self.path).to_dict()
            except Exception as e:
                v1_profile = {"error": str(e)}

            if self.run_v1:
                from street_v2.engine import StreetEngineV2

                StreetEngineV2(self.out_dir).analyze(
                    self.path,
                    emu=self.run_emu,
                    disasm=True,
                    max_insns_disasm=self.max_insns_disasm,
                    max_insns_emu=self.max_insns_emu,
                    out=self.out_dir / "full",
                )

            pe = None
            ent = None
            crypto = None
            ida = None
            emu_res: EmuResult | None = None
            report = None
            try:
                pe = load_pe(self.path)
            except Exception:
                pe = None

            self.out_dir.mkdir(parents=True, exist_ok=True)
            if pe is not None:
                ent = analyze_entropy(pe)
                crypto = detect_crypto_system(pe, ent)
                ida = build_ida_view(pe, recursive=True, max_insns=self.max_insns_disasm)
                if self.run_emu:
                    emu_res = emulate_pe_entry(pe, max_insns=self.max_insns_emu)
                report = generate_crypto_report(
                    pe,
                    crypto,
                    ent,
                    self.out_dir,
                    extra={
                        "v1_profile": v1_profile,
                        "ida_insn_count": ida.to_dict()["insn_count"],
                        "ida_functions": len(ida.functions),
                        "emu": emu_res.to_dict() if emu_res else None,
                    },
                )
                (self.out_dir / "ida_view.json").write_text(
                    json.dumps(ida.to_dict(), indent=2), encoding="utf-8"
                )
                (self.out_dir / "entropy_map.json").write_text(
                    json.dumps(ent.to_dict(), indent=2), encoding="utf-8"
                )
                if emu_res:
                    (self.out_dir / "emu_trace.json").write_text(
                        json.dumps(emu_res.to_dict(), indent=2), encoding="utf-8"
                    )

            self.generation += 1
            self._mtime = st.st_mtime
            self.pe = pe
            self.entropy = ent
            self.crypto = crypto
            self.ida = ida
            self.emu = emu_res
            snap = AnalysisSnapshot(
                generation=self.generation,
                ts=time.time(),
                pe=pe.to_dict() if pe else None,
                entropy=ent.to_dict() if ent else None,
                crypto=crypto.to_dict() if crypto else None,
                ida=ida.to_dict() if ida else None,
                emu=emu_res.to_dict() if emu_res else None,
                report_paths=report,
                v1_profile=v1_profile,
            )
            self.snapshot = snap
            (self.out_dir / "LIVE_SNAPSHOT.json").write_text(
                json.dumps(snap.to_dict(), indent=2), encoding="utf-8"
            )
            for fn in self.listeners:
                try:
                    fn(snap)
                except Exception:
                    pass
            self.last_error = None
            return snap

    def status(self) -> dict[str, Any]:
        with self._lock:
            return {
                "path": str(self.path),
                "out_dir": str(self.out_dir),
                "generation": self.generation,
                "watching": self._thread is not None and self._thread.is_alive(),
                "interval_sec": self.interval_sec,
                "mtime": self._mtime,
                "last_error": self.last_error,
                "primary": self.crypto.primary if self.crypto else None,
                "family": (self.snapshot.v1_profile or {}).get("family") if self.snapshot else None,
                "insn_count": len(self.ida.instructions) if self.ida else 0,
            }

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                changed = False
                if self.path.is_file():
                    m = self.path.stat().st_mtime
                    changed = m != self._mtime
                if changed or self.snapshot is None:
                    self.refresh(force=changed)
                else:
                    # frequent soft update: re-emit snapshot heartbeat for UI polls
                    with self._lock:
                        if self.snapshot:
                            beat = dict(self.snapshot.to_dict())
                            beat["heartbeat"] = time.time()
                            (self.out_dir / "LIVE_HEARTBEAT.json").write_text(
                                json.dumps(beat, indent=2), encoding="utf-8"
                            )
            except Exception as e:
                self.last_error = str(e)
            self._stop.wait(self.interval_sec)

    def start_watch(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        if self.snapshot is None:
            self.refresh(force=True)
        self._thread = threading.Thread(target=self._loop, name="street-v2-live", daemon=True)
        self._thread.start()

    def stop_watch(self) -> None:
        self._stop.set()
        t = self._thread
        if t:
            t.join(timeout=self.interval_sec + 1.0)
        self._thread = None
